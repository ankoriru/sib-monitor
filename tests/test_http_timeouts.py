import asyncio
import os
import unittest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import psycopg2
from psycopg2 import sql

import app


class TimeoutValidationTests(unittest.TestCase):
    def test_bounds(self):
        for value in (1, 8, 30, 60, "30"):
            self.assertEqual(app._validated_http_timeout(value), int(value))

    def test_invalid_input_is_rejected(self):
        for value in (None, True, False, 0, -1, 61, 30.5, 30.0, "", "8.5", "abc", [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app._validated_http_timeout(value)

    def test_bad_stored_value_cannot_disable_timeout(self):
        for value in (None, 0, -1, 10000, True):
            self.assertEqual(app._effective_http_timeout(value), 8)

    def test_exact_ten_experiment_sites(self):
        self.assertEqual(set(app.TIMEOUT_EXPERIMENT_SITES), {
            "transportorder.sibur.ru", "cp.tdms.sibur.ru/cp/",
            "tst-stdo.tdms.sibur.ru/cp/", "bopp.sibur.ru", "eshop.sibur.ru",
            "srm.sibur.ru", "resti.club", "lsdts.sibur.ru", "tms.sibur.ru",
            "sharefile.sibur.ru",
        })


class TimeoutRequestTests(unittest.IsolatedAsyncioTestCase):
    async def test_configured_timeout_is_sent_and_described(self):
        session = MagicMock()
        session.get.side_effect = asyncio.TimeoutError()
        for limit in (8, 30, 45):
            with self.subTest(limit=limit):
                result = await app.check_single_site(
                    session, "example.org", asyncio.Semaphore(1), timeout_seconds=limit)
                self.assertEqual(session.get.call_args.kwargs["timeout"].total, limit)
                self.assertEqual(result[1], 0)
                self.assertIn(f"{limit} секунд", result[3])

    async def test_body_timeout_uses_site_limit_not_old_ten_second_limit(self):
        session = MagicMock()
        response = MagicMock(status=200)
        response.text = AsyncMock(side_effect=asyncio.TimeoutError())
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        session.get.return_value.__aexit__ = AsyncMock(return_value=False)
        with patch.object(app, "_cm_sites_set", {"example.org"}):
            result = await app.check_single_site(
                session, "example.org", asyncio.Semaphore(1), timeout_seconds=30)
        self.assertEqual(result[1], 701)
        self.assertIn("30 секунд", result[3])
        self.assertEqual(session.get.call_args.kwargs["timeout"].total, 30)

    async def test_ssl_disabled_still_uses_configured_timeout(self):
        session = MagicMock()
        session.close = AsyncMock()
        session.get.side_effect = asyncio.TimeoutError()
        with patch.object(app.aiohttp, "ClientSession", return_value=session), \
                patch.object(app.aiohttp, "TCPConnector") as connector:
            result = await app.check_single_site(
                MagicMock(), "example.org", asyncio.Semaphore(1),
                verify_ssl=False, timeout_seconds=30)
        connector.assert_called_once_with(ssl=False)
        self.assertEqual(session.get.call_args.kwargs["timeout"].total, 30)
        self.assertIn("30 секунд", result[3])
        session.close.assert_awaited_once()

    async def test_timeout_map_is_per_site(self):
        with patch.object(app, "check_single_site", new_callable=AsyncMock) as check:
            await app.check_all_sites(["slow.example", "normal.example"],
                                     {"slow.example": False},
                                     {"slow.example": 30})
        options = {call.args[1]: call.kwargs for call in check.call_args_list}
        self.assertEqual(options["slow.example"], dict(verify_ssl=False, timeout_seconds=30))
        self.assertEqual(options["normal.example"], dict(verify_ssl=True, timeout_seconds=8))

    async def test_invalid_api_input_does_not_open_database(self):
        for endpoint in (app.add_site, app.update_site):
            for value in (None, True, 0, 61, 8.5, "bad"):
                request = MagicMock()
                request.json = AsyncMock(return_value={
                    "site": "example.org", "http_timeout_seconds": value})
                with self.subTest(endpoint=endpoint.__name__, value=value), \
                        patch.object(app, "get_db_connection") as db:
                    if endpoint is app.add_site:
                        response = await endpoint(request, auth=True)
                    else:
                        response = await endpoint("example.org", request, auth=True)
                    self.assertEqual(response.status_code, 400)
                    db.assert_not_called()

    async def test_content_tester_uses_same_timeout(self):
        conn = MagicMock()
        conn.cursor.return_value.fetchone.return_value = (True, 45)
        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        response = MagicMock(status=200)
        response.text = AsyncMock(return_value="sibur")
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        session.get.return_value.__aexit__ = AsyncMock(return_value=False)
        request = MagicMock()
        request.json = AsyncMock(return_value={"site": "example.org", "pattern": "sibur"})
        with patch.object(app, "get_db_connection", return_value=conn), \
                patch.object(aiohttp, "ClientSession", return_value=session) as factory:
            result = await app.test_content_match(request, auth=True)
        self.assertEqual(factory.call_args.kwargs["timeout"].total, 45)
        self.assertEqual(result["status"], "ok")


@unittest.skipUnless(os.getenv("SIB_MONITOR_TEST_DSN"), "isolated PostgreSQL DSN not set")
class TimeoutPostgresTests(unittest.TestCase):
    def setUp(self):
        self.dsn = os.environ["SIB_MONITOR_TEST_DSN"]
        self.schema = "test_timeouts_" + uuid.uuid4().hex
        self.admin = psycopg2.connect(self.dsn)
        self.admin.autocommit = True
        with self.admin.cursor() as cur:
            cur.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.addCleanup(self.cleanup)
        conn = self.connection()
        with conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE monitored_sites (
                    site TEXT PRIMARY KEY, site_group TEXT DEFAULT 'external',
                    is_active BOOLEAN DEFAULT TRUE, alert_threshold INTEGER DEFAULT 5,
                    ssl_verify BOOLEAN DEFAULT FALSE, content_match_enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT NOW());
                CREATE TABLE app_meta (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE site_categories (
                    id TEXT PRIMARY KEY, label TEXT, content_match_enabled BOOLEAN DEFAULT TRUE,
                    sort_order INTEGER DEFAULT 0);
                INSERT INTO site_categories (id, label) VALUES ('external', 'Внешние');
                CREATE TABLE logs (site TEXT, status INTEGER, response_time REAL,
                    ssl_days INTEGER, domain_days INTEGER, ssl_chain_valid BOOLEAN, timestamp TIMESTAMP);
                CREATE TABLE latest_status (site TEXT PRIMARY KEY, status INTEGER,
                    response_time REAL, ssl_days INTEGER, domain_days INTEGER,
                    ssl_chain_valid BOOLEAN, timestamp TIMESTAMP);
            """)
            for site in (*app.TIMEOUT_EXPERIMENT_SITES, "normal.example"):
                cur.execute("INSERT INTO monitored_sites (site) VALUES (%s)", (site,))
            app._migrate_http_timeouts(cur)
        conn.close()

    def connection(self):
        return psycopg2.connect(self.dsn, options=f"-csearch_path={self.schema}")

    def cleanup(self):
        with self.admin.cursor() as cur:
            cur.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(self.schema)))
        self.admin.close()

    def query(self, statement, parameters=()):
        conn = self.connection()
        try:
            with conn, conn.cursor() as cur:
                cur.execute(statement, parameters)
                return cur.fetchall() if cur.description else None
        finally:
            conn.close()

    def test_only_requested_sites_receive_thirty_seconds(self):
        rows = self.query("SELECT site, http_timeout_seconds, ssl_verify FROM monitored_sites")
        self.assertEqual(sum(r[1] == 30 for r in rows), 10)
        self.assertTrue(all(r[2] is False for r in rows))
        self.assertEqual(self.query("""
            SELECT http_timeout_seconds FROM monitored_sites WHERE site='normal.example'
        """), [(8,)])

    def test_restart_does_not_overwrite_manual_settings(self):
        self.query("UPDATE monitored_sites SET http_timeout_seconds=45 WHERE site='bopp.sibur.ru'")
        conn = self.connection()
        with conn, conn.cursor() as cur:
            app._migrate_http_timeouts(cur)
            app._migrate_http_timeouts(cur)
        conn.close()
        self.assertEqual(self.query("""
            SELECT http_timeout_seconds FROM monitored_sites WHERE site='bopp.sibur.ru'
        """), [(45,)])

    def test_admin_save_list_and_worker_round_trip(self):
        request = MagicMock()
        request.json = AsyncMock(return_value={"http_timeout_seconds": 40})
        with patch.object(app, "get_db_connection", side_effect=self.connection), \
                patch.object(app, "_invalidate_dashboard_cache"):
            saved = asyncio.run(app.update_site("cp.tdms.sibur.ru/cp/", request, auth=True))
            listing = asyncio.run(app.list_sites(auth=True))
            loaded = app.load_active_sites()
        self.assertEqual(saved["status"], "ok")
        row = next(r for r in listing["sites"] if r["site"] == "cp.tdms.sibur.ru/cp/")
        self.assertEqual(row["http_timeout_seconds"], 40)
        self.assertFalse(row["ssl_verify"])
        self.assertEqual(loaded[5]["cp.tdms.sibur.ru/cp/"], 40)
        self.assertEqual(loaded[5]["normal.example"], 8)

    def test_legacy_update_preserves_timeout(self):
        request = MagicMock()
        request.json = AsyncMock(return_value={"threshold": 9})
        with patch.object(app, "get_db_connection", side_effect=self.connection), \
                patch.object(app, "_invalidate_dashboard_cache"):
            result = asyncio.run(app.update_site("bopp.sibur.ru", request, auth=True))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.query("""
            SELECT alert_threshold, http_timeout_seconds FROM monitored_sites WHERE site='bopp.sibur.ru'
        """), [(9, 30)])

    def test_add_new_site_with_custom_timeout(self):
        request = MagicMock()
        request.json = AsyncMock(return_value={"site": "new.example", "group": "external",
                                               "http_timeout_seconds": 25})
        with patch.object(app, "get_db_connection", side_effect=self.connection), \
                patch.object(app, "_invalidate_dashboard_cache"):
            result = asyncio.run(app.add_site(request, auth=True))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.query("""
            SELECT http_timeout_seconds FROM monitored_sites WHERE site='new.example'
        """), [(25,)])

    def test_unknown_site_returns_404(self):
        request = MagicMock()
        request.json = AsyncMock(return_value={"http_timeout_seconds": 30})
        with patch.object(app, "get_db_connection", side_effect=self.connection):
            result = asyncio.run(app.update_site("missing.example", request, auth=True))
        self.assertEqual(result.status_code, 404)

    def test_database_constraint_rejects_invalid_values(self):
        with self.assertRaises(psycopg2.errors.CheckViolation):
            self.query("UPDATE monitored_sites SET http_timeout_seconds=0")

    def test_admin_page_shows_current_value_and_labels(self):
        with patch.object(app, "get_db_connection", side_effect=self.connection):
            response = asyncio.run(app._admin_page_inner(MagicMock(), MagicMock()))
        html = response.body.decode()
        self.assertIn('id="timeout-bopp.sibur.ru" value="30"', html)
        self.assertIn('id="timeout-normal.example" value="8"', html)
        self.assertIn("Таймаут HTTP, с", html)


if __name__ == "__main__":
    unittest.main()
