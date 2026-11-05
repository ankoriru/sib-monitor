"""Regression checks for the current Amvera hostname and non-destructive retirement."""
import asyncio
import os
import unittest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import psycopg2
from psycopg2 import sql

import app


CURRENT = "sib-monitor-ankori.msk1.amvera.tech"
RETIRED = "sib-monitor-ankori.amvera.io"


class SelfMonitoringTargetTests(unittest.IsolatedAsyncioTestCase):
    async def probe(self, status=200, error=None):
        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        session.get.return_value.__aenter__ = AsyncMock(
            return_value=MagicMock(status=status), side_effect=error)
        session.get.return_value.__aexit__ = AsyncMock(return_value=False)
        with patch.object(app.aiohttp, "ClientSession", return_value=session):
            results = await app.check_self_monitoring()
        self.assertEqual(app.SELF_MONITORING_SITES, [CURRENT])
        session.get.assert_called_once()
        self.assertEqual(session.get.call_args.args[0], f"https://{CURRENT}/")
        self.assertEqual(session.get.call_args.kwargs["timeout"].total, 8)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], CURRENT)
        return results[0]

    async def test_current_hostname_is_checked(self):
        self.assertEqual((await self.probe())[1], 200)

    async def test_authentication_challenge_is_online(self):
        self.assertEqual((await self.probe(status=401))[1], 200)

    async def test_existing_http_response_policy_is_unchanged(self):
        for status in (403, 404, 500):
            with self.subTest(status=status):
                self.assertEqual((await self.probe(status=status))[1], 200)

    async def test_timeout_remains_offline(self):
        self.assertEqual((await self.probe(error=asyncio.TimeoutError()))[1], 0)

    async def test_connection_failure_remains_offline(self):
        self.assertEqual((await self.probe(error=OSError("unreachable")))[1], 0)


@unittest.skipUnless(os.getenv("SIB_MONITOR_TEST_DSN"), "isolated PostgreSQL DSN not set")
class SelfMonitoringMigrationTests(unittest.TestCase):
    def setUp(self):
        self.schema = "test_self_target_" + uuid.uuid4().hex
        self.admin = psycopg2.connect(os.environ["SIB_MONITOR_TEST_DSN"])
        self.admin.autocommit = True
        with self.admin.cursor() as cur:
            cur.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.addCleanup(self.cleanup)
        self.conn = psycopg2.connect(
            os.environ["SIB_MONITOR_TEST_DSN"], options=f"-csearch_path={self.schema}")
        with self.conn, self.conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE monitored_sites (
                    site TEXT PRIMARY KEY, site_group TEXT, alert_threshold INTEGER,
                    is_active BOOLEAN);
                CREATE TABLE logs (site TEXT, status INTEGER);
                CREATE TABLE incidents (site TEXT, resolved BOOLEAN);
                CREATE TABLE checks_agg (site TEXT, cnt INTEGER);
            """)
            cur.execute("INSERT INTO monitored_sites VALUES (%s, 'self', 10, TRUE)", (RETIRED,))
            cur.execute("INSERT INTO monitored_sites VALUES ('other.example', 'external', 5, TRUE)")
            cur.execute("INSERT INTO logs VALUES (%s, 0)", (RETIRED,))
            cur.execute("INSERT INTO incidents VALUES (%s, FALSE)", (RETIRED,))
            cur.execute("INSERT INTO checks_agg VALUES (%s, 42)", (RETIRED,))

    def cleanup(self):
        if getattr(self, "conn", None):
            self.conn.close()
        with self.admin.cursor() as cur:
            cur.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(self.schema)))
        self.admin.close()

    def test_retirement_is_idempotent_and_preserves_history(self):
        with self.conn, self.conn.cursor() as cur:
            app._sync_self_monitoring_sites(cur)
            app._sync_self_monitoring_sites(cur)
            cur.execute("SELECT site, site_group, alert_threshold, is_active FROM monitored_sites")
            rows = {r[0]: r[1:] for r in cur.fetchall()}
            self.assertEqual(rows[CURRENT], ("self", 10, True))
            self.assertEqual(rows[RETIRED], ("self", 10, False))
            self.assertEqual(rows["other.example"], ("external", 5, True))
            self.assertEqual(len(rows), 3)
            for table in ("logs", "incidents", "checks_agg"):
                cur.execute(sql.SQL("SELECT COUNT(*) FROM {} WHERE site=%s").format(
                    sql.Identifier(table)), (RETIRED,))
                self.assertEqual(cur.fetchone()[0], 1)

    def test_existing_current_target_stays_in_separate_self_group(self):
        with self.conn, self.conn.cursor() as cur:
            cur.execute("INSERT INTO monitored_sites VALUES (%s, 'external', 5, FALSE)", (CURRENT,))
            app._sync_self_monitoring_sites(cur)
            cur.execute("SELECT site_group, alert_threshold, is_active FROM monitored_sites WHERE site=%s",
                        (CURRENT,))
            self.assertEqual(cur.fetchone(), ("self", 10, True))
