"""Read-only fixtures: tests never call production sites, DB or Telegram."""
import asyncio
import datetime
import socket
import ssl
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import app


def dashboard_fixture():
    latest = {
        "offline.example": dict(status=0, response_time=8.12, ssl_days=90,
                                domain_days=100, ssl_chain_valid=True,
                                check_error="DNS: не удалось определить IP-адрес сайта"),
        "online.example": dict(status=200, response_time=0.21, ssl_days=5,
                               domain_days=100, ssl_chain_valid=True,
                               check_error=None),
    }
    return dict(
        s24=dict(up=99.1, resp=0.5), s30=dict(up=99.2, resp=0.6),
        latest=latest, stats={}, incidents=[], active_incidents=[],
        now_msk="30.10.2026 12:00:00", group_agg={},
        categories=[dict(id="external", label="Внешние", sort_order=0,
                         sites=list(latest))],
        sites_by_cat={"external": list(latest)},
        db_cats=[dict(id="external", label="Внешние", sort_order=0)],
    )


class ErrorClassificationTests(unittest.TestCase):
    def test_network_causes(self):
        key = MagicMock()
        errors = [
            (asyncio.TimeoutError(), "Таймаут"),
            (aiohttp.ClientConnectorError(key, socket.gaierror(-2, "not found")), "DNS"),
            (aiohttp.ClientConnectorError(key, ConnectionRefusedError(111, "refused")),
             "отклонено"),
            (aiohttp.ClientConnectorError(key, ConnectionResetError(104, "reset")),
             "сброшено"),
            (aiohttp.ClientConnectorError(key, OSError(101, "unreachable")), "101"),
            (aiohttp.ServerDisconnectedError(), "Сервер закрыл"),
            (aiohttp.TooManyRedirects(MagicMock(), ()), "перенаправлений"),
            (ssl.SSLError("handshake failed"), "TLS"),
        ]
        for exc, label in errors:
            with self.subTest(exc=type(exc).__name__, label=label):
                self.assertIn(label, app._describe_check_error(exc))

    def test_certificate_reason_is_preserved(self):
        error = ssl.SSLCertVerificationError("expired")
        error.verify_message = "certificate has expired"
        wrapped = aiohttp.ClientConnectorCertificateError(MagicMock(), error)
        self.assertIn("certificate has expired", app._describe_check_error(wrapped))

    def test_unknown_exception_does_not_leak_request_secrets(self):
        error = RuntimeError("https://user:secret@example.org/?token=private")
        self.assertEqual(app._describe_check_error(error), "Ошибка запроса: RuntimeError")


class RequestDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    async def probe(self, status=200, body="sibur", exc=None, content_match=False,
                    body_error=None):
        session = MagicMock()
        response = MagicMock(status=status)
        response.text = AsyncMock(return_value=body, side_effect=body_error)
        session.get.return_value.__aenter__ = AsyncMock(
            return_value=response, side_effect=exc)
        session.get.return_value.__aexit__ = AsyncMock(return_value=False)
        with patch.object(app, "_cm_sites_set", {"example.org"} if content_match else set()), \
                patch.object(app.time, "perf_counter", side_effect=[100.0, 108.25]):
            result = await app.check_single_site(
                session, "example.org", asyncio.Semaphore(1))
        self.assertEqual(session.get.call_args.kwargs["timeout"].total, 8)
        self.assertTrue(session.get.call_args.kwargs["allow_redirects"])
        return result

    async def test_timeout_records_actual_duration_and_reason(self):
        site, status, elapsed, reason = await self.probe(exc=asyncio.TimeoutError())
        self.assertEqual((site, status, elapsed), ("example.org", 0, 8.25))
        self.assertIn("Таймаут", reason)

    async def test_success_has_no_error(self):
        result = await self.probe()
        self.assertEqual(result[1:], (200, 8.25, None))

    async def test_http_error_remains_offline_with_reason(self):
        result = await self.probe(status=403)
        self.assertEqual(result[1], 403)
        self.assertIn("HTTP 403", result[3])

    async def test_content_mismatch_keeps_701(self):
        result = await self.probe(body="Welcome", content_match=True)
        self.assertEqual(result[1], 701)
        self.assertIn("нет совпадения", result[3])

    async def test_content_read_failure_is_distinct_from_pattern_mismatch(self):
        result = await self.probe(content_match=True, body_error=asyncio.TimeoutError())
        self.assertEqual(result[1], 701)
        self.assertIn("ошибка чтения", result[3])

    async def test_401_policy_unchanged(self):
        self.assertEqual((await self.probe(status=401))[1], 200)
        self.assertEqual((await self.probe(status=401, body="", content_match=True))[1], 701)

    async def test_redirect_policy_unchanged(self):
        for status in (307, 308):
            self.assertEqual((await self.probe(status=status))[1], 200)

    async def test_measurement_starts_after_queue_wait(self):
        entered = False

        class Queue:
            async def __aenter__(self):
                nonlocal entered
                entered = True

            async def __aexit__(self, *args):
                pass

        readings = iter([50.0, 50.4])

        def clock():
            self.assertTrue(entered)
            return next(readings)

        session = MagicMock()
        session.get.side_effect = ConnectionResetError()
        with patch.object(app.time, "perf_counter", side_effect=clock):
            result = await app.check_single_site(session, "example.org", Queue())
        self.assertAlmostEqual(result[2], 0.4)

    async def test_ssl_verification_is_not_disabled_by_diagnostics(self):
        with patch.object(app.aiohttp, "TCPConnector") as connector:
            await self.probe()
        connector.assert_not_called()


class DiagnosticPersistenceTests(unittest.TestCase):
    def test_batch_stores_reason_and_legacy_log_tuple_shape(self):
        conn = MagicMock()
        rows = [
            ("failed.example", 0, 8.12, 5, 100, True, "Таймаут"),
            ("recovered.example", 200, 0.4, 5, 100, True, None),
            ("self.example", 200, 0.3, -1, -1, None),
        ]
        with patch.object(app, "get_db_connection", return_value=conn), \
                patch.object(app, "execute_values") as insert_logs, \
                patch.object(app, "_update_checks_agg"), \
                patch.object(app, "batch_buffer", list(rows)):
            app._flush_batch_unlocked()
        self.assertEqual(insert_logs.call_args.args[2], [row[:6] for row in rows])
        calls = conn.cursor.return_value.execute.call_args_list
        self.assertEqual([call.args[1][-1] for call in calls], ["Таймаут", None, None])
        for call in calls:
            update = call.args[0].split("DO UPDATE SET")[1]
            self.assertIn("check_error = EXCLUDED.check_error", update)
            self.assertNotIn("ssl_days =", update)
            self.assertNotIn("domain_days =", update)
        conn.commit.assert_called_once()

    def test_processor_keeps_reason_attached_to_same_sample(self):
        buffer = []
        with patch.object(app, "batch_buffer", buffer):
            app._process_site_result(
                "example.org", 0, 8.12, 5, 100, True,
                {"example.org": 200}, {}, {}, {"example.org": 100}, {},
                check_error="DNS")
        self.assertEqual(buffer, [("example.org", 0, 8.12, 5, 100, True, "DNS")])

    def test_migration_is_additive_and_idempotent(self):
        cursor = MagicMock()
        app._ensure_check_error_column(cursor)
        self.assertEqual(cursor.execute.call_args.args[0],
                         "ALTER TABLE latest_status ADD COLUMN IF NOT EXISTS check_error TEXT")


class DashboardDiagnosticsTests(unittest.TestCase):
    def test_reason_in_warning_and_site_table(self):
        html = app._build_body(dashboard_fixture())
        self.assertEqual(html.count("DNS: не удалось определить IP-адрес сайта"), 2)
        self.assertIn("1 / 2", html)
        self.assertIn("8.12с", html)
        self.assertIn(app.APP_VERSION, html)

    def test_error_text_is_escaped_in_both_locations(self):
        data = dashboard_fixture()
        data["latest"]["offline.example"]["check_error"] = '<script>alert("x")</script>'
        html = app._build_body(data)
        self.assertNotIn('<script>alert("x")</script>', html)
        self.assertEqual(html.count("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"), 2)

    def test_recovery_hides_stale_reason(self):
        data = dashboard_fixture()
        data["latest"]["offline.example"]["status"] = 200
        html = app._build_body(data)
        self.assertNotIn("DNS: не удалось", html)
        self.assertIn("2 / 2", html)

    def test_old_rows_without_diagnostics_still_render(self):
        data = dashboard_fixture()
        del data["latest"]["offline.example"]["check_error"]
        html = app._build_body(data)
        self.assertIn("Недоступен", html)
        self.assertIn("Offline", html)


class HealthVersionTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_exposes_running_version(self):
        conn = MagicMock()
        now = datetime.datetime.now()
        conn.cursor.return_value.fetchone.return_value = (now.isoformat(), now)
        with patch.object(app, "get_db_connection", return_value=conn):
            result = await app.health()
        self.assertEqual(result["version"], app.APP_VERSION)
        self.assertEqual(result["status"], "ok")


if __name__ == "__main__":
    unittest.main()
