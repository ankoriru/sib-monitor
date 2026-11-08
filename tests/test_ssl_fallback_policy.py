"""Globalping — только когда основная проверка недоступна; пустой SSL-результат не теряет данных."""
import ssl
import socket
import unittest
from unittest.mock import MagicMock, patch

import app
import external_checks


class StopWorker(BaseException):
    pass


def _ssl_raising(exc):
    ctx = MagicMock()
    ctx.wrap_socket.side_effect = exc
    return ctx


class DirectSslClassificationTests(unittest.TestCase):
    def setUp(self):
        p = patch.dict(app.tls_chain.tls_state, clear=True)
        p.start(); self.addCleanup(p.stop)
        p = patch.dict(app._ssl_notes, clear=True)
        p.start(); self.addCleanup(p.stop)
        self.ext = patch.object(app, "_check_ssl_external",
                                return_value=((31, True, False), None)).start()
        self.addCleanup(patch.stopall)

    def run_check(self, exc=None, connect_exc=None, verify_ssl=True):
        conn = patch.object(app.socket, "create_connection",
                            side_effect=connect_exc) if connect_exc else \
            patch.object(app.socket, "create_connection")
        with conn, patch.object(app.tls_chain, "context", return_value=_ssl_raising(exc)):
            return app._check_ssl_with_fallback("lsdts.sibur.ru", "lsdts.sibur.ru",
                                                verify_ssl=verify_ssl)

    def test_connect_timeout_uses_globalping(self):
        self.assertEqual(self.run_check(connect_exc=socket.timeout("t")), (31, True))
        self.ext.assert_called_once_with("lsdts.sibur.ru")
        self.assertIsNone(app.ssl_note("lsdts.sibur.ru"))

    def test_dns_failure_uses_globalping(self):
        self.run_check(connect_exc=socket.gaierror(-2, "x"))
        self.ext.assert_called_once()

    def test_eof_during_handshake_is_network_failure(self):
        self.run_check(exc=ssl.SSLEOFError(8, "EOF"))
        self.ext.assert_called_once()

    def test_handshake_error_is_direct_result_not_fallback(self):
        self.assertEqual(self.run_check(exc=ssl.SSLError(1, "handshake failure")), (-1, False))
        self.ext.assert_not_called()
        self.assertIn("рукопожатия", app.ssl_note("lsdts.sibur.ru"))

    def test_certificate_error_is_direct_result_not_fallback(self):
        err = ssl.SSLCertVerificationError("certificate has expired")
        err.verify_code = 10
        err.verify_message = "certificate has expired"
        self.assertEqual(self.run_check(exc=err), (-1, False))
        self.ext.assert_not_called()
        self.assertIn("certificate has expired", app.ssl_note("lsdts.sibur.ru"))

    def test_disabled_verification_never_connects_or_falls_back(self):
        with patch.object(app.socket, "create_connection") as conn:
            self.assertEqual(app._check_ssl_with_fallback("x.ru", "x.ru", verify_ssl=False),
                             (-1, None))
        conn.assert_not_called()
        self.ext.assert_not_called()
        self.assertEqual(app.ssl_note("x.ru"), app.SSL_NOTE_DISABLED)

    def test_external_failure_is_explained(self):
        self.ext.return_value = (None, "api_rate_limit")
        self.assertEqual(self.run_check(connect_exc=socket.timeout("t")), (-1, None))
        note = app.ssl_note("lsdts.sibur.ru")
        self.assertIn("таймаут подключения", note)
        self.assertIn("лимит запросов Globalping", note)
        self.assertIn("Повтор через 15 мин", note)

    def test_connect_timeout_is_not_too_short(self):
        self.assertGreaterEqual(app.SSL_CONNECT_TIMEOUT, 8)


class HttpFallbackPolicyTests(unittest.TestCase):
    def test_only_network_failures_go_to_globalping(self):
        self.assertTrue(external_checks.network_failure(0, "Таймаут: 8 с"))
        self.assertTrue(external_checks.network_failure(0, "DNS: имя не найдено"))
        for status, reason in ((0, "TLS: сертификат не прошёл проверку"), (502, "HTTP 502"),
                               (701, "Content Match: нет совпадения"), (200, None),
                               (0, "TLS: самоподписанный сертификат просрочен или ещё не действует")):
            with self.subTest(reason=reason):
                self.assertFalse(external_checks.network_failure(status, reason))


class WorkerRetryTests(unittest.TestCase):
    def setUp(self):
        p = patch.dict(app.tls_chain.tls_state, clear=True)
        p.start(); self.addCleanup(p.stop)
        p = patch.dict(app._ssl_notes, clear=True)
        p.start(); self.addCleanup(p.stop)

    def test_missing_result_keeps_known_days_and_records_reason(self):
        conn = MagicMock()
        app._ssl_notes["lsdts.sibur.ru"] = "Нет связи"
        with patch.object(app, "_check_ssl_with_fallback", return_value=(-1, None)), \
                patch.object(app, "_check_whois_sync", return_value=112), \
                patch.object(app, "get_db_connection", return_value=conn), \
                patch.object(app, "_invalidate_dashboard_cache"):
            self.assertTrue(app._ssl_check_and_save("lsdts.sibur.ru", True))
        sql, args = conn.cursor.return_value.execute.call_args.args
        update = sql.split("DO UPDATE SET", 1)[1]
        self.assertNotIn("ssl_days", update)
        self.assertNotIn("ssl_chain_valid", update)
        self.assertIn("ssl_note", update)
        self.assertIn("Нет связи", args)

    def test_disabled_ssl_is_not_retried(self):
        conn = MagicMock()
        with patch.object(app, "get_db_connection", return_value=conn), \
                patch.object(app, "_check_whois_sync", return_value=100), \
                patch.object(app, "_invalidate_dashboard_cache"):
            self.assertFalse(app._ssl_check_and_save("x.ru", False))

    def test_worker_retries_only_missing_sites_without_whois(self):
        calls, sleeps = [], []

        def check(site, verify_ssl, with_whois=True):
            calls.append((site, with_whois))
            return site == "lsdts.sibur.ru" and len(calls) < 3

        def sleep(seconds):
            sleeps.append(seconds)
            if len([s for s in sleeps if s >= 60]) >= 2:
                raise StopWorker()

        with patch.object(app, "_load_ssl_check_sites",
                          return_value=[("lsdts.sibur.ru", True), ("sibur.ru", True)]), \
                patch.object(app, "_ssl_check_and_save", side_effect=check), \
                patch.object(app.time, "sleep", side_effect=sleep), \
                patch.object(app.asyncio, "new_event_loop"), \
                patch.object(app.asyncio, "set_event_loop"):
            with self.assertRaises(StopWorker):
                app.ssl_whois_worker()
        self.assertEqual(calls, [("lsdts.sibur.ru", True), ("sibur.ru", True),
                                 ("lsdts.sibur.ru", False)])
        self.assertIn(app.SSL_RETRY_SECONDS, sleeps)


if __name__ == "__main__":
    unittest.main()
