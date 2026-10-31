"""Regression tests: no production database, TLS connections or Telegram calls."""
import datetime
import unittest
from unittest.mock import MagicMock, patch

import app


class SSLReportTests(unittest.TestCase):
    def setUp(self):
        self.connection = MagicMock()
        self.cursor = self.connection.cursor.return_value.__enter__.return_value
        self.cursor.fetchall.return_value = [("ksot.nipigas.ru",)]
        self.db = patch.object(app, "get_db_connection", return_value=self.connection)
        self.send = patch.object(app, "send_tg_msg", return_value=True)
        self.enabled = patch.object(app, "TG_SSL_REPORT_ENABLED", True)
        self.db.start()
        self.sender = self.send.start()
        self.enabled.start()
        self.addCleanup(patch.stopall)

    def test_consecutive_mornings_recalculate_from_certificate(self):
        class Clock(datetime.datetime):
            current = datetime.datetime(2026, 10, 29, 6, 0)

            @classmethod
            def utcnow(cls):
                return cls.current

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = {
            "notAfter": "Nov 03 12:00:00 2026 GMT"
        }
        with patch.object(app.datetime, "datetime", Clock), \
                patch.object(app.socket, "create_connection"), \
                patch.object(app.ssl, "create_default_context", return_value=context):
            app._send_daily_ssl_report()
            Clock.current += datetime.timedelta(days=1)
            app._send_daily_ssl_report()

        messages = [call.args[0] for call in self.sender.call_args_list]
        self.assertIn("ksot.nipigas.ru — осталось 5д.", messages[0])
        self.assertIn("ksot.nipigas.ru — осталось 4д.", messages[1])

    def test_renewed_certificate_does_not_send_old_warning(self):
        with patch.object(app, "_check_ssl_sync", return_value=(90, True)):
            app._send_daily_ssl_report()
        self.sender.assert_not_called()

    def test_failed_check_never_reuses_old_countdown(self):
        with patch.object(app, "_check_ssl_sync", return_value=(-1, None)):
            app._send_daily_ssl_report()
        self.sender.assert_not_called()

    def test_invalid_certificate_with_unknown_expiry_is_only_logged(self):
        with patch.object(app, "_check_ssl_sync", return_value=(-1, False)), \
                patch("builtins.print") as log:
            app._send_daily_ssl_report()
        self.sender.assert_not_called()
        self.assertIn("[SSL REPORT SKIP]", log.call_args.args[0])
        self.assertIn("ошибка проверки сертификата", log.call_args.args[0])

    def test_none_expiry_is_not_sent(self):
        with patch.object(app, "_check_ssl_sync", return_value=(None, None)):
            app._send_daily_ssl_report()
        self.sender.assert_not_called()

    def test_mixed_checks_send_only_confirmed_expiry(self):
        self.cursor.fetchall.return_value = [
            ("unknown.example",), ("broken.example",), ("soon.example",), ("renewed.example",)
        ]
        with patch.object(app, "_check_ssl_sync",
                          side_effect=[(-1, None), (-1, False), (4, True), (90, True)]):
            app._send_daily_ssl_report()
        self.sender.assert_called_once()
        message = self.sender.call_args.args[0]
        self.assertIn("soon.example — осталось 4д.", message)
        for excluded in ("unknown.example", "broken.example", "renewed.example",
                         "актуальный срок неизвестен", "Проблемы проверки SSL"):
            self.assertNotIn(excluded, message)

    def test_exception_does_not_prevent_remaining_site_alert(self):
        self.cursor.fetchall.return_value = [("failed.example",), ("soon.example",)]
        with patch.object(app, "_check_ssl_sync",
                          side_effect=[TimeoutError("private detail"), (5, True)]), \
                patch("builtins.print") as log:
            app._send_daily_ssl_report()
        self.sender.assert_called_once()
        self.assertIn("soon.example", self.sender.call_args.args[0])
        self.assertNotIn("failed.example", self.sender.call_args.args[0])
        self.assertIn("TimeoutError", log.call_args.args[0])
        self.assertNotIn("private detail", log.call_args.args[0])

    def test_threshold_boundaries(self):
        for days in (0, 20, 21):
            with self.subTest(days=days):
                self.sender.reset_mock()
                with patch.object(app, "_check_ssl_sync", return_value=(days, True)):
                    app._send_daily_ssl_report()
                self.assertEqual(self.sender.call_count, int(days <= 20))

    def test_disabled_report_performs_no_io(self):
        with patch.object(app, "TG_SSL_REPORT_ENABLED", False), \
                patch.object(app, "_check_ssl_sync") as check:
            app._send_daily_ssl_report()
        self.connection.cursor.assert_not_called()
        check.assert_not_called()
        self.sender.assert_not_called()

    def test_only_active_ssl_enabled_non_self_sites_are_selected(self):
        self.cursor.fetchall.return_value = []
        app._send_daily_ssl_report()
        sql = self.cursor.execute.call_args.args[0]
        self.assertIn("is_active = TRUE", sql)
        self.assertIn("site_group != 'self'", sql)
        self.assertIn("COALESCE(ssl_verify, TRUE) = TRUE", sql)
        self.assertNotIn("latest_status", sql)
        self.connection.close.assert_called_once()
        self.sender.assert_not_called()

    def test_database_failure_closes_connection(self):
        self.cursor.execute.side_effect = RuntimeError("database unavailable")
        with self.assertRaises(RuntimeError):
            app._send_daily_ssl_report()
        self.connection.close.assert_called_once()
        self.sender.assert_not_called()

    def test_domain_with_path(self):
        self.cursor.fetchall.return_value = [("example.org/cp/",)]
        with patch.object(app, "_check_ssl_sync", return_value=(4, True)) as check:
            app._send_daily_ssl_report()
        check.assert_called_once_with("example.org", "example.org/cp/")

    def test_many_expiry_alerts_fit_telegram_limit(self):
        self.cursor.fetchall.return_value = [(f"host-{i}.example.org",) for i in range(200)]
        with patch.object(app, "_check_ssl_sync", return_value=(5, True)):
            app._send_daily_ssl_report()
        messages = [call.args[0] for call in self.sender.call_args_list]
        self.assertGreater(len(messages), 1)
        self.assertTrue(all(len(message) <= 4000 for message in messages))
        for i in range(200):
            self.assertEqual("\n".join(messages).count(f"host-{i}.example.org"), 1)
        for call in self.sender.call_args_list:
            self.assertEqual(call.kwargs["category"], "ssl_report")


class BatchOwnershipTests(unittest.TestCase):
    def test_http_flush_does_not_overwrite_new_ssl_whois_values(self):
        conn = MagicMock()
        cur = conn.cursor.return_value
        # HTTP read 5 days; SSL worker has since written 4 days to latest_status.
        stale_batch = [("ksot.nipigas.ru", 200, 0.2, 5, 100, True)]
        with patch.object(app, "batch_buffer", stale_batch), \
                patch.object(app, "get_db_connection", return_value=conn), \
                patch.object(app, "execute_values"), \
                patch.object(app, "_update_checks_agg"):
            app._flush_batch_unlocked()
        sql = cur.execute.call_args.args[0]
        update_clause = sql.split("DO UPDATE SET", 1)[1]
        for field in ("ssl_days", "domain_days", "ssl_chain_valid"):
            self.assertNotIn(field, update_clause)
        self.assertIn("status = EXCLUDED.status", update_clause)
        self.assertIn("response_time = EXCLUDED.response_time", update_clause)
        self.assertIn("timestamp = EXCLUDED.timestamp", update_clause)
        conn.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
