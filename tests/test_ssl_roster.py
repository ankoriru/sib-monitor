"""SSL startup must not depend on the HTTP worker populating global SITES."""
import unittest
from unittest.mock import MagicMock, patch

import app


class StopWorker(BaseException):
    pass


class SSLRosterTests(unittest.TestCase):
    def test_roster_reads_active_database_sites_and_closes_connection(self):
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = [("ksot.nipigas.ru", True), ("disabled-ssl.example", False)]
        with patch.object(app, "get_db_connection", return_value=conn):
            result = app._load_ssl_check_sites()
        self.assertEqual(result, cur.fetchall.return_value)
        sql = cur.execute.call_args.args[0]
        self.assertIn("WHERE is_active = TRUE", sql)
        self.assertIn("COALESCE(ssl_verify, TRUE)", sql)
        conn.close.assert_called_once()

    def test_failed_roster_read_closes_connection(self):
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.execute.side_effect = RuntimeError("db")
        with patch.object(app, "get_db_connection", return_value=conn):
            with self.assertRaises(RuntimeError):
                app._load_ssl_check_sites()
        conn.close.assert_called_once()

    def test_startup_checks_database_only_site_and_persists_fresh_days(self):
        conn = MagicMock()

        def sleep(seconds):
            if seconds == 4 * 3600:
                raise StopWorker()

        with patch.object(app, "SITES", ["legacy.example"]), \
                patch.object(app, "_load_ssl_check_sites",
                             return_value=[("ksot.nipigas.ru", True)]), \
                patch.object(app, "_check_ssl_sync", return_value=(3, True)) as check, \
                patch.object(app, "_check_whois_sync", return_value=100), \
                patch.object(app, "get_db_connection", return_value=conn), \
                patch.object(app, "_invalidate_dashboard_cache") as invalidate, \
                patch.object(app.time, "sleep", side_effect=sleep), \
                patch.object(app.asyncio, "new_event_loop"), \
                patch.object(app.asyncio, "set_event_loop"):
            with self.assertRaises(StopWorker):
                app.ssl_whois_worker()
        check.assert_called_once_with("ksot.nipigas.ru", "ksot.nipigas.ru", verify_ssl=True)
        self.assertEqual(conn.cursor.return_value.execute.call_args.args[1],
                         ("ksot.nipigas.ru", 3, 100, True))
        conn.commit.assert_called_once()
        invalidate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
