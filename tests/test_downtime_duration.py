import datetime
import unittest
from unittest.mock import patch

import app

HOST = "career.example"


class DowntimeDurationTests(unittest.TestCase):
    def setUp(self):
        for name, kw in (("_db_incident_start", {}), ("_db_incident_update", {}),
                         ("_send_screenshot_async", {}), ("_invalidate_dashboard_cache", {}),
                         ("batch_buffer", {"new": []}), ("BATCH_SIZE", {"new": 1000})):
            p = patch.object(app, name, **kw)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(app, "send_tg_msg", return_value=True)
        self.tg = p.start()
        self.addCleanup(p.stop)
        self.last, self.fails, self.first = {}, {}, {}

    def run_check(self, status):
        app._process_site_result(HOST, status, .1, 90, 100, True, self.last, self.fails,
                                 {}, {HOST: 5}, self.first)

    def up_message(self):
        return [c.args[0] for c in self.tg.call_args_list if "UP:" in c.args[0]][-1]

    def test_unknown_checks_during_incident_do_not_reset_duration(self):
        with patch.object(app, "_db_incident_resolve", return_value=None):
            for _ in range(5):
                self.run_check(502)
            self.first[HOST] -= datetime.timedelta(minutes=23)
            self.run_check(app.CHECK_UNKNOWN)
            self.run_check(502)
            self.run_check(200)
        self.assertIn("Был недоступен: 23 мин.", self.up_message())

    def test_db_incident_duration_preferred(self):
        with patch.object(app, "_db_incident_resolve", return_value=28):
            for _ in range(5):
                self.run_check(502)
            self.run_check(200)
        self.assertIn("Был недоступен: 28 мин.", self.up_message())

    def test_never_reports_zero_minutes(self):
        with patch.object(app, "_db_incident_resolve", return_value=None):
            self.last[HOST] = 502  # инцидент без сведений о начале (например, после сбоя состояния)
            self.run_check(200)
        self.assertNotIn(": 0 мин.", self.up_message())


if __name__ == "__main__":
    unittest.main()
