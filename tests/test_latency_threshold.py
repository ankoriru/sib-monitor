import unittest
from unittest.mock import patch

import app
from test_check_diagnostics import dashboard_fixture


class LatencyThresholdTests(unittest.TestCase):
    def setUp(self):
        self.latency = {}
        self.last_status = {}
        self.fail_count = {}
        self.first_fail = {}
        app._latency_streak.clear()
        self.addCleanup(app._latency_streak.clear)
        for name, kwargs in (
            ("send_tg_msg", {}),
            ("_db_incident_start", {}),
            ("_db_incident_resolve", {}),
            ("_send_screenshot_async", {}),
            ("_invalidate_dashboard_cache", {}),
            ("batch_buffer", {"new": []}),
            ("BATCH_SIZE", {"new": 1000}),
        ):
            p = patch.object(app, name, **kwargs)
            value = p.start()
            self.addCleanup(p.stop)
            if name == "send_tg_msg":
                self.telegram = value
            elif name == "_db_incident_start":
                self.incident = value

    def sample(self, elapsed, status=200):
        app._process_site_result(
            "latency.example", status, elapsed, 90, 100, True,
            self.last_status, self.fail_count, self.latency,
            {"latency.example": 1}, self.first_fail)

    def test_up_to_25_seconds_inclusive_does_not_alert(self):
        for elapsed in (0, 10, 20, 20.01, 24.99, 25):
            with self.subTest(elapsed=elapsed):
                self.sample(elapsed)
                self.telegram.assert_not_called()
                self.assertFalse(self.latency.get("latency.example", False))
        self.incident.assert_not_called()

    def test_single_slow_check_is_not_reported(self):
        self.sample(40)
        self.telegram.assert_not_called()
        self.assertFalse(self.latency.get("latency.example", False))
        self.sample(3)
        self.sample(40)
        self.sample(25)
        self.telegram.assert_not_called()

    def test_slow_check_interrupted_by_failure_is_not_confirmed(self):
        self.sample(30)
        self.sample(0, status=0)
        self.telegram.reset_mock()
        self.sample(30)
        self.assertFalse(any("ЗАДЕРЖКА" in c.args[0] for c in self.telegram.call_args_list))

    def test_unknown_check_breaks_latency_confirmation(self):
        self.sample(30)
        self.sample(0, status=app.CHECK_UNKNOWN)
        self.sample(30)
        self.telegram.assert_not_called()

    def test_strictly_above_25_alerts_once_after_confirmation(self):
        self.sample(25.01)
        self.telegram.assert_not_called()
        self.sample(25.01)
        self.telegram.assert_called_once()
        self.assertIn("ЗАДЕРЖКА", self.telegram.call_args.args[0])
        self.assertIn("25.01", self.telegram.call_args.args[0])
        self.assertTrue(self.latency["latency.example"])
        self.sample(26)
        self.sample(40)
        self.telegram.assert_called_once()
        self.incident.assert_not_called()

    def test_boundary_fluctuations_do_not_create_message_spam(self):
        for elapsed in (26, 25, 24, 25.1, 10, 27):
            self.sample(elapsed)
        self.telegram.assert_not_called()
        for elapsed in (26, 27, 25, 24, 25.1, 10, 27, 28):
            self.sample(elapsed)
        self.telegram.assert_called_once()
        self.assertTrue(self.latency["latency.example"])

    def test_existing_recovery_hysteresis_is_preserved(self):
        self.sample(26)
        self.sample(26)
        self.sample(9.99)
        self.assertEqual(self.telegram.call_count, 2)
        self.assertIn("СКОРОСТЬ ВОССТАНОВЛЕНА", self.telegram.call_args.args[0])
        self.assertFalse(self.latency["latency.example"])
        self.sample(25)
        self.assertEqual(self.telegram.call_count, 2)

    def test_fast_check_resets_pending_latency(self):
        self.sample(30)
        self.assertIn("latency.example", app._latency_streak)
        self.sample(20)
        self.assertNotIn("latency.example", app._latency_streak)

    def test_network_failure_still_creates_down_alert(self):
        self.sample(24, status=0)
        self.telegram.assert_called_once()
        self.assertIn("DOWN", self.telegram.call_args.args[0])
        self.incident.assert_called_once()
        self.assertFalse(self.latency.get("latency.example", False))

    def test_dashboard_uses_the_same_inclusive_boundary(self):
        for elapsed, warning in ((20.01, False), (24.99, False),
                                 (25, False), (25.01, True), (26, True)):
            with self.subTest(elapsed=elapsed):
                data = dashboard_fixture()
                data["latest"]["online.example"].update(
                    response_time=elapsed, ssl_days=90)
                html = app._build_body(data)
                self.assertEqual("Задержка " in html, warning)
                if warning:
                    self.assertIn(f"Задержка {round(elapsed, 2)}с", html)

    def test_dashboard_does_not_label_failed_requests_as_latency(self):
        data = dashboard_fixture()
        data["latest"]["offline.example"]["response_time"] = 30
        self.assertNotIn("Задержка ", app._build_body(data))
