import datetime
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
        app._latency_started.clear()
        app._latency_max.clear()
        self.addCleanup(app._latency_max.clear)
        self.addCleanup(app._latency_streak.clear)
        self.addCleanup(app._latency_started.clear)
        for name, kwargs in (
            ("send_tg_msg", {}),
            ("_db_incident_start", {}),
            ("_db_incident_resolve", {}),
            ("_send_screenshot_async", {}),
            ("_invalidate_dashboard_cache", {}),
            ("batch_buffer", {"new": []}),
            ("BATCH_SIZE", {"new": 1000}),
            ("_db_latency_start", {}),
            ("_db_latency_update", {}),
            ("_db_latency_end", {"return_value": None}),
        ):
            p = patch.object(app, name, **kwargs)
            value = p.start()
            self.addCleanup(p.stop)
            if name == "send_tg_msg":
                self.telegram = value
            elif name == "_db_incident_start":
                self.incident = value
            elif name == "_db_latency_start":
                self.db_start = value
            elif name == "_db_latency_update":
                self.db_update = value
            elif name == "_db_latency_end":
                self.db_end = value

    def sample(self, elapsed, status=200, threshold=1):
        app._process_site_result(
            "latency.example", status, elapsed, 90, 100, True,
            self.last_status, self.fail_count, self.latency,
            {"latency.example": threshold}, self.first_fail)

    def messages(self):
        return [c.args[0] for c in self.telegram.call_args_list]

    def test_first_check_up_to_15_seconds_inclusive_does_not_start_latency(self):
        for elapsed in (0, 5, 10, 10.01, 14.99, 15):
            with self.subTest(elapsed=elapsed):
                self.sample(elapsed)
                self.telegram.assert_not_called()
                self.assertNotIn("latency.example", app._latency_streak)
                self.assertFalse(self.latency.get("latency.example", False))
        self.incident.assert_not_called()

    def test_single_slow_check_is_not_reported(self):
        self.sample(40)
        self.telegram.assert_not_called()
        self.assertFalse(self.latency.get("latency.example", False))
        self.sample(3)
        self.sample(40)
        self.sample(10)  # повтор не дольше 10 с — не подтверждение
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

    def test_above_15_then_two_above_10_alerts_once_on_third_check(self):
        self.sample(15.01)
        self.telegram.assert_not_called()
        self.sample(10.02)
        self.telegram.assert_not_called()
        self.assertFalse(self.latency.get("latency.example", False))
        self.sample(10.01)
        self.telegram.assert_called_once()
        self.assertIn("ЗАДЕРЖКА", self.telegram.call_args.args[0])
        self.assertIn("10.01", self.telegram.call_args.args[0])
        self.assertTrue(self.latency["latency.example"])
        self.sample(26)
        self.sample(10.5)
        self.sample(40)
        self.telegram.assert_called_once()
        self.incident.assert_not_called()

    def test_two_slow_checks_are_not_enough(self):
        self.sample(20)
        self.sample(12)
        self.assertEqual(app._latency_streak["latency.example"][0], 2)
        self.sample(10)  # третья проверка не дольше 10 с — задержка не подтверждена
        self.telegram.assert_not_called()
        self.assertNotIn("latency.example", app._latency_streak)
        self.db_start.assert_not_called()

    def test_failure_on_third_check_breaks_confirmation(self):
        self.sample(20, threshold=5)
        self.sample(12, threshold=5)
        self.sample(0, status=0, threshold=5)
        self.sample(12, threshold=5)
        self.assertFalse(any("ЗАДЕРЖКА" in m for m in self.messages()))

    def test_third_check_above_15_also_confirms(self):
        self.sample(20)
        self.sample(25)
        self.sample(29)
        self.assertIn("ЗАДЕРЖКА", self.messages()[0])

    def test_two_checks_between_10_and_15_do_not_alert(self):
        for elapsed in (12, 14, 14.99, 11, 13):
            self.sample(elapsed)
        self.telegram.assert_not_called()

    def test_boundary_fluctuations_do_not_create_message_spam(self):
        for elapsed in (16, 10, 9, 15, 5, 12):
            self.sample(elapsed)
        self.telegram.assert_not_called()
        for elapsed in (16, 11, 12, 10.5, 15, 20, 11):
            self.sample(elapsed)
        self.telegram.assert_called_once()
        self.assertTrue(self.latency["latency.example"])

    def test_recovery_at_10_seconds_inclusive(self):
        self.sample(16)
        self.sample(11)
        self.sample(10.01)
        self.assertEqual(self.telegram.call_count, 1)
        self.sample(10)
        self.assertEqual(self.telegram.call_count, 2)
        self.assertIn("СКОРОСТЬ ВОССТАНОВЛЕНА", self.telegram.call_args.args[0])
        self.assertFalse(self.latency["latency.example"])
        self.sample(9)
        self.sample(14)
        self.assertEqual(self.telegram.call_count, 2)

    def test_fast_check_resets_pending_latency(self):
        self.sample(30)
        self.assertIn("latency.example", app._latency_streak)
        self.sample(10)
        self.assertNotIn("latency.example", app._latency_streak)

    def test_recovery_reports_duration_from_first_slow_check(self):
        self.sample(30)
        first_slow = app._latency_streak["latency.example"][1]
        self.sample(12)
        self.sample(12)
        self.assertEqual(app._latency_started["latency.example"], first_slow)
        # Задержка началась 17 минут назад — с первой медленной проверки.
        app._latency_started["latency.example"] = (
            datetime.datetime.now() - datetime.timedelta(minutes=17, seconds=20))
        self.sample(10.5)  # дольше 10 с — задержка продолжается
        self.assertEqual(self.telegram.call_count, 1)
        self.sample(2)
        text = self.telegram.call_args.args[0]
        self.assertIn("СКОРОСТЬ ВОССТАНОВЛЕНА", text)
        self.assertIn("Задержка длилась: 17 мин.", text)
        self.assertNotIn("latency.example", app._latency_started)

    def test_short_latency_duration_is_at_least_one_minute(self):
        self.sample(30)
        self.sample(30)
        self.sample(30)
        self.sample(1)
        self.assertIn("Задержка длилась: 1 мин.", self.telegram.call_args.args[0])

    def test_recovery_without_known_start_has_no_duration(self):
        self.latency["latency.example"] = True  # задержка была до перезапуска
        self.sample(1)
        text = self.telegram.call_args.args[0]
        self.assertIn("СКОРОСТЬ ВОССТАНОВЛЕНА", text)
        self.assertNotIn("длилась", text)

    def test_down_during_latency_closes_it_without_double_message(self):
        self.sample(20)
        self.sample(12)
        self.sample(12)
        self.assertTrue(self.latency["latency.example"])
        self.sample(0, status=0)  # порог 1 — сразу DOWN
        self.assertFalse(self.latency["latency.example"])
        self.assertNotIn("latency.example", app._latency_started)
        self.db_end.assert_called_once_with("latency.example", "down")
        self.sample(1)
        msgs = self.messages()
        self.assertEqual(len(msgs), 3)
        self.assertIn("ЗАДЕРЖКА", msgs[0])
        self.assertIn("DOWN", msgs[1])
        self.assertIn("UP", msgs[2])
        self.assertFalse(any("СКОРОСТЬ ВОССТАНОВЛЕНА" in m for m in msgs))

    def test_short_failure_below_down_threshold_keeps_latency(self):
        self.sample(20, threshold=5)
        self.sample(12, threshold=5)
        self.sample(12, threshold=5)
        self.sample(0, status=0, threshold=5)
        self.assertTrue(self.latency["latency.example"])
        self.db_end.assert_not_called()
        self.sample(2, threshold=5)
        self.assertIn("СКОРОСТЬ ВОССТАНОВЛЕНА", self.messages()[-1])
        self.db_end.assert_called_once_with("latency.example", "recovered")

    def test_latency_is_recorded_in_history(self):
        self.sample(20)
        first_slow = app._latency_streak["latency.example"][1]
        self.sample(13)
        self.db_start.assert_not_called()
        self.sample(12)
        self.db_start.assert_called_once_with("latency.example", first_slow, 12)
        self.sample(11)      # не выше максимума — без записи
        self.db_update.assert_not_called()
        self.sample(25)
        self.db_update.assert_called_once_with("latency.example", 25)
        self.sample(3)
        self.db_end.assert_called_once_with("latency.example", "recovered")

    def test_restored_latency_uses_db_duration(self):
        self.latency["latency.example"] = True
        self.db_end.return_value = 42
        self.sample(1)
        self.assertIn("Задержка длилась: 42 мин.", self.messages()[-1])

    def test_dashboard_marks_confirmed_latency_below_start_threshold(self):
        data = dashboard_fixture()
        data["latest"]["online.example"].update(response_time=12, ssl_days=90)
        data["latency_events"] = [dict(site="online.example", start_time=app.datetime.datetime.now(),
                                       resolved=False, end_reason=None, max_response=20.5, dur=7)]
        html = app._build_body(data)
        self.assertIn("Задержка 12с, 7 мин", html)
        self.assertIn("Задержки (30 дней)", html)
        self.assertIn("Идёт", html)
        self.assertIn("20.5с", html)

    def test_dashboard_latency_history_statuses(self):
        data = dashboard_fixture()
        now = app.datetime.datetime.now()
        data["latency_events"] = [
            dict(site="online.example", start_time=now, resolved=True, end_reason="recovered",
                 max_response=18.0, dur=3),
            dict(site="offline.example", start_time=now, resolved=True, end_reason="down",
                 max_response=None, dur=5),
        ]
        html = app._build_body(data)
        self.assertIn("Завершена", html)
        self.assertIn("Перешла в простой", html)
        self.assertNotIn("Задержка 18", html)
        self.assertEqual(html.count('<div id="t3"'), 1)
        t3 = html[html.index('<div id="t3"'):html.index('<div id="t4"')]
        self.assertIn("Задержки (30 дней)", t3)

    def test_dashboard_without_latency_history(self):
        html = app._build_body(dashboard_fixture())
        self.assertIn("Задержек не было", html)

    def test_network_failure_still_creates_down_alert(self):
        self.sample(24, status=0)
        self.telegram.assert_called_once()
        self.assertIn("DOWN", self.telegram.call_args.args[0])
        self.incident.assert_called_once()
        self.assertFalse(self.latency.get("latency.example", False))

    def test_dashboard_uses_the_same_inclusive_boundary(self):
        for elapsed, warning in ((10.01, False), (14.99, False),
                                 (15, False), (15.01, True), (26, True)):
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
