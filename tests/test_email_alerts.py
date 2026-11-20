import datetime
import unittest
from unittest.mock import patch

import pytz

import app
import email_alerts as ea

T0 = datetime.datetime(2026, 11, 20, 10, 0, 0)
CFG = {"enabled": True, "recipients": ["sap_sm@sibur.ru"], "after_min": 15}
SMTP = {"host": "smtp.example", "port": 587, "security": "starttls", "user": "",
        "password": "", "from": "monitor@example.ru", "timeout": 5}


class SyncExecutor:
    def submit(self, fn, *args):
        fn(*args)


class AlerterTests(unittest.TestCase):
    def setUp(self):
        self.sent, self.log, self.fail_send = [], [], False

        def sender(msg, cfg):
            if self.fail_send:
                return False, "SMTP down"
            self.sent.append(msg)
            return True, None

        self.al = ea.EmailAlerter(sender=sender, on_result=lambda *a: self.log.append(a),
                                  executor=SyncExecutor(), unknown_status=-1,
                                  config=lambda: SMTP, incident_lookup=lambda s: 42)

    def tick(self, minute, status=502, cfg=CFG, **kw):
        return self.al.observe("srm.sibur.ru", status, cfg,
                               now=T0 + datetime.timedelta(minutes=minute),
                               fail_start=T0, reason="HTTP 502: ошибка шлюза", **kw)

    def test_no_mail_before_threshold_then_exactly_once(self):
        for m in range(15):
            self.assertIsNone(self.tick(m))
        self.assertEqual(self.tick(15), "down")
        for m in range(16, 40):
            self.assertIsNone(self.tick(m))
        self.assertEqual(len(self.sent), 1)
        self.assertIn("[ИНЦИДЕНТ] srm.sibur.ru недоступен более 15 мин", self.sent[0]["Subject"])
        self.assertEqual(self.sent[0]["To"], "sap_sm@sibur.ru")

    def test_recovery_mail_threads_to_incident(self):
        self.tick(15)
        self.assertEqual(self.tick(42, status=200), "up")
        self.assertEqual(len(self.sent), 2)
        up = self.sent[1]
        self.assertIn("[ВОССТАНОВЛЕН] srm.sibur.ru доступен, простой 42 мин", up["Subject"])
        self.assertEqual(up["In-Reply-To"], self.sent[0]["Message-ID"])
        self.assertIsNone(self.tick(43, status=200))

    def test_short_outage_sends_nothing(self):
        for m in range(10):
            self.tick(m)
        self.assertIsNone(self.tick(10, status=200))
        self.assertEqual(self.sent, [])

    def test_switch_off_and_global_switch(self):
        self.assertIsNone(self.tick(20, cfg=dict(CFG, enabled=False)))
        self.assertIsNone(self.tick(21, global_enabled=False))
        self.assertIsNone(self.tick(22, cfg=dict(CFG, recipients=[])))
        self.assertEqual(self.sent, [])
        self.assertEqual(self.tick(23), "down")

    def test_unknown_result_is_ignored(self):
        self.tick(15)
        self.assertIsNone(self.tick(16, status=-1))
        self.assertIsNotNone(self.al.state("srm.sibur.ru"))

    def test_failed_send_is_retried_after_pause(self):
        self.fail_send = True
        self.assertEqual(self.tick(15), "down")
        self.fail_send = False
        self.assertIsNone(self.tick(16))  # пауза между повторами 5 минут
        self.assertEqual(self.tick(20), "down")
        self.assertEqual(len(self.sent), 1)
        self.assertEqual([r[4] for r in self.log], [False, True])

    def test_seed_after_restart_avoids_duplicate(self):
        self.al.seed("srm.sibur.ru", T0 - datetime.timedelta(minutes=30), down_sent=True,
                     message_id="<x@y>", recipients=["sap_sm@sibur.ru"])
        self.assertIsNone(self.tick(1))
        self.assertEqual(self.tick(5, status=200), "up")
        self.assertIn("простой 35 мин", self.sent[0]["Subject"])

    def test_incident_number_in_mail(self):
        self.tick(15)
        self.assertIn("#42", self.sent[0].get_body(("plain",)).get_content())


class FormatTests(unittest.TestCase):
    def test_parse_recipients(self):
        self.assertEqual(ea.parse_recipients("sap_sm@sibur.ru; a@b.ru, A@B.ru"),
                         ["sap_sm@sibur.ru", "a@b.ru"])
        self.assertEqual(ea.parse_recipients(""), [])
        with self.assertRaises(ValueError):
            ea.parse_recipients("not-an-email")

    def test_after_min_bounds(self):
        self.assertEqual(ea.validated_after_min("15"), 15)
        for bad in (0, 1441, "x"):
            with self.assertRaises(ValueError):
                ea.validated_after_min(bad)

    def test_down_message_contents(self):
        info = {"site": "tms.sibur.ru", "status": 0, "reason": "Таймаут: запрос не завершён",
                "started_at": T0, "detected_at": T0 + datetime.timedelta(minutes=15),
                "after_min": 15, "category": "Ключевые", "incident_id": 7}
        msg = ea.build_down_message(info, ["sap_sm@sibur.ru"], "monitor@example.ru")
        text = msg.get_body(("plain",)).get_content()
        html = msg.get_body(("html",)).get_content()
        for part in ("https://tms.sibur.ru", "НЕДОСТУПЕН", "15 мин", "Таймаут", "Ключевые", "#7"):
            self.assertIn(part, text)
            self.assertIn(part, html)
        self.assertEqual(msg["X-Priority"], "1")
        self.assertNotIn("globalping", (text + html).lower())

    def test_html_escapes_reason(self):
        info = {"site": "a.ru", "status": 502, "reason": "<script>", "started_at": T0,
                "detected_at": T0 + datetime.timedelta(minutes=20), "after_min": 15}
        html = ea.build_down_message(info, ["x@y.ru"], "m@y.ru").get_body(("html",)).get_content()
        self.assertNotIn("<script>", html)

    def test_moscow_time(self):
        ts = pytz.utc.localize(T0)
        self.assertEqual(ea._fmt_ts(ts, pytz.timezone("Europe/Moscow")), "20.11.2026 13:00:00 МСК")

    def test_smtp_not_configured(self):
        ok, err = ea.send_message(ea.build_test_message(["x@y.ru"], ""), ea.smtp_config({}))
        self.assertFalse(ok)
        self.assertIn("SMTP_HOST", err)

    def test_public_status_hides_password(self):
        st = ea.smtp_public_status({"SMTP_HOST": "h", "SMTP_FROM": "f@x.ru", "SMTP_PASSWORD": "secret"})
        self.assertTrue(st["configured"])
        self.assertNotIn("secret", str(st))


class WorkerIntegrationTests(unittest.TestCase):
    """_process_site_result передаёт результаты в e-mail оповещения и не ломает TG-логику."""

    def setUp(self):
        for name in ("_db_incident_start", "_db_incident_update", "_send_screenshot_async",
                     "_invalidate_dashboard_cache"):
            p = patch.object(app, name)
            p.start()
            self.addCleanup(p.stop)
        for name, new in (("batch_buffer", []), ("BATCH_SIZE", 1000),
                          ("EMAIL_ALERT_CFG", {"srm.sibur.ru": CFG}), ("EMAIL_ALERTS_ENABLED", True)):
            p = patch.object(app, name, new)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(app, "send_tg_msg", return_value=True)
        self.tg = p.start()
        self.addCleanup(p.stop)
        p = patch.object(app, "_db_incident_resolve", return_value=None)
        p.start()
        self.addCleanup(p.stop)
        self.sent = []
        alerter = ea.EmailAlerter(sender=lambda m, c: (self.sent.append(m) or (True, None)),
                                  executor=SyncExecutor(), unknown_status=app.CHECK_UNKNOWN,
                                  config=lambda: SMTP)
        p = patch.object(app, "email_alerter", alerter)
        p.start()
        self.addCleanup(p.stop)
        self.last, self.fails, self.first = {}, {}, {}

    def run_check(self, status, site="srm.sibur.ru"):
        app._process_site_result(site, status, .1, 90, 100, True, self.last, self.fails,
                                 {}, {site: 5}, self.first, check_error="HTTP 502: ошибка шлюза")

    def test_mail_after_15_minutes_and_on_recovery(self):
        self.run_check(502)
        self.first["srm.sibur.ru"] -= datetime.timedelta(minutes=16)
        self.run_check(502)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("ИНЦИДЕНТ", self.sent[0]["Subject"])
        self.run_check(200)
        self.assertEqual(len(self.sent), 2)
        self.assertIn("ВОССТАНОВЛЕН", self.sent[1]["Subject"])

    def test_site_without_email_settings_is_untouched(self):
        self.run_check(502, site="other.example")
        self.first["other.example"] -= datetime.timedelta(minutes=60)
        self.run_check(502, site="other.example")
        self.run_check(200, site="other.example")
        self.assertEqual(self.sent, [])

    def test_email_failure_does_not_break_worker(self):
        with patch.object(app.email_alerter, "observe", side_effect=RuntimeError("boom")):
            for _ in range(5):
                self.run_check(502)
        self.assertTrue(any("DOWN:" in c.args[0] for c in self.tg.call_args_list))


if __name__ == "__main__":
    unittest.main()
