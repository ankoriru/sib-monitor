import asyncio
import datetime
import json
import unittest
from unittest.mock import MagicMock, patch

import app
import release_digest as rd

SAMPLE = """# Изменения

## 2026.11.09-monitor.13 — 2026-11-09
### Улучшения
- Завтрашнее.

## 2026.11.08-monitor.12 — 2026-11-08
### Исправлено
- Второй релиз:
  продолжение строки.
### Прочее
- Техническое.

## 2026.11.08-monitor.11 — 2026-11-08
### Улучшения
- Первый релиз.

## 2026.11.07-monitor.7 — 2026-11-07
### Улучшения
- Вчерашнее.
"""
MSK = app.TZ_MOSCOW


class DigestTextTests(unittest.TestCase):
    def setUp(self):
        self.rel = rd.parse_changelog(SAMPLE)

    def test_parse(self):
        self.assertEqual([r["version"] for r in self.rel],
                         ["2026.11.09-monitor.13", "2026.11.08-monitor.12",
                          "2026.11.08-monitor.11", "2026.11.07-monitor.7"])
        self.assertEqual(self.rel[1]["sections"]["Исправлено"], ["Второй релиз: продолжение строки."])

    def test_only_today_in_release_order(self):
        text = rd.build_digest(self.rel, datetime.date(2026, 11, 8))
        self.assertIn("08.11.2026", text)
        self.assertIn("Релизов: 2 (2026.11.08-monitor.11 → 2026.11.08-monitor.12)", text)
        self.assertNotIn("Вчерашнее", text)
        self.assertNotIn("Завтрашнее", text)
        self.assertLess(text.index("✨ Улучшения"), text.index("🐞 Исправлено"))
        self.assertLess(text.index("🐞 Исправлено"), text.index("🔧 Прочее"))

    def test_no_releases_no_message(self):
        self.assertIsNone(rd.build_digest(self.rel, datetime.date(2026, 11, 5)))
        self.assertIsNone(rd.build_digest([], datetime.date(2026, 11, 8)))

    def test_telegram_limit(self):
        many = [{"version": "v", "date": datetime.date(2026, 11, 8),
                 "sections": {"Улучшения": ["x" * 300] * 40}}]
        self.assertLessEqual(len(rd.build_digest(many, datetime.date(2026, 11, 8))), rd.TG_LIMIT)

    def test_due_from_2330_msk(self):
        self.assertFalse(rd.due(datetime.datetime(2026, 11, 8, 23, 29, tzinfo=MSK)))
        self.assertTrue(rd.due(datetime.datetime(2026, 11, 8, 23, 30, tzinfo=MSK)))
        self.assertTrue(rd.due(datetime.datetime(2026, 11, 8, 23, 59, tzinfo=MSK)))

    def test_repo_changelog_has_current_version(self):
        self.assertIn(app.APP_VERSION, [r["version"] for r in rd.load_releases()])


class FakeDb:
    def __init__(self):
        self.meta = {}
        self.cur = MagicMock()
        self._last = None

        def execute(sql, params=()):
            if sql.startswith("SELECT"):
                self._last = (self.meta[params[0]],) if params[0] in self.meta else None
            elif sql.startswith("INSERT"):
                self.meta.setdefault(params[0], params[1])
        self.cur.execute.side_effect = execute
        self.cur.fetchone.side_effect = lambda: self._last

    def connect(self):
        conn = MagicMock()
        conn.cursor.return_value = self.cur
        return conn


class DigestSendTests(unittest.TestCase):
    NOW = datetime.datetime(2026, 11, 8, 23, 30, tzinfo=MSK)

    def setUp(self):
        self.db = FakeDb()
        patches = [patch.object(app, "get_db_connection", side_effect=self.db.connect),
                   patch.object(app.release_digest, "load_releases",
                                return_value=rd.parse_changelog(SAMPLE))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_sent_once_per_day(self):
        with patch.object(app, "send_tg_msg", return_value=True) as tg:
            app._send_release_digest(self.NOW)
            app._send_release_digest(self.NOW)  # перезапуск/повторный цикл
        self.assertEqual(tg.call_count, 1)
        self.assertEqual(tg.call_args.kwargs["category"], "release_digest")
        self.assertEqual(self.db.meta["release_digest_2026-11-08"], "sent")

    def test_nothing_sent_without_releases(self):
        quiet = datetime.datetime(2026, 11, 5, 23, 30, tzinfo=MSK)
        with patch.object(app, "send_tg_msg") as tg:
            self.assertIsNone(app._send_release_digest(quiet))
        tg.assert_not_called()

    def test_failed_send_is_retried(self):
        with patch.object(app, "send_tg_msg", side_effect=[False, True]) as tg:
            app._send_release_digest(self.NOW)
            app._send_release_digest(self.NOW)
        self.assertEqual(tg.call_count, 2)

    def test_worker_waits_until_2330(self):
        class Stop(BaseException):
            pass
        times = iter([datetime.datetime(2026, 11, 8, 23, 0, tzinfo=MSK), self.NOW])

        class FakeDT(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return next(times)
        sleeps = []

        def sleep(sec):
            sleeps.append(sec)
            if sec >= 60 or len(sleeps) > 5:
                raise Stop()
        with patch.object(app.datetime, "datetime", FakeDT), \
             patch.object(app.time, "sleep", side_effect=sleep), \
             patch.object(app, "_send_release_digest") as send:
            with self.assertRaises(Stop):
                app.release_digest_worker()
        send.assert_called_once()
        self.assertEqual(sleeps[0], 30)


class HealthTimeoutTests(unittest.TestCase):
    def test_db_has_connect_timeout(self):
        with patch.object(app.psycopg2, "connect") as connect:
            app.get_db_connection()
        self.assertEqual(connect.call_args.kwargs["connect_timeout"], app.DB_CONNECT_TIMEOUT)
        self.assertLessEqual(app.DB_CONNECT_TIMEOUT, 15)

    def test_health_returns_503_when_db_hangs(self):
        async def run():
            async def hang(*a, **k):
                await asyncio.sleep(10)
            with patch.object(app, "DB_CONNECT_TIMEOUT", -4.9), \
                 patch.object(app.asyncio, "to_thread", side_effect=hang):
                return await app.health()
        resp = asyncio.run(run())
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(json.loads(resp.body)["version"], app.APP_VERSION)


if __name__ == "__main__":
    unittest.main()
