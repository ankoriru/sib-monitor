"""Расписание и выполнение обслуживания checks_agg (monitor.19)."""
import datetime
import os
import unittest
import uuid

import pytz

import db_maintenance as m

MSK = pytz.timezone("Europe/Moscow")


def msk(y, mo, d, h, mi):
    return MSK.localize(datetime.datetime(y, mo, d, h, mi))


class DueActionTests(unittest.TestCase):
    # 2026-11-22 — воскресенье.
    def test_first_run_is_full(self):
        self.assertEqual(m.due_action(msk(2026, 11, 21, 3, 5), None, None), "full")

    def test_nothing_due_right_after_full(self):
        full = msk(2026, 11, 21, 3, 5)
        self.assertIsNone(m.due_action(msk(2026, 11, 21, 3, 6), None, full))

    def test_daily_analyze_after_slot(self):
        full = msk(2026, 11, 21, 3, 25)
        self.assertIsNone(m.due_action(msk(2026, 11, 22, 3, 19), None, full))
        self.assertEqual(m.due_action(msk(2026, 11, 22, 3, 20), None, full), "analyze")

    def test_analyze_once_per_day(self):
        full = msk(2026, 11, 21, 3, 5)
        done = msk(2026, 11, 22, 3, 20)
        self.assertIsNone(m.due_action(msk(2026, 11, 22, 4, 0), done, full))

    def test_weekly_full_on_sunday(self):
        full = msk(2026, 11, 21, 3, 5)
        analyze = msk(2026, 11, 22, 3, 20)
        self.assertIsNone(m.due_action(msk(2026, 11, 22, 4, 29), analyze, full))
        self.assertEqual(m.due_action(msk(2026, 11, 22, 4, 30), analyze, full), "full")

    def test_missed_slot_runs_later(self):
        full = msk(2026, 11, 14, 4, 31)
        self.assertEqual(m.due_action(msk(2026, 11, 24, 12, 0), None, full), "full")

    def test_utc_timestamps_compare(self):
        full = datetime.datetime(2026, 11, 22, 1, 31, tzinfo=datetime.timezone.utc)  # 04:31 МСК
        self.assertIsNone(m.due_action(msk(2026, 11, 22, 5, 0), None, full))

    def test_retention_not_applied_forces_full(self):
        full = msk(2026, 11, 21, 3, 25)
        self.assertEqual(m.due_action(msk(2026, 11, 21, 3, 30), full, full, retention_done=False), "full")
        self.assertIsNone(m.due_action(msk(2026, 11, 21, 3, 30), full, full, retention_done=True))

    def test_retention_floor(self):
        self.assertGreaterEqual(m.RETENTION_DAYS, 31)
        self.assertEqual(m.RETENTION_DAYS, 90)

    def test_parse_ts(self):
        self.assertIsNone(m._parse_ts(None))
        self.assertIsNone(m._parse_ts("мусор"))
        self.assertEqual(m._parse_ts("2026-11-21T00:00:00").tzinfo, datetime.timezone.utc)


class _Cur:
    def __init__(self, fail_on=None, reloptions=None):
        self.sql = []
        self.fail_on = fail_on
        self.reloptions = reloptions
        self._last = None
        self.rowcount = 0

    def execute(self, q, vars=None):
        self.sql.append(q)
        self._last = q
        if self.fail_on and self.fail_on in q:
            raise RuntimeError("lock timeout")

    def fetchone(self):
        if "reloptions" in self._last:
            return (self.reloptions,)
        if "pg_size_pretty" in self._last:
            return ("70 MB",)
        return None


class _Conn:
    def __init__(self, cur):
        self.cur = cur
        self.autocommit = False
        self.closed = False

    def cursor(self):
        assert self.autocommit, "VACUUM должен идти вне транзакции"
        return self.cur

    def close(self):
        self.closed = True


class RunTests(unittest.TestCase):
    def test_full_sets_options_and_meta(self):
        cur = _Cur()
        conn = _Conn(cur)
        logs = []
        ok = m.run(lambda: conn, "full", log=lambda *a, **k: logs.append(a[0]))
        self.assertTrue(ok)
        self.assertTrue(conn.closed)
        joined = "\n".join(cur.sql)
        self.assertIn("SET lock_timeout", joined)
        self.assertIn("ALTER TABLE checks_agg SET (", joined)
        self.assertIn("fillfactor = 80", joined)
        self.assertIn("VACUUM (FULL, ANALYZE) checks_agg", joined)
        self.assertIn("DELETE FROM checks_agg", joined)
        self.assertLess(joined.index("DELETE FROM checks_agg"), joined.index("VACUUM (FULL"))
        self.assertTrue(any(m.META_FULL in str(q) or "app_meta" in q for q in cur.sql))
        self.assertTrue(any("готово" in l for l in logs))

    def test_options_not_reapplied(self):
        opts = [f"{k}={v}" for k, v in m.TABLE_OPTIONS.items()]
        cur = _Cur(reloptions=opts)
        m.run(lambda: _Conn(cur), "analyze", log=lambda *a, **k: None)
        self.assertFalse(any(q.startswith("ALTER TABLE") for q in cur.sql))
        self.assertIn("VACUUM (ANALYZE) checks_agg", cur.sql)

    def test_failure_is_logged_not_raised(self):
        cur = _Cur(fail_on="VACUUM")
        conn = _Conn(cur)
        logs = []
        ok = m.run(lambda: conn, "full", log=lambda *a, **k: logs.append(a[0]))
        self.assertFalse(ok)
        self.assertTrue(conn.closed)
        self.assertTrue(any("[DB MAINT ERROR]" in l for l in logs))
        self.assertFalse(any("app_meta" in q for q in cur.sql))


@unittest.skipUnless(os.getenv("SIB_MONITOR_TEST_DSN"), "isolated PostgreSQL DSN not set")
class PostgreSQLMaintenanceTests(unittest.TestCase):
    def setUp(self):
        import psycopg2
        self.psycopg2 = psycopg2
        self.dsn = os.environ["SIB_MONITOR_TEST_DSN"]
        self.schema = "test_maint_" + uuid.uuid4().hex
        admin = psycopg2.connect(self.dsn)
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute(f"CREATE SCHEMA {self.schema}")
        admin.close()
        self.addCleanup(self._drop)
        conn = self.conn()
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE app_meta (key TEXT PRIMARY KEY, value TEXT, updated_at TIMESTAMP)")
            cur.execute("CREATE TABLE checks_agg (site TEXT, bucket TIMESTAMP, checks_count INT, "
                        "PRIMARY KEY (site, bucket))")
            # 5000 строк за последние ~17 дней и 3000 строк старше 90 дней.
            cur.execute("INSERT INTO checks_agg SELECT 's' || (g % 10), "
                        "date_trunc('minute', NOW()) - g * INTERVAL '5 min', 1 FROM generate_series(1, 5000) g")
            cur.execute("INSERT INTO checks_agg SELECT 'old' || (g % 10), "
                        "NOW() - INTERVAL '91 days' - g * INTERVAL '5 min', 1 FROM generate_series(1, 3000) g")
            for _ in range(5):
                cur.execute("UPDATE checks_agg SET checks_count = checks_count + 1")
        conn.commit()
        conn.close()

    def conn(self):
        return self.psycopg2.connect(self.dsn, options=f"-c search_path={self.schema}")

    def _drop(self):
        admin = self.psycopg2.connect(self.dsn)
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute(f"DROP SCHEMA {self.schema} CASCADE")
        admin.close()

    def test_full_then_schedule(self):
        m.DELETE_BATCH, saved = 700, m.DELETE_BATCH  # несколько порций
        self.addCleanup(setattr, m, "DELETE_BATCH", saved)
        now = msk(2026, 11, 21, 3, 5)
        self.assertEqual(m.run_if_due(self.conn, now, log=lambda *a, **k: None), "full")
        conn = self.conn()
        with conn.cursor() as cur:
            cur.execute("SELECT reloptions FROM pg_class WHERE oid = 'checks_agg'::regclass")
            self.assertIn("fillfactor=80", cur.fetchone()[0])
            cur.execute("SELECT COUNT(*), SUM(checks_count) FROM checks_agg")
            self.assertEqual(cur.fetchone(), (5000, 30000))
        conn.close()
        self.assertIsNone(m.run_if_due(self.conn, msk(2026, 11, 21, 3, 10), log=lambda *a, **k: None))
        self.assertEqual(m.run_if_due(self.conn, msk(2026, 11, 22, 3, 21), log=lambda *a, **k: None),
                         "analyze")


if __name__ == "__main__":
    unittest.main()
