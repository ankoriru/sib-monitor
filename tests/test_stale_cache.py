"""monitor.18: тяжёлая 30-дневная статистика держится в памяти и обновляется в фоне."""
import threading
import time
import unittest

import app


class StaleCacheTests(unittest.TestCase):
    def test_first_get_computes_once_for_concurrent_callers(self):
        calls = []

        def compute():
            calls.append(1)
            time.sleep(0.2)
            return {"v": len(calls)}

        cache = app._StaleCache("t", compute, ttl=60)
        results = []
        threads = [threading.Thread(target=lambda: results.append(cache.get())) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        self.assertEqual(len(calls), 1)
        self.assertEqual(results, [{"v": 1}] * 4)

    def test_stale_value_served_while_refreshing_in_background(self):
        release = threading.Event()
        calls = []
        refreshed = threading.Event()

        def compute():
            calls.append(1)
            if len(calls) > 1:
                release.wait(5)
            return {"v": len(calls)}

        cache = app._StaleCache("t", compute, ttl=60, on_refresh=refreshed.set)
        self.assertEqual(cache.get(), {"v": 1})
        cache.timestamp = 0  # устарело
        t0 = time.monotonic()
        self.assertEqual(cache.get(), {"v": 1})   # старое значение, без ожидания
        self.assertEqual(cache.get(), {"v": 1})   # второй фоновый расчёт не запускается
        self.assertLess(time.monotonic() - t0, 0.5)
        release.set()
        self.assertTrue(refreshed.wait(5))
        self.assertEqual(cache.get(), {"v": 2})
        self.assertEqual(len(calls), 2)

    def test_background_error_keeps_old_value(self):
        state = {"fail": False}

        def compute():
            if state["fail"]:
                raise RuntimeError("db down")
            return {"ok": True}

        cache = app._StaleCache("t", compute, ttl=60)
        cache.get()
        state["fail"] = True
        cache.timestamp = 0
        cache.get()
        for _ in range(50):
            if not cache._refreshing.locked():
                break
            time.sleep(0.02)
        self.assertEqual(cache.get(), {"ok": True})

    def test_dashboard_uses_cached_heavy_stats(self):
        self.assertIsInstance(app._heavy_stats, app._StaleCache)
        self.assertIsInstance(app._charts_cache, app._StaleCache)
        src = open(app.__file__, encoding="utf-8").read()
        body = src[src.index("def _build_dashboard_data():"):src.index("def _index_stream():")]
        self.assertIn("_get_heavy_stats()", body)
        self.assertNotIn("FROM checks_agg", body)


if __name__ == "__main__":
    unittest.main()
