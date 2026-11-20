"""monitor.17: главная страница не запускает тяжёлые SQL параллельно и без
коррелированного подзапроса к site_categories на каждую строку checks_agg."""
import os
import threading
import time
import unittest
from unittest.mock import patch

import app

APP_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


class DashboardBuildTests(unittest.TestCase):
    def setUp(self):
        with app._dashboard_cache["lock"]:
            app._dashboard_cache["data"] = None
            app._dashboard_cache["timestamp"] = 0

    def test_concurrent_requests_share_one_build(self):
        calls = []

        def slow_build():
            calls.append(1)
            time.sleep(0.3)
            data = {"n": len(calls)}
            with app._dashboard_cache["lock"]:
                app._dashboard_cache["data"] = data
                app._dashboard_cache["timestamp"] = time.time()
            return data

        bodies = []
        with patch.object(app, "_build_dashboard_data", slow_build), \
                patch.object(app, "_build_head", lambda: "HEAD"), \
                patch.object(app, "_build_body", lambda d: f"BODY{d['n']}"):
            threads = [threading.Thread(target=lambda: bodies.append(list(app._index_stream())))
                       for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(5)
        self.assertEqual(len(calls), 1)
        self.assertEqual(bodies, [["HEAD", "BODY1"]] * 4)

    def test_stale_cache_is_rebuilt(self):
        calls = []

        def build():
            calls.append(1)
            return {"n": len(calls)}

        with app._dashboard_cache["lock"]:
            app._dashboard_cache["data"] = {"n": 0}
            app._dashboard_cache["timestamp"] = 0  # сброшен воркером при смене статуса
        with patch.object(app, "_build_dashboard_data", build), \
                patch.object(app, "_build_head", lambda: "HEAD"), \
                patch.object(app, "_build_body", lambda d: f"BODY{d['n']}"):
            self.assertEqual(list(app._index_stream()), ["HEAD", "BODY1"])
        self.assertEqual(len(calls), 1)

    def test_no_per_row_category_subquery(self):
        with open(APP_SRC, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("(SELECT sort_order FROM site_categories WHERE id = ms.site_group)", src)
        self.assertIn("WITH per_site AS", src)


if __name__ == "__main__":
    unittest.main()
