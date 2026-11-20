"""monitor.14: обработчики с синхронными запросами к БД не должны блокировать event loop.

Если async-обработчик вызывает get_db_connection()/cur.execute() напрямую, медленная база
останавливает весь сервер: /health и главная отвечают 502, после троббера — белая страница.
"""
import ast
import inspect
import pathlib
import unittest
import unittest.mock

import app

SRC = pathlib.Path(app.__file__).read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _blocking_db(node):
    for sub in ast.walk(node):
        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and sub is not node:
            continue
        if isinstance(sub, ast.Call):
            name = ast.unparse(sub.func)
            if name.endswith("get_db_connection") or name.endswith("cur.execute"):
                return True
    return False


class NonBlockingRoutesTests(unittest.TestCase):
    def test_get_routes_with_db_are_sync(self):
        offenders = []
        for node in TREE.body:
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            routes = [ast.unparse(d) for d in node.decorator_list]
            is_get = any(r.startswith("app.get(") for r in routes)
            # только прямые вызовы в теле, не во вложенных функциях, выполняемых в потоке
            direct = any(_blocking_db(stmt) for stmt in node.body
                         if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)))
            if is_get and direct:
                offenders.append(node.name)
        self.assertEqual(offenders, [], "GET-обработчики с синхронной БД в event loop")

    def test_dashboard_stream_runs_in_threadpool(self):
        self.assertFalse(inspect.isasyncgenfunction(app._index_stream))
        self.assertTrue(inspect.isgeneratorfunction(app._index_stream))
        self.assertFalse(inspect.iscoroutinefunction(app._admin_page_inner))

    def test_dashboard_error_instead_of_blank_page(self):
        with unittest.mock.patch.object(app, "_load_dashboard_data", side_effect=RuntimeError("db")):
            chunks = list(app._index_stream())
        self.assertEqual(len(chunks), 2)
        self.assertIn("Не удалось загрузить данные мониторинга", chunks[1])
        self.assertIn("location.reload()", chunks[1])

    def test_overlay_not_force_hidden(self):
        head = app._build_head()
        self.assertIn("Данные загружаются дольше обычного", head)
        self.assertNotIn("o.classList.add('hidden'); setTimeout(function(){o.remove();},600); }\n        }, 8000)", head)

    def test_dashboard_queries_have_timeout(self):
        self.assertIn("statement_timeout", inspect.getsource(app._load_dashboard_data_conn))


if __name__ == "__main__":
    unittest.main()
