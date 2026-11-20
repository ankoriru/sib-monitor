"""monitor.16: обработчики, читающие БД, не должны выполняться в event loop.

Синхронный вызов psycopg2 внутри `async def` останавливает весь сервер, пока база
не ответит: зависают даже /health и /favicon.ico. Такие обработчики должны быть
обычными `def` (FastAPI выполняет их в пуле потоков) или выносить БД в asyncio.to_thread.
"""
import ast
import asyncio
import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import AsyncMock, MagicMock, patch

import app

APP_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


def _route_functions():
    with open(APP_SRC, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    return tree, funcs


class EventLoopSafetyTests(unittest.TestCase):
    def test_async_handlers_do_not_touch_db_directly(self):
        tree, _ = _route_functions()

        def direct_nodes(fn):
            """Узлы тела функции без вложенных def/lambda (их вызывают через asyncio.to_thread)."""
            stack = list(fn.body)
            while stack:
                n = stack.pop()
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    continue
                yield n
                stack.extend(ast.iter_child_nodes(n))

        offenders = []
        for node in tree.body:
            if not isinstance(node, ast.AsyncFunctionDef) or node.name == "startup_event":
                continue  # startup_event выполняется до приёма запросов
            for n in direct_nodes(node):
                if isinstance(n, ast.Call):
                    f = n.func
                    name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
                    if name in ("get_db_connection", "load_settings") or \
                            (name == "execute" and isinstance(f, ast.Attribute)):
                        offenders.append(node.name)
                        break
        self.assertEqual(offenders, [], "async-обработчики с синхронной БД блокируют event loop")

    def test_dashboard_stream_is_sync_generator(self):
        _, funcs = _route_functions()
        self.assertIsInstance(funcs["_index_stream"], ast.FunctionDef)
        self.assertIsInstance(funcs["index"], ast.FunctionDef)
        self.assertIsInstance(funcs["_admin_page_inner"], ast.FunctionDef)

    def test_json_body_helpers(self):
        req = MagicMock()
        req.json = AsyncMock(return_value={"a": 1})
        self.assertEqual(app._json_data(asyncio.run(app._json_body(req))), {"a": 1})
        req.json = AsyncMock(side_effect=ValueError("bad json"))
        body = asyncio.run(app._json_body(req))
        with self.assertRaises(ValueError):
            app._json_data(body)

    def test_slow_sql_is_logged(self):
        class Base:
            def execute(self, query, vars=None):
                return "done"
        timed = app._timed_cursor_class(Base)
        self.assertIs(timed, app._timed_cursor_class(Base))
        cur = timed()
        buf = io.StringIO()
        with patch.object(app, "SLOW_SQL_SEC", 0.0), redirect_stdout(buf):
            self.assertEqual(cur.execute("SELECT  1\n FROM t"), "done")
        self.assertIn("[SLOW SQL]", buf.getvalue())
        self.assertIn("SELECT 1 FROM t", buf.getvalue())
        buf = io.StringIO()
        with patch.object(app, "SLOW_SQL_SEC", 100.0), redirect_stdout(buf):
            cur.execute("SELECT 1")
        self.assertEqual(buf.getvalue(), "")

    def test_slow_http_middleware_passes_response_through(self):
        sent = []

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        async def send(msg):
            sent.append(msg)

        mw = app._SlowRequestLog(inner)
        buf = io.StringIO()
        with patch.object(app, "SLOW_HTTP_SEC", 0.0), redirect_stdout(buf):
            asyncio.run(mw({"type": "http", "method": "GET", "path": "/x"}, None, send))
        self.assertEqual([m["type"] for m in sent], ["http.response.start", "http.response.body"])
        self.assertIn("[SLOW HTTP]", buf.getvalue())
        self.assertIn("GET /x -> 204", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
