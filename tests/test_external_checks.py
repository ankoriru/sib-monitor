"""No real network, production DB or Telegram calls."""
import asyncio
import copy
import datetime
import re
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import app
import external_checks as ec
from test_check_diagnostics import dashboard_fixture


HOST = "eshop.sibur.ru"


def measurement(http=200, tls=True, body="sibur login", path="/", **overrides):
    result = dict(status="finished", statusCode=http, tls={"authorized": tls, "protocol": "TLSv1.2"},
                  rawBody=body, timings={"total": 80}, headers={})
    result.update(overrides)
    return dict(type="http", target=HOST, status="finished", createdAt=ec.utcnow(),
                measurementOptions={"request": {"path": path}},
                results=[{"probe": {"country": "RU", "network": "Test network", "asn": 123},
                          "result": result}])


def parsed(data, verify=True, pattern=None, path="/"):
    return ec.parse_measurement(data, HOST, path, verify, pattern)[0][0]


class InterpretationTests(unittest.TestCase):
    def test_verified_200(self):
        row = parsed(measurement())
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["response_time"], .08)

    def test_api_omits_default_root_path(self):
        data = measurement()
        del data["measurementOptions"]["request"]["path"]
        self.assertEqual(parsed(data)["status"], 200)

    def test_401_is_available_without_content_match(self):
        self.assertEqual(parsed(measurement(401))["status"], 200)
        self.assertEqual(parsed(measurement(401, body=""), pattern=re.compile("sibur"))["status"], 200)

    def test_403_not_success(self):
        self.assertEqual(parsed(measurement(403))["status"], 403)

    def test_tls_failure_not_success(self):
        self.assertEqual(parsed(measurement(tls=False))["status"], 703)
        self.assertEqual(parsed(measurement(tls=False), verify=False)["status"], 200)

    def test_tls_evidence_required_even_when_verify_disabled(self):
        data = measurement()
        data["results"][0]["result"]["tls"] = {}
        self.assertEqual(parsed(data, verify=False)["status"], 702)

    def test_content_match_required(self):
        pattern = re.compile("sibur", re.I)
        self.assertEqual(parsed(measurement(body="unrelated"), pattern=pattern)["status"], 701)
        self.assertEqual(parsed(measurement(body=None), pattern=pattern)["status"], 702)
        self.assertEqual(parsed(measurement(body="unrelated", truncated=True), pattern=pattern)["status"], 702)
        self.assertEqual(parsed(measurement(body="SIBUR", truncated=True), pattern=pattern)["status"], 200)

    def test_redirect_not_automatically_healthy(self):
        data = measurement(302, headers={"location": "/login"})
        rows, redirects, _ = ec.parse_measurement(data, HOST, "/", True, None)
        self.assertEqual(rows[0]["status"], 702)
        self.assertEqual(redirects, {"/login"})

    def test_unsafe_redirects_blocked(self):
        for location in ["http://eshop.sibur.ru/", "//other.test/login", "/?token=x",
                         "https://user:pass@eshop.sibur.ru/", "https://eshop.sibur.ru:444/",
                         "/#secret", "https://eshop.sibur.ru:broken/"]:
            with self.subTest(location=location):
                self.assertIsNone(ec.public_redirect(HOST, "/", location))
        self.assertEqual(ec.public_redirect(HOST, "/", "/login"), "/login")

    def test_stale_and_wrong_measurements_rejected(self):
        for key, value in [
            ("createdAt", "2020-01-01T00:00:00Z"), ("createdAt", "bad"),
            ("target", "other.test"), ("status", "in-progress"), ("type", "ping"),
            ("measurementOptions", {"request": {"path": "/wrong"}}),
        ]:
            data = measurement()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                parsed(data)

    def test_transport_errors_are_unknown(self):
        self.assertEqual(parsed(measurement(None, status="failed"))["status"], 702)

    def test_only_network_failures_eligible(self):
        self.assertTrue(ec.network_failure(0, "Таймаут: запрос"))
        self.assertTrue(ec.network_failure(0, "DNS: ошибка"))
        for status, reason in [(403, "HTTP 403"), (701, "Content Match"),
                               (0, "TLS: ошибка"), (200, None), (0, None)]:
            self.assertFalse(ec.network_failure(status, reason))

    def test_private_or_sensitive_targets_not_sent(self):
        for site in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "[::1]",
                     "intranet", "host.internal", "host.corp", "foo.local",
                     "example.org/?token=x", "user:secret@example.org",
                     "example.org:443", "example.org\\@127.0.0.1", "example.org/\nsecret"]:
            self.assertFalse(ec.public_site(site), site)
        for site in ["sibur.ru", "cp.tdms.sibur.ru/cp/", "resti.club"]:
            self.assertTrue(ec.public_site(site), site)

    def test_bodies_headers_and_cookies_not_persisted(self):
        row = parsed(measurement(body="private body", headers={"set-cookie": "secret"}))
        self.assertNotIn("private body", str(row))
        self.assertNotIn("secret", str(row))


class CheckerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.checker = ec.ExternalChecker()
        self.session = MagicMock()

    async def test_redirect_is_actually_checked(self):
        self.checker.measurement = AsyncMock(side_effect=[
            ("firstMeasurement", measurement(302, headers={"location": "/login"})),
            ("secondMeasurement", measurement(path="/login")),
        ])
        result = await self.checker.get(self.session, HOST)
        self.assertEqual(result["status"], 200)
        self.assertEqual(len(result["measurements"]), 2)
        self.assertEqual(self.checker.measurement.call_args.args[2], "/login")

    async def test_verified_success_from_one_point_is_enough(self):
        data = measurement()
        bad = copy.deepcopy(data["results"][0])
        bad["result"].update(status="failed", statusCode=None)
        data["results"].insert(0, bad)
        self.checker.measurement = AsyncMock(return_value=("testMeasurement", data))
        self.assertEqual((await self.checker.get(self.session, HOST))["status"], 200)

    async def test_cache_used_and_policy_change_rechecked(self):
        self.checker.measurement = AsyncMock(return_value=("testMeasurement", measurement()))
        first = await self.checker.get(self.session, HOST)
        cached = await self.checker.get(self.session, HOST)
        self.assertFalse(first["cached"])
        self.assertTrue(cached["cached"])
        self.checker.measurement.assert_awaited_once()
        await self.checker.get(self.session, HOST, verify_ssl=False)
        self.assertEqual(self.checker.measurement.await_count, 2)

    async def test_expired_success_not_reused_when_api_fails(self):
        self.checker.measurement = AsyncMock(return_value=("testMeasurement", measurement()))
        await self.checker.get(self.session, HOST)
        key = next(iter(self.checker.cache))
        old_time, saved = self.checker.cache[key]
        self.checker.cache[key] = (old_time - ec.INTERVAL - 1, saved)
        self.checker.measurement.side_effect = TimeoutError()
        result = await self.checker.get(self.session, HOST)
        self.assertEqual(result["status"], 702)
        self.assertFalse(result["cached"])

    async def test_measurement_age_expires_before_cache_age(self):
        self.checker.measurement = AsyncMock(return_value=("testMeasurement", measurement()))
        await self.checker.get(self.session, HOST)
        key = next(iter(self.checker.cache))
        self.checker.cache[key][1]["checked_at"] = "2020-01-01T00:00:00+00:00"
        self.checker.measurement.side_effect = TimeoutError()
        self.assertEqual((await self.checker.get(self.session, HOST))["status"], 702)

    async def test_unknown_target_rejected(self):
        self.checker.fresh = AsyncMock()
        self.assertEqual((await self.checker.get(self.session, "other.test"))["status"], 702)
        self.checker.fresh.assert_not_awaited()

    async def test_api_error_not_leaked(self):
        self.checker.fresh = AsyncMock(side_effect=RuntimeError("https://user:pass@test/?token=x"))
        result = await self.checker.get(self.session, HOST)
        self.assertNotIn("token", str(result))
        self.assertEqual(result["status"], 702)

    async def test_direct_success_and_unapproved_site_do_not_call_api(self):
        self.checker.get = AsyncMock()
        rows = [(HOST, 200, .1, None), ("other.test", 0, 30, "Таймаут: запрос"),
                ("tms.sibur.ru", 403, .1, "HTTP 403"),
                ("srm.sibur.ru", 0, 1, "TLS: ошибка")]
        self.assertEqual(await self.checker.apply(self.session, rows, {}, set(), None), rows)
        self.checker.get.assert_not_awaited()

    async def test_disabled_switch(self):
        self.checker.get = AsyncMock()
        rows = [(HOST, 0, 30, "Таймаут: запрос")]
        with patch.object(ec, "ENABLED", False):
            self.assertEqual(await self.checker.apply(self.session, rows, {}, set(), None), rows)
        self.checker.get.assert_not_awaited()

    async def test_all_active_public_sites_eligible_not_just_original_nine(self):
        self.checker.get = AsyncMock(return_value={
            "verdict": "unknown", "status": 702, "response_time": 0,
            "checked_at": ec.utcnow(), "probes": [], "measurements": [], "cached": False})
        rows = [("sibur.ru", 0, 8, "DNS: ошибка")]
        result = await self.checker.apply(self.session, rows, {}, set(), None)
        self.checker.get.assert_awaited_once()
        self.assertEqual(result[0][1], 702)

    async def test_apply_preserves_direct_result_and_obeys_policy(self):
        self.checker.measurement = AsyncMock(return_value=("testMeasurement", measurement()))
        pattern = re.compile("sibur")
        rows = await self.checker.apply(
            self.session, [(HOST, 0, 30, "Таймаут: запрос")], {HOST: True}, {HOST}, pattern)
        self.assertEqual(rows[0][1], 200)
        self.assertEqual(rows[0][4]["direct"]["status"], 0)
        self.assertIn("Amvera", rows[0][3])
        self.assertEqual(rows[0][4]["external"]["probes"][0]["reason"], "Content Match подтверждён")

    async def test_hop_limit(self):
        async def response(session, host, path):
            return "testMeasurement", measurement(302, path=path, headers={"location": path + "next"})
        self.checker.measurement = AsyncMock(side_effect=response)
        self.assertEqual((await self.checker.get(self.session, HOST))["status"], 702)
        self.assertEqual(self.checker.measurement.await_count, ec.MAX_HOPS)

    async def test_budget_and_cooldown(self):
        self.checker.spent.extend([time.monotonic()] * ec.HOURLY_BUDGET)
        with self.assertRaises(RuntimeError):
            self.checker.reserve()
        self.checker.spent.clear()
        self.checker.cooldown = time.monotonic() + 30
        with self.assertRaises(RuntimeError):
            self.checker.reserve()

    async def test_rate_limit_backoff(self):
        response = MagicMock(status=429, headers={"Retry-After": "120"})
        self.session.request.return_value.__aenter__ = AsyncMock(return_value=response)
        self.session.request.return_value.__aexit__ = AsyncMock(return_value=False)
        with self.assertRaises(RuntimeError):
            await self.checker.api(self.session, "POST", ec.API, {})
        self.assertGreater(self.checker.cooldown, time.monotonic() + 100)


class PersistenceAndPresentationTests(unittest.TestCase):
    def test_unknown_neither_creates_nor_resolves_incident(self):
        with patch.object(app, "batch_buffer", []), \
                patch.object(app, "send_tg_msg") as tg, \
                patch.object(app, "_db_incident_start") as start, \
                patch.object(app, "_db_incident_resolve") as resolve:
            fails = {HOST: 10}
            app._process_site_result(HOST, 702, 0, 30, 100, True,
                                     {HOST: 0}, fails, {}, {HOST: 5}, {},
                                     "Не подтверждено", {"source": "globalping"})
            self.assertEqual(fails[HOST], 0)
            self.assertEqual(app.batch_buffer[0][1], 702)
            tg.assert_not_called()
            start.assert_not_called()
            resolve.assert_not_called()

    def test_unknown_excluded_from_uptime_and_downtime(self):
        cur = MagicMock()
        app._update_checks_agg(cur, [(HOST, 702, 0, 30, 100, True)])
        cur.execute.assert_not_called()
        conn = MagicMock()
        with patch.object(app, "get_db_connection", return_value=conn), \
                patch.object(app, "execute_values") as logs, \
                patch.object(app, "batch_buffer", [(HOST, 702, 0, 30, 100, True, "Нет данных", {})]):
            app._flush_batch_unlocked()
        logs.assert_not_called()
        self.assertIn("latest_status", conn.cursor.return_value.execute.call_args_list[0].args[0])

    def test_details_stored_and_cleared_after_direct_recovery(self):
        conn = MagicMock()
        with patch.object(app, "get_db_connection", return_value=conn), \
                patch.object(app, "execute_values"), patch.object(app, "_update_checks_agg"), \
                patch.object(app, "batch_buffer", [(HOST, 200, .1, 30, 100, True, None, {})]):
            app._flush_batch_unlocked()
        self.assertEqual(conn.cursor.return_value.execute.call_args.args[1], (None, HOST))

    def test_fresh_external_success_resolves_preexisting_incident(self):
        with patch.object(app, "batch_buffer", []), \
                patch.object(app, "_db_incident_resolve") as resolve:
            app._process_site_result(
                HOST, 200, .1, 30, 100, True, {HOST: 200}, {}, {}, {HOST: 5}, {},
                "Доступен из внешней точки",
                {"source": "globalping", "external": {"cached": False}})
        resolve.assert_called_once_with(HOST)

    def test_dashboard_external_not_silent_green(self):
        data = dashboard_fixture()
        row = data["latest"]["offline.example"]
        row.update(status=200, check_error="Amvera: Таймаут; Globalping: OK",
                   check_details={"source": "globalping", "external": {"probes": [], "measurements": []}})
        html = app._build_body(data)
        self.assertIn("Online (внешняя точка)", html)
        self.assertIn("Amvera: Таймаут", html)

    def test_dashboard_unknown_is_not_offline(self):
        data = dashboard_fixture()
        data["latest"]["offline.example"].update(status=702, check_error="Нет внешних данных")
        html = app._build_body(data)
        self.assertIn("Не подтверждено", html)
        self.assertNotIn(">Offline<", html)
        self.assertIn("не подтверждено: 1", html)

    def test_external_probe_metadata_is_escaped(self):
        data = dashboard_fixture()
        data["latest"]["offline.example"].update(
            status=200, check_details={"source": "globalping", "external": {
                "probes": [{"network": "<script>alert(1)</script>"}],
                "measurements": ['"><script>']}})
        html = app._build_body(data)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
