import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import app
import external_checks as ec
from check_targets import check_target
from test_check_diagnostics import dashboard_fixture
from test_external_checks import measurement


OLD = "tst-stdo.tdms.sibur.ru/cp/"
NEW = "tst-stdo.tdms.sibur.ru/cp/component/main"


class TargetTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_target_changes_but_history_key_does_not(self):
        session = MagicMock()
        response = MagicMock(status=401)
        response.text = AsyncMock(return_value="")
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        session.get.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await app.check_single_site(session, OLD, asyncio.Semaphore(1))
        self.assertEqual(session.get.call_args.args[0], "https://" + NEW)
        self.assertEqual(result[0], OLD)
        self.assertEqual(result[1], 200)

    async def test_external_target_changes_without_reclassifying_403(self):
        checker = ec.ExternalChecker()
        data = measurement(403, path="/cp/component/main")
        data["target"] = "tst-stdo.tdms.sibur.ru"
        checker.measurement = AsyncMock(return_value=("testMeasurement", data))
        result = await checker.get(MagicMock(), OLD)
        self.assertEqual(checker.measurement.call_args.args[1:],
                         ("tst-stdo.tdms.sibur.ru", "/cp/component/main"))
        self.assertEqual(result["status"], 403)

    async def test_target_change_invalidates_cache(self):
        checker = ec.ExternalChecker()
        checker.fresh = AsyncMock(return_value=dict(
            status=200, verdict="available", response_time=.1, checked_at=ec.utcnow(),
            probes=[], measurements=[], cached=False))
        await checker.get(MagicMock(), OLD)
        with patch.object(ec, "check_target", return_value=OLD):
            result = await checker.get(MagicMock(), OLD)
        self.assertEqual(checker.fresh.await_count, 2)
        self.assertFalse(result["cached"])

    def test_other_targets_unchanged(self):
        self.assertEqual(check_target("cp.tdms.sibur.ru/cp/"), "cp.tdms.sibur.ru/cp/")
        self.assertEqual(check_target(NEW), NEW)

    def test_dashboard_link_uses_new_target_and_keeps_history_stats(self):
        data = dashboard_fixture()
        data["latest"][OLD] = dict(status=403, response_time=.1, ssl_days=-1,
                                  domain_days=100, ssl_chain_valid=None,
                                  check_error="Globalping: HTTP 403",
                                  check_details={"source": "globalping"})
        data["sites_by_cat"]["external"].append(OLD)
        data["categories"][0]["sites"].append(OLD)
        data["stats"][OLD] = {"upt": 77.77, "down_sec": 120}
        html = app._build_body(data)
        self.assertIn(f'href="https://{NEW}"', html)
        self.assertIn(f"<strong>{NEW}</strong>", html)
        self.assertIn("77.77%", html)
        self.assertIn("HTTP 403: доступ запрещён", html)
