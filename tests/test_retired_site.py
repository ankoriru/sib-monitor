"""Retired site cannot return through defaults or startup diagnostics."""
import unittest

import app
import external_checks
import network_diagnostics


class RetiredSiteTests(unittest.TestCase):
    def test_not_in_default_monitoring_or_diagnostic_rosters(self):
        for roster in (app.SITES, app.STDO_SITES, app.KEY_SITES, app.EXTERNAL_SITES,
                       app.TIMEOUT_EXPERIMENT_SITES, external_checks.SITES,
                       network_diagnostics.TIMEOUT_SITES):
            with self.subTest(roster=roster):
                self.assertFalse(any("tst-stdo.tdms.sibur.ru" in site for site in roster))

    def test_no_replacement_path_was_added(self):
        self.assertNotIn("tst-stdo.tdms.sibur.ru/cp/component/main", app.SITES)
