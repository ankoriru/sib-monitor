import datetime
import ssl
import unittest
import unittest.mock
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

import external_checks
import tls_chain

NOW = datetime.datetime.now(datetime.timezone.utc)


def name(cn, org="Test CA", country="BE"):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make(subject, issuer_name, issuer_key, ca, key=None, aia=None, days=30, san=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - datetime.timedelta(days=1))
         .not_valid_after(NOW + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if aia:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))]),
            critical=False)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    return b.sign(issuer_key, hashes.SHA256()), key


class TlsChainTests(unittest.TestCase):
    def setUp(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root, _ = make(name("Test Root"), name("Test Root"), self.root_key, True, self.root_key)
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.inter, _ = make(name("Test OV CA 2025"), self.root.subject, self.root_key, True, self.int_key)
        self.leaf, _ = make(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "site.example")]),
                            self.inter.subject, self.int_key, False,
                            aia="http://ca.example/int.crt", san="site.example")
        for target, kw in (("_roots", {"new": [self.root]}), ("_intermediates", {"new": {}}),
                           ("_last_attempt", {"new": {}}), ("incomplete_chain", {"new": {}}),
                           ("_ctx", {"new": None})):
            p = patch.object(tls_chain, target, **kw)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(tls_chain, "_leaf_der", return_value=self.leaf.public_bytes(Encoding.DER))
        p.start(); self.addCleanup(p.stop)
        p = patch.object(tls_chain, "_verify_with_context", return_value=True)
        self.verify = p.start(); self.addCleanup(p.stop)

    def download(self, cert):
        return patch.object(tls_chain, "_download", return_value=cert.public_bytes(Encoding.DER))

    def test_repairs_missing_intermediate_via_aia(self):
        with self.download(self.inter):
            self.assertTrue(tls_chain.repair("site.example"))
        self.assertEqual(len(tls_chain._intermediates), 1)
        self.assertEqual(tls_chain.incomplete_chain["site.example"]["issuer"], "Test OV CA 2025")
        self.verify.assert_called_once()

    def test_rejects_intermediate_not_issued_by_trusted_root(self):
        rogue_key = ec.generate_private_key(ec.SECP256R1())
        rogue_root, _ = make(name("Rogue Root"), name("Rogue Root"), rogue_key, True, rogue_key)
        rogue_int, _ = make(name("Test OV CA 2025"), rogue_root.subject, rogue_key, True, self.int_key)
        with self.download(rogue_int):
            self.assertFalse(tls_chain.repair("site.example"))
        self.assertEqual(tls_chain._intermediates, {})
        self.verify.assert_not_called()

    def test_rejects_self_signed_fake_intermediate(self):
        fake, _ = make(name("Test OV CA 2025"), name("Test OV CA 2025"), self.int_key, True, self.int_key)
        with self.download(fake):
            self.assertFalse(tls_chain.repair("site.example"))
        self.assertEqual(tls_chain._intermediates, {})

    def test_rejects_non_ca_certificate(self):
        not_ca, _ = make(name("Test OV CA 2025"), self.root.subject, self.root_key, False, self.int_key)
        with self.download(not_ca):
            self.assertFalse(tls_chain.repair("site.example"))

    def test_failed_repair_is_rate_limited(self):
        with patch.object(tls_chain, "_download", return_value=b"") as dl:
            self.assertFalse(tls_chain.repair("site.example"))
            self.assertFalse(tls_chain.repair("site.example"))
        self.assertEqual(dl.call_count, 1)

    def test_private_aia_urls_refused(self):
        self.assertFalse(tls_chain._public_http_url("http://127.0.0.1/ca.crt"))
        self.assertFalse(tls_chain._public_http_url("http://10.0.0.5/ca.crt"))
        self.assertFalse(tls_chain._public_http_url("ftp://ca.example/ca.crt"))
        self.assertFalse(tls_chain._public_http_url("http://ca.example:8080/ca.crt"))

    def test_missing_issuer_detection(self):
        err = ssl.SSLCertVerificationError()
        err.verify_code, err.verify_message = 20, "unable to get local issuer certificate"
        self.assertTrue(tls_chain.is_missing_issuer(err))
        err.verify_code, err.verify_message = 10, "certificate has expired"
        self.assertFalse(tls_chain.is_missing_issuer(err))

    def test_globalping_incomplete_chain_accepted_only_for_known_issuer(self):
        with self.download(self.inter):
            tls_chain.repair("site.example")
        tls = {"authorized": False, "error": "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
               "issuer": {"C": "BE", "O": "Test CA", "CN": "Test OV CA 2025"},
               "subject": {"CN": "site.example", "alt": "DNS:site.example"},
               "expiresAt": (NOW + datetime.timedelta(days=30)).isoformat()}
        self.assertTrue(external_checks.incomplete_chain_only(tls, "site.example"))
        self.assertFalse(external_checks.incomplete_chain_only(tls, "other.example"))
        self.assertFalse(external_checks.incomplete_chain_only(
            dict(tls, issuer={"CN": "Unknown CA"}), "site.example"))
        self.assertFalse(external_checks.incomplete_chain_only(
            dict(tls, error="CERT_HAS_EXPIRED"), "site.example"))
        self.assertFalse(external_checks.incomplete_chain_only(
            dict(tls, expiresAt=(NOW - datetime.timedelta(days=1)).isoformat()), "site.example"))

    def test_shipped_bundle_is_trusted_by_system_roots(self):
        with patch.object(tls_chain, "_roots", None):
            self.assertEqual(tls_chain.load_bundle(), 2)
        self.assertTrue(tls_chain.known_issuer(
            {"C": "BE", "O": "GlobalSign nv-sa", "CN": "GlobalSign RSA OV SSL CA 2018"}))
        self.assertTrue(tls_chain.known_issuer(
            {"C": "BE", "O": "GlobalSign nv-sa", "CN": "GlobalSign GCC R46 OV TLS CA 2025"}))


if __name__ == "__main__":
    unittest.main()


class SslWorkerRetryTests(unittest.TestCase):
    def test_ssl_check_retries_after_aia_repair(self):
        import app
        err = ssl.SSLCertVerificationError("unable to get local issuer certificate")
        err.verify_code = 20
        good = unittest.mock.MagicMock()
        good.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = {
            "notAfter": (datetime.datetime.utcnow() + datetime.timedelta(days=40)).strftime(
                "%b %d %H:%M:%S %Y GMT")}
        bad = unittest.mock.MagicMock()
        bad.wrap_socket.side_effect = err
        with patch.object(app.socket, "create_connection"), \
                patch.object(app.tls_chain, "context", side_effect=[bad, good]), \
                patch.object(app.tls_chain, "repair", return_value=True) as repair:
            days, valid = app._check_ssl_sync("site.example", "site.example")
        repair.assert_called_once_with("site.example")
        self.assertTrue(valid)
        self.assertGreaterEqual(days, 39)

    def test_real_certificate_errors_still_fail(self):
        import app
        err = ssl.SSLCertVerificationError("certificate has expired")
        err.verify_code = 10
        bad = unittest.mock.MagicMock()
        bad.wrap_socket.side_effect = err
        with patch.object(app.socket, "create_connection"), \
                patch.object(app.tls_chain, "context", return_value=bad), \
                patch.object(app.tls_chain, "repair") as repair:
            self.assertEqual(app._check_ssl_sync("site.example", "site.example"), (-1, False))
        repair.assert_not_called()


class SelfSignedTests(unittest.TestCase):
    def setUp(self):
        key = ec.generate_private_key(ec.SECP256R1())
        self.cert, _ = make(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intra.example")]),
                            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intra.example")]),
                            key, False, key, san="intra.example", days=100)
        for target in ("tls_state", "_self_signed_info"):
            p = patch.dict(getattr(tls_chain, target), clear=True)
            p.start(); self.addCleanup(p.stop)
        p = patch.object(tls_chain, "_leaf_der", return_value=self.cert.public_bytes(Encoding.DER))
        p.start(); self.addCleanup(p.stop)

    def test_self_signed_error_detection(self):
        err = ssl.SSLCertVerificationError()
        err.verify_code, err.verify_message = 18, "self-signed certificate"
        self.assertTrue(tls_chain.is_self_signed_error(err))
        err.verify_code, err.verify_message = 19, "self-signed certificate in certificate chain"
        self.assertTrue(tls_chain.is_self_signed_error(err))
        err.verify_code, err.verify_message = 20, "unable to get local issuer certificate"
        self.assertFalse(tls_chain.is_self_signed_error(err))

    def test_valid_self_signed_is_acceptable(self):
        info = tls_chain.inspect_self_signed("intra.example")
        self.assertTrue(info["acceptable"])
        self.assertGreaterEqual(info["days"], 99)
        self.assertIsNone(tls_chain.self_signed_problem(info))

    def test_hostname_mismatch_rejected(self):
        info = tls_chain.inspect_self_signed("other.example")
        self.assertFalse(info["acceptable"])
        self.assertIn("имени сайта", tls_chain.self_signed_problem(info))

    def test_expired_self_signed_rejected(self):
        key = ec.generate_private_key(ec.SECP256R1())
        old, _ = make(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intra.example")]),
                      x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intra.example")]),
                      key, False, key, san="intra.example", days=-1)
        with patch.object(tls_chain, "_leaf_der", return_value=old.public_bytes(Encoding.DER)):
            info = tls_chain.inspect_self_signed("intra.example")
        self.assertIn("просрочен", tls_chain.self_signed_problem(info))

    def test_ssl_worker_returns_days_and_marks_site(self):
        import app
        err = ssl.SSLCertVerificationError("self-signed certificate")
        err.verify_code = 18
        bad = unittest.mock.MagicMock()
        bad.wrap_socket.side_effect = err
        with patch.object(app.socket, "create_connection"), \
                patch.object(app.tls_chain, "context", return_value=bad):
            days, chain = app._check_ssl_sync("intra.example", "intra.example")
        self.assertGreaterEqual(days, 99)
        self.assertIsNone(chain)  # не ошибка цепочки
        self.assertTrue(tls_chain.is_self_signed("intra.example"))
        tls_chain.mark_trusted("intra.example")
        self.assertFalse(tls_chain.is_self_signed("intra.example"))

    def test_globalping_self_signed_accepted_and_marked(self):
        tls = {"authorized": False, "error": "DEPTH_ZERO_SELF_SIGNED_CERT",
               "subject": {"CN": "intra.example", "alt": "DNS:intra.example"},
               "expiresAt": (NOW + datetime.timedelta(days=30)).isoformat()}
        self.assertTrue(external_checks.self_signed_acceptable(tls, "intra.example"))
        self.assertTrue(tls_chain.is_self_signed("intra.example"))
        self.assertFalse(external_checks.self_signed_acceptable(tls, "x.example"))
        self.assertFalse(external_checks.self_signed_acceptable(
            dict(tls, expiresAt=(NOW - datetime.timedelta(days=1)).isoformat()), "intra.example"))
        self.assertFalse(external_checks.self_signed_acceptable(
            dict(tls, error="CERT_HAS_EXPIRED"), "intra.example"))


class SelfSignedHttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_check_online_with_badge_state(self):
        import aiohttp
        import app
        err = ssl.SSLCertVerificationError("self-signed certificate")
        err.verify_code = 18
        exc = aiohttp.ClientConnectorCertificateError(
            unittest.mock.MagicMock(host="intra.example", port=443, ssl=True), err)
        ok = unittest.mock.MagicMock(status=200)
        calls = []

        class CM:
            def __init__(self, ssl_arg):
                self.ssl_arg = ssl_arg

            async def __aenter__(self):
                calls.append(self.ssl_arg)
                if self.ssl_arg is not False:
                    raise exc
                return ok

            async def __aexit__(self, *a):
                return False

        session = unittest.mock.MagicMock()
        session.get.side_effect = lambda *a, **kw: CM(kw["ssl"])
        with patch.dict(tls_chain.tls_state, clear=True), \
                patch.object(app.tls_chain, "inspect_self_signed",
                             return_value={"acceptable": True, "valid_now": True,
                                           "hostname_ok": True, "days": 50}):
            site, status, _, error = await app.check_single_site(
                session, "intra.example", __import__("asyncio").Semaphore(1))
            self.assertTrue(tls_chain.is_self_signed("intra.example"))
        self.assertEqual((status, error), (200, None))
        self.assertEqual(calls[-1], False)

    async def test_http_check_rejects_expired_self_signed(self):
        import aiohttp
        import app
        err = ssl.SSLCertVerificationError("self-signed certificate")
        err.verify_code = 18
        exc = aiohttp.ClientConnectorCertificateError(
            unittest.mock.MagicMock(host="intra.example", port=443, ssl=True), err)

        class CM:
            async def __aenter__(self):
                raise exc

            async def __aexit__(self, *a):
                return False

        session = unittest.mock.MagicMock()
        session.get.side_effect = lambda *a, **kw: CM()
        with patch.dict(tls_chain.tls_state, clear=True), \
                patch.object(app.tls_chain, "inspect_self_signed",
                             return_value={"acceptable": False, "valid_now": False,
                                           "hostname_ok": True, "days": -3}):
            _, status, _, error = await app.check_single_site(
                session, "intra.example", __import__("asyncio").Semaphore(1))
        self.assertEqual(status, 0)
        self.assertIn("просрочен", error)


class SelfSignedDashboardTests(unittest.TestCase):
    def test_row_shows_badge_and_is_not_error(self):
        import app
        from test_check_diagnostics import dashboard_fixture
        data = dashboard_fixture()
        row = data["latest"]["offline.example"]
        row.update(status=200, check_error=None, ssl_chain_valid=None, ssl_self_signed=True, ssl_days=200)
        with patch.dict(tls_chain.tls_state, clear=True):
            html = app._build_body(data)
        self.assertIn("самоподписанный сертификат", html)
        part = html[html.index("offline.example"):]
        part = part[:part.index("</tr>")]
        self.assertIn("Online", part)
        self.assertIn("⚠️", part)
        self.assertNotIn("❌", part)
        with patch.dict(tls_chain.tls_state, {"offline.example": "trusted"}, clear=True):
            self.assertNotIn("самоподписанный сертификат", app._build_body(data))


class PrivateCaTests(unittest.TestCase):
    def setUp(self):
        for target in ("tls_state", "_self_signed_info", "pending_changes"):
            p = patch.dict(getattr(tls_chain, target), clear=True)
            p.start(); self.addCleanup(p.stop)

    def tls(self, **kw):
        base = {"protocol": "TLSv1.3", "authorized": False, "error": "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
                "issuer": {"CN": "SiburInfrastructureCAG1"},
                "subject": {"CN": "cp.tdms.sibur.ru", "alt": "DNS:cp.tdms.sibur.ru"},
                "expiresAt": (NOW + datetime.timedelta(days=375)).isoformat()}
        base.update(kw)
        return base

    def test_globalping_private_ca_is_self_signed_not_error(self):
        days, chain, self_signed = external_checks.tls_verdict(self.tls(), "cp.tdms.sibur.ru")
        self.assertGreaterEqual(days, 374)
        self.assertIsNone(chain)
        self.assertTrue(self_signed)
        self.assertEqual(tls_chain.drain_changes(), {"cp.tdms.sibur.ru": True})

    def test_known_public_intermediate_is_trusted_not_self_signed(self):
        tls = self.tls(issuer={"C": "BE", "O": "GlobalSign nv-sa", "CN": "GlobalSign RSA OV SSL CA 2018"},
                       subject={"CN": "lsdts.sibur.ru", "alt": "DNS:lsdts.sibur.ru"})
        self.assertEqual(external_checks.tls_verdict(tls, "lsdts.sibur.ru")[1:], (True, False))

    def test_authorized_and_failed_verdicts(self):
        self.assertEqual(external_checks.tls_verdict(self.tls(authorized=True, error=None),
                                                     "cp.tdms.sibur.ru")[1:], (True, False))
        self.assertEqual(external_checks.tls_verdict(self.tls(error="CERT_HAS_EXPIRED"),
                                                     "cp.tdms.sibur.ru")[1:], (False, False))
        self.assertIsNone(external_checks.tls_verdict({"protocol": ""}, "x.ru"))

    def test_direct_ssl_check_private_ca_after_failed_aia(self):
        import app
        err = ssl.SSLCertVerificationError("unable to get local issuer certificate")
        err.verify_code = 20
        bad = unittest.mock.MagicMock()
        bad.wrap_socket.side_effect = err
        with patch.object(app.socket, "create_connection"), \
                patch.object(app.tls_chain, "context", return_value=bad), \
                patch.object(app.tls_chain, "repair", return_value=False), \
                patch.object(app.tls_chain, "inspect_self_signed",
                             return_value={"acceptable": True, "days": 300}):
            self.assertEqual(app._check_ssl_sync("cp.tdms.sibur.ru", "cp.tdms.sibur.ru/cp/"), (300, None))
        self.assertTrue(tls_chain.is_self_signed("cp.tdms.sibur.ru"))

    def test_ssl_worker_uses_external_when_unreachable(self):
        import app
        with patch.object(app, "_check_ssl_sync", return_value=(-1, None)), \
                patch.object(app, "_check_ssl_external", return_value=((120, True, False), None)) as ext:
            self.assertEqual(app._check_ssl_with_fallback("srm.sibur.ru", "srm.sibur.ru", verify_ssl=True),
                             (120, True))
            ext.assert_called_once_with("srm.sibur.ru")
            # Отключённая проверка SSL и реальная ошибка сертификата не подменяются.
            ext.reset_mock()
            app._check_ssl_with_fallback("srm.sibur.ru", "srm.sibur.ru", verify_ssl=False)
        with patch.object(app, "_check_ssl_sync", return_value=(-1, False)), \
                patch.object(app, "_check_ssl_external") as ext2:
            app._check_ssl_with_fallback("srm.sibur.ru", "srm.sibur.ru")
            ext2.assert_not_called()
        ext.assert_not_called()

    def test_marks_persisted_for_sites_with_paths(self):
        import app
        tls_chain.mark_self_signed("cp.tdms.sibur.ru")
        conn = unittest.mock.MagicMock()
        with patch.object(app, "get_db_connection", return_value=conn), \
                patch.object(app, "_invalidate_dashboard_cache"):
            app._persist_tls_marks(["cp.tdms.sibur.ru/cp/", "sibur.ru"])
        conn.cursor.return_value.execute.assert_called_once_with(
            "UPDATE latest_status SET ssl_self_signed = %s WHERE site = %s", (True, "cp.tdms.sibur.ru/cp/"))
        self.assertEqual(tls_chain.drain_changes(), {})
