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
