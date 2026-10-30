import contextlib
import io
import json
import socket
import ssl
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import network_diagnostics as diag


def events(output):
    return [json.loads(line[len(diag.PREFIX) + 1:])
            for line in output.splitlines() if line.startswith(diag.PREFIX + " ")]


class HTTPProbeTests(unittest.TestCase):
    def probe(self, reply=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
              dns_error=None, tcp_error=None, tls_error=None, http_error=None):
        output = io.StringIO()
        raw = MagicMock()
        raw.connect.side_effect = tcp_error
        secured = MagicMock()
        secured.recv.side_effect = http_error or [reply]
        secured.version.return_value = "TLSv1.3"
        context = MagicMock()
        context.wrap_socket.return_value = secured
        context.wrap_socket.side_effect = tls_error
        with contextlib.redirect_stdout(output), \
                patch.object(diag.socket, "getaddrinfo", side_effect=dns_error,
                             return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                                            ("192.0.2.1", 443))]), \
                patch.object(diag.socket, "socket", return_value=raw), \
                patch.object(diag.ssl, "create_default_context", return_value=context):
            diag.probe_http("cp.tdms.sibur.ru/cp/")
        return events(output.getvalue()), raw, secured, context

    def test_success_logs_all_stages_without_body(self):
        recorded, raw, secured, context = self.probe(
            b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nSECRET_BODY_TEXT")
        self.assertEqual([e["stage"] for e in recorded],
                         ["DNS", "DNS", "TCP", "TCP", "TLS", "TLS", "HTTP", "HTTP", "END"])
        self.assertEqual(recorded[-2]["status"], 200)
        self.assertFalse(recorded[-2]["body_checked"])
        self.assertNotIn("SECRET_BODY_TEXT", str(recorded))
        context.wrap_socket.assert_called_once_with(raw, server_hostname="cp.tdms.sibur.ru")
        self.assertIn(b"GET /cp/ HTTP/1.1", secured.sendall.call_args.args[0])
        self.assertNotIn(b"Authorization:", secured.sendall.call_args.args[0])
        secured.close.assert_called_once()

    def test_dns_failure_stops_before_connect(self):
        recorded, raw, _, context = self.probe(dns_error=socket.gaierror(-2, "bad"))
        self.assertEqual(recorded[-1]["stage"], "DNS")
        self.assertEqual(recorded[-1]["result"], "failed")
        raw.connect.assert_not_called()
        context.wrap_socket.assert_not_called()

    def test_tcp_refused_names_the_failed_stage(self):
        recorded, raw, _, context = self.probe(tcp_error=ConnectionRefusedError(111, "refused"))
        self.assertEqual(recorded[-1]["stage"], "TCP")
        self.assertEqual(recorded[-1]["errno"], 111)
        raw.close.assert_called_once()
        context.wrap_socket.assert_not_called()

    def test_tls_error_preserves_verification_and_never_sends_http(self):
        error = ssl.SSLCertVerificationError("certificate error")
        error.verify_code = 20
        error.verify_message = "unable to get local issuer certificate"
        recorded, raw, secured, _ = self.probe(tls_error=error)
        self.assertEqual(recorded[-1]["stage"], "TLS")
        self.assertEqual(recorded[-1]["verify_code"], 20)
        secured.sendall.assert_not_called()
        raw.close.assert_called_once()

    def test_http_wait_is_identifiable(self):
        recorded, _, secured, _ = self.probe(http_error=TimeoutError())
        self.assertEqual(recorded[-1]["stage"], "HTTP")
        self.assertEqual(recorded[-1]["error_type"], "TimeoutError")
        secured.close.assert_called_once()

    def test_redirect_is_not_followed_or_logged_with_secrets(self):
        recorded, raw, secured, _ = self.probe(
            b"HTTP/1.1 302 Found\r\n"
            b"Location: https://user:secret@example.net/private?token=SECRET\r\n\r\n")
        self.assertEqual(recorded[-2]["redirect_host"], "example.net")
        self.assertFalse(recorded[-2]["redirects_followed"])
        self.assertNotIn("SECRET", str(recorded))
        self.assertNotIn("private", str(recorded))
        raw.connect.assert_called_once()
        secured.sendall.assert_called_once()

    def test_incomplete_headers_are_not_reported_as_success(self):
        recorded, _, _, _ = self.probe(b"")
        self.assertEqual(recorded[-2]["result"], "invalid_or_incomplete_headers")


class ProcessBoundTests(unittest.TestCase):
    def test_subprocess_deadline_covers_dns_and_keeps_last_stage(self):
        output = io.StringIO()
        partial = b'[NET DIAG] {"site":"resti.club","stage":"DNS","result":"start"}\n'
        timeout = subprocess.TimeoutExpired("probe", 30, output=partial)
        with contextlib.redirect_stdout(output), \
                patch.object(diag.subprocess, "run", side_effect=timeout) as run:
            diag.run_http_probe("resti.club")
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        recorded = events(output.getvalue())
        self.assertEqual(recorded[0]["stage"], "DNS")
        self.assertEqual(recorded[-1]["stage"], "DEADLINE")

    def test_child_output_is_filtered(self):
        result = subprocess.CompletedProcess([], 0, stdout=(
            "unstructured private text\n"
            '[NET DIAG] {"site":"resti.club","stage":"END"}\n'), stderr="")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch.object(diag.subprocess, "run", return_value=result):
            diag.run_http_probe("resti.club")
        self.assertNotIn("private text", output.getvalue())
        self.assertEqual(len(events(output.getvalue())), 1)


class CertificateProbeTests(unittest.TestCase):
    def test_public_chain_metadata_and_verification_errors_only(self):
        chain = ("-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n"
                 "Verify return code: 20 (unable to get local issuer certificate)\n"
                 "Session ticket: NEVER_LOG_THIS")
        metadata = ("subject=CN = example.org\nissuer=CN = Test CA\n"
                    "notBefore=Oct 1 00:00:00 2026 GMT\n"
                    "notAfter=Nov 1 00:00:00 2026 GMT\n"
                    "sha256 Fingerprint=AA:BB\n")
        result = subprocess.CompletedProcess([], 0, stdout=chain,
                    stderr="verify error:num=20:unable to get local issuer certificate")
        parsed = subprocess.CompletedProcess([], 0, stdout=metadata, stderr="")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch.object(diag.subprocess, "run", side_effect=[result, parsed]) as run:
            diag.inspect_certificate_chain("sibur.ru")
        first_call = run.call_args_list[0]
        self.assertEqual(first_call.kwargs["input"], "")
        self.assertLessEqual(first_call.kwargs["timeout"], 30)
        self.assertIn("-showcerts", first_call.args[0])
        recorded = events(output.getvalue())
        self.assertEqual(recorded[1]["presented_certificates"], 1)
        self.assertEqual(recorded[1]["verification"][0][0], "20")
        self.assertEqual(recorded[2]["issuer"], "CN = Test CA")
        self.assertNotIn("NEVER_LOG_THIS", output.getvalue())
        self.assertNotIn("BEGIN CERTIFICATE", output.getvalue())

    def test_openssl_timeout_is_reported(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(
                diag.subprocess, "run",
                side_effect=subprocess.TimeoutExpired("openssl", 30)):
            diag.inspect_certificate_chain("sibur.ru")
        self.assertEqual(events(output.getvalue())[-1]["result"], "timeout")

    def test_missing_openssl_does_not_crash_worker(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch.object(diag.subprocess, "run", side_effect=FileNotFoundError()):
            diag.inspect_certificate_chain("sibur.ru")
        self.assertEqual(events(output.getvalue())[-1]["error_type"], "FileNotFoundError")


class RunTests(unittest.TestCase):
    def test_only_approved_sites_are_probed_once_and_done_is_logged(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch.object(diag, "inspect_certificate_chain") as certificates, \
                patch.object(diag, "run_http_probe") as http, \
                patch.object(diag.ssl, "create_default_context") as context:
            context.return_value.get_ca_certs.return_value = [{}]
            diag.run_diagnostics()
        self.assertCountEqual([c.args[0] for c in certificates.call_args_list], diag.TLS_SITES)
        self.assertCountEqual([c.args[0] for c in http.call_args_list], diag.TIMEOUT_SITES)
        recorded = events(output.getvalue())
        self.assertEqual(recorded[0]["concurrency"], 2)
        self.assertEqual(recorded[-1], {"site": "all", "stage": "DONE", "probes": 13})


if __name__ == "__main__":
    unittest.main()
