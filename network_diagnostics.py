"""Bounded, read-only network probes. No database, Telegram or monitor state."""
import concurrent.futures
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit


TLS_SITES = ("sibur.ru", "shop.sibur.ru", "rusvinyl.ru", "greencity-sibur.ru")
TIMEOUT_SITES = (
    "eshop.sibur.ru", "lsdts.sibur.ru", "sharefile.sibur.ru", "srm.sibur.ru",
    "tms.sibur.ru", "transportorder.sibur.ru", "cp.tdms.sibur.ru/cp/",
    "tst-stdo.tdms.sibur.ru/cp/", "resti.club",
)
PROBE_TIMEOUT = 30
PREFIX = "[NET DIAG]"


def event(site, stage, **fields):
    print(PREFIX + " " + json.dumps(
        {"site": site, "stage": stage, **fields}, ensure_ascii=False), flush=True)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("diagnostic deadline")
    return remaining


def _error_fields(exc):
    """Only exception metadata: no request headers, credentials or response body."""
    result = {"error_type": type(exc).__name__}
    if isinstance(exc, OSError) and exc.errno is not None:
        result["errno"] = exc.errno
    if isinstance(exc, ssl.SSLCertVerificationError):
        result["verify_code"] = exc.verify_code
        result["verify_message"] = exc.verify_message
    return result


def probe_http(site):
    """One strict HTTPS request. Report redirects, do not follow them or read bodies."""
    host, _, suffix = site.partition("/")
    path = "/" + suffix
    started = time.monotonic()
    deadline = started + PROBE_TIMEOUT
    stage = "DNS"
    phase_start = started
    sock = None
    event(site, stage, result="start")
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        event(site, stage, result="ok", seconds=round(time.monotonic() - phase_start, 3),
              addresses=list(dict.fromkeys(a[4][0] for a in addresses)))
        last_error = None
        for family, kind, proto, _, address in addresses:
            stage, phase_start = "TCP", time.monotonic()
            event(site, stage, result="start", address=address[0])
            sock = socket.socket(family, kind, proto)
            try:
                sock.settimeout(_remaining(deadline))
                sock.connect(address)
                last_error = None
                event(site, stage, result="ok", address=address[0],
                      seconds=round(time.monotonic() - phase_start, 3))
                break
            except OSError as exc:
                last_error = exc
                event(site, stage, result="failed", address=address[0],
                      seconds=round(time.monotonic() - phase_start, 3),
                      **_error_fields(exc))
                sock.close()
                sock = None
                _remaining(deadline)
        if sock is None:
            raise last_error or OSError("no addresses")
        stage, phase_start = "TLS", time.monotonic()
        event(site, stage, result="start")
        context = ssl.create_default_context()
        sock.settimeout(_remaining(deadline))
        sock = context.wrap_socket(sock, server_hostname=host)
        event(site, stage, result="ok", seconds=round(time.monotonic() - phase_start, 3),
              protocol=sock.version(), verification="required")

        stage, phase_start = "HTTP", time.monotonic()
        event(site, stage, result="start")
        sock.settimeout(_remaining(deadline))
        # Default aiohttp User-Agent, as in the production checker.
        try:
            import aiohttp
            user_agent = f"Python/{sys.version_info.major}.{sys.version_info.minor} aiohttp/{aiohttp.__version__}"
        except ImportError:
            user_agent = "sib-monitor-network-diagnostic"
        request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: {user_agent}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        sock.sendall(request.encode("ascii"))
        headers = bytearray()
        first_byte_seconds = None
        while b"\r\n\r\n" not in headers and len(headers) < 16384:
            sock.settimeout(_remaining(deadline))
            chunk = sock.recv(min(1024, 16384 - len(headers)))
            if not chunk:
                break
            if first_byte_seconds is None:
                first_byte_seconds = round(time.monotonic() - phase_start, 3)
            headers.extend(chunk)
        lines = bytes(headers).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1").split("\r\n")
        match = re.fullmatch(r"HTTP/\d(?:\.\d)? (\d{3})(?: .*)?", lines[0])
        if not match or b"\r\n\r\n" not in headers:
            event(site, stage, result="invalid_or_incomplete_headers",
                  bytes_received=len(headers))
        else:
            fields = {"status": int(match[1]), "first_byte_seconds": first_byte_seconds,
                      "seconds": round(time.monotonic() - phase_start, 3),
                      "body_checked": False, "redirects_followed": False}
            # Only log the hostname, not query strings, paths or credentials.
            for line in lines[1:]:
                if line.lower().startswith("location:"):
                    fields["redirect_host"] = urlsplit(line.split(":", 1)[1].strip()).hostname or host
            event(site, stage, result="response", **fields)
        event(site, "END", result="completed",
              total_seconds=round(time.monotonic() - started, 3))
    except Exception as exc:
        event(site, stage, result="failed",
              seconds=round(time.monotonic() - phase_start, 3),
              total_seconds=round(time.monotonic() - started, 3), **_error_fields(exc))
    finally:
        if sock is not None:
            sock.close()


def run_http_probe(site):
    """The child-process deadline also bounds OS DNS resolution."""
    try:
        result = subprocess.run(
            [sys.executable, "-u", os.path.abspath(__file__), "--probe", site],
            capture_output=True, timeout=PROBE_TIMEOUT, text=True)
        for line in result.stdout.splitlines():
            if line.startswith(PREFIX + " "):
                print(line, flush=True)
        if result.returncode:
            event(site, "PROCESS", result="failed", returncode=result.returncode)
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        for line in output.splitlines():
            if line.startswith(PREFIX + " "):
                print(line, flush=True)
        event(site, "DEADLINE", result="timeout", limit_seconds=PROBE_TIMEOUT,
              note="Последний этап start без результата показывает место ожидания")
    except Exception as exc:
        event(site, "PROCESS", result="failed", **_error_fields(exc))


def inspect_certificate_chain(host):
    """Inspect presented PUBLIC certificates, without sending any HTTP request.

    OpenSSL reports verification errors but can still print the presented chain.
    This metadata is not trusted, installed or used by production HTTP checks.
    """
    deadline = time.monotonic() + PROBE_TIMEOUT
    event(host, "CERT_CHAIN", result="start", metadata_only=True)
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", host + ":443", "-servername", host,
             "-showcerts", "-verify", "10"],
            input="", capture_output=True, text=True, timeout=_remaining(deadline))
        combined = result.stdout + "\n" + result.stderr
        verification = re.findall(r"Verify return code:\s*(\d+)\s*\(([^)\r\n]+)\)", combined)
        verify_errors = re.findall(r"verify error:num=(\d+):([^\r\n]+)", combined)
        certificates = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            result.stdout, flags=re.DOTALL)
        event(host, "CERT_VERIFY", returncode=result.returncode,
              verification=verification, errors=verify_errors,
              presented_certificates=len(certificates), metadata_only=True)
        for index, pem in enumerate(certificates):
            parsed = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates",
                 "-fingerprint", "-sha256"],
                input=pem, capture_output=True, text=True,
                timeout=min(3, _remaining(deadline)))
            # The output contains certificate metadata only, never the private key.
            metadata = {}
            for line in parsed.stdout.splitlines():
                key, sep, value = line.partition("=")
                if sep and key in ("subject", "issuer", "notBefore", "notAfter",
                                   "sha256 Fingerprint", "SHA256 Fingerprint"):
                    metadata[key] = value[:500]
            event(host, "CERT", index=index, **metadata)
        if not certificates:
            event(host, "CERT_CHAIN", result="no_certificates")
    except subprocess.TimeoutExpired:
        event(host, "CERT_CHAIN", result="timeout", limit_seconds=PROBE_TIMEOUT)
    except Exception as exc:
        event(host, "CERT_CHAIN", result="failed", **_error_fields(exc))


def run_diagnostics():
    """One pass per application start, at most two concurrent probes, no retries."""
    event("all", "START", timeout_seconds=PROBE_TIMEOUT, concurrency=2,
          note="Разовый диагностический проход; рабочие статусы не изменяются")
    try:
        paths = ssl.get_default_verify_paths()
        context = ssl.create_default_context()
        event("all", "TRUST_STORE", openssl=ssl.OPENSSL_VERSION,
              cafile=paths.cafile, capath=paths.capath,
              trusted_ca_count=len(context.get_ca_certs()))
    except Exception as exc:
        event("all", "TRUST_STORE", result="failed", **_error_fields(exc))
    jobs = [(inspect_certificate_chain, host) for host in TLS_SITES]
    jobs += [(run_http_probe, site) for site in TIMEOUT_SITES]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(function, site) for function, site in jobs]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                event("all", "PROBE", result="failed", **_error_fields(exc))
    event("all", "DONE", probes=len(jobs))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--probe" and sys.argv[2] in TIMEOUT_SITES:
        probe_http(sys.argv[2])
    else:
        raise SystemExit("Use --probe with one of the approved diagnostic sites")
