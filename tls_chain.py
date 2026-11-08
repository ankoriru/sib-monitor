"""Восстановление неполной цепочки TLS (AIA chasing), как это делают браузеры.

Часть серверов отдаёт только конечный сертификат без промежуточного. Браузер
догружает промежуточный по ссылке «CA Issuers» (AIA) и сайт открывается, а
Python/OpenSSL сообщает «unable to get local issuer certificate».

Модуль:
  * загружает промежуточный сертификат по AIA только с публичных адресов;
  * принимает его, лишь если он криптографически выдан доверенным корнем
    системного хранилища (или уже проверенным промежуточным), является CA,
    не самоподписан и действует сейчас;
  * добавляет такие сертификаты в общий SSL-контекст. OpenSSL без
    PARTIAL_CHAIN не считает промежуточный сертификат якорем доверия,
    поэтому цепочка всё равно должна дойти до системного корня;
  * запоминает сайты с неполной цепочкой, чтобы показать это отдельно от
    реальной ошибки сертификата.
"""
import datetime
import ipaddress
import os
import socket
import ssl
import threading
import time
import urllib.parse
import warnings

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20
X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21
MAX_DOWNLOAD_BYTES = 20_000
TIMEOUT = 5
MAX_DEPTH = 3
RETRY_INTERVAL = 600  # не чаще раза в 10 минут на хост при неудаче
BUNDLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "intermediates.pem")

_lock = threading.RLock()
_intermediates = {}      # sha256 fingerprint -> x509.Certificate (проверенные)
_roots = None            # list[x509.Certificate]
_ctx = None
_last_attempt = {}       # host -> monotonic
incomplete_chain = {}    # host -> {"issuer": CN, "since": iso}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _load_roots():
    global _roots
    if _roots is not None:
        return _roots
    roots = []
    paths = ssl.get_default_verify_paths()
    for path in (paths.cafile, paths.openssl_cafile):
        if path and os.path.isfile(path):
            try:
                with open(path, "rb") as fh, warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    roots = x509.load_pem_x509_certificates(fh.read())
                break
            except (OSError, ValueError):
                continue
    if not roots:
        try:
            import certifi
            with open(certifi.where(), "rb") as fh:
                roots = x509.load_pem_x509_certificates(fh.read())
        except Exception:
            roots = []
    _roots = roots
    return roots


def _valid_now(cert):
    now = _now()
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def _is_ca(cert):
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        return False


def _issued_by(child, parent):
    if child.issuer != parent.subject:
        return False
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:
        return False


def _trusted_parent(cert):
    """Доверенный выдавший сертификат: системный корень или уже проверенный промежуточный."""
    with _lock:
        candidates = list(_load_roots()) + list(_intermediates.values())
    for parent in candidates:
        if _issued_by(cert, parent):
            return parent
    return None


def _acceptable_intermediate(cert):
    return _is_ca(cert) and cert.subject != cert.issuer and _valid_now(cert)


def _fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _add(certs):
    global _ctx
    with _lock:
        changed = False
        for cert in certs:
            fp = _fingerprint(cert)
            if fp not in _intermediates:
                _intermediates[fp] = cert
                changed = True
        if changed:
            _ctx = None
        return changed


def load_bundle(path=BUNDLE_PATH):
    """Загружает поставляемые промежуточные сертификаты с той же проверкой доверия."""
    try:
        with open(path, "rb") as fh:
            certs = x509.load_pem_x509_certificates(fh.read())
    except (OSError, ValueError):
        return 0
    accepted = 0
    pending = [c for c in certs if _acceptable_intermediate(c)]
    for _ in range(MAX_DEPTH):  # несколько проходов: промежуточный может зависеть от другого
        rest = []
        for cert in pending:
            if _trusted_parent(cert):
                _add([cert])
                accepted += 1
            else:
                rest.append(cert)
        if not rest or len(rest) == len(pending):
            break
        pending = rest
    return accepted


def context():
    """Общий проверяющий SSL-контекст: системные корни + проверенные промежуточные."""
    global _ctx
    with _lock:
        if _ctx is None:
            ctx = ssl.create_default_context()
            if _intermediates:
                ctx.load_verify_locations(cadata="".join(
                    c.public_bytes(Encoding.PEM).decode() for c in _intermediates.values()))
            _ctx = ctx
        return _ctx


def is_missing_issuer(exc):
    """True для ошибки «unable to get local issuer certificate» (неполная цепочка)."""
    err = getattr(exc, "certificate_error", exc)
    code = getattr(err, "verify_code", None)
    if code in (X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE):
        return True
    msg = str(getattr(err, "verify_message", "") or "").lower()
    return "unable to get local issuer" in msg or "unable to verify the first certificate" in msg


def _public_http_url(url):
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        return False
    if u.port not in (None, 80, 443):
        return False
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


def _download(url):
    if not _public_http_url(url):
        return b""
    with requests.get(url, timeout=TIMEOUT, allow_redirects=False, stream=True) as resp:
        if resp.status_code != 200:
            return b""
        data = b""
        for chunk in resp.iter_content(4096):
            data += chunk
            if len(data) > MAX_DOWNLOAD_BYTES:
                return b""
        return data


def _parse(data):
    for loader in (lambda d: [x509.load_der_x509_certificate(d)],
                   x509.load_pem_x509_certificates,
                   pkcs7.load_der_pkcs7_certificates,
                   pkcs7.load_pem_pkcs7_certificates):
        try:
            certs = loader(data)
            if certs:
                return certs
        except Exception:
            continue
    return []


def _aia_urls(cert):
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in aia
            if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(d.access_location, x509.UniformResourceIdentifier)]


def _fetch_parent(cert):
    for url in _aia_urls(cert)[:2]:
        try:
            for candidate in _parse(_download(url)):
                if _issued_by(cert, candidate):
                    return candidate
        except Exception:
            continue
    return None


def _leaf_der(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)


def _verify_with_context(host, port=443):
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with context().wrap_socket(sock, server_hostname=host):
            return True


def _cn(name):
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def repair(host, port=443, force=False):
    """Пытается достроить цепочку для host по AIA. True — сертификат прошёл
    полную проверку (имя, срок, цепочка до корня) с догруженным промежуточным."""
    now = time.monotonic()
    with _lock:
        last = _last_attempt.get(host)
        if not force and last is not None and now - last < RETRY_INTERVAL:
            return False
        _last_attempt[host] = now
    try:
        leaf = x509.load_der_x509_certificate(_leaf_der(host, port))
        chain, cur = [], leaf
        if not _trusted_parent(leaf):
            for _ in range(MAX_DEPTH):
                parent = _fetch_parent(cur)
                if parent is None or not _acceptable_intermediate(parent):
                    return False
                chain.append(parent)
                if _trusted_parent(parent):
                    break
                cur = parent
            else:
                return False
            _add(chain)
        _verify_with_context(host, port)
    except Exception as exc:
        print(f"[TLS AIA] {host}: не удалось достроить цепочку ({type(exc).__name__})", flush=True)
        return False
    issuer = _cn(leaf.issuer)
    with _lock:
        incomplete_chain[host] = {"issuer": issuer, "since": _now().isoformat()}
        _last_attempt.pop(host, None)
    print(f"[TLS AIA] {host}: сервер не отдаёт промежуточный сертификат; "
          f"цепочка достроена по AIA ({issuer}), сертификат действителен", flush=True)
    return True


def known_issuer(issuer):
    """Для внешней проверки (Globalping): issuer — словарь {C, O, CN} из ответа.
    True, если это проверенный промежуточный сертификат из нашего хранилища."""
    if not isinstance(issuer, dict) or not issuer.get("CN"):
        return False
    with _lock:
        certs = list(_intermediates.values())
    for cert in certs:
        s = cert.subject
        values = {
            "CN": _cn(s),
            "O": (s.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or [None])[0],
            "C": (s.get_attributes_for_oid(NameOID.COUNTRY_NAME) or [None])[0],
        }
        values = {k: (v.value if hasattr(v, "value") else v) for k, v in values.items()}
        if all(issuer.get(k) in (None, values[k]) for k in ("C", "O")) and issuer["CN"] == values["CN"]:
            return True
    return False


load_bundle()
