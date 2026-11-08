"""Bounded Globalping fallback for active public HTTPS monitoring targets.

No credentials/cookies are sent to monitored sites. Raw bodies are used transiently
for the existing content check and are never persisted. Globalping is a separate
measurement source, not an HTTP proxy. This process serves one monitoring worker.
"""
import asyncio
import copy
import datetime
import json
import ipaddress
import os
import re
import time
from collections import deque
from urllib.parse import urljoin, urlsplit

import aiohttp

UNKNOWN = 702
TLS_ERROR = 703
API = "https://api.globalping.io/v1/measurements"
SITES = frozenset({
    "cp.tdms.sibur.ru/cp/",
    "eshop.sibur.ru", "srm.sibur.ru", "resti.club", "lsdts.sibur.ru",
    "tms.sibur.ru", "sharefile.sibur.ru", "transportorder.sibur.ru",
})
ENABLED = os.getenv("GLOBALPING_ENABLED", "true").lower() == "true"
INTERVAL = 600
MAX_AGE = 600
HOURLY_BUDGET = 230  # Headroom under unauthenticated 250 tests/hour/IP.
PROBES = 2
MAX_RESPONSE = 2 * 1024 * 1024
MAX_HOPS = 3


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def network_failure(status, reason):
    """Never override an HTTP error, content failure or direct TLS failure."""
    return status == 0 and bool(reason) and reason.startswith((
        "Таймаут:", "DNS:", "Соединение ", "Ошибка подключения",
        "Сервер закрыл соединение",
    ))


def public_site(site):
    """Accept only public DNS names and non-sensitive paths from the active roster.

    No literal IPs, credentials, query strings, ports, local or reserved names.
    DNS is intentionally not resolved locally: that may be the failing route.
    """
    try:
        if not isinstance(site, str) or len(site) > 500:
            return False
        u = urlsplit("https://" + site)
        host = u.hostname
        if (not host or u.username or u.password or u.query or u.fragment
                or u.port is not None or site != host + u.path
                or "." not in host or len(host) > 253):
            return False
        if host.endswith((".local", ".localhost", ".internal", ".lan", ".corp",
                          ".test", ".invalid", ".example", ".arpa")):
            return False
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in host.split(".")):
            return False
        if any(ord(c) < 33 or ord(c) > 126 or c == "\\" for c in site):
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            return True
    except ValueError:
        return False


def public_redirect(host, current_path, location):
    """Only same-host HTTPS, standard port, no credentials or query strings."""
    try:
        u = urlsplit(urljoin("https://" + host + current_path, location))
        if (u.scheme != "https" or u.hostname != host or u.port not in (None, 443)
                or u.username or u.password or u.query or u.fragment):
            return None
        return u.path or "/"
    except (TypeError, ValueError):
        return None


def _host_matches(pattern, host):
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])
    return pattern == host


def incomplete_chain_only(tls, host):
    """Точка Globalping не смогла проверить подпись конечного сертификата только потому,
    что сервер не отдал промежуточный (UNABLE_TO_VERIFY_LEAF_SIGNATURE). Считаем TLS
    подтверждённым, если выдавший CA — проверенный промежуточный из нашего хранилища,
    срок не истёк и имя хоста совпадает с сертификатом."""
    if tls.get("error") != "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
        return False
    try:
        import tls_chain
        if not tls_chain.known_issuer(tls.get("issuer")):
            return False
        expires = datetime.datetime.fromisoformat(str(tls.get("expiresAt")).replace("Z", "+00:00"))
        if expires <= datetime.datetime.now(datetime.timezone.utc):
            return False
    except Exception:
        return False
    subject = tls.get("subject") or {}
    names = [n.strip()[4:] for n in str(subject.get("alt", "")).split(",")
             if n.strip().startswith("DNS:")] or [subject.get("CN") or ""]
    return any(_host_matches(n, host) for n in names if n)


def parse_measurement(data, host, path, verify_ssl, pattern):
    """Interpret probe data; require TLS evidence even if verification is disabled."""
    checked_at = data.get("createdAt")
    try:
        created = datetime.datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        age = (datetime.datetime.now(datetime.timezone.utc) - created).total_seconds()
        valid = -60 <= age < MAX_AGE
    except (AttributeError, ValueError, TypeError):
        valid = False
    if (not valid or data.get("status") != "finished" or data.get("target") != host
            or data.get("type") != "http"
            or data.get("measurementOptions", {}).get("request", {}).get("path", "/") != path):
        raise ValueError("invalid_or_stale_measurement")
    rows, redirects = [], set()
    for entry in data.get("results", []):
        result = entry.get("result") or {}
        probe = entry.get("probe") or {}
        tls = result.get("tls") or {}
        http = result.get("statusCode")
        row = {
            "country": str(probe.get("country", ""))[:8],
            "network": str(probe.get("network", ""))[:100],
            "asn": probe.get("asn"), "http": http,
            "tls_authorized": tls.get("authorized"),
            "checked_at": checked_at, "path": path,
            "status": UNKNOWN, "reason": "Нет завершённого HTTP-ответа",
        }
        total = (result.get("timings") or {}).get("total")
        row["response_time"] = total / 1000 if isinstance(total, (int, float)) else 0
        if (result.get("status") != "finished" or type(http) is not int
                or not 100 <= http <= 599):
            rows.append(row)
            continue
        if not str(tls.get("protocol", "")).startswith("TLS"):
            row["reason"] = "Нет подтверждения TLS-соединения"
        elif verify_ssl and tls.get("authorized") is not True and not incomplete_chain_only(tls, host):
            row.update(status=TLS_ERROR, reason="TLS: цепочка сертификата не подтверждена")
        elif http in (301, 302, 303, 307, 308):
            location = (result.get("headers") or {}).get("location")
            target = public_redirect(host, path, location) if isinstance(location, str) else None
            if target and target != path:
                redirects.add(target)
                row["reason"] = "Ожидается проверка страницы перенаправления"
            else:
                row["reason"] = "Нельзя безопасно проверить перенаправление"
        elif http not in (200, 401):
            row.update(status=http, reason=f"HTTP {http}")
        elif http == 401:
            row.update(status=200, reason="HTTP 401: сервер доступен, требуется авторизация")
        elif pattern is not None:
            body = result.get("rawBody")
            if not isinstance(body, str):
                row["reason"] = "Содержимое для Content Match отсутствует"
            elif pattern.search(body.lower()):
                row.update(status=200, reason="Content Match подтверждён")
            elif result.get("truncated"):
                row["reason"] = "Содержимое усечено; Content Match не подтверждён"
            else:
                row.update(status=701, reason="Content Match: нет совпадения с шаблоном")
        else:
            row.update(status=200, reason="HTTP-ответ подтверждён")
        rows.append(row)
    return rows, redirects, checked_at


class ExternalChecker:
    def __init__(self):
        self.cache = {}
        self.spent = deque()
        self.cooldown = 0
        self.allowed_sites = set(SITES)

    def reserve(self):
        now = time.monotonic()
        while self.spent and self.spent[0] <= now - 3600:
            self.spent.popleft()
        if now < self.cooldown:
            raise RuntimeError("api_cooldown")
        if len(self.spent) + PROBES > HOURLY_BUDGET:
            raise RuntimeError("local_hourly_budget")
        self.spent.extend([now] * PROBES)

    async def api(self, session, method, url, payload=None):
        kwargs = {"timeout": aiohttp.ClientTimeout(total=12), "allow_redirects": False}
        if payload is not None:
            kwargs["json"] = payload
        async with session.request(method, url, **kwargs) as resp:
            if resp.status == 429:
                # Shared NAT IP may have other users. Never assume a full quota.
                try:
                    wait = max(60, min(3600, int(resp.headers.get("Retry-After", "3600"))))
                except ValueError:
                    wait = 3600
                self.cooldown = time.monotonic() + wait
                raise RuntimeError("api_rate_limit")
            if not 200 <= resp.status < 300:
                raise RuntimeError("api_http_" + str(resp.status))
            chunks, size = [], 0
            async for chunk in resp.content.iter_chunked(65536):
                size += len(chunk)
                if size > MAX_RESPONSE:
                    raise ValueError("api_response_too_large")
                chunks.append(chunk)
            return json.loads(b"".join(chunks))

    async def measurement(self, session, host, path):
        self.reserve()
        created = await self.api(session, "POST", API, {
            "type": "http", "target": host,
            "locations": [{"country": "RU", "limit": PROBES}],
            "measurementOptions": {
                "protocol": "HTTPS", "request": {"method": "GET", "path": path}},
        })
        mid = created.get("id", "")
        if not isinstance(mid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", mid):
            raise ValueError("invalid_measurement_id")
        for _ in range(20):
            # Respect <=2 GETs/second/measurement.
            await asyncio.sleep(1)
            data = await self.api(session, "GET", API + "/" + mid)
            if data.get("status") != "in-progress":
                return mid, data
        raise TimeoutError("measurement_deadline")

    async def fresh(self, session, site, verify_ssl, pattern):
        host, _, suffix = site.partition("/")
        paths, seen, rows, ids, times = ["/" + suffix], set(), [], [], []
        for _ in range(MAX_HOPS):
            if not paths:
                break
            path = paths.pop(0)
            if path in seen:
                continue
            seen.add(path)
            mid, data = await self.measurement(session, host, path)
            ids.append(mid)
            found, redirects, stamp = parse_measurement(data, host, path, verify_ssl, pattern)
            rows.extend(found)
            times.append(stamp)
            paths.extend(sorted(redirects - seen))
            good = next((r for r in found if r["status"] == 200), None)
            if good:
                return dict(verdict="available", status=200,
                            response_time=good["response_time"], checked_at=min(times),
                            probes=rows, measurements=ids, cached=False)
        explicit = next((r for r in rows if r["status"] != UNKNOWN), None)
        return dict(verdict="error" if explicit else "unknown",
                    status=explicit["status"] if explicit else UNKNOWN,
                    response_time=explicit["response_time"] if explicit else 0,
                    checked_at=min(times) if times else utcnow(),
                    probes=rows, measurements=ids, cached=False)

    async def get(self, session, site, verify_ssl=True, pattern=None):
        key = (site, verify_ssl, pattern.pattern if pattern else None,
               pattern.flags if pattern else None)
        saved = self.cache.get(key)
        if saved and time.monotonic() - saved[0] < INTERVAL:
            cached = copy.deepcopy(saved[1])
            # Also check the actual measurement age, not just cache insertion.
            age = (datetime.datetime.now(datetime.timezone.utc) -
                   datetime.datetime.fromisoformat(cached["checked_at"].replace("Z", "+00:00"))).total_seconds()
            if 0 <= age < MAX_AGE:
                cached["cached"] = True
                return cached
        started = time.monotonic()
        try:
            if site not in self.allowed_sites or not public_site(site):
                raise ValueError("site_not_approved")
            result = await asyncio.wait_for(self.fresh(session, site, verify_ssl, pattern), 50)
        except Exception as exc:
            # Do not leak exception URLs, headers, bodies or tokens.
            code = str(exc) if isinstance(exc, (RuntimeError, ValueError)) else type(exc).__name__
            if not re.fullmatch(r"[A-Za-z0-9_]{1,60}", code):
                code = type(exc).__name__
            result = dict(verdict="unknown", status=UNKNOWN, response_time=0,
                          checked_at=utcnow(), probes=[], measurements=[],
                          api_error=code, cached=False)
            if isinstance(exc, (aiohttp.ClientError, TimeoutError, OSError)):
                self.cooldown = max(self.cooldown, time.monotonic() + 60)
        self.cache[key] = (started, copy.deepcopy(result))
        return result

    async def apply(self, session, results, ssl_map, cm_sites, pattern):
        if not ENABLED:
            return results
        # Only the actual active roster passed by the HTTP worker is approved.
        self.allowed_sites = {row[0] for row in results if public_site(row[0])}
        semaphore = asyncio.Semaphore(3)

        async def one(row):
            site, status, elapsed, reason = row
            if site not in self.allowed_sites or not network_failure(status, reason):
                return row
            direct = dict(status=status, response_time=elapsed, error=reason,
                          checked_at=utcnow(), url="https://" + site)
            async with semaphore:
                external = await self.get(
                    session, site, ssl_map.get(site, True), pattern if site in cm_sites else None)
            details = dict(source="globalping", direct=direct, external=external)
            label = {"available": "Доступен из внешней точки",
                     "error": "Ошибка внешней проверки",
                     "unknown": "Доступность не подтверждена"}[external["verdict"]]
            specifics = sorted({p["reason"] for p in external["probes"] if p["status"] != UNKNOWN})
            note = (f"{label}. Amvera: {reason}. Globalping: "
                    f"{', '.join(specifics) or external.get('api_error', 'нет HTTP-ответа')}. "
                    f"Измерение: {external['checked_at']}"
                    + (" (кэш, не старше 10 минут)" if external["cached"] else ""))
            if not ssl_map.get(site, True):
                note += ". TLS-проверка отключена в настройках сайта"
            print(f"[GLOBALPING] {site} verdict={external['verdict']} "
                  f"status={external['status']} cached={external['cached']} "
                  f"target={site} "
                  f"measurements={','.join(external['measurements'])} "
                  f"api_error={external.get('api_error', '-')}", flush=True)
            return (site, external["status"], external["response_time"], note, details)

        return await asyncio.gather(*(one(row) for row in results))


checker = ExternalChecker()
