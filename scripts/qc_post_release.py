#!/usr/bin/env python3
"""QC после выкладки: контроль рабочего экземпляра sib-monitor по дашборду и /health.

Ничего не меняет в приложении: только GET-запросы /health и главной страницы.
Сравнивает результат с прошлым снимком (baseline) и показывает регрессии.

Пример:
    QC_BASIC_AUTH=user:pass python3 scripts/qc_post_release.py \
        --url https://sib-monitor-ankori.msk1.amvera.tech \
        --expect-version 2026.11.08-monitor.10 --baseline .qc/baseline.json

Без QC_BASIC_AUTH запрос уходит без заголовка авторизации (например, когда его
подставляет внешний прокси с сохранённым секретом).
Код выхода: 0 — пройдено, 1 — есть FAIL, 2 — не удалось выполнить проверку.
"""
import argparse
import base64
import datetime
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

STATUSES = {"Online", "Offline", "TLS Error", "Content Mismatch", "Не подтверждено",
            "⏳ Ожидает проверки"}


def fetch(url, auth=None, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "sib-monitor-qc/1"})
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace"), time.monotonic() - started


def _text(fragment):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


def parse_dashboard(page):
    """Строки таблицы сайтов -> dict site -> поля."""
    body = page.split('id="t2"', 1)[0]
    rows = {}
    for tr_attrs, tr in re.findall(r"<tr([^>]*)>(.*?)</tr>", body, re.S):
        if "btn-test" not in tr:
            continue
        cells = re.findall(r"<td([^>]*)>(.*?)</td>", tr, re.S)
        if len(cells) < 8:
            continue
        site_m = re.search(r"<strong>(.*?)</strong>", cells[0][1], re.S)
        if not site_m:
            continue
        site = html.unescape(site_m.group(1)).strip()
        status_m = re.search(r'<span class="txt-[a-z]+">(.*?)</span>', cells[1][1], re.S)
        reason_m = re.search(r'<span class="check-error">(.*?)</span>', cells[1][1], re.S)
        ssl_attrs, ssl_cell = cells[5]
        title_m = re.search(r'title="([^"]*)"', ssl_attrs)
        ssl_txt = _text(ssl_cell).replace("ⓘ", "").strip()
        rows[site] = {
            "status": _text(status_m.group(1)) if status_m else _text(cells[1][1]),
            "reason": _text(reason_m.group(1)) if reason_m else None,
            "ssl_days": int(ssl_txt[:-1]) if re.fullmatch(r"-?\d+д", ssl_txt) else None,
            "ssl_note": html.unescape(title_m.group(1)) if title_m else None,
            "chain": _text(cells[6][1]) or "—",
            "self_signed": "self-signed-badge" in cells[0][1],
            "row_err": "row-err" in tr_attrs,
        }
    return rows


class Report:
    def __init__(self):
        self.items = []

    def add(self, level, code, text):
        self.items.append((level, code, text))

    def has(self, level):
        return any(i[0] == level for i in self.items)

    def print(self):
        for level, code, text in self.items:
            print(f"[{level}] {code}: {text}")
        fails = sum(1 for i in self.items if i[0] == "FAIL")
        warns = sum(1 for i in self.items if i[0] == "WARN")
        print(f"\nИтог: FAIL={fails} WARN={warns} OK={sum(1 for i in self.items if i[0] == 'OK')}")


def check(args):
    rep = Report()
    auth = os.getenv("QC_BASIC_AUTH")
    base = args.url.rstrip("/")

    code, body, _ = fetch(base + "/health")
    try:
        health = json.loads(body)
    except ValueError:
        health = {}
    if code != 200 or health.get("status") != "ok":
        rep.add("FAIL", "NFR-AVAIL-1", f"/health вернул {code}: {body[:200]}")
    else:
        rep.add("OK", "NFR-AVAIL-1", "/health отвечает status=ok")
    if args.expect_version:
        level = "OK" if health.get("version") == args.expect_version else "FAIL"
        rep.add(level, "REL-1", f"версия {health.get('version')} (ожидалась {args.expect_version})")
    tick = health.get("last_worker_tick")
    try:
        tick_dt = datetime.datetime.fromisoformat(str(tick)).replace(tzinfo=datetime.timezone.utc)
        age = (datetime.datetime.now(datetime.timezone.utc) - tick_dt).total_seconds()
        rep.add("OK" if age < 300 else "FAIL", "NFR-WORKER-1",
                f"последний цикл HTTP-воркера {int(age)} с назад (норма < 300)")
    except (TypeError, ValueError):
        rep.add("FAIL", "NFR-WORKER-1", f"нет отметки воркера: {tick!r}")

    if args.check_anonymous:
        code, _, _ = fetch(base + "/")
        rep.add("OK" if code == 401 else "FAIL", "NFR-SEC-1",
                f"дашборд без авторизации -> HTTP {code} (ожидается 401)")

    code, page, elapsed = fetch(base + "/", auth)
    if code != 200:
        rep.add("FAIL", "FR-UI-1", f"дашборд вернул HTTP {code}")
        return rep, {}
    rep.add("OK" if elapsed < 10 else "WARN", "NFR-PERF-1",
            f"дашборд открылся за {elapsed:.1f} с (норма < 10 с)")
    rows = parse_dashboard(page)
    if not rows:
        rep.add("FAIL", "FR-UI-1", "в дашборде не найдено ни одной строки сайта")
        return rep, rows
    rep.add("OK", "FR-UI-1", f"строк сайтов: {len(rows)}")

    unknown = {s: r["status"] for s, r in rows.items() if r["status"] not in STATUSES}
    if unknown:
        rep.add("FAIL", "FR-UI-2", f"неизвестные статусы: {unknown}")
    down = {s: f'{r["status"]} — {r["reason"] or ""}'.strip(" —")
            for s, r in rows.items() if r["status"] not in ("Online",)}
    rep.add("WARN" if down else "OK", "FR-HTTP-1",
            "не Online: " + "; ".join(f"{s} ({v})" for s, v in down.items()) if down
            else "все сайты Online")

    no_ssl = {s: r for s, r in rows.items() if r["ssl_days"] is None}
    unexplained = [s for s, r in no_ssl.items() if not r["ssl_note"]]
    if unexplained:
        rep.add("FAIL", "FR-SSL-1", "нет срока SSL и нет причины: " + ", ".join(unexplained))
    for s, r in no_ssl.items():
        if r["ssl_note"]:
            rep.add("WARN" if "отключена" not in r["ssl_note"] else "OK", "FR-SSL-1",
                    f"{s}: срок SSL не определён — {r['ssl_note']}")
    if not no_ssl:
        rep.add("OK", "FR-SSL-1", "срок SSL определён для всех сайтов")

    for s, r in rows.items():
        if r["self_signed"]:
            ok = r["status"] != "TLS Error" and r["chain"] in ("⚠️", "❌")
            rep.add("OK" if ok else "FAIL", "FR-SSL-3",
                    f"{s}: 🔓 самоподписанный, статус {r['status']}, цепочка {r['chain']}")
        if r["chain"] == "❌":
            rep.add("WARN", "FR-SSL-2", f"{s}: цепочка SSL не прошла проверку")
        if r["ssl_days"] is not None and 0 <= r["ssl_days"] <= 20 and not r["row_err"]:
            rep.add("FAIL", "FR-SSL-4", f"{s}: SSL {r['ssl_days']}д, но строка не выделена")

    baseline = {}
    if args.baseline and os.path.isfile(args.baseline):
        with open(args.baseline, encoding="utf-8") as fh:
            baseline = json.load(fh).get("rows", {})
    if baseline:
        lost = sorted(set(baseline) - set(rows))
        if lost:
            rep.add("FAIL", "REG-1", "пропали строки сайтов: " + ", ".join(lost))
        for s, old in baseline.items():
            new = rows.get(s)
            if not new:
                continue
            if old["status"] == "Online" and new["status"] != "Online":
                rep.add("WARN", "REG-2", f"{s}: был Online, сейчас {new['status']}")
            if old.get("ssl_days") is not None and new["ssl_days"] is None:
                rep.add("FAIL", "REG-3", f"{s}: срок SSL был {old['ssl_days']}д, сейчас не определён")
            if old.get("chain") == "✅" and new["chain"] != "✅":
                rep.add("WARN", "REG-4", f"{s}: цепочка была ✅, сейчас {new['chain']}")
            if old.get("self_signed") != new["self_signed"]:
                rep.add("WARN", "REG-5", f"{s}: признак самоподписанного изменился "
                                         f"({old.get('self_signed')} -> {new['self_signed']})")
        if not rep.has("FAIL"):
            rep.add("OK", "REG-0", f"сравнение с прошлым снимком: {len(baseline)} сайтов")
    return rep, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True)
    ap.add_argument("--expect-version")
    ap.add_argument("--baseline", help="JSON прошлого снимка; обновляется, если нет FAIL")
    ap.add_argument("--check-anonymous", action="store_true",
                    help="проверить, что дашборд без авторизации отдаёт 401")
    ap.add_argument("--json", help="сохранить строки дашборда в файл")
    args = ap.parse_args()
    try:
        rep, rows = check(args)
    except Exception as exc:  # сеть, разбор страницы
        print(f"[FAIL] QC-0: проверка не выполнена: {type(exc).__name__}: {exc}")
        return 2
    rep.print()
    snapshot = {"taken_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "rows": rows}
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, ensure_ascii=False, indent=1)
    if args.baseline and rows and not rep.has("FAIL"):
        os.makedirs(os.path.dirname(os.path.abspath(args.baseline)), exist_ok=True)
        with open(args.baseline, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, ensure_ascii=False, indent=1)
    return 1 if rep.has("FAIL") else 0


if __name__ == "__main__":
    sys.exit(main())
