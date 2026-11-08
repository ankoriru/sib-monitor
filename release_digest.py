"""Ежедневная сводка релизов для Telegram (23:30 МСК).

Источник — CHANGELOG.md в образе приложения. Раздел релиза:

    ## 2026.11.08-monitor.10 — 2026-11-08
    ### Улучшения
    - ...
    ### Исправлено
    - ...
    ### Прочее
    - ...

Дата в заголовке — день выкладки (МСК). Если в этот день релизов не было,
сводка не отправляется.
"""
import datetime
import os
import re

CHANGELOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "CHANGELOG.md")
SEND_AT = (23, 30)
SECTIONS = (("Улучшения", "✨ Улучшения"), ("Исправлено", "🐞 Исправлено"), ("Прочее", "🔧 Прочее"))
TG_LIMIT = 4000

_HEADER = re.compile(r"^##\s+(\S+)\s+[—-]\s+(\d{4}-\d{2}-\d{2})\s*$")


def parse_changelog(text):
    """-> список релизов [{version, date, sections: {name: [items]}}] в порядке файла."""
    releases, current, section = [], None, None
    for raw in text.splitlines():
        line = raw.rstrip()
        m = _HEADER.match(line)
        if m:
            current = {"version": m.group(1), "date": datetime.date.fromisoformat(m.group(2)),
                       "sections": {}}
            releases.append(current)
            section = None
            continue
        if current is None:
            continue
        if line.startswith("### "):
            section = line[4:].strip()
            current["sections"].setdefault(section, [])
        elif section and re.match(r"^\s*[-*]\s+", line):
            current["sections"][section].append(re.sub(r"^\s*[-*]\s+", "", line).strip())
        elif section and line.startswith("  ") and current["sections"][section]:
            current["sections"][section][-1] += " " + line.strip()
    return releases


def load_releases(path=CHANGELOG_PATH):
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_changelog(fh.read())
    except OSError:
        return []


def build_digest(releases, day):
    """Текст сводки за день или None, если релизов не было."""
    todays = [r for r in releases if r["date"] == day]
    if not todays:
        return None
    todays.reverse()  # в CHANGELOG новые сверху; в сводке — по порядку выкладки
    versions = [r["version"] for r in todays]
    head = [f"📦 Обновления мониторинга за {day.strftime('%d.%m.%Y')}",
            f"Релизов: {len(todays)} (" + (versions[0] if len(versions) == 1
                                            else f"{versions[0]} → {versions[-1]}") + ")"]
    body = []
    for key, title in SECTIONS:
        items, seen = [], set()
        for rel in todays:
            for item in rel["sections"].get(key, []):
                if item not in seen:
                    seen.add(item)
                    items.append(item)
        if items:
            body.append("")
            body.append(title)
            body.extend(f"• {item}" for item in items)
    text = "\n".join(head + body)
    if len(text) > TG_LIMIT:
        text = text[:TG_LIMIT - 40].rsplit("\n", 1)[0] + "\n… полный список — в CHANGELOG.md"
    return text


def due(now):
    """Наступило ли время отправки (МСК), с запасом до конца суток на случай перезапуска."""
    return (now.hour, now.minute) >= SEND_AT
