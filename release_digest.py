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

Повторы за день. Если одно исправление дорабатывалось в нескольких релизах, у пунктов
ставится одинаковая метка темы — в сводку попадает только пункт из последнего релиза:

    - Главная страница открывается быстрее ... <!-- тема: скорость-главной -->

Отменённые релизы указываются в релизе-откате; их пункты в сводку не попадают:

    ## 2026.11.21-monitor.15 — 2026-11-21
    <!-- отменяет: 2026.11.21-monitor.13, 2026.11.21-monitor.14 -->

Дословные повторы пунктов убираются всегда.
"""
import datetime
import os
import re

CHANGELOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "CHANGELOG.md")
SEND_AT = (23, 30)
SECTIONS = (("Улучшения", "✨ Улучшения"), ("Исправлено", "🐞 Исправлено"), ("Прочее", "🔧 Прочее"))
TG_LIMIT = 4000

_HEADER = re.compile(r"^##\s+(\S+)\s+[—-]\s+(\d{4}-\d{2}-\d{2})\s*$")
_TOPIC = re.compile(r"<!--\s*тема:\s*(.*?)\s*-->", re.IGNORECASE)
_REVERTS = re.compile(r"^<!--\s*отменяет:\s*(.*?)\s*-->\s*$", re.IGNORECASE)
_COMMENT = re.compile(r"\s*<!--.*?-->")


def _split_item(raw):
    """Текст пункта без служебных комментариев и его тема (или None)."""
    m = _TOPIC.search(raw)
    topic = m.group(1).strip().lower() if m and m.group(1).strip() else None
    return _COMMENT.sub("", raw).strip(), topic


def parse_changelog(text):
    """-> список релизов [{version, date, sections, topics, reverts}] в порядке файла.

    sections: {раздел: [текст пункта]}; topics: {раздел: [тема или None]} — параллельно
    sections; reverts: список версий, отменённых этим релизом.
    """
    releases = _parse_raw(text)
    for rel in releases:
        rel["topics"] = {}
        for name, items in rel["sections"].items():
            pairs = [_split_item(item) for item in items]
            rel["sections"][name] = [t for t, _ in pairs]
            rel["topics"][name] = [tp for _, tp in pairs]
    return releases


def _parse_raw(text):
    releases, current, section = [], None, None
    for raw in text.splitlines():
        line = raw.rstrip()
        m = _HEADER.match(line)
        if m:
            current = {"version": m.group(1), "date": datetime.date.fromisoformat(m.group(2)),
                       "sections": {}, "reverts": []}
            releases.append(current)
            section = None
            continue
        if current is None:
            continue
        rv = _REVERTS.match(line.strip())
        if rv:
            current["reverts"].extend(v.strip() for v in re.split(r"[,;\s]+", rv.group(1)) if v.strip())
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
    reverted = {v for r in releases for v in r.get("reverts", [])}
    entries = []  # (раздел, тема, текст) по порядку выкладки
    for rel in todays:
        if rel["version"] in reverted:
            continue
        for key, _ in SECTIONS:
            items = rel["sections"].get(key, [])
            topics = rel.get("topics", {}).get(key) or [None] * len(items)
            entries.extend((key, topic, item) for item, topic in zip(items, topics))
    last_of_topic = {topic: i for i, (_, topic, _) in enumerate(entries) if topic}
    body = []
    for key, title in SECTIONS:
        items, seen = [], set()
        for i, (sec, topic, item) in enumerate(entries):
            if sec != key or (topic and last_of_topic[topic] != i) or item in seen:
                continue
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
