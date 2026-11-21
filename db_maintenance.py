"""Обслуживание таблицы checks_agg (monitor.19).

checks_agg — 5-минутные агрегаты проверок; воркер перезаписывает строку текущего интервала
при каждом пакете проверок (UPSERT), поэтому в таблице постоянно копятся старые версии строк.
Если автоочистка PostgreSQL не успевает (или её статистика сброшена перезапуском БД),
таблица раздувается: на проде 21.11 она весила 640 МБ вместо ~70 МБ, и 30-дневные запросы
читали её по 10–60 с.

Что делает модуль:
- настройки таблицы: fillfactor=80 (обновления строк остаются на той же странице, без
  разрастания индексов) и более частая автоочистка/сбор статистики;
- ежедневно VACUUM (ANALYZE) — не блокирует чтение и запись;
- еженедельно VACUUM FULL — переписывает таблицу заново и возвращает место; на время
  выполнения (на проде — порядка минуты) запись в таблицу ждёт;
- однократный VACUUM FULL при первом запуске версии с этим модулем.

Хранение (monitor.20): в checks_agg остаются данные за RETENTION_DAYS (90) дней; всё старше
удаляется ежедневно перед VACUUM порциями по DELETE_BATCH строк, чтобы не держать долгих
блокировок. Все экраны используют не больше 30 дней. После первого удаления (на проде —
около 2,5 млн строк) один раз выполняется VACUUM FULL, чтобы сразу вернуть место.

Время последнего выполнения хранится в app_meta, поэтому расписание переживает перезапуски.
"""
import datetime
import os
import time

TABLE = "checks_agg"
META_ANALYZE = "maint_checks_agg_vacuum_last"
META_FULL = "maint_checks_agg_vacuum_full_last"
META_RETENTION = "maint_checks_agg_retention_v1"

RETENTION_DAYS = max(31, int(os.getenv("CHECKS_AGG_RETENTION_DAYS", "90")))
DELETE_BATCH = int(os.getenv("DB_MAINT_DELETE_BATCH", "50000"))

# Расписание (МСК). 03:00 — ротация логов, поэтому обслуживание после неё.
DAILY_HOUR = int(os.getenv("DB_MAINT_DAILY_HOUR", "3"))
DAILY_MINUTE = int(os.getenv("DB_MAINT_DAILY_MINUTE", "20"))
FULL_WEEKDAY = int(os.getenv("DB_MAINT_FULL_WEEKDAY", "6"))  # 0=пн … 6=вс
FULL_HOUR = int(os.getenv("DB_MAINT_FULL_HOUR", "4"))
FULL_MINUTE = int(os.getenv("DB_MAINT_FULL_MINUTE", "30"))
ENABLED = os.getenv("DB_MAINT_ENABLED", "1") == "1"

LOCK_TIMEOUT = os.getenv("DB_MAINT_LOCK_TIMEOUT", "60s")
STATEMENT_TIMEOUT = os.getenv("DB_MAINT_STATEMENT_TIMEOUT", "20min")

TABLE_OPTIONS = {
    "fillfactor": "80",
    "autovacuum_vacuum_scale_factor": "0.02",
    "autovacuum_vacuum_threshold": "1000",
    "autovacuum_analyze_scale_factor": "0.02",
    "autovacuum_analyze_threshold": "1000",
}


def _parse_ts(value):
    if not value:
        return None
    try:
        ts = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=datetime.timezone.utc)
    return ts


def _slot(now, hour, minute, weekday=None):
    """Последний наступивший момент расписания не позже now (в часовом поясе now)."""
    slot = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if weekday is None:
        if slot > now:
            slot -= datetime.timedelta(days=1)
        return slot
    slot -= datetime.timedelta(days=(slot.weekday() - weekday) % 7)
    if slot > now:
        slot -= datetime.timedelta(days=7)
    return slot


def due_action(now, last_analyze, last_full, retention_done=True):
    """Что пора выполнить: 'full', 'analyze' или None.

    now — aware datetime (МСК); last_* — aware datetime или None.
    VACUUM FULL: если ни разу не выполнялся или пропущен последний недельный слот.
    VACUUM (ANALYZE): если пропущен последний ежедневный слот. FULL заменяет ANALYZE.
    Пропущенный слот (приложение было выключено) выполняется при следующей проверке.
    retention_done=False (хранение 90 дней ещё ни разу не применялось) — сразу 'full'.
    """
    if not retention_done:
        return "full"
    full_slot = _slot(now, FULL_HOUR, FULL_MINUTE, FULL_WEEKDAY)
    if last_full is None or last_full < full_slot:
        return "full"
    daily_slot = _slot(now, DAILY_HOUR, DAILY_MINUTE)
    last = max(x for x in (last_analyze, last_full) if x is not None)
    if last < daily_slot:
        return "analyze"
    return None


def _read_meta(cur, key):
    cur.execute("SELECT value FROM app_meta WHERE key = %s", (key,))
    row = cur.fetchone()
    return _parse_ts(row[0]) if row else None


def _write_meta(cur, key, ts):
    cur.execute("""
        INSERT INTO app_meta (key, value, updated_at) VALUES (%s, %s, NOW())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
    """, (key, ts.isoformat()))


def table_size(cur):
    cur.execute("SELECT pg_size_pretty(pg_total_relation_size(%s::regclass))", (TABLE,))
    return cur.fetchone()[0]


def purge_old(cur, log=print):
    """Удаляет строки старше RETENTION_DAYS порциями (autocommit — каждая порция отдельно)."""
    total = 0
    t0 = time.monotonic()
    while True:
        cur.execute(f"""
            DELETE FROM {TABLE} WHERE ctid = ANY(ARRAY(
                SELECT ctid FROM {TABLE}
                WHERE bucket < NOW() - make_interval(days => %s)
                LIMIT %s))
        """, (RETENTION_DAYS, DELETE_BATCH))
        n = cur.rowcount or 0
        total += n
        if n < DELETE_BATCH:
            break
    log(f"[DB MAINT] {TABLE}: удалено {total} строк старше {RETENTION_DAYS} дн. "
        f"за {time.monotonic() - t0:.1f}s", flush=True)
    return total


def apply_table_options(cur):
    """Ставит TABLE_OPTIONS, если они ещё не заданы. Возвращает список изменённых опций."""
    cur.execute("SELECT reloptions FROM pg_class WHERE oid = %s::regclass", (TABLE,))
    row = cur.fetchone()
    current = {}
    for item in (row[0] if row and row[0] else []):
        k, _, v = item.partition("=")
        current[k] = v
    changed = {k: v for k, v in TABLE_OPTIONS.items() if current.get(k) != v}
    if changed:
        opts = ", ".join(f"{k} = {v}" for k, v in changed.items())
        cur.execute(f"ALTER TABLE {TABLE} SET ({opts})")
    return sorted(changed)


def run(conn_factory, action, log=print, now=None):
    """Выполняет VACUUM FULL / VACUUM (ANALYZE) для checks_agg. Возвращает True при успехе."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    sql = f"VACUUM (FULL, ANALYZE) {TABLE}" if action == "full" else f"VACUUM (ANALYZE) {TABLE}"
    conn = conn_factory()
    try:
        conn.autocommit = True  # VACUUM нельзя выполнять внутри транзакции
        cur = conn.cursor()
        cur.execute(f"SET lock_timeout = '{LOCK_TIMEOUT}'")
        cur.execute(f"SET statement_timeout = '{STATEMENT_TIMEOUT}'")
        changed = apply_table_options(cur)
        if changed:
            log(f"[DB MAINT] {TABLE}: заданы параметры {', '.join(changed)}", flush=True)
        purge_old(cur, log=log)
        before = table_size(cur)
        t0 = time.monotonic()
        log(f"[DB MAINT] {sql}: старт, размер {before}", flush=True)
        cur.execute(sql)
        dt = time.monotonic() - t0
        after = table_size(cur)
        _write_meta(cur, META_FULL if action == "full" else META_ANALYZE, now)
        if action == "full":
            _write_meta(cur, META_RETENTION, now)
        log(f"[DB MAINT] {sql}: готово за {dt:.1f}s, размер {before} -> {after}", flush=True)
        return True
    except Exception as e:
        log(f"[DB MAINT ERROR] {sql}: {type(e).__name__}: {e}", flush=True)
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def run_if_due(conn_factory, now_msk, log=print):
    """Проверяет расписание и выполняет нужное действие. Возвращает действие или None."""
    if not ENABLED:
        return None
    conn = conn_factory()
    try:
        cur = conn.cursor()
        last_analyze = _read_meta(cur, META_ANALYZE)
        last_full = _read_meta(cur, META_FULL)
        retention_done = _read_meta(cur, META_RETENTION) is not None
        conn.rollback()
    finally:
        conn.close()
    action = due_action(now_msk, last_analyze, last_full, retention_done)
    if action:
        run(conn_factory, action, log=log, now=now_msk)
    return action
