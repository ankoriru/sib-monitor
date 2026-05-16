import datetime
import ssl
import socket
import requests
import psycopg2
import json
import base64
import pytz
import threading
import time
import os
import whois
import asyncio
import aiohttp
import bcrypt
import queue
import concurrent.futures
import re
from io import StringIO
from string import Template
from psycopg2.extras import DictCursor, execute_values
from playwright.async_api import async_playwright
from fastapi import FastAPI, Request, Response, Depends, HTTPException, Cookie
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, StreamingResponse, RedirectResponse

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================
DATABASE_URL = os.getenv("DATABASE_URL")
TELEGRAM_TOKEN = os.getenv("TG_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID")
TZ_MOSCOW = pytz.timezone('Europe/Moscow')

NEW_MONITORING_SITES = [
    "icenter.tdms.nipigas.ru/cp/",
    "tdms.progress-epc.ru/cp/",
    "icenter.tdms.newresources.ru/cp/",
    "agpp.tdms.nipigas.ru/cp/",
    "agpp.tdms.nipigas.ru/DMS21/",
    "tst-stdo.tdms.sibur.ru/cp/",
    "cp.tdms.sibur.ru/cp/",
    "portal-rd.rusproject.ru"
]

SELF_MONITORING_SITES = [
    "sib-monitor-ankori.amvera.io"
]

# --- Content match для Ключевых сайтов ---
# re.IGNORECASE: sibur/SIBUR/Sibur/сибур/СИБУР/Сибур — любой регистр
CONTENT_MATCH_KEYWORDS = re.compile(r"sibur|сибур|логин|пароль|login|username|password|вход|войти|auth|authorization|транспорт|заказ", re.IGNORECASE)

# Глобальный кэш для динамического content match (обновляется из БД)
_content_match_pattern = None
_content_match_regex = CONTENT_MATCH_KEYWORDS
# Глобальный набор сайтов с content match (заполняется в check_worker)
_cm_sites_set = set()

# --- SEC-1: Whitelist для self-signed сертификатов ---
SELF_SIGNED_SITES = set(NEW_MONITORING_SITES)
if os.getenv("SELF_SIGNED_SITES"):
    SELF_SIGNED_SITES.update(os.getenv("SELF_SIGNED_SITES").split(","))

# --- SEC-2: BCrypt-хеширование паролей через env ---
AUTH_USERNAME = os.getenv("AUTH_USERNAME", "sibur")
AUTH_PASSWORD_HASH = os.getenv("AUTH_PASSWORD_HASH", "")

# --- ADMIN: Пароль для вкладки Управление (bcrypt hash for "flvby") ---
ADMIN_PASSWORD_HASH = "$2b$12$rsNPWPiJyP5NSwg71GUw9uBxPAbGk..gOD2W.CU9SGLrNuFO.bIgC"

SITES = [
    "sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru",
    "alphapor.ru", "amur-gcc.ru", "ar24.sibur.ru",
    "bopp.sibur.ru", "carbo.sibur.ru", "carbonfootprintcalculator.sibur.ru",
    "career.sibur.ru", "catalog.sibur.ru", "coach.sibur.ru",
    "ecoball.sibur.ru", "greencity-sibur.ru", "guide.sibur.ru",
    "laika.sibur.ru", "magazine.sibur.ru", "mendeleev-smena.ru",
    "messages2.sibur.ru", "nauka.sibur.ru", "oknavdome.info",
    "photo.sibur.ru", "polylabsearch.ru", "portenergo.com",
    "rusvinyl.ru", "sharefile.sibur.ru",
    "sibur.digital", "sibur-int.com", "sibur-int.ru", "sibur-yug.ru",
    "snck.ru", "transportorder.sibur.ru", "tu-sibur.ru", "vivilen.sibur.ru"
] + NEW_MONITORING_SITES

PRIORITY_SITES = [
    "sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru", "career.sibur.ru"
] + NEW_MONITORING_SITES

# --- Группировка сайтов для UI ---
KEY_SITES = ["sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru", "career.sibur.ru", "transportorder.sibur.ru"]
STDO_SITES = NEW_MONITORING_SITES[:]
EXTERNAL_SITES = [s for s in SITES if s not in KEY_SITES and s not in STDO_SITES]

app = FastAPI()

# ============================================================================
# BATCH-BUFFER для накопления результатов (Этап 2.1)
# ============================================================================
batch_buffer = []
BATCH_SIZE = 50
BATCH_LOCK = threading.Lock()

# КЭШ DASHBOARD — храним dict с данными (не HTML-строку)
_dashboard_cache = {"data": None, "timestamp": 0, "lock": threading.Lock()}
CACHE_TTL = 30

# ============================================================================
# PLAYWRIGHT SCREENSHOT QUEUE — thread-safe воркер
# ============================================================================
# Screenshot rate limit (30 sec per site)
_screenshot_rate_limit = {}
_screenshot_rate_lock = threading.Lock()


def _take_screenshot_sync(site):
    """Скриншот одного сайта через Playwright. Делает скриншот через 3 сек после загрузки."""
    import asyncio as _asyncio
    path = f"debug_{site.replace('/', '_')}_{int(time.time())}.jpg"

    async def _shoot():
        p = await async_playwright().start()
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-sandbox-usage", "--disable-gpu",
                  "--disable-setuid-sandbox", "--no-zygote"]
        )
        context = await browser.new_context(
            viewport={'width': 1280, 'height': 720},
            ignore_https_errors=True
        )
        try:
            page = await context.new_page()
            try:
                await page.goto(f"https://{site}", timeout=20000, wait_until="domcontentloaded")
            except Exception as e:
                print(f"[SCREEN WARN] {site} goto timeout/error: {e}")
            await _asyncio.sleep(3)
            await page.screenshot(path=path, type="jpeg", quality=80)
            if os.path.exists(path) and os.path.getsize(path) > 1000:
                print(f"[SCREEN OK] Screenshot saved: {path} ({os.path.getsize(path)} bytes)")
                return path
            else:
                print(f"[SCREEN ERR] {site} screenshot too small or missing")
                return None
        finally:
            await context.close()
            await browser.close()

    try:
        return _asyncio.run(_shoot())
    except Exception as e:
        print(f"[SCREEN ERR] {site}: {type(e).__name__}: {e}")
        return None


def take_screenshot_fast(site, retries=2):
    """Скриншот с retry: если не удался, пробуем ещё через 3 сек"""
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_take_screenshot_sync, site)
                result = future.result(timeout=60)
                if result:
                    return result
                print(f"[SCREEN RETRY] {site} attempt {attempt}/{retries} returned None")
        except Exception as e:
            last_err = e
            print(f"[SCREEN ERR] {site} attempt {attempt}/{retries}: {type(e).__name__}: {e}")
        if attempt < retries:
            time.sleep(3)
    return None


# ============================================================================
# BCrypt AUTH (SEC-2)
# ============================================================================
def check_auth(request: Request, response: Response, session_auth: str = Cookie(None)):
    """Аутентификация через BCrypt-хеш пароля из env + cookie-сессия"""
    if session_auth == "authenticated_sibur":
        return True

    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": "Basic realm='Sibur Monitoring'"}
        )

    try:
        scheme, credentials = auth.split()
        decoded = base64.b64decode(credentials).decode("ascii")
        u, p = decoded.split(":", 1)

        if u == AUTH_USERNAME and AUTH_PASSWORD_HASH:
            if bcrypt.checkpw(p.encode('utf-8'), AUTH_PASSWORD_HASH.encode('utf-8')):
                response.set_cookie(
                    key="session_auth",
                    value="authenticated_sibur",
                    max_age=2592000,
                    httponly=True,
                    secure=True,
                    samesite="lax"
                )
                return True
    except Exception:
        pass
    raise HTTPException(status_code=401)


# ============================================================================
# УТИЛИТЫ
# ============================================================================
def admin_check_auth(request: Request, response: Response, admin_session: str = Cookie(None)):
    """Аутентификация для вкладки Управление (пароль 'flvby')"""
    if admin_session == "authenticated_admin":
        return True
    auth = request.headers.get("X-Admin-Auth")
    if auth:
        try:
            if bcrypt.checkpw(auth.encode('utf-8'), ADMIN_PASSWORD_HASH.encode('utf-8')):
                response.set_cookie(
                    key="admin_session",
                    value="authenticated_admin",
                    max_age=2592000,
                    httponly=True,
                    secure=True,
                    samesite="lax"
                )
                return True
        except Exception:
            pass
    raise HTTPException(status_code=401, detail="Admin authentication required")


def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


def load_active_sites():
    """Читает список активных сайтов из БД. Fallback на дефолтный список. Self-monitoring исключены."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT site, site_group, alert_threshold FROM monitored_sites WHERE is_active = TRUE ORDER BY site")
        rows = cur.fetchall()
        # Load dynamic categories from DB
        cur.execute("SELECT id, label, content_match_enabled FROM site_categories ORDER BY sort_order")
        cat_rows = cur.fetchall()
        cur.close()
        conn.close()
        if rows:
            sites = [r[0] for r in rows if r[0] not in SELF_MONITORING_SITES]
            thresholds = {r[0]: (r[2] if r[2] is not None else 5) for r in rows if r[0] not in SELF_MONITORING_SITES}
            # Build dynamic categories dict
            categories = {}
            cat_ids = [c[0] for c in cat_rows]
            for cat_id in cat_ids:
                categories[cat_id] = [r[0] for r in rows if r[1] == cat_id and r[0] not in SELF_MONITORING_SITES]
            # Sites with unknown category go to 'external'
            for r in rows:
                if r[1] not in cat_ids and r[0] not in SELF_MONITORING_SITES:
                    categories.setdefault('external', []).append(r[0])
            return sites, categories, thresholds
    except Exception as e:
        print(f"[WARN] Failed to load sites from DB: {e}")
    # Fallback — всегда возвращаем 3 значения (sites, categories, thresholds)
    all_sites = [s for s in SITES if s not in SELF_MONITORING_SITES]
    key = KEY_SITES[:]
    stdo = STDO_SITES[:]
    ext = [s for s in EXTERNAL_SITES if s not in SELF_MONITORING_SITES]
    categories = {'key': key, 'stdo': stdo, 'external': ext}
    thresholds = {s: 5 for s in all_sites}
    return all_sites, categories, thresholds



def load_settings():
    """Читает настройки приложения из БД. Fallback на дефолты."""
    defaults = {
        'content_match_pattern': 'sibur|сибур|логин|пароль|login|username|password|вход|войти|auth|authorization|транспорт|заказ',
        'category_key_label': 'Ключевые',
        'category_stdo_label': 'СТДО',
        'category_external_label': 'Внешние сайты'
    }
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM app_settings")
        for row in cur.fetchall():
            defaults[row[0]] = row[1]
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[WARN] Failed to load settings: {e}")
    return defaults

def should_verify(site: str) -> bool:
    """SEC-1: Определяет, нужна ли полная SSL-валидация для сайта"""
    return site not in SELF_SIGNED_SITES


def _safe_index(cur, conn, index_name, table_name, columns):
    """Создаёт индекс, если его ещё нет; игнорирует DuplicateTable/DuplicateObject"""
    try:
        cur.execute(f"""
            CREATE INDEX IF NOT EXISTS {index_name}
            ON {table_name} ({columns})
        """)
    except psycopg2.Error:
        conn.rollback()


def _column_exists(cur, table, column):
    cur.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.columns
            WHERE table_name = %s AND column_name = %s
        )
    """, (table, column))
    return cur.fetchone()[0]


def init_db():
    """Инициализация БД с поддержкой партиционирования + incidents + health + ssl_chain"""
    conn = get_db_connection()
    cur = conn.cursor()

    # Таблица health (heartbeat worker'а)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS health (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Проверяем, существует ли уже партиционированная таблица logs
    cur.execute("""
        SELECT EXISTS (
            SELECT FROM pg_tables
            WHERE tablename = 'logs'
            AND schemaname = 'public'
        )
    """)
    logs_exists = cur.fetchone()[0]

    if not logs_exists:
        cur.execute("""
            CREATE TABLE logs (
                site TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status INTEGER,
                response_time REAL,
                ssl_days INTEGER,
                domain_days INTEGER,
                ssl_chain_valid BOOLEAN
            ) PARTITION BY RANGE (timestamp)
        """)

        now = datetime.datetime.now()
        y, m = now.year, now.month
        next_y, next_m = (y, m + 1) if m < 12 else (y + 1, 1)
        next_next_y, next_next_m = (y, m + 2) if m < 11 else (y + 1, (m + 1) % 12 + 1)

        for yy, mm in [(y, m), (next_y, next_m), (next_next_y, next_next_m)]:
            mm_next = mm + 1 if mm < 12 else 1
            yy_next = yy if mm < 12 else yy + 1
            try:
                cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS logs_{yy}_{mm:02d}
                    PARTITION OF logs
                    FOR VALUES FROM ('{yy}-{mm:02d}-01')
                    TO ('{yy_next}-{mm_next:02d}-01')
                """)
            except psycopg2.Error:
                conn.rollback()

        _safe_index(cur, conn, "idx_logs_site_ts", "logs", "site, timestamp DESC")
    else:
        # Миграция: добавляем ssl_chain_valid если нужно
        if not _column_exists(cur, 'logs', 'ssl_chain_valid'):
            cur.execute("ALTER TABLE logs ADD COLUMN ssl_chain_valid BOOLEAN")
        # Проверяем, что таблица партиционирована
        cur.execute("""
            SELECT pg_get_partkeydef(c.oid)
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = 'logs' AND n.nspname = 'public'
        """)
        result = cur.fetchone()
        if result and result[0] is None:
            print("Миграция: переименование старой таблицы в logs_old")
            cur.execute("ALTER TABLE logs RENAME TO logs_old")
            cur.execute("""
                CREATE TABLE logs (
                    site TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    status INTEGER,
                    response_time REAL,
                    ssl_days INTEGER,
                    domain_days INTEGER,
                    ssl_chain_valid BOOLEAN
                ) PARTITION BY RANGE (timestamp)
            """)
            now = datetime.datetime.now()
            y, m = now.year, now.month
            next_y, next_m = (y, m + 1) if m < 12 else (y + 1, 1)
            for yy, mm in [(y, m), (next_y, next_m)]:
                mm_next = mm + 1 if mm < 12 else 1
                yy_next = yy if mm < 12 else yy + 1
                try:
                    cur.execute(f"""
                        CREATE TABLE IF NOT EXISTS logs_{yy}_{mm:02d}
                        PARTITION OF logs
                        FOR VALUES FROM ('{yy}-{mm:02d}-01')
                        TO ('{yy_next}-{mm_next:02d}-01')
                    """)
                except psycopg2.Error:
                    conn.rollback()
            _safe_index(cur, conn, "idx_logs_site_ts", "logs", "site, timestamp DESC")

    # Таблица агрегатов
    cur.execute("""
        CREATE TABLE IF NOT EXISTS checks_agg (
            site TEXT NOT NULL,
            bucket TIMESTAMP NOT NULL,
            checks_count INTEGER DEFAULT 1,
            status_200_count INTEGER DEFAULT 0,
            avg_response_time REAL,
            min_response_time REAL,
            max_response_time REAL,
            last_ssl_days INTEGER,
            last_domain_days INTEGER,
            last_ssl_chain_valid BOOLEAN,
            PRIMARY KEY (site, bucket)
        )
    """)
    if not _column_exists(cur, 'checks_agg', 'last_ssl_chain_valid'):
        cur.execute("ALTER TABLE checks_agg ADD COLUMN last_ssl_chain_valid BOOLEAN")
    if not _column_exists(cur, 'checks_agg', 'down_sec'):
        cur.execute("ALTER TABLE checks_agg ADD COLUMN down_sec INTEGER DEFAULT 0")
        # Backfill для существующих записей — одноразовый, при создании столбца
        cur.execute("UPDATE checks_agg SET down_sec = (checks_count - status_200_count) * 60 WHERE down_sec = 0 AND checks_count > status_200_count")
        print(f"[INIT] Backfilled down_sec: {cur.rowcount} rows")
    _safe_index(cur, conn, "idx_checks_agg_bucket", "checks_agg", "bucket DESC")

    # Материализованное представление — пересоздаём если нет ssl_chain_valid
    need_recreate_mv = False
    cur.execute("""
        SELECT EXISTS (
            SELECT FROM pg_matviews WHERE matviewname = 'latest_status'
        )
    """)
    mv_exists = cur.fetchone()[0]
    if not mv_exists:
        need_recreate_mv = True
    elif not _column_exists(cur, 'latest_status', 'ssl_chain_valid'):
        cur.execute("DROP MATERIALIZED VIEW IF EXISTS latest_status CASCADE")
        need_recreate_mv = True

    if need_recreate_mv:
        cur.execute("""
            CREATE MATERIALIZED VIEW latest_status AS
            SELECT DISTINCT ON (site)
                site, status, response_time, ssl_days, domain_days, ssl_chain_valid, timestamp
            FROM logs
            ORDER BY site, timestamp DESC
        """)
        try:
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_latest_status_site ON latest_status (site)")
        except psycopg2.Error:
            conn.rollback()
    else:
        try:
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_latest_status_site ON latest_status (site)")
        except psycopg2.Error:
            conn.rollback()

    # Таблица инцидентов
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id SERIAL PRIMARY KEY,
            site TEXT NOT NULL,
            start_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            duration_min INTEGER,
            max_status INTEGER,
            description TEXT,
            resolved BOOLEAN DEFAULT FALSE,
            ssl_chain_valid BOOLEAN
        )
    """)
    if not _column_exists(cur, 'incidents', 'ssl_chain_valid'):
        cur.execute("ALTER TABLE incidents ADD COLUMN ssl_chain_valid BOOLEAN")
    _safe_index(cur, conn, "idx_incidents_site_start", "incidents", "site, start_time DESC")
    try:
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_unresolved
            ON incidents (resolved)
            WHERE resolved = FALSE
        """)
    except psycopg2.Error:
        conn.rollback()

    # Таблица управляемых сайтов
    cur.execute("""
        CREATE TABLE IF NOT EXISTS monitored_sites (
            site TEXT PRIMARY KEY,
            site_group TEXT DEFAULT 'external',
            is_active BOOLEAN DEFAULT TRUE,
            alert_threshold INTEGER DEFAULT 5,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Миграция: добавить отсутствующие столбцы в monitored_sites
    if not _column_exists(cur, 'monitored_sites', 'site_group'):
        cur.execute("ALTER TABLE monitored_sites ADD COLUMN site_group TEXT DEFAULT 'external'")
        print("[INIT] Migrated: added site_group column")
    if not _column_exists(cur, 'monitored_sites', 'is_active'):
        cur.execute("ALTER TABLE monitored_sites ADD COLUMN is_active BOOLEAN DEFAULT TRUE")
        print("[INIT] Migrated: added is_active column")
    if not _column_exists(cur, 'monitored_sites', 'alert_threshold'):
        cur.execute("ALTER TABLE monitored_sites ADD COLUMN alert_threshold INTEGER DEFAULT 5")
        print("[INIT] Migrated: added alert_threshold column")
    if not _column_exists(cur, 'monitored_sites', 'created_at'):
        cur.execute("ALTER TABLE monitored_sites ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        print("[INIT] Migrated: added created_at column")
    # Таблица категорий сайтов (динамические)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS site_categories (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            content_match_enabled BOOLEAN DEFAULT FALSE,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Seed default categories if empty
    cur.execute("SELECT COUNT(*) FROM site_categories")
    if cur.fetchone()[0] == 0:
        cur.execute("""
            INSERT INTO site_categories (id, label, content_match_enabled, sort_order) VALUES
                ('key', 'Ключевые', TRUE, 0),
                ('stdo', 'СТДО', FALSE, 1),
                ('external', 'Внешние сайты', FALSE, 2)
            ON CONFLICT (id) DO NOTHING
        """)
        print("[INIT] Seeded site_categories")

    # Заполняем дефолтными сайтами если таблица пустая
    cur.execute("SELECT COUNT(*) FROM monitored_sites")
    if cur.fetchone()[0] == 0:
        print("[INIT] Seeding monitored_sites with default list...")
        default_sites = [
            ("sibur.ru", "key"),
            ("eshop.sibur.ru", "key"),
            ("shop.sibur.ru", "key"),
            ("srm.sibur.ru", "key"),
            ("career.sibur.ru", "key"),
            ("alphapor.ru", "external"),
            ("amur-gcc.ru", "external"),
            ("ar24.sibur.ru", "external"),
            ("bopp.sibur.ru", "external"),
            ("carbo.sibur.ru", "external"),
            ("carbonfootprintcalculator.sibur.ru", "external"),
            ("catalog.sibur.ru", "external"),
            ("coach.sibur.ru", "external"),
            ("ecoball.sibur.ru", "external"),
            ("greencity-sibur.ru", "external"),
            ("guide.sibur.ru", "external"),
            ("laika.sibur.ru", "external"),
            ("magazine.sibur.ru", "external"),
            ("mendeleev-smena.ru", "external"),
            ("messages2.sibur.ru", "external"),
            ("nauka.sibur.ru", "external"),
            ("oknavdome.info", "external"),
            ("photo.sibur.ru", "external"),
            ("polylabsearch.ru", "external"),
            ("portenergo.com", "external"),
            ("portal-rd.rusproject.ru", "external"),
            ("rusvinyl.ru", "external"),
            ("sharefile.sibur.ru", "external"),
            ("sibur.digital", "external"),
            ("sibur-int.com", "external"),
            ("sibur-int.ru", "external"),
            ("sibur-yug.ru", "external"),
            ("snck.ru", "external"),
            ("tu-sibur.ru", "external"),
            ("transportorder.sibur.ru", "key"),
            ("vivilen.sibur.ru", "external"),
        ]
        # STDO сайты
        for s in NEW_MONITORING_SITES:
            default_sites.append((s, "stdo"))
        execute_values(cur,
            "INSERT INTO monitored_sites (site, site_group) VALUES %s ON CONFLICT DO NOTHING",
            default_sites
        )

    # Self-monitoring сайты — отдельная группа 'self'
    for s in SELF_MONITORING_SITES:
        cur.execute("""
            INSERT INTO monitored_sites (site, site_group, alert_threshold, is_active)
            VALUES (%s, 'self', 10, TRUE)
            ON CONFLICT (site) DO UPDATE SET
                site_group = 'self',
                is_active = TRUE,
                alert_threshold = 10
        """, (s,))
        if cur.rowcount > 0:
            print(f"[INIT] Added/updated self-monitoring site: {s}")

    # Таблица миграций
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """)

    # Таблица настроек приложения
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        INSERT INTO app_settings (key, value) VALUES
            ('content_match_pattern', 'sibur|сибур|логин|пароль|login|username|password|вход|войти|auth|authorization|транспорт|заказ'),
            ('category_key_label', 'Ключевые'),
            ('category_stdo_label', 'СТДО'),
            ('category_external_label', 'Внешние сайты')
        ON CONFLICT (key) DO NOTHING
    """)
    if cur.rowcount > 0:
        print(f"[INIT] Seeded app_settings: {cur.rowcount} defaults")

    conn.commit()
    cur.close()
    conn.close()


def backfill_checks_agg():
    """Предзаполнение checks_agg из существующих logs (при первом запуске)"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM checks_agg")
        if cur.fetchone()[0] == 0:
            print("Backfill checks_agg из logs...")
            cur.execute("""
                INSERT INTO checks_agg (site, bucket, checks_count, status_200_count, down_sec,
                                        avg_response_time, min_response_time, max_response_time,
                                        last_ssl_days, last_domain_days, last_ssl_chain_valid)
                SELECT
                    site,
                    date_trunc('hour', timestamp)
                        + INTERVAL '5 min' * (EXTRACT(MINUTE FROM timestamp)::int / 5),
                    COUNT(*),
                    COUNT(*) FILTER (WHERE status = 200),
                    (COUNT(*) - COUNT(*) FILTER (WHERE status = 200)) * 60,
                    AVG(response_time),
                    MIN(response_time),
                    MAX(response_time),
                    MAX(ssl_days) FILTER (WHERE ssl_days IS NOT NULL),
                    MAX(domain_days) FILTER (WHERE domain_days IS NOT NULL),
                    bool_and(ssl_chain_valid) FILTER (WHERE ssl_chain_valid IS NOT NULL)
                FROM logs
                WHERE timestamp > NOW() - INTERVAL '30 days'
                GROUP BY site,
                    date_trunc('hour', timestamp)
                        + INTERVAL '5 min' * (EXTRACT(MINUTE FROM timestamp)::int / 5)
                ON CONFLICT (site, bucket) DO NOTHING
            """)
            conn.commit()
            print(f"Backfill checks_agg завершён: {cur.rowcount} записей")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Ошибка backfill checks_agg: {e}")


def _backfill_incidents():
    """Предзаполнение incidents из существующих logs (разово при первом создании таблицы). Self-monitoring исключён."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM incidents")
        if cur.fetchone()[0] == 0:
            print("Backfill incidents из logs...")
            cur.execute("""
                WITH status_changes AS (
                    SELECT site, timestamp, status,
                        CASE WHEN status != 200 AND
                            (LAG(status) OVER (PARTITION BY site ORDER BY timestamp) = 200
                             OR LAG(status) OVER (PARTITION BY site ORDER BY timestamp) IS NULL)
                        THEN 1 ELSE 0 END as is_start
                    FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'
                      AND site <> ALL(%s)
                ),
                incident_groups AS (
                    SELECT site, timestamp, status,
                        SUM(is_start) OVER (PARTITION BY site ORDER BY timestamp) as grp_id
                    FROM status_changes WHERE status != 200
                ),
                incident_summary AS (
                    SELECT site,
                        MIN(timestamp) as start_time,
                        MAX(timestamp) as end_time,
                        COUNT(*) as dur,
                        MAX(status) as max_status,
                        CASE WHEN MAX(status) = 0 THEN 'Timeout'
                             WHEN MAX(status) = 502 THEN 'Bad Gateway'
                             WHEN MAX(status) = 503 THEN 'Service Unavailable'
                             WHEN MAX(status) = 701 THEN 'Content Mismatch'
                             ELSE 'Server Error' END as description
                    FROM incident_groups
                    GROUP BY site, grp_id
                    HAVING COUNT(*) >= 5
                )
                INSERT INTO incidents (site, start_time, end_time, duration_min,
                                       max_status, description, resolved, ssl_chain_valid)
                SELECT site, start_time, end_time,
                       CEIL(EXTRACT(EPOCH FROM (end_time - start_time))/60)::INT,
                       max_status, description, TRUE, NULL
                FROM incident_summary
                ORDER BY start_time
            """, (SELF_MONITORING_SITES,))
            conn.commit()
            print(f"Backfill incidents завершён: {cur.rowcount} записей")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Ошибка backfill incidents: {e}")


def ensure_partitions():
    """Автоматическое создание партиций на следующий месяц (Этап 1)"""
    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.datetime.now()
    for offset in range(3):
        yy, mm = now.year, now.month + offset
        while mm > 12:
            mm -= 12
            yy += 1
        mm_next = mm + 1 if mm < 12 else 1
        yy_next = yy if mm < 12 else yy + 1
        try:
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS logs_{yy}_{mm:02d}
                PARTITION OF logs
                FOR VALUES FROM ('{yy}-{mm:02d}-01')
                TO ('{yy_next}-{mm_next:02d}-01')
            """)
        except psycopg2.Error:
            conn.rollback()
    conn.commit()
    cur.close()
    conn.close()


# ============================================================================
# TELEGRAM
# ============================================================================
def send_tg_msg(text, photo_path=None):
    """Отправка в Telegram с retry (3 попытки) + логированием"""
    print(f"[TG SEND] Attempting to send: {text[:80]} photo={'yes' if photo_path else 'no'} token_len={len(TELEGRAM_TOKEN or '')} chat_id={TELEGRAM_CHAT_ID}")
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[TG SKIP] No token/chat_id configured. Message: {text[:60]}")
        return False
    base_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/"
    ok = False
    for attempt in range(1, 4):
        try:
            if photo_path and os.path.exists(photo_path):
                with open(photo_path, 'rb') as f:
                    resp = requests.post(
                        base_url + "sendPhoto",
                        data={"chat_id": TELEGRAM_CHAT_ID, "caption": text},
                        files={"photo": f},
                        timeout=30
                    )
                if resp.status_code == 200:
                    print(f"[TG OK] Photo sent (attempt {attempt}) to {TELEGRAM_CHAT_ID[:5]}...: {text[:80]}")
                    ok = True
                    break
                print(f"[TG ERR] Photo attempt {attempt}: HTTP {resp.status_code} — {resp.text[:200]}")
            else:
                resp = requests.post(
                    base_url + "sendMessage",
                    json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
                    timeout=10
                )
                if resp.status_code == 200:
                    print(f"[TG OK] Text sent (attempt {attempt}) to {TELEGRAM_CHAT_ID[:5]}...: {text[:80]}")
                    ok = True
                    break
                print(f"[TG ERR] Text attempt {attempt}: HTTP {resp.status_code} — {resp.text[:200]}")
        except Exception as e:
            print(f"[TG ERR] attempt {attempt}: {type(e).__name__}: {e}")
        # exponential backoff
        if attempt < 3:
            time.sleep(2 ** attempt)
    # cleanup photo in any case
    if photo_path and os.path.exists(photo_path):
        try:
            os.remove(photo_path)
        except Exception:
            pass
    return ok


# ============================================================================
# WHOIS
# ============================================================================
def _check_ssl_sync(domain_only, site):
    """Синхронная SSL-проверка (для вызова через asyncio.to_thread)"""
    try:
        if site in SELF_SIGNED_SITES:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain_only, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain_only) as ssock:
                    cert = ssock.getpeercert()
                    exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    ssl_d = (exp - datetime.datetime.utcnow()).days
                    return ssl_d, None  # N/A for self-signed
        else:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain_only, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain_only) as ssock:
                    cert = ssock.getpeercert()
                    exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    ssl_d = (exp - datetime.datetime.utcnow()).days
                    return ssl_d, True
    except ssl.SSLCertVerificationError:
        return -1, False
    except Exception:
        return -1, None


def _check_whois_sync(domain_only):
    """Синхронная WHOIS-проверка (для вызова через asyncio.to_thread)"""
    try:
        import whois
        w = whois.whois(domain_only)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if exp:
            return (exp.replace(tzinfo=None) - datetime.datetime.now()).days
    except Exception:
        pass
    return -1


def get_domain_info(site):
    return _check_whois_sync(site.split('/')[0])


# ============================================================================
# АСИНХРОННЫЕ ПРОВЕРКИ САЙТОВ (Этап 2.2)
# ============================================================================
async def check_single_site(session, site, semaphore):
    """Быстрая HTTP-проверка сайта. Content match для Ключевых сайтов.
    SSL+WHOIS обновляются отдельным циклом."""
    check_url = f"https://{site}"
    curr_status, resp_time = 0, 25.0

    ssl_verify = not should_verify(site)
    connector = aiohttp.TCPConnector(ssl=False) if ssl_verify else None
    start = time.time()
    actual_session = None
    async with semaphore:
        try:
            if ssl_verify and connector:
                actual_session = aiohttp.ClientSession(connector=connector)
            else:
                actual_session = session

            timeout = aiohttp.ClientTimeout(total=8)
            async with actual_session.get(check_url, timeout=timeout, allow_redirects=True) as resp:
                curr_status = resp.status
                resp_time = time.time() - start
                # Content match для сайтов с включенным content match в их категории
                if site in _cm_sites_set and curr_status in (200, 401):
                    try:
                        text = await asyncio.wait_for(resp.text(), timeout=10)
                        text_lower = text.lower()
                        match_found = _content_match_regex.search(text_lower)
                        if match_found:
                            curr_status = 200
                            print(f"[CONTENT MATCH OK] {site} (status {resp.status})")
                        else:
                            curr_status = 701
                            # Диагностика: показать ВЕСЬ текст и найденные слова
                            print(f"[CONTENT MISMATCH] {site} — text ({len(text)} chars): {repr(text_lower[:800])}")
                            for kw in ['войдите', 'логин', 'пароль', 'login', 'password', 'sibur', 'сибур']:
                                idx = text_lower.find(kw)
                                if idx >= 0:
                                    print(f"  FOUND '{kw}' at pos {idx}: ...{text_lower[max(0,idx-20):idx+len(kw)+20]}...")
                                else:
                                    print(f"  NOT FOUND: '{kw}'")
                    except Exception as e:
                        curr_status = 701
                        print(f"[CONTENT MISMATCH] {site} — {type(e).__name__}: {e}")
                elif curr_status == 401:
                    # 401 = сервер работает, требует авторизацию — считаем OK
                    curr_status = 200
        except Exception as e:
            curr_status, resp_time = 0, 25.0
        finally:
            if ssl_verify and connector and actual_session is not None:
                await actual_session.close()

    return (site, curr_status, resp_time)


async def check_all_sites(sites_list):
    """Параллельная HTTP-проверка всех сайтов (только status + response_time)"""
    semaphore = asyncio.Semaphore(15)
    async with aiohttp.ClientSession() as session:
        tasks = [check_single_site(session, site, semaphore) for site in sites_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]


async def check_self_monitoring():
    """Проверка self-monitoring: любой HTTP-ответ = сервер жив (status→200).
    Только полный отказ (timeout, connection error) = Offline (status=0)."""
    results = []
    async with aiohttp.ClientSession() as session:
        for site in SELF_MONITORING_SITES:
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with session.get(f"https://{site}", timeout=timeout, allow_redirects=True) as resp:
                    # Любой HTTP-ответ (200, 401, 403, 404, 500...) = сервер отвечает
                    status = 200 if resp.status > 0 else 0
            except Exception:
                status = 0
            results.append((site, status, 0.5, -1, -1, None))
    return results


# ============================================================================
# BATCH-ВСТАВКА (Этап 2.1)
# ============================================================================
def _update_checks_agg(cur, batch_data):
    """UPSERT агрегатов за 5-минутный bucket при batch-вставке"""
    from collections import defaultdict
    agg = defaultdict(lambda: {
        'cnt': 0, 'ok': 0, 'r_sum': 0.0,
        'r_min': float('inf'), 'r_max': 0.0, 'ssl': None, 'dom': None, 'ssl_chain': None
    })
    for row in batch_data:
        site, status, resp, ssl_d, dom_d, ssl_chain_valid = row[:6]
        now = datetime.datetime.now()
        bucket = now.replace(minute=(now.minute // 5) * 5, second=0, microsecond=0)
        k = (site, bucket)
        a = agg[k]
        a['cnt'] += 1
        if status == 200:
            a['ok'] += 1
        a['r_sum'] += resp
        a['r_min'] = min(a['r_min'], resp)
        a['r_max'] = max(a['r_max'], resp)
        if ssl_d is not None and ssl_d >= 0:
            a['ssl'] = ssl_d
        if dom_d is not None and dom_d >= 0:
            a['dom'] = dom_d
        if ssl_chain_valid is not None:
            a['ssl_chain'] = ssl_chain_valid
    for (site, bucket), a in agg.items():
        failed = a['cnt'] - a['ok']
        down_sec = failed * 60  # каждая проверка раз в 60 сек
        cur.execute("""
            INSERT INTO checks_agg (site, bucket, checks_count, status_200_count, down_sec,
                                    avg_response_time, min_response_time, max_response_time,
                                    last_ssl_days, last_domain_days, last_ssl_chain_valid)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (site, bucket) DO UPDATE SET
                checks_count = checks_agg.checks_count + EXCLUDED.checks_count,
                status_200_count = checks_agg.status_200_count + EXCLUDED.status_200_count,
                down_sec = checks_agg.down_sec + EXCLUDED.down_sec,
                avg_response_time = (checks_agg.avg_response_time * checks_agg.checks_count
                                     + EXCLUDED.avg_response_time * EXCLUDED.checks_count)
                                    / (checks_agg.checks_count + EXCLUDED.checks_count),
                min_response_time = LEAST(checks_agg.min_response_time, EXCLUDED.min_response_time),
                max_response_time = GREATEST(checks_agg.max_response_time, EXCLUDED.max_response_time),
                last_ssl_days = COALESCE(EXCLUDED.last_ssl_days, checks_agg.last_ssl_days),
                last_domain_days = COALESCE(EXCLUDED.last_domain_days, checks_agg.last_domain_days),
                last_ssl_chain_valid = COALESCE(EXCLUDED.last_ssl_chain_valid, checks_agg.last_ssl_chain_valid)
        """, (site, bucket, a['cnt'], a['ok'], down_sec,
              a['r_sum'] / a['cnt'], a['r_min'], a['r_max'], a['ssl'], a['dom'], a['ssl_chain']))


def flush_batch():
    """Сброс накопленных данных пакетом в БД + обновление агрегатов"""
    global batch_buffer
    with BATCH_LOCK:
        if not batch_buffer:
            return
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            execute_values(
                cur,
                """INSERT INTO logs
                   (site, status, response_time, ssl_days, domain_days, ssl_chain_valid)
                   VALUES %s""",
                batch_buffer
            )
            _update_checks_agg(cur, batch_buffer)
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"Ошибка batch-вставки: {e}")
        finally:
            batch_buffer.clear()


# ============================================================================
# ИНЦИДЕНТЫ — запись из worker
# ============================================================================
def _db_incident_start(site, status, ssl_chain_valid=None, start_time=None):
    """Фиксирует начало инцидента. Если активный уже есть — обновляет max_status, не дублирует."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        description = {
            0: 'Timeout',
            502: 'Bad Gateway',
            503: 'Service Unavailable',
            701: 'Content Mismatch'
        }.get(status, 'Server Error')
        ts = start_time if start_time else datetime.datetime.now()
        # Проверяем: есть ли уже активный инцидент для этого сайта
        cur.execute("SELECT id FROM incidents WHERE site = %s AND resolved = FALSE LIMIT 1", (site,))
        existing = cur.fetchone()
        if existing:
            # Активный инцидент уже есть — обновляем max_status
            cur.execute("""
                UPDATE incidents
                SET max_status = GREATEST(COALESCE(max_status, 0), %s),
                    description = %s,
                    ssl_chain_valid = COALESCE(%s, ssl_chain_valid)
                WHERE id = %s
            """, (status, description, ssl_chain_valid, existing[0]))
            conn.commit()
            cur.close()
            conn.close()
            return
        # Активного нет — создаём новый
        cur.execute("""
            INSERT INTO incidents (site, start_time, max_status, description, ssl_chain_valid)
            VALUES (%s, %s, %s, %s, %s)
        """, (site, ts, status, description, ssl_chain_valid))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[INCIDENT START ERR] {site}: {e}")


def _db_incident_update(site, status, ssl_chain_valid=None):
    """Обновляет max_status текущего неразрешённого инцидента"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        description = {
            0: 'Timeout',
            502: 'Bad Gateway',
            503: 'Service Unavailable',
            701: 'Content Mismatch'
        }.get(status, 'Server Error')
        cur.execute("""
            UPDATE incidents
            SET max_status = GREATEST(COALESCE(max_status, 0), %s),
                description = %s,
                ssl_chain_valid = COALESCE(%s, ssl_chain_valid)
            WHERE site = %s AND resolved = FALSE
        """, (status, description, ssl_chain_valid, site))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[INCIDENT UPDATE ERR] {site}: {e}")


def _db_incident_resolve(site):
    """Закрывает открытый инцидент (сайт восстановился)"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE incidents
            SET end_time = NOW(),
                duration_min = GREATEST(1, FLOOR(EXTRACT(EPOCH FROM (NOW() - start_time))/60)::INT),
                resolved = TRUE
            WHERE site = %s AND resolved = FALSE
        """, (site,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[INCIDENT RESOLVE ERR] {site}: {e}")


# ============================================================================
# ОБНОВЛЕНИЕ МАТЕРИАЛИЗОВАННОГО ПРЕДСТАВЛЕНИЯ (Этап 3)
# ============================================================================
def refresh_materialized_view():
    """Обновление latest_status — CONCURRENTLY если возможно, иначе обычно"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY latest_status")
        except psycopg2.Error:
            conn.rollback()
            cur.execute("REFRESH MATERIALIZED VIEW latest_status")
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Ошибка обновления мат. представления: {e}")


# ============================================================================
# RETENTION POLICY / РОТАЦИЯ (Этап 1)
# ============================================================================
def rotate_logs(retention_days: int = 30):
    """Агрегация старых данных и удаление устаревших партиций"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=retention_days)

        cur.execute("""
            INSERT INTO checks_agg (site, bucket, checks_count, status_200_count,
                                   avg_response_time, min_response_time, max_response_time,
                                   last_ssl_days, last_domain_days, last_ssl_chain_valid)
            SELECT
                site,
                date_trunc('hour', timestamp)
                    + INTERVAL '5 min' * (EXTRACT(MINUTE FROM timestamp)::int / 5),
                COUNT(*),
                COUNT(*) FILTER (WHERE status = 200),
                AVG(response_time),
                MIN(response_time),
                MAX(response_time),
                MAX(ssl_days) FILTER (WHERE ssl_days IS NOT NULL),
                MAX(domain_days) FILTER (WHERE domain_days IS NOT NULL),
                bool_and(ssl_chain_valid) FILTER (WHERE ssl_chain_valid IS NOT NULL)
            FROM logs
            WHERE timestamp < %s
              AND timestamp >= %s - INTERVAL '1 day'
            GROUP BY site,
                date_trunc('hour', timestamp)
                    + INTERVAL '5 min' * (EXTRACT(MINUTE FROM timestamp)::int / 5)
            ON CONFLICT (site, bucket) DO UPDATE SET
                checks_count = checks_agg.checks_count + EXCLUDED.checks_count,
                status_200_count = checks_agg.status_200_count + EXCLUDED.status_200_count,
                avg_response_time = (checks_agg.avg_response_time * checks_agg.checks_count
                                     + EXCLUDED.avg_response_time * EXCLUDED.checks_count)
                                    / (checks_agg.checks_count + EXCLUDED.checks_count),
                min_response_time = LEAST(checks_agg.min_response_time, EXCLUDED.min_response_time),
                max_response_time = GREATEST(checks_agg.max_response_time, EXCLUDED.max_response_time),
                last_ssl_days = COALESCE(EXCLUDED.last_ssl_days, checks_agg.last_ssl_days),
                last_domain_days = COALESCE(EXCLUDED.last_domain_days, checks_agg.last_domain_days),
                last_ssl_chain_valid = COALESCE(EXCLUDED.last_ssl_chain_valid, checks_agg.last_ssl_chain_valid)
        """, (cutoff_date, cutoff_date))

        cur.execute("""
            SELECT tablename FROM pg_tables
            WHERE tablename LIKE 'logs________'
              AND tablename < 'logs_' || to_char(%s, 'YYYY_MM')
        """, (cutoff_date,))
        for row in cur.fetchall():
            tbl = row[0]
            try:
                cur.execute(f"DROP TABLE IF EXISTS {tbl} CASCADE")
            except psycopg2.Error:
                conn.rollback()

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Ошибка ротации логов: {e}")


# ============================================================================
# CHECK WORKER (обновлённый)
# ============================================================================
def _invalidate_dashboard_cache():
    """Сбрасывает кэш dashboard для мгновенного обновления при DOWN/UP"""
    global _dashboard_cache
    with _dashboard_cache["lock"]:
        _dashboard_cache["timestamp"] = 0


def _update_worker_heartbeat():
    """Записывает метку времени последнего цикла проверок"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO health (key, value, updated)
            VALUES ('last_worker_tick', NOW()::text, NOW())
            ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                updated = NOW()
        """)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[HEARTBEAT ERR] {e}")


def _get_ssl_whois_data(site, latest_data):
    """Читает SSL/WHOIS из latest_status (обновляется отдельным воркером)"""
    row = latest_data.get(site, {})
    return (
        row.get('ssl_days', -1),
        row.get('domain_days', -1),
        row.get('ssl_chain_valid', None)
    )


# ===== SCREENSHOT QUEUE (singleton, один фоновый поток) =====
_screenshot_queue = queue.Queue()
_screenshot_thread = None

def _screenshot_worker():
    """Фоновый поток: обрабатывает скриншоты ПО ОДНОМУ — без race condition."""
    while True:
        try:
            site, caption = _screenshot_queue.get(timeout=30)
        except queue.Empty:
            continue
        try:
            path = take_screenshot_fast(site)
            if path:
                send_tg_msg(caption, path)
            else:
                print(f"[SCREEN QUEUE] {site}: screenshot failed, skipping TG")
        except Exception as e:
            print(f"[SCREEN QUEUE ERR] {site}: {e}")
        finally:
            _screenshot_queue.task_done()

def _ensure_screenshot_thread():
    """Запускает фоновый поток если ещё не запущен."""
    global _screenshot_thread
    if _screenshot_thread is None or not _screenshot_thread.is_alive():
        _screenshot_thread = threading.Thread(target=_screenshot_worker, daemon=True)
        _screenshot_thread.start()
        print("[SCREEN QUEUE] worker thread started")

def _fmt_downtime(down_sec):
    """Форматирует время простоя: '—' если 0, 'X мин' если <60, 'X ч Y мин' если >=60."""
    if not down_sec or down_sec <= 0:
        return "—"
    mins = int(down_sec / 60)
    if mins < 60:
        return f"{mins} мин"
    hours = mins // 60
    rem_mins = mins % 60
    if rem_mins == 0:
        return f"{hours} ч"
    return f"{hours} ч {rem_mins} мин"


def _send_screenshot_async(site, caption):
    """Добавляет скриншот в очередь. Один поток обрабатывает последовательно — никаких race condition."""
    _ensure_screenshot_thread()
    _screenshot_queue.put((site, caption))
    print(f"[SCREEN QUEUE] {site} added (queue size: {_screenshot_queue.qsize()})")


def _process_site_result(site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid,
                         last_status, fail_count, last_latency_map, thresholds, first_fail_time):
    """Алерт + инцидент только при превышении порога (alert_threshold, default 5 мин).
    TG-алерт и _db_incident_start — при fail_count >= threshold.
    Скриншот в фоне — не блокирует worker."""
    try:
        changed = (curr_status != 200) or (last_status.get(site, 200) != 200)
        if changed:
            print(f"[WORKER] {site} status={curr_status} resp={round(resp_time,2)}s fail={fail_count.get(site, 0)} last={last_status.get(site, 200)}")

        if curr_status != 200:
            was_up = last_status.get(site, 200) == 200
            fail_count[site] = fail_count.get(site, 0) + 1

            if fail_count[site] == 1:
                first_fail_time[site] = datetime.datetime.now()
                print(f"[FIRST FAIL] {site} at {first_fail_time[site]}")

            alert_threshold = thresholds.get(site, 5)
            print(f"[ALERT CHECK] {site} fail={fail_count[site]} thr={alert_threshold} last={last_status.get(site, 200)}")

            if fail_count[site] >= alert_threshold and was_up:
                # Порог превышен — создаём инцидент + алерт
                incident_start = first_fail_time.get(site) or datetime.datetime.now()
                print(f"[INCIDENT START] {site} fail={fail_count[site]} thr={alert_threshold} status={curr_status} (start: {incident_start})")
                _db_incident_start(site, curr_status, ssl_chain_valid, incident_start)
                print(f"[ALERT TRIGGER] {site} fail={fail_count[site]} thr={alert_threshold}")
                ok = send_tg_msg(f"🚨 DOWN: {site} (Код: {curr_status})")
                print(f"[ALERT RESULT] {site} DOWN send_tg_msg={'OK' if ok else 'FAIL'}")
                _send_screenshot_async(site, f"📸 Скриншот при падении: {site}")
                last_status[site] = curr_status
                _invalidate_dashboard_cache()
            elif fail_count[site] > alert_threshold:
                _db_incident_update(site, curr_status, ssl_chain_valid)

            with BATCH_LOCK:
                if fail_count[site] >= 2:
                    batch_buffer.append((site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid))
                if len(batch_buffer) >= BATCH_SIZE:
                    flush_batch()
        else:
            with BATCH_LOCK:
                batch_buffer.append((site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid))
                if len(batch_buffer) >= BATCH_SIZE:
                    flush_batch()

            fc = fail_count.get(site, 0)
            if fc >= thresholds.get(site, 5):
                print(f"[INCIDENT RESOLVE] {site} after {fc} min down")
                _db_incident_resolve(site)

            if last_status.get(site, 200) != 200:
                duration = fc
                print(f"[ALERT TRIGGER] {site} UP after {duration} min")
                ok = send_tg_msg(f"✅ UP: {site} (Был недоступен: {duration} мин.)")
                print(f"[ALERT RESULT] {site} UP send_tg_msg={'OK' if ok else 'FAIL'}")
                _send_screenshot_async(site, f"📸 Скриншот при восстановлении: {site}")
                _invalidate_dashboard_cache()

            last_status[site] = 200
            fail_count[site] = 0
            first_fail_time.pop(site, None)

            if resp_time > 20 and not last_latency_map.get(site, False):
                ok = send_tg_msg(f"🐢 ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек.")
                last_latency_map[site] = True
            elif resp_time < 10 and last_latency_map.get(site, False):
                ok = send_tg_msg(f"⚡️ СКОРОСТЬ ВОСТАНОВЛЕНА! {site}: {round(resp_time, 2)} сек.")
                last_latency_map[site] = False
    except Exception as e:
        print(f"[ERR] {site}: {e}")


def _process_self_monitoring_result(site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid,
                                    last_status, fail_count, last_latency_map, first_fail_time):
    """Self-monitoring: алерт + инцидент только при пороге 10 мин.
    Скриншот в фоне — не блокирует worker."""
    try:
        SM_THRESHOLD = 10
        if curr_status != 200:
            was_up = last_status.get(site, 200) == 200
            fail_count[site] = fail_count.get(site, 0) + 1

            if fail_count[site] == 1:
                first_fail_time[site] = datetime.datetime.now()
                print(f"[SM FIRST FAIL] {site} at {first_fail_time[site]}")

            print(f"[SM ALERT CHECK] {site} fail={fail_count[site]} thr={SM_THRESHOLD} last={last_status.get(site, 200)}")

            if fail_count[site] >= SM_THRESHOLD and was_up:
                # Порог 10 мин превышен — инцидент + алерт
                incident_start = first_fail_time.get(site) or datetime.datetime.now()
                print(f"[SM INCIDENT START] {site} (start: {incident_start})")
                _db_incident_start(site, curr_status, ssl_chain_valid, incident_start)
                print(f"[SM ALERT TRIGGER] {site} fail={fail_count[site]} thr={SM_THRESHOLD}")
                ok = send_tg_msg(f"🚨 [SELF-MONITORING] DOWN: {site} (Код: {curr_status})")
                print(f"[SM ALERT RESULT] DOWN {'OK' if ok else 'FAIL'}")
                _send_screenshot_async(site, f"📸 [SM] Скриншот при падении: {site}")
                last_status[site] = curr_status
                _invalidate_dashboard_cache()
            elif fail_count[site] > SM_THRESHOLD:
                _db_incident_update(site, curr_status, ssl_chain_valid)

            with BATCH_LOCK:
                batch_buffer.append((site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid))
                if len(batch_buffer) >= BATCH_SIZE:
                    flush_batch()
        else:
            with BATCH_LOCK:
                batch_buffer.append((site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid))
                if len(batch_buffer) >= BATCH_SIZE:
                    flush_batch()

            fc = fail_count.get(site, 0)
            if fc >= SM_THRESHOLD:
                _db_incident_resolve(site)

            if last_status.get(site, 200) != 200:
                duration = fc
                print(f"[SM ALERT] {site} UP after {duration} min")
                ok = send_tg_msg(f"✅ [SELF-MONITORING] UP: {site} (Был недоступен: {duration} мин.)")
                print(f"[SM ALERT RESULT] UP {'OK' if ok else 'FAIL'}")
                _send_screenshot_async(site, f"📸 [SM] Скриншот при восстановлении: {site}")
                _invalidate_dashboard_cache()

            last_status[site] = 200
            fail_count[site] = 0
            first_fail_time.pop(site, None)
    except Exception as e:
        print(f"[SM ERR] {site}: {e}")


def check_worker():
    """Фоновый воркер: быстрые HTTP-проверки каждую минуту. SSL+WHOIS — отдельный воркер."""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("[WORKER START] check_worker started")

    global SITES, KEY_SITES, STDO_SITES, EXTERNAL_SITES
    last_status = {}
    fail_count = {}
    last_latency_map = {}
    first_fail_time = {}

    # Инициализация self-monitoring состояния
    for site in SELF_MONITORING_SITES:
        last_status[site] = 200
        fail_count[site] = 0
        last_latency_map[site] = False

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    while True:
        t_start = time.time()
        try:
            # Обновляем список сайтов из БД каждый цикл
            SITES, _categories, thresholds = load_active_sites()
            # Build legacy vars for backward compat
            KEY_SITES = _categories.get('key', [])
            STDO_SITES = _categories.get('stdo', [])
            EXTERNAL_SITES = _categories.get('external', [])
            # Build content match set: all sites from categories with content_match_enabled
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT id FROM site_categories WHERE content_match_enabled = TRUE")
            cm_cats = [r[0] for r in cur.fetchall()]
            cur.close()
            conn.close()
            global _cm_sites_set
            _cm_sites_set = set()
            for cat_id in cm_cats:
                _cm_sites_set.update(_categories.get(cat_id, []))
            # Обновляем настройки (content match pattern)
            global _content_match_pattern, _content_match_regex
            settings = load_settings()
            new_pattern = settings.get('content_match_pattern', 'sibur|сибур')
            if new_pattern != _content_match_pattern:
                try:
                    _content_match_regex = re.compile(new_pattern, re.IGNORECASE)
                    _content_match_pattern = new_pattern
                    print(f"[WORKER] Content match updated: {new_pattern}")
                except re.error as e:
                    print(f"[WORKER] Invalid content match pattern: {e}")
            # Защита: если thresholds пустой (например, БД пустая), fallback на 5
            if not thresholds and SITES:
                thresholds = {s: 5 for s in SITES}
                print(f"[WORKER] thresholds empty, fallback to 5 for all {len(SITES)} sites")
            # Инициализируем состояние для новых сайтов
            for site in SITES:
                if site not in last_status:
                    last_status[site] = 200
                    fail_count[site] = 0
                    last_latency_map[site] = False
            # Убираем удаленные сайты
            for site in list(last_status.keys()):
                if site not in SITES and site not in SELF_MONITORING_SITES:
                    del last_status[site]
                    del fail_count[site]
                    del last_latency_map[site]

            print(f"[WORKER] {len(SITES)} sites loaded, {len(_categories)} categories, thresholds={len(thresholds)} sites at {datetime.datetime.now(TZ_MOSCOW).strftime('%H:%M:%S')}")
            if not SITES:
                print("[WORKER WARN] SITES is empty! Check monitored_sites table and is_active flags.")

            # Быстрые HTTP-проверки обычных сайтов
            results = loop.run_until_complete(check_all_sites(SITES))
            http_time = round(time.time() - t_start, 1)
            print(f"[WORKER] HTTP checks done: {len(results)} sites in {http_time}s")

            # Проверка self-monitoring через /health
            self_results = loop.run_until_complete(check_self_monitoring())
            print(f"[WORKER] Self-monitoring: {len(self_results)} sites")

            # Читаем SSL/WHOIS из latest_status
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute("SELECT site, ssl_days, domain_days, ssl_chain_valid FROM latest_status")
            latest_data = {r['site']: r for r in cur.fetchall()}
            cur.close()
            conn.close()

            # Обработка обычных сайтов
            for site, curr_status, resp_time in results:
                ssl_d, dom_d, ssl_chain_valid = _get_ssl_whois_data(site, latest_data)
                _process_site_result(site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid,
                                     last_status, fail_count, last_latency_map, thresholds, first_fail_time)

            # Обработка self-monitoring сайтов (алерты с порогом 10 мин)
            for site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid in self_results:
                _process_self_monitoring_result(site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid,
                                                last_status, fail_count, last_latency_map, first_fail_time)

            flush_batch()
            refresh_materialized_view()
            _update_worker_heartbeat()
            failed_now = sum(1 for _, st, *_ in results if st != 200)
            cycle_time = round(time.time() - t_start, 1)
            print(f"[CHECK SUMMARY] checked={len(results)} failed={failed_now} cycle_time={cycle_time}s")

        except Exception as e:
            print(f"[WORKER ERROR] {type(e).__name__}: {e}")

        # Динамический sleep: гарантируем ровно 60 сек между стартами циклов
        elapsed = time.time() - t_start
        sleep_time = max(0, 60 - elapsed)
        print(f"[WORKER] Sleeping {round(sleep_time,1)}s (elapsed={round(elapsed,1)}s)")
        time.sleep(sleep_time)


def ssl_whois_worker():
    """Отдельный воркер: SSL + WHOIS проверки раз в 4 часа (медленные операции)"""
    print("[SSL WORKER START] ssl_whois_worker started")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    while True:
        try:
            t_start = time.time()
            print(f"[SSL WORKER] Starting SSL+WHOIS checks at {datetime.datetime.now(TZ_MOSCOW).strftime('%H:%M:%S')}")

            # Проверяем все сайты, включая self-monitoring
            all_sites_to_check = list(SITES) + list(SELF_MONITORING_SITES)
            for site in all_sites_to_check:
                domain_only = site.split('/')[0]
                try:
                    ssl_d, ssl_chain_valid = _check_ssl_sync(domain_only, site)
                except Exception:
                    ssl_d, ssl_chain_valid = -1, None

                try:
                    dom_d = _check_whois_sync(domain_only)
                except Exception:
                    dom_d = -1

                # Обновляем latest_status через direct DB update
                try:
                    conn = get_db_connection()
                    cur = conn.cursor()
                    cur.execute("""
                        UPDATE logs
                        SET ssl_days = %s, domain_days = %s, ssl_chain_valid = %s
                        WHERE site = %s
                          AND timestamp = (SELECT MAX(timestamp) FROM logs WHERE site = %s)
                    """, (ssl_d, dom_d, ssl_chain_valid, site, site))
                    conn.commit()
                    cur.close()
                    conn.close()
                except Exception:
                    pass

                time.sleep(0.5)  # Небольшая пауза между сайтами

            refresh_materialized_view()
            elapsed = round(time.time() - t_start, 1)
            print(f"[SSL WORKER] Completed in {elapsed}s, sleeping 4 hours")

        except Exception as e:
            print(f"[SSL WORKER ERROR] {e}")

        time.sleep(4 * 3600)


# ============================================================================
# DAILY REPORT WORKER
# ============================================================================
def daily_report_worker():
    """Рассылка отчёта по SSL в 09:00 МСК"""
    while True:
        now = datetime.datetime.now(TZ_MOSCOW)
        if now.hour == 9 and now.minute == 0:
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=DictCursor)
                cur.execute("SELECT site, ssl_days FROM latest_status")
                rows = cur.fetchall()
                cur.close()
                conn.close()

                ssl_alerts = [
                    f"🔒 {r[0]} — осталось {r[1]}д."
                    for r in rows
                    if r[1] is not None and 0 <= r[1] <= 20 and r[0] not in SELF_MONITORING_SITES
                ]

                if ssl_alerts:
                    msg = "🔔 Утренний отчет по SSL (менее 20 дней):\n\n" + "\n".join(ssl_alerts)
                    send_tg_msg(msg)

                time.sleep(61)
            except Exception:
                pass
        time.sleep(30)


# ============================================================================
# ROTATION WORKER (Этап 1)
# ============================================================================
def rotation_worker():
    """Ежедневная ротация логов в 03:00 МСК + создание партиций"""
    while True:
        now = datetime.datetime.now(TZ_MOSCOW)
        if now.hour == 3 and now.minute == 0:
            try:
                ensure_partitions()
                rotate_logs(retention_days=30)
                print(f"Ротация логов выполнена: {now}")
                time.sleep(61)
            except Exception as e:
                print(f"Ошибка ротации: {e}")
        time.sleep(60)


# ============================================================================
# STARTUP
# ============================================================================
@app.on_event("startup")
async def startup_event():
    # Неблокирующий запуск тяжёлых операций в отдельных потоках
    print("[STARTUP] Starting init_db, backfill, workers...")
    await asyncio.to_thread(init_db)
    # Cleanup self-monitoring — одноразовый (после миграции self-monitoring в отдельную группу)
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT value FROM app_meta WHERE key = 'sm_cleanup_v1'")
        if not cur.fetchone():
            cur.execute("DELETE FROM incidents WHERE site = ANY(%s)", (SELF_MONITORING_SITES,))
            cur.execute("DELETE FROM checks_agg WHERE site = ANY(%s)", (SELF_MONITORING_SITES,))
            cur.execute("DELETE FROM logs WHERE site = ANY(%s)", (SELF_MONITORING_SITES,))
            for s in SELF_MONITORING_SITES:
                cur.execute("""
                    INSERT INTO logs (site, status, response_time, ssl_days, domain_days, ssl_chain_valid, timestamp)
                    VALUES (%s, 200, 0.5, -1, -1, NULL, NOW())
                """, (s,))
            cur.execute("INSERT INTO app_meta (key, value) VALUES ('sm_cleanup_v1', 'done') ON CONFLICT (key) DO NOTHING")
            conn.commit()
            print("[STARTUP] Self-monitoring cleanup done (one-time)")
        # Обновление content match паттерна при старте
        try:
            cur.execute("""
                UPDATE app_settings SET value = 'sibur|сибур|логин|пароль|login|username|password|вход|войти|auth|authorization|транспорт|заказ'
                WHERE key = 'content_match_pattern' AND value NOT LIKE '%транспорт%'
            """)
            if cur.rowcount > 0:
                print(f"[STARTUP] Content match pattern updated ({cur.rowcount} rows)")
            conn.commit()
        except Exception as e:
            print(f"[STARTUP WARN] Pattern update: {e}")
        # Миграция: добавить portal-rd.rusproject.ru если отсутствует
        try:
            cur.execute("SELECT 1 FROM monitored_sites WHERE site = 'portal-rd.rusproject.ru'")
            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO monitored_sites (site, site_group, alert_threshold, is_active)
                    VALUES ('portal-rd.rusproject.ru', 'external', 2, TRUE)
                    ON CONFLICT DO NOTHING
                """)
                conn.commit()
                print("[STARTUP] Added portal-rd.rusproject.ru to monitored_sites")
        except Exception as e:
            print(f"[STARTUP WARN] portal-rd migration: {e}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[STARTUP WARN] Self-monitoring cleanup: {e}")
    await asyncio.to_thread(backfill_checks_agg)
    await asyncio.to_thread(_backfill_incidents)
    # Cleanup: закрыть "висящие" unresolved инциденты для сайтов, которые сейчас Online
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE incidents
            SET end_time = NOW(),
                duration_min = GREATEST(1, FLOOR(EXTRACT(EPOCH FROM (NOW() - start_time))/60)::INT),
                resolved = TRUE
            WHERE resolved = FALSE
              AND site IN (
                  SELECT site FROM latest_status WHERE status = 200 OR status = 401
              )
        """)
        if cur.rowcount > 0:
            print(f"[STARTUP] Closed {cur.rowcount} stale unresolved incidents for online sites")
        # Force-close incidents for sites that return 401 (auth required = online)
        cur.execute("""
            UPDATE incidents
            SET end_time = NOW(),
                duration_min = GREATEST(1, FLOOR(EXTRACT(EPOCH FROM (NOW() - start_time))/60)::INT),
                resolved = TRUE
            WHERE resolved = FALSE AND site = 'sharefile.sibur.ru'
        """)
        if cur.rowcount > 0:
            print(f"[STARTUP] Force-closed {cur.rowcount} incidents for sharefile.sibur.ru (401=online)")
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[STARTUP WARN] Stale incident cleanup: {e}")

    threading.Thread(target=check_worker, daemon=True).start()
    threading.Thread(target=ssl_whois_worker, daemon=True).start()
    threading.Thread(target=daily_report_worker, daemon=True).start()
    threading.Thread(target=rotation_worker, daemon=True).start()
    # Telegram config check
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[WARN] TELEGRAM_TOKEN or TELEGRAM_CHAT_ID not set — alerts disabled")
    else:
        print(f"[OK] Telegram configured: chat_id={TELEGRAM_CHAT_ID[:5]}... (len={len(TELEGRAM_CHAT_ID)}), token_len={len(TELEGRAM_TOKEN)}")


# ============================================================================
# ENDPOINTS
# ============================================================================
@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    file_path = 'favicon.ico'
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return Response(status_code=204)


def check_screenshot_rate(site: str) -> bool:
    """Rate limit: 1 скриншот на сайт раз в 30 секунд"""
    now = time.time()
    with _screenshot_rate_lock:
        last = _screenshot_rate_limit.get(site, 0)
        if now - last < 30:
            return False
        _screenshot_rate_limit[site] = now
        return True


@app.get("/test-screen/{site_name:path}")
async def test_screen(site_name: str, auth: bool = Depends(check_auth)):
    if site_name not in SITES and site_name not in SELF_MONITORING_SITES:
        return JSONResponse(
            {"status": "error", "msg": "Сайт не найден в списке"},
            status_code=404
        )

    if not check_screenshot_rate(site_name):
        return JSONResponse(
            {"status": "error", "msg": "Rate limit: повторите через 30 сек"},
            status_code=429
        )

    shot = await asyncio.to_thread(take_screenshot_fast, site_name)
    if shot:
        send_tg_msg(f"🧪 Тестовый скриншот: {site_name}", shot)
        return {"status": "success", "msg": f"Скриншот {site_name} отправлен в ТГ"}

    return JSONResponse(
        {"status": "error", "msg": "Ошибка Playwright (таймаут или доступ)"},
        status_code=500
    )


@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page():
    """Страница входа в админ-панель"""
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Вход — Управление</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 320px; }
        h2 { color: #00717a; margin: 0 0 20px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 14px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #00717a; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; margin-top: 10px; }
        button:hover { background: #005f66; }
        .error { color: #dc2626; font-size: 13px; margin-top: 8px; display: none; }
    </style></head><body>
    <div class="login-box">
        <h2>🔐 Управление</h2>
        <input type="password" id="pwd" placeholder="Пароль" onkeypress="if(event.key==='Enter')doLogin()">
        <button onclick="doLogin()">Войти</button>
        <div id="err" class="error">Неверный пароль</div>
    </div>
    <script>
    async function doLogin() {
        const pwd = document.getElementById('pwd').value;
        const r = await fetch('/admin/auth', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password: pwd})});
        if (r.ok) { location.href = '/admin/page'; }
        else { document.getElementById('err').style.display = 'block'; }
    }
    </script></body></html>"""


@app.post("/admin/auth")
async def admin_auth(request: Request, response: Response):
    """Проверка пароля для админ-панели"""
    try:
        data = await request.json()
        pwd = data.get("password", "")
        if bcrypt.checkpw(pwd.encode('utf-8'), ADMIN_PASSWORD_HASH.encode('utf-8')):
            response.set_cookie(
                key="admin_session",
                value="authenticated_admin",
                max_age=2592000,
                httponly=True,
                samesite="lax"
            )
            return {"status": "ok"}
        return JSONResponse({"status": "error", "msg": "Invalid password"}, status_code=401)
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.get("/admin/page", response_class=HTMLResponse)
async def admin_page(request: Request, response: Response, admin_session: str = Cookie(None)):
    """Страница управления сайтами (требует admin-пароль) + Self Monitoring"""
    if admin_session != "authenticated_admin":
        # HTML-редирект + удаление возможной stale cookie с secure=True
        return HTMLResponse("""<script>document.cookie='admin_session=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;';location.href='/admin/login';</script>""")
    try:
        return await _admin_page_inner(request, response)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[ADMIN PAGE FATAL] {e}\n{tb}")
        return HTMLResponse(f"""<html><body style="padding:20px;font-family:monospace"><h2 style="color:#dc2626">Ошибка: {e}</h2><pre style="background:#fee2e2;padding:15px;border-radius:8px;overflow:auto">{tb}</pre><p><a href="/">← Назад</a></p></body></html>""", status_code=500)

async def _admin_page_inner(request, response):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT site, site_group, is_active, alert_threshold, created_at FROM monitored_sites WHERE site_group != 'self' ORDER BY site_group, site")
        rows = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT id, label FROM site_categories ORDER BY sort_order")
        cat_rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
    except Exception as e:
        import traceback
        print(f"[ADMIN PAGE DB ERROR] {e}")
        traceback.print_exc()
        rows = []
        cat_rows = []

    H = []
    # Pass categories to JS for dynamic badge rendering
    cat_json = json.dumps({c['id']: c['label'] for c in cat_rows})
    H.append(f"""<html><head><meta charset="UTF-8"><title>Управление сайтами</title>
    <script>window._adminCategories = {cat_json};</script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>""")
    H.append("""        body { font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; color: #1e293b; }")
        .container { max-width: 1000px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #00717a; margin: 0 0 20px; }
        .tabs { display: flex; gap: 8px; margin-bottom: 15px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
        .tab-btn { padding: 10px 20px; border: none; background: #e2e8f0; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .tab-btn.active { background: #00717a; color: white; }
        .tab-content { display: none; }
        .active-content { display: block; }
        .add-form { display: flex; gap: 10px; margin-bottom: 20px; padding: 15px; background: #f1f5f9; border-radius: 8px; flex-wrap: wrap; }
        input, select { padding: 10px; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 14px; }
        .btn { padding: 5px 10px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 12px; }
        .btn-primary { background: #00717a; color: white; }
        .btn-primary:hover { background: #005f66; }
        .btn-warn { background: #f59e0b; color: white; }
        .btn-warn:hover { background: #d97706; }
        .btn-danger { background: #ef4444; color: white; }
        .btn-danger:hover { background: #dc2626; }
        .btn-success { background: #10b981; color: white; }
        .btn-success:hover { background: #059669; }
        .btn-gray { background: #e2e8f0; color: #475569; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { padding: 10px 8px; text-align: left; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }
        th { background: #e2e8f0; color: #475569; }
        .badge { padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .badge-key { background: #fef3c7; color: #92400e; }
        .badge-stdo { background: #dbeafe; color: #1e40af; }
        .badge-ext { background: #f3f4f6; color: #4b5563; }
        /* Dynamic category badges */
        .badge-cat { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .badge-cat[data-cat="key"] { background: #fef3c7; color: #92400e; }
        .badge-cat[data-cat="stdo"] { background: #dbeafe; color: #1e40af; }
        .badge-cat[data-cat="external"] { background: #f3f4f6; color: #4b5563; }
        .actions { display: flex; gap: 4px; flex-wrap: nowrap; }
        .actions .btn { white-space: nowrap; }
        .row-disabled td { opacity: 0.6; background: #f8fafc; }
        .edit-form { display: none; }
        .edit-form select, .edit-form input { padding: 6px; font-size: 13px; width: 100%; }
        .toast { position: fixed; bottom: 20px; right: 20px; background: #333; color: white; padding: 12px 24px; border-radius: 8px; display: none; z-index: 1000; }
        .kpi-card { background: #fff; padding: 10px; border-radius: 10px; border: 1px solid #e2e8f0; border-top: 4px solid #00717a; text-align: center; }
        .row-err { background-color: #fff1f2 !important; }
        .txt-err { color: #dc2626; font-weight: bold; }
        .txt-ok { color: #16a34a; font-weight: bold; }
        .loading { text-align: center; padding: 40px; color: #999; }
    </style></head><body>
    <div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
            <h1>🔧 Управление</h1>
            <button class="btn btn-gray" onclick="location.href='/'">← Назад</button>
        </div>
        <div class="tabs">
            <button class="tab-btn active" onclick="adminTab(this, 'sites-tab')">Сайты</button>
            <button class="tab-btn" onclick="adminTab(this, 'settings-tab')">Настройки</button>
            <button class="tab-btn" onclick="adminTab(this, 'self-tab')">Self Monitoring</button>
            <button class="tab-btn" onclick="adminTab(this, 'docs-tab')">Описание</button>
        </div>
        <div id="sites-tab" class="tab-content active-content">
        <div class="add-form">
            <input type="text" id="newSite" placeholder="site.ru" style="flex:1;min-width:200px;">
            <select id="newGroup" data-dynamic="categories">
                <option value="">Загрузка...</option>
            </select>
            <input type="number" id="newThreshold" value="5" min="1" max="60" style="width:80px;" title="Порог в минутах">
            <button class="btn btn-primary" onclick="addSite()">➕ Добавить</button>
        </div>
        <table><thead><tr><th>Сайт</th><th>Группа</th><th>Статус</th><th>Порог мин</th><th style="width:300px;">Действия</th></tr></thead><tbody>""")

    cat_labels = {c['id']: c['label'] for c in cat_rows}
    for r in rows:
        badge = 'badge-cat'
        grp_name = cat_labels.get(r['site_group'], r['site_group'])
        disabled_cls = 'row-disabled' if not r['is_active'] else ''
        status = '🟢 Активен' if r['is_active'] else '🔴 Отключен'
        site_esc = r['site'].replace("'", "\\'")
        toggle_btn = (
            '<button class="btn btn-gray" onclick="toggleSite(' + "'" + site_esc + "'" + ')">🛑 Отключить</button>'
            if r['is_active']
            else '<button class="btn btn-success" onclick="toggleSite(' + "'" + site_esc + "'" + ')">✅ Восстановить</button>'
        )
        H.append(f"""<tr class="{disabled_cls}" id="row-{site_esc}">
            <td><strong>{r['site']}</strong></td>
            <td><span class="badge badge-cat" data-cat="{r['site_group']}">{grp_name}</span></td>
            <td>{status}</td>
            <td>{r['alert_threshold']}</td>
            <td>
                <div class="actions">
                    <button class="btn btn-warn" onclick="editRow('{site_esc}')">✏️ Изменить</button>
                    {toggle_btn}
                    <button class="btn btn-danger" onclick="deleteSite('{site_esc}')">🗑️ Удалить</button>
                </div>
                <div class="edit-form" id="edit-{site_esc}" style="display:none;margin-top:8px;gap:6px;">
                    <select id="grp-{site_esc}" data-group="{r['site_group']}" data-dynamic="categories" style="width:120px;">
                        <option value="">Загрузка...</option>
                    </select>
                    <input type="number" id="thr-{site_esc}" value="{r['alert_threshold']}" min="1" max="60" style="width:70px;">
                    <button class="btn btn-primary" onclick="saveRow('{site_esc}')">💾 Сохранить</button>
                    <button class="btn btn-gray" onclick="cancelEdit('{site_esc}')">Отмена</button>
                </div>
            </td>
        </tr>""")

    H.append("""</tbody></table></div>
    <div id="settings-tab" class="tab-content">
        <h3 style="color:#00717a;margin-top:0;">Настройки приложения</h3>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:15px;max-width:800px;">
            <div style="background:#f8fafc;padding:15px;border-radius:8px;border:1px solid #e2e8f0;">
                <h4 style="margin-top:0;color:#475569;">Content Match (regex)</h4>
                <p style="font-size:12px;color:#64748b;margin:0 0 8px;">Паттерн проверки контента для ключевых сайтов. Если контент не содержит совпадений, сайт считается DOWN (701).</p>
                <input type="text" id="setting-pattern" placeholder="sibur|сибур|логин" style="width:100%;padding:8px;border:1px solid #cbd5e1;border-radius:4px;font-size:13px;box-sizing:border-box;">
            </div>
            <div style="background:#f8fafc;padding:15px;border-radius:8px;border:1px solid #e2e8f0;">
                <h4 style="margin-top:0;color:#475569;">Категории сайтов</h4>
                <table style="font-size:12px;margin-bottom:10px;">
                    <thead><tr><th>ID</th><th>Название</th><th>Content Match</th><th>Порядок</th><th></th></tr></thead>
                    <tbody id="category-list"></tbody>
                </table>
                <div style="border-top:1px solid #e2e8f0;padding-top:10px;">
                    <h5 style="margin:0 0 8px;color:#475569;">Новая категория</h5>
                    <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:6px;align-items:end;">
                        <div><label style="font-size:11px;color:#64748b;">ID (a-z_)</label><input type="text" id="new-cat-id" placeholder="partner" style="width:100%;padding:6px;border:1px solid #cbd5e1;border-radius:4px;font-size:12px;box-sizing:border-box;"></div>
                        <div><label style="font-size:11px;color:#64748b;">Название</label><input type="text" id="new-cat-label" placeholder="Партнерские" style="width:100%;padding:6px;border:1px solid #cbd5e1;border-radius:4px;font-size:12px;box-sizing:border-box;"></div>
                        <div><label style="font-size:11px;color:#64748b;"><input type="checkbox" id="new-cat-cm"> Content Match</label></div>
                        <div><button onclick="createCategory()" class="btn" style="font-size:12px;padding:6px 12px;">Добавить</button></div>
                    </div>
                </div>
            </div>
        </div>
        <div style="margin-top:15px;">
            <button class="btn btn-primary" onclick="saveSettings()">Сохранить настройки</button>
            <span id="settings-msg" style="font-size:13px;margin-left:10px;"></span>
        </div>
    </div>
    <div id="self-tab" class="tab-content">
        <div id="self-loading" class="loading">Загрузка данных self-monitoring...</div>
        <div id="self-content" style="display:none;">
            <h3 style="color:#00717a;margin-top:0;">Self Monitoring</h3>
            <table><thead><tr><th>Сайт</th><th>Статус</th><th>Uptime 30д</th><th>Простой 30д</th><th>Ответ</th><th>SSL</th><th>Цепочка SSL</th><th>Домен</th></tr></thead><tbody id="self-tbody"></tbody></table>
            <h4 style="color:#475569;margin-top:25px;">📈 График</h4>
            <div id="self-chart-container" style="max-width:600px;"><div style="text-align:center;padding:30px;color:#999;">Загрузка графика...</div></div>
            <h4 style="color:#475569;margin-top:25px;">📋 Инциденты</h4>
            <table><thead><tr><th>Начало</th><th>Сайт</th><th>Длительность</th><th>Код</th><th>Описание</th><th>Цепочка SSL</th></tr></thead><tbody id="self-incidents-tbody"></tbody></table>
        </div>
    </div>
    <div id="docs-tab" class="tab-content">
        <h3 style="color:#00717a;margin-top:0;">📖 Описание функционала</h3>
        <div id="docs-loading" style="padding:20px;color:#999;">Загрузка...</div>
        <pre id="docs-content" style="background:#f8fafc;padding:15px;border-radius:8px;border:1px solid #e2e8f0;white-space:pre-wrap;font-family:'Segoe UI',sans-serif;font-size:13px;line-height:1.6;max-height:70vh;overflow-y:auto;display:none;"></pre>
    </div>
    </div>
    <div id="toast" class="toast"></div>
    <script>
    // Скрипт в конце body — DOM уже готов, вызываем сразу
    // Загрузить категории при первой загрузке страницы
    setTimeout(function() { if (window.loadCategorySelects) loadCategorySelects(); }, 100);
    window.adminTab = function(btn, n) {
        console.log('adminTab clicked:', n);
        var i, x = document.getElementsByClassName('tab-content'),
            b = document.getElementsByClassName('tab-btn');
        for(i = 0; i < x.length; i++) x[i].classList.remove('active-content');
        for(i = 0; i < b.length; i++) b[i].classList.remove('active');
        var target = document.getElementById(n);
        if (!target) { console.error('Tab not found:', n); return; }
        target.classList.add('active-content');
        btn.classList.add('active');
        console.log('Tab activated:', n);
        if (n === 'sites-tab') loadCategorySelects();
        if (n === 'settings-tab') loadSettings();
        if (n === 'self-tab') loadSelfMonitoring();
        if (n === 'docs-tab') loadDocs();
    }
    window.loadSettings = async function() {
        try {
            // Load content match pattern
            var r = await fetch('/api/settings');
            var d = await r.json();
            if (d.status === 'ok' && d.settings) {
                document.getElementById('setting-pattern').value = d.settings['content_match_pattern'] || '';
            }
            // Load dynamic categories
            var cr = await fetch('/api/site-categories');
            var cd = await cr.json();
            if (cd.status === 'ok' && cd.categories) {
                window._categories = cd.categories;
                renderCategoryList(cd.categories);
            }
        } catch(e) { console.error('loadSettings error:', e); }
    }
    function renderCategoryList(cats) {
        var tbody = document.getElementById('category-list');
        if (!tbody) return;
        tbody.innerHTML = '';
        for (var i = 0; i < cats.length; i++) {
            var c = cats[i];
            tbody.innerHTML += '<tr>' +
                '<td>' + c.id + '</td>' +
                '<td><input type="text" id="cat-label-' + c.id + '" value="' + c.label + '" style="width:100%;padding:4px;border:1px solid #cbd5e1;border-radius:4px;"></td>' +
                '<td><input type="checkbox" id="cat-cm-' + c.id + '" ' + (c.content_match_enabled ? 'checked' : '') + '></td>' +
                '<td><input type="number" id="cat-sort-' + c.id + '" value="' + c.sort_order + '" style="width:60px;padding:4px;"></td>' +
                '<td><button onclick="saveCategory(\\'' + c.id + '\\')" class="btn" style="font-size:11px;padding:4px 8px;">Сохранить</button></td>' +
            '</tr>';
        }
    }
    window.saveCategory = async function(catId) {
        var label = document.getElementById('cat-label-' + catId).value.trim();
        var cm = document.getElementById('cat-cm-' + catId).checked;
        var sort = parseInt(document.getElementById('cat-sort-' + catId).value) || 0;
        if (!label) { alert('Название обязательно'); return; }
        try {
            var r = await fetch('/api/site-categories/' + catId, {
                method: 'PUT', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({label: label, content_match_enabled: cm, sort_order: sort})
            });
            var d = await r.json();
            alert(d.status === 'ok' ? 'Сохранено' : 'Ошибка: ' + d.msg);
        } catch(e) { alert('Ошибка сети'); }
    }
    window.createCategory = async function() {
        var id = document.getElementById('new-cat-id').value.trim().toLowerCase();
        var label = document.getElementById('new-cat-label').value.trim();
        var cm = document.getElementById('new-cat-cm').checked;
        if (!id || !label) { alert('ID и название обязательны'); return; }
        if (!/^[a-z0-9_]+$/.test(id)) { alert('ID: только a-z, 0-9, _'); return; }
        try {
            var r = await fetch('/api/site-categories', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({id: id, label: label, content_match_enabled: cm})
            });
            var d = await r.json();
            if (d.status === 'ok') {
                alert('Категория создана');
                document.getElementById('new-cat-id').value = '';
                document.getElementById('new-cat-label').value = '';
                loadSettings();
            } else {
                alert('Ошибка: ' + d.msg);
            }
        } catch(e) { alert('Ошибка сети'); }
    }
    window.saveSettings = async function() {
        var msg = document.getElementById('settings-msg');
        msg.textContent = 'Сохранение...';
        var pattern = document.getElementById('setting-pattern').value.trim();
        if (!pattern) { msg.textContent = 'Паттерн обязателен'; return; }
        try {
            var r = await fetch('/api/settings/content_match_pattern', {
                method: 'PUT', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({value: pattern})
            });
            var d = await r.json();
            if (d.status !== 'ok') { msg.textContent = 'Ошибка: ' + d.msg; return; }
            // Save category changes
            if (window._categories) {
                for (var i = 0; i < window._categories.length; i++) {
                    var c = window._categories[i];
                    var label = document.getElementById('cat-label-' + c.id).value.trim();
                    var cm = document.getElementById('cat-cm-' + c.id).checked;
                    var sort = parseInt(document.getElementById('cat-sort-' + c.id).value) || 0;
                    if (!label) continue;
                    var cr = await fetch('/api/site-categories/' + c.id, {
                        method: 'PUT', headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({label: label, content_match_enabled: cm, sort_order: sort})
                    });
                }
            }
            msg.textContent = 'Настройки сохранены';
            setTimeout(function(){ msg.textContent = ''; }, 3000);
        } catch(e) {
            msg.textContent = 'Ошибка сети';
            console.error('saveSettings error:', e);
        }
    }
    window.loadCategorySelects = async function() {
        try {
            var r = await fetch('/api/site-categories');
            var d = await r.json();
            if (d.status !== 'ok' || !d.categories) return;
            var cats = d.categories;
            // Заполняем все select[data-dynamic="categories"]
            var selects = document.querySelectorAll('select[data-dynamic="categories"]');
            selects.forEach(function(sel) {
                var currentVal = sel.value;
                var dataGroup = sel.getAttribute('data-group');
                sel.innerHTML = '';
                cats.forEach(function(c) {
                    var opt = document.createElement('option');
                    opt.value = c.id;
                    opt.textContent = c.label;
                    sel.appendChild(opt);
                });
                // Восстанавливаем выбранное
                if (currentVal) sel.value = currentVal;
                else if (dataGroup) sel.value = dataGroup;
            });
        } catch(e) { console.error('loadCategorySelects error:', e); }
    }
    window.loadSelfMonitoring = async function() {
        const loading = document.getElementById('self-loading');
        const content = document.getElementById('self-content');
        loading.style.display = 'block';
        content.style.display = 'none';
        try {
            const r = await fetch('/api/self-monitoring');
            const data = await r.json();
            if (data.status === 'ok') {
                renderSelfTable(data);
                renderSelfIncidents(data.incidents);
                renderSelfChart(data.charts);
                loading.style.display = 'none';
                content.style.display = 'block';
            } else {
                loading.innerText = 'Ошибка загрузки данных';
            }
        } catch (e) {
            loading.innerText = 'Ошибка связи с сервером';
        }
    }
    window.loadDocs = async function() {
        const loading = document.getElementById('docs-loading');
        const content = document.getElementById('docs-content');
        loading.style.display = 'block';
        content.style.display = 'none';
        try {
            const r = await fetch('/api/functional');
            const data = await r.json();
            if (data.status === 'ok') {
                content.innerText = data.content;
                loading.style.display = 'none';
                content.style.display = 'block';
            } else {
                loading.innerText = 'Ошибка загрузки описания';
            }
        } catch (e) {
            loading.innerText = 'Ошибка связи с сервером';
        }
    }
    function renderSelfTable(data) {
        const tbody = document.getElementById('self-tbody');
        let html = '';
        for (const s of data.sites) {
            const isOnline = s.status === 200 || s.status === 401;
            html += `<tr class="${isOnline ? '' : 'row-err'}">
                <td><strong>${s.site}</strong></td>
                <td><span class="${isOnline ? 'txt-ok' : 'txt-err'}">${isOnline ? 'Online' : 'Offline'}</span></td>
                <td>${s.upt}%</td>
                <td>${(() => { const m = s.down_min || 0; if (m <= 0) return '—'; if (m < 60) return m + ' мин'; const h = Math.floor(m / 60), r = m % 60; return r === 0 ? h + ' ч' : h + ' ч ' + r + ' мин'; })()}</td>
                <td>${s.response_time}с</td>
                <td class="${(s.ssl_days >= 0 && s.ssl_days <= 20) ? 'txt-err' : ''}">${s.ssl_days}д</td>
                <td class="${s.ssl_chain_valid === false ? 'txt-err' : (s.ssl_chain_valid === true ? 'txt-ok' : '')}">${s.ssl_chain_valid === true ? '✅' : (s.ssl_chain_valid === false ? '❌' : '—')}</td>
                <td class="${(s.domain_days >= 0 && s.domain_days <= 30) ? 'txt-err' : ''}">${s.domain_days}д</td>
            </tr>`;
        }
        tbody.innerHTML = html;
    }
    function renderSelfIncidents(incidents) {
        const tbody = document.getElementById('self-incidents-tbody');
        if (!incidents || incidents.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#999;">Нет инцидентов за 30 дней</td></tr>';
            return;
        }
        let html = '';
        for (const inc of incidents) {
            html += `<tr>
                <td>${inc.start_time}</td>
                <td>${inc.site}</td>
                <td class="txt-err">${inc.dur} мин</td>
                <td>${inc.max_status}</td>
                <td>${inc.description}</td>
                <td class="${inc.ssl_chain_valid === false ? 'txt-err' : (inc.ssl_chain_valid === true ? 'txt-ok' : '')}">${inc.ssl_chain_valid === true ? '✅' : (inc.ssl_chain_valid === false ? '❌' : '—')}</td>
            </tr>`;
        }
        tbody.innerHTML = html;
    }
    function renderSelfChart(charts) {
        const container = document.getElementById('self-chart-container');
        container.innerHTML = '';
        if (!charts) {
            container.innerHTML = '<div style="text-align:center;padding:30px;color:#999;">Нет данных для графика</div>';
            return;
        }
        for (const site in charts) {
            const d = charts[site];
            if (!d || !d.l || d.l.length === 0) continue;
            const div = document.createElement('div');
            div.className = 'kpi-card';
            div.style.borderTop = '2px solid #eee';
            div.innerHTML = `<h5>${site}</h5><canvas id="admin-self-${site.replace(/\\./g, '_')}"></canvas>`;
            container.appendChild(div);
            new Chart(document.getElementById('admin-self-' + site.replace(/\\./g, '_')), {
                type: 'line',
                data: {
                    labels: d.l,
                    datasets: [
                        { label: 'Uptime %', data: d.u, borderColor: '#10b981', backgroundColor: '#10b981', yAxisID: 'y', tension: 0.3, pointRadius: 3 },
                        { label: 'Ответ сек', data: d.r, borderColor: '#3b82f6', backgroundColor: '#3b82f6', yAxisID: 'y1', tension: 0.3, pointRadius: 3 }
                    ]
                },
                options: {
                    scales: {
                        y: { suggestedMin: 95, suggestedMax: 100.5, title: { display: true, text: 'Uptime %' } },
                        y1: { position: 'right', grid: { display: false }, title: { display: true, text: 'Ответ, сек' } }
                    }
                }
            });
        }
    }
    window.addSite = async function() {
        const site = document.getElementById('newSite').value.trim();
        const group = document.getElementById('newGroup').value;
        const threshold = parseInt(document.getElementById('newThreshold').value) || 5;
        if (!site) return showToast('Введите сайт');
        const r = await fetch('/api/sites', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({site, group, threshold})});
        const data = await r.json();
        if (data.status === 'ok') { location.reload(); }
        else { showToast(data.msg || 'Ошибка'); }
    }
    window.editRow = function(site) {
        const form = document.getElementById('edit-' + site);
        form.style.display = form.style.display === 'none' ? 'flex' : 'none';
    }
    function cancelEdit(site) {
        document.getElementById('edit-' + site).style.display = 'none';
    }
    window.saveRow = async function(site) {
        const group = document.getElementById('grp-' + site).value;
        const threshold = parseInt(document.getElementById('thr-' + site).value);
        const r = await fetch('/api/sites/' + encodeURIComponent(site), {
            method:'PUT', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({group, threshold})
        });
        const data = await r.json();
        if (data.status === 'ok') { location.reload(); }
        else { showToast(data.msg || 'Ошибка'); }
    }
    window.toggleSite = async function(site) {
        const r = await fetch('/api/sites/' + encodeURIComponent(site) + '/toggle', {method:'POST'});
        const data = await r.json();
        if (data.status === 'ok') { location.reload(); }
        else { showToast(data.msg || 'Ошибка'); }
    }
    window.deleteSite = async function(site) {
        if (!confirm('Удалить ' + site + ' окончательно?')) return;
        const r = await fetch('/api/sites/' + encodeURIComponent(site), {method:'DELETE'});
        const data = await r.json();
        if (data.status === 'ok') { location.reload(); }
        else { showToast(data.msg || 'Ошибка'); }
    }
    function showToast(msg) {
        const t = document.getElementById('toast'); t.innerText = msg; t.style.display = 'block';
        setTimeout(() => { t.style.display = 'none'; }, 3000);
    }
    </script></body></html>""")
    return HTMLResponse("".join(H))



# ============================================================================
# API: Настройки приложения (content match, названия категорий)
# ============================================================================
@app.get("/api/settings")
async def get_settings(auth: bool = Depends(check_auth)):
    """Получить все настройки приложения"""
    try:
        return {"status": "ok", "settings": load_settings()}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.put("/api/settings/{key}")
async def update_setting(key: str, request: Request, auth: bool = Depends(check_auth)):
    """Обновить одну настройку (content_match_pattern, category_*_label)"""
    try:
        data = await request.json()
        value = data.get("value", "").strip()
        allowed_keys = {
            'content_match_pattern',
            'category_key_label',
            'category_stdo_label',
            'category_external_label'
        }
        if key not in allowed_keys:
            return JSONResponse({"status": "error", "msg": f"Unknown key. Allowed: {allowed_keys}"}, status_code=400)
        if not value:
            return JSONResponse({"status": "error", "msg": "value required"}, status_code=400)
        if key == 'content_match_pattern':
            try:
                re.compile(value, re.IGNORECASE)
            except re.error as e:
                return JSONResponse({"status": "error", "msg": f"Invalid regex: {e}"}, status_code=400)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO app_settings (key, value, updated_at) VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        """, (key, value))
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "ok", "msg": f"Setting '{key}' updated"}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.get("/api/categories")
async def get_categories(auth: bool = Depends(check_auth)):
    """Получить сайты по категориям (динамические из БД)"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT id, label, content_match_enabled, sort_order FROM site_categories ORDER BY sort_order")
        cat_rows = cur.fetchall()
        cur.execute("""
            SELECT site, site_group, is_active, alert_threshold
            FROM monitored_sites WHERE site_group != 'self' ORDER BY site_group, site
        """)
        site_rows = cur.fetchall()
        cur.close()
        conn.close()
        categories = {}
        for c in cat_rows:
            categories[c['id']] = {
                'label': c['label'],
                'content_match_enabled': c['content_match_enabled'],
                'sort_order': c['sort_order'],
                'sites': []
            }
        for r in site_rows:
            g = r['site_group']
            if g in categories:
                categories[g]['sites'].append(dict(r))
            else:
                categories.setdefault('external', {}).setdefault('sites', []).append(dict(r))
        return {"status": "ok", "categories": categories}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.get("/api/site-categories")
async def list_site_categories(auth: bool = Depends(check_auth)):
    """Получить список категорий сайтов"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT id, label, content_match_enabled, sort_order FROM site_categories ORDER BY sort_order")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return {"status": "ok", "categories": [dict(r) for r in rows]}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.post("/api/site-categories")
async def create_site_category(request: Request, auth: bool = Depends(check_auth)):
    """Создать новую категорию сайтов"""
    try:
        data = await request.json()
        cat_id = data.get("id", "").strip().lower()
        label = data.get("label", "").strip()
        cm_enabled = data.get("content_match_enabled", False)
        sort_order = data.get("sort_order", 99)
        if not cat_id or not label:
            return JSONResponse({"status": "error", "msg": "id and label required"}, status_code=400)
        if not re.match(r'^[a-z0-9_]+$', cat_id):
            return JSONResponse({"status": "error", "msg": "id must be lowercase alphanumeric with underscores"}, status_code=400)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO site_categories (id, label, content_match_enabled, sort_order)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET label = EXCLUDED.label,
                content_match_enabled = EXCLUDED.content_match_enabled,
                sort_order = EXCLUDED.sort_order
        """, (cat_id, label, cm_enabled, sort_order))
        conn.commit()
        cur.close()
        conn.close()
        _invalidate_dashboard_cache()
        return {"status": "ok", "msg": f"Category '{label}' created/updated"}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.put("/api/site-categories/{cat_id}")
async def update_site_category(cat_id: str, request: Request, auth: bool = Depends(check_auth)):
    """Обновить категорию сайтов"""
    try:
        data = await request.json()
        label = data.get("label", "").strip()
        cm_enabled = data.get("content_match_enabled")
        sort_order = data.get("sort_order")
        if not label:
            return JSONResponse({"status": "error", "msg": "label required"}, status_code=400)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE site_categories SET label = %s,
                content_match_enabled = COALESCE(%s, content_match_enabled),
                sort_order = COALESCE(%s, sort_order)
            WHERE id = %s
        """, (label, cm_enabled, sort_order, cat_id))
        conn.commit()
        cur.close()
        conn.close()
        _invalidate_dashboard_cache()
        return {"status": "ok", "msg": f"Category '{cat_id}' updated"}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.delete("/api/site-categories/{cat_id}")
async def delete_site_category(cat_id: str, auth: bool = Depends(check_auth)):
    """Удалить категорию (сайты перемещаются в 'external')"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Move sites to external
        cur.execute("UPDATE monitored_sites SET site_group = 'external' WHERE site_group = %s", (cat_id,))
        # Delete category
        cur.execute("DELETE FROM site_categories WHERE id = %s", (cat_id,))
        conn.commit()
        cur.close()
        conn.close()
        _invalidate_dashboard_cache()
        return {"status": "ok", "msg": f"Category '{cat_id}' deleted, sites moved to external"}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.get("/health")
async def health():
    """Health-check: проверяет heartbeat worker'а"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT value, updated FROM health WHERE key = 'last_worker_tick'")
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row:
            last_tick = datetime.datetime.fromisoformat(str(row[0]))
            if (datetime.datetime.now() - last_tick).total_seconds() > 120:
                return JSONResponse(
                    {"status": "degraded", "reason": "worker stale"},
                    status_code=503
                )
            return {"status": "ok", "last_worker_tick": str(row[1])}
        return JSONResponse(
            {"status": "starting", "reason": "no heartbeat yet"},
            status_code=503
        )
    except Exception as e:
        return JSONResponse(
            {"status": "error", "reason": str(e)},
            status_code=500
        )


@app.get("/api/sites")
async def list_sites(auth: bool = Depends(check_auth)):
    """Список всех сайтов в мониторинге (без self-monitoring)"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT site, site_group, is_active, alert_threshold, created_at FROM monitored_sites WHERE site_group != 'self' ORDER BY site_group, site")
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return {"sites": rows, "total": len(rows)}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.post("/api/sites")
async def add_site(request: Request, auth: bool = Depends(check_auth)):
    """Добавить сайт в мониторинг"""
    try:
        data = await request.json()
        site = data.get("site", "").strip()
        group = data.get("group", "external")
        threshold = int(data.get("threshold", 5))
        if not site:
            return JSONResponse({"status": "error", "msg": "site required"}, status_code=400)
        # Validate group against DB categories
        cur.execute("SELECT id FROM site_categories")
        valid_groups = [r[0] for r in cur.fetchall()]
        cur.close()
        if group not in valid_groups:
            return JSONResponse({"status": "error", "msg": f"group must be one of: {valid_groups}"}, status_code=400)
        if threshold < 1 or threshold > 60:
            return JSONResponse({"status": "error", "msg": "threshold must be 1-60"}, status_code=400)
        if site in SELF_MONITORING_SITES:
            return JSONResponse({"status": "error", "msg": "Cannot modify self-monitoring sites"}, status_code=400)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO monitored_sites (site, site_group, alert_threshold, is_active)
            VALUES (%s, %s, %s, TRUE)
            ON CONFLICT (site) DO UPDATE SET
                is_active = TRUE,
                site_group = EXCLUDED.site_group,
                alert_threshold = EXCLUDED.alert_threshold
        """, (site, group, threshold))
        conn.commit()
        cur.close()
        conn.close()
        _invalidate_dashboard_cache()
        return {"status": "ok", "msg": f"Site '{site}' added"}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.put("/api/sites/{site_name:path}")
async def update_site(site_name: str, request: Request, auth: bool = Depends(check_auth)):
    """Обновить группу и порог сайта"""
    try:
        data = await request.json()
        group = data.get("group")
        threshold = data.get("threshold")
        if site_name in SELF_MONITORING_SITES:
            return JSONResponse({"status": "error", "msg": "Cannot modify self-monitoring sites"}, status_code=400)
        conn = get_db_connection()
        cur = conn.cursor()
        if group and threshold is not None:
            cur.execute("""
                UPDATE monitored_sites
                SET site_group = %s, alert_threshold = %s
                WHERE site = %s
            """, (group, int(threshold), site_name))
        elif group:
            cur.execute("UPDATE monitored_sites SET site_group = %s WHERE site = %s", (group, site_name))
        elif threshold is not None:
            cur.execute("UPDATE monitored_sites SET alert_threshold = %s WHERE site = %s", (int(threshold), site_name))
        conn.commit()
        affected = cur.rowcount
        cur.close()
        conn.close()
        if affected == 0:
            return JSONResponse({"status": "error", "msg": "Site not found"}, status_code=404)
        _invalidate_dashboard_cache()
        return {"status": "ok", "msg": f"Site '{site_name}' updated"}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.post("/api/sites/{site_name:path}/toggle")
async def toggle_site(site_name: str, auth: bool = Depends(check_auth)):
    """Включить / отключить сайт (toggle is_active)"""
    try:
        if site_name in SELF_MONITORING_SITES:
            return JSONResponse({"status": "error", "msg": "Cannot modify self-monitoring sites"}, status_code=400)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE monitored_sites
            SET is_active = NOT is_active
            WHERE site = %s
            RETURNING is_active
        """, (site_name,))
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        if row is None:
            return JSONResponse({"status": "error", "msg": "Site not found"}, status_code=404)
        _invalidate_dashboard_cache()
        new_status = "enabled" if row[0] else "disabled"
        return {"status": "ok", "msg": f"Site '{site_name}' {new_status}", "is_active": row[0]}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


@app.delete("/api/sites/{site_name:path}")
async def delete_site(site_name: str, auth: bool = Depends(check_auth)):
    """Окончательное удаление сайта из БД"""
    try:
        if site_name in SELF_MONITORING_SITES:
            return JSONResponse({"status": "error", "msg": "Cannot modify self-monitoring sites"}, status_code=400)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM monitored_sites WHERE site = %s", (site_name,))
        conn.commit()
        affected = cur.rowcount
        cur.close()
        conn.close()
        if affected == 0:
            return JSONResponse({"status": "error", "msg": "Site not found"}, status_code=404)
        _invalidate_dashboard_cache()
        return {"status": "ok", "msg": f"Site '{site_name}' deleted"}
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


# ============================================================================
# API: Self Monitoring (для админ-панели)
# ============================================================================
@app.get("/api/self-monitoring")
async def api_self_monitoring(auth: bool = Depends(check_auth)):
    """Данные self-monitoring для админ-панели"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)

        # Latest status — нормализуем 401 → 200 для self-monitoring
        cur.execute("""
            SELECT site, status, response_time, ssl_days, domain_days, ssl_chain_valid, timestamp
            FROM latest_status WHERE site = ANY(%s)
        """, (SELF_MONITORING_SITES,))
        latest_rows = {r['site']: dict(r) for r in cur.fetchall()}
        for s in SELF_MONITORING_SITES:
            if s not in latest_rows:
                latest_rows[s] = {'status': 200, 'response_time': 0.5, 'ssl_days': -1, 'domain_days': -1, 'ssl_chain_valid': None}
            elif latest_rows[s].get('status') == 401:
                latest_rows[s]['status'] = 200

        # Stats 30 days — для self-monitoring 401 считаем как 200
        cur.execute("""
            SELECT site,
                ROUND(SUM(status_200_count) * 100.0
                      / NULLIF(SUM(checks_count), 0)::numeric, 2) as upt,
                COALESCE(SUM(down_sec), 0) as down_sec
            FROM checks_agg WHERE bucket > NOW() - INTERVAL '30 days'
              AND site = ANY(%s)
            GROUP BY site
        """, (SELF_MONITORING_SITES,))
        stats_rows = {r['site']: dict(r) for r in cur.fetchall()}
        if not stats_rows:
            cur.execute("""
                SELECT site,
                    ROUND((COUNT(*) FILTER (WHERE status = 200 OR status = 401) * 100.0
                           / NULLIF(COUNT(*), 0))::numeric, 2) as upt,
                    COUNT(*) FILTER (WHERE status != 200 AND status != 401) * 60 as down_sec
                FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'
                  AND site = ANY(%s)
                GROUP BY site
            """, (SELF_MONITORING_SITES,))
            stats_rows = {r['site']: dict(r) for r in cur.fetchall()}

        # Incidents — исключаем 401, длительность пересчитываем динамически
        cur.execute("""
            SELECT site, start_time,
                CASE 
                    WHEN resolved = TRUE THEN GREATEST(1, CEIL(EXTRACT(EPOCH FROM (COALESCE(end_time, NOW()) - start_time))/60)::INT)
                    ELSE CEIL(EXTRACT(EPOCH FROM (NOW() - start_time))/60)::INT
                END as dur,
                max_status,
                CASE WHEN max_status = 0 THEN 'Timeout'
                     WHEN max_status = 502 THEN 'Bad Gateway'
                     WHEN max_status = 503 THEN 'Service Unavailable'
                     WHEN max_status = 701 THEN 'Content Mismatch'
                     ELSE 'Server Error' END as description,
                ssl_chain_valid
            FROM incidents
            WHERE start_time > NOW() - INTERVAL '30 days'
              AND site = ANY(%s)
              AND max_status != 401
            ORDER BY start_time DESC LIMIT 20
        """, (SELF_MONITORING_SITES,))
        incidents = []
        for r in cur.fetchall():
            inc = dict(r)
            if inc.get('start_time'):
                inc['start_time'] = inc['start_time'].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')
            incidents.append(inc)

        # Charts data — для self-monitoring 401 считаем как 200
        cur.execute("""
            SELECT site, bucket::date as d,
                   ROUND((SUM(avg_response_time * checks_count)
                         / NULLIF(SUM(checks_count), 0))::numeric, 2) as r,
                   ROUND(SUM(status_200_count) * 100.0 / NULLIF(SUM(checks_count), 0)::numeric, 2) as u
            FROM checks_agg
            WHERE bucket > NOW() - INTERVAL '30 days'
              AND site = ANY(%s)
            GROUP BY site, bucket::date
            ORDER BY bucket::date
        """, (SELF_MONITORING_SITES,))
        charts = {}
        for r in cur.fetchall():
            s = r['site']
            charts.setdefault(s, {'l': [], 'u': [], 'r': []})
            charts[s]['l'].append(r['d'].strftime("%d.%m"))
            charts[s]['u'].append(float(r['u']) if r['u'] is not None else 0)
            charts[s]['r'].append(float(r['r']) if r['r'] is not None else 0)

        if not charts:
            cur.execute("""
                SELECT site, DATE(timestamp) as d,
                       ROUND(AVG(response_time)::numeric, 2) as r,
                       ROUND(COUNT(*) FILTER (WHERE status=200 OR status=401) * 100.0 / COUNT(*)::numeric, 2) as u
                FROM logs
                WHERE timestamp > NOW() - INTERVAL '30 days'
                  AND site = ANY(%s)
                GROUP BY 1, 2
                ORDER BY 2
            """, (SELF_MONITORING_SITES,))
            for r in cur.fetchall():
                s = r['site']
                charts.setdefault(s, {'l': [], 'u': [], 'r': []})
                charts[s]['l'].append(r['d'].strftime("%d.%m"))
                charts[s]['u'].append(float(r['u']) if r['u'] is not None else 0)
                charts[s]['r'].append(float(r['r']) if r['r'] is not None else 0)

        cur.close()
        conn.close()

        sites_data = []
        for s in SELF_MONITORING_SITES:
            lr = latest_rows.get(s, {})
            sr = stats_rows.get(s, {})
            sites_data.append({
                'site': s,
                'status': lr.get('status', 0),
                'response_time': round(float(lr.get('response_time', 0) or 0), 2),
                'upt': float(sr.get('upt', 0) or 0),
                'down_min': round(int(sr.get('down_sec', 0) or 0) / 60),
                'ssl_days': lr.get('ssl_days', -1),
                'domain_days': lr.get('domain_days', -1),
                'ssl_chain_valid': lr.get('ssl_chain_valid')
            })

        return {
            "status": "ok",
            "sites": sites_data,
            "incidents": incidents,
            "charts": charts
        }
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


def _get_stats_from_agg(cur, interval: str):
    """Статистика из checks_agg; fallback на logs если агрегаты пустые.
    Uptime — взвешенный через SUM, response_time — взвешенное среднее.
    Self-monitoring сайты исключены."""
    cur.execute("""
        SELECT
            ROUND(SUM(status_200_count) * 100.0
                  / NULLIF(SUM(checks_count), 0)::numeric, 2) as up,
            ROUND((SUM(avg_response_time * checks_count)
                  / NULLIF(SUM(checks_count), 0))::numeric, 3) as resp
        FROM checks_agg WHERE bucket > NOW() - INTERVAL %s
          AND site <> ALL(%s)
    """, (interval, SELF_MONITORING_SITES))
    row = cur.fetchone()
    if row and row[0] is not None:
        return {'up': float(row[0]), 'resp': float(row[1]) if row[1] is not None else 0}
    # Fallback на logs
    cur.execute("""
        SELECT
            ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0
                   / NULLIF(COUNT(*), 0))::numeric, 2) as up,
            ROUND(AVG(response_time)::numeric, 3) as resp
        FROM logs WHERE timestamp > NOW() - INTERVAL %s
          AND site <> ALL(%s)
    """, (interval, SELF_MONITORING_SITES))
    row = cur.fetchone()
    return {'up': float(row[0]) if row[0] is not None else 0, 'resp': float(row[1]) if row[1] is not None else 0}


@app.get("/api/functional")
async def api_functional(auth: bool = Depends(check_auth)):
    """Отдает содержимое FUNCTIONAL.md — документацию функционала"""
    try:
        md_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "FUNCTIONAL.md")
        if os.path.exists(md_path):
            with open(md_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return {"status": "ok", "content": content}
        return JSONResponse({"status": "error", "msg": "FUNCTIONAL.md not found"}, status_code=404)
    except Exception as e:
        return JSONResponse({"status": "error", "msg": str(e)}, status_code=500)


# ============================================================================
# API для графиков — lazy load фоном после first paint
# ============================================================================
@app.get("/api/charts")
async def api_charts(auth: bool = Depends(check_auth)):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    allowed_sites = set(SITES) | set(SELF_MONITORING_SITES)  # include self-monitoring for charts

    cur.execute("""
        SELECT site, bucket::date as d,
               ROUND((SUM(avg_response_time * checks_count)
                     / NULLIF(SUM(checks_count), 0))::numeric, 2) as r,
               ROUND(SUM(status_200_count) * 100.0 / NULLIF(SUM(checks_count), 0)::numeric, 2) as u
        FROM checks_agg
        WHERE bucket > NOW() - INTERVAL '30 days'
          AND site = ANY(%s)
        GROUP BY site, bucket::date
        ORDER BY bucket::date
    """, (list(allowed_sites),))

    data = {}
    for r in cur.fetchall():
        s = r['site']
        data.setdefault(s, {'l': [], 'u': [], 'r': []})
        data[s]['l'].append(r['d'].strftime("%d.%m"))
        data[s]['u'].append(float(r['u']) if r['u'] is not None else 0)
        data[s]['r'].append(float(r['r']) if r['r'] is not None else 0)

    if not data:
        cur.execute("""
            SELECT site, DATE(timestamp) as d,
                   ROUND(AVG(response_time)::numeric, 2) as r,
                   ROUND(COUNT(*) FILTER (WHERE status=200 OR (site = ANY(%s) AND status=401)) * 100.0 / COUNT(*)::numeric, 2) as u
            FROM logs
            WHERE timestamp > NOW() - INTERVAL '30 days'
              AND site = ANY(%s)
            GROUP BY 1, 2
            ORDER BY 2
        """, (SELF_MONITORING_SITES, list(allowed_sites),))

        for r in cur.fetchall():
            s = r['site']
            data.setdefault(s, {'l': [], 'u': [], 'r': []})
            data[s]['l'].append(r['d'].strftime("%d.%m"))
            data[s]['u'].append(float(r['u']) if r['u'] is not None else 0)
            data[s]['r'].append(float(r['r']) if r['r'] is not None else 0)

    cur.close()
    conn.close()
    return JSONResponse(data)


# ============================================================================
# DASHBOARD — shell (KPI + таблица + инциденты + календарь)
# Графики подгружаются фоном через /api/charts
# ============================================================================
async def _index_stream():
    """Генератор: мгновенно yield-ит head с троббером, потом SQL, потом body.
    Браузер получает <head> за миллисекунды — троббер показывается ДО загрузки данных."""
    # === CHUNK 1: HEAD + INLINE SPINNER (мгновенно) ===
    yield _build_head()

    # === CHUNK 2: SQL-запросы (это занимает время, троббер уже крутится) ===
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    s30 = _get_stats_from_agg(cur, '30 days')
    s24 = _get_stats_from_agg(cur, '24 hours')

    cur.execute("SELECT * FROM latest_status")
    latest_all = {r['site']: r for r in cur.fetchall()}
    latest = {s: latest_all[s] for s in SITES if s in latest_all}
    self_latest = {s: latest_all[s] for s in SELF_MONITORING_SITES if s in latest_all}
    for s in SELF_MONITORING_SITES:
        if s not in self_latest:
            self_latest[s] = {'status': 200, 'response_time': 0.5, 'ssl_days': -1, 'domain_days': -1, 'ssl_chain_valid': None}
        elif self_latest[s].get('status') == 401:
            self_latest[s]['status'] = 200
    for s in latest:
        if latest[s].get('status') == 401:
            latest[s]['status'] = 200

    cur.execute("""
        SELECT site,
            ROUND(SUM(status_200_count) * 100.0
                  / NULLIF(SUM(checks_count), 0)::numeric, 2) as upt,
            COALESCE(SUM(down_sec), 0) as down_sec
        FROM checks_agg WHERE bucket > NOW() - INTERVAL '30 days'
          AND site <> ALL(%s)
        GROUP BY site
    """, (SELF_MONITORING_SITES,))
    stats_rows = cur.fetchall()
    if stats_rows and stats_rows[0][0] is not None:
        stats = {r['site']: r for r in stats_rows}
    else:
        cur.execute("""
            SELECT site,
                ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0
                       / NULLIF(COUNT(*), 0))::numeric, 2) as upt,
                COUNT(*) FILTER (WHERE status != 200) * 60 as down_sec
            FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'
              AND site <> ALL(%s)
            GROUP BY site
        """, (SELF_MONITORING_SITES,))
        stats = {r['site']: r for r in cur.fetchall()}

    cur.execute("""
        SELECT site,
            ROUND(SUM(CASE WHEN status_200_count > 0 OR last_ssl_days IS NULL THEN checks_count ELSE status_200_count END) * 100.0
                  / NULLIF(SUM(checks_count), 0)::numeric, 2) as upt,
            COALESCE(SUM(down_sec), 0) as down_sec
        FROM checks_agg WHERE bucket > NOW() - INTERVAL '30 days'
          AND site = ANY(%s)
        GROUP BY site
    """, (SELF_MONITORING_SITES,))
    self_stats_rows = cur.fetchall()
    if self_stats_rows and self_stats_rows[0][0] is not None:
        self_stats = {r['site']: r for r in self_stats_rows}
    else:
        cur.execute("""
            SELECT site,
                ROUND((COUNT(*) FILTER (WHERE status = 200 OR status = 401) * 100.0
                       / NULLIF(COUNT(*), 0))::numeric, 2) as upt,
                COUNT(*) FILTER (WHERE status != 200 AND status != 401) * 60 as down_sec
            FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'
              AND site = ANY(%s)
            GROUP BY site
        """, (SELF_MONITORING_SITES,))
        self_stats = {r['site']: r for r in cur.fetchall()}

    cur.execute("""
        SELECT 
            COALESCE((SELECT sort_order FROM site_categories WHERE id = ms.site_group), 2) as grp,
            ROUND(SUM(ca.status_200_count) * 100.0 
                  / NULLIF(SUM(ca.checks_count), 0)::numeric, 2) as upt,
            ROUND((SUM(ca.avg_response_time * ca.checks_count) 
                  / NULLIF(SUM(ca.checks_count), 0))::numeric, 3) as resp
        FROM checks_agg ca
        JOIN monitored_sites ms ON ca.site = ms.site
        WHERE ca.bucket > NOW() - INTERVAL '30 days'
          AND ca.site <> ALL(%s)
        GROUP BY grp
    """, (SELF_MONITORING_SITES,))
    group_agg_rows = cur.fetchall()
    if group_agg_rows and group_agg_rows[0][0] is not None:
        group_agg = {r['grp']: r for r in group_agg_rows}
    else:
        cur.execute("""
            SELECT 
                COALESCE((SELECT sort_order FROM site_categories WHERE id = ms.site_group), 2) as grp,
                ROUND(COUNT(*) FILTER (WHERE l.status = 200) * 100.0
                      / NULLIF(COUNT(*), 0)::numeric, 2) as upt,
                ROUND(AVG(l.response_time)::numeric, 3) as resp
            FROM logs l
            JOIN monitored_sites ms ON l.site = ms.site
            WHERE l.timestamp > NOW() - INTERVAL '30 days'
              AND l.site <> ALL(%s)
            GROUP BY grp
        """, (SELF_MONITORING_SITES,))
        group_agg = {r['grp']: r for r in cur.fetchall()}

    cur.execute("""
        SELECT site, start_time,
            CASE 
                WHEN resolved = TRUE THEN GREATEST(1, CEIL(EXTRACT(EPOCH FROM (COALESCE(end_time, NOW()) - start_time))/60)::INT)
                ELSE CEIL(EXTRACT(EPOCH FROM (NOW() - start_time))/60)::INT
            END as dur,
            max_status, resolved,
            CASE WHEN max_status = 0 THEN 'Timeout'
                 WHEN max_status = 502 THEN 'Bad Gateway'
                 WHEN max_status = 503 THEN 'Service Unavailable'
                 WHEN max_status = 701 THEN 'Content Mismatch'
                 ELSE 'Server Error' END as description,
            ssl_chain_valid
        FROM incidents
        WHERE start_time > NOW() - INTERVAL '30 days'
          AND site <> ALL(%s)
        ORDER BY start_time DESC LIMIT 100
    """, (SELF_MONITORING_SITES,))
    incidents_list = [dict(r) for r in cur.fetchall()]

    if not incidents_list:
        cur.execute("""
            WITH status_changes AS (
                SELECT site, timestamp, status,
                    CASE WHEN status != 200 AND
                        (LAG(status) OVER (PARTITION BY site ORDER BY timestamp) = 200
                         OR LAG(status) OVER (PARTITION BY site ORDER BY timestamp) IS NULL)
                    THEN 1 ELSE 0 END as is_start
                FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'
                  AND site <> ALL(%s)
            ),
            incident_groups AS (
                SELECT site, timestamp, status,
                    SUM(is_start) OVER (PARTITION BY site ORDER BY timestamp) as grp_id
                FROM status_changes WHERE status != 200
            )
            SELECT site, MIN(timestamp) as start_time, COUNT(*) * 1 as dur,
                MAX(status) as max_status,
                CASE WHEN MAX(status) = 0 THEN 'Timeout'
                     WHEN MAX(status) = 502 THEN 'Bad Gateway'
                     WHEN MAX(status) = 503 THEN 'Service Unavailable'
                     WHEN MAX(status) = 701 THEN 'Content Mismatch'
                     ELSE 'Server Error' END as description,
                NULL::boolean as ssl_chain_valid
            FROM incident_groups
            GROUP BY site, grp_id ORDER BY start_time DESC LIMIT 100
        """, (SELF_MONITORING_SITES,))
        incidents_list = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT site, start_time,
            COALESCE(duration_min, CEIL(EXTRACT(EPOCH FROM (NOW() - start_time))/60)::INT) as dur,
            max_status,
            CASE WHEN max_status = 0 THEN 'Timeout'
                 WHEN max_status = 502 THEN 'Bad Gateway'
                 WHEN max_status = 503 THEN 'Service Unavailable'
                 WHEN max_status = 701 THEN 'Content Mismatch'
                 ELSE 'Server Error' END as description,
            ssl_chain_valid
        FROM incidents
        WHERE start_time > NOW() - INTERVAL '30 days'
          AND site = ANY(%s)
          AND max_status != 401
        ORDER BY start_time DESC LIMIT 20
    """, (SELF_MONITORING_SITES,))
    self_incidents_list = [dict(r) for r in cur.fetchall()]

    if not self_incidents_list:
        cur.execute("""
            WITH status_changes AS (
                SELECT site, timestamp, status,
                    CASE WHEN status != 200 AND status != 401 AND
                        (LAG(status) OVER (PARTITION BY site ORDER BY timestamp) = 200
                         OR LAG(status) OVER (PARTITION BY site ORDER BY timestamp) IS NULL)
                    THEN 1 ELSE 0 END as is_start
                FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'
                  AND site = ANY(%s)
            ),
            incident_groups AS (
                SELECT site, timestamp, status,
                    SUM(is_start) OVER (PARTITION BY site ORDER BY timestamp) as grp_id
                FROM status_changes WHERE status != 200 AND status != 401
            )
            SELECT site, MIN(timestamp) as start_time, COUNT(*) * 1 as dur,
                MAX(status) as max_status,
                CASE WHEN MAX(status) = 0 THEN 'Timeout'
                     WHEN MAX(status) = 502 THEN 'Bad Gateway'
                     WHEN MAX(status) = 503 THEN 'Service Unavailable'
                     WHEN MAX(status) = 701 THEN 'Content Mismatch'
                     ELSE 'Server Error' END as description,
                NULL::boolean as ssl_chain_valid
            FROM incident_groups
            GROUP BY site, grp_id ORDER BY start_time DESC LIMIT 20
        """, (SELF_MONITORING_SITES,))
        self_incidents_list = [dict(r) for r in cur.fetchall()]

    cur.close()
    conn.close()

    active_incidents = [r for r in incidents_list if not r.get('resolved', True)]

    # Загружаем динамические категории + сайты по категориям
    conn2 = get_db_connection()
    cur2 = conn2.cursor(cursor_factory=DictCursor)
    cur2.execute("SELECT id, label, sort_order FROM site_categories ORDER BY sort_order")
    db_cats_list = [dict(r) for r in cur2.fetchall()]
    cur2.execute("SELECT site, site_group FROM monitored_sites WHERE site_group != 'self' ORDER BY site")
    monitored_rows = cur2.fetchall()
    cur2.close()
    conn2.close()

    # Собираем сайты по категориям
    sites_by_cat = {}
    for r in monitored_rows:
        sg = r['site_group'] or 'external'
        sites_by_cat.setdefault(sg, []).append(r['site'])
    # Добавляем сайты не из monitored_sites во 'external'
    for s in SITES:
        found = False
        for cat_sites in sites_by_cat.values():
            if s in cat_sites:
                found = True
                break
        if not found:
            sites_by_cat.setdefault('external', []).append(s)

    categories_data = []
    for cat in db_cats_list:
        cat_id = cat['id']
        cat_sites = sites_by_cat.get(cat_id, [])
        categories_data.append({
            'id': cat_id,
            'label': cat['label'],
            'sort_order': cat['sort_order'],
            'sites': cat_sites
        })

    data = {
        "s30": s30, "s24": s24,
        "latest": latest, "stats": stats,
        "incidents": incidents_list,
        "active_incidents": active_incidents,
        "group_agg": group_agg,
        "categories": categories_data,
        "sites_by_cat": sites_by_cat,
        "db_cats": db_cats_list,
        "now_msk": datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")
    }
    with _dashboard_cache["lock"]:
        _dashboard_cache["data"] = data
        _dashboard_cache["timestamp"] = time.time()

    # === CHUNK 3: BODY (когда SQL готов) ===
    yield _build_body(data)


@app.get("/")
async def index(auth: bool = Depends(check_auth)):
    """StreamingResponse: троббер показывается мгновенно, данные приходят потом."""
    global _dashboard_cache
    now = time.time()
    with _dashboard_cache["lock"]:
        cached = _dashboard_cache["data"] and (now - _dashboard_cache["timestamp"] < CACHE_TTL)
        if cached:
            # Кэш хит — отправляем всё за один чанк (head + body)
            return HTMLResponse(_build_head() + _build_body(_dashboard_cache["data"]))

    # Кэш промах — стримим: head мгновенно, body после SQL
    return StreamingResponse(_index_stream(), media_type="text/html; charset=utf-8")



def _build_head() -> str:
    """HTML <head> + inline spinner + CSS — отправляется мгновенно (streaming), без SQL.
    Разделено от body чтобы троббер показался ДО загрузки данных."""
    return (
        """<html><head><meta charset="UTF-8"><title>Мониторинг сайтов</title>"""
        """<!-- CRITICAL: instant loading spinner -->
    <script>
    (function(){
        var CIRC = 251.2;
        document.write(
            '<style>'+
            '#load-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;'+
            'z-index:99999;display:flex;flex-direction:column;align-items:center;justify-content:center;'+
            'transition:opacity .5s,visibility .5s}'+
            '#load-overlay.hidden{opacity:0;visibility:hidden;pointer-events:none}'+
            '.load-spinner{position:relative;width:100px;height:100px;margin-bottom:25px}'+
            '.load-spinner svg{width:100px;height:100px;transform:rotate(-90deg)}'+
            '.load-spinner .track{fill:none;stroke:#e2e8f0;stroke-width:6}'+
            '.load-spinner .fill{fill:none;stroke:#00717a;stroke-width:6;stroke-linecap:round;'+
            'stroke-dasharray:'+CIRC+';stroke-dashoffset:'+CIRC+';transition:stroke-dashoffset .3s}'+
            '.load-pct{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);'+
            'font-size:22px;font-weight:700;color:#00717a;font-family:Segoe UI,sans-serif}'+
            '.load-label{font-size:15px;color:#475569;font-weight:500;margin-top:5px}'+
            '.load-sub{font-size:12px;color:#94a3b8;margin-top:6px}'+
            '</style>'+
            '<div id="load-overlay">'+
            '<div class="load-spinner">'+
            '<svg viewBox="0 0 100 100">'+
            '<circle class="track" cx="50" cy="50" r="40"/>'+
            '<circle class="fill" id="load-fill" cx="50" cy="50" r="40"/>'+
            '</svg><div class="load-pct" id="load-pct">0%</div></div>'+
            '<div class="load-label">Опрос объектов мониторинга</div>'+
            '<div class="load-sub" id="load-sub">Инициализация</div></div>'
        );
        var progress = 0, target = 5;
        var phases = [
            {t:15,s:'Загрузка статусов сайтов'},{t:35,s:'Сбор метрик доступности'},
            {t:55,s:'Анализ SSL-сертификатов'},{t:70,s:'Загрузка истории инцидентов'},
            {t:88,s:'Формирование интерфейса'},{t:100,s:'Готово'}
        ];
        var fill = null, pctTxt = null, subTxt = null;
        function findEl() {
            if (!fill) { fill = document.getElementById('load-fill'); pctTxt = document.getElementById('load-pct'); subTxt = document.getElementById('load-sub'); }
        }
        function setProg(p) {
            progress = Math.min(100, Math.max(0, p));
            findEl();
            if (fill) fill.style.strokeDashoffset = CIRC - (progress/100)*CIRC;
            if (pctTxt) pctTxt.textContent = Math.round(progress)+'%';
            for (var i = phases.length-1; i>=0; i--) { if (progress >= phases[i].t) { if (subTxt) subTxt.textContent = phases[i].s; break; } }
        }
        function tick() {
            if (progress < target) { var step = Math.max(0.3, (target-progress)*0.06); setProg(progress+step); }
            if (progress < 100) requestAnimationFrame(tick);
        }
        var phaseIdx = 0;
        function advance() {
            if (phaseIdx < phases.length) { target = phases[phaseIdx].t; phaseIdx++; setTimeout(advance, 250+Math.random()*400); }
        }
        setProg(0); requestAnimationFrame(tick); setTimeout(advance, 100);
        window.__setLoadProg = setProg;
        /* Safety hide */
        setTimeout(function(){
            var o = document.getElementById('load-overlay');
            if (o && !o.classList.contains('hidden')) { setProg(100); o.classList.add('hidden'); setTimeout(function(){o.remove();},600); }
        }, 8000);
    })();
    </script>"""
        """<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f8fafc;
                padding: 20px; color: #1e293b; }
        .container { max-width: 1400px; margin: auto; background: white;
                      padding: 25px; border-radius: 12px;
                      box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .kpi-grid { display: grid; grid-template-columns: repeat(5, 1fr);
                     gap: 10px; margin-bottom: 20px; }
        .kpi-card { background: #fff; padding: 10px; border-radius: 10px;
                     border: 1px solid #e2e8f0; border-top: 4px solid #00717a;
                     text-align: center; }
        .danger-card { border-top-color: #ef4444 !important;
                        background: #fef2f2 !important; }
        .error-bar { background: #fff1f2; border: 1px solid #fee2e2;
                      color: #b91c1c; padding: 15px; border-radius: 8px;
                      margin-bottom: 20px; font-weight: bold; }
        .error-list { margin: 5px 0 0 20px; padding: 0; list-style-type: disc; }
        .tabs { display: flex; gap: 8px; margin-bottom: 15px;
                 border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
        .tab-btn { padding: 10px 20px; border: none; background: #e2e8f0;
                    border-radius: 6px; cursor: pointer; font-weight: bold; }
        .tab-btn.active { background: #00717a; color: white; }
        .tab-content { display: none; }
        .active-content { display: block; }
        .tab-content { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th, td { padding: 10px 8px; text-align: left;
                  border-bottom: 1px solid #f1f5f9; white-space: nowrap; }
        td:first-child, th:first-child { white-space: nowrap; min-width: 220px; }
        .incidents-table th:first-child, .incidents-table td:first-child { min-width: auto; width: 11ch; }
        .table-wrap { overflow-x: auto; }
        .row-err { background-color: #fff1f2 !important; }
        .txt-err { color: #dc2626; font-weight: bold; }
        .txt-ok { color: #16a34a; font-weight: bold; }
        .refresh-btn { background: #00717a; color: white; border: none;
                        padding: 8px 15px; border-radius: 6px; cursor: pointer; }
        .btn-test { background: #00717a; color: white; border: none;
                     padding: 5px 10px; border-radius: 4px; cursor: pointer;
                     text-decoration: none; font-size: 11px;
                     display: inline-flex; align-items: center;
                     justify-content: center; min-width: 80px; }
        .loader { border: 2px solid #f3f3f3; border-top: 2px solid #00717a;
                   border-radius: 50%; width: 12px; height: 12px;
                   animation: spin 1s linear infinite; display: none; margin-right: 5px; }
        @keyframes spin { 0% { transform: rotate(0deg); }
                           100% { transform: rotate(360deg); } }
        .loading .loader { display: inline-block; }
        .loading span { display: none; }
        .toast { position: fixed; bottom: 20px; right: 20px;
                  background: #333; color: white; padding: 12px 24px;
                  border-radius: 8px; display: none; z-index: 1000;
                  box-shadow: 0 4px 10px rgba(0,0,0,0.3); }
        .group-header { background: #e2e8f0; font-weight: bold; color: #475569; padding: 8px 12px; }
        .group-sub { font-weight: normal; font-size: 12px; color: #64748b; margin-left: 12px; }
        .incident-hidden { display: none; }
        .btn-show-all { background: #e2e8f0; color: #475569; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; margin-top: 10px; }
        .btn-show-all:hover { background: #cbd5e1; }
    </style></head><body>"""
    )


def _build_body(data: dict) -> str:
    """Сборка body + JS — часть которая зависит от SQL-данных.
    Отправляется ВТОРОЙ чанкой в streaming response (после head)."""
    s30 = data["s30"]
    s24 = data["s24"]
    latest = data["latest"]
    stats = data["stats"]
    incidents_list = data["incidents"]
    now_msk = data["now_msk"]
    active_incidents = data.get("active_incidents", [])
    group_agg = data.get("group_agg", {})

    incidents = [s for s, v in latest.items() if v['status'] != 200]
    ssl_warn = [s for s, v in latest.items() if 0 <= v['ssl_days'] <= 20]
    latency_warn = [s for s, v in latest.items()
                    if v['response_time'] > 20 and v['status'] == 200]
    active_incidents = data.get("active_incidents", [])

    # Сборка предупреждений: объединяем ❌ + ⚠️ в одну строку
    # Билдим lookup: site → incident info
    inc_lookup = {r['site']: f", Инцидент {r['dur']} мин, {r['description']}" for r in active_incidents}
    all_warn_list = []
    for s in incidents:
        line = f"❌ {s} (Offline){inc_lookup.pop(s, '')}"
        all_warn_list.append(line)
    # Добавляем оставшиеся инциденты (не связанные с offline)
    for r in active_incidents:
        if r['site'] not in incidents:
            all_warn_list.append(f"⚠️ {r['site']} (Инцидент {r['dur']} мин, {r['description']})")
    all_warn_list += (
        [f"🔒 {s} (SSL {latest[s]['ssl_days']}д)" for s in ssl_warn]
        + [f"🐢 {s} (Задержка {round(latest[s]['response_time'], 1)}с)"
           for s in latency_warn]
    )

    online_count = sum(1 for s in latest.values() if s['status'] == 200)
    total_sites = len(SITES)
    # Уникальные активные инциденты (1 на сайт)
    active_incidents_count = len({r['site'] for r in active_incidents})
    offline_count = len(incidents)

    # Динамические категории из данных (загружены в _index_stream)
    categories = data.get("categories", [])
    sites_by_cat = data.get("sites_by_cat", {})
    db_cats = data.get("db_cats", [])

    # Build cat index: cat_id -> sort_index
    cat_index = {c['id']: i for i, c in enumerate(db_cats)}
    group_names = {i: c['label'] for i, c in enumerate(db_cats)}

    # Site -> group index
    site_to_cat = {}
    for cat_id, sites_list in sites_by_cat.items():
        idx = cat_index.get(cat_id, 999)
        for s in sites_list:
            site_to_cat[s] = idx

    def get_site_group(site_name):
        return site_to_cat.get(site_name, 999)

    sorted_sites = sorted(SITES, key=lambda x: (get_site_group(x), 0 if x == 'sibur.ru' else 1, x))
    sorted_sites_json = json.dumps(sorted_sites)

    # Build categoriesData for JS: [{id, label, sites}]
    categories_data_js = []
    for cat in categories:
        categories_data_js.append({
            'id': cat['id'],
            'label': cat['label'],
            'sites': cat['sites']
        })
    categories_json = json.dumps(categories_data_js)

    group_stats = {}
    for c in db_cats:
        cat_id = c['id']
        cat_idx = cat_index[cat_id]
        group_sites = [s for s in sorted_sites if get_site_group(s) == cat_idx]
        group_valid = [latest[s] for s in group_sites if s in latest]
        g_row = group_agg.get(cat_idx)
        if g_row and g_row.get('upt') is not None:
            g_upt = float(g_row['upt'])
            g_resp = float(g_row['resp'] or 0)
        else:
            if group_valid:
                g_upt = round(sum(float((stats.get(site, {}) or {}).get('upt', 0) or 0) for site in group_sites) / max(len(group_sites), 1), 1)
                g_resp = round(sum(float(v['response_time']) for v in group_valid) / len(group_valid), 2)
            else:
                g_upt, g_resp = 0, 0
        g_online = sum(1 for v in group_valid if v['status'] == 200) if group_valid else 0
        group_stats[cat_idx] = {
            'online': g_online, 'total': len(group_sites),
            'upt': float(g_upt), 'resp': float(g_resp)
        }
    group_stats_json = json.dumps(group_stats)

    js_vars = {
        'categories_json': categories_json,
        'group_stats_json': group_stats_json,
    }

    H = []

    H.append(f"""<div id="toast" class="toast"></div>
    <div class="container">
        <div style="display:flex; justify-content:space-between;
                     align-items:center; margin-bottom:20px;">
            <h1 style="color:#00717a; margin:0;">📊 Мониторинг сайтов</h1>
            <button class="refresh-btn" onclick="location.reload()">
                🔄 Обновить: {now_msk}
            </button>
        </div>
        <div class="kpi-grid">
            <div class="kpi-card {'danger-card' if online_count < total_sites else ''}">
                <span>Доступно</span><strong><br>{online_count} / {total_sites}</strong>
            </div>
            <div class="kpi-card">
                <span>Uptime (24ч / 30д)</span>
                <strong><br>{s24['up']}% / {s30['up']}%</strong>
            </div>
            <div class="kpi-card">
                <span>Ответ (24ч / 30д)</span>
                <strong><br>{s24['resp']}с / {s30['resp']}с</strong>
            </div>
            <div class="kpi-card {'danger-card' if active_incidents_count > 0 or offline_count > 0 else ''}">
                <span>Инциденты</span><strong><br>{active_incidents_count}</strong>
                {f'<br><span style="font-size:11px;color:#dc2626;">({active_incidents_count} active)</span>' if active_incidents_count > 0 else ''}
            </div>
            <div class="kpi-card {'danger-card' if ssl_warn else ''}">
                <span>SSL &lt;=20д</span><strong><br>{len(ssl_warn)}</strong>
            </div>
        </div>
        {f'<div class="error-bar">⚠️ Обратите внимание:<ul class="error-list"><li>'
         + '</li><li>'.join(all_warn_list) + '</li></ul></div>' if all_warn_list else ''}
        <div class="tabs">
            <button class="tab-btn active" onclick="tab(event, 't1')">Список</button>
            <button class="tab-btn" onclick="tab(event, 't2')">Аналитика</button>
            <button class="tab-btn" onclick="tab(event, 't3')">Инциденты</button>
            <button class="tab-btn" onclick="tab(event, 't4')">Календарь событий</button>
            <button class="tab-btn" onclick="location.href='/admin/page'">Управление</button>
        </div>
        <div id="t1" class="tab-content active-content">
            <div class="table-wrap"><table><thead><tr><th>Сайт</th><th>Статус</th><th>Uptime 30д</th><th>Простой 30д</th>
            <th>Ответ</th><th>SSL</th><th>Цепочка SSL</th><th>Домен</th><th>Тест</th></tr></thead><tbody>
    """)

    current_group = -1
    for s in sorted_sites:
        g = get_site_group(s)
        if g != current_group:
            st = group_stats.get(g, {'online': 0, 'total': 0, 'upt': 0, 'resp': 0})
            g_sub = f'<span class="group-sub">Online: {st["online"]}/{st["total"]} | Uptime: {st["upt"]}% | Avg Ответ: {st["resp"]}с</span>'
            H.append(f'<tr><td colspan="9" class="group-header">{group_names[g]}{g_sub}</td></tr>')
            current_group = g
        v = latest.get(s, {'status': 0, 'response_time': 0, 'ssl_days': -1, 'domain_days': -1, 'ssl_chain_valid': None})
        st30 = stats.get(s, {'upt': 0, 'down_sec': 0})
        is_err = (v['status'] != 200 or (0 <= v['ssl_days'] <= 20) or
                  (0 <= v['domain_days'] <= 30) or v.get('ssl_chain_valid') == False)
        g_idx = get_site_group(s)
        prefix = "⭐ " if g_idx == 0 else ("🛡️ " if g_idx == 1 else "")

        H.append(f"""<tr class="{'row-err' if is_err else ''}">
            <td>{prefix}<a href="https://{s}" target="_blank"
                style="text-decoration:none; color:inherit;"><strong>{s}</strong></a></td>
            <td><span class="{'txt-ok' if v['status']==200 else 'txt-err'}">
                {'Online' if v['status']==200 else ('Content Mismatch' if v['status']==701 else 'Offline')}</span></td>
            <td>{st30['upt']}%</td><td>{_fmt_downtime(st30.get('down_sec', 0))}</td><td>{round(v['response_time'], 2)}с</td>
            <td class="{'txt-err' if 0<=v['ssl_days']<=20 else ''}">{v['ssl_days']}д</td>
            <td class="{'txt-err' if v.get('ssl_chain_valid') == False else 'txt-ok' if v.get('ssl_chain_valid') == True else ''}">
                {'✅' if v.get('ssl_chain_valid') == True else '❌' if v.get('ssl_chain_valid') == False else '—'}</td>
            <td class="{'txt-err' if 0<=v['domain_days']<=30 else ''}">{v['domain_days']}д</td>
            <td><button class="btn-test" onclick="runTest('{s}', this)">
                <div class="loader"></div><span>📸 Screen</span></button></td></tr>""")

    H.append("""</tbody></table></div></div>
    <div id="t2" class="tab-content">
    <div id="charts-container" style="display:grid; grid-template-columns:repeat(auto-fit,minmax(400px,1fr)); gap:20px;">
        <div style="text-align:center; padding:40px; color:#999;">Загрузка графиков...</div>
    </div></div>
    <div id="t3" class="tab-content">
    <div class="table-wrap"><table class="incidents-table"><thead><tr><th>Начало</th><th>Сайт</th><th>Длительность</th>
    <th>Код</th><th>Описание</th><th>Цепочка SSL</th><th>Статус</th></tr></thead><tbody>""")

    for idx, r in enumerate(incidents_list):
        hidden_class = 'incident-hidden' if idx >= 20 else ''
        resolved_badge = '✅ Resolved' if r.get('resolved', True) else '🔴 Active'
        H.append(f"""<tr class="{hidden_class}"><td>{r['start_time'].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')}</td>
            <td>{r['site']}</td><td class='txt-err'>{r['dur']} мин</td>
            <td>{r['max_status']}</td><td>{r['description']}</td>
            <td class="{'txt-err' if r.get('ssl_chain_valid') == False else 'txt-ok' if r.get('ssl_chain_valid') == True else ''}">
                {'✅' if r.get('ssl_chain_valid') == True else '❌' if r.get('ssl_chain_valid') == False else '—'}</td>
            <td><span style="font-size:12px;padding:3px 8px;border-radius:4px;background:{'#dcfce7;color:#166534' if r.get('resolved', True) else '#fee2e2;color:#991b1b'}">{resolved_badge}</span></td></tr>""")

    total_incidents = len(incidents_list)
    if total_incidents > 20:
        H.append(f"""</tbody></table>
        <div style="text-align:center;">
            <button id="btn-show-incidents" class="btn-show-all" onclick="toggleIncidents()">
                Показать все ({total_incidents})
            </button>
        </div></div></div>""")
    else:
        H.append("""</tbody></table></div></div>""")

    H.append("""<div id="t4" class="tab-content">
    <div class="table-wrap"><table><thead><tr><th>Тип события</th><th>Сайт</th><th>Осталось дней</th>
    </tr></thead><tbody>""")

    cal_events = []
    for s in SITES:
        v = latest.get(s, {})
        if v.get('ssl_days', -1) >= 0:
            cal_events.append({'t': 'SSL сертификат', 's': s, 'd': v['ssl_days']})
        if v.get('domain_days', -1) >= 0:
            cal_events.append({'t': 'Оплата домена', 's': s, 'd': v['domain_days']})
    for ev in sorted(cal_events, key=lambda x: x['d']):
        H.append(f"""<tr><td>{ev['t']}</td><td>{ev['s']}</td>
            <td class="{'txt-err' if ev['d']<=30 else ''}">{ev['d']} дн.</td></tr>""")

    H.append("""</tbody></table></div>
    </div>""")

    dash_js_template = """
    <script>
    // ===== FINALIZE LOADING (троббер создан inline в <head>) =====
    (function(){
        const overlay = document.getElementById('load-overlay');
        const setProg = window.__setLoadProg || function(){};
        // Контент загружен — мгновенно скрываем троббер, не ждем window.load
        setProg(100);
        requestAnimationFrame(function(){
            if (overlay) overlay.classList.add('hidden');
            setTimeout(function(){ if (overlay) overlay.remove(); }, 500);
        });
    })();
    // =============================

    let chartsLoaded = false;
    let chartsLoading = false;
    let showingAll = false;

    const categoriesData = $categories_json;
    const groupStats = $group_stats_json;

    function tab(e, n){
        var i, x = document.getElementsByClassName('tab-content'),
            b = document.getElementsByClassName('tab-btn');
        for(i = 0; i < x.length; i++) x[i].className = 'tab-content';
        for(i = 0; i < b.length; i++) b[i].className = 'tab-btn';
        document.getElementById(n).className = 'tab-content active-content';
        e.currentTarget.className += ' active';
        if (n === 't2') loadCharts();
    }

    async function runTest(site, btn) {
        if (btn.classList.contains('loading')) return;
        btn.classList.add('loading');
        btn.disabled = true;
        try {
            const response = await fetch('/test-screen/' + site);
            const data = await response.json();
            showToast(data.msg);
        } catch (e) { showToast('Ошибка связи с сервером'); }
        finally { btn.classList.remove('loading'); btn.disabled = false; }
    }

    function showToast(msg) {
        const t = document.getElementById('toast');
        t.innerText = msg;
        t.style.display = 'block';
        setTimeout(() => { t.style.display = 'none'; }, 4000);
    }

    function renderChartSection(titleKey, titleIdx, sitesList, g_data, container) {
        const filtered = sitesList.filter(s => g_data[s]);
        if (filtered.length === 0) return;
        const st = groupStats[titleIdx] || {online:0, total:0, upt:0, resp:0};
        const h3 = document.createElement('h3');
        h3.style.gridColumn = '1 / -1';
        h3.style.marginTop = '20px';
        h3.style.color = '#475569';
        h3.innerHTML = titleKey + ' <span style="float:right;font-weight:normal;font-size:13px;">Online: ' + st.online + '/' + st.total + ' | Uptime: ' + st.upt + '% | Avg Ответ: ' + st.resp + 'с</span>';
        container.appendChild(h3);
        for (const s of filtered) {
            const d = g_data[s];
            const div = document.createElement('div');
            div.className = 'kpi-card';
            div.style.borderTop = '2px solid #eee';
            div.innerHTML = '<h5>' + s + '</h5><canvas id="c-' + s.replace(/\\./g, '_') + '"></canvas>';
            container.appendChild(div);
            new Chart(document.getElementById('c-' + s.replace(/\\./g, '_')), {
                type: 'line',
                data: {
                    labels: d.l,
                    datasets: [
                        { label: 'Uptime %', data: d.u, borderColor: '#10b981', backgroundColor: '#10b981', yAxisID: 'y', tension: 0.3, pointRadius: 3, pointHoverRadius: 5 },
                        { label: 'Ответ сек', data: d.r, borderColor: '#3b82f6', backgroundColor: '#3b82f6', yAxisID: 'y1', tension: 0.3, pointRadius: 3, pointHoverRadius: 5 }
                    ]
                },
                options: {
                    scales: {
                        y: { suggestedMin: 95, suggestedMax: 100.5, title: { display: true, text: 'Uptime %' } },
                        y1: { position: 'right', grid: { display: false }, title: { display: true, text: 'Ответ, сек' } }
                    }
                }
            });
        }
    }

    async function loadCharts() {
        if (chartsLoaded || chartsLoading) return;
        chartsLoading = true;
        try {
            const res = await fetch('/api/charts');
            const g_data = await res.json();
            const container = document.getElementById('charts-container');
            container.innerHTML = '';

            // Рендерим графики по динамическим категориям
            for (let i = 0; i < categoriesData.length; i++) {
                const cat = categoriesData[i];
                renderChartSection(cat.label, i, cat.sites, g_data, container);
            }

            chartsLoaded = true;
        } catch (e) {
            document.getElementById('charts-container').innerHTML =
                '<div style="text-align:center; padding:40px; color:#b91c1c;">Ошибка загрузки графиков</div>';
        } finally {
            chartsLoading = false;
        }
    }

    function toggleIncidents() {
        const hidden = document.querySelectorAll('#t3 .incident-hidden');
        const btn = document.getElementById('btn-show-incidents');
        for (const row of hidden) {
            row.classList.remove('incident-hidden');
        }
        if (btn) btn.style.display = 'none';
    }

    setInterval(() => { location.reload(); }, 600000);
    </script></body></html>"""

    dash_js = Template(dash_js_template).substitute(js_vars)
    H.append(dash_js)

    return "".join(H)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))