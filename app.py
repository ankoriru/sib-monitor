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
from io import StringIO
from psycopg2.extras import DictCursor, execute_values
from playwright.async_api import async_playwright
from fastapi import FastAPI, Request, Response, Depends, HTTPException, Cookie
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

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
    "cp.tdms.sibur.ru/cp/"
]

# --- SEC-1: Whitelist для self-signed сертификатов ---
SELF_SIGNED_SITES = set(NEW_MONITORING_SITES)
if os.getenv("SELF_SIGNED_SITES"):
    SELF_SIGNED_SITES.update(os.getenv("SELF_SIGNED_SITES").split(","))

# --- SEC-2: BCrypt-хеширование паролей через env ---
AUTH_USERNAME = os.getenv("AUTH_USERNAME", "sibur")
AUTH_PASSWORD_HASH = os.getenv("AUTH_PASSWORD_HASH", "")

SITES = [
    "sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru",
    "alphapor.ru", "amur-gcc.ru", "ar24.sibur.ru",
    "bopp.sibur.ru", "carbo.sibur.ru", "carbonfootprintcalculator.sibur.ru",
    "career.sibur.ru", "catalog.sibur.ru", "coach.sibur.ru",
    "ecoball.sibur.ru", "greencity-sibur.ru", "guide.sibur.ru",
    "laika.sibur.ru", "magazine.sibur.ru", "mendeleev-smena.ru",
    "messages2.sibur.ru", "nauka.sibur.ru", "oknavdome.info",
    "photo.sibur.ru", "polylabsearch.ru", "portenergo.com",
    "rusvinyl.ru",
    "sibur.digital", "sibur-int.com", "sibur-int.ru", "sibur-yug.ru",
    "snck.ru", "tu-sibur.ru", "vivilen.sibur.ru"
] + NEW_MONITORING_SITES

PRIORITY_SITES = [
    "sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru", "career.sibur.ru"
] + NEW_MONITORING_SITES

# --- Группировка сайтов для UI ---
KEY_SITES = ["sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru", "career.sibur.ru"]
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
_screenshot_queue = queue.Queue()
_screenshot_thread = None
_screenshot_thread_lock = threading.Lock()

# WHOIS cache (24h TTL)
_whois_cache = {}
WHOIS_CACHE_TTL = 86400

# Screenshot rate limit (30 sec per site)
_screenshot_rate_limit = {}
_screenshot_rate_lock = threading.Lock()


def _screenshot_worker():
    """Отдельный поток с event loop для Playwright (избегает loop conflict)"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_screenshot_loop())


def _ensure_screenshot_worker():
    """Лениво запускает Playwright worker только при первом запросе скриншота."""
    global _screenshot_thread
    with _screenshot_thread_lock:
        if _screenshot_thread is None or not _screenshot_thread.is_alive():
            _screenshot_thread = threading.Thread(target=_screenshot_worker, daemon=True)
            _screenshot_thread.start()


async def _screenshot_loop():
    """Event loop воркера: держит браузер открытым и обрабатывает очередь."""
    p = await async_playwright().start()
    browser = await p.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-sandbox-usage", "--disable-gpu",
              "--disable-setuid-sandbox", "--no-zygote"]
    )
    while True:
        try:
            site, fut = _screenshot_queue.get(timeout=1)
        except queue.Empty:
            continue
        try:
            path = await _do_screenshot(browser, site)
            fut.set_result(path)
        except Exception as e:
            print(f"[SCREEN ERR] {site}: {e}")
            try:
                fut.set_exception(e)
            except Exception:
                pass


async def _do_screenshot(browser, site):
    """Скриншот одного сайта (вызывается в loop воркера)"""
    full_url = f"https://{site}"
    path = f"debug_{site.replace('/', '_')}_{int(time.time())}.png"
    context = await browser.new_context(
        viewport={'width': 1280, 'height': 720},
        ignore_https_errors=True
    )
    try:
        page = await context.new_page()
        try:
            await page.goto(full_url, timeout=15000, wait_until="domcontentloaded")
        except Exception:
            pass
        await asyncio.sleep(1)
        await page.screenshot(path=path, type="jpeg", quality=80)
        return path
    finally:
        await context.close()


def take_screenshot_fast(site):
    """Синхронный вызов: кладёт задачу в очередь и ждёт результат"""
    _ensure_screenshot_worker()
    fut = concurrent.futures.Future()
    _screenshot_queue.put((site, fut))
    try:
        return fut.result(timeout=30)
    except concurrent.futures.TimeoutError:
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
def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


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
        # Индекс на существующее представление
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
    """Предзаполнение incidents из существующих logs (разово при первом создании таблицы)"""
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
                             ELSE 'Server Error' END as description
                    FROM incident_groups
                    GROUP BY site, grp_id
                    HAVING COUNT(*) >= 2
                )
                INSERT INTO incidents (site, start_time, end_time, duration_min,
                                       max_status, description, resolved, ssl_chain_valid)
                SELECT site, start_time, end_time,
                       CEIL(EXTRACT(EPOCH FROM (end_time - start_time))/60)::INT,
                       max_status, description, TRUE, NULL
                FROM incident_summary
                ORDER BY start_time
            """)
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
    """Проверка одного сайта: HTTP через aiohttp (async), SSL+WHOIS через to_thread (не блокирует семафор)"""
    check_url = f"https://{site}"
    domain_only = site.split('/')[0]
    curr_status, resp_time = 0, 25.0

    # --- Шаг 1: HTTP проверка (async, под семафором) ---
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

            timeout = aiohttp.ClientTimeout(total=10)
            async with actual_session.get(check_url, timeout=timeout, allow_redirects=True) as resp:
                curr_status = resp.status
                resp_time = time.time() - start
        except Exception as e:
            print(f"[CHECK ERR] {site}: {type(e).__name__}: {e}")
            curr_status, resp_time = 0, 25.0
        finally:
            if ssl_verify and connector and actual_session is not None:
                await actual_session.close()

    # --- Шаг 2: SSL + WHOIS (в отдельном потоке, НЕ блокирует семафор и event loop) ---
    ssl_d, ssl_chain_valid = -1, None
    try:
        ssl_d, ssl_chain_valid = await asyncio.wait_for(
            asyncio.to_thread(_check_ssl_sync, domain_only, site),
            timeout=5
        )
    except asyncio.TimeoutError:
        print(f"[SSL TIMEOUT] {site}")
    except Exception as e:
        print(f"[SSL ERR] {site}: {e}")

    dom_d = -1
    try:
        dom_d = await asyncio.wait_for(
            asyncio.to_thread(_check_whois_sync, domain_only),
            timeout=5
        )
    except asyncio.TimeoutError:
        print(f"[WHOIS TIMEOUT] {site}")
    except Exception as e:
        print(f"[WHOIS ERR] {site}: {e}")

    return (site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid)


async def check_all_sites():
    """Параллельная проверка всех сайтов через asyncio.gather"""
    semaphore = asyncio.Semaphore(10)
    async with aiohttp.ClientSession() as session:
        tasks = [check_single_site(session, site, semaphore) for site in SITES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]


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
        cur.execute("""
            INSERT INTO checks_agg (site, bucket, checks_count, status_200_count,
                                    avg_response_time, min_response_time, max_response_time,
                                    last_ssl_days, last_domain_days, last_ssl_chain_valid)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
        """, (site, bucket, a['cnt'], a['ok'],
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
def _db_incident_start(site, status, ssl_chain_valid=None):
    """Фиксирует начало инцидента (первый фейл сайта)"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        description = {
            0: 'Timeout',
            502: 'Bad Gateway',
            503: 'Service Unavailable'
        }.get(status, 'Server Error')
        cur.execute("""
            INSERT INTO incidents (site, start_time, max_status, description, ssl_chain_valid)
            VALUES (%s, NOW(), %s, %s, %s)
        """, (site, status, description, ssl_chain_valid))
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
            503: 'Service Unavailable'
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
                duration_min = CEIL(EXTRACT(EPOCH FROM (NOW() - start_time))/60)::INT,
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


def check_worker():
    """Фоновый воркер проверки сайтов с batch-вставкой, ротацией, incidents и heartbeat"""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("[WORKER START] check_worker started")

    last_status = {site: 200 for site in SITES}
    fail_count = {site: 0 for site in SITES}
    last_latency_map = {site: False for site in SITES}

    # Один event loop на весь воркер вместо asyncio.run() в цикле
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    while True:
        try:
            print(f"[WORKER] Starting check cycle at {datetime.datetime.now(TZ_MOSCOW).strftime('%H:%M:%S')}")
            results = loop.run_until_complete(check_all_sites())
            print(f"[WORKER] check_all_sites returned {len(results)} results")

            for site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid in results:
                try:
                    print(f"[WORKER] Processing {site} status={curr_status} resp={round(resp_time,2)}s last_status={last_status[site]} fail_count={fail_count[site]}")
                    if curr_status != 200:
                        fail_count[site] += 1
                        alert_threshold = 5
                        print(f"[CHECK FAIL] {site} status={curr_status} fail_count={fail_count[site]}/{alert_threshold} last_status={last_status[site]}")

                        # --- Incident tracking ---
                        if fail_count[site] == 1 and last_status[site] == 200:
                            print(f"[INCIDENT START] {site} first failure, creating incident")
                            _db_incident_start(site, curr_status, ssl_chain_valid)
                        elif fail_count[site] > 1:
                            _db_incident_update(site, curr_status, ssl_chain_valid)

                        with BATCH_LOCK:
                            if fail_count[site] >= 2:
                                batch_buffer.append(
                                    (site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid)
                                )
                            if len(batch_buffer) >= BATCH_SIZE:
                                flush_batch()

                        if fail_count[site] >= alert_threshold and last_status[site] == 200:
                            print(f"[ALERT TRIGGER] {site} fail_count={fail_count[site]} threshold={alert_threshold} status={curr_status}")
                            shot_path = take_screenshot_fast(site)
                            msg = f"🚨 DOWN: {site} (Код: {curr_status})"
                            ok = send_tg_msg(msg, shot_path)
                            print(f"[ALERT RESULT] {site} send_tg_msg={'OK' if ok else 'FAIL'}")
                            last_status[site] = curr_status
                            _invalidate_dashboard_cache()
                    else:
                        with BATCH_LOCK:
                            batch_buffer.append((site, curr_status, resp_time, ssl_d, dom_d, ssl_chain_valid))
                            if len(batch_buffer) >= BATCH_SIZE:
                                flush_batch()

                        if last_status[site] != 200:
                            duration = fail_count[site]
                            print(f"[ALERT TRIGGER] {site} UP after {duration} min downtime")
                            _db_incident_resolve(site)
                            ok = send_tg_msg(f"✅ UP: {site} (Был недоступен: {duration} мин.)")
                            print(f"[ALERT RESULT] {site} UP send_tg_msg={'OK' if ok else 'FAIL'}")
                            _invalidate_dashboard_cache()

                        last_status[site], fail_count[site] = 200, 0

                        if resp_time > 20 and not last_latency_map[site]:
                            print(f"[ALERT TRIGGER] {site} LATENCY {round(resp_time, 2)}s")
                            ok = send_tg_msg(f"🐢 ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек.")
                            print(f"[ALERT RESULT] {site} LATENCY send_tg_msg={'OK' if ok else 'FAIL'}")
                            last_latency_map[site] = True
                        elif resp_time < 10 and last_latency_map[site]:
                            print(f"[ALERT TRIGGER] {site} LATENCY RECOVERED {round(resp_time, 2)}s")
                            ok = send_tg_msg(
                                f"⚡️ СКОРОСТЬ ВОССТАНОВЛЕНА! {site}: {round(resp_time, 2)} сек."
                            )
                            print(f"[ALERT RESULT] {site} LATENCY REC send_tg_msg={'OK' if ok else 'FAIL'}")
                            last_latency_map[site] = False
                except Exception as e:
                    print(f"Ошибка обработки результата для {site}: {e}")

            flush_batch()
            refresh_materialized_view()
            _update_worker_heartbeat()
            # Summary каждого цикла
            total_checked = len(results)
            failed_now = sum(1 for _, st, *_ in results if st != 200)
            print(f"[CHECK SUMMARY] checked={total_checked} failed={failed_now} batch_size={len(batch_buffer)}")

        except Exception as e:
            print(f"[WORKER ERROR] {type(e).__name__}: {e}")

        finally:
            # Гарантируем ровно 60 секунд между циклами даже при ошибке
            time.sleep(60)


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
                    if r[1] is not None and 0 <= r[1] <= 20
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
    await asyncio.to_thread(backfill_checks_agg)
    await asyncio.to_thread(_backfill_incidents)
    threading.Thread(target=check_worker, daemon=True).start()
    threading.Thread(target=daily_report_worker, daemon=True).start()
    threading.Thread(target=rotation_worker, daemon=True).start()
    # Telegram config check
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[WARN] TELEGRAM_TOKEN or TELEGRAM_CHAT_ID not set — alerts disabled")
    else:
        print(f"[OK] Telegram configured: chat_id={TELEGRAM_CHAT_ID[:5]}..., token_len={len(TELEGRAM_TOKEN)}")


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
    if site_name not in SITES:
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


def _get_stats_from_agg(cur, interval: str):
    """Статистика из checks_agg; fallback на logs если агрегаты пусты.
    Uptime — взвешенный через SUM, response_time — взвешенное среднее."""
    cur.execute("""
        SELECT
            ROUND(SUM(status_200_count) * 100.0
                  / NULLIF(SUM(checks_count), 0)::numeric, 2) as up,
            ROUND((SUM(avg_response_time * checks_count)
                  / NULLIF(SUM(checks_count), 0))::numeric, 3) as resp
        FROM checks_agg WHERE bucket > NOW() - INTERVAL %s
    """, (interval,))
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
    """, (interval,))
    row = cur.fetchone()
    return {'up': float(row[0]) if row[0] is not None else 0, 'resp': float(row[1]) if row[1] is not None else 0}


# ============================================================================
# API для графиков — lazy load фоном после first paint
# ============================================================================
@app.get("/api/charts")
async def api_charts(auth: bool = Depends(check_auth)):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    allowed_sites = set(SITES)

    cur.execute("""
        SELECT site, bucket::date as d,
               ROUND((SUM(avg_response_time * checks_count)
                     / NULLIF(SUM(checks_count), 0))::numeric, 2) as r,
               ROUND(SUM(status_200_count) * 100.0 / NULLIF(SUM(checks_count), 0)::numeric, 2) as u
        FROM checks_agg
        WHERE bucket > NOW() - INTERVAL '14 days'
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
                   ROUND(COUNT(*) FILTER (WHERE status=200) * 100.0 / COUNT(*)::numeric, 2) as u
            FROM logs
            WHERE timestamp > NOW() - INTERVAL '14 days'
              AND site = ANY(%s)
            GROUP BY 1, 2
            ORDER BY 2
        """, (list(allowed_sites),))

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
@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    global _dashboard_cache
    now = time.time()
    with _dashboard_cache["lock"]:
        if _dashboard_cache["data"] and now - _dashboard_cache["timestamp"] < CACHE_TTL:
            return _build_html(_dashboard_cache["data"])

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    # --- SQL: только лёгкие запросы (нет графиков) ---
    s30 = _get_stats_from_agg(cur, '30 days')
    s24 = _get_stats_from_agg(cur, '24 hours')

    cur.execute("SELECT * FROM latest_status")
    latest_all = {r['site']: r for r in cur.fetchall()}
    latest = {s: latest_all[s] for s in SITES if s in latest_all}

    # Статистика по сайтам — из checks_agg
    cur.execute("""
        SELECT site,
            ROUND(SUM(status_200_count) * 100.0
                  / NULLIF(SUM(checks_count), 0)::numeric, 2) as upt,
            SUM(checks_count - status_200_count) * 5 as down_sec
        FROM checks_agg WHERE bucket > NOW() - INTERVAL '30 days'
        GROUP BY site
    """)
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
            GROUP BY site
        """)
        stats = {r['site']: r for r in cur.fetchall()}

    # Групповые метрики (правильный расчет uptime/resp через взвешенное среднее)
    cur.execute("""
        SELECT 
            CASE WHEN site = ANY(%s) THEN 0
                 WHEN site = ANY(%s) THEN 1
                 ELSE 2 END as grp,
            ROUND(SUM(status_200_count) * 100.0 
                  / NULLIF(SUM(checks_count), 0)::numeric, 2) as upt,
            ROUND((SUM(avg_response_time * checks_count) 
                  / NULLIF(SUM(checks_count), 0))::numeric, 3) as resp
        FROM checks_agg 
        WHERE bucket > NOW() - INTERVAL '30 days'
        GROUP BY grp
    """, (KEY_SITES, STDO_SITES))
    group_agg_rows = cur.fetchall()
    if group_agg_rows and group_agg_rows[0][0] is not None:
        group_agg = {r['grp']: r for r in group_agg_rows}
    else:
        # fallback на logs
        cur.execute("""
            SELECT 
                CASE WHEN site = ANY(%s) THEN 0
                     WHEN site = ANY(%s) THEN 1
                     ELSE 2 END as grp,
                ROUND(COUNT(*) FILTER (WHERE status = 200) * 100.0
                      / NULLIF(COUNT(*), 0)::numeric, 2) as upt,
                ROUND(AVG(response_time)::numeric, 3) as resp
            FROM logs 
            WHERE timestamp > NOW() - INTERVAL '30 days'
            GROUP BY grp
        """, (KEY_SITES, STDO_SITES))
        group_agg = {r['grp']: r for r in cur.fetchall()}

    # Инциденты — читаем из таблицы incidents (быстро), fallback на CTE из logs (разово)
    cur.execute("""
        SELECT site, start_time,
            COALESCE(duration_min, CEIL(EXTRACT(EPOCH FROM (NOW() - start_time))/60)::INT) as dur,
            max_status,
            CASE WHEN max_status = 0 THEN 'Timeout'
                 WHEN max_status = 502 THEN 'Bad Gateway'
                 WHEN max_status = 503 THEN 'Service Unavailable'
                 ELSE 'Server Error' END as description,
            ssl_chain_valid
        FROM incidents
        WHERE start_time > NOW() - INTERVAL '30 days'
        ORDER BY start_time DESC LIMIT 100
    """)
    incidents_list = [dict(r) for r in cur.fetchall()]

    # Fallback: если таблица incidents пустая — один раз используем CTE из logs
    if not incidents_list:
        cur.execute("""
            WITH status_changes AS (
                SELECT site, timestamp, status,
                    CASE WHEN status != 200 AND
                        (LAG(status) OVER (PARTITION BY site ORDER BY timestamp) = 200
                         OR LAG(status) OVER (PARTITION BY site ORDER BY timestamp) IS NULL)
                    THEN 1 ELSE 0 END as is_start
                FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'
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
                     ELSE 'Server Error' END as description,
                NULL::boolean as ssl_chain_valid
            FROM incident_groups
            GROUP BY site, grp_id ORDER BY start_time DESC LIMIT 100
        """)
        incidents_list = [dict(r) for r in cur.fetchall()]

    cur.close()
    conn.close()

    data = {
        "s30": s30, "s24": s24,
        "latest": latest, "stats": stats,
        "incidents": incidents_list,
        "group_agg": group_agg,
        "now_msk": datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")
    }
    with _dashboard_cache["lock"]:
        _dashboard_cache["data"] = data
        _dashboard_cache["timestamp"] = time.time()
    return _build_html(data)


def _build_html(data: dict) -> str:
    """Сборка HTML из кэшированного dict (без SQL, <10 мс) — оптимизировано через list"""
    s30 = data["s30"]
    s24 = data["s24"]
    latest = data["latest"]
    stats = data["stats"]
    incidents_list = data["incidents"]
    now_msk = data["now_msk"]

    incidents = [s for s, v in latest.items() if v['status'] != 200]
    ssl_warn = [s for s, v in latest.items() if 0 <= v['ssl_days'] <= 20]
    latency_warn = [s for s, v in latest.items()
                    if v['response_time'] > 20 and v['status'] == 200]

    all_warn_list = (
        [f"❌ {s} (Offline)" for s in incidents]
        + [f"🔒 {s} (SSL {latest[s]['ssl_days']}д)" for s in ssl_warn]
        + [f"🐢 {s} (Задержка {round(latest[s]['response_time'], 1)}с)"
           for s in latency_warn]
    )

    online_count = sum(1 for s in latest.values() if s['status'] == 200)
    total_sites = len(SITES)

    def get_site_group(site_name):
        if site_name in KEY_SITES:
            return 0
        if site_name in STDO_SITES:
            return 1
        return 2

    group_names = {0: "Ключевые", 1: "СТДО", 2: "Внешние сайты"}
    sorted_sites = sorted(SITES, key=lambda x: (get_site_group(x), x))
    sorted_sites_json = json.dumps(sorted_sites)
    key_sites_json = json.dumps(KEY_SITES)
    stdo_sites_json = json.dumps(STDO_SITES)
    external_sites_json = json.dumps(EXTERNAL_SITES)

    group_agg = data.get("group_agg", {})

    # Промежуточные итоги по группам для графиков (из checks_agg, взвешенное среднее)
    group_stats = {}
    for g in [0, 1, 2]:
        group_sites = [s for s in sorted_sites if get_site_group(s) == g]
        group_valid = [latest[s] for s in group_sites if s in latest]
        g_row = group_agg.get(g)
        if g_row and g_row.get('upt') is not None:
            g_upt = float(g_row['upt'])
            g_resp = float(g_row['resp'] or 0)
        else:
            # fallback: если в checks_agg нет данных — ручной расчет по сайтам
            if group_valid:
                g_upt = round(sum(float((stats.get(site, {}) or {}).get('upt', 0) or 0) for site in group_sites) / max(len(group_sites), 1), 1)
                g_resp = round(sum(float(v['response_time']) for v in group_valid) / len(group_valid), 2)
            else:
                g_upt, g_resp = 0, 0
        g_online = sum(1 for v in group_valid if v['status'] == 200) if group_valid else 0
        group_stats[g] = {
            'online': g_online, 'total': len(group_sites),
            'upt': float(g_upt), 'resp': float(g_resp)
        }
    group_stats_json = json.dumps(group_stats)

    # Используем list для O(n) сборки вместо O(n^2) string concatenation
    H = []

    H.append(f"""<html><head><meta charset="UTF-8"><title>Мониторинг сайтов</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc;
                padding: 20px; color: #1e293b; }}
        .container {{ max-width: 1400px; margin: auto; background: white;
                      padding: 25px; border-radius: 12px;
                      box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(5, 1fr);
                     gap: 10px; margin-bottom: 20px; }}
        .kpi-card {{ background: #fff; padding: 10px; border-radius: 10px;
                     border: 1px solid #e2e8f0; border-top: 4px solid #00717a;
                     text-align: center; }}
        .danger-card {{ border-top-color: #ef4444 !important;
                        background: #fef2f2 !important; }}
        .error-bar {{ background: #fff1f2; border: 1px solid #fee2e2;
                      color: #b91c1c; padding: 15px; border-radius: 8px;
                      margin-bottom: 20px; font-weight: bold; }}
        .error-list {{ margin: 5px 0 0 20px; padding: 0; list-style-type: disc; }}
        .tabs {{ display: flex; gap: 8px; margin-bottom: 15px;
                 border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
        .tab-btn {{ padding: 10px 20px; border: none; background: #e2e8f0;
                    border-radius: 6px; cursor: pointer; font-weight: bold; }}
        .tab-btn.active {{ background: #00717a; color: white; }}
        .tab-content {{ display: none; }}
        .active-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 12px; text-align: left;
                  border-bottom: 1px solid #f1f5f9; }}
        .row-err {{ background-color: #fff1f2 !important; }}
        .txt-err {{ color: #dc2626; font-weight: bold; }}
        .txt-ok {{ color: #16a34a; font-weight: bold; }}
        .refresh-btn {{ background: #00717a; color: white; border: none;
                        padding: 8px 15px; border-radius: 6px; cursor: pointer; }}
        .btn-test {{ background: #00717a; color: white; border: none;
                     padding: 5px 10px; border-radius: 4px; cursor: pointer;
                     text-decoration: none; font-size: 11px;
                     display: inline-flex; align-items: center;
                     justify-content: center; min-width: 80px; }}
        .loader {{ border: 2px solid #f3f3f3; border-top: 2px solid #00717a;
                   border-radius: 50%; width: 12px; height: 12px;
                   animation: spin 1s linear infinite; display: none; margin-right: 5px; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }}
                           100% {{ transform: rotate(360deg); }} }}
        .loading .loader {{ display: inline-block; }}
        .loading span {{ display: none; }}
        .toast {{ position: fixed; bottom: 20px; right: 20px;
                  background: #333; color: white; padding: 12px 24px;
                  border-radius: 8px; display: none; z-index: 1000;
                  box-shadow: 0 4px 10px rgba(0,0,0,0.3); }}
        .group-header {{ background: #e2e8f0; font-weight: bold; color: #475569; padding: 8px 12px; }}
        .group-sub {{ font-weight: normal; font-size: 12px; color: #64748b; margin-left: 12px; }}
        .incident-hidden {{ display: none; }}
        .btn-show-all {{ background: #e2e8f0; color: #475569; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; margin-top: 10px; }}
        .btn-show-all:hover {{ background: #cbd5e1; }}
    </style></head><body>
    <div id="toast" class="toast"></div>
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
            <div class="kpi-card {'danger-card' if len(incidents) > 0 else ''}">
                <span>Инциденты</span><strong><br>{len(incidents)}</strong>
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
        </div>
        <div id="t1" class="tab-content active-content">
            <table><thead><tr><th>Сайт</th><th>Статус</th><th>Uptime 30д</th>
            <th>Ответ</th><th>SSL</th><th>Цепочка SSL</th><th>Домен</th><th>Тест</th></tr></thead><tbody>
    """)

    current_group = -1
    for s in sorted_sites:
        g = get_site_group(s)
        if g != current_group:
            st = group_stats.get(g, {'online': 0, 'total': 0, 'upt': 0, 'resp': 0})
            g_sub = f'<span class="group-sub">Online: {st["online"]}/{st["total"]} | Uptime: {st["upt"]}% | ⌀ Ответ: {st["resp"]}с</span>'
            H.append(f'<tr><td colspan="8" class="group-header">{group_names[g]}{g_sub}</td></tr>')
            current_group = g
        v = latest.get(s, {'status': 0, 'response_time': 0, 'ssl_days': -1, 'domain_days': -1, 'ssl_chain_valid': None})
        st30 = stats.get(s, {'upt': 0, 'down_sec': 0})
        is_err = (v['status'] != 200 or (0 <= v['ssl_days'] <= 20) or
                  (0 <= v['domain_days'] <= 30) or v.get('ssl_chain_valid') == False)
        prefix = "🛡️ " if s in STDO_SITES else ("⭐ " if s in KEY_SITES else "")

        H.append(f"""<tr class="{'row-err' if is_err else ''}">
            <td>{prefix}<a href="https://{s}" target="_blank"
                style="text-decoration:none; color:inherit;"><strong>{s}</strong></a></td>
            <td><span class="{'txt-ok' if v['status']==200 else 'txt-err'}">
                {'Online' if v['status']==200 else 'Offline'}</span></td>
            <td>{st30['upt']}%</td><td>{round(v['response_time'], 2)}с</td>
            <td class="{'txt-err' if 0<=v['ssl_days']<=20 else ''}">{v['ssl_days']}д</td>
            <td class="{'txt-err' if v.get('ssl_chain_valid') == False else 'txt-ok' if v.get('ssl_chain_valid') == True else ''}">
                {'✅' if v.get('ssl_chain_valid') == True else '❌' if v.get('ssl_chain_valid') == False else '—'}</td>
            <td class="{'txt-err' if 0<=v['domain_days']<=30 else ''}">{v['domain_days']}д</td>
            <td><button class="btn-test" onclick="runTest('{s}', this)">
                <div class="loader"></div><span>📸 Screen</span></button></td></tr>""")

    H.append("""</tbody></table></div>
    <div id="t2" class="tab-content">
    <div id="charts-container" style="display:grid; grid-template-columns:repeat(auto-fit,minmax(400px,1fr)); gap:20px;">
        <div style="text-align:center; padding:40px; color:#999;">Загрузка графиков...</div>
    </div></div>
    <div id="t3" class="tab-content">
    <table><thead><tr><th>Начало</th><th>Сайт</th><th>Длительность</th>
    <th>Код</th><th>Описание</th><th>Цепочка SSL</th></tr></thead><tbody>""")

    for idx, r in enumerate(incidents_list):
        hidden_class = 'incident-hidden' if idx >= 20 else ''
        H.append(f"""<tr class="{hidden_class}"><td>{r['start_time'].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')}</td>
            <td>{r['site']}</td><td class='txt-err'>{r['dur']} мин</td>
            <td>{r['max_status']}</td><td>{r['description']}</td>
            <td class="{'txt-err' if r.get('ssl_chain_valid') == False else 'txt-ok' if r.get('ssl_chain_valid') == True else ''}">
                {'✅' if r.get('ssl_chain_valid') == True else '❌' if r.get('ssl_chain_valid') == False else '—'}</td></tr>""")

    total_incidents = len(incidents_list)
    if total_incidents > 20:
        H.append(f"""</tbody></table>
        <div style="text-align:center;">
            <button id="btn-show-incidents" class="btn-show-all" onclick="toggleIncidents()">
                Показать все ({total_incidents})
            </button>
        </div></div>""")
    else:
        H.append("""</tbody></table></div>""")

    H.append("""<div id="t4" class="tab-content">
    <table><thead><tr><th>Тип события</th><th>Сайт</th><th>Осталось дней</th>
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

    H.append(f"""</tbody></table></div></div><script>
    let chartsLoaded = false;
    let chartsLoading = false;
    let showingAll = false;

    const keySites = {key_sites_json};
    const stdoSites = {stdo_sites_json};
    const externalSites = {external_sites_json};
    const groupStats = {group_stats_json};

    function tab(e, n){{
        var i, x = document.getElementsByClassName('tab-content'),
            b = document.getElementsByClassName('tab-btn');
        for(i = 0; i < x.length; i++) x[i].className = 'tab-content';
        for(i = 0; i < b.length; i++) b[i].className = 'tab-btn';
        document.getElementById(n).className = 'tab-content active-content';
        e.currentTarget.className += ' active';
        if (n === 't2') loadCharts();
    }}

    async function runTest(site, btn) {{
        if (btn.classList.contains('loading')) return;
        btn.classList.add('loading');
        btn.disabled = true;
        try {{
            const response = await fetch('/test-screen/' + site);
            const data = await response.json();
            showToast(data.msg);
        }} catch (e) {{ showToast('Ошибка связи с сервером'); }}
        finally {{ btn.classList.remove('loading'); btn.disabled = false; }}
    }}

    function showToast(msg) {{
        const t = document.getElementById('toast');
        t.innerText = msg;
        t.style.display = 'block';
        setTimeout(() => {{ t.style.display = 'none'; }}, 4000);
    }}

    function renderChartSection(titleKey, titleIdx, sitesList, g_data, container) {{
        const filtered = sitesList.filter(s => g_data[s]);
        if (filtered.length === 0) return;
        const st = groupStats[titleIdx] || {{online:0, total:0, upt:0, resp:0}};
        const h3 = document.createElement('h3');
        h3.style.gridColumn = '1 / -1';
        h3.style.marginTop = '20px';
        h3.style.color = '#475569';
        h3.innerHTML = `${{titleKey}} <span style="float:right;font-weight:normal;font-size:13px;">Online: ${{st.online}}/${{st.total}} | Uptime: ${{st.upt}}% | ⌀ Ответ: ${{st.resp}}с</span>`;
        container.appendChild(h3);
        for (const s of filtered) {{
            const d = g_data[s];
            const div = document.createElement('div');
            div.className = 'kpi-card';
            div.style.borderTop = '2px solid #eee';
            div.innerHTML = `<h5>${{s}}</h5><canvas id="c-${{s.replace(/\\./g, '_')}}"></canvas>`;
            container.appendChild(div);
            new Chart(document.getElementById('c-' + s.replace(/\\./g, '_')), {{
                type: 'line',
                data: {{
                    labels: d.l,
                    datasets: [
                        {{ label: 'Uptime %', data: d.u, borderColor: '#10b981', backgroundColor: '#10b981', yAxisID: 'y', tension: 0.3, pointRadius: 3, pointHoverRadius: 5 }},
                        {{ label: 'Ответ сек', data: d.r, borderColor: '#3b82f6', backgroundColor: '#3b82f6', yAxisID: 'y1', tension: 0.3, pointRadius: 3, pointHoverRadius: 5 }}
                    ]
                }},
                options: {{
                    scales: {{
                        y: {{ suggestedMin: 95, suggestedMax: 100.5, title: {{ display: true, text: 'Uptime %' }} }},
                        y1: {{ position: 'right', grid: {{ display: false }}, title: {{ display: true, text: 'Ответ, сек' }} }}
                    }}
                }}
            }});
        }}
    }}

    async function loadCharts() {{
        if (chartsLoaded || chartsLoading) return;
        chartsLoading = true;
        try {{
            const res = await fetch('/api/charts');
            const g_data = await res.json();
            const container = document.getElementById('charts-container');
            container.innerHTML = '';

            renderChartSection('Ключевые', 0, keySites, g_data, container);
            renderChartSection('СТДО', 1, stdoSites, g_data, container);

            if (showingAll) {{
                renderChartSection('Внешние сайты', 2, externalSites, g_data, container);
            }} else {{
                const btnDiv = document.createElement('div');
                btnDiv.style.textAlign = 'center';
                btnDiv.style.padding = '20px';
                btnDiv.style.gridColumn = '1 / -1';
                const btn = document.createElement('button');
                btn.innerText = 'Показать все внешние сайты';
                btn.className = 'tab-btn';
                btn.style.cursor = 'pointer';
                btn.onclick = () => {{ showingAll = true; chartsLoaded = false; loadCharts(); }};
                btnDiv.appendChild(btn);
                container.appendChild(btnDiv);
            }}

            chartsLoaded = true;
        }} catch (e) {{
            document.getElementById('charts-container').innerHTML =
                '<div style="text-align:center; padding:40px; color:#b91c1c;">Ошибка загрузки графиков</div>';
        }} finally {{
            chartsLoading = false;
        }}
    }}

    function toggleIncidents() {{
        const hidden = document.querySelectorAll('#t3 .incident-hidden');
        const btn = document.getElementById('btn-show-incidents');
        for (const row of hidden) {{
            row.classList.remove('incident-hidden');
        }}
        if (btn) btn.style.display = 'none';
    }}

    setInterval(() => {{ location.reload(); }}, 120000);
    </script></body></html>""")

    return "".join(H)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
