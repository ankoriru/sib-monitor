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
# Внутренние /cp/ сайты — self-signed по умолчанию
# Дополнительные через env SELF_SIGNED_SITES (через запятую)
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
_screenshot_queue = queue.Queue()  # (site, result_future)
_screenshot_thread = None
_screenshot_thread_lock = threading.Lock()


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
    """Event loop воркера: держит браузер открытым и обрабатывает очередь.
    При ошибке одного скриншота — продолжает работу (не падает)."""
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
                pass  # Future мог уже быть отменён


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

        # Проверка через BCrypt (константное время сравнения)
        if u == AUTH_USERNAME and AUTH_PASSWORD_HASH:
            if bcrypt.checkpw(p.encode('utf-8'), AUTH_PASSWORD_HASH.encode('utf-8')):
                # SEC-3: secure=True + samesite для cookie
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
                                        last_ssl_days, last_domain_days)
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
                    MAX(domain_days) FILTER (WHERE domain_days IS NOT NULL)
                FROM logs
                WHERE timestamp > NOW() - INTERVAL '30 days'
                GROUP BY site,
                    date_trunc('hour', timestamp)
                        + INTERVAL '5 min' * (EXTRACT(MINUTE FROM timestamp)::int / 5)
                ON CONFLICT (site, bucket) DO NOTHING
            """)
            conn.commit()
            print(f"Backfill завершён: {cur.rowcount} записей")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Ошибка backfill checks_agg: {e}")


def init_db():
    """Инициализация БД с поддержкой партиционирования (Этап 1)"""
    conn = get_db_connection()
    cur = conn.cursor()

    # Проверяем, существует ли уже партиционированная таблица logs
    cur.execute("""
        SELECT EXISTS (
            SELECT FROM pg_tables
            WHERE tablename = 'logs'
            AND schemaname = 'public'
        )
    """)
    logs_exists = cur.fetchone()[0]

    def _safe_index(index_name, table_name, columns):
        """Создаёт индекс, если его ещё нет; игнорирует DuplicateTable/DuplicateObject"""
        try:
            cur.execute(f"""
                CREATE INDEX IF NOT EXISTS {index_name}
                ON {table_name} ({columns})
            """)
        except psycopg2.Error:
            conn.rollback()

    if not logs_exists:
        # Создаём партиционированную таблицу (Этап 1)
        cur.execute("""
            CREATE TABLE logs (
                site TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status INTEGER,
                response_time REAL,
                ssl_days INTEGER,
                domain_days INTEGER
            ) PARTITION BY RANGE (timestamp)
        """)

        # Создаём партиции за текущий и следующий месяц
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

        _safe_index("idx_logs_site_ts", "logs", "site, timestamp DESC")
    else:
        # Проверяем, что таблица партиционирована
        cur.execute("""
            SELECT pg_get_partkeydef(c.oid)
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = 'logs' AND n.nspname = 'public'
        """)
        result = cur.fetchone()
        if result and result[0] is None:
            # Таблица существует но не партиционирована - мигрируем
            print("Миграция: переименование старой таблицы в logs_old")
            cur.execute("ALTER TABLE logs RENAME TO logs_old")
            cur.execute("""
                CREATE TABLE logs (
                    site TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    status INTEGER,
                    response_time REAL,
                    ssl_days INTEGER,
                    domain_days INTEGER
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
            _safe_index("idx_logs_site_ts", "logs", "site, timestamp DESC")

    # Таблица агрегатов (Этап 1)
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
            PRIMARY KEY (site, bucket)
        )
    """)
    _safe_index("idx_checks_agg_bucket", "checks_agg", "bucket DESC")

    # Материализованное представление (Этап 3)
    cur.execute("""
        CREATE MATERIALIZED VIEW IF NOT EXISTS latest_status AS
        SELECT DISTINCT ON (site)
            site, status, response_time, ssl_days, domain_days, timestamp
        FROM logs
        ORDER BY site, timestamp DESC
    """)
    # Уникальный индекс обязателен для REFRESH CONCURRENTLY
    try:
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_latest_status_site ON latest_status (site)")
    except psycopg2.Error:
        conn.rollback()

    conn.commit()
    cur.close()
    conn.close()


def ensure_partitions():
    """Автоматическое создание партиций на следующий месяц (Этап 1)"""
    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.datetime.now()
    for offset in range(3):  # Текущий + 2 месяца вперёд
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
    base_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/"
    try:
        if photo_path and os.path.exists(photo_path):
            with open(photo_path, 'rb') as f:
                requests.post(
                    base_url + "sendPhoto",
                    data={"chat_id": TELEGRAM_CHAT_ID, "caption": text},
                    files={"photo": f},
                    timeout=30
                )
            if os.path.exists(photo_path):
                os.remove(photo_path)
        else:
            requests.post(
                base_url + "sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": text},
                timeout=10
            )
    except Exception:
        pass


# ============================================================================
# WHOIS
# ============================================================================
def get_domain_info(site):
    try:
        domain_only = site.split('/')[0]
        w = whois.whois(domain_only)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if exp:
            return (exp.replace(tzinfo=None) - datetime.datetime.now()).days
    except Exception:
        pass
    return -1


# ============================================================================
# АСИНХРОННЫЕ ПРОВЕРКИ САЙТОВ (Этап 2.2)
# ============================================================================
async def check_single_site(session, site, semaphore):
    """Проверка одного сайта через aiohttp с семафором"""
    async with semaphore:
        check_url = f"https://{site}"
        domain_only = site.split('/')[0]
        curr_status, resp_time, ssl_d, dom_d = 0, 25.0, -1, -1

        # SEC-1: verify=False только для сайтов из whitelist
        ssl_verify = not should_verify(site)
        connector = aiohttp.TCPConnector(ssl=False) if ssl_verify else None

        start = time.time()
        actual_session = None
        try:
            if ssl_verify and connector:
                actual_session = aiohttp.ClientSession(connector=connector)
            else:
                actual_session = session

            timeout = aiohttp.ClientTimeout(total=25)
            async with actual_session.get(check_url, timeout=timeout, allow_redirects=True) as resp:
                curr_status = resp.status
                resp_time = time.time() - start

        except Exception as e:
            print(f"[CHECK ERR] {site}: {type(e).__name__}: {e}")
            curr_status, resp_time = 0, 25.0
        finally:
            # Закрываем только собственную сессию (не общую из check_all_sites)
            if ssl_verify and connector and actual_session is not None:
                await actual_session.close()

        # Проверка SSL (синхронно в отдельном потоке)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain_only, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain_only) as ssock:
                    cert = ssock.getpeercert()
                    exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    ssl_d = (exp - datetime.datetime.utcnow()).days
        except Exception:
            pass

        # WHOIS
        dom_d = get_domain_info(domain_only)

        return (site, curr_status, resp_time, ssl_d, dom_d)


async def check_all_sites():
    """Параллельная проверка всех сайтов через asyncio.gather"""
    semaphore = asyncio.Semaphore(10)  # Не более 10 параллельных проверок
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
        'r_min': float('inf'), 'r_max': 0.0, 'ssl': None, 'dom': None
    })
    for row in batch_data:
        site, status, resp, ssl_d, dom_d = row[:5]
        # bucket = округление до 5 минут
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
    for (site, bucket), a in agg.items():
        cur.execute("""
            INSERT INTO checks_agg (site, bucket, checks_count, status_200_count,
                                    avg_response_time, min_response_time, max_response_time,
                                    last_ssl_days, last_domain_days)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (site, bucket) DO UPDATE SET
                checks_count = checks_agg.checks_count + EXCLUDED.checks_count,
                status_200_count = checks_agg.status_200_count + EXCLUDED.status_200_count,
                avg_response_time = (checks_agg.avg_response_time * checks_agg.checks_count
                                     + EXCLUDED.avg_response_time * EXCLUDED.checks_count)
                                    / (checks_agg.checks_count + EXCLUDED.checks_count),
                min_response_time = LEAST(checks_agg.min_response_time, EXCLUDED.min_response_time),
                max_response_time = GREATEST(checks_agg.max_response_time, EXCLUDED.max_response_time),
                last_ssl_days = COALESCE(EXCLUDED.last_ssl_days, checks_agg.last_ssl_days),
                last_domain_days = COALESCE(EXCLUDED.last_domain_days, checks_agg.last_domain_days)
        """, (site, bucket, a['cnt'], a['ok'],
              a['r_sum'] / a['cnt'], a['r_min'], a['r_max'], a['ssl'], a['dom']))


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
                   (site, status, response_time, ssl_days, domain_days)
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

        # 1. Агрегируем данные перед удалением
        cur.execute("""
            INSERT INTO checks_agg (site, bucket, checks_count, status_200_count,
                                   avg_response_time, min_response_time, max_response_time,
                                   last_ssl_days, last_domain_days)
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
                MAX(domain_days) FILTER (WHERE domain_days IS NOT NULL)
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
                max_response_time = GREATEST(checks_agg.max_response_time, EXCLUDED.max_response_time)
        """, (cutoff_date, cutoff_date))

        # 2. Удаляем старые партиции
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
def check_worker():
    """Фоновый воркер проверки сайтов с batch-вставкой и ротацией"""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    last_status = {site: 200 for site in SITES}
    fail_count = {site: 0 for site in SITES}
    last_latency_map = {site: False for site in SITES}

    while True:
        try:
            # Параллельная проверка всех сайтов (Этап 2.2)
            results = asyncio.run(check_all_sites())

            for site, curr_status, resp_time, ssl_d, dom_d in results:
                try:
                    # --- ЛОГИКА АЛЕРТОВ И ЗАПИСИ ---
                    if curr_status != 200:
                        fail_count[site] += 1
                        alert_threshold = 5 if site in PRIORITY_SITES else 10

                        with BATCH_LOCK:
                            if fail_count[site] >= 2:
                                batch_buffer.append(
                                    (site, curr_status, resp_time, ssl_d, dom_d)
                                )

                            if len(batch_buffer) >= BATCH_SIZE:
                                flush_batch()

                        if fail_count[site] == alert_threshold and last_status[site] == 200:
                            shot_path = take_screenshot_fast(site)
                            msg = f"🚨 DOWN: {site} (Код: {curr_status})"
                            send_tg_msg(msg, shot_path)
                            last_status[site] = curr_status
                    else:
                        with BATCH_LOCK:
                            batch_buffer.append((site, curr_status, resp_time, ssl_d, dom_d))
                            if len(batch_buffer) >= BATCH_SIZE:
                                flush_batch()

                        if last_status[site] != 200:
                            duration = fail_count[site]
                            send_tg_msg(f"✅ UP: {site} (Был недоступен: {duration} мин.)")

                        last_status[site], fail_count[site] = 200, 0

                        if resp_time > 20 and not last_latency_map[site]:
                            send_tg_msg(f"🐢 ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек.")
                            last_latency_map[site] = True
                        elif resp_time < 10 and last_latency_map[site]:
                            send_tg_msg(
                                f"⚡️ СКОРОСТЬ ВОССТАНОВЛЕНА! {site}: {round(resp_time, 2)} сек."
                            )
                            last_latency_map[site] = False
                except Exception as e:
                    print(f"Ошибка обработки результата для {site}: {e}")

            # Финальный flush оставшихся данных
            flush_batch()

            # Обновление мат. представления (Этап 3)
            refresh_materialized_view()

        except Exception as e:
            print(f"Ошибка воркера: {e}")

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
                # Используем материализованное представление (Этап 3)
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
    init_db()
    threading.Thread(target=backfill_checks_agg, daemon=True).start()
    threading.Thread(target=check_worker, daemon=True).start()
    threading.Thread(target=daily_report_worker, daemon=True).start()
    threading.Thread(target=rotation_worker, daemon=True).start()


# ============================================================================
# ENDPOINTS
# ============================================================================
@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    file_path = 'favicon.ico'
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return Response(status_code=204)


@app.get("/test-screen/{site_name:path}")
async def test_screen(site_name: str, auth: bool = Depends(check_auth)):
    if site_name not in SITES:
        return JSONResponse(
            {"status": "error", "msg": "Сайт не найден в списке"},
            status_code=404
        )

    shot = await asyncio.to_thread(take_screenshot_fast, site_name)
    if shot:
        send_tg_msg(f"🧪 Тестовый скриншот: {site_name}", shot)
        return {"status": "success", "msg": f"Скриншот {site_name} отправлен в ТГ"}

    return JSONResponse(
        {"status": "error", "msg": "Ошибка Playwright (таймаут или доступ)"},
        status_code=500
    )


def _get_stats_from_agg(cur, interval: str):
    """Статистика из checks_agg; fallback на logs если агрегаты пусты"""
    cur.execute("""
        SELECT
            ROUND(SUM(status_200_count) * 100.0
                  / NULLIF(SUM(checks_count), 0)::numeric, 2) as up,
            ROUND(AVG(avg_response_time)::numeric, 3) as resp
        FROM checks_agg WHERE bucket > NOW() - INTERVAL %s
    """, (interval,))
    row = cur.fetchone()
    if row and row[0] is not None:
        return {'up': row[0], 'resp': row[1]}
    # Fallback на logs
    cur.execute("""
        SELECT
            ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0
                   / NULLIF(COUNT(*), 0))::numeric, 2) as up,
            ROUND(AVG(response_time)::numeric, 3) as resp
        FROM logs WHERE timestamp > NOW() - INTERVAL %s
    """, (interval,))
    row = cur.fetchone()
    return {'up': row[0] or 0, 'resp': row[1] or 0}


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
               ROUND(AVG(avg_response_time)::numeric, 2) as r,
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

    # Инциденты — CTE с ограничением 3 днями (быстро, не грузит память)
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
                 ELSE 'Server Error' END as description
        FROM incident_groups
        GROUP BY site, grp_id ORDER BY start_time DESC LIMIT 20
    """)
    incidents_list = [dict(r) for r in cur.fetchall()]

    cur.close()
    conn.close()

    # Сохраняем dict в кэш (не HTML-строку — экономия ~2 MB RAM)
    data = {
        "s30": s30, "s24": s24,
        "latest": latest, "stats": stats,
        "incidents": incidents_list,
        "now_msk": datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")
    }
    with _dashboard_cache["lock"]:
        _dashboard_cache["data"] = data
        _dashboard_cache["timestamp"] = time.time()
    return _build_html(data)


def _build_html(data: dict) -> str:
    """Сборка HTML из кэшированного dict (без SQL, <10 мс)"""
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

    html = f"""
    <html><head><meta charset="UTF-8"><title>Мониторинг сайтов</title>
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
            <th>Ответ</th><th>SSL</th><th>Домен</th><th>Тест</th></tr></thead><tbody>
    """

    def get_site_weight(site_name):
        if site_name == "sibur.ru":
            return 0
        if site_name in NEW_MONITORING_SITES:
            return 2
        if site_name in PRIORITY_SITES:
            return 1
        return 3

    sorted_sites = sorted(SITES, key=lambda x: (get_site_weight(x), x))
    sorted_sites_json = json.dumps(sorted_sites)
    for s in sorted_sites:
        v = latest.get(s, {'status': 0, 'response_time': 0, 'ssl_days': -1, 'domain_days': -1})
        st30 = stats.get(s, {'upt': 0, 'down_sec': 0})
        is_err = v['status'] != 200 or (0 <= v['ssl_days'] <= 20) or (0 <= v['domain_days'] <= 30)
        prefix = "🔰 " if s in NEW_MONITORING_SITES else ("⭐️ " if s in PRIORITY_SITES else "")

        html += f"""<tr class="{'row-err' if is_err else ''}">
            <td>{prefix}<a href="https://{s}" target="_blank"
                style="text-decoration:none; color:inherit;"><strong>{s}</strong></a></td>
            <td><span class="{'txt-ok' if v['status']==200 else 'txt-err'}">
                {'Online' if v['status']==200 else 'Offline'}</span></td>
            <td>{st30['upt']}%</td><td>{round(v['response_time'], 2)}с</td>
            <td class="{'txt-err' if 0<=v['ssl_days']<=20 else ''}">{v['ssl_days']}д</td>
            <td class="{'txt-err' if 0<=v['domain_days']<=30 else ''}">{v['domain_days']}д</td>
            <td><button class="btn-test" onclick="runTest('{s}', this)">
                <div class="loader"></div><span>📸 Screen</span></button></td></tr>"""

    html += """</tbody></table></div>
    <div id="t2" class="tab-content">
    <div id="charts-container" style="display:grid; grid-template-columns:repeat(auto-fit,minmax(400px,1fr)); gap:20px;">
        <div style="text-align:center; padding:40px; color:#999;">Загрузка графиков...</div>
    </div></div>
    <div id="t3" class="tab-content">
    <table><thead><tr><th>Начало</th><th>Сайт</th><th>Длительность</th>
    <th>Код</th><th>Описание</th></tr></thead><tbody>"""

    for r in incidents_list:
        html += f"""<tr><td>{r['start_time'].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')}</td>
            <td>{r['site']}</td><td class='txt-err'>{r['dur']} мин</td>
            <td>{r['max_status']}</td><td>{r['description']}</td></tr>"""

    html += """</tbody></table></div>
    <div id="t4" class="tab-content">
    <table><thead><tr><th>Тип события</th><th>Сайт</th><th>Осталось дней</th>
    </tr></thead><tbody>"""

    cal_events = []
    for s in SITES:
        v = latest.get(s, {})
        if v.get('ssl_days', -1) >= 0:
            cal_events.append({'t': 'SSL сертификат', 's': s, 'd': v['ssl_days']})
        if v.get('domain_days', -1) >= 0:
            cal_events.append({'t': 'Оплата домена', 's': s, 'd': v['domain_days']})
    for ev in sorted(cal_events, key=lambda x: x['d']):
        html += f"""<tr><td>{ev['t']}</td><td>{ev['s']}</td>
            <td class="{'txt-err' if ev['d']<=30 else ''}">{ev['d']} дн.</td></tr>"""

    html += f"""</tbody></table></div></div><script>
    let chartsLoaded = false;
    let chartsLoading = false;

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

    async function loadCharts() {{
        if (chartsLoaded || chartsLoading) return;
        chartsLoading = true;
        try {{
            const res = await fetch('/api/charts');
            const g_data = await res.json();
            const container = document.getElementById('charts-container');
            container.innerHTML = '';
            const sites = {sorted_sites_json}.filter(s => g_data[s]);
            for (const s of sites) {{
                const d = g_data[s];
                const div = document.createElement('div');
                div.className = 'kpi-card';
                div.style.borderTop = '2px solid #eee';
                div.innerHTML = `<h5>${{s}}</h5><canvas id="c-${{s.replace(/\./g, '_')}}"></canvas>`;
                container.appendChild(div);
                new Chart(document.getElementById('c-' + s.replace(/\./g, '_')), {{
                    type: 'line',
                    data: {{
                        labels: d.l,
                        datasets: [
                            {{ label: 'Uptime %', data: d.u, borderColor: '#10b981', yAxisID: 'y', tension: 0.3 }},
                            {{ label: 'Ответ сек', data: d.r, borderColor: '#3b82f6', yAxisID: 'y1', tension: 0.3 }}
                        ]
                    }},
                    options: {{
                        scales: {{
                            y: {{ min: 75, max: 110 }},
                            y1: {{ position: 'right', grid: {{ display: false }} }}
                        }}
                    }}
                }});
            }}
            chartsLoaded = true;
        }} catch (e) {{
            document.getElementById('charts-container').innerHTML =
                '<div style="text-align:center; padding:40px; color:#b91c1c;">Ошибка загрузки графиков</div>';
        }} finally {{
            chartsLoading = false;
        }}
    }}

    setInterval(() => {{ location.reload(); }}, 120000);
    </script></body></html>"""
    return html


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
