import datetime
import ssl
import socket
import requests
import psycopg2 
import json
import os
import threading
import time
import whois
import pytz
from psycopg2.extras import DictCursor
from playwright.sync_api import sync_playwright
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

# --- КОНФИГУРАЦИЯ ---
DATABASE_URL = os.getenv("DATABASE_URL")
TELEGRAM_TOKEN = os.getenv("TG_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID")
TZ_MOSCOW = pytz.timezone('Europe/Moscow')

SITES = [
    "sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru", 
    "alphapor.ru", "amur-gcc.ru", "ar24.sibur.ru",
    "bopp.sibur.ru", "carbo.sibur.ru", "carbonfootprintcalculator.sibur.ru",
    "career.sibur.ru", "catalog.sibur.ru", "coach.sibur.ru",
    "ecoball.sibur.ru", "greencity-sibur.ru", "guide.sibur.ru",
    "laika.sibur.ru", "magazine.sibur.ru", "mendeleev-smena.ru",
    "messages2.sibur.ru", "nauka.sibur.ru", "oknavdome.info",
    "photo.sibur.ru", "polylabsearch.ru", "portenergo.com",
    "quality-certificates.sibur.ru", "rusvinyl.ru",
    "sibur.digital", "sibur-int.com", "sibur-int.ru", "sibur-yug.ru",
    "sintez-kazan.ru", "snck.ru", "tu-sibur.ru", "vivilen.sibur.ru"
]

PRIORITY_SITES = ["sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru", "career.sibur.ru"]

app = FastAPI()

def get_db_connection():
    # На Render/Amvera часто требуется sslmode='require' для внешних баз, 
    # но для внутренних в Amvera можно пробовать без него, если будут ошибки.
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """Автоматическое создание таблицы и колонок при старте"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Базовая таблица
        cur.execute('''CREATE TABLE IF NOT EXISTS logs 
                      (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                       status INTEGER, response_time REAL)''')
        conn.commit()
        
        # Добавление новых колонок по одной (если их нет)
        cols = [("ssl_days", "INTEGER DEFAULT -1"), ("domain_days", "INTEGER DEFAULT -1")]
        for col_name, col_type in cols:
            try:
                cur.execute(f"ALTER TABLE logs ADD COLUMN {col_name} {col_type};")
                conn.commit()
            except:
                conn.rollback()
        
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_site_ts ON logs (site, timestamp DESC)")
        conn.commit()
        cur.close()
        conn.close()
        print("✅ База данных успешно инициализирована")
    except Exception as e:
        print(f"❌ Ошибка инициализации БД: {e}")

def send_tg_msg(text, photo_path=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/"
    try:
        if photo_path and os.path.exists(photo_path):
            with open(photo_path, 'rb') as photo:
                requests.post(url + "sendPhoto", data={"chat_id": TELEGRAM_CHAT_ID, "caption": text}, files={"photo": photo}, timeout=20)
            os.remove(photo_path)
        else:
            requests.post(url + "sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
    except Exception as e:
        print(f"DEBUG: TG Error -> {e}")

def take_screenshot(site):
    path = f"screenshot_{site.replace('.','_')}.png"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = browser.new_page()
            page.goto(f"https://{site}", timeout=30000, wait_until="load")
            page.screenshot(path=path)
            browser.close()
        return path
    except Exception as e:
        print(f"DEBUG: Screenshot error for {site} -> {e}")
        return None

def get_domain_days(site):
    try:
        socket.setdefaulttimeout(5)
        w = whois.whois(site)
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if exp:
            delta = exp - datetime.datetime.now()
            return delta.days
        return -1
    except:
        return -1

def check_worker():
    """Фоновый поток мониторинга"""
    last_status = {site: 200 for site in SITES}
    
    while True:
        for site in SITES:
            try:
                # 1. Проверка доступности
                status_code = 0
                try:
                    r = requests.get(f"https://{site}", timeout=15)
                    status_code = r.status_code
                except:
                    status_code = 0

                # 2. SSL
                ssl_d = -1
                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((site, 443), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=site) as ssock:
                            cert = ssock.getpeercert()
                            exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            ssl_d = (exp - datetime.datetime.utcnow()).days
                except: pass

                # 3. Домен
                dom_d = get_domain_days(site)

                # 4. Логика уведомлений
                if status_code != 200 and last_status[site] == 200:
                    shot = take_screenshot(site) if site in PRIORITY_SITES else None
                    send_tg_msg(f"🚨 СБОЙ: {site} (Status: {status_code})", shot)
                elif status_code == 200 and last_status[site] != 200:
                    send_tg_msg(f"✅ ВОССТАНОВЛЕН: {site}")

                last_status[site] = status_code

                # 5. Запись в БД
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days) VALUES (%s, %s, %s, %s, %s)", 
                           (site, status_code, 1.0, ssl_d, dom_d))
                conn.commit()
                cur.close()
                conn.close()

            except Exception as e:
                print(f"Worker error for {site}: {e}")
        
        time.sleep(300) # Проверка каждые 5 минут

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
    # Общий аптайм
    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2) as up FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'")
    uptime = cur.fetchone()['up'] or 0
    
    # Последние статусы
    cur.execute("SELECT DISTINCT ON (site) * FROM logs ORDER BY site, timestamp DESC")
    rows = cur.fetchall()
    
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")
    
    html = f"""
    <html><head><meta charset="UTF-8"><title>Sibur Monitor</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; background: #f4f7f9; padding: 20px; color: #333; }}
        .container {{ max-width: 900px; margin: auto; background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }}
        h1 {{ color: #00717a; border-bottom: 2px solid #00717a; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        .status-ok {{ color: #28a745; font-weight: bold; }}
        .status-err {{ color: #dc3545; font-weight: bold; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; background: #eee; }}
    </style>
    </head><body>
    <div class="container">
        <h1>📊 Sibur Monitoring</h1>
        <p>Общий аптайм (30д): <strong>{uptime}%</strong></p>
        <p>Последнее обновление: {now_msk}</p>
        <table>
            <thead><tr><th>Сайт</th><th>Статус</th><th>SSL</th><th>Домен</th></tr></thead>
            <tbody>
    """
    for r in sorted(rows, key=lambda x: x['site']):
        st_class = "status-ok" if r['status'] == 200 else "status-err"
        st_text = "Online" if r['status'] == 200 else f"Error ({r['status']})"
        html += f"""
            <tr>
                <td>{'⭐ ' if r['site'] in PRIORITY_SITES else ''}<strong>{r['site']}</strong></td>
                <td class="{st_class}">{st_text}</td>
                <td><span class="badge">{r['ssl_days']} дн.</span></td>
                <td><span class="badge">{r['domain_days']} дн.</span></td>
            </tr>
        """
    html += "</tbody></table></div></body></html>"
    cur.close(); conn.close()
    return html

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
