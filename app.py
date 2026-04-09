import datetime
import ssl
import socket
import requests
import psycopg2 
import json
import base64
import pytz
from psycopg2.extras import DictCursor
import threading
import time
import os
import whois
from playwright.sync_api import sync_playwright
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import HTMLResponse

# --- КОНФИГУРАЦИЯ ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siburdb_user:IbaJQKbh6DQ5z9i3J82EWRJFnl1z3gkt@dpg-d797355m5p6s739tgr1g-a/siburdb")
TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "8305761464:AAE--AkY662Cm3DlKsrd8tcBnxXeTOLrO9I")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "-1003747357407")
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
    return psycopg2.connect(DATABASE_URL, sslmode='require')

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
            # Исправленный запуск для Docker
            browser = p.chromium.launch(
                headless=True, 
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-setuid-sandbox"]
            )
            page = browser.new_page()
            page.goto(f"https://{site}", timeout=30000, wait_until="load")
            page.screenshot(path=path)
            browser.close()
        return path
    except Exception as e:
        print(f"DEBUG: Playwright error for {site} -> {e}")
        return None

def get_domain_expiry(site):
    try:
        # WHOIS часто виснет, ограничиваем через socket
        socket.setdefaulttimeout(5)
        w = whois.whois(site)
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if exp:
            return (exp - datetime.datetime.now()).days
        return -1
    except:
        return -1

def check_worker():
    last_status_map = {site: 200 for site in SITES}
    down_time_tracker = {site: None for site in SITES}
    
    while True:
        for site in SITES:
            curr_status, resp_time, ssl_d, dom_d = 0, 25.0, -1, -1
            try:
                # 1. Основная проверка
                try:
                    r = requests.get(f"https://{site}", timeout=20, allow_redirects=True)
                    curr_status, resp_time = r.status_code, time.time()
                except:
                    curr_status = 0

                # 2. SSL
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((site, 443), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=site) as ssock:
                            cert = ssock.getpeercert()
                            exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            ssl_d = (exp - datetime.datetime.utcnow()).days
                except: ssl_d = -1

                # 3. Domain (WHOIS)
                dom_d = get_domain_expiry(site)

                # 4. Алерты
                if curr_status != 200:
                    if down_time_tracker[site] is None:
                        down_time_tracker[site] = datetime.datetime.now()
                    
                    if last_status_map[site] == 200:
                        if site in PRIORITY_SITES:
                            shot = take_screenshot(site)
                            send_tg_msg(f"🚨 КРИТИЧЕСКИЙ СБОЙ: {site} (Код: {curr_status})", shot)
                        else:
                            # Для обычных сайтов просто ждем 5 минут (проверка логикой выше)
                            pass
                    
                    # Если лежит более 5 минут и это не критичный сайт
                    if site not in PRIORITY_SITES:
                        elapsed = (datetime.datetime.now() - down_time_tracker[site]).total_seconds()
                        if 300 <= elapsed < 365: # Оповещаем один раз на 5-й минуте
                            send_tg_msg(f"⚠️ Вторичный ресурс лежит > 5 мин: {site}")

                elif last_status_map[site] != 200:
                    send_tg_msg(f"✅ Восстановлен: {site}")
                    down_time_tracker[site] = None

                last_status_map[site] = curr_status

                # Запись в БД
                conn = get_db_connection(); cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days) VALUES (%s, %s, %s, %s, %s)", 
                           (site, curr_status, 1.0, ssl_d, dom_d))
                conn.commit(); cur.close(); conn.close()

            except Exception as e:
                print(f"DEBUG: Worker error for {site} -> {e}")
        time.sleep(60)

# --- Остальная часть FastAPI (index) остается такой же, как в прошлом сообщении ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Упрощенная авторизация для дебага (можно вернуть Basic Auth позже)
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")

    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2) as up FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'")
    s30 = cur.fetchone() or {'up': 0}
    
    cur.execute("SELECT DISTINCT ON (site) * FROM logs ORDER BY site, timestamp DESC")
    latest = {r['site']: r for r in cur.fetchall()}
    
    # Сбор ошибок
    errs = [f"{s} (Offline)" for s,v in latest.items() if v['status']!=200]
    doms = [f"{s} (Домен: {v['domain_days']}д)" for s,v in latest.items() if 0<=v['domain_days']<=30]
    
    html = f"""
    <html><head><title>Sibur Monitoring</title>
    <style>
        body {{ font-family: sans-serif; background: #f0f2f5; padding: 20px; }}
        .card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .txt-err {{ color: red; font-weight: bold; }}
        .txt-ok {{ color: green; font-weight: bold; }}
        .row-err {{ background: #fff1f2; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; border-bottom: 1px solid #ddd; text-align: left; }}
    </style>
    </head><body>
    <div class="card">
        <h1>📊 Sibur Monitoring</h1>
        <p>Uptime (30д): <strong>{s30['up']}%</strong> | Обновлено: {now_msk}</p>
        {f'<div style="color:red; padding:10px; border:1px solid red; margin:10px 0;">⚠️ {", ".join(errs+doms)}</div>' if (errs+doms) else ''}
        
        <div style="margin-top:20px;">
            <button onclick="location.reload()">🔄 Обновить</button>
        </div>

        <table>
            <thead><tr><th>Сайт</th><th>Статус</th><th>SSL</th><th>Домен</th></tr></thead>
            <tbody>
    """
    for s in sorted(SITES):
        v = latest.get(s, {'status':0, 'ssl_days':-1, 'domain_days':-1})
        is_ok = v['status'] == 200
        html += f"""<tr class="{'row-err' if not is_ok else ''}">
            <td>{'⭐ ' if s in PRIORITY_SITES else ''}<strong>{s}</strong></td>
            <td class="{'txt-ok' if is_ok else 'txt-err'}">{'Online' if is_ok else 'Offline'}</td>
            <td>{v['ssl_days']}д</td>
            <td class="{'txt-err' if 0<=v['domain_days']<=30 else ''}">{v['domain_days']}д</td>
        </tr>"""
        
    html += "</tbody></table></div></body></html>"
    cur.close(); conn.close(); return html

@app.on_event("startup")
def startup():
    # Создаем таблицы если нет
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS logs (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, status INTEGER, response_time REAL, ssl_days INTEGER, domain_days INTEGER)")
        conn.commit(); cur.close(); conn.close()
    except: pass
    threading.Thread(target=check_worker, daemon=True).start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
