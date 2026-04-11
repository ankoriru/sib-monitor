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
from psycopg2.extras import DictCursor
from playwright.sync_api import sync_playwright
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse

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

def check_auth(request: Request):
    auth = request.headers.get("Authorization")
    if not auth: raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic realm='Sibur Monitoring'"})
    try:
        scheme, credentials = auth.split()
        decoded = base64.b64decode(credentials).decode("ascii")
        u, p = decoded.split(":")
        if u == "sibur" and p == "sibur": return True
    except: pass
    raise HTTPException(status_code=401)

def get_db_connection(): return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS logs 
                  (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                   status INTEGER, response_time REAL, ssl_days INTEGER, domain_days INTEGER)''')
    conn.commit(); cur.close(); conn.close()

def send_tg_msg(text, photo_path=None):
    base_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/"
    try:
        if photo_path and os.path.exists(photo_path):
            with open(photo_path, 'rb') as f:
                requests.post(base_url + "sendPhoto", data={"chat_id": TELEGRAM_CHAT_ID, "caption": text}, files={"photo": f}, timeout=30)
            if os.path.exists(photo_path): os.remove(photo_path)
        else:
            requests.post(base_url + "sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
    except: pass

def take_screenshot(site):
    path = f"debug_{int(time.time())}.png"
    try:
        with sync_playwright() as p:
            # Исправлено: добавлены флаги для контейнеров
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
            page = browser.new_page()
            # Увеличен таймаут до 60 секунд
            page.goto(f"https://{site}", timeout=60000, wait_until="load")
            time.sleep(2) # Даем время на рендер JS
            page.screenshot(path=path)
            browser.close()
        return path
    except Exception as e:
        print(f"Playwright error for {site}: {e}")
        return None

def get_domain_info(site):
    try:
        w = whois.whois(site)
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if exp: return (exp.replace(tzinfo=None) - datetime.datetime.now()).days
    except: pass
    return -1

def check_worker():
    last_status = {site: 200 for site in SITES}
    fail_count = {site: 0 for site in SITES}
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
    
    while True:
        for site in SITES:
            try:
                curr_status, resp_time, start = 0, 25.0, time.time()
                try:
                    r = requests.get(f"https://{site}", timeout=25, headers=headers, allow_redirects=True)
                    curr_status, resp_time = r.status_code, time.time() - start
                except: curr_status, resp_time = 0, 25.0

                ssl_d = -1
                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((site, 443), timeout=3) as sock:
                        with ctx.wrap_socket(sock, server_hostname=site) as ssock:
                            cert = ssock.getpeercert()
                            exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            ssl_d = (exp - datetime.datetime.utcnow()).days
                except: pass
                
                dom_d = get_domain_info(site)

                if curr_status != 200:
                    fail_count[site] += 1
                    alert_limit = 5 if site in PRIORITY_SITES else 10
                    
                    if fail_count[site] >= 2:
                        conn = get_db_connection(); cur = conn.cursor()
                        if fail_count[site] == 2:
                            prev_ts = datetime.datetime.now() - datetime.timedelta(minutes=1)
                            cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days, timestamp) VALUES (%s,%s,%s,%s,%s,%s)", (site, curr_status, resp_time, ssl_d, dom_d, prev_ts))
                        cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days) VALUES (%s,%s,%s,%s,%s)", (site, curr_status, resp_time, ssl_d, dom_d))
                        conn.commit(); cur.close(); conn.close()

                    if fail_count[site] == alert_limit and last_status[site] == 200:
                        shot = take_screenshot(site)
                        desc = 'Timeout' if curr_status == 0 else ('Bad Gateway' if curr_status == 502 else 'Error')
                        send_tg_msg(f"🚨 DOWN: {site} (Код: {curr_status}, {desc})", shot)
                        last_status[site] = curr_status
                else:
                    conn = get_db_connection(); cur = conn.cursor()
                    cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days) VALUES (%s,%s,%s,%s,%s)", (site, curr_status, resp_time, ssl_d, dom_d))
                    conn.commit(); cur.close(); conn.close()

                    if last_status[site] != 200:
                        send_tg_msg(f"✅ UP: {site} (Был недоступен: {fail_count[site]} мин.)")
                    
                    last_status[site], fail_count[site] = 200, 0
            except: pass
        time.sleep(60)

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

# --- НОВЫЙ РОУТ ДЛЯ ТЕСТА СКРИНШОТОВ ---
@app.get("/test-screen/{site_name}")
async def test_screen(site_name: str, auth: bool = Depends(check_auth)):
    if site_name not in SITES: raise HTTPException(status_code=404)
    shot = take_screenshot(site_name)
    if shot:
        send_tg_msg(f"🧪 Тестовый скриншот: {site_name}", shot)
        return HTMLResponse(f"Успешно! Скриншот {site_name} отправлен в ТГ. <br><a href='/'>Назад</a>")
    return HTMLResponse(f"Ошибка при создании скриншота {site_name}. Проверьте логи сервера. <br><a href='/'>Назад</a>")

@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")

    cur.execute("SELECT DISTINCT ON (site) * FROM logs ORDER BY site, timestamp DESC")
    latest = {r['site']: r for r in cur.fetchall()}
    
    cur.execute("SELECT site, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as upt, COUNT(*) FILTER (WHERE status!=200)*60 as down_sec FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY site")
    stats = {r['site']: r for r in cur.fetchall()}

    html = f"""
    <html><head><meta charset="UTF-8"><title>Мониторинг</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; }}
        .container {{ max-width: 1400px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
        .btn-test {{ background: #00717a; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 11px; }}
        .txt-err {{ color: #dc2626; font-weight: bold; }} .txt-ok {{ color: #16a34a; font-weight: bold; }}
    </style></head><body><div class="container">
        <h1>📊 Мониторинг ({now_msk})</h1>
        <table><thead><tr><th>Сайт</th><th>Статус</th><th>Uptime</th><th>Ответ</th><th>SSL</th><th>Тест</th></tr></thead><tbody>
    """
    sorted_sites = sorted(SITES, key=lambda x: (x != "sibur.ru", x not in PRIORITY_SITES, x))
    for s in sorted_sites:
        v = latest.get(s, {'status':0,'response_time':0,'ssl_days':-1})
        st = stats.get(s, {'upt':0})
        html += f"""<tr>
            <td><strong>{s}</strong></td>
            <td><span class="{'txt-ok' if v['status']==200 else 'txt-err'}">{'Online' if v['status']==200 else 'Offline'}</span></td>
            <td>{st['upt']}%</td><td>{round(v['response_time'],2)}с</td>
            <td>{v['ssl_days']}д</td>
            <td><a href="/test-screen/{s}" class="btn-test">📸 Screen</a></td></tr>"""

    html += "</tbody></table>"
    
    # Секция Инцидентов
    html += "<h2>Последние инциденты</h2><table><thead><tr><th>Начало</th><th>Сайт</th><th>Длительность</th><th>Код</th></tr></thead><tbody>"
    cur.execute("""
        WITH status_changes AS (
            SELECT site, timestamp, status,
            CASE WHEN status != 200 AND (LAG(status) OVER (PARTITION BY site ORDER BY timestamp) = 200 OR LAG(status) OVER (PARTITION BY site ORDER BY timestamp) IS NULL) THEN 1 ELSE 0 END as is_start
            FROM logs
        ),
        incident_groups AS (
            SELECT site, timestamp, status, SUM(is_start) OVER (PARTITION BY site ORDER BY timestamp) as grp_id
            FROM status_changes WHERE status != 200
        )
        SELECT site, MIN(timestamp) as start_time, COUNT(*)*1 as dur, MAX(status)
        FROM incident_groups GROUP BY site, grp_id ORDER BY start_time DESC LIMIT 10
    """)
    for r in cur.fetchall():
        html += f"<tr><td>{r[1].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')}</td><td>{r[0]}</td><td class='txt-err'>{r[2]} мин</td><td>{r[3]}</td></tr>"
    
    cur.close(); conn.close(); return html + "</tbody></table></div></body></html>"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
