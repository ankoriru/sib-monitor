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
from psycopg2.extras import DictCursor
from playwright.async_api import async_playwright
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

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

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

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
    try: cur.execute("ALTER TABLE logs ADD COLUMN domain_days INTEGER DEFAULT -1")
    except: conn.rollback()
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_site_ts ON logs (site, timestamp DESC)")
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

async def take_screenshot(site):
    path = f"debug_{int(time.time())}.jpg"
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True, 
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-setuid-sandbox", "--no-zygote"]
            )
            context = await browser.new_context(viewport={'width': 1280, 'height': 720}, ignore_https_errors=True)
            page = await context.new_page()
            try:
                await page.goto(f"https://{site}", timeout=25000, wait_until="domcontentloaded")
            except: pass
            
            await asyncio.sleep(2) # Быстрая пауза 2 сек после начала загрузки
            await page.screenshot(path=path, type="jpeg", quality=80)
            await browser.close()
        return path
    except: return None

def get_domain_info(site):
    try:
        w = whois.whois(site)
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if exp: return (exp.replace(tzinfo=None) - datetime.datetime.now()).days
    except: pass
    return -1

# --- ТВОЙ ОРИГИНАЛЬНЫЙ ВОРКЕР (БЕЗ УПРОЩЕНИЙ) ---

def check_worker():
    last_status = {site: 200 for site in SITES}
    fail_count = {site: 0 for site in SITES}
    last_latency_map = {site: False for site in SITES}
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    
    while True:
        for site in SITES:
            try:
                curr_status, resp_time, ssl_d, dom_d = 0, 25.0, -1, -1
                start = time.time()
                try:
                    r = requests.get(f"https://{site}", timeout=25, headers=headers, allow_redirects=True)
                    curr_status, resp_time = r.status_code, time.time() - start
                except: curr_status, resp_time = 0, 25.0

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
                    alert_threshold = 5 if site in PRIORITY_SITES else 10
                    
                    if fail_count[site] >= 2:
                        conn = get_db_connection(); cur = conn.cursor()
                        if fail_count[site] == 2:
                            prev_ts = datetime.datetime.now() - datetime.timedelta(minutes=1)
                            cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days, timestamp) VALUES (%s,%s,%s,%s,%s,%s)", (site, curr_status, resp_time, ssl_d, dom_d, prev_ts))
                        cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days) VALUES (%s,%s,%s,%s,%s)", (site, curr_status, resp_time, ssl_d, dom_d))
                        conn.commit(); cur.close(); conn.close()

                    if fail_count[site] == alert_threshold and last_status[site] == 200:
                        shot_path = asyncio.run(take_screenshot(site))
                        desc = 'Timeout' if curr_status == 0 else ('Error ' + str(curr_status))
                        send_tg_msg(f"🚨 DOWN: {site} ({desc})", shot_path)
                        last_status[site] = curr_status
                else:
                    conn = get_db_connection(); cur = conn.cursor()
                    cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days) VALUES (%s,%s,%s,%s,%s)", (site, curr_status, resp_time, ssl_d, dom_d))
                    conn.commit(); cur.close(); conn.close()

                    if last_status[site] != 200:
                        send_tg_msg(f"✅ UP: {site} (Был недоступен {fail_count[site]} мин.)")
                    
                    last_status[site], fail_count[site] = 200, 0

                    # Мониторинг задержки (твои уведомления)
                    if resp_time > 20 and not last_latency_map[site]:
                        send_tg_msg(f"🐢 ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек.")
                        last_latency_map[site] = True
                    elif resp_time < 10 and last_latency_map[site]:
                        send_tg_msg(f"⚡️ СКОРОСТЬ ВОССТАНОВЛЕНА! {site}: {round(resp_time, 2)} сек.")
                        last_latency_map[site] = False
            except: pass
        time.sleep(60)

# --- РОУТЫ ---

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    file_path = 'favicon.ico'
    if os.path.exists(file_path): return FileResponse(file_path)
    return Response(status_code=204)

@app.get("/test-screen/{site_name}")
async def test_screen(site_name: str, auth: bool = Depends(check_auth)):
    if site_name not in SITES: return JSONResponse({"status": "error", "msg": "Сайт не найден"}, status_code=404)
    shot = await take_screenshot(site_name)
    if shot:
        send_tg_msg(f"🧪 Тестовый скриншот: {site_name}", shot)
        return {"status": "success", "msg": f"Скриншот {site_name} отправлен"}
    return JSONResponse({"status": "error", "msg": "Ошибка скриншота"}, status_code=500)

@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")

    cur.execute("SELECT DISTINCT ON (site) * FROM logs ORDER BY site, timestamp DESC")
    latest = {r['site']: r for r in cur.fetchall()}
    cur.execute("SELECT site, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as upt FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY site")
    stats = {r['site']: r for r in cur.fetchall()}

    html = f"""
    <html><head><meta charset="UTF-8"><title>Sibur Monitoring</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; color: #1e293b; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        h1 {{ color: #00717a; border-bottom: 2px solid #f1f5f9; padding-bottom: 15px; display: flex; justify-content: space-between; align-items: center; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th {{ text-align: left; padding: 12px; color: #64748b; font-size: 11px; text-transform: uppercase; }}
        td {{ padding: 12px; border-bottom: 1px solid #f1f5f9; font-size: 14px; }}
        .btn-test {{ background: #00717a; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; min-width: 100px; justify-content: center; }}
        .loader {{ border: 2px solid #f3f3f3; border-top: 2px solid #ffffff; border-radius: 50%; width: 14px; height: 14px; animation: spin 0.8s linear infinite; display: none; margin-right: 8px; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        .loading .loader {{ display: block; }} .loading span {{ display: none; }}
        .toast {{ position: fixed; bottom: 20px; right: 20px; background: #1e293b; color: white; padding: 12px 24px; border-radius: 8px; display: none; font-size: 14px; z-index: 1000; }}
    </style></head><body>
    <div id="toast" class="toast"></div>
    <div class="container">
        <h1>📊 Sibur Monitoring <span style="font-size: 14px; color: #94a3b8;">{now_msk}</span></h1>
        <table><thead><tr><th>Сайт</th><th>Статус</th><th>Uptime 30д</th><th>SSL</th><th>Проверка</th></tr></thead><tbody>
    """
    sorted_sites = sorted(SITES, key=lambda x: (x != "sibur.ru", x not in PRIORITY_SITES, x))
    for s in sorted_sites:
        v = latest.get(s, {'status':0,'ssl_days':-1})
        st = stats.get(s, {'upt':0})
        html += f"""<tr><td><strong>{s}</strong></td><td><span style="color: {'#16a34a' if v['status']==200 else '#dc2626'}">● {'Online' if v['status']==200 else 'Offline'}</span></td><td>{st['upt']}%</td><td>{v['ssl_days']}д</td>
        <td><button class="btn-test" onclick="runTest('{s}', this)"><div class="loader"></div><span>📸 Screen</span></button></td></tr>"""
    html += """</tbody></table></div>
    <script>
    async function runTest(site, btn) {
        if (btn.classList.contains('loading')) return;
        btn.classList.add('loading'); btn.disabled = true;
        try {
            const r = await fetch('/test-screen/' + site); const d = await r.json();
            showToast(d.msg);
        } catch (e) { showToast('Ошибка сети'); }
        finally { btn.classList.remove('loading'); btn.disabled = false; }
    }
    function showToast(m) { const t = document.getElementById('toast'); t.innerText = m; t.style.display = 'block'; setTimeout(() => t.style.display='none', 4000); }
    setTimeout(() => location.reload(), 300000);
    </script></body></html>"""
    cur.close(); conn.close(); return html

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
