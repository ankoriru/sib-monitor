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
from fastapi import FastAPI, Request, Response, Depends, HTTPException, Cookie
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

# --- КОНФИГУРАЦИЯ ---
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

@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    file_path = 'favicon.ico'
    if os.path.exists(file_path): return FileResponse(file_path)
    return Response(status_code=204)

def check_auth(request: Request, response: Response, session_auth: str = Cookie(None)):
    if session_auth == "authenticated_sibur": return True
    auth = request.headers.get("Authorization")
    if not auth: raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic realm='Sibur Monitoring'"})
    try:
        scheme, credentials = auth.split()
        decoded = base64.b64decode(credentials).decode("ascii")
        u, p = decoded.split(":")
        if u == "sibur" and p == "sibur":
            response.set_cookie(key="session_auth", value="authenticated_sibur", max_age=2592000, httponly=True)
            return True
    except: pass
    raise HTTPException(status_code=401)

def get_db_connection(): return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS logs 
                  (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                   status INTEGER, response_time REAL, ssl_days INTEGER, domain_days INTEGER)''')
    # Инициализация таблицы для Вкладки ЗС (события)
    cur.execute('''CREATE TABLE IF NOT EXISTS events_zs 
                  (id SERIAL PRIMARY KEY, event_text TEXT, event_time TIMESTAMP, is_sent BOOLEAN DEFAULT FALSE)''')
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

def daily_report_worker():
    while True:
        now = datetime.datetime.now(TZ_MOSCOW)
        if now.hour == 9 and now.minute == 0:
            try:
                conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
                cur.execute("SELECT DISTINCT ON (site) site, ssl_days FROM logs ORDER BY site, timestamp DESC")
                rows = cur.fetchall(); cur.close(); conn.close()
                ssl_alerts = [f"🔒 {r[0]} — осталось {r[1]}д." for r in rows if r[1] is not None and 0 <= r[1] <= 20]
                if ssl_alerts:
                    send_tg_msg("🔔 Утренний отчет по SSL (менее 20 дней):\n\n" + "\n".join(ssl_alerts))
                time.sleep(61)
            except: pass
        time.sleep(30)

def events_zs_worker():
    """Воркер для обработки вкладки ЗС (Значимые события)"""
    while True:
        try:
            now = datetime.datetime.now(TZ_MOSCOW)
            conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
            # Ищем события, время которых пришло, но уведомление еще не ушло
            cur.execute("SELECT id, event_text, event_time FROM events_zs WHERE event_time <= %s AND is_sent = False", (now,))
            events = cur.fetchall()
            for ev in events:
                send_tg_msg(f"🚩 {ev['event_text']}")
                cur.execute("UPDATE events_zs SET is_sent = True WHERE id = %s", (ev['id'],))
            conn.commit(); cur.close(); conn.close()
        except Exception as e:
            print(f"Ошибка воркера ЗС: {e}")
        time.sleep(15) # Проверка каждые 15 секунд для точности

async def take_screenshot(site):
    path = f"debug_{int(time.time())}.png"
    full_url = f"https://{site}" 
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-setuid-sandbox", "--no-zygote"])
            context = await browser.new_context(viewport={'width': 1280, 'height': 720}, ignore_https_errors=True)
            page = await context.new_page()
            try: await page.goto(full_url, timeout=20000, wait_until="domcontentloaded")
            except: pass
            await asyncio.sleep(2); await page.screenshot(path=path, type="jpeg", quality=80); await browser.close()
        return path
    except Exception as e:
        print(f"ОШИБКА PLAYWRIGHT {site}: {e}"); return None

def get_domain_info(site):
    try:
        w = whois.whois(site); exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if exp: return (exp.replace(tzinfo=None) - datetime.datetime.now()).days
    except: pass
    return -1

def check_worker():
    import urllib3 
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    last_status = {site: 200 for site in SITES}
    fail_count = {site: 0 for site in SITES}
    last_latency_map = {site: False for site in SITES}
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    
    while True:
        for site in SITES:
            try:
                curr_status, resp_time, ssl_d, dom_d = 0, 25.0, -1, -1
                check_url = f"https://{site}"; domain_only = site.split('/')[0]
                start = time.time()
                try:
                    r = requests.get(check_url, timeout=25, headers=headers, allow_redirects=True, verify=False)
                    curr_status, resp_time = r.status_code, time.time() - start
                except: curr_status, resp_time = 0, 25.0

                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((domain_only, 443), timeout=3) as sock:
                        with ctx.wrap_socket(sock, server_hostname=domain_only) as ssock:
                            cert = ssock.getpeercert()
                            exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            ssl_d = (exp - datetime.datetime.utcnow()).days
                except: pass
                dom_d = get_domain_info(domain_only)

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
                        send_tg_msg(f"🚨 DOWN: {site} (Код: {curr_status})", shot_path)
                        last_status[site] = curr_status
                else:
                    conn = get_db_connection(); cur = conn.cursor()
                    cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days) VALUES (%s,%s,%s,%s,%s)", (site, curr_status, resp_time, ssl_d, dom_d))
                    conn.commit(); cur.close(); conn.close()
                    if last_status[site] != 200: send_tg_msg(f"✅ UP: {site} (Был недоступен: {fail_count[site]} мин.)")
                    last_status[site], fail_count[site] = 200, 0
                    if resp_time > 20 and not last_latency_map[site]:
                        send_tg_msg(f"🐢 ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек."); last_latency_map[site] = True
                    elif resp_time < 10 and last_latency_map[site]:
                        send_tg_msg(f"⚡️ СКОРОСТЬ ВОССТАНОВЛЕНА! {site}: {round(resp_time, 2)} сек."); last_latency_map[site] = False
            except: pass
        time.sleep(60)

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()
    threading.Thread(target=daily_report_worker, daemon=True).start() 
    threading.Thread(target=events_zs_worker, daemon=True).start() 

@app.get("/test-screen/{site_name:path}")
async def test_screen(site_name: str, auth: bool = Depends(check_auth)):
    if site_name not in SITES: return JSONResponse({"status": "error", "msg": "Сайт не найден"}, status_code=404)
    shot = await take_screenshot(site_name)
    if shot:
        send_tg_msg(f"🧪 Тестовый скриншот: {site_name}", shot)
        return {"status": "success", "msg": f"Скриншот {site_name} отправлен"}
    return JSONResponse({"status": "error", "msg": "Ошибка"}, status_code=500)

@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")
    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as up, ROUND(AVG(response_time)::numeric,3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'")
    s30 = cur.fetchone() or {'up':0, 'resp':0}
    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as up, ROUND(AVG(response_time)::numeric,3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '24 hours'")
    s24 = cur.fetchone() or {'up':0, 'resp':0}
    cur.execute("SELECT DISTINCT ON (site) * FROM logs ORDER BY site, timestamp DESC")
    latest_all = {r['site']: r for r in cur.fetchall()}
    latest = {s: latest_all[s] for s in SITES if s in latest_all}
    cur.execute("SELECT site, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as upt FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY site")
    stats = {r['site']: r for r in cur.fetchall()}
    incidents = [s for s,v in latest.items() if v['status']!=200]
    ssl_warn = [s for s,v in latest.items() if 0 <= v['ssl_days'] <= 20]
    latency_warn = [s for s,v in latest.items() if v['response_time'] > 20 and v['status'] == 200]
    all_warn_list = [f"❌ {s} (Offline)" for s in incidents] + [f"🔒 {s} (SSL {latest[s]['ssl_days']}д)" for s in ssl_warn] + [f"🐢 {s} (Задержка {round(latest[s]['response_time'],1)}с)" for s in latency_warn]
    online_count = sum(1 for s in latest.values() if s['status']==200); total_sites = len(SITES)

    html = f"""
    <html><head><meta charset="UTF-8"><title>Мониторинг</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; color: #1e293b; }}
        .container {{ max-width: 1400px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 20px; }}
        .kpi-card {{ background: #fff; padding: 10px; border-radius: 10px; border: 1px solid #e2e8f0; border-top: 4px solid #00717a; text-align: center; }}
        .danger-card {{ border-top-color: #ef4444 !important; background: #fef2f2 !important; }}
        .tabs {{ display: flex; gap: 8px; margin-bottom: 15px; border-bottom: 2px solid #e2e8f0; }}
        .tab-btn {{ padding: 10px 20px; border: none; background: #e2e8f0; cursor: pointer; font-weight: bold; }}
        .tab-btn.active {{ background: #00717a; color: white; }}
        .tab-content {{ display: none; }} .active-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
        .btn-test {{ background: #00717a; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; }}
        .toast {{ position: fixed; bottom: 20px; right: 20px; background: #333; color: white; padding: 12px 24px; display: none; border-radius: 8px; }}
    </style></head><body>
    <div id="toast" class="toast"></div>
    <div class="container">
        <h1 style="color:#00717a;">📊 Мониторинг сайтов <button onclick="location.reload()" style="float:right;">🔄 {now_msk}</button></h1>
        <div class="kpi-grid">
            <div class="kpi-card {'danger-card' if online_count < total_sites else ''}"><span>Доступно</span><strong><br>{online_count} / {total_sites}</strong></div>
            <div class="kpi-card"><span>Uptime 24ч</span><strong><br>{s24['up']}%</strong></div>
            <div class="kpi-card"><span>Uptime 30д</span><strong><br>{s30['up']}%</strong></div>
            <div class="kpi-card {'danger-card' if len(incidents) > 0 else ''}"><span>Инциденты</span><strong><br>{len(incidents)}</strong></div>
            <div class="kpi-card {'danger-card' if ssl_warn else ''}"><span>SSL <=20д</span><strong><br>{len(ssl_warn)}</strong></div>
        </div>
        <div class="tabs"><button class="tab-btn active" onclick="tab(event, 't1')">Список</button></div>
        <div id="t1" class="tab-content active-content">
            <table><thead><tr><th>Сайт</th><th>Статус</th><th>Uptime</th><th>Ответ</th><th>SSL</th><th>Тест</th></tr></thead><tbody>
    """
    def get_site_weight(s):
        if s == "sibur.ru": return 0
        if s in NEW_MONITORING_SITES: return 2
        if s in PRIORITY_SITES: return 1
        return 3
    sorted_sites = sorted(SITES, key=lambda x: (get_site_weight(x), x))

    for s in sorted_sites:
        v = latest.get(s, {'status':0,'response_time':0,'ssl_days':-1}); st30 = stats.get(s, {'upt':0})
        prefix = "🔰 " if s in NEW_MONITORING_SITES else ("⭐️ " if s in PRIORITY_SITES else "")
        html += f"""<tr><td>{prefix}<a href="https://{s}" target="_blank" style="text-decoration:none; color:inherit;">{s}</a></td>
            <td><span style="color:{'green' if v['status']==200 else 'red'}">{'Online' if v['status']==200 else 'Offline'}</span></td>
            <td>{st30['upt']}%</td><td>{round(v['response_time'],2)}с</td><td>{v['ssl_days']}д</td>
            <td><button class="btn-test" onclick="runTest('{s}', this)">📸 Screen</button></td></tr>"""

    html += f"""</tbody></table></div></div>
    <script>
    function tab(e,n){{ var i,x=document.getElementsByClassName('tab-content'),b=document.getElementsByClassName('tab-btn'); for(i=0;i<x.length;i++)x[i].className='tab-content'; for(i=0;i<b.length;i++)b[i].className='tab-btn'; document.getElementById(n).className='tab-content active-content'; e.currentTarget.className+=' active'; }}
    async function runTest(site, btn) {{
        btn.innerText = '⏳';
        try {{
            const r = await fetch('/test-screen/' + encodeURIComponent(site));
            const d = await r.json(); showToast(d.msg);
        }} catch(e) {{ showToast('Ошибка'); }}
        finally {{ btn.innerText = '📸 Screen'; }}
    }}
    function showToast(msg) {{
        const t = document.getElementById('toast'); t.innerText = msg; t.style.display = 'block';
        setTimeout(() => {{ t.style.display = 'none'; }}, 4000);
    }}
    setInterval(() => {{ location.reload(); }}, 120000);
    </script></body></html>"""
    cur.close(); conn.close(); return html

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
