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
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-setuid-sandbox", "--no-zygote"])
            context = await browser.new_context(viewport={'width': 1280, 'height': 720}, ignore_https_errors=True)
            page = await context.new_page()
            try: await page.goto(f"https://{site}", timeout=20000, wait_until="domcontentloaded")
            except: pass
            await asyncio.sleep(2) 
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

# --- ВОРКЕРЫ ---

def daily_report_worker():
    while True:
        now = datetime.datetime.now(TZ_MOSCOW)
        if now.hour == 9 and now.minute == 0:
            conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute("SELECT DISTINCT ON (site) site, ssl_days FROM logs ORDER BY site, timestamp DESC")
            rows = cur.fetchall()
            cur.close(); conn.close()
            ssl_alerts = [f"🔒 {r[0]} — осталось {r[1]}д." for r in rows if 0 <= r[1] <= 20]
            if ssl_alerts:
                send_tg_msg("🔔 Утренний отчет по SSL (менее 20 дней):\n\n" + "\n".join(ssl_alerts))
            time.sleep(61)
        time.sleep(30)

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
                        send_tg_msg(f"🚨 DOWN: {site} (Error {curr_status})", shot_path); last_status[site] = curr_status
                else:
                    conn = get_db_connection(); cur = conn.cursor()
                    cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days) VALUES (%s,%s,%s,%s,%s)", (site, curr_status, resp_time, ssl_d, dom_d))
                    conn.commit(); cur.close(); conn.close()
                    if last_status[site] != 200:
                        send_tg_msg(f"✅ UP: {site} (Был недоступен {fail_count[site]} мин.)")
                    last_status[site], fail_count[site] = 200, 0
                    if resp_time > 20 and not last_latency_map[site]:
                        send_tg_msg(f"🐢 ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек."); last_latency_map[site] = True
                    elif resp_time < 10 and last_latency_map[site]:
                        send_tg_msg(f"⚡️ СКОРОСТЬ ВОССТАНОВЛЕНА! {site}: {round(resp_time, 2)} сек."); last_latency_map[site] = False
            except: pass
        time.sleep(60)

# --- РОУТЫ ---

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()
    threading.Thread(target=daily_report_worker, daemon=True).start()

@app.get("/test-screen/{site_name}")
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
    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as up, ROUND(AVG(response_time)::numeric,3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'")
    s30 = cur.fetchone() or {'up':0, 'resp':0}
    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as up, ROUND(AVG(response_time)::numeric,3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '24 hours'")
    s24 = cur.fetchone() or {'up':0, 'resp':0}
    cur.execute("SELECT DISTINCT ON (site) * FROM logs ORDER BY site, timestamp DESC")
    latest = {r['site']: r for r in cur.fetchall()}
    cur.execute("SELECT site, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as upt FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY site")
    stats = {r['site']: r for r in cur.fetchall()}

    incidents = [s for s,v in latest.items() if v['status']!=200]
    ssl_warn = [s for s,v in latest.items() if 0 <= v['ssl_days'] <= 20]
    latency_warn = [s for s,v in latest.items() if v['response_time'] > 20 and v['status'] == 200]
    all_warn_list = [f"❌ {s} (Offline)" for s in incidents] + [f"🔒 {s} (SSL {latest[s]['ssl_days']}д)" for s in ssl_warn] + [f"🐢 {s} (Задержка {round(latest[s]['response_time'],1)}с)" for s in latency_warn]
    online_count = sum(1 for s in latest.values() if s['status']==200); total_sites = len(SITES)

    html = f"""
    <html><head><meta charset="UTF-8"><title>Sibur Monitoring</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; }}
        .container {{ max-width: 1400px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 20px; }}
        .kpi-card {{ background: #fff; padding: 10px; border-radius: 10px; border: 1px solid #e2e8f0; border-top: 4px solid #00717a; text-align: center; }}
        .danger-card {{ border-top-color: #ef4444 !important; background: #fef2f2 !important; }}
        .error-bar {{ background: #fff1f2; border: 1px solid #fee2e2; color: #b91c1c; padding: 15px; border-radius: 8px; margin-bottom: 20px; font-weight: bold; }}
        .error-list {{ margin: 5px 0 0 20px; padding: 0; list-style-type: disc; }}
        .tabs {{ display: flex; gap: 8px; margin-bottom: 15px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
        .tab-btn {{ padding: 10px 20px; border: none; background: #e2e8f0; border-radius: 6px; cursor: pointer; font-weight: bold; }}
        .tab-btn.active {{ background: #00717a; color: white; }}
        .tab-content {{ display: none; }} .active-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
        .btn-test {{ background: #00717a; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; min-width: 100px; }}
        .loader {{ border: 2px solid #f3f3f3; border-top: 2px solid #ffffff; border-radius: 50%; width: 14px; height: 14px; animation: spin 0.8s linear infinite; display: none; margin-right: 8px; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        .loading .loader {{ display: block; }} .loading span {{ display: none; }}
        .toast {{ position: fixed; bottom: 20px; right: 20px; background: #333; color: white; padding: 12px 24px; border-radius: 8px; display: none; z-index: 1000; }}
    </style></head><body>
    <div id="toast" class="toast"></div>
    <div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
            <h1 style="color:#00717a; margin:0;">📊 Мониторинг сайтов</h1>
            <button class="refresh-btn" style="background:#00717a; color:white; border:none; padding:8px 15px; border-radius:6px; cursor:pointer;" onclick="location.reload()">🔄 Обновить: {now_msk}</button>
        </div>
        <div class="kpi-grid">
            <div class="kpi-card {'danger-card' if online_count < total_sites else ''}"><span>Доступно</span><strong><br>{online_count} / {total_sites}</strong></div>
            <div class="kpi-card"><span>Uptime 24ч</span><strong><br>{s24['up']}%</strong></div>
            <div class="kpi-card"><span>Uptime 30д</span><strong><br>{s30['up']}%</strong></div>
            <div class="kpi-card {'danger-card' if len(incidents) > 0 else ''}"><span>Инциденты</span><strong><br>{len(incidents)}</strong></div>
            <div class="kpi-card {'danger-card' if ssl_warn else ''}"><span>SSL <=20д</span><strong><br>{len(ssl_warn)}</strong></div>
        </div>
        {f'<div class="error-bar">⚠️ Обратите внимание:<ul class="error-list"><li>' + '</li><li>'.join(all_warn_list) + '</li></ul></div>' if all_warn_list else ''}
        <div class="tabs"><button class="tab-btn active" onclick="tab(event, 't1')">Список</button><button class="tab-btn" onclick="tab(event, 't2')">Аналитика</button><button class="tab-btn" onclick="tab(event, 't3')">Инциденты</button><button class="tab-btn" onclick="tab(event, 't4')">Календарь событий</button></div>
        
        <div id="t1" class="tab-content active-content">
            <table><thead><tr><th>Сайт</th><th>Статус</th><th>Uptime 30д</th><th>Ответ</th><th>SSL</th><th>Проверка</th></tr></thead><tbody>
    """
    sorted_sites = sorted(SITES, key=lambda x: (x != "sibur.ru", x not in PRIORITY_SITES, x))
    for s in sorted_sites:
        v = latest.get(s, {'status':0,'response_time':0,'ssl_days':-1}); st = stats.get(s, {'upt':0})
        html += f"""<tr><td><strong>{s}</strong></td><td><span style="color: {'#16a34a' if v['status']==200 else '#dc2626'}">● {'Online' if v['status']==200 else 'Offline'}</span></td><td>{st['upt']}%</td><td>{round(v['response_time'],2)}с</td><td>{v['ssl_days']}д</td>
        <td><button class="btn-test" onclick="runTest('{s}', this)"><div class="loader"></div><span>📸 Screen</span></button></td></tr>"""
    
    html += """</tbody></table></div><div id="t2" class="tab-content"><div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(400px,1fr)); gap:20px;">"""
    cur.execute("SELECT site, DATE(timestamp) as d, ROUND(AVG(response_time)::numeric,2) as r, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/COUNT(*))::numeric,2) as u FROM logs WHERE timestamp > NOW() - INTERVAL '14 days' GROUP BY 1,2 ORDER BY 2")
    g_data = {}
    for r in cur.fetchall():
        s = r['site']; g_data.setdefault(s, {"l":[], "u":[], "r":[]})
        g_data[s]["l"].append(r['d'].strftime('%d.%m')); g_data[s]["u"].append(float(r['u'])); g_data[s]["r"].append(float(r['r']))
    for s in sorted_sites:
        if s in g_data: html += f"<div class='kpi-card' style='border-top:2px solid #eee'><h5>{s}</h5><canvas id='c-{s.replace('.','_')}'></canvas></div>"

    html += """</div></div><div id="t3" class="tab-content"><table><thead><tr><th>Начало</th><th>Сайт</th><th>Длительность</th><th>Код</th><th>Описание</th></tr></thead><tbody>"""
    cur.execute("""WITH status_changes AS (SELECT site, timestamp, status, CASE WHEN status != 200 AND (LAG(status) OVER (PARTITION BY site ORDER BY timestamp) = 200 OR LAG(status) OVER (PARTITION BY site ORDER BY timestamp) IS NULL) THEN 1 ELSE 0 END as is_start FROM logs), incident_groups AS (SELECT site, timestamp, status, SUM(is_start) OVER (PARTITION BY site ORDER BY timestamp) as grp_id FROM status_changes WHERE status != 200) SELECT site, MIN(timestamp), COUNT(*), MAX(status), CASE WHEN MAX(status) = 0 THEN 'Timeout' WHEN MAX(status) = 502 THEN 'Bad Gateway' WHEN MAX(status) = 503 THEN 'Service Unavailable' ELSE 'Server Error' END FROM incident_groups GROUP BY site, grp_id ORDER BY 2 DESC LIMIT 20""")
    for r in cur.fetchall():
        html += f"<tr><td>{r[1].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')}</td><td>{r[0]}</td><td style='color:#dc2626'>{r[2]} мин</td><td>{r[3]}</td><td>{r[4]}</td></tr>"

    html += """</tbody></table></div><div id="t4" class="tab-content"><table><thead><tr><th>Событие</th><th>Сайт</th><th>Осталось дней</th></tr></thead><tbody>"""
    for s in SITES:
        v = latest.get(s, {})
        if v.get('ssl_days', -1) >= 0: html += f"<tr><td>SSL сертификат</td><td>{s}</td><td>{v['ssl_days']} дн.</td></tr>"
        if v.get('domain_days', -1) >= 0: html += f"<tr><td>Оплата домена</td><td>{s}</td><td>{v['domain_days']} дн.</td></tr>"

    html += """</tbody></table></div></div>
    <script>
    function tab(e,n){ var i,x=document.getElementsByClassName('tab-content'),b=document.getElementsByClassName('tab-btn'); for(i=0;i<x.length;i++)x[i].className='tab-content'; for(i=0;i<b.length;i++)b[i].className='tab-btn'; document.getElementById(n).className='tab-content active-content'; e.currentTarget.className+=' active'; }
    async function runTest(site, btn) {
        if (btn.classList.contains('loading')) return;
        btn.classList.add('loading'); btn.disabled = true;
        try { const r = await fetch('/test-screen/' + site); const d = await r.json(); showToast(d.msg); } catch (e) { showToast('Ошибка сети'); }
        finally { btn.classList.remove('loading'); btn.disabled = false; }
    }
    function showToast(m) { const t = document.getElementById('toast'); t.innerText = m; t.style.display = 'block'; setTimeout(() => t.style.display='none', 4000); }
    setTimeout(() => location.reload(), 300000);
    </script>"""
    for s, d in g_data.items():
        html += f"""<script>new Chart(document.getElementById('c-{s.replace('.','_')}'), {{ type:'line', data:{{ labels:{json.dumps(d['l'])}, datasets:[ {{label:'Uptime %', data:{json.dumps(d['u'])}, borderColor:'#10b981', yAxisID:'y', tension:0.3}}, {{label:'Ответ сек', data:{json.dumps(d['r'])}, borderColor:'#3b82f6', yAxisID:'y1', tension:0.3}} ]}}, options:{{ scales:{{ y:{{min:75, max:110}}, y1:{{position:'right', grid:{{display:false}}}} }} }} }});</script>"""
    cur.close(); conn.close(); return html

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
