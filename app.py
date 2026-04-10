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
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import HTMLResponse

# --- КОНФИГУРАЦИЯ ---
# В Amvera DATABASE_URL подтянется автоматически из настроек проекта
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
    "quality-certificates.sibur.ru", "rusvinyl.ru", "shop.rusvinyl.ru",
    "sibur.digital", "sibur-int.com", "sibur-int.ru", "sibur-yug.ru",
    "sintez-kazan.ru", "snck.ru", "tu-sibur.ru", "vivilen.sibur.ru"
]

PRIORITY_SITES = ["sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru"]

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

def get_db_connection():
    # Для Amvera чаще всего sslmode не требуется, но если будет ошибка - верните 'require'
    return psycopg2.connect(DATABASE_URL)

def init_db():
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS logs 
                      (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                       status INTEGER, response_time REAL, ssl_days INTEGER)''')
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_site_ts ON logs (site, timestamp DESC)")
        conn.commit(); cur.close(); conn.close()
        print("✅ DB Initialized")
    except Exception as e:
        print(f"❌ DB Init Error: {e}")

def send_tg_msg(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try: requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
    except: pass

def check_worker():
    last_status_map = {site: 200 for site in SITES}
    last_latency_map = {site: False for site in SITES}
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    while True:
        for site in SITES:
            curr_status, resp_time, ssl_d = 0, 25.0, -1
            try:
                start = time.time()
                try:
                    r = requests.get(f"https://{site}", timeout=20, headers=headers, allow_redirects=True)
                    curr_status, resp_time = r.status_code, time.time() - start
                except: curr_status, resp_time = 0, 25.0

                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((site, 443), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=site) as ssock:
                            cert = ssock.getpeercert()
                            exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            ssl_d = (exp - datetime.datetime.utcnow()).days
                except: ssl_d = -1

                # Уведомления в ТГ
                if last_status_map[site] == 200 and curr_status != 200:
                    send_tg_msg(f"🚨 {site} DOWN! Код: {curr_status}")
                elif last_status_map[site] != 200 and curr_status == 200:
                    send_tg_msg(f"✅ {site} UP!")

                if curr_status == 200:
                    if resp_time > 20 and not last_latency_map[site]:
                        send_tg_msg(f"🐢 ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек.")
                        last_latency_map[site] = True
                    elif resp_time < 10 and last_latency_map[site]:
                        send_tg_msg(f"⚡️ СКОРОСТЬ ВОССТАНОВЛЕНА! {site}: {round(resp_time, 2)} сек.")
                        last_latency_map[site] = False

                last_status_map[site] = curr_status
                conn = get_db_connection(); cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time, ssl_days) VALUES (%s, %s, %s, %s)", (site, curr_status, resp_time, ssl_d))
                conn.commit(); cur.close(); conn.close()
            except Exception as e:
                print(f"Worker Error for {site}: {e}")
        time.sleep(180) # Проверка каждые 3 минуты

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")

    # Статистика 30д и 24ч
    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2) as up, ROUND(AVG(response_time)::numeric, 3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'")
    s30 = cur.fetchone()
    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2) as up, ROUND(AVG(response_time)::numeric, 3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '24 hours'")
    s24 = cur.fetchone()

    cur.execute("SELECT DISTINCT ON (site) site, status, response_time, ssl_days FROM logs ORDER BY site, timestamp DESC")
    latest_states = {r['site']: r for r in cur.fetchall()}
    cur.execute("SELECT site, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric, 2) as upt, COUNT(*) FILTER (WHERE status != 200)*180 as down_sec FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY site")
    stats_30d = {r['site']: r for r in cur.fetchall()}
    
    # Данные для графиков
    cur.execute("SELECT site, DATE(timestamp) as d, ROUND(AVG(response_time)::numeric,2) as r, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/COUNT(*))::numeric,2) as u FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY 1, 2 ORDER BY 2")
    graph_raw = cur.fetchall(); chart_data = {}
    for r in graph_raw:
        s = r['site']; chart_data.setdefault(s, {"labels":[], "uptime":[], "resp":[]})
        chart_data[s]["labels"].append(r['d'].strftime('%d.%m')); chart_data[s]["uptime"].append(float(r['u'])); chart_data[s]["resp"].append(float(r['r']))

    # Списки ошибок
    inc_list = [f"{s}" for s,v in latest_states.items() if v['status']!=200]
    ssl_list = [f"{s}" for s,v in latest_states.items() if 0<=v['ssl_days']<=20]
    all_err = inc_list + ssl_list

    html = f"""
    <html><head><meta charset="UTF-8"><title>Sibur Monitor Pro</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; color: #1e293b; }}
        .container {{ max-width: 1400px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 20px; }}
        .kpi-card {{ background: #fff; padding: 10px 5px; border-radius: 10px; border: 1px solid #e2e8f0; border-top: 4px solid #00717a; text-align: center; }}
        .kpi-card strong {{ font-size: 16px; display: block; margin-top: 5px; }}
        .danger-card {{ border-top-color: #ef4444; color: #991b1b; background: #fef2f2; }}
        .tabs {{ display: flex; gap: 8px; margin-bottom: 15px; }}
        .tab-btn {{ padding: 10px 20px; border: none; background: #e2e8f0; border-radius: 6px; cursor: pointer; font-weight: bold; }}
        .tab-btn.active {{ background: #00717a; color: white; }}
        .tab-content {{ display: none; }} .active-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
        .txt-err {{ color: #dc2626; font-weight: bold; }} .txt-ok {{ color: #16a34a; font-weight: bold; }}
        @media (max-width: 900px) {{ .kpi-grid {{ grid-template-columns: repeat(2, 1fr); }} }}
    </style></head><body><div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
            <h1 style="color:#00717a">📊 Sibur Monitoring Pro</h1>
            <span style="font-weight:bold; color:#64748b">🔄 {now_msk}</span>
        </div>
        <div class="kpi-grid">
            <div class="kpi-card"><span>Доступно</span><strong>{sum(1 for s in latest_states.values() if s['status']==200)} / {len(SITES)}</strong></div>
            <div class="kpi-card"><span>Uptime 30д</span><strong>{s30['up']}%</strong></div>
            <div class="kpi-card"><span>Ответ 24ч</span><strong>{s24['resp']}с</strong></div>
            <div class="kpi-card {'danger-card' if inc_list else ''}"><span>Инциденты</span><strong>{len(inc_list)}</strong></div>
            <div class="kpi-card {'danger-card' if ssl_list else ''}"><span>SSL SSL <=20д</span><strong>{len(ssl_list)}</strong></div>
        </div>
        
        <div class="tabs">
            <button class="tab-btn active" onclick="tab(event, 't1')">Список</button>
            <button class="tab-btn" onclick="tab(event, 't2')">Аналитика</button>
            <button class="tab-btn" onclick="tab(event, 't3')">Журнал</button>
        </div>
        
        <div id="t1" class="tab-content active-content">
            <table><thead><tr><th>Сайт</th><th>Статус</th><th>Uptime 30д</th><th>Ответ</th><th>SSL</th></tr></thead><tbody>
    """
    sorted_sites = PRIORITY_SITES + sorted([s for s in SITES if s not in PRIORITY_SITES])
    for s in sorted_sites:
        st = latest_states.get(s, {'status':0,'response_time':0,'ssl_days':-1}); s30_st = stats_30d.get(s, {'upt':0})
        is_on = (st['status']==200); st_cls = "txt-ok" if is_on else "txt-err"
        html += f"""<tr>
            <td>{'⭐ ' if s in PRIORITY_SITES else ''}<strong>{s}</strong></td>
            <td><span class="{st_cls}">{'Online' if is_on else 'Offline'}</span></td>
            <td>{s30_st['upt']}%</td>
            <td>{round(st['response_time'],2)}с</td>
            <td class="{'txt-err' if 0<=st['ssl_days']<=20 else ''}">{st['ssl_days']}д</td></tr>"""
    
    html += """</tbody></table></div><div id="t2" class="tab-content"><div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 15px;">"""
    for s in sorted_sites: 
        if s in chart_data: html += f"<div class='kpi-card' style='border-top:2px solid #eee'><h5>{s}</h5><canvas id='c-{s.replace('.','_')}'></canvas></div>"
    
    html += """</div></div><div id="t3" class="tab-content"><table><thead><tr><th>Время (МСК)</th><th>Сайт</th><th>Длительность</th><th>Описание</th></tr></thead><tbody>"""
    
    cur.execute("""
        WITH status_logs AS (
            SELECT site, timestamp, status,
            CASE WHEN status != 200 THEN 1 ELSE 0 END as is_err,
            LAG(status) OVER (PARTITION BY site ORDER BY timestamp) as prev_status
            FROM logs
        ),
        incident_starts AS (
            SELECT *, CASE WHEN is_err = 1 AND (prev_status = 200 OR prev_status IS NULL) THEN 1 ELSE 0 END as start_flag FROM status_logs
        ),
        incident_groups AS (
            SELECT *, SUM(start_flag) OVER (PARTITION BY site ORDER BY timestamp) as grp_id FROM incident_starts WHERE is_err = 1
        )
        SELECT site, MIN(timestamp), EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp)))/60 + 3 as dur, MAX(status)
        FROM incident_groups GROUP BY site, grp_id ORDER BY 2 DESC LIMIT 30
    """)
    for err in cur.fetchall():
        html += f"<tr><td>{err[1].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')}</td><td>{err[0]}</td><td class='txt-err'>{int(err[2])} мин</td><td>Код {err[3]}</td></tr>"
    
    html += """</tbody></table></div></div><script>
    function tab(e,n){
        var i,x=document.getElementsByClassName('tab-content'),b=document.getElementsByClassName('tab-btn');
        for(i=0;i<x.length;i++)x[i].className='tab-content';
        for(i=0;i<b.length;i++)b[i].className='tab-btn';
        document.getElementById(n).className='tab-content active-content';
        e.currentTarget.className+=' active';
    }"""
    for s, d in chart_data.items():
        html += f"new Chart(document.getElementById('c-{s.replace('.','_')}'), {{type:'line', data:{{labels:{json.dumps(d['labels'])}, datasets:[{{label:'Uptime %', data:{json.dumps(d['uptime'])}, borderColor:'#10b981', tension:0.3}},{{label:'Ответ сек', data:{json.dumps(d['resp'])}, borderColor:'#3b82f6', tension:0.3}}]}}, options:{{scales:{{y:{{display:false}}}} }} }});"
    html += "</script></body></html>"; cur.close(); conn.close(); return html

if __name__ == "__main__":
    import uvicorn
    # Amvera передает порт через переменную окружения PORT
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
