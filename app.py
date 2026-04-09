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

def get_db_connection(): return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS logs 
                  (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                   status INTEGER, response_time REAL, ssl_days INTEGER)''')
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_site_ts ON logs (site, timestamp DESC)")
    conn.commit(); cur.close(); conn.close()

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
                    r = requests.get(f"https://{site}", timeout=25, headers=headers, allow_redirects=True)
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

                if last_status_map[site] == 200 and curr_status != 200:
                    send_tg_msg(f"🚨 {site} DOWN! Код: {curr_status}")
                    last_latency_map[site] = False
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
            except: pass
        time.sleep(60)

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")

    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2) as up, ROUND(AVG(response_time)::numeric, 3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'")
    s30 = cur.fetchone()
    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2) as up, ROUND(AVG(response_time)::numeric, 3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '24 hours'")
    s24 = cur.fetchone()

    cur.execute("SELECT DISTINCT ON (site) site, status, response_time, ssl_days FROM logs ORDER BY site, timestamp DESC")
    latest_states = {r['site']: r for r in cur.fetchall()}
    cur.execute("SELECT site, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric, 2) as upt, COUNT(*) FILTER (WHERE status != 200)*60 as down_sec FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY site")
    stats_30d = {r['site']: r for r in cur.fetchall()}
    cur.execute("SELECT site, DATE(timestamp) as d, ROUND(AVG(response_time)::numeric,2) as r, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/COUNT(*))::numeric,2) as u FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY 1, 2 ORDER BY 2")
    graph_raw = cur.fetchall(); chart_data = {}
    for r in graph_raw:
        s = r['site']; chart_data.setdefault(s, {"labels":[], "uptime":[], "resp":[]})
        chart_data[s]["labels"].append(r['d'].strftime('%d.%m')); chart_data[s]["uptime"].append(float(r['u'])); chart_data[s]["resp"].append(float(r['r']))

    inc_list = [f"{s} (Ошибка: {v['status']})" for s,v in latest_states.items() if v['status']!=200]
    slow_list = [f"{s} (Медленно: {round(v['response_time'],1)}с)" for s,v in latest_states.items() if v['status']==200 and v['response_time']>20]
    ssl_list = [f"{s} (SSL: {v['ssl_days']}д)" for s,v in latest_states.items() if 0<=v['ssl_days']<=20]
    all_err = inc_list + slow_list + ssl_list

    html = f"""
    <html><head><title>Мониторинг сайтов</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; color: #1e293b; }}
        .container {{ max-width: 1400px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 20px; }}
        .kpi-card {{ background: #fff; padding: 15px; border-radius: 10px; border: 1px solid #e2e8f0; border-top: 4px solid #3b82f6; text-align: center; }}
        .kpi-card span {{ font-size: 13px; color: #64748b; font-weight: 600; }}
        .kpi-card strong {{ font-size: 18px; display: block; margin-top: 5px; }}
        .danger-card {{ border-top-color: #ef4444; color: #991b1b; background: #fef2f2; }}
        .error-bar {{ background: #fef2f2; border: 1px solid #fee2e2; color: #b91c1c; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-weight: 600; font-size: 14px; }}
        .tabs {{ display: flex; gap: 8px; margin-bottom: 15px; }}
        .tab-btn {{ padding: 10px 20px; border: none; background: #e2e8f0; border-radius: 6px; cursor: pointer; font-weight: bold; }}
        .tab-btn.active {{ background: #3b82f6; color: white; }}
        .tab-content {{ display: none; }} .active-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
        .row-err {{ background-color: #fff1f2 !important; }}
        .row-err td {{ color: #dc2626 !important; font-weight: bold !important; }}
        .row-err a {{ color: #dc2626 !important; }}
        .txt-err {{ color: #dc2626; font-weight: bold; }} .txt-ok {{ color: #16a34a; font-weight: bold; }}
        .refresh-btn {{ background: #3b82f6; color: white; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; font-weight: bold; }}
        @media (max-width: 900px) {{ .kpi-grid {{ grid-template-columns: repeat(2, 1fr); }} }}
    </style></head><body><div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
            <h1>📊 Мониторинг сайтов</h1>
            <button class="refresh-btn" onclick="location.reload()">🔄 {now_msk}</button>
        </div>
        <div class="kpi-grid">
            <div class="kpi-card"><span>Доступно</span><strong>{sum(1 for s in latest_states.values() if s['status']==200)} / {len(SITES)}</strong></div>
            <div class="kpi-card"><span>Uptime (24ч / 30д)</span><strong>{s24['up']}% / {s30['up']}%</strong></div>
            <div class="kpi-card"><span>Ответ (24ч / 30д)</span><strong>{s24['resp']}с / {s30['resp']}с</strong></div>
            <div class="kpi-card {'danger-card' if inc_list else ''}"><span>Инциденты</span><strong>{len(inc_list)}</strong></div>
            <div class="kpi-card {'danger-card' if ssl_list else ''}"><span>SSL (<=20д)</span><strong>{len(ssl_list)}</strong></div>
        </div>
        {f'<div class="error-bar">⚠️ Обратите внимание: {", ".join(all_err)}</div>' if all_err else ''}
        <div class="tabs">
            <button class="tab-btn active" onclick="tab(event, 't1')">Список</button>
            <button class="tab-btn" onclick="tab(event, 't2')">Аналитика</button>
            <button class="tab-btn" onclick="tab(event, 't3')">Инциденты</button>
        </div>
        <div id="t1" class="tab-content active-content">
            <table><thead><tr><th>Сайт</th><th>Статус</th><th>Uptime</th><th>Ответ</th><th>SSL</th><th>Простой</th></tr></thead><tbody>
    """
    sorted_sites = PRIORITY_SITES + sorted([s for s in SITES if s not in PRIORITY_SITES])
    for s in sorted_sites:
        st = latest_states.get(s, {'status':0,'response_time':0,'ssl_days':-1}); s30 = stats_30d.get(s, {'upt':0,'down_sec':0})
        h, m = s30['down_sec']//3600, (s30['down_sec']%3600)//60
        is_on = (st['status']==200); is_err = (not is_on or st['response_time']>20 or 0<=st['ssl_days']<=20)
        html += f"""<tr class="{'row-err' if is_err else ''}">
            <td>{'⭐ ' if s in PRIORITY_SITES else ''}<a href="https://{s}" target="_blank" style="text-decoration:none; color:inherit;"><strong>{s}</strong></a></td>
            <td><span class="{'txt-ok' if is_on else 'txt-err'}">{'Online' if is_on else 'Offline'}</span></td>
            <td>{s30['upt']}%</td><td>{round(st['response_time'],2)}с</td><td>{st['ssl_days']}д</td><td>{h}ч {m}м</td></tr>"""
    
    html += """</tbody></table></div><div id="t2" class="tab-content"><div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 15px;">"""
    for s in sorted_sites: html += f"<div class='kpi-card'><h4>{s}</h4><canvas id='c-{s.replace('.','_')}'></canvas></div>"
    
    html += """</div></div><div id="t3" class="tab-content"><table><thead><tr><th>Время инцидента (МСК)</th><th>Сайт</th><th>Длительность</th><th>Код ошибки</th><th>Описание</th></tr></thead><tbody>"""
    cur.execute("""
        WITH status_logs AS (
            SELECT site, timestamp, status, response_time,
            CASE WHEN (status != 200 OR response_time > 20) THEN 1 ELSE 0 END as is_err,
            LAG(status) OVER (PARTITION BY site ORDER BY timestamp) as prev_status
            FROM logs
        ),
        incident_starts AS (
            SELECT *, CASE WHEN is_err = 1 AND (prev_status = 200 OR prev_status IS NULL) THEN 1 ELSE 0 END as start_flag FROM status_logs
        ),
        incident_groups AS (
            SELECT *, SUM(start_flag) OVER (PARTITION BY site ORDER BY timestamp) as grp_id FROM incident_starts WHERE is_err = 1
        )
        SELECT site, MIN(timestamp), EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp)))/60 + 1 as dur, STRING_AGG(DISTINCT status::text, ', '),
        CASE WHEN MAX(status) = 0 THEN 'Timeout' WHEN MAX(status) = 502 THEN 'Bad Gateway' ELSE 'Server Error' END
        FROM incident_groups GROUP BY site, grp_id ORDER BY 2 DESC LIMIT 50
    """)
    for err in cur.fetchall():
        dur = int(err[2]); dur_str = f"{dur} мин" if dur < 60 else f"{dur//60}ч {dur%60}м"
        html += f"<tr><td>{err[1].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')}</td><td><strong>{err[0]}</strong></td><td class='txt-err'>{dur_str}</td><td>{err[3]}</td><td>{err[4]}</td></tr>"
    
    html += "</tbody></table></div></div><script>function tab(e,n){var i,x=document.getElementsByClassName('tab-content'),b=document.getElementsByClassName('tab-btn');for(i=0;i<x.length;i++)x[i].className='tab-content';for(i=0;i<b.length;i++)b[i].className='tab-btn';document.getElementById(n).className='tab-content active-content';e.currentTarget.className+=' active';}"
    for s, d in chart_data.items():
        html += f"Chart.defaults.font.size=10; new Chart(document.getElementById('c-{s.replace('.','_')}'), {{type:'line', data:{{labels:{json.dumps(d['labels'])}, datasets:[{{label:'Uptime', data:{json.dumps(d['uptime'])}, borderColor:'#10b981', yAxisID:'y', tension:0.3}},{{label:'Ответ', data:{json.dumps(d['resp'])}, borderColor:'#3b82f6', yAxisID:'y1', tension:0.3}}]}}, options:{{scales:{{y:{{min:70, max:105}},y1:{{position:'right', grid:{{drawOnChartArea:false}}}} }} }} }});"
    html += "</script></body></html>"; cur.close(); conn.close(); return html

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
