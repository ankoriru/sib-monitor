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
from starlette.status import HTTP_401_UNAUTHORIZED

# --- КОНФИГУРАЦИЯ ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siburdb_user:IbaJQKbh6DQ5z9i3J82EWRJFnl1z3gkt@dpg-d797355m5p6s739tgr1g-a/siburdb")
TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "8305761464:AAE--AkY662Cm3DlKsrd8tcBnxXeTOLrO9I")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "-5282148036")
TZ_MOSCOW = pytz.timezone('Europe/Moscow')

SITES = [
    "sibur.ru", "alphapor.ru", "amur-gcc.ru", "ar24.sibur.ru",
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

app = FastAPI()

def check_auth(request: Request):
    auth = request.headers.get("Authorization")
    if not auth: raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
    try:
        scheme, credentials = auth.split()
        decoded = base64.b64decode(credentials).decode("ascii")
        u, p = decoded.split(":")
        if u == "sibur" and p == "sibur": return True
    except: pass
    raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})

def get_db_connection(): return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS logs 
                  (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                   status INTEGER, response_time REAL, ssl_days INTEGER)''')
    conn.commit(); cur.close(); conn.close()

def get_global_stats(hours=24):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute(f"SELECT ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2), ROUND(AVG(response_time)::numeric, 3) FROM logs WHERE timestamp > NOW() - INTERVAL '{hours} hours'")
        res = cur.fetchone(); conn.close()
        return res if res[0] is not None else (0, 0)
    except: return (0, 0)

def check_worker():
    last_ssl_alert = {}; last_lat_alert = {}
    while True:
        for site in SITES:
            try:
                conn = get_db_connection(); cur = conn.cursor()
                cur.execute("SELECT status FROM logs WHERE site = %s ORDER BY timestamp DESC LIMIT 1", (site,))
                row = cur.fetchone(); last_status = row[0] if row else 200
                cur.close(); conn.close()

                start = time.time()
                try:
                    r = requests.get(f"https://{site}", timeout=25)
                    curr_status, resp_time = r.status_code, time.time() - start
                except: curr_status, resp_time = 0, 25.0
                
                ssl_d = -1
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((site, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=site) as ssock:
                            cert = ssock.getpeercert()
                            exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            ssl_d = (exp - datetime.datetime.utcnow()).days
                except: pass

                # Уведомления: Down/Up
                if last_status == 200 and curr_status != 200:
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"🚨 {site} DOWN! Код: {curr_status}"})
                elif last_status != 200 and curr_status == 200:
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"✅ {site} UP!"})

                # Уведомление: Высокий пинг (> 20 сек)
                if resp_time > 20:
                    today = datetime.date.today().isoformat()
                    if last_lat_alert.get(site) != today:
                        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"🐢 КРИТИЧЕСКАЯ ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек."})
                        last_lat_alert[site] = today

                # SSL
                if 0 <= ssl_d <= 20:
                    today = datetime.date.today().isoformat()
                    if last_ssl_alert.get(site) != today:
                        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"⚠️ SSL ({ssl_d} дн.): {site}"})
                        last_ssl_alert[site] = today

                conn = get_db_connection(); cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time, ssl_days) VALUES (%s, %s, %s, %s)", (site, curr_status, resp_time, ssl_d))
                conn.commit(); cur.close(); conn.close()
            except: pass
        time.sleep(300)

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")
    
    # Сбор данных для KPI
    cur.execute("SELECT COUNT(DISTINCT site) FROM logs l1 WHERE status=200 AND timestamp=(SELECT MAX(timestamp) FROM logs l2 WHERE l1.site=l2.site)")
    sites_up = cur.fetchone()[0] or 0
    cur.execute("SELECT COUNT(DISTINCT site) FROM logs l1 WHERE (status != 200 OR response_time > 20) AND timestamp=(SELECT MAX(timestamp) FROM logs l2 WHERE l1.site=l2.site)")
    active_incidents = cur.fetchone()[0] or 0
    cur.execute("SELECT site, ssl_days FROM logs l1 WHERE ssl_days <= 20 AND ssl_days >= 0 AND timestamp=(SELECT MAX(timestamp) FROM logs l2 WHERE l1.site=l2.site)")
    ssl_issues = cur.fetchall()

    html = f"""
    <html><head><title>Мониторинг сайтов</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Inter', sans-serif; background: #f8fafc; color: #1e293b; padding: 20px; }}
        .container {{ max-width: 1300px; margin: auto; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .kpi-card {{ background: white; padding: 15px; border-radius: 10px; border-top: 4px solid #3b82f6; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .kpi-label {{ font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; }}
        .kpi-val {{ font-size: 22px; font-weight: bold; display: block; margin-top: 5px; }}
        .danger-card {{ border-top-color: #ef4444; color: #b91c1c; }}
        .tabs {{ display: flex; gap: 8px; margin-bottom: 15px; }}
        .tab-btn {{ padding: 10px 20px; border: none; background: #e2e8f0; border-radius: 6px; cursor: pointer; font-weight: bold; }}
        .tab-btn.active {{ background: #3b82f6; color: white; }}
        .tab-content {{ display: none; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .active-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
        .row-err {{ background-color: #fef2f2; }}
        .txt-err {{ color: #ef4444; font-weight: bold; }}
        .txt-ok {{ color: #10b981; font-weight: bold; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 15px; }}
    </style></head><body><div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center">
            <h1>📊 Мониторинг сайтов</h1>
            <button class="tab-btn" style="background:#3b82f6; color:white" onclick="location.reload()">🔄 Обновить: {now_msk}</button>
        </div>
        <div class="kpi-grid">
            <div class="kpi-card"><span class="kpi-label">Сайтов доступно</span><span class="kpi-val">{sites_up} / {len(SITES)}</span></div>
            <div class="kpi-card { 'danger-card' if active_incidents > 0 else '' }"><span class="kpi-label">Текущие инциденты</span><span class="kpi-val">{active_incidents}</span></div>
            <div class="kpi-card { 'danger-card' if ssl_issues else '' }"><span class="kpi-label">SSL под угрозой</span><span class="kpi-val">{len(ssl_issues)}</span></div>
        </div>
        <div class="tabs">
            <button class="tab-btn active" onclick="tab(event, 't1')">Монитор</button>
            <button class="tab-btn" onclick="tab(event, 't2')">Графики</button>
            <button class="tab-btn" onclick="tab(event, 't3')">Ошибки (30д)</button>
        </div>
        <div id="t1" class="tab-content active-content">
            <table><thead><tr><th>Сайт</th><th>Uptime (30д)</th><th>Ответ</th><th>SSL (дн)</th><th>Простой (30д)</th></tr></thead><tbody>
    """
    
    chart_data = {}
    for s in SITES:
        cur.execute("""SELECT 
            ROUND((COUNT(*) FILTER (WHERE status=200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2),
            COUNT(*) FILTER (WHERE status != 200) * 300,
            (SELECT response_time FROM logs WHERE site=%s ORDER BY timestamp DESC LIMIT 1),
            (SELECT ssl_days FROM logs WHERE site=%s ORDER BY timestamp DESC LIMIT 1),
            (SELECT status FROM logs WHERE site=%s ORDER BY timestamp DESC LIMIT 1)
            FROM logs WHERE site=%s AND timestamp > NOW() - INTERVAL '30 days'""", (s, s, s, s))
        upt, down_sec, last_resp, last_ssl, last_st = cur.fetchone()
        
        # Получаем данные для графиков
        cur.execute("SELECT DATE(timestamp), ROUND(AVG(response_time)::numeric,2), ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/COUNT(*))::numeric,2) FROM logs WHERE site=%s AND timestamp > NOW() - INTERVAL '30 days' GROUP BY 1 ORDER BY 1",(s,))
        rows = cur.fetchall()
        chart_data[s] = {"labels": [r[0].strftime('%d.%m') for r in rows], "uptime": [float(r[2]) for r in rows], "resp": [float(r[1]) for r in rows]}

        is_err = (last_st != 200 or (last_resp or 0) > 20 or (last_ssl or 999) <= 20)
        html += f"""<tr class="{'row-err' if is_err else ''}">
            <td><a href="https://{s}" target="_blank" style="color:inherit"><strong>{s}</strong></a></td>
            <td class="{'txt-err' if (upt or 0) < 99 else 'txt-ok'}">{upt or 0}%</td>
            <td class="{'txt-err' if (last_resp or 0) > 20 else ''}">{round(last_resp or 0, 2)} сек</td>
            <td class="{'txt-err' if (last_ssl or 999) <= 20 else ''}">{last_ssl if last_ssl is not None else 'N/A'}</td>
            <td>{down_sec or 0} сек</td></tr>"""

    html += """</tbody></table></div><div id="t2" class="tab-content"><div class="grid">"""
    for s in SITES: html += f"<div class='kpi-card'><h4>{s}</h4><canvas id='c-{s.replace('.','_')}'></canvas></div>"
    
    # Вкладка Ошибки
    html += """</div></div><div id="t3" class="tab-content"><table><thead><tr><th>Время</th><th>Сайт</th><th>Статус</th><th>Ответ</th><th>SSL</th></tr></thead><tbody>"""
    cur.execute("SELECT timestamp, site, status, response_time, ssl_days FROM logs WHERE (status != 200 OR response_time > 20) AND timestamp > NOW() - INTERVAL '30 days' ORDER BY timestamp DESC LIMIT 100")
    for err in cur.fetchall():
        html += f"<tr><td>{err[0].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')}</td><td>{err[1]}</td><td class='txt-err'>{err[2]}</td><td>{round(err[3],2)}</td><td>{err[4]}</td></tr>"
    
    html += """</tbody></table></div></div><script>
        function tab(e, n) {
            var i, x = document.getElementsByClassName("tab-content"), b = document.getElementsByClassName("tab-btn");
            for (i=0; i<x.length; i++) x[i].className = "tab-content";
            for (i=0; i<b.length; i++) b[i].className = "tab-btn";
            document.getElementById(n).className = "tab-content active-content";
            e.currentTarget.className += " active";
        }
    """
    for s, d in chart_data.items():
        html += f"new Chart(document.getElementById('c-{s.replace('.','_')}'), {{type:'line', data:{{labels:{json.dumps(d['labels'])}, datasets:[{{label:'Uptime', data:{json.dumps(d['uptime'])}, borderColor:'#10b981', yAxisID:'y', tension:0.3}},{{label:'Ответ', data:{json.dumps(d['resp'])}, borderColor:'#3b82f6', yAxisID:'y1', tension:0.3}}]}}, options:{{scales:{{y:{{min:0, max:105, ticks:{{display:true}} }},y1:{{position:'right', grid:{{drawOnChartArea:false}}}} }} }} }});"
    html += "</script></body></html>"
    cur.close(); conn.close(); return html

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
