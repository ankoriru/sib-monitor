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

# --- АВТОРИЗАЦИЯ ---
def check_auth(request: Request):
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, headers={"WWW-Authenticate": "Basic"})
    try:
        scheme, credentials = auth.split()
        decoded = base64.b64decode(credentials).decode("ascii")
        username, password = decoded.split(":")
        if username == "sibur" and password == "sibur":
            return True
    except: pass
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, headers={"WWW-Authenticate": "Basic"})

# --- РАБОТА С БД ---
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS logs 
                  (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                   status INTEGER, response_time REAL, ssl_days INTEGER)''')
    conn.commit()
    cur.close()
    conn.close()

def get_global_stats(hours=24):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(f"SELECT ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2), ROUND(AVG(response_time)::numeric, 3) FROM logs WHERE timestamp > NOW() - INTERVAL '{hours} hours'")
        res = cur.fetchone()
        conn.close()
        return res if res[0] is not None else (0, 0)
    except: return (0, 0)

def get_historical_data(site, days=30):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("""SELECT DATE(timestamp) as d, ROUND(AVG(response_time)::numeric, 3), 
                    ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2)
                    FROM logs WHERE site = %s AND timestamp > NOW() - INTERVAL %s 
                    GROUP BY DATE(timestamp) ORDER BY DATE(timestamp) ASC""", (site, f'{days} days'))
        rows = cur.fetchall()
        conn.close()
        return {"labels": [r[0].strftime('%d.%m') for r in rows], "uptime": [float(r[2]) for r in rows], "resp": [float(r[1]) for r in rows]}
    except: return {"labels": [], "uptime": [], "resp": []}

# --- ПРОВЕРКИ ---
def get_real_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return (expire_date - datetime.datetime.utcnow()).days
    except: return -1

def check_worker():
    last_ssl_alert = {}
    while True:
        for site in SITES:
            try:
                # Получаем прошлый статус
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT status FROM logs WHERE site = %s ORDER BY timestamp DESC LIMIT 1", (site,))
                row = cur.fetchone()
                last_status = row[0] if row else 200
                cur.close(); conn.close()

                # Текущая проверка
                start = time.time()
                try:
                    r = requests.get(f"https://{site}", timeout=10)
                    current_status, resp_time = r.status_code, time.time() - start
                except: current_status, resp_time = 0, 0
                
                ssl_d = get_real_ssl(site)

                # Уведомления UP/DOWN
                if last_status == 200 and current_status != 200:
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"🚨 {site} DOWN! Код: {current_status}"})
                elif last_status != 200 and current_status == 200:
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"✅ {site} UP! Доступ восстановлен."})

                # Уведомление SSL (раз в сутки)
                if 0 <= ssl_d <= 20:
                    today = datetime.date.today().isoformat()
                    if last_ssl_alert.get(site) != today:
                        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"⚠️ SSL истекает ({ssl_d} дн.): {site}"})
                        last_ssl_alert[site] = today

                # Сохранение
                conn = get_db_connection(); cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time, ssl_days) VALUES (%s, %s, %s, %s)", (site, current_status, resp_time, ssl_d))
                conn.commit(); cur.close(); conn.close()
            except Exception as e: print(f"Worker error: {e}")
        time.sleep(300)

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

# --- ИНТЕРФЕЙС ---
@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_moscow = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")
    up24, resp24 = get_global_stats(24)
    up30, resp30 = get_global_stats(720)
    
    cur.execute("SELECT COUNT(DISTINCT site) FROM logs l1 WHERE status != 200 AND timestamp = (SELECT MAX(timestamp) FROM logs l2 WHERE l1.site = l2.site)")
    problems = cur.fetchone()[0] or 0
    cur.execute("SELECT site, ssl_days FROM logs l1 WHERE ssl_days <= 20 AND ssl_days >= 0 AND timestamp = (SELECT MAX(timestamp) FROM logs l2 WHERE l1.site = l2.site)")
    ssl_issues = cur.fetchall()

    html = f"""
    <html><head><title>Мониторинг сайтов</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f4f7f6; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .kpi-card {{ background: #fff; padding: 15px; border-radius: 10px; border-top: 4px solid #007bff; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }}
        .danger {{ border-top-color: #e74c3c !important; }}
        .kpi-val {{ font-size: 20px; font-weight: bold; display: block; }}
        .alert {{ background: #fff5f5; border: 1px solid #feb2b2; padding: 10px; border-radius: 8px; margin-bottom: 20px; color: #c53030; }}
        .tabs {{ margin-bottom: 15px; }}
        .tab-btn {{ padding: 10px 20px; border: none; background: #e2e8f0; border-radius: 5px; cursor: pointer; font-weight: bold; }}
        .tab-btn.active {{ background: #007bff; color: white; }}
        .tab-content {{ display: none; }} .active-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; border-bottom: 1px solid #eee; text-align: left; }}
        .ssl-err {{ background: #fff5f5; color: #c53030; font-weight: bold; }}
        .up {{ color: #27ae60; font-weight: bold; }} .down {{ color: #e74c3c; font-weight: bold; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 15px; }}
    </style></head><body><div class="container">
        <h1>📊 Мониторинг сайтов</h1>
        <p>Актуально на (МСК): <strong>{now_moscow}</strong></p>
        <div class="kpi-grid">
            <div class="kpi-card"><span>Uptime (24ч / 30д)</span><span class="kpi-val">{up24}% / {up30}%</span></div>
            <div class="kpi-card"><span>Средний ответ (24ч)</span><span class="kpi-val">{resp24} сек</span></div>
            <div class="kpi-card {'danger' if problems > 0 else ''}"><span>Инциденты</span><span class="kpi-val">{problems}</span></div>
            <div class="kpi-card {'danger' if ssl_issues else ''}"><span>SSL <= 20д</span><span class="kpi-val">{len(ssl_issues)}</span></div>
        </div>
        {"<div class='alert'>⚠️ <strong>Внимание!</strong> Истекают SSL: " + ", ".join([f"{x[0]} ({x[1]}д)" for x in ssl_issues]) + "</div>" if ssl_issues else ""}
        <div class="tabs">
            <button class="tab-btn active" onclick="tab(event, 't1')">Список</button>
            <button class="tab-btn" onclick="tab(event, 't2')">Графики</button>
            <button class="tab-btn" style="float:right; background:#007bff; color:white" onclick="location.reload()">🔄 Обновить</button>
        </div>
        <div id="t1" class="tab-content active-content"><table>
            <thead><tr><th>Сайт</th><th>Uptime</th><th>Ответ</th><th>SSL (дн)</th></tr></thead><tbody>
    """
    chart_data = {}
    for s in SITES:
        h = get_historical_data(s); chart_data[s] = h
        cur.execute("SELECT status, response_time, ssl_days FROM logs WHERE site = %s ORDER BY timestamp DESC LIMIT 1", (s,))
        l = cur.fetchone()
        ssl_v = l['ssl_days'] if l and l['ssl_days'] is not None else 999
        st_cl = "up" if l and l['status'] == 200 else "down"
        html += f"""<tr class="{'ssl-err' if ssl_v <= 20 else ''}">
            <td><a href="https://{s}" target="_blank" style="color:inherit"><strong>{s}</strong></a></td>
            <td class="{st_cl}">{h['uptime'][-1] if h['uptime'] else 0}%</td>
            <td>{round(l['response_time'], 3) if l else 0}</td><td>{ssl_v if ssl_v != 999 else 'N/A'}</td></tr>"""
    
    html += """</tbody></table></div><div id="t2" class="tab-content"><div class="grid">"""
    for s in SITES: html += f"<div style='border:1px solid #eee; padding:10px'><h4>{s}</h4><canvas id='c-{s.replace('.','_')}'></canvas></div>"
    html += """</div></div></div><script>
        function tab(e, n) {
            var i, x = document.getElementsByClassName("tab-content"), b = document.getElementsByClassName("tab-btn");
            for (i=0; i<x.length; i++) x[i].className = "tab-content";
            for (i=0; i<b.length; i++) b[i].className = "tab-btn";
            document.getElementById(n).className = "tab-content active-content";
            e.currentTarget.className += " active";
        }
    """
    for s, d in chart_data.items():
        html += f"new Chart(document.getElementById('c-{s.replace('.','_')}'), {{type:'line', data:{{labels:{json.dumps(d['labels'])}, datasets:[{{label:'Uptime', data:{json.dumps(d['uptime'])}, borderColor:'#27ae60', yAxisID:'y'}},{{label:'Ответ', data:{json.dumps(d['resp'])}, borderColor:'#3498db', yAxisID:'y1'}}]}}, options:{{scales:{{y:{{display:false}},y1:{{position:'right'}}}}}} }});"
    html += "</script></body></html>"
    cur.close(); conn.close(); return html

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
