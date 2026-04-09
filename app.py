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
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    while True:
        for site in SITES:
            curr_status, resp_time = 0, 25.0
            try:
                start = time.time()
                try:
                    r = requests.get(f"https://{site}", timeout=25, headers=headers, allow_redirects=True)
                    curr_status, resp_time = r.status_code, time.time() - start
                except: curr_status, resp_time = 0, 25.0

                if last_status_map[site] == 200 and curr_status != 200:
                    send_tg_msg(f"🚨 {site} DOWN! Код: {curr_status}")
                elif last_status_map[site] != 200 and curr_status == 200:
                    send_tg_msg(f"✅ {site} UP!")

                last_status_map[site] = curr_status
                conn = get_db_connection(); cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time) VALUES (%s, %s, %s)", (site, curr_status, resp_time))
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

    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2) as up FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'")
    s30 = cur.fetchone()
    cur.execute("SELECT DISTINCT ON (site) site, status, response_time FROM logs ORDER BY site, timestamp DESC")
    latest_states = {r['site']: r for r in cur.fetchall()}
    cur.execute("SELECT site, COUNT(*) FILTER (WHERE status != 200)*60 as down_sec FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY site")
    stats_30d = {r['site']: r for r in cur.fetchall()}

    html = f"""
    <html><head><title>Мониторинг сайтов</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; color: #1e293b; }}
        .container {{ max-width: 1400px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .tabs {{ display: flex; gap: 8px; margin-bottom: 20px; }}
        .tab-btn {{ padding: 10px 20px; border: none; background: #e2e8f0; border-radius: 6px; cursor: pointer; font-weight: bold; }}
        .tab-btn.active {{ background: #3b82f6; color: white; }}
        .tab-content {{ display: none; }} .active-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
        .txt-err {{ color: #dc2626; font-weight: bold; }} .txt-ok {{ color: #16a34a; font-weight: bold; }}
    </style></head><body><div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
            <h1>📊 Мониторинг сайтов</h1>
            <span style="color: #64748b;">Обновлено: {now_msk}</span>
        </div>
        <div class="tabs">
            <button class="tab-btn active" onclick="tab(event, 't1')">Текущий статус</button>
            <button class="tab-btn" onclick="tab(event, 't3')">Инциденты (Лог падений)</button>
        </div>

        <div id="t1" class="tab-content active-content">
            <table><thead><tr><th>Сайт</th><th>Статус</th><th>Ответ</th><th>Простой (30д)</th></tr></thead><tbody>
    """
    for s in sorted(SITES):
        st = latest_states.get(s, {'status':0,'response_time':0})
        d_sec = stats_30d.get(s, {'down_sec':0})['down_sec']
        h, m = d_sec//3600, (d_sec%3600)//60
        html += f"<tr><td><strong>{s}</strong></td><td><span class='{'txt-ok' if st['status']==200 else 'txt-err'}'>{'Online' if st['status']==200 else 'Offline'}</span></td><td>{round(st['response_time'],2)}с</td><td>{h}ч {m}м</td></tr>"
    
    html += """</tbody></table></div><div id="t3" class="tab-content">
            <table><thead><tr><th>Время инцидента (МСК)</th><th>Сайт</th><th>Длительность</th><th>Код ошибки</th><th>Описание</th></tr></thead><tbody>"""
    
    cur.execute("""
        WITH status_logs AS (
            SELECT site, timestamp, status, response_time,
            CASE WHEN (status != 200 OR response_time > 20) THEN 1 ELSE 0 END as is_err,
            LAG(status) OVER (PARTITION BY site ORDER BY timestamp) as prev_status,
            LAG(response_time) OVER (PARTITION BY site ORDER BY timestamp) as prev_resp
            FROM logs
        ),
        incident_starts AS (
            SELECT *,
            CASE WHEN is_err = 1 AND (prev_status = 200 OR prev_status IS NULL) THEN 1 ELSE 0 END as start_flag
            FROM status_logs
        ),
        incident_groups AS (
            SELECT *,
            SUM(start_flag) OVER (PARTITION BY site ORDER BY timestamp) as grp_id
            FROM incident_starts WHERE is_err = 1
        )
        SELECT 
            site, 
            MIN(timestamp) as start_time, 
            EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp)))/60 + 1 as dur,
            STRING_AGG(DISTINCT status::text, ', ') as codes,
            CASE 
                WHEN MAX(status) = 0 THEN 'Timeout / No Connection'
                WHEN MAX(status) = 502 THEN 'Bad Gateway'
                WHEN MAX(status) = 200 THEN 'Slow Response (>20s)'
                ELSE 'Server Error'
            END as descr
        FROM incident_groups
        GROUP BY site, grp_id ORDER BY start_time DESC LIMIT 50
    """)
    
    for err in cur.fetchall():
        dur = int(err[2])
        dur_str = f"{dur} мин" if dur < 60 else f"{dur//60}ч {dur%60}м"
        html += f"<tr><td>{err[1].astimezone(TZ_MOSCOW).strftime('%d.%m %H:%M')}</td><td><strong>{err[0]}</strong></td><td class='txt-err'>{dur_str}</td><td>{err[3]}</td><td>{err[4]}</td></tr>"
    
    html += """</tbody></table></div></div>
    <script>function tab(e,n){
        var i,x=document.getElementsByClassName('tab-content'),b=document.getElementsByClassName('tab-btn');
        for(i=0;i<x.length;i++)x[i].className='tab-content';
        for(i=0;i<b.length;i++)b[i].className='tab-btn';
        document.getElementById(n).className='tab-content active-content';
        e.currentTarget.className+=' active';
    }</script></body></html>"""
    
    cur.close(); conn.close(); return html

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
