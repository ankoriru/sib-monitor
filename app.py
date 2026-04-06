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

# Список сайтов с учетом новых адресов
SITES = [
    "sibur.ru", "eshop.sibur.ru", "srm.sibur.ru", # Приоритетные
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

PRIORITY_SITES = ["sibur.ru", "eshop.sibur.ru", "srm.sibur.ru"]

app = FastAPI()

# --- АВТОРИЗАЦИЯ ---
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

# --- БД ---
def get_db_connection(): return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS logs 
                  (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                   status INTEGER, response_time REAL, ssl_days INTEGER)''')
    conn.commit(); cur.close(); conn.close()

def get_stats_period(hours=24):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute(f"""SELECT 
            ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2), 
            ROUND(AVG(response_time)::numeric, 3) 
            FROM logs WHERE timestamp > NOW() - INTERVAL '{hours} hours'""")
        res = cur.fetchone(); conn.close()
        return res if res[0] is not None else (0, 0)
    except: return (0, 0)

# --- ВОРКЕР И ОПОВЕЩЕНИЯ ---
def check_worker():
    last_status_map = {}
    last_latency_map = {}
    last_ssl_notification_date = None
    
    # Имитация реального браузера для обхода 503 ошибок
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
    }

    while True:
        now_msk = datetime.datetime.now(TZ_MOSCOW)
        
        # Ежедневный отчет в 09:00 МСК
        if now_msk.hour == 9 and last_ssl_notification_date != now_msk.date():
            ssl_alerts = []
            for site in SITES:
                d = get_real_ssl(site)
                if 0 <= d <= 20: ssl_alerts.append(f"{site} ({d}д)")
            if ssl_alerts:
                requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                              json={"chat_id": TELEGRAM_CHAT_ID, "text": f"📅 Ежедневный отчет SSL (<=20д):\n" + "\n".join(ssl_alerts)})
            last_ssl_notification_date = now_msk.date()

        for site in SITES:
            try:
                start = time.time()
                try:
                    # Добавлены headers для предотвращения 503 ошибок
                    r = requests.get(f"https://{site}", timeout=25, headers=headers)
                    curr_status, resp_time = r.status_code, time.time() - start
                except: curr_status, resp_time = 0, 25.0
                
                ssl_d = get_real_ssl(site)
                prev_status = last_status_map.get(site, 200)
                was_slow = last_latency_map.get(site, False)

                # Уведомления: Down / Up
                if prev_status == 200 and curr_status != 200:
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"🚨 {site} DOWN! Код: {curr_status}"})
                elif prev_status != 200 and curr_status == 200:
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"✅ {site} UP!"})
                
                # Уведомления: Latency
                if resp_time > 20 and not was_slow:
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"🐢 ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек."})
                    last_latency_map[site] = True
                elif resp_time < 10 and was_slow:
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": f"⚡️ СКОРОСТЬ ВОССТАНОВЛЕНА! {site}: {round(resp_time, 2)} сек."})
                    last_latency_map[site] = False

                last_status_map[site] = curr_status
                conn = get_db_connection(); cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time, ssl_days) VALUES (%s, %s, %s, %s)", (site, curr_status, resp_time, ssl_d))
                conn.commit(); cur.close(); conn.close()
            except: pass
        time.sleep(300)

def get_real_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return (exp - datetime.datetime.utcnow()).days
    except: return -1

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

# --- ИНТЕРФЕЙС ---
@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")
    
    up24, resp24 = get_stats_period(24)
    up30, resp30 = get_stats_period(720)
    
    cur.execute("SELECT COUNT(DISTINCT site) FROM logs l1 WHERE status=200 AND timestamp=(SELECT MAX(timestamp) FROM logs l2 WHERE l1.site=l2.site)")
    sites_online = cur.fetchone()[0] or 0
    cur.execute("SELECT COUNT(DISTINCT site) FROM logs l1 WHERE (status != 200 OR response_time > 20) AND timestamp=(SELECT MAX(timestamp) FROM logs l2 WHERE l1.site=l2.site)")
    incident_count = cur.fetchone()[0] or 0
    cur.execute("SELECT site, ssl_days FROM logs l1 WHERE (ssl_days <= 20 OR ssl_days < 0) AND timestamp=(SELECT MAX(timestamp) FROM logs l2 WHERE l1.site=l2.site)")
    ssl_issues = cur.fetchall()

    html = f"""
    <html><head><title>Мониторинг сайтов</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; color: #1e293b; }}
        .container {{ max-width: 1300px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; border-bottom: 2px solid #f1f5f9; padding-bottom: 15px; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .kpi-card {{ background: #fff; padding: 15px; border-radius: 10px; border: 1px solid #e2e8f0; border-top: 4px solid #3b82f6; }}
        .kpi-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; }}
        .kpi-val {{ font-size: 20px; font-weight: 800; display: block; margin-top: 5px; }}
        .danger-card {{ border-top-color: #ef4444; color: #991b1b; background: #fef2f2; }}
        .alert-box {{ background: #fff5f5; border: 1px solid #feb2b2; padding: 15px; border-radius: 8px; margin-bottom: 20px; color: #c53030; font-weight: 600; }}
        .tabs {{ display: flex; gap: 8px; margin-bottom: 15px; }}
        .tab-btn {{ padding: 10px 20px; border: none; background: #e2e8f0; border-radius: 6px; cursor: pointer; font-weight: bold; }}
        .tab-btn.active {{ background: #3b82f6; color: white; }}
        .tab-content {{ display: none; }} .active-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
        .row-err {{ background-color: #fff1f2; }}
        .txt-err {{ color: #dc2626; font-weight: bold; }}
        .txt-ok {{ color: #16a34a; font-weight: bold; }}
        .refresh-btn {{ background: #3b82f6; color: white; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: 0.2s; }}
        .refresh-btn:hover {{ background: #2563eb; }}
    </style></head><body><div class="container">
        <div class="header">
            <h1 style="margin:0">📊 Мониторинг сайтов</h1>
            <div style="text-align:right">
                <button class="refresh-btn" onclick="location.reload()">🔄 Обновить: {now_msk}</button>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><span class="kpi-label">Доступно</span><span class="kpi-val">{sites_online} / {len(SITES)}</span></div>
            <div class="kpi-card"><span class="kpi-label">Uptime (24ч / 30д)</span><span class="kpi-val">{up24}% / {up30}%</span></div>
            <div class="kpi-card"><span class="kpi-label">Ответ (24ч / 30д)</span><span class="kpi-val">{resp24}с / {resp30}с</span></div>
            <div class="kpi-card { 'danger-card' if incident_count > 0 else '' }"><span class="kpi-label">Инциденты</span><span class="kpi-val">{incident_count}</span></div>
            <div class="kpi-card { 'danger-card' if ssl_issues else '' }"><span class="kpi-label">SSL под угрозой</span><span class="kpi-val">{len(ssl_issues)}</span></div>
        </div>

        {" <div class='alert-box'>⚠️ Внимание! Истекают SSL: " + ", ".join([f"{x[0]} ({x[1]}д)" for x in ssl_issues]) + "</div>" if ssl_issues else ""}

        <div class="tabs">
            <button class="tab-btn active" onclick="tab(event, 't1')">Список сайтов</button>
            <button class="tab-btn" onclick="tab(event, 't2')">Аналитика (Графики)</button>
            <button class="tab-btn" onclick="tab(event, 't3')">Журнал ошибок</button>
        </div>

        <div id="t1" class="tab-content active-content">
            <table><thead><tr><th>Сайт</th><th>Uptime (30д)</th><th>Ответ</th><th>SSL (дн)</th><th>Простой (30д)</th></tr></thead><tbody>
    """
    
    chart_data = {}
    
    # Сортировка: Приоритетные в начале, остальные по алфавиту
    other_sites = sorted([s for s in SITES if s not in PRIORITY_SITES])
    sorted_sites = PRIORITY_SITES + other_sites

    for s in sorted_sites:
        cur.execute("""SELECT 
            ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric, 2),
            COUNT(*) FILTER (WHERE status != 200)*300,
            (SELECT response_time FROM logs WHERE site=%s ORDER BY timestamp DESC LIMIT 1),
            (SELECT ssl_days FROM logs WHERE site=%s ORDER BY timestamp DESC LIMIT 1),
            (SELECT status FROM logs WHERE site=%s ORDER BY timestamp DESC LIMIT 1)
            FROM logs WHERE site=%s AND timestamp > NOW() - INTERVAL '30 days'""", (s, s, s, s))
        upt, down_sec, last_resp, last_ssl, last_st = cur.fetchone()
        
        cur.execute("SELECT DATE(timestamp), ROUND(AVG(response_time)::numeric,2), ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/COUNT(*))::numeric,2) FROM logs WHERE site=%s AND timestamp > NOW() - INTERVAL '30 days' GROUP BY 1 ORDER BY 1",(s,))
        rows = cur.fetchall()
        chart_data[s] = {"labels": [r[0].strftime('%d.%m') for r in rows], "uptime": [float(r[2]) for r in rows], "resp": [float(r[1]) for r in rows]}

        is_err = (last_st != 200 or (last_resp or 0) > 20 or (last_ssl or 999) <= 20)
        display_name = f"⭐ {s}" if s in PRIORITY_SITES else s
        
        html += f"""<tr class="{'row-err' if is_err else ''}">
            <td><a href="https://{s}" target="_blank" style="color:inherit"><strong>{display_name}</strong></a></td>
            <td class="{'txt-err' if (upt or 0) < 99 else 'txt-ok'}">{upt or 0}%</td>
            <td class="{'txt-err' if (last_resp or 0) > 20 else ''}">{round(last_resp or 0, 2)} сек</td>
            <td class="{'txt-err' if (last_ssl or 999) <= 20 else ''}">{last_ssl if last_ssl is not None else 'N/A'}</td>
            <td>{down_sec or 0} сек</td></tr>"""

    html += """</tbody></table></div>
        <div id="t2" class="tab-content"><div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 15px;">"""
    for s in sorted_sites: html += f"<div class='kpi-card'><h4>{'⭐ ' if s in PRIORITY_SITES else ''}{s}</h4><canvas id='c-{s.replace('.','_')}'></canvas></div>"
    
    html += """</div></div><div id="t3" class="tab-content"><table><thead><tr><th>Время (МСК)</th><th>Сайт</th><th>Статус</th><th>Ответ</th><th>SSL</th></tr></thead><tbody>"""
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

    # --- ВРЕМЕННЫЙ СКРИПТ ОЧИСТКИ (Удалить после использования) ---
@app.get("/admin/clear-srm-logs")
async def clear_srm_logs(auth: bool = Depends(check_auth)):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Удаляем только ошибочные записи для конкретного сайта
        cur.execute("DELETE FROM logs WHERE site = 'srm.sibur.ru' AND status != 200")
        deleted_rows = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "success", "message": f"Удалено {deleted_rows} ошибочных записей для srm.sibur.ru"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

