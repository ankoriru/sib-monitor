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
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "-5282148036")
TZ_MOSCOW = pytz.timezone('Europe/Moscow')

SITES = [
    "sibur.ru", "eshop.sibur.ru", "srm.sibur.ru",
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

def send_tg(text):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        r = requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
        print(f"TG Status: {r.status_code}, Response: {r.text}")
    except Exception as e:
        print(f"TG Error: {e}")

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

def get_real_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return (exp - datetime.datetime.utcnow()).days
    except: return -1

def check_worker():
    last_status_map = {}
    last_latency_map = {}
    last_ssl_notification_date = None
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/ *;q=0.8',
        'Referer': 'https://www.google.com/'
    }

    while True:
        now_msk = datetime.datetime.now(TZ_MOSCOW)
        print(f"Current MSK Time: {now_msk.strftime('%H:%M:%S')}") # Лог для проверки времени на Render

        # ИСПРАВЛЕННЫЙ БЛОК SSL: Проверяем час (9), а не точную минуту
        if now_msk.hour == 9 and last_ssl_notification_date != now_msk.date():
            print("Running scheduled SSL check at 09:00 MSK...")
            ssl_alerts = []
            for site in SITES:
                d = get_real_ssl(site)
                if 0 <= d <= 20:
                    ssl_alerts.append(f"• {site}: {d} дн.")
            
            if ssl_alerts:
                send_tg(f"📅 Ежедневный отчет SSL (<=20 дней):\n" + "\n".join(ssl_alerts))
            else:
                print("No SSL issues found today.")
            
            last_ssl_notification_date = now_msk.date()

        for site in SITES:
            try:
                start = time.time()
                try:
                    r = requests.get(f"https://{site}", timeout=25, headers=headers)
                    curr_status, resp_time = r.status_code, time.time() - start
                except:
                    curr_status, resp_time = 0, 25.0
                
                ssl_d = get_real_ssl(site)
                
                if site not in last_status_map: last_status_map[site] = 200
                if site not in last_latency_map: last_latency_map[site] = False

                # Доступность
                if last_status_map[site] == 200 and curr_status != 200:
                    send_tg(f"🚨 {site} DOWN!\nКод: {curr_status}")
                elif last_status_map[site] != 200 and curr_status == 200:
                    send_tg(f"✅ {site} UP!")
                
                # Задержка
                if resp_time >= 20.0 and not last_latency_map[site]:
                    send_tg(f"🐢 ЗАДЕРЖКА! {site}: {round(resp_time, 2)} сек.")
                    last_latency_map[site] = True
                elif resp_time < 10.0 and last_latency_map[site]:
                    send_tg(f"⚡️ ВОССТАНОВЛЕНИЕ! {site}: {round(resp_time, 2)} сек.")
                    last_latency_map[site] = False

                last_status_map[site] = curr_status
                
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
    
    cur.execute("SELECT COUNT(DISTINCT site) FROM logs l1 WHERE status=200 AND timestamp=(SELECT MAX(timestamp) FROM logs l2 WHERE l1.site=l2.site)")
    sites_online = cur.fetchone()[0] or 0
    cur.execute("SELECT site, ssl_days FROM logs l1 WHERE (ssl_days <= 20 OR ssl_days < 0) AND timestamp=(SELECT MAX(timestamp) FROM logs l2 WHERE l1.site=l2.site)")
    ssl_issues = cur.fetchall()

    html = f"""
    <html><head><title>Мониторинг</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #f8fafc; padding: 20px; }}
        .container {{ max-width: 1300px; margin: auto; background: white; padding: 25px; border-radius: 12px; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .kpi-card {{ background: #fff; padding: 15px; border-radius: 10px; border: 1px solid #e2e8f0; border-top: 4px solid #3b82f6; }}
        .danger-card {{ border-top-color: #ef4444; background: #fef2f2; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
        .row-err {{ background-color: #fff1f2; }}
        .refresh-btn {{ background: #3b82f6; color: white; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; }}
    </style></head><body><div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
            <h1>📊 Мониторинг</h1>
            <button class="refresh-btn" onclick="location.reload()">🔄 {now_msk}</button>
        </div>
        <div class="kpi-grid">
            <div class="kpi-card"><span>Доступно</span><br><strong>{sites_online} / {len(SITES)}</strong></div>
            <div class="kpi-card {'danger-card' if ssl_issues else ''}"><span>SSL (<=20д)</span><br><strong>{len(ssl_issues)}</strong></div>
        </div>
        <table><thead><tr><th>Сайт</th><th>Uptime 30д</th><th>Ответ</th><th>SSL</th></tr></thead><tbody>
    """
    sorted_sites = PRIORITY_SITES + sorted([s for s in SITES if s not in PRIORITY_SITES])
    for s in sorted_sites:
        cur.execute("""SELECT ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric, 2),
            (SELECT response_time FROM logs WHERE site=%s ORDER BY timestamp DESC LIMIT 1),
            (SELECT ssl_days FROM logs WHERE site=%s ORDER BY timestamp DESC LIMIT 1),
            (SELECT status FROM logs WHERE site=%s ORDER BY timestamp DESC LIMIT 1)
            FROM logs WHERE site=%s AND timestamp > NOW() - INTERVAL '30 days'""", (s, s, s, s))
        upt, last_resp, last_ssl, last_st = cur.fetchone()
        is_err = (last_st != 200 or (last_resp or 0) > 20 or (last_ssl or 999) <= 20)
        html += f"<tr class='{'row-err' if is_err else ''}'><td><strong>{'⭐ ' if s in PRIORITY_SITES else ''}{s}</strong></td><td>{upt or 0}%</td><td>{round(last_resp or 0, 2)}с</td><td>{last_ssl}д</td></tr>"
    html += "</tbody></table></div></body></html>"; cur.close(); conn.close(); return html

# --- СКРИПТ ПОЛНОЙ ОЧИСТКИ SRM ---
@app.get("/admin/clear-srm-full")
async def clear_srm_full(auth: bool = Depends(check_auth)):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("DELETE FROM logs WHERE site = 'srm.sibur.ru'")
        deleted_rows = cur.rowcount
        conn.commit(); cur.close(); conn.close()
        return {"status": "success", "message": f"Удалено {deleted_rows} записей для srm.sibur.ru."}
    except Exception as e: return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
