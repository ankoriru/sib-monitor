import datetime
import ssl
import socket
import requests
import psycopg2 
import json
from psycopg2.extras import DictCursor
import threading
import time
import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

# --- КОНФИГУРАЦИЯ ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siburdb_user:IbaJQKbh6DQ5z9i3J82EWRJFnl1z3gkt@dpg-d797355m5p6s739tgr1g-a/siburdb")
TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "8305761464:AAE--AkY662Cm3DlKsrd8tcBnxXeTOLrO9I")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "-5282148036")

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

def get_historical_data(site, days=30):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        # Группируем данные по дням для графиков
        cur.execute("""
            SELECT 
                DATE(timestamp) as date,
                ROUND(AVG(response_time)::numeric, 3) as avg_resp,
                ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / COUNT(*))::numeric, 2) as uptime
            FROM logs 
            WHERE site = %s AND timestamp > NOW() - INTERVAL %s
            GROUP BY DATE(timestamp)
            ORDER BY DATE(timestamp) ASC
        """, (site, f'{days} days'))
        rows = cur.fetchall()
        conn.close()
        return {
            "labels": [r['date'].strftime('%d.%m') for r in rows],
            "uptime": [float(r['uptime']) for r in rows],
            "resp": [float(r['avg_resp']) for r in rows]
        }
    except:
        return {"labels": [], "uptime": [], "resp": []}

# --- ВОРКЕР (БЕЗ ИЗМЕНЕНИЙ) ---
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
    while True:
        for site in SITES:
            try:
                start = time.time()
                r = requests.get(f"https://{site}", timeout=10)
                status, resp_time = r.status_code, time.time() - start
            except: status, resp_time = 0, 0
            ssl_d = get_real_ssl(site)
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time, ssl_days) VALUES (%s, %s, %s, %s)",
                           (site, status, resp_time, ssl_d))
                conn.commit()
                cur.close()
                conn.close()
            except: pass
        time.sleep(300)

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

@app.get("/", response_class=HTMLResponse)
async def index():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
    html = """
    <html>
    <head>
        <title>Sibur Advanced Monitor</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; }
            .container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 8px; shadow: 0 2px 10px rgba(0,0,0,0.1); }
            table { width: 100%; border-collapse: collapse; margin-bottom: 40px; }
            th, td { padding: 12px; border-bottom: 1px solid #eee; text-align: left; }
            th { background: #007bff; color: white; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 20px; }
            .chart-card { background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 8px; }
            .up { color: #28a745; font-weight: bold; }
            .down { color: #dc3545; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 Мониторинг систем СИБУР</h1>
            <table>
                <tr><th>Сайт</th><th>Uptime</th><th>Ответ</th><th>SSL</th></tr>
    """
    
    chart_data = {}

    for site in SITES:
        history = get_historical_data(site)
        chart_data[site] = history
        
        cur.execute("SELECT status, response_time, ssl_days FROM logs WHERE site = %s ORDER BY timestamp DESC LIMIT 1", (site,))
        last = cur.fetchone()
        
        uptime_val = history['uptime'][-1] if history['uptime'] else 0
        status_class = "up" if last and last['status'] == 200 else "down"
        
        html += f"""
            <tr>
                <td><strong>{site}</strong></td>
                <td class="{status_class}">{uptime_val}%</td>
                <td>{round(last['response_time'], 3) if last else 0} сек</td>
                <td>{last['ssl_days'] if last else 'N/A'} дн.</td>
            </tr>
        """
    
    html += """</table><h2>📈 Графики производительности (30 дней)</h2><div class="grid">"""
    
    for site in SITES:
        html += f"""
            <div class="chart-card">
                <h3>{site}</h3>
                <canvas id="chart-{site.replace('.', '_')}"></canvas>
            </div>
        """

    html += """</div></div><script>"""
    
    # Передаем данные в JS
    for site, data in chart_data.items():
        safe_id = site.replace('.', '_')
        html += f"""
        new Chart(document.getElementById('chart-{safe_id}'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(data['labels'])},
                datasets: [
                    {{ label: 'Uptime %', data: {json.dumps(data['uptime'])}, borderColor: '#28a745', yAxisID: 'y' }},
                    {{ label: 'Ответ (сек)', data: {json.dumps(data['resp'])}, borderColor: '#007bff', yAxisID: 'y1' }}
                ]
            }},
            options: {{
                scales: {{
                    y: {{ type: 'linear', position: 'left', min: 0, max: 100 }},
                    y1: {{ type: 'linear', position: 'right', grid: {{ drawOnChartArea: false }} }}
                }}
            }}
        }});
        """
    
    html += "</script></body></html>"
    cur.close()
    conn.close()
    return html
