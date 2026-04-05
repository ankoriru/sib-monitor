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

# --- ФУНКЦИИ БД ---
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
        cur.execute("""
            SELECT 
                DATE(timestamp) as date,
                ROUND(AVG(response_time)::numeric, 3) as avg_resp,
                ROUND((COUNT(*) FILTER (WHERE status = 200) * 100.0 / NULLIF(COUNT(*), 0))::numeric, 2) as uptime
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

# --- ГЛАВНАЯ СТРАНИЦА ---
@app.get("/", response_class=HTMLResponse)
async def index():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
    current_time = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    
    html = f"""
    <html>
    <head>
        <title>Sibur Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f6; margin: 0; padding: 20px; }}
            .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }}
            
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 20px; }}
            .refresh-btn {{ background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: 0.3s; }}
            .refresh-btn:hover {{ background: #0056b3; }}
            .last-update {{ color: #666; font-size: 0.9em; }}

            .tabs {{ display: flex; gap: 10px; margin-bottom: 20px; }}
            .tab-btn {{ padding: 10px 25px; border: none; background: #e9ecef; border-radius: 6px; cursor: pointer; font-weight: 600; color: #495057; }}
            .tab-btn.active {{ background: #007bff; color: white; }}
            
            .tab-content {{ display: none; }}
            .tab-content.active {{ display: block; }}

            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #edf2f7; }}
            th {{ background: #f8f9fa; color: #4a5568; text-transform: uppercase; font-size: 0.85em; letter-spacing: 0.05em; }}
            tr:hover {{ background: #fcfcfc; }}
            
            .site-link {{ color: #007bff; text-decoration: none; font-weight: 500; }}
            .site-link:hover {{ text-decoration: underline; }}
            
            .up {{ color: #2ecc71; font-weight: bold; }}
            .down {{ color: #e74c3c; font-weight: bold; }}

            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 25px; }}
            .chart-card {{ border: 1px solid #edf2f7; border-radius: 10px; padding: 15px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h1 style="margin:0; color: #2d3748;">Мониторинг СИБУР</h1>
                    <span class="last-update">Данные актуальны на: <strong>{current_time}</strong></span>
                </div>
                <button class="refresh-btn" onclick="location.reload()">🔄 Обновить данные</button>
            </div>

            <div class="tabs">
                <button class="tab-btn active" onclick="openTab(event, 'table-view')">📊 Таблица</button>
                <button class="tab-btn" onclick="openTab(event, 'charts-view')">📈 Графики (30д)</button>
            </div>

            <div id="table-view" class="tab-content active">
                <table>
                    <thead>
                        <tr>
                            <th>Сайт</th>
                            <th>Uptime (30д)</th>
                            <th>Последний ответ</th>
                            <th>SSL Сертификат</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    chart_data = {}

    for site in SITES:
        history = get_historical_data(site)
        chart_data[site] = history
        
        cur.execute("SELECT status, response_time, ssl_days FROM logs WHERE site = %s ORDER BY timestamp DESC LIMIT 1", (site,))
        last = cur.fetchone()
        
        uptime_val = history['uptime'][-1] if history['uptime'] else 0
        status_class = "up" if last and last['status'] == 200 else "down"
        resp_time = round(last['response_time'], 3) if last else 0
        ssl_days = last['ssl_days'] if last and last['ssl_days'] is not None else "N/A"
        
        html += f"""
            <tr>
                <td><a href="https://{site}" target="_blank" class="site-link">{site}</a></td>
                <td class="{status_class}">{uptime_val}%</td>
                <td>{resp_time} сек</td>
                <td>{ssl_days} дн.</td>
            </tr>
        """
    
    html += """
                    </tbody>
                </table>
            </div>

            <div id="charts-view" class="tab-content">
                <div class="grid">
    """
    
    for site in SITES:
        html += f"""
            <div class="chart-card">
                <h3 style="margin-top:0; color:#4a5568; font-size: 1em;">{site}</h3>
                <canvas id="chart-{site.replace('.', '_')}"></canvas>
            </div>
        """

    html += """
                </div>
            </div>
        </div>

        <script>
            function openTab(evt, tabName) {
                var i, tabcontent, tablinks;
                tabcontent = document.getElementsByClassName("tab-content");
                for (i = 0; i < tabcontent.length; i++) {
                    tabcontent[i].classList.remove("active");
                }
                tablinks = document.getElementsByClassName("tab-btn");
                for (i = 0; i < tablinks.length; i++) {
                    tablinks[i].classList.remove("active");
                }
                document.getElementById(tabName).classList.add("active");
                evt.currentTarget.classList.add("active");
            }
    """
    
    for site, data in chart_data.items():
        safe_id = site.replace('.', '_')
        html += f"""
        new Chart(document.getElementById('chart-{safe_id}'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(data['labels'])},
                datasets: [
                    {{ label: 'Uptime %', data: {json.dumps(data['uptime'])}, borderColor: '#2ecc71', backgroundColor: 'rgba(46, 204, 113, 0.1)', fill: true, tension: 0.3, yAxisID: 'y' }},
                    {{ label: 'Ответ (сек)', data: {json.dumps(data['resp'])}, borderColor: '#3498db', tension: 0.3, yAxisID: 'y1' }}
                ]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{ type: 'linear', position: 'left', min: 0, max: 105, display: false }},
                    y1: {{ type: 'linear', position: 'right', grid: {{ drawOnChartArea: false }} }}
                }},
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});
        """
    
    html += "</script></body></html>"
    cur.close()
    conn.close()
    return html

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
