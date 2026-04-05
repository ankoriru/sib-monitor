
import datetime
import ssl
import socket
import requests
import psycopg2 # Библиотека для PostgreSQL
from psycopg2.extras import DictCursor
import threading
import time
import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

# --- КОНФИГУРАЦИЯ ---
# Render автоматически подставляет DATABASE_URL, если ты свяжешь сервисы
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

# --- РАБОТА С POSTGRESQL ---
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

def get_stats(site, days=30):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                COUNT(*) FILTER (WHERE status = 200), 
                COUNT(*),
                AVG(response_time)
            FROM logs 
            WHERE site = %s AND timestamp > NOW() - INTERVAL %s""", (site, f'{days} days'))
        up, total, avg_time = cur.fetchone()
        conn.close()
        uptime = (up / total * 100) if total and total > 0 else 0
        return round(uptime, 2), round(avg_time or 0, 3)
    except:
        return 0, 0

# --- ПРОВЕРКИ ---
def get_real_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return (expire_date - datetime.datetime.utcnow()).days
    except:
        return -1

def check_worker():
    while True:
        for site in SITES:
            try:
                start = time.time()
                r = requests.get(f"https://{site}", timeout=10)
                status = r.status_code
                resp_time = time.time() - start
            except:
                status, resp_time = 0, 0
            
            ssl_d = get_real_ssl(site)
            
            # Сохранение в Postgres
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time, ssl_days) VALUES (%s, %s, %s, %s)",
                           (site, status, resp_time, ssl_d))
                conn.commit()
                cur.close()
                conn.close()
            except Exception as e:
                print(f"DB Error: {e}")

            # Telegram уведомления
            if status != 200:
                requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                              json={"chat_id": TELEGRAM_CHAT_ID, "text": f"🚨 {site} DOWN! Код: {status}"})
        
        time.sleep(300)

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

@app.get("/", response_class=HTMLResponse)
async def index():
    # Генерируем HTML аналогично предыдущему примеру, используя данные из Postgres
    # (Код HTML остается таким же, как в прошлом ответе)
    return "HTML Dashboard Code Here"

if __name__ == "__main__":
    import uvicorn
    # На Render порт берется из переменной окружения
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
