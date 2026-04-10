import datetime
import ssl
import socket
import requests
import psycopg2 
import json
import base64
import pytz
import threading
import time
import os
import whois
from psycopg2.extras import DictCursor
from playwright.sync_api import sync_playwright
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import HTMLResponse

# --- КОНФИГУРАЦИЯ ---
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
    "quality-certificates.sibur.ru", "rusvinyl.ru",
    "sibur.digital", "sibur-int.com", "sibur-int.ru", "sibur-yug.ru",
    "sintez-kazan.ru", "snck.ru", "tu-sibur.ru", "vivilen.sibur.ru"
]

PRIORITY_SITES = ["sibur.ru", "eshop.sibur.ru", "shop.sibur.ru", "srm.sibur.ru", "career.sibur.ru"]

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

def get_db_connection(): return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS logs 
                  (site TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                   status INTEGER, response_time REAL, ssl_days INTEGER, domain_days INTEGER)''')
    conn.commit(); cur.close(); conn.close()

def send_tg_msg(text, photo_path=None):
    base_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/"
    try:
        if photo_path and os.path.exists(photo_path):
            with open(photo_path, 'rb') as f:
                requests.post(base_url + "sendPhoto", data={"chat_id": TELEGRAM_CHAT_ID, "caption": text}, files={"photo": f}, timeout=20)
            os.remove(photo_path)
        else:
            requests.post(base_url + "sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
    except: pass

def take_screenshot(site):
    path = f"debug_{site.replace('.','_')}.png"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            page = browser.new_page()
            page.goto(f"https://{site}", timeout=30000)
            page.screenshot(path=path)
            browser.close()
        return path
    except: return None

def get_domain_info(site):
    try:
        w = whois.whois(site)
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if exp:
            days = (exp.replace(tzinfo=None) - datetime.datetime.now()).days
            return days, exp.strftime('%d.%m.%Y')
    except: pass
    return -1, "Н/Д"

def check_worker():
    last_status = {site: 200 for site in SITES}
    fail_count = {site: 0 for site in SITES}
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    
    while True:
        for site in SITES:
            try:
                curr_status, resp_time, ssl_d, dom_d = 0, 25.0, -1, -1
                start = time.time()
                try:
                    r = requests.get(f"https://{site}", timeout=20, headers=headers, allow_redirects=True)
                    curr_status, resp_time = r.status_code, time.time() - start
                except: curr_status, resp_time = 0, 25.0

                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((site, 443), timeout=3) as sock:
                        with ctx.wrap_socket(sock, server_hostname=site) as ssock:
                            cert = ssock.getpeercert()
                            exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            ssl_d = (exp - datetime.datetime.utcnow()).days
                except: pass
                
                dom_d, _ = get_domain_info(site)

                if curr_status != 200:
                    fail_count[site] += 1
                    if site in PRIORITY_SITES or fail_count[site] >= 2:
                        if last_status[site] == 200:
                            shot = take_screenshot(site) if site in PRIORITY_SITES else None
                            send_tg_msg(f"🚨 DOWN: {site} (Status: {curr_status})", shot)
                            last_status[site] = curr_status
                else:
                    if last_status[site] != 200: send_tg_msg(f"✅ UP: {site}")
                    last_status[site] = 200; fail_count[site] = 0

                conn = get_db_connection(); cur = conn.cursor()
                cur.execute("INSERT INTO logs (site, status, response_time, ssl_days, domain_days) VALUES (%s,%s,%s,%s,%s)", 
                           (site, curr_status, resp_time, ssl_d, dom_d))
                conn.commit(); cur.close(); conn.close()
            except: pass
        time.sleep(180)

@app.on_event("startup")
def startup_event():
    init_db()
    threading.Thread(target=check_worker, daemon=True).start()

@app.get("/", response_class=HTMLResponse)
async def index(auth: bool = Depends(check_auth)):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=DictCursor)
    now_msk = datetime.datetime.now(TZ_MOSCOW).strftime("%d.%m.%Y %H:%M:%S")

    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as up, ROUND(AVG(response_time)::numeric,3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '30 days'")
    s30 = cur.fetchone()
    cur.execute("SELECT ROUND((COUNT(*) FILTER (WHERE status = 200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as up, ROUND(AVG(response_time)::numeric,3) as resp FROM logs WHERE timestamp > NOW() - INTERVAL '24 hours'")
    s24 = cur.fetchone()

    cur.execute("SELECT DISTINCT ON (site) * FROM logs ORDER BY site, timestamp DESC")
    latest = {r['site']: r for r in cur.fetchall()}
    cur.execute("SELECT site, ROUND((COUNT(*) FILTER (WHERE status=200)*100.0/NULLIF(COUNT(*),0))::numeric,2) as upt, COUNT(*) FILTER (WHERE status!=200)*180 as down_sec FROM logs WHERE timestamp > NOW() - INTERVAL '30 days' GROUP BY site")
    stats = {r['site']: r for r in cur.fetchall()}

    incidents = [s for s,v in latest.items() if v['status']!=200]
    ssl_warn = [s for s,v in latest.items() if 0 <= v['ssl_days'] <=
