"""E-mail оповещения о длительной недоступности сайтов.

Для каждого сайта в админке задаются: переключатель «оповещать», адреса получателей,
время простоя в минутах, после которого уходит письмо об инциденте, и отдельные флажки
«при инциденте» и «при восстановлении» (по умолчанию включены оба). Письмо об инциденте
отправляется один раз за простой; при восстановлении уходит письмо «восстановлен»
(ответом в ту же цепочку, если письмо об инциденте было). Отправка идёт в фоновом потоке и не задерживает проверки.

Почтовый сервер задаётся переменными окружения (секреты не хранятся в БД и коде):
SMTP_HOST, SMTP_PORT (587), SMTP_SECURITY (starttls | ssl | none), SMTP_USER,
SMTP_PASSWORD, SMTP_FROM, SMTP_TIMEOUT (15).
"""
import concurrent.futures
import datetime
import os
import re
import smtplib
import ssl
import threading
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from html import escape

DEFAULT_AFTER_MIN = 15
# Сайты, для которых письмо о восстановлении не отправляется никогда (требование владельца
# продукта, monitor.15). Письмо об инциденте для них сохраняется.
NO_RECOVERY_SITES = frozenset({"srm.sibur.ru", "tms.sibur.ru"})
MIN_AFTER_MIN = 1
MAX_AFTER_MIN = 1440
MAX_RECIPIENTS = 20
RETRY_SECONDS = 300  # повтор неудачной отправки не чаще раза в 5 минут
PRODUCT_NAME = "Мониторинг сайтов СИБУР"
DEFAULT_DASHBOARD_URL = "https://sib-monitor-ankori.msk1.amvera.tech/"

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")


# ---------------------------------------------------------------------------
# Настройки
# ---------------------------------------------------------------------------
def parse_recipients(value):
    """'a@x.ru; b@y.ru' -> ['a@x.ru', 'b@y.ru']. Ошибка — ValueError с понятным текстом."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        parts = [str(v) for v in value]
    else:
        parts = re.split(r"[,;\s]+", str(value))
    result = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if len(p) > 254 or not _EMAIL_RE.match(p):
            raise ValueError(f"Некорректный адрес e-mail: {p}")
        if p.lower() not in (r.lower() for r in result):
            result.append(p)
    if len(result) > MAX_RECIPIENTS:
        raise ValueError(f"Не больше {MAX_RECIPIENTS} адресов на сайт")
    return result


def validated_after_min(value):
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        raise ValueError("Время простоя до оповещения — целое число минут")
    if not MIN_AFTER_MIN <= minutes <= MAX_AFTER_MIN:
        raise ValueError(f"Время простоя до оповещения: {MIN_AFTER_MIN}–{MAX_AFTER_MIN} минут")
    return minutes


def smtp_config(env=None):
    env = os.environ if env is None else env
    security = (env.get("SMTP_SECURITY") or "starttls").strip().lower()
    if security not in ("starttls", "ssl", "none"):
        security = "starttls"
    default_port = 465 if security == "ssl" else 587
    try:
        port = int(env.get("SMTP_PORT") or default_port)
    except ValueError:
        port = default_port
    try:
        timeout = max(3, min(60, int(env.get("SMTP_TIMEOUT") or 15)))
    except ValueError:
        timeout = 15
    user = (env.get("SMTP_USER") or "").strip()
    return {
        "host": (env.get("SMTP_HOST") or "").strip(),
        "port": port,
        "security": security,
        "user": user,
        "password": env.get("SMTP_PASSWORD") or "",
        "from": (env.get("SMTP_FROM") or user).strip(),
        "timeout": timeout,
    }


def smtp_public_status(env=None):
    """Состояние почтового сервера для админки — без пароля."""
    cfg = smtp_config(env)
    return {
        "configured": bool(cfg["host"] and cfg["from"]),
        "host": cfg["host"],
        "port": cfg["port"],
        "security": cfg["security"],
        "from": cfg["from"],
        "auth": bool(cfg["user"]),
    }


def notify_on_down(cfg):
    """Отправлять письмо при возникновении инцидента (по умолчанию — да)."""
    return cfg.get("on_down", True) is not False


def notify_on_up(cfg, site=None):
    """Отправлять письмо при восстановлении (по умолчанию — да; для NO_RECOVERY_SITES — нет)."""
    if site is not None and not recovery_allowed(site):
        return False
    return cfg.get("on_up", True) is not False


def recovery_allowed(site):
    """Можно ли в принципе отправлять письмо о восстановлении для сайта."""
    return str(site).strip().lower() not in NO_RECOVERY_SITES


# ---------------------------------------------------------------------------
# Формирование писем
# ---------------------------------------------------------------------------
def fmt_duration(minutes):
    minutes = max(0, int(minutes))
    if minutes < 60:
        return f"{minutes} мин"
    h, m = divmod(minutes, 60)
    if h < 24:
        return f"{h} ч {m} мин" if m else f"{h} ч"
    d, h = divmod(h, 24)
    return f"{d} д {h} ч {m} мин"


def _fmt_ts(ts, tz):
    if ts is None:
        return "—"
    if tz is not None:
        # Наивное время — локальное время процесса (как во всём приложении).
        ts = ts.astimezone(tz)
    return ts.strftime("%d.%m.%Y %H:%M:%S") + " МСК"


def _site_url(site):
    return site if site.startswith(("http://", "https://")) else f"https://{site}"


def _status_text(status):
    names = {0: "нет ответа (таймаут/соединение)", 403: "доступ запрещён",
             404: "страница не найдена", 500: "внутренняя ошибка сервера",
             502: "ошибка шлюза", 503: "сервис недоступен", 504: "таймаут шлюза",
             701: "содержимое страницы не соответствует шаблону",
             703: "сертификат TLS не прошёл проверку"}
    if status is None:
        return "—"
    return f"{status} — {names.get(status, 'неожиданный ответ')}"


def _html(title, color, rows, note, dashboard_url):
    tr = "".join(
        f'<tr><td style="padding:6px 12px 6px 0;color:#64748b;white-space:nowrap;vertical-align:top;">'
        f'{escape(k)}</td><td style="padding:6px 0;color:#0f172a;">{v}</td></tr>'
        for k, v in rows)
    return f"""<!doctype html><html lang="ru"><body style="margin:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:24px 0;"><tr><td align="center">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;">
<tr><td style="background:{color};color:#ffffff;padding:16px 24px;font-size:18px;font-weight:bold;border-radius:8px 8px 0 0;">{escape(title)}</td></tr>
<tr><td style="padding:20px 24px;font-size:14px;line-height:1.5;">
<table role="presentation" cellpadding="0" cellspacing="0" style="font-size:14px;">{tr}</table>
<p style="margin:18px 0 0;color:#475569;">{escape(note)}</p>
<p style="margin:18px 0 0;"><a href="{escape(dashboard_url)}" style="background:#00717a;color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:6px;display:inline-block;">Открыть мониторинг</a></p>
</td></tr>
<tr><td style="padding:12px 24px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:12px;">Письмо сформировано автоматически системой «{escape(PRODUCT_NAME)}». Отвечать на него не нужно. Настройки оповещений — в админке, вкладка «Сайты».</td></tr>
</table></td></tr></table></body></html>"""


def build_down_message(info, recipients, sender, tz=None, dashboard_url=DEFAULT_DASHBOARD_URL):
    """info: site, status, reason, started_at, detected_at, after_min, category, incident_id."""
    site = info["site"]
    minutes = int((info["detected_at"] - info["started_at"]).total_seconds() // 60)
    subject = f"[ИНЦИДЕНТ] {site} недоступен более {info['after_min']} мин"
    rows = [
        ("Сайт", site),
        ("Адрес", _site_url(site)),
        ("Состояние", "НЕДОСТУПЕН"),
        ("Начало простоя", _fmt_ts(info["started_at"], tz)),
        ("Длительность", fmt_duration(minutes)),
        ("Последняя проверка", _fmt_ts(info["detected_at"], tz)),
        ("Код ответа", _status_text(info.get("status"))),
        ("Причина", info.get("reason") or "—"),
        ("Категория", info.get("category") or "—"),
        ("Порог оповещения", f"{info['after_min']} мин простоя"),
    ]
    if info.get("incident_id"):
        rows.append(("Номер инцидента", f"#{info['incident_id']}"))
    if info.get("notify_up", True):
        note = ("Сайт проверяется каждую минуту. Когда он снова станет доступен, "
                "в эту же цепочку придёт письмо о восстановлении.")
    else:
        note = ("Сайт проверяется каждую минуту. Письмо о восстановлении для этого сайта "
                "не отправляется — следите за состоянием в мониторинге.")
    text = _plain(f"ИНЦИДЕНТ: {site} недоступен", rows, note, dashboard_url)
    html_rows = [(k, f'<b style="color:#b91c1c;">{escape(v)}</b>' if k == "Состояние" else escape(v))
                 for k, v in rows]
    html = _html(f"🚨 Инцидент: {site} недоступен", "#b91c1c", html_rows, note, dashboard_url)
    msg = _message(subject, text, html, recipients, sender, urgent=True)
    return msg


def build_up_message(info, recipients, sender, tz=None, dashboard_url=DEFAULT_DASHBOARD_URL,
                     in_reply_to=None):
    """info: site, started_at, resolved_at, last_status, last_reason, incident_id."""
    site = info["site"]
    minutes = max(1, int((info["resolved_at"] - info["started_at"]).total_seconds() // 60))
    subject = f"[ВОССТАНОВЛЕН] {site} доступен, простой {fmt_duration(minutes)}"
    rows = [
        ("Сайт", site),
        ("Адрес", _site_url(site)),
        ("Состояние", "ДОСТУПЕН"),
        ("Начало простоя", _fmt_ts(info["started_at"], tz)),
        ("Восстановлен", _fmt_ts(info["resolved_at"], tz)),
        ("Общий простой", fmt_duration(minutes)),
        ("Последняя ошибка", info.get("last_reason") or _status_text(info.get("last_status"))),
    ]
    if info.get("incident_id"):
        rows.append(("Номер инцидента", f"#{info['incident_id']}"))
    note = "Сайт отвечает штатно. Инцидент закрыт автоматически."
    text = _plain(f"ВОССТАНОВЛЕН: {site}", rows, note, dashboard_url)
    html_rows = [(k, f'<b style="color:#15803d;">{escape(v)}</b>' if k == "Состояние" else escape(v))
                 for k, v in rows]
    html = _html(f"✅ Восстановлен: {site}", "#15803d", html_rows, note, dashboard_url)
    msg = _message(subject, text, html, recipients, sender)
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to
    return msg


def build_test_message(recipients, sender, tz=None, now=None, dashboard_url=DEFAULT_DASHBOARD_URL):
    now = now or datetime.datetime.now()
    rows = [("Назначение", "Проверка доставки e-mail оповещений"), ("Время", _fmt_ts(now, tz))]
    note = "Если вы получили это письмо, оповещения об инцидентах будут доставляться на этот адрес."
    text = _plain("Тестовое письмо", rows, note, dashboard_url)
    html = _html("Тестовое письмо", "#00717a", [(k, escape(v)) for k, v in rows], note, dashboard_url)
    return _message(f"[ТЕСТ] {PRODUCT_NAME}: проверка оповещений", text, html, recipients, sender)


def _plain(title, rows, note, dashboard_url):
    width = max(len(k) for k, _ in rows) + 2
    lines = [title, "=" * len(title), ""]
    lines += [f"{(k + ':').ljust(width)} {v}" for k, v in rows]
    lines += ["", note, "", f"Мониторинг: {dashboard_url}", "",
              "--", f"Письмо сформировано автоматически системой «{PRODUCT_NAME}»."]
    return "\n".join(lines) + "\n"


def _message(subject, text, html, recipients, sender, urgent=False):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((PRODUCT_NAME, sender)) if sender else PRODUCT_NAME
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    domain = sender.split("@")[-1] if sender and "@" in sender else "sib-monitor.local"
    msg["Message-ID"] = make_msgid(domain=domain)
    msg["Auto-Submitted"] = "auto-generated"
    if urgent:
        msg["X-Priority"] = "1"
        msg["Importance"] = "high"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg


# ---------------------------------------------------------------------------
# Отправка
# ---------------------------------------------------------------------------
def send_message(msg, cfg=None):
    """Возвращает (ok, error). Текст ошибки не содержит пароля."""
    cfg = cfg or smtp_config()
    if not cfg["host"] or not cfg["from"]:
        return False, "Почтовый сервер не настроен (SMTP_HOST / SMTP_FROM)"
    try:
        ctx = ssl.create_default_context()
        if cfg["security"] == "ssl":
            server = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=cfg["timeout"], context=ctx)
        else:
            server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"])
        try:
            server.ehlo()
            if cfg["security"] == "starttls":
                server.starttls(context=ctx)
                server.ehlo()
            if cfg["user"]:
                server.login(cfg["user"], cfg["password"])
            server.send_message(msg)
        finally:
            try:
                server.quit()
            except Exception:
                pass
        return True, None
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP: ошибка авторизации (проверьте SMTP_USER/SMTP_PASSWORD)"
    except smtplib.SMTPRecipientsRefused:
        return False, "SMTP: сервер отклонил адрес получателя"
    except (smtplib.SMTPException, OSError) as e:
        return False, f"SMTP: {type(e).__name__}: {str(e)[:200]}"


# ---------------------------------------------------------------------------
# Логика: одно письмо об инциденте за простой + письмо о восстановлении
# ---------------------------------------------------------------------------
class EmailAlerter:
    """Потокобезопасное состояние оповещений по сайтам.

    observe() вызывается после каждой проверки сайта. Письма собираются и отправляются
    в фоне; результат передаётся в on_result(kind, site, recipients, subject, ok, error,
    started_at) — для журнала в БД.
    """

    def __init__(self, sender=send_message, on_result=None, tz=None,
                 dashboard_url=DEFAULT_DASHBOARD_URL, retry_seconds=RETRY_SECONDS,
                 executor=None, unknown_status=None, config=smtp_config, incident_lookup=None):
        self._send = sender
        self._on_result = on_result
        self._tz = tz
        self._dashboard_url = dashboard_url
        self._retry = retry_seconds
        self._unknown = unknown_status
        self._config = config
        self._incident_lookup = incident_lookup
        self._executor = executor or concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="email-alert")
        self._lock = threading.Lock()
        self._state = {}

    # --- состояние ---------------------------------------------------------
    def seed(self, site, started_at, down_sent=False, message_id=None, recipients=None):
        """Восстановление после перезапуска: открытый простой и отправленное письмо."""
        with self._lock:
            st = self._state.setdefault(site, self._new(started_at))
            if started_at and (st["start"] is None or started_at < st["start"]):
                st["start"] = started_at
            if down_sent:
                st["down"] = "sent"
                st["message_id"] = message_id
                st["recipients"] = list(recipients or [])

    def state(self, site):
        with self._lock:
            st = self._state.get(site)
            return dict(st) if st else None

    @staticmethod
    def _new(start):
        return {"start": start, "down": "none", "last_try": None, "message_id": None,
                "recipients": [], "last_status": None, "last_reason": None, "incident_id": None}

    # --- основной вход -----------------------------------------------------
    def observe(self, site, status, cfg, now=None, fail_start=None, reason=None,
                category=None, incident_id=None, global_enabled=True):
        """cfg: {'enabled': bool, 'recipients': [...], 'after_min': int,
        'on_down': bool, 'on_up': bool} (on_down / on_up по умолчанию True).
        Возвращает 'down' / 'up', если поставлена отправка, иначе None."""
        now = now or datetime.datetime.now()
        if self._unknown is not None and status == self._unknown:
            return None  # результат не получен — не считаем ни сбоем, ни восстановлением
        if status != 200:
            return self._on_fail(site, status, cfg, now, fail_start, reason, category,
                                 incident_id, global_enabled)
        return self._on_ok(site, now, cfg)

    def _on_fail(self, site, status, cfg, now, fail_start, reason, category, incident_id,
                 global_enabled):
        with self._lock:
            st = self._state.setdefault(site, self._new(fail_start or now))
            if fail_start and (st["start"] is None or fail_start < st["start"]):
                st["start"] = fail_start
            st["last_status"], st["last_reason"] = status, reason
            if incident_id:
                st["incident_id"] = incident_id
            recipients = list(cfg.get("recipients") or [])
            after_min = int(cfg.get("after_min") or DEFAULT_AFTER_MIN)
            on_down = notify_on_down(cfg)
            on_up = notify_on_up(cfg, site)
            if not (global_enabled and cfg.get("enabled") and recipients and (on_down or on_up)):
                return None
            if st["down"] != "none":
                return None
            if (now - st["start"]).total_seconds() < after_min * 60:
                return None
            if st["last_try"] and (now - st["last_try"]).total_seconds() < self._retry:
                return None
            if not on_down:
                # Письмо об инциденте выключено: простой засчитан, ждём восстановления.
                st["down"], st["recipients"] = "skipped", recipients
                return None
            st["down"], st["last_try"], st["recipients"] = "pending", now, recipients
            info = {"site": site, "status": status, "reason": reason, "started_at": st["start"],
                    "detected_at": now, "after_min": after_min, "category": category,
                    "incident_id": st["incident_id"], "notify_up": on_up}
        self._submit(self._deliver_down, site, info, recipients)
        return "down"

    def _on_ok(self, site, now, cfg=None):
        with self._lock:
            st = self._state.pop(site, None)
        if not st or st["down"] == "none":
            return None
        if not notify_on_up(cfg or {}, site):
            return None  # письмо о восстановлении для сайта выключено или запрещено
        info = {"site": site, "started_at": st["start"], "resolved_at": now,
                "last_status": st["last_status"], "last_reason": st["last_reason"],
                "incident_id": st["incident_id"]}
        self._submit(self._deliver_up, site, info, st["recipients"], st["message_id"])
        return "up"

    def _submit(self, fn, *args):
        try:
            self._executor.submit(fn, *args)
        except RuntimeError:
            fn(*args)

    # --- доставка ----------------------------------------------------------
    def _deliver_down(self, site, info, recipients):
        if not info.get("incident_id") and self._incident_lookup:
            try:
                info["incident_id"] = self._incident_lookup(site)
            except Exception:
                pass
            if info.get("incident_id"):
                with self._lock:
                    st = self._state.get(site)
                    if st is not None:
                        st["incident_id"] = info["incident_id"]
        cfg = self._config()
        msg = build_down_message(info, recipients, cfg["from"], self._tz, self._dashboard_url)
        ok, err = self._safe_send(msg, cfg)
        with self._lock:
            st = self._state.get(site)
            if st is not None and st["down"] == "pending":
                if ok:
                    st["down"], st["message_id"], st["recipients"] = "sent", msg["Message-ID"], recipients
                else:
                    st["down"] = "none"  # повтор через RETRY_SECONDS
        self._report("down", site, recipients, msg, ok, err, info["started_at"])

    def _deliver_up(self, site, info, recipients, message_id):
        if not recipients:
            return
        cfg = self._config()
        msg = build_up_message(info, recipients, cfg["from"], self._tz, self._dashboard_url,
                               in_reply_to=message_id)
        ok, err = self._safe_send(msg, cfg)
        self._report("up", site, recipients, msg, ok, err, info["started_at"])

    def _safe_send(self, msg, cfg):
        try:
            return self._send(msg, cfg)
        except Exception as e:  # отправитель не должен ронять воркер
            return False, f"{type(e).__name__}: {str(e)[:200]}"

    def _report(self, kind, site, recipients, msg, ok, err, started_at):
        print(f"[EMAIL {kind.upper()}] {site} -> {', '.join(recipients)}: "
              f"{'OK' if ok else 'FAIL ' + str(err)}", flush=True)
        if self._on_result:
            try:
                self._on_result(kind, site, recipients, msg["Subject"], ok, err, started_at,
                                msg["Message-ID"])
            except Exception as e:
                print(f"[EMAIL LOG ERR] {site}: {e}")
