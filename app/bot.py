"""
NoFuss — Telegram-бот + HTTP-сервер подписок.
Ноды проверяются через sing-box (checker.py), отдаются как есть.
"""
import os, json, base64, threading, logging, sqlite3, secrets, asyncio
import urllib.parse, urllib.request
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta, timezone

from checker import fetch_and_check, get_progress

# ── Конфиг ──
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ADMIN_ID  = int(os.environ.get("ADMIN_ID", "0"))
BASE_URL  = os.environ.get("BASE_URL", "")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
MAX_DEVICES = int(os.environ.get("MAX_DEVICES", "3"))
MAX_NODES = int(os.environ.get("MAX_NODES", "45"))
NOTIFY_DAYS = [3, 1]

DATA = Path("/app/data")
DATA.mkdir(parents=True, exist_ok=True)
SF  = DATA / "sub.b64"
PF  = DATA / "sub_plain.txt"
LU  = DATA / "last_update.txt"
DBF = DATA / "users.db"

EXPIRED_MSG = "# NoFuss\n# Подписка истекла\n# Обратитесь к администратору"

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(DATA / "bot.log"), logging.StreamHandler()])
log = logging.getLogger("bot")

STATUS_EMOJI = {"active": "✅", "pending": "⏳", "blocked": "🚫", "new": "🆕"}
_update_lock = threading.Lock()


# ═══════════════════════════════════════════════════════
#  БАЗА ДАННЫХ
# ═══════════════════════════════════════════════════════
def _db():
    c = sqlite3.connect(DBF, check_same_thread=False, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c

def init_db():
    with _db() as d:
        d.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT, first_name TEXT,
            status TEXT DEFAULT 'new', token TEXT UNIQUE, sub_until TEXT,
            created_at TEXT DEFAULT(datetime('now')), notified_days TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS devices(
            token TEXT NOT NULL, hwid TEXT NOT NULL, last_seen TEXT,
            device_info TEXT DEFAULT '',
            PRIMARY KEY(token, hwid)
        );
        """)
        if ADMIN_ID:
            d.execute("INSERT OR IGNORE INTO users(id,username,first_name,status,sub_until)"
                      " VALUES(?,?,?,?,?)",
                      (ADMIN_ID, "", "Admin", "active", "2099-12-31T23:59:59+00:00"))
            t = secrets.token_urlsafe(24)
            d.execute("UPDATE users SET token=COALESCE(token,?), status='active',"
                      " sub_until=COALESCE(sub_until,?) WHERE id=?",
                      (t, "2099-12-31T23:59:59+00:00", ADMIN_ID))
        if BASE_URL:
            d.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('base_url',?)", (BASE_URL,))

def get_setting(k, default=""):
    with _db() as d:
        r = d.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
        return r["value"] if r else default

def set_setting(k, v):
    with _db() as d:
        d.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (k, v))

def uget(uid):
    with _db() as d:
        return d.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def uins(uid, un, fn):
    with _db() as d:
        d.execute("INSERT INTO users(id,username,first_name,status) VALUES(?,?,?,'new')"
                  " ON CONFLICT(id) DO UPDATE SET username=excluded.username,"
                  " first_name=excluded.first_name", (uid, un or "", fn or ""))

def uset(uid, s):
    with _db() as d:
        d.execute("UPDATE users SET status=? WHERE id=?", (s, uid))

def uapprove(uid, months):
    u = uget(uid)
    tok = (u["token"] if u and u["token"] else None) or secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    if u and u["sub_until"] and u["status"] == "active":
        old = datetime.fromisoformat(u["sub_until"]).replace(tzinfo=timezone.utc)
        end = (old if old > now else now) + timedelta(days=30 * months)
    else:
        end = now + timedelta(days=30 * months)
    with _db() as d:
        d.execute("UPDATE users SET status='active', token=?, sub_until=?,"
                  " notified_days='' WHERE id=?", (tok, end.isoformat(), uid))
    return tok, end

def ublock(uid):
    with _db() as d:
        d.execute("UPDATE users SET status='blocked', sub_until=NULL WHERE id=?", (uid,))

def ureset_sub(uid):
    with _db() as d:
        d.execute("UPDATE users SET sub_until=NULL, status='new', notified_days='' WHERE id=?", (uid,))

def udel(uid):
    with _db() as d:
        d.execute("DELETE FROM users WHERE id=?", (uid,))

def uall():
    with _db() as d:
        return d.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()

def uactive():
    with _db() as d:
        return d.execute("SELECT * FROM users WHERE status='active'").fetchall()

def utoken(t):
    with _db() as d:
        return d.execute("SELECT * FROM users WHERE token=?", (t,)).fetchone()

def device_check(token, hwid, device_info=""):
    """Проверить/зарегистрировать устройство. Вернуть (ok, count)."""
    if not hwid or MAX_DEVICES <= 0:
        return True, 0
    now = datetime.now(timezone.utc).isoformat()
    with _db() as d:
        d.execute("INSERT INTO devices(token,hwid,last_seen,device_info) VALUES(?,?,?,?)"
                  " ON CONFLICT(token,hwid) DO UPDATE SET last_seen=?,device_info=?",
                  (token, hwid, now, device_info, now, device_info))
        cnt = d.execute("SELECT COUNT(*) FROM devices WHERE token=?", (token,)).fetchone()[0]
    return cnt <= MAX_DEVICES, cnt

def device_count(token):
    with _db() as d:
        return d.execute("SELECT COUNT(*) FROM devices WHERE token=?", (token,)).fetchone()[0]

def device_list(token):
    with _db() as d:
        return d.execute("SELECT hwid, device_info, last_seen FROM devices WHERE token=? ORDER BY last_seen DESC", (token,)).fetchall()

def device_reset(token):
    with _db() as d:
        d.execute("DELETE FROM devices WHERE token=?", (token,))

def ulinks():
    with _db() as d:
        return d.execute("SELECT * FROM users WHERE id < 0 ORDER BY created_at DESC").fetchall()

def ucounts():
    au = uall()
    return {"all": len(au),
            "act": sum(1 for u in au if u["status"] == "active"),
            "pnd": sum(1 for u in au if u["status"] == "pending"),
            "blk": sum(1 for u in au if u["status"] == "blocked")}


# ═══════════════════════════════════════════════════════
#  УТИЛИТЫ
# ═══════════════════════════════════════════════════════
def sub_url(token):
    base = get_setting("base_url") or BASE_URL
    if base:
        b = base.rstrip("/")
        if not b.startswith("http://") and not b.startswith("https://"):
            b = f"https://{b}"
        return f"{b}/sub/{token}"
    return f"http://localhost:{HTTP_PORT}/sub/{token}"

def display_name(u):
    if not u: return "?"
    if u["username"]: return f"@{u['username']}"
    return u["first_name"] or f"id{u['id']}"

def days_left_str(sub_until):
    if not sub_until: return "—"
    d = (datetime.fromisoformat(sub_until).replace(tzinfo=timezone.utc)
         - datetime.now(timezone.utc)).days
    if d < 0: return "истекла"
    m, dd = divmod(d, 30)
    return f"{m} мес {dd} дн" if m else f"{dd} дн"

def sub_ready():
    return SF.exists() and SF.stat().st_size > 10

def node_count():
    if not PF.exists(): return 0
    return len([l for l in PF.read_text().splitlines() if l.strip()])


# ═══════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ НОД
# ═══════════════════════════════════════════════════════
def do_update(notify_admin=False) -> str:
    if not _update_lock.acquire(blocking=False):
        return "⏳ Обновление уже идёт"
    try:
        good = asyncio.run(fetch_and_check())
        if not good:
            msg = "❌ Ни одна нода не прошла проверку (старые ноды сохранены)"
            if notify_admin:
                try: send_msg(ADMIN_ID, msg)
                except: pass
            return msg
        body = "\n".join(good) + "\n"
        # Атомарная замена — пишем во временные файлы, потом переименовываем
        tmp_plain = PF.with_suffix(".tmp")
        tmp_b64 = SF.with_suffix(".tmp")
        tmp_plain.write_text(body)
        tmp_b64.write_text(base64.b64encode(body.encode()).decode())
        tmp_plain.replace(PF)
        tmp_b64.replace(SF)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        LU.write_text(now_str)
        msg = f"✅ Обновлено: {len(good)} нод ({now_str})"
        if notify_admin:
            try: send_msg(ADMIN_ID, f"🔄 Авто-обновление\n{msg}")
            except: pass
        return msg
    except Exception as e:
        log.exception("do_update failed")
        msg = f"❌ Ошибка: {e}"
        if notify_admin:
            try: send_msg(ADMIN_ID, f"🔄 Авто-обновление\n{msg}")
            except: pass
        return msg
    finally:
        _update_lock.release()


# ═══════════════════════════════════════════════════════
#  HTTP-СЕРВЕР ПОДПИСОК
# ═══════════════════════════════════════════════════════
class SubHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    HWID_EXCEEDED_MSG = "# NoFuss\n# Достигнут предел количества подключенных устройств на эту подписку"

    def _serve(self, head_only=False):
        path = self.path.rstrip("/")
        if not path.startswith("/sub/"):
            self.send_response(404); self.end_headers()
            if not head_only: self.wfile.write(b"Not found")
            return
        token = path[5:].split("?")[0].split("/")[0]

        hwid = self.headers.get("x-hwid", "")
        device_info = f"{self.headers.get('user-agent', '')} | {self.headers.get('x-device-model', '')} | {self.headers.get('x-device-os', '')}"

        u = utoken(token)
        if not u:
            self.send_response(403); self.end_headers()
            if not head_only: self.wfile.write(b"Invalid token")
            return

        expired = False
        if u["sub_until"]:
            expired = datetime.now(timezone.utc) > datetime.fromisoformat(
                u["sub_until"]).replace(tzinfo=timezone.utc)

        if expired or u["status"] in ("new", "pending", "blocked"):
            payload = base64.b64encode(EXPIRED_MSG.encode())
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("subscription-userinfo",
                             "upload=0;download=0;total=0;expire=1")
            self.send_header("profile-update-interval", "1")
            self._headers_buffer.append(b"profile-title: NoFussVPN\r\n")
            self.end_headers()
            if not head_only: self.wfile.write(payload)
            return

        # HWID check
        if hwid and MAX_DEVICES > 0:
            ok, cnt = device_check(token, hwid, device_info)
            if not ok:
                log.warning(f"HWID limit exceeded: token={token[:8]}... hwid={hwid} devices={cnt}/{MAX_DEVICES}")
                payload = base64.b64encode(self.HWID_EXCEEDED_MSG.encode())
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("profile-update-interval", "1")
                self._headers_buffer.append(b"profile-title: NoFussVPN\r\n")
                self.end_headers()
                if not head_only: self.wfile.write(payload)
                return

        if not sub_ready():
            self.send_response(503); self.end_headers()
            if not head_only: self.wfile.write(b"Not ready")
            return

        # Отдаём все рабочие ноды, перемешанные случайно
        import random
        lines = PF.read_text().strip().splitlines()
        random.shuffle(lines)
        body = "\n".join(lines) + "\n"
        payload = base64.b64encode(body.encode()).decode().encode()
        exp = int(datetime.fromisoformat(u["sub_until"]).timestamp()) if u["sub_until"] else 9999999999
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("subscription-userinfo",
                         f"upload=0;download=0;total=0;expire={exp}")
        self.send_header("profile-update-interval", "1")
        self._headers_buffer.append(b"profile-title: NoFussVPN\r\n")
        self.send_header("content-disposition", 'attachment; filename="nofuss.txt"')
        self.end_headers()
        if not head_only: self.wfile.write(payload)

    def do_GET(self): self._serve(False)
    def do_HEAD(self): self._serve(True)

def run_http():
    log.info(f"HTTP :{HTTP_PORT}")
    HTTPServer(("0.0.0.0", HTTP_PORT), SubHandler).serve_forever()


# ═══════════════════════════════════════════════════════
#  TELEGRAM API
# ═══════════════════════════════════════════════════════
API = f"https://api.telegram.org/bot{BOT_TOKEN}"

def tg(method, data):
    req = urllib.request.Request(f"{API}/{method}",
        data=json.dumps(data).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

def send_msg(cid, text, kb=None):
    d = {"chat_id": cid, "text": text, "parse_mode": "HTML"}
    if kb: d["reply_markup"] = kb
    try: return tg("sendMessage", d)
    except Exception as e: log.error(f"send {cid}: {e}")

def edit_msg(cid, mid, text, kb=None):
    d = {"chat_id": cid, "message_id": mid, "text": text, "parse_mode": "HTML"}
    if kb: d["reply_markup"] = kb
    try: return tg("editMessageText", d)
    except Exception as e:
        if "not modified" in str(e): return
        log.error(f"edit {cid}: {e}")
        return send_msg(cid, text, kb)

def answer_cb(cbid):
    try: tg("answerCallbackQuery", {"callback_query_id": cbid})
    except: pass

def set_commands():
    try:
        tg("setMyCommands", {"commands": [
            {"command": "start", "description": "Главное меню"},
            {"command": "sub", "description": "Моя подписка"},
            {"command": "help", "description": "Помощь"},
        ]})
        tg("setMyCommands", {"commands": [
            {"command": "start", "description": "Главное меню"},
            {"command": "panel", "description": "Панель"},
            {"command": "update", "description": "Обновить ноды"},
            {"command": "adduser", "description": "Создать ссылку"},
        ], "scope": {"type": "chat", "chat_id": ADMIN_ID}})
    except Exception as e:
        log.warning(f"setMyCommands: {e}")


# ═══════════════════════════════════════════════════════
#  КЛАВИАТУРЫ
# ═══════════════════════════════════════════════════════
def kb_admin():
    return {"keyboard": [[{"text": "📊 Панель"}, {"text": "📋 Подписка"}]], "resize_keyboard": True}

def kb_user():
    return {"keyboard": [[{"text": "📋 Моя подписка"}],
                          [{"text": "📊 Мой статус"}, {"text": "ℹ️ Помощь"}]], "resize_keyboard": True}

def kb_pending():
    return {"keyboard": [[{"text": "📊 Мой статус"}], [{"text": "ℹ️ Помощь"}]], "resize_keyboard": True}

def kb_new():
    return {"keyboard": [[{"text": "🙋 Запросить доступ"}], [{"text": "ℹ️ Помощь"}]], "resize_keyboard": True}

def kb_for(uid):
    if uid == ADMIN_ID: return kb_admin()
    u = uget(uid)
    if not u or u["status"] in ("new", "blocked"): return kb_new()
    if u["status"] == "pending": return kb_pending()
    return kb_user()

def ik_panel():
    c = ucounts()
    lc = len(ulinks())
    return {"inline_keyboard": [
        [{"text": f"👥 Все: {c['all']}", "callback_data": "ul:all"},
         {"text": f"⏳ Заявки: {c['pnd']}", "callback_data": "ul:pnd"}],
        [{"text": f"✅ Активные: {c['act']}", "callback_data": "ul:act"},
         {"text": f"🚫 Заблок: {c['blk']}", "callback_data": "ul:blk"}],
        [{"text": f"🔗 Ссылки: {lc}", "callback_data": "links"},
         {"text": "➕ Создать ссылку", "callback_data": "create_link"}],
        [{"text": "🔄 Обновить ноды", "callback_data": "do_update"}],
        [{"text": "⚙️ Настройки", "callback_data": "settings"}],
    ]}

def ik_approve(uid):
    return {"inline_keyboard": [
        [{"text": "1м", "callback_data": f"approve:{uid}:1"},
         {"text": "3м", "callback_data": f"approve:{uid}:3"},
         {"text": "6м", "callback_data": f"approve:{uid}:6"},
         {"text": "12м", "callback_data": f"approve:{uid}:12"}],
        [{"text": "❌ Отклонить", "callback_data": f"reject:{uid}"}],
    ]}

def ik_manage(uid, lst="all"):
    u = uget(uid)
    rows = [[{"text": "+1м", "callback_data": f"ext:{uid}:1:{lst}"},
             {"text": "+3м", "callback_data": f"ext:{uid}:3:{lst}"},
             {"text": "+6м", "callback_data": f"ext:{uid}:6:{lst}"},
             {"text": "+12м", "callback_data": f"ext:{uid}:12:{lst}"}]]
    if u and u["status"] == "active" and u["sub_until"]:
        rows.append([{"text": "🔄 Обнулить", "callback_data": f"reset:{uid}:{lst}"},
                      {"text": "📱 Сброс устройств", "callback_data": f"devreset:{uid}:{lst}"}])
    ar = []
    if u and u["status"] != "blocked":
        ar.append({"text": "🚫 Блок", "callback_data": f"block:{uid}:{lst}"})
    ar.append({"text": "🗑 Удалить", "callback_data": f"cdel:{uid}:{lst}"})
    rows.append(ar)
    rows.append([{"text": "◀️ Назад", "callback_data": f"ul:{lst}"}])
    return {"inline_keyboard": rows}

def ik_link_manage(uid):
    return {"inline_keyboard": [
        [{"text": "+1м", "callback_data": f"ext:{uid}:1:links"},
         {"text": "+3м", "callback_data": f"ext:{uid}:3:links"},
         {"text": "+6м", "callback_data": f"ext:{uid}:6:links"}],
        [{"text": "🔄 Обнулить", "callback_data": f"reset:{uid}:links"},
         {"text": "🗑 Удалить", "callback_data": f"cdel:{uid}:links"}],
        [{"text": "◀️ Назад", "callback_data": "links"}],
    ]}

def ik_create_link():
    return {"inline_keyboard": [
        [{"text": "1м", "callback_data": "gen:1"}, {"text": "3м", "callback_data": "gen:3"},
         {"text": "6м", "callback_data": "gen:6"}, {"text": "12м", "callback_data": "gen:12"}],
        [{"text": "◀️ Панель", "callback_data": "panel"}],
    ]}

def ik_back():
    return {"inline_keyboard": [[{"text": "◀️ Панель", "callback_data": "panel"}]]}

def ik_confirm_del(uid, lst):
    back = "links" if lst == "links" else f"manage:{uid}:{lst}"
    return {"inline_keyboard": [
        [{"text": "⚠️ Да, удалить!", "callback_data": f"del:{uid}:{lst}"},
         {"text": "◀️ Отмена", "callback_data": back}],
    ]}


# ═══════════════════════════════════════════════════════
#  ТЕКСТЫ
# ═══════════════════════════════════════════════════════
def panel_text():
    c = ucounts()
    lt = LU.read_text().strip() if LU.exists() else "ещё не обновлялись"
    base = get_setting("base_url") or BASE_URL or f"http://localhost:{HTTP_PORT}"
    nc = node_count()
    prog = get_progress()
    if prog["active"] and prog["total"] > 0:
        pct = round(prog["done"] / prog["total"] * 100)
        update_line = f"🔄 Обновление: <b>{pct}%</b> ({prog['done']}/{prog['total']})"
    else:
        update_line = f"🕐 Обновлено: {lt}"
    return (f"📊 <b>Панель NoFuss</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ Активных: <b>{c['act']}</b>  ⏳ Заявок: <b>{c['pnd']}</b>  "
            f"🚫 Заблок: <b>{c['blk']}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📦 Нод: <b>{nc}</b>\n"
            f"{update_line}\n"
            f"🌐 URL: <code>{base}</code>")

def user_list_text(filt="all"):
    au = uall()
    counts = {"all": len(au),
              "act": sum(1 for u in au if u["status"] == "active"),
              "pnd": sum(1 for u in au if u["status"] == "pending"),
              "blk": sum(1 for u in au if u["status"] == "blocked")}
    labels = {"all": f"👥 Все ({counts['all']})", "act": f"✅ Активные ({counts['act']})",
              "pnd": f"⏳ Заявки ({counts['pnd']})", "blk": f"🚫 Заблок ({counts['blk']})"}
    tabs = []
    for k in ("all", "act", "pnd", "blk"):
        lbl = f"• {labels[k]} •" if k == filt else labels[k]
        tabs.append({"text": lbl, "callback_data": f"ul:{k}"})
    filtered = {"all": au,
                "act": [u for u in au if u["status"] == "active"],
                "pnd": [u for u in au if u["status"] == "pending"],
                "blk": [u for u in au if u["status"] == "blocked"]}.get(filt, au)
    rows = [tabs]
    title = {"all": "Все", "act": "Активные", "pnd": "Заявки", "blk": "Заблок"}.get(filt, "")
    if not filtered:
        txt = f"📋 <b>{title}</b>\n\n<i>Пусто</i>"
    else:
        txt = f"📋 <b>{title} ({len(filtered)})</b>"
        for u in filtered[:30]:
            left = days_left_str(u["sub_until"]) if u["sub_until"] else "—"
            em = STATUS_EMOJI.get(u["status"], "❓")
            rows.append([{"text": f"{em} {display_name(u)}  │  {left}",
                          "callback_data": f"manage:{u['id']}:{filt}"}])
        if len(filtered) > 30:
            txt += f"\n<i>(показано 30 из {len(filtered)})</i>"
    rows.append([{"text": "◀️ Панель", "callback_data": "panel"}])
    return {"inline_keyboard": rows}, txt

def user_card_text(uid, lst="all"):
    u = uget(uid)
    if not u: return None, "❌ Не найден"
    until = u["sub_until"][:10] if u["sub_until"] else "—"
    left = days_left_str(u["sub_until"])
    tok = u["token"] or ""
    url = sub_url(tok) if tok else "—"
    em = STATUS_EMOJI.get(u["status"], "❓")
    dc = device_count(tok) if tok else 0
    devices_line = f"📱 Устройств: <b>{dc}/{MAX_DEVICES}</b>"
    txt = (f"{em} <b>{display_name(u)}</b>\n"
           f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
           f"🆔 ID: <code>{u['id']}</code>\n"
           f"📌 Статус: <b>{u['status']}</b>\n"
           f"📅 До: <b>{until}</b>\n"
           f"⏳ Осталось: <b>{left}</b>\n"
           f"{devices_line}\n"
           f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
           f"🔗 URL:\n<code>{url}</code>")
    return ik_manage(uid, lst), txt

def links_list_text():
    links = ulinks()
    rows = []
    if not links:
        txt = "🔗 <b>Ссылки</b>\n\n<i>Нет</i>"
    else:
        txt = f"🔗 <b>Ссылки ({len(links)})</b>"
        for u in links[:30]:
            left = days_left_str(u["sub_until"]) if u["sub_until"] else "—"
            em = STATUS_EMOJI.get(u["status"], "❓")
            lbl = u["first_name"] or f"link_{abs(u['id'])}"
            rows.append([{"text": f"{em} {lbl}  │  {left}",
                          "callback_data": f"lcard:{u['id']}"}])
    rows.append([{"text": "➕ Создать", "callback_data": "create_link"}])
    rows.append([{"text": "◀️ Панель", "callback_data": "panel"}])
    return {"inline_keyboard": rows}, txt

def link_card_text(uid):
    u = uget(uid)
    if not u: return None, "❌ Не найдена"
    until = u["sub_until"][:10] if u["sub_until"] else "—"
    left = days_left_str(u["sub_until"])
    tok = u["token"] or ""
    url = sub_url(tok) if tok else "—"
    em = STATUS_EMOJI.get(u["status"], "❓")
    txt = (f"{em} <b>{u['first_name'] or 'Ссылка'}</b>\n"
           f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
           f"📌 Статус: <b>{u['status']}</b>\n"
           f"📅 До: <b>{until}</b>  ({left})\n"
           f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
           f"🔗 URL:\n<code>{url}</code>")
    return ik_link_manage(uid), txt

def send_subscription(cid, uid=None):
    if uid is None: uid = cid
    u = uget(uid)
    if uid != ADMIN_ID:
        if not u or u["status"] != "active":
            send_msg(cid, "❌ Подписка не активна\n\nНажми «🙋 Запросить доступ»", kb_for(uid))
            return
    if not u or not u["token"]:
        send_msg(cid, "❌ Токен не найден", kb_for(uid))
        return
    if not sub_ready():
        send_msg(cid, "⏳ Подписка готовится\n\nПопробуй через минуту", kb_for(uid))
        return
    tok = u["token"]
    url = sub_url(tok)
    until = u["sub_until"][:10] if u["sub_until"] else "∞"
    left = days_left_str(u["sub_until"]) if u["sub_until"] else "∞"
    lt = LU.read_text().strip() if LU.exists() else "—"
    nc = node_count()
    send_msg(cid,
        f"📋 <b>NoFuss</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📅 До: <b>{until}</b>  (ост: {left})\n"
        f"📦 Нод: <b>{nc}</b>\n"
        f"🕐 Обновлено: {lt}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔗 <b>Ссылка:</b>\n<code>{url}</code>\n\n"
        f"📱 <b>Как подключить:</b>\n"
        f"1. Скопируй ссылку выше\n"
        f"2. Открой <b>Hiddify</b> или <b>v2rayTUN</b>\n"
        f"3. Добавить подписку → вставь ссылку\n"
        f"4. Обнови список и подключайся 🚀",
        kb_for(uid))

def create_user_link(months: int) -> tuple:
    tok = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    end = now + timedelta(days=30 * months)
    fake_id = -abs(int.from_bytes(secrets.token_bytes(4), "big"))
    with _db() as d:
        d.execute("INSERT INTO users(id,username,first_name,status,token,sub_until)"
                  " VALUES(?,?,?,'active',?,?)",
                  (fake_id, f"link_{abs(fake_id)}", "Ссылка", tok, end.isoformat()))
    return tok, sub_url(tok), end.strftime("%Y-%m-%d")


# ═══════════════════════════════════════════════════════
#  ОБРАБОТЧИКИ
# ═══════════════════════════════════════════════════════
def handle_start(cid, uid, un, fn):
    uins(uid, un, fn)
    u = uget(uid)
    if uid == ADMIN_ID:
        send_msg(cid, "👑 <b>Админ-панель</b>\n\nНажми «📊 Панель»", kb_admin())
        send_msg(cid, panel_text(), ik_panel())
        return
    if u["status"] == "active":
        until = u["sub_until"][:10] if u["sub_until"] else "∞"
        left = days_left_str(u["sub_until"]) if u["sub_until"] else "∞"
        send_msg(cid, f"👋 <b>Привет!</b>\n\n✅ Подписка до: <b>{until}</b> ({left})\n\n"
                      f"Нажми «📋 Моя подписка»", kb_user())
    elif u["status"] == "pending":
        send_msg(cid, "⏳ Заявка на рассмотрении", kb_pending())
    else:
        send_msg(cid, f"👋 <b>Привет!</b>\n\nНажми кнопку ниже для доступа 👇", kb_new())

def handle_panel(cid, mid=None):
    if mid: edit_msg(cid, mid, panel_text(), ik_panel())
    else: send_msg(cid, panel_text(), ik_panel())

def handle_run_update(cid, mid=None):
    txt = "🔄 <b>Обновляю ноды...</b>\n\nЭто займёт несколько минут."
    if mid: edit_msg(cid, mid, txt, ik_back())
    else: send_msg(cid, txt, ik_back())
    def _run():
        result = do_update()
        send_msg(cid, result, ik_back())
    threading.Thread(target=_run, daemon=True).start()

def handle_button(cid, uid, text, un, fn):
    uins(uid, un, fn)
    if text in ("📋 Моя подписка", "📋 Подписка"):
        send_subscription(cid, uid)
    elif text == "📊 Мой статус":
        u = uget(uid)
        if not u or u["status"] != "active":
            send_msg(cid, "❌ Нет активной подписки", kb_for(uid)); return
        tok = u["token"] or ""
        url = sub_url(tok)
        until = u["sub_until"][:10] if u["sub_until"] else "∞"
        left = days_left_str(u["sub_until"]) if u["sub_until"] else "∞"
        send_msg(cid, f"📊 <b>Статус</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
                      f"📅 До: <b>{until}</b>\n⏳ Осталось: <b>{left}</b>\n"
                      f"━━━━━━━━━━━━━━━━━━━━━━━━\n🔗 <code>{url}</code>", kb_for(uid))
    elif text == "ℹ️ Помощь":
        send_msg(cid, "ℹ️ <b>Помощь</b>\n\n📋 Моя подписка — ссылка для Hiddify/v2rayTUN\n"
                      "📊 Мой статус — срок действия\n\n❓ Вопросы → администратору", kb_for(uid))
    elif text == "🙋 Запросить доступ":
        u = uget(uid)
        if u and u["status"] == "active":
            send_msg(cid, "✅ Подписка уже активна!", kb_user()); return
        if u and u["status"] == "pending":
            send_msg(cid, "⏳ Заявка уже отправлена", kb_pending()); return
        uset(uid, "pending")
        send_msg(cid, "✅ <b>Заявка отправлена!</b>\n\nОжидай уведомления.", kb_pending())
        u = uget(uid)
        send_msg(ADMIN_ID, f"🔔 <b>Заявка</b>\n👤 {display_name(u)}\n🆔 <code>{uid}</code>",
                 ik_approve(uid))
    elif text == "📊 Панель" and uid == ADMIN_ID:
        handle_panel(cid)

def handle_command(cid, uid, un, fn, text):
    cmd = text.split()[0].split("@")[0].lower()
    if cmd == "/start": handle_start(cid, uid, un, fn)
    elif cmd == "/help":
        send_msg(cid, "ℹ️ <b>Помощь</b>\n\n/sub — подписка\n/start — меню", kb_for(uid))
    elif cmd in ("/sub", "/subscription"): send_subscription(cid, uid)
    elif cmd == "/panel" and uid == ADMIN_ID: handle_panel(cid)
    elif cmd == "/update" and uid == ADMIN_ID: handle_run_update(cid)
    elif cmd == "/adduser" and uid == ADMIN_ID:
        send_msg(cid, "➕ <b>Создать ссылку</b>\n\nВыбери срок:", ik_create_link())
    elif cmd == "/seturl" and uid == ADMIN_ID:
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            cur = get_setting("base_url") or BASE_URL or f"http://localhost:{HTTP_PORT}"
            send_msg(cid, f"🌐 URL: <code>{cur}</code>\n\n/seturl <code>https://...</code>\n/seturl auto", kb_admin())
            return
        val = parts[1].strip()
        if val.lower() == "auto":
            set_setting("base_url", "")
            send_msg(cid, "✅ URL сброшен", kb_admin())
        else:
            set_setting("base_url", val.rstrip("/"))
            send_msg(cid, f"✅ URL: <code>{val.rstrip('/')}</code>", kb_admin())


# ═══════════════════════════════════════════════════════
#  CALLBACK HANDLER
# ═══════════════════════════════════════════════════════
def handle_callback(cb):
    cid = cb["message"]["chat"]["id"]
    mid = cb["message"]["message_id"]
    data = cb.get("data", "")
    uid = cb["from"]["id"]
    un = cb["from"].get("username", "")
    fn = cb["from"].get("first_name", "")
    uins(uid, un, fn)
    answer_cb(cb["id"])

    if data == "get_sub":
        send_subscription(cid, uid); return
    if data == "req_access":
        u = uget(uid)
        if u and u["status"] == "active":
            send_msg(cid, "✅ Уже активна!", kb_user()); return
        if u and u["status"] == "pending":
            send_msg(cid, "⏳ Заявка отправлена", kb_pending()); return
        uset(uid, "pending")
        send_msg(cid, "✅ Заявка отправлена!", kb_pending())
        u = uget(uid)
        send_msg(ADMIN_ID, f"🔔 <b>Заявка</b>: {display_name(u)} <code>{uid}</code>",
                 ik_approve(uid))
        return

    if uid != ADMIN_ID:
        return

    # ── Админ ──
    if data == "panel":
        handle_panel(cid, mid)
    elif data == "do_update":
        handle_run_update(cid, mid)
    elif data == "settings":
        base = get_setting("base_url") or BASE_URL or f"http://localhost:{HTTP_PORT}"
        nc = node_count()
        edit_msg(cid, mid,
            f"⚙️ <b>Настройки</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🌐 URL:\n<code>{base}</code>\n\n📦 Нод: <b>{nc}</b>\n\n"
            f"/seturl <code>https://domain.com</code>\n/seturl auto", ik_back())
    elif data == "create_link":
        edit_msg(cid, mid, "➕ <b>Создать ссылку</b>\n\nВыбери срок:", ik_create_link())
    elif data == "links":
        kb, txt = links_list_text()
        edit_msg(cid, mid, txt, kb)
    elif data.startswith("lcard:"):
        tuid = int(data.split(":")[1])
        kb, txt = link_card_text(tuid)
        if kb: edit_msg(cid, mid, txt, kb)
    elif data.startswith("gen:"):
        months = int(data.split(":")[1])
        tok, url, until_str = create_user_link(months)
        send_msg(cid,
            f"✅ <b>Ссылка создана!</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📅 {months} мес (до {until_str})\n\n"
            f"🔗 <code>{url}</code>\n\n<i>Отправь пользователю</i>",
            {"inline_keyboard": [
                [{"text": "➕ Ещё", "callback_data": "create_link"}],
                [{"text": "◀️ Панель", "callback_data": "panel"}]]})
    elif data.startswith("ul:"):
        flt = data[3:]
        kb, txt = user_list_text(flt)
        edit_msg(cid, mid, txt, kb)
    elif data.startswith("manage:"):
        parts = data.split(":")
        tuid, lst = int(parts[1]), parts[2] if len(parts) > 2 else "all"
        kb, txt = user_card_text(tuid, lst)
        if kb: edit_msg(cid, mid, txt, kb)
    elif data.startswith("approve:"):
        _, us, ms = data.split(":")
        tuid, months = int(us), int(ms)
        tok, end = uapprove(tuid, months)
        end_str = end.strftime("%Y-%m-%d")
        mu = uget(tuid)
        url = sub_url(tok)
        edit_msg(cid, mid,
            f"✅ <b>Одобрено!</b>\n👤 {display_name(mu)}\n📅 До: {end_str}", ik_back())
        send_msg(tuid,
            f"🎉 <b>Доступ одобрен!</b>\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📅 До: <b>{end_str}</b>\n\n🔗 <code>{url}</code>\n\n"
            f"📱 Добавь в <b>Hiddify</b> / <b>v2rayTUN</b> 🚀", kb_user())
    elif data.startswith("reject:"):
        tuid = int(data.split(":")[1])
        mu = uget(tuid)
        ublock(tuid)
        edit_msg(cid, mid, f"❌ Отклонено: {display_name(mu)}", ik_back())
        try: send_msg(tuid, "❌ Заявка отклонена", kb_new())
        except: pass
    elif data.startswith("ext:"):
        parts = data.split(":")
        tuid, months, lst = int(parts[1]), int(parts[2]), parts[3] if len(parts) > 3 else "all"
        uapprove(tuid, months)
        if lst == "links":
            kb, txt = link_card_text(tuid)
        else:
            kb, txt = user_card_text(tuid, lst)
        if kb: edit_msg(cid, mid, txt, kb)
        if tuid > 0:
            mu = uget(tuid)
            try: send_msg(tuid, f"✅ Подписка продлена!\n📅 До: <b>{mu['sub_until'][:10]}</b>", kb_user())
            except: pass
    elif data.startswith("reset:"):
        parts = data.split(":")
        tuid, lst = int(parts[1]), parts[2] if len(parts) > 2 else "all"
        ureset_sub(tuid)
        if lst == "links":
            kb, txt = link_card_text(tuid)
        else:
            kb, txt = user_card_text(tuid, lst)
        if kb: edit_msg(cid, mid, txt, kb)
        if tuid > 0:
            try: send_msg(tuid, "⚠️ Подписка обнулена", kb_new())
            except: pass
    elif data.startswith("devreset:"):
        parts = data.split(":")
        tuid, lst = int(parts[1]), parts[2] if len(parts) > 2 else "all"
        u = uget(tuid)
        if u and u["token"]:
            device_reset(u["token"])
        if lst == "links":
            kb, txt = link_card_text(tuid)
        else:
            kb, txt = user_card_text(tuid, lst)
        if kb: edit_msg(cid, mid, txt, kb)
    elif data.startswith("block:"):
        parts = data.split(":")
        tuid, lst = int(parts[1]), parts[2] if len(parts) > 2 else "all"
        ublock(tuid)
        if lst == "links":
            kb, txt = link_card_text(tuid)
        else:
            kb, txt = user_card_text(tuid, lst)
        if kb: edit_msg(cid, mid, txt, kb)
        if tuid > 0:
            try: send_msg(tuid, "🚫 Подписка заблокирована", kb_new())
            except: pass
    elif data.startswith("cdel:"):
        parts = data.split(":")
        tuid, lst = int(parts[1]), parts[2] if len(parts) > 2 else "all"
        mu = uget(tuid)
        nm = display_name(mu) if mu else "?"
        edit_msg(cid, mid, f"⚠️ <b>Удалить {nm}?</b>", ik_confirm_del(tuid, lst))
    elif data.startswith("del:"):
        parts = data.split(":")
        tuid, lst = int(parts[1]), parts[2] if len(parts) > 2 else "all"
        mu = uget(tuid)
        nm = display_name(mu) if mu else str(tuid)
        udel(tuid)
        if lst == "links":
            kb, txt = links_list_text()
        else:
            kb, txt = user_list_text(lst)
        edit_msg(cid, mid, f"🗑 Удалён: {nm}\n\n" + txt, kb)
        if tuid > 0:
            try: send_msg(tuid, "❌ Аккаунт удалён", kb_new())
            except: pass


# ═══════════════════════════════════════════════════════
#  УВЕДОМЛЕНИЯ
# ═══════════════════════════════════════════════════════
def check_expiry():
    now = datetime.now(timezone.utc)
    for u in uactive():
        if not u["sub_until"]: continue
        until = datetime.fromisoformat(u["sub_until"]).replace(tzinfo=timezone.utc)
        days = (until - now).days
        notified = set((u["notified_days"] or "").split(","))
        if days < 0:
            if "expired" not in notified:
                try:
                    send_msg(u["id"], "⚠️ <b>Подписка истекла!</b>", kb_new())
                    send_msg(ADMIN_ID, f"⚠️ Истекла: {display_name(u)} <code>{u['id']}</code>",
                             {"inline_keyboard": [[{"text": "Продлить", "callback_data": f"manage:{u['id']}:act"}]]})
                    notified.add("expired")
                    with _db() as d:
                        d.execute("UPDATE users SET notified_days=? WHERE id=?",
                                  (",".join(notified), u["id"]))
                except: pass
            continue
        for dd in NOTIFY_DAYS:
            if days <= dd and str(dd) not in notified:
                try:
                    send_msg(u["id"], f"⏰ Подписка истекает через <b>{days_left_str(u['sub_until'])}</b>", kb_for(u["id"]))
                    notified.add(str(dd))
                    with _db() as d:
                        d.execute("UPDATE users SET notified_days=? WHERE id=?",
                                  (",".join(notified), u["id"]))
                except: pass


# ═══════════════════════════════════════════════════════
#  POLLING
# ═══════════════════════════════════════════════════════
def run_bot():
    log.info("Bot polling started")
    set_commands()
    offset = 0
    fail_count = 0
    last_expiry_check = 0
    last_node_update = 0

    from concurrent.futures import ThreadPoolExecutor
    pool = ThreadPoolExecutor(max_workers=4)

    while True:
        try:
            now = time.time()
            # Проверка истечений каждые 6 часов
            if now - last_expiry_check > 21600:
                last_expiry_check = now
                try: check_expiry()
                except: pass
            # Автообновление нод каждые 3 часа
            if now - last_node_update > 3600:
                last_node_update = now
                threading.Thread(target=do_update, args=(True,), daemon=True).start()

            resp = tg("getUpdates", {"offset": offset, "timeout": 30})
            fail_count = 0
            for upd in resp.get("result", []):
                offset = upd["update_id"] + 1
                try:
                    if "message" in upd:
                        m = upd["message"]
                        cid = m["chat"]["id"]
                        fr = m["from"]
                        uid, un, fn = fr["id"], fr.get("username", ""), fr.get("first_name", "")
                        txt = m.get("text", "")
                        if not txt: continue
                        uins(uid, un, fn)
                        if txt.startswith("/"):
                            pool.submit(handle_command, cid, uid, un, fn, txt)
                        else:
                            pool.submit(handle_button, cid, uid, txt, un, fn)
                    elif "callback_query" in upd:
                        pool.submit(handle_callback, upd["callback_query"])
                except Exception as e:
                    log.error(f"Handler error: {e}", exc_info=True)
        except urllib.error.HTTPError as e:
            if e.code == 409:
                log.warning("409 conflict, waiting 15s")
                time.sleep(15)
            else:
                fail_count += 1; time.sleep(min(fail_count * 5, 60))
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            fail_count += 1; time.sleep(min(fail_count * 5, 60))
        except Exception as e:
            fail_count += 1; log.error(f"Polling: {e}"); time.sleep(5)


# ═══════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════
if __name__ == "__main__":
    import time
    init_db()
    log.info(f"NoFuss started | admin={ADMIN_ID}")

    # Первый запуск — обновить ноды
    if not sub_ready():
        log.info("First run — updating nodes...")
        threading.Thread(target=do_update, daemon=True).start()

    threading.Thread(target=run_http, daemon=True).start()
    run_bot()
