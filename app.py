import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, jsonify, redirect, render_template_string,
    request, session, url_for, send_from_directory
)

app = Flask(__name__)

ALLOWED_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in os.environ.get("SCARRED_ALLOWED_ORIGINS", "https://scarredsite01.netlify.app").split(",")
    if origin.strip()
}

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

@app.route("/api/orders", methods=["OPTIONS"])
def orders_preflight():
    return ("", 204)
app.secret_key = os.environ.get("SCARRED_SECRET_KEY", "scarred-local-development-key-change-before-publishing")
ADMIN_PASSWORD = os.environ.get("SCARRED_ADMIN_PASSWORD", "scarred123")
BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "scarred_state.json"
DB_FILE = BASE_DIR / "scarred_orders.db"

STATUSES = {"Новая", "В работе", "Завершена", "Отменена"}


def db_connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                name TEXT NOT NULL,
                contact TEXT NOT NULL,
                service TEXT NOT NULL,
                budget TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Новая',
                ip_address TEXT NOT NULL DEFAULT 'не определён'
            )
        """)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(orders)").fetchall()}
        if "ip_address" not in columns:
            conn.execute("ALTER TABLE orders ADD COLUMN ip_address TEXT NOT NULL DEFAULT 'не определён'")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
        """)
init_db()

def client_ip():
    # Uses the direct connection address. Configure trusted proxy handling separately
    # if deployed behind a reverse proxy; do not trust arbitrary X-Forwarded-For headers.
    return request.remote_addr or "не определён"


def is_ip_blocked(ip):
    with db_connect() as conn:
        return conn.execute("SELECT 1 FROM blocked_ips WHERE ip_address = ?", (ip,)).fetchone() is not None


def is_site_open():
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8")).get("open", True)
    except (OSError, ValueError, TypeError):
        return True


def set_site_open(value):
    STATE_FILE.write_text(json.dumps({"open": bool(value)}), encoding="utf-8")


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return func(*args, **kwargs)
    return wrapper


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

app.jinja_env.globals["csrf_token"] = csrf_token

STYLE = """
*{box-sizing:border-box}body{margin:0;padding:28px 18px;background:#090909;color:#ededed;font-family:Inter,Arial,sans-serif}
a{color:inherit;text-decoration:none}.wrap{width:min(1050px,100%);margin:28px auto}.panel{padding:26px;background:#101010;border:1px solid #292929;margin:16px 0}.logo{font-size:24px;font-weight:800;letter-spacing:-1.5px}.muted{color:#909090}.top{display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap}.btn,button{display:inline-block;padding:10px 13px;background:#ededed;color:#090909;border:1px solid #ededed;font-size:12px;font-weight:700;cursor:pointer}.btn.secondary,button.secondary{background:transparent;color:#ededed;border-color:#444}.btn.danger,button.danger{background:#262626;color:#eee;border-color:#555}input,select,textarea{width:100%;padding:10px;background:#090909;color:#eee;border:1px solid #333;font:inherit}label{display:block;margin:10px 0 6px;font-size:12px;color:#aaa}.error{color:#ffaaaa}.status{font-size:11px;color:#aaa}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;vertical-align:top;padding:12px;border-bottom:1px solid #292929}th{color:#aaa;font-weight:500}td p{max-width:330px;white-space:pre-wrap;overflow-wrap:anywhere;color:#ccc}.actions{display:flex;gap:8px;flex-wrap:wrap}.inline{display:inline-flex;gap:6px;align-items:center}.small{font-size:11px;color:#999;line-height:1.6}.count{font-size:30px;font-weight:700}.field{margin-bottom:12px}.filters{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}@media(max-width:650px){.panel{padding:18px}th,td{padding:9px}.wrap{margin-top:8px}}
"""

LOGIN_PAGE = """<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Scarred — вход</title><style>""" + STYLE + """</style></head><body><main class='wrap'><section class='panel' style='max-width:430px;margin:70px auto'><div class='logo'>SCARRED.</div><h2>Вход администратора</h2><p class='muted'>Введи пароль для доступа к заявкам.</p>{% if error %}<p class='error'>{{ error }}</p>{% endif %}<form method='post'><input type='hidden' name='csrf_token' value='{{ csrf_token() }}'><label for='password'>Пароль</label><input id='password' name='password' type='password' required autofocus><p style='margin-top:16px'><button type='submit'>Войти</button></p></form><p class='small'>Для локального теста пароль по умолчанию — scarred123. Перед публикацией измени его.</p><a class='muted' href='/'>← На сайт</a></section></main></body></html>"""

DASHBOARD_PAGE = """<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Scarred — управление</title><style>""" + STYLE + """</style></head><body><main class='wrap'>
<header class='top'><div><div class='logo'>SCARRED.</div><p class='muted'>Панель управления</p></div><div class='actions'><a class='btn secondary' href='/' target='_blank'>Открыть сайт ↗</a><a class='btn secondary' href='{{ url_for("logout") }}'>Выйти</a></div></header>
<section class='panel'><div class='top'><div><div class='muted'>Заявок всего</div><div class='count'>{{ orders|length }}</div></div><div><div class='muted'>Сайт</div><p>{% if opened %}<strong>Открыт</strong>{% else %}<strong>Закрыт</strong>{% endif %}</p><form class='actions' method='post' action='{{ url_for("toggle_site") }}'><input type='hidden' name='csrf_token' value='{{ csrf_token() }}'><button class='secondary' name='open' value='{{ "false" if opened else "true" }}'>{{ 'Закрыть сайт' if opened else 'Открыть сайт' }}</button></form></div></div></section>
<section class='panel'><div class='top'><h2>Заявки</h2><div class='actions'><button class='secondary' id='soundToggle' type='button'>Включить звук</button><span class='muted' id='liveState'>Автопроверка новых заявок активна</span></div></div>
<p class='small'>Оставь эту вкладку открытой. Для звука сначала нажми «Включить звук» — это ограничение браузера.</p>
{% if orders %}<div class='table-wrap'><table><thead><tr><th># / Дата</th><th>Заказчик</th><th>Задача</th><th>IP-адрес</th><th>Статус</th><th>Действия</th></tr></thead><tbody>
{% for order in orders %}<tr><td>#{{ order['id'] }}<br><span class='small'>{{ order['created_at'] }}</span></td><td><strong>{{ order['name'] }}</strong><p>{{ order['contact'] }}</p></td><td><strong>{{ order['service'] }}</strong><p>Бюджет: {{ order['budget'] }}</p><p>{{ order['description'] }}</p></td><td><code>{{ order['ip_address'] }}</code>{% if order['ip_address'] != 'не определён' %}<form method='post' action='{{ url_for("block_ip") }}' onsubmit='return confirm("Заблокировать этот IP? Другие люди в той же сети тоже могут потерять доступ.")'><input type='hidden' name='csrf_token' value='{{ csrf_token() }}'><input type='hidden' name='ip_address' value='{{ order["ip_address"] }}'><button class='danger' type='submit'>Блокировать</button></form>{% endif %}</td><td>{{ order['status'] }}</td><td><form method='post' action='{{ url_for("update_order", order_id=order["id"]) }}'><input type='hidden' name='csrf_token' value='{{ csrf_token() }}'><select name='status'>{% for status in statuses %}<option value='{{ status }}' {% if status == order['status'] %}selected{% endif %}>{{ status }}</option>{% endfor %}</select><p style='margin-top:8px'><button type='submit'>Сохранить</button></p></form><form method='post' action='{{ url_for("delete_order", order_id=order["id"]) }}' onsubmit='return confirm("Удалить заявку #{{ order["id"] }}?")'><input type='hidden' name='csrf_token' value='{{ csrf_token() }}'><button class='danger' type='submit'>Удалить</button></form></td></tr>{% endfor %}
</tbody></table></div>{% else %}<p class='muted'>Пока заявок нет. Отправь тестовую заявку с главной страницы.</p>{% endif %}</section>
<section class='panel'><h2>Заблокированные IP</h2>
{% if blocked_ips %}<div class='table-wrap'><table><thead><tr><th>IP-адрес</th><th>Дата блокировки</th><th>Действие</th></tr></thead><tbody>{% for item in blocked_ips %}<tr><td><code>{{ item['ip_address'] }}</code></td><td>{{ item['created_at'] }}</td><td><form method='post' action='{{ url_for("unblock_ip") }}'><input type='hidden' name='csrf_token' value='{{ csrf_token() }}'><input type='hidden' name='ip_address' value='{{ item["ip_address"] }}'><button class='secondary' type='submit'>Разблокировать</button></form></td></tr>{% endfor %}</tbody></table></div>{% else %}<p class='muted'>Пока IP-адреса не заблокированы.</p>{% endif %}</section>
<p class='small'>IP-адреса сохраняются вместе с заявками. Укажи обработку IP в политике конфиденциальности. Блокировка IP может затронуть других пользователей общей сети. Заявки хранятся в scarred_orders.db.</p></main>
<script>
(() => {
  let lastId = Number({{ orders[0]['id'] if orders else 0 }});
  let soundEnabled = false;
  let audioCtx = null;
  const button = document.getElementById('soundToggle');
  const state = document.getElementById('liveState');
  function beep() {
    if (!soundEnabled || !audioCtx) return;
    try {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = 'sine'; osc.frequency.value = 880; gain.gain.value = 0.08;
      osc.connect(gain); gain.connect(audioCtx.destination);
      osc.start(); osc.stop(audioCtx.currentTime + 0.22);
    } catch (_) {}
  }
  button.addEventListener('click', async () => {
    try {
      audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
      await audioCtx.resume(); soundEnabled = true;
      button.textContent = 'Звук включён';
      state.textContent = 'Слушаю новые заявки · вкладка должна оставаться открытой';
      beep();
    } catch (_) { state.textContent = 'Браузер не разрешил звук'; }
  });
  async function poll() {
    try {
      const response = await fetch('/admin/api/latest-order-id', {cache:'no-store'});
      if (!response.ok) return;
      const data = await response.json();
      if (data.latest_id > lastId) {
        beep();
        lastId = data.latest_id;
        state.textContent = 'Новая заявка! Обновляю список…';
        window.location.reload();
      }
    } catch (_) { state.textContent = 'Соединение потеряно, повторная проверка…'; }
  }
  setInterval(poll, 5000);
})();
</script></body></html>"""

CLOSED_PAGE = """<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>SCARRED.</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#090909;color:#ededed;font-family:Arial,sans-serif;text-align:center;padding:24px}h1{font-size:clamp(42px,10vw,90px);letter-spacing:-.08em}p{color:#888}</style></head><body><main><h1>SCARRED.</h1><p>Сайт временно недоступен.</p></main></body></html>"""

@app.before_request
def check_admin_csrf():
    if request.method == "POST" and request.endpoint in {"admin_login", "toggle_site", "update_order", "delete_order", "block_ip", "unblock_ip"}:
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            abort(400, description="Неверный токен безопасности. Обнови страницу и попробуй снова.")

@app.route("/")
def home():
    if not is_site_open():
        return render_template_string(CLOSED_PAGE), 503
    return send_from_directory(str(BASE_DIR), "index.html")

@app.route("/api/orders", methods=["POST"])
def create_order():
    if not is_site_open():
        return jsonify(error="Приём заявок временно закрыт."), 503
    ip = client_ip()
    if is_ip_blocked(ip):
        return jsonify(error="Доступ с этого IP-адреса ограничен."), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Некорректные данные формы."), 400

    name = str(data.get("name", "")).strip()
    contact = str(data.get("contact", "")).strip()
    service = str(data.get("service", "")).strip()
    budget = str(data.get("budget", "Пока не знаю")).strip()
    description = str(data.get("description", "")).strip()

    allowed_services = {"Сайт", "Python и программы", "Дизайн", "Автоматизация", "Другое"}
    if not name or len(name) > 80:
        return jsonify(error="Укажи имя длиной до 80 символов."), 400
    if not contact or len(contact) > 160:
        return jsonify(error="Укажи контакт для связи (до 160 символов)."), 400
    if service not in allowed_services:
        return jsonify(error="Выбери тип проекта из списка."), 400
    if not description or len(description) > 3000:
        return jsonify(error="Описание должно содержать до 3000 символов."), 400
    if len(budget) > 80:
        return jsonify(error="Проверь поле бюджета."), 400

    created_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    with db_connect() as conn:
        cursor = conn.execute(
            "INSERT INTO orders (created_at, name, contact, service, budget, description, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (created_at, name, contact, service, budget, description, ip),
        )
        order_id = cursor.lastrowid
    return jsonify(ok=True, id=order_id), 201

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if session.get("admin"):
        return redirect(url_for("dashboard"))
    error = ""
    if request.method == "POST":
        supplied = request.form.get("password", "")
        if hmac.compare_digest(supplied, ADMIN_PASSWORD):
            session.clear()
            session["admin"] = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
        error = "Неверный пароль."
    return render_template_string(LOGIN_PAGE, error=error)

@app.route("/admin/api/latest-order-id")
@admin_required
def latest_order_id():
    with db_connect() as conn:
        row = conn.execute("SELECT COALESCE(MAX(id), 0) AS latest_id FROM orders").fetchone()
    response = jsonify(latest_id=row["latest_id"])
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/admin/ip/block", methods=["POST"])
@admin_required
def block_ip():
    ip = request.form.get("ip_address", "").strip()
    if not ip or len(ip) > 64 or ip == "не определён":
        abort(400, description="Некорректный IP-адрес.")
    created_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    with db_connect() as conn:
        conn.execute("INSERT OR IGNORE INTO blocked_ips (ip_address, created_at) VALUES (?, ?)", (ip, created_at))
    return redirect(url_for("dashboard"))


@app.route("/admin/ip/unblock", methods=["POST"])
@admin_required
def unblock_ip():
    ip = request.form.get("ip_address", "").strip()
    with db_connect() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    return redirect(url_for("dashboard"))


@app.route("/admin/dashboard")
@admin_required
def dashboard():
    with db_connect() as conn:
        orders = conn.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
        blocked_ips = conn.execute("SELECT * FROM blocked_ips ORDER BY created_at DESC").fetchall()
    return render_template_string(DASHBOARD_PAGE, orders=orders, blocked_ips=blocked_ips, opened=is_site_open(), statuses=sorted(STATUSES))

@app.route("/admin/order/<int:order_id>/status", methods=["POST"])
@admin_required
def update_order(order_id):
    status = request.form.get("status", "")
    if status not in STATUSES:
        abort(400, description="Неизвестный статус.")
    with db_connect() as conn:
        result = conn.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
        if result.rowcount == 0:
            abort(404)
    return redirect(url_for("dashboard"))

@app.route("/admin/order/<int:order_id>/delete", methods=["POST"])
@admin_required
def delete_order(order_id):
    with db_connect() as conn:
        conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    return redirect(url_for("dashboard"))

@app.route("/admin/toggle", methods=["POST"])
@admin_required
def toggle_site():
    set_site_open(request.form.get("open") == "true")
    return redirect(url_for("dashboard"))

@app.route("/admin/logout")
@admin_required
def logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/health")
def health():
    return jsonify(status="ok")

if __name__ == "__main__":
    init_db()
    print("SCARRED запущен")
    print("Сайт:    http://127.0.0.1:5000")
    print("Админка: http://127.0.0.1:5000/admin")
    print("Локальный пароль по умолчанию: scarred123")
    print("База заявок: scarred_orders.db")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
