# Flask backend ng New Berco Machine Shop: quote form + kumpletong admin login system

# Mga kailangang library
import getpass
import os
import re
import sqlite3
import secrets
import sys
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, send_from_directory, render_template,
    session, redirect, url_for, abort, flash, g,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Basahin ang .env file (kung naka-install ang python-dotenv); dapat ito ang una bago basahin ang mga setting
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- Mga setting at lokasyon ng mga file ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))      # folder kung nasaan ang app.py
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")             # dito mase-save ang mga larawan
DB_PATH = os.path.join(BASE_DIR, "quotes.db")              # SQLite database file
ALLOWED_EXT = {"jpg", "jpeg", "png", "webp", "gif"}        # mga pinapayagang uri ng larawan
MAX_UPLOAD_MB = 8                                          # pinakamalaking laki ng larawan
STATUSES = ["New", "Contacted", "Done"]                    # mga estado ng bawat request

# Mga setting ng login
MIN_PASSWORD = 10                                          # pinakamaikling password
IDLE_SECONDS = 60 * 60                                     # auto-logout pagkatapos ng 1 oras na walang galaw
REMEMBER_DAYS = 30                                         # tagal ng "Remember me"
MAX_TRIES = 5                                              # ilang maling subok bago i-lock
LOCK_SECONDS = 300                                         # tagal ng lock: 5 minuto

# Para sa pinakaunang owner account lang ang dalawang ito (binabasa sa .env kapag walang admin pa sa database)
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

os.makedirs(UPLOAD_DIR, exist_ok=True)                     # gumawa ng uploads folder kung wala pa

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = (MAX_UPLOAD_MB + 1) * 1024 * 1024   # limitahan ang laki ng request
# Secret key para sa pag-sign ng session cookie; kung wala sa .env, random ito at mag-log out ang lahat tuwing i-restart
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True               # hindi mababasa ng JavaScript ang cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"              # proteksyon laban sa cross-site na request
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("HTTPS_ONLY") == "1"   # itakda ang HTTPS_ONLY=1 kapag online na at may HTTPS
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=REMEMBER_DAYS)    # para sa "Remember me"


# --- Database ---
def get_db():
    # Magbukas ng koneksyon; row_factory para madaling basahin ang mga column ayon sa pangalan
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_str():
    # Kasalukuyang oras bilang text
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    # Gumawa ng mga table kung wala pa
    with get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS quotes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                name TEXT NOT NULL,
                contact TEXT NOT NULL,
                service TEXT NOT NULL,
                notes TEXT NOT NULL,
                photo TEXT,
                status TEXT NOT NULL DEFAULT 'New'
            )"""
        )
        # Para sa lumang quotes.db na walang "status" column
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(quotes)")]
        if "status" not in cols:
            conn.execute("ALTER TABLE quotes ADD COLUMN status TEXT NOT NULL DEFAULT 'New'")

        # Mga admin account; password ay naka-hash, hindi kailanman nakasulat nang buo
        conn.execute(
            """CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'staff',
                must_change INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login TEXT
            )"""
        )
        # Tala ng lahat ng subok mag-login (tagumpay at hindi)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS login_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                username TEXT NOT NULL,
                ip TEXT NOT NULL,
                ok INTEGER NOT NULL
            )"""
        )
        # Kapag wala pang admin at may ADMIN_PASSWORD sa .env, gawin itong unang owner
        if conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0 and ADMIN_PASSWORD:
            conn.execute(
                "INSERT INTO admins (username, password_hash, role, created_at) VALUES (?, ?, 'owner', ?)",
                (ADMIN_USER, generate_password_hash(ADMIN_PASSWORD), now_str()),
            )


init_db()
DUMMY_HASH = generate_password_hash("not-a-real-password")  # panlinlang para pantay ang oras ng sagot kahit mali ang username


# --- Proteksyon: CSRF token at limit sa maling login ---
def csrf_token():
    # Gumawa ng random na token na nakatali sa session ng user
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token           # magagamit ang csrf_token() sa mga template


@app.context_processor
def inject_user():
    # Magagamit ang "me" (naka-login na admin) sa lahat ng template
    return {"me": g.get("user")}


def check_csrf():
    # Siguraduhing galing sa sarili nating form ang POST; kung hindi, tanggihan
    sent = request.form.get("csrf", "").encode()
    if not secrets.compare_digest(sent, session.get("csrf", "").encode()):
        abort(400)


FAILED = {}              # tala ng maling login bawat IP: {ip: (bilang, oras ng pagtatapos ng lock)}


def is_locked(ip):
    # Tingnan kung naka-lock pa ang IP; kapag tapos na ang lock, burahin ang tala
    rec = FAILED.get(ip)
    if rec and rec[1]:
        if rec[1] > time.time():
            return True
        FAILED.pop(ip, None)
    return False


def record_fail(ip):
    # Dagdagan ang bilang ng maling subok; i-lock kapag umabot sa limit
    count = FAILED.get(ip, (0, 0))[0] + 1
    FAILED[ip] = (count, time.time() + LOCK_SECONDS if count >= MAX_TRIES else 0)


def log_event(username, ip, ok):
    # Isulat sa login_log ang bawat subok mag-login
    with get_db() as conn:
        conn.execute("INSERT INTO login_log (at, username, ip, ok) VALUES (?, ?, ?, ?)",
                     (now_str(), username[:50], ip, 1 if ok else 0))


def validate_password(pw, username):
    # Mga patakaran ng password; ibabalik ang mensahe ng error o None kung ayos
    if len(pw) < MIN_PASSWORD:
        return "Password must be at least %d characters." % MIN_PASSWORD
    if pw.lower() == username.lower():
        return "Password cannot be the same as the username."
    if pw.isdigit() or pw.isalpha():
        return "Use a mix of letters and numbers (or symbols)."
    return None


# --- Decorators: kailangang naka-login, at kailangang owner ---
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        uid = session.get("uid")
        if not uid:
            return redirect(url_for("admin_login"))
        # Auto-logout kapag masyadong matagal na walang galaw
        if time.time() - session.get("last_seen", 0) > session.get("idle", IDLE_SECONDS):
            session.clear()
            flash("You were logged out after a period of inactivity. Please log in again.", "error")
            return redirect(url_for("admin_login"))
        # Kunin ang account sa database; kapag nabura na ito, i-logout
        with get_db() as conn:
            user = conn.execute("SELECT * FROM admins WHERE id = ?", (uid,)).fetchone()
        if not user:
            session.clear()
            return redirect(url_for("admin_login"))
        g.user = user
        session["last_seen"] = time.time()
        # Kapag temporary ang password, bago gumamit ng iba, kailangang magpalit muna
        if user["must_change"] and request.endpoint not in ("change_password", "admin_logout"):
            flash("Please set a new password to continue.", "error")
            return redirect(url_for("change_password"))
        return view(*args, **kwargs)
    return wrapper


def owner_required(view):
    # Para sa mga page na owner lang ang puwede
    @wraps(view)
    def inner(*args, **kwargs):
        if g.user["role"] != "owner":
            abort(403)
        return view(*args, **kwargs)
    return login_required(inner)


# --- Mga tulong na function para sa larawan ---
def looks_like_image(head: bytes) -> bool:
    # Tingnan ang unang bytes ng file para siguradong totoong larawan, hindi lang pinalitan ang extension
    return (
        head.startswith(b"\xff\xd8\xff")                          # JPEG
        or head.startswith(b"\x89PNG\r\n\x1a\n")                  # PNG
        or head.startswith(b"GIF87a") or head.startswith(b"GIF89a")  # GIF
        or (head[:4] == b"RIFF" and head[8:12] == b"WEBP")        # WebP
    )


def save_photo(file):
    # I-save ang larawan; ibabalik ang bagong filename, o None kung walang larawan
    if not file or not file.filename:
        return None
    ext = secure_filename(file.filename).rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXT:
        raise ValueError("Photo must be a JPG, PNG, WebP, or GIF image.")
    if not looks_like_image(file.stream.read(16)):
        raise ValueError("That file does not look like a valid image.")
    file.stream.seek(0)
    name = uuid.uuid4().hex + "." + ext                           # random na pangalan para walang magkabanggaan
    file.save(os.path.join(UPLOAD_DIR, name))
    return name


# --- Pampublikong mga route ---
@app.route("/")
def home():
    # Ipakita ang index.html mula sa parehong folder
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/quote", methods=["POST"])
def create_quote():
    # Tumatanggap ng form data mula sa website
    form = request.form
    if form.get("website", "").strip():                           # honeypot: bot ito kung may laman
        return jsonify(ok=True, ref="BER-00000")

    name = form.get("name", "").strip()
    contact = form.get("contact", "").strip()
    service = form.get("service", "").strip()
    notes = form.get("notes", "").strip()

    # Server-side validation (hindi dapat umasa sa JavaScript lang)
    if not (name and contact and service and notes):
        return jsonify(ok=False, error="Please fill in all required fields."), 400
    if len(name) > 100 or len(contact) > 100 or len(service) > 100 or len(notes) > 2000:
        return jsonify(ok=False, error="One of the fields is too long."), 400

    try:
        photo = save_photo(request.files.get("photo"))
    except ValueError as err:
        return jsonify(ok=False, error=str(err)), 400

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO quotes (created_at, name, contact, service, notes, photo, status) VALUES (?, ?, ?, ?, ?, ?, 'New')",
            (datetime.now().strftime("%Y-%m-%d %H:%M"), name, contact, service, notes, photo),
        )
        ref = "BER-%05d" % cur.lastrowid                          # reference number para sa customer
    return jsonify(ok=True, ref=ref)


@app.errorhandler(413)
def too_large(_err):
    # Kapag lampas sa limit ang laki ng ipinadala
    return jsonify(ok=False, error="Upload is too large. Use a photo under %d MB." % MAX_UPLOAD_MB), 413


# --- Login, logout, at pagpalit ng password ---
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
    if count == 0:
        return render_template("login.html", disabled=True), 503   # wala pang admin account
    if session.get("uid"):
        return redirect(url_for("dashboard"))                      # naka-login na

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if is_locked(ip):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
        else:
            check_csrf()
            with get_db() as conn:
                row = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
            # Laging mag-check ng hash, kahit walang ganoong username, para pantay ang oras
            good = check_password_hash(row["password_hash"] if row else DUMMY_HASH, password) and row is not None
            if good:
                session.clear()                                    # bagong session para iwas session fixation
                session["uid"] = row["id"]
                session["last_seen"] = time.time()
                remember = bool(request.form.get("remember"))
                session.permanent = remember                       # kapag hindi remember, mawawala ang login pagsara ng browser
                session["idle"] = REMEMBER_DAYS * 86400 if remember else IDLE_SECONDS
                with get_db() as conn:
                    conn.execute("UPDATE admins SET last_login = ? WHERE id = ?", (now_str(), row["id"]))
                log_event(username, ip, True)
                FAILED.pop(ip, None)
                return redirect(url_for("dashboard"))
            record_fail(ip)
            log_event(username, ip, False)
            flash("Incorrect username or password.", "error")
    return render_template("login.html", disabled=False)


@app.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    # Mag-logout ang admin
    check_csrf()
    session.clear()
    flash("You have been logged out.", "ok")
    return redirect(url_for("admin_login"))


@app.route("/admin/password", methods=["GET", "POST"])
@login_required
def change_password():
    # Palitan ang sariling password
    if request.method == "POST":
        check_csrf()
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        problem = validate_password(new, g.user["username"])
        if not check_password_hash(g.user["password_hash"], current):
            flash("Your current password is incorrect.", "error")
        elif new != confirm:
            flash("The new passwords do not match.", "error")
        elif problem:
            flash(problem, "error")
        elif check_password_hash(g.user["password_hash"], new):
            flash("The new password must be different from the current one.", "error")
        else:
            with get_db() as conn:
                conn.execute("UPDATE admins SET password_hash = ?, must_change = 0 WHERE id = ?",
                             (generate_password_hash(new), g.user["id"]))
            flash("Password changed.", "ok")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html")


# --- Pamamahala ng mga account (owner lang) ---
@app.route("/admin/users")
@owner_required
def users():
    # Listahan ng mga admin at staff account
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM admins ORDER BY id").fetchall()
    return render_template("user.html", users=rows)


@app.route("/admin/users/add", methods=["POST"])
@owner_required
def add_user():
    # Gumawa ng bagong account na may temporary password
    check_csrf()
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "staff")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username) or role not in ("owner", "staff"):
        flash("Username must be 3-30 letters, numbers, dots, dashes, or underscores.", "error")
        return redirect(url_for("users"))
    temp = secrets.token_urlsafe(9)                               # random na temporary password
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO admins (username, password_hash, role, must_change, created_at) VALUES (?, ?, ?, 1, ?)",
                (username, generate_password_hash(temp), role, now_str()),
            )
        flash("Account created. Temporary password for %s: %s (shown only once; they must change it at first login)." % (username, temp), "ok")
    except sqlite3.IntegrityError:
        flash("That username is already taken.", "error")
    return redirect(url_for("users"))


@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@owner_required
def reset_user(user_id):
    # Bigyan ng bagong temporary password ang ibang account (para sa nakalimot)
    check_csrf()
    if user_id == g.user["id"]:
        abort(400)                                                # sariling password: gamitin ang Change password
    temp = secrets.token_urlsafe(9)
    with get_db() as conn:
        row = conn.execute("SELECT username FROM admins WHERE id = ?", (user_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("UPDATE admins SET password_hash = ?, must_change = 1 WHERE id = ?",
                     (generate_password_hash(temp), user_id))
    flash("New temporary password for %s: %s (shown only once)." % (row["username"], temp), "ok")
    return redirect(url_for("users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@owner_required
def delete_user(user_id):
    # Burahin ang account; hindi puwedeng sarili o ang huling owner
    check_csrf()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM admins WHERE id = ?", (user_id,)).fetchone()
        owners = conn.execute("SELECT COUNT(*) FROM admins WHERE role = 'owner'").fetchone()[0]
        if not row:
            abort(404)
        if user_id == g.user["id"]:
            flash("You cannot delete your own account.", "error")
        elif row["role"] == "owner" and owners <= 1:
            flash("You cannot delete the last owner account.", "error")
        else:
            conn.execute("DELETE FROM admins WHERE id = ?", (user_id,))
            flash("Account %s deleted." % row["username"], "ok")
    return redirect(url_for("users"))


@app.route("/admin/security")
@owner_required
def security():
    # Tala ng mga subok mag-login: sino, kailan, mula saang IP, at tagumpay ba
    since = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM login_log ORDER BY id DESC LIMIT 100").fetchall()
        failed = conn.execute("SELECT COUNT(*) FROM login_log WHERE ok = 0 AND at >= ?", (since,)).fetchone()[0]
    return render_template("security.html", rows=rows, failed=failed)


# --- Dashboard at mga quote request ---
@app.route("/admin")
@login_required
def dashboard():
    # Mga bilang, paghahanap, filter ayon sa status, at listahan ng lahat ng request
    status = request.args.get("status", "")
    q = request.args.get("q", "").strip()
    sql = "SELECT * FROM quotes WHERE 1=1"
    params = []
    if status in STATUSES:
        sql += " AND status = ?"
        params.append(status)
    if q:
        sql += " AND (name LIKE ? OR contact LIKE ? OR notes LIKE ? OR service LIKE ?)"
        params += ["%" + q + "%"] * 4
    sql += " ORDER BY id DESC"
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
        counts = {s: conn.execute("SELECT COUNT(*) FROM quotes WHERE status = ?", (s,)).fetchone()[0] for s in STATUSES}
    return render_template(
        "dashboard.html", quotes=rows, counts=counts, total=sum(counts.values()),
        statuses=STATUSES, current=status if status in STATUSES else "", q=q,
    )


@app.route("/admin/quotes")
@login_required
def admin_quotes_old():
    # Lumang address; ihatid sa dashboard
    return redirect(url_for("dashboard"))


@app.route("/admin/quotes/<int:quote_id>/status", methods=["POST"])
@login_required
def set_status(quote_id):
    # Palitan ang status ng isang request (puwede ang staff)
    check_csrf()
    status = request.form.get("status", "")
    if status not in STATUSES:
        abort(400)
    with get_db() as conn:
        conn.execute("UPDATE quotes SET status = ? WHERE id = ?", (status, quote_id))
    return redirect(url_for("dashboard", status=request.form.get("f_status", ""), q=request.form.get("f_q", "")))


@app.route("/admin/quotes/<int:quote_id>/delete", methods=["POST"])
@owner_required
def delete_quote(quote_id):
    # Burahin ang request at ang larawan nito (owner lang)
    check_csrf()
    with get_db() as conn:
        row = conn.execute("SELECT photo FROM quotes WHERE id = ?", (quote_id,)).fetchone()
        conn.execute("DELETE FROM quotes WHERE id = ?", (quote_id,))
    if row and row["photo"]:
        path = os.path.join(UPLOAD_DIR, os.path.basename(row["photo"]))   # basename para hindi makalabas sa uploads folder
        if os.path.isfile(path):
            os.remove(path)
    return redirect(url_for("dashboard", status=request.form.get("f_status", ""), q=request.form.get("f_q", "")))


@app.route("/admin/uploads/<path:filename>")
@login_required
def admin_upload(filename):
    # Ang mga larawan ay makikita lang ng naka-login na admin
    return send_from_directory(UPLOAD_DIR, filename)


# --- Command para sa nakalimot ng password: python app.py set-password <username> ---
def cli_set_password(username):
    # Itakda ang password mula sa terminal ng server (hindi lumalabas ang tina-type)
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Repeat password: "):
        print("Passwords do not match.")
        return
    problem = validate_password(pw, username)
    if problem:
        print(problem)
        return
    with get_db() as conn:
        row = conn.execute("SELECT id FROM admins WHERE username = ?", (username,)).fetchone()
        if row:
            conn.execute("UPDATE admins SET password_hash = ?, must_change = 0 WHERE id = ?",
                         (generate_password_hash(pw), row["id"]))
            print("Password updated for %s." % username)
        elif conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0:
            conn.execute("INSERT INTO admins (username, password_hash, role, created_at) VALUES (?, ?, 'owner', ?)",
                         (username, generate_password_hash(pw), now_str()))
            print("Owner account %s created." % username)
        else:
            print("No account named %s." % username)


# --- Pagpapatakbo ---
if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "set-password":
        cli_set_password(sys.argv[2])
    else:
        # Para sa pagsubok sa sariling computer; sa totoong server, gumamit ng gunicorn
        app.run(host="0.0.0.0", port=5000, debug=False)