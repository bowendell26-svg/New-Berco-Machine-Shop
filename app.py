# Flask backend ng New Berco Machine Shop: quote form + admin login + dashboard

# Mga kailangang library
import os
import sqlite3
import secrets
import time
import uuid
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, jsonify, send_from_directory, render_template,
    session, redirect, url_for, abort,
)
from werkzeug.utils import secure_filename

# Basahin ang .env file (kung naka-install ang python-dotenv); dapat ito ang una bago basahin ang mga setting
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # kapag wala ang python-dotenv, gagamitin na lang ang environment variables ng terminal

# --- Mga setting at lokasyon ng mga file ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))      # folder kung nasaan ang app.py
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")             # dito mase-save ang mga larawan
DB_PATH = os.path.join(BASE_DIR, "quotes.db")              # SQLite database file
ALLOWED_EXT = {"jpg", "jpeg", "png", "webp", "gif"}        # mga pinapayagang uri ng larawan
MAX_UPLOAD_MB = 8                                          # pinakamalaking laki ng larawan
STATUSES = ["New", "Contacted", "Done"]                    # mga estado ng bawat request

# Login ng admin; itakda sa .env o sa environment, huwag isulat dito sa code
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")      # kapag walang laman, naka-disable ang admin login

os.makedirs(UPLOAD_DIR, exist_ok=True)                     # gumawa ng uploads folder kung wala pa

app = Flask(__name__)
# Limitahan ang kabuuang laki ng request para hindi ma-overload ang server
app.config["MAX_CONTENT_LENGTH"] = (MAX_UPLOAD_MB + 1) * 1024 * 1024
# Secret key para sa pag-sign ng session cookie; kung walang SECRET_KEY sa .env, random ito at mag-log out ang admin tuwing i-restart
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True               # hindi mababasa ng JavaScript ang cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"              # proteksyon laban sa cross-site na request
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("HTTPS_ONLY") == "1"  # itakda ang HTTPS_ONLY=1 kapag online na at may HTTPS
app.config["PERMANENT_SESSION_LIFETIME"] = 8 * 60 * 60     # mag-e-expire ang login pagkatapos ng 8 oras


# --- Database ---
def get_db():
    # Magbukas ng koneksyon; row_factory para madaling basahin ang mga column ayon sa pangalan
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    # Gumawa ng table ng mga quote request kung wala pa
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
        # Para sa lumang quotes.db na walang "status" column: idagdag ito nang hindi nabubura ang mga lumang request
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(quotes)")]
        if "status" not in cols:
            conn.execute("ALTER TABLE quotes ADD COLUMN status TEXT NOT NULL DEFAULT 'New'")


init_db()


# --- Proteksyon: CSRF token at limit sa maling login ---
def csrf_token():
    # Gumawa ng random na token na nakatali sa session ng user
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token           # magagamit ang csrf_token() sa mga template


def check_csrf():
    # Siguraduhing galing sa sarili nating form ang POST; kung hindi, tanggihan
    sent = request.form.get("csrf", "").encode()
    if not secrets.compare_digest(sent, session.get("csrf", "").encode()):
        abort(400)


FAILED = {}              # tala ng maling login bawat IP: {ip: (bilang, oras ng pagtatapos ng lock)}
MAX_TRIES = 5            # ilang maling subok bago i-lock
LOCK_SECONDS = 300       # tagal ng lock: 5 minuto


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


def login_required(view):
    # Decorator: kailangang naka-login ang admin bago makita ang page
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapper


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
    file.stream.seek(0)                                           # ibalik sa simula pagkatapos basahin ang header
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

    # Honeypot: nakatagong field na hindi pinupunan ng totoong tao; kapag may laman, bot ito
    if form.get("website", "").strip():
        return jsonify(ok=True, ref="BER-00000")                  # magkunwaring tagumpay, pero huwag i-save

    # Kunin at linisin ang mga field
    name = form.get("name", "").strip()
    contact = form.get("contact", "").strip()
    service = form.get("service", "").strip()
    notes = form.get("notes", "").strip()

    # Server-side validation (hindi dapat umasa sa JavaScript lang)
    if not (name and contact and service and notes):
        return jsonify(ok=False, error="Please fill in all required fields."), 400
    if len(name) > 100 or len(contact) > 100 or len(service) > 100 or len(notes) > 2000:
        return jsonify(ok=False, error="One of the fields is too long."), 400

    # I-save ang larawan kung meron
    try:
        photo = save_photo(request.files.get("photo"))
    except ValueError as err:
        return jsonify(ok=False, error=str(err)), 400

    # I-save ang request sa database; "New" ang unang status
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


# --- Mga route ng admin ---
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    # Login page ng admin
    if not ADMIN_PASSWORD:
        return render_template("login.html", error=None, disabled=True), 503
    if session.get("admin"):
        return redirect(url_for("dashboard"))                     # naka-login na, diretso sa dashboard

    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if is_locked(ip):
            error = "Too many failed attempts. Try again in a few minutes."
        else:
            check_csrf()
            user = request.form.get("username", "").encode()
            pw = request.form.get("password", "").encode()
            # compare_digest para hindi mahulaan ang password sa pamamagitan ng bilis ng sagot
            ok_user = secrets.compare_digest(user, ADMIN_USER.encode())
            ok_pw = secrets.compare_digest(pw, ADMIN_PASSWORD.encode())
            if ok_user and ok_pw:
                session.clear()                                   # bagong session para iwas session fixation
                session["admin"] = True
                session.permanent = True
                FAILED.pop(ip, None)
                return redirect(url_for("dashboard"))
            record_fail(ip)
            error = "Incorrect username or password."
    return render_template("login.html", error=error, disabled=False)


@app.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    # Mag-logout ang admin
    check_csrf()
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin")
@login_required
def dashboard():
    # Dashboard: mga bilang, paghahanap, filter ayon sa status, at listahan ng lahat ng request
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
        counts = {
            s: conn.execute("SELECT COUNT(*) FROM quotes WHERE status = ?", (s,)).fetchone()[0]
            for s in STATUSES
        }
    return render_template(
        "dashboard.html", quotes=rows, counts=counts, total=sum(counts.values()),
        statuses=STATUSES, current=status if status in STATUSES else "", q=q,
    )


@app.route("/admin/quotes")
@login_required
def admin_quotes_old():
    # Lumang address; ihatid sa bagong dashboard
    return redirect(url_for("dashboard"))


@app.route("/admin/quotes/<int:quote_id>/status", methods=["POST"])
@login_required
def set_status(quote_id):
    # Palitan ang status ng isang request (New / Contacted / Done)
    check_csrf()
    status = request.form.get("status", "")
    if status not in STATUSES:
        abort(400)
    with get_db() as conn:
        conn.execute("UPDATE quotes SET status = ? WHERE id = ?", (status, quote_id))
    # Bumalik sa dashboard na nasa parehong filter at paghahanap
    return redirect(url_for("dashboard", status=request.form.get("f_status", ""), q=request.form.get("f_q", "")))


@app.route("/admin/quotes/<int:quote_id>/delete", methods=["POST"])
@login_required
def delete_quote(quote_id):
    # Burahin ang request at ang larawan nito
    check_csrf()
    with get_db() as conn:
        row = conn.execute("SELECT photo FROM quotes WHERE id = ?", (quote_id,)).fetchone()
        conn.execute("DELETE FROM quotes WHERE id = ?", (quote_id,))
    if row and row["photo"]:
        path = os.path.join(UPLOAD_DIR, os.path.basename(row["photo"]))  # basename para hindi makalabas sa uploads folder
        if os.path.isfile(path):
            os.remove(path)
    return redirect(url_for("dashboard", status=request.form.get("f_status", ""), q=request.form.get("f_q", "")))


@app.route("/admin/uploads/<path:filename>")
@login_required
def admin_upload(filename):
    # Ang mga larawan ay makikita lang ng naka-login na admin; hindi ito pampublikong folder
    return send_from_directory(UPLOAD_DIR, filename)


# --- Pagpapatakbo ---
if __name__ == "__main__":
    # Para sa pagsubok sa sariling computer; sa totoong server, gumamit ng gunicorn
    app.run(host="0.0.0.0", port=5000, debug=False)