import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from database import get_connection, init_db, generate_org_code
from translations import TRANSLATIONS
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from email_service import generate_verification_code, send_org_verification, send_staff_notification
from datetime import datetime, timedelta

app = Flask(__name__)

# ══════════════════════════════════════════
# 1. Secret Key من البيئة (لا تضعها في الكود أبداً)
#    في PythonAnywhere: Web → Environment variables → SECRET_KEY
#    قيمة عشوائية مثال: python3 -c "import secrets; print(secrets.token_hex(32))"
# ══════════════════════════════════════════
app.secret_key = os.environ.get("SECRET_KEY") or "3c23c600bdf76f847bcd15584b92ad49d63764935b05e1a4a06d5c75e9e03aaa"

# ══════════════════════════════════════════
# 2. إعدادات Session الآمنة
# ══════════════════════════════════════════
app.config["SESSION_COOKIE_HTTPONLY"]  = True   # لا يصل JavaScript للـ cookie
app.config["SESSION_COOKIE_SAMESITE"]  = "Lax"  # حماية CSRF جزئية
app.config["SESSION_COOKIE_SECURE"]    = True   # HTTPS فقط
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)  # تنتهي بعد 8 ساعات

UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024  # 3MB حد رفع الملفات

# ══════════════════════════════════════════
# 3. Brute Force Protection — تتبع محاولات تسجيل الدخول
# ══════════════════════════════════════════
_login_attempts: dict = {}   # {ip: {"count": N, "blocked_until": datetime}}
MAX_LOGIN_ATTEMPTS = 5
BLOCK_MINUTES = 15

def _get_ip():
    # نستخدم remote_addr الحقيقي من الـ proxy — لا نثق بـ X-Forwarded-For القابل للتلاعب
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # آخر IP في السلسلة هو الـ proxy الموثوق
        return forwarded.split(",")[-1].strip()
    return request.remote_addr or "unknown"

def _is_blocked(ip):
    rec = _login_attempts.get(ip)
    if not rec:
        return False
    if rec.get("blocked_until") and datetime.now() < rec["blocked_until"]:
        return True
    if rec.get("blocked_until") and datetime.now() >= rec["blocked_until"]:
        _login_attempts.pop(ip, None)
    return False

def _record_failed(ip):
    rec = _login_attempts.setdefault(ip, {"count": 0, "blocked_until": None})
    rec["count"] += 1
    if rec["count"] >= MAX_LOGIN_ATTEMPTS:
        rec["blocked_until"] = datetime.now() + timedelta(minutes=BLOCK_MINUTES)

def _clear_attempts(ip):
    _login_attempts.pop(ip, None)

# ══════════════════════════════════════════
# 4. CSRF Token
# ══════════════════════════════════════════
def generate_csrf():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(24)
    return session["_csrf"]

def validate_csrf():
    token = session.get("_csrf")
    form_token = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or not form_token or not secrets.compare_digest(token, form_token):
        return False
    return True

app.jinja_env.globals["csrf_token"] = generate_csrf

# ══════════════════════════════════════════
# 5. Security Headers لكل الردود
# ══════════════════════════════════════════
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"]        = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-XSS-Protection"]       = "1; mode=block"
    resp.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com "
        "https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; style-src 'self' 'unsafe-inline' "
        "https://cdn.jsdelivr.net https://fonts.googleapis.com "
        "https://cdnjs.cloudflare.com; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;"
    )
    return resp

# ══════════════════════════════════════════
# 6. Session Timeout — التحقق عند كل طلب
# ══════════════════════════════════════════
@app.before_request
def check_session_timeout():
    if "user_id" not in session:
        return
    last = session.get("_last_active")
    if last:
        idle = (datetime.now() - datetime.fromisoformat(last)).total_seconds()
        if idle > 8 * 3600:
            session.clear()
            flash("انتهت جلستك، يرجى تسجيل الدخول مجدداً", "warning")
            return redirect(url_for("login"))
    session["_last_active"] = datetime.now().isoformat()

init_db()
from database import migrate_db; migrate_db()

# ══════════════════════════════════════════
# Language support — AR / TR
# ══════════════════════════════════════════
@app.route("/set_lang/<lang>")
def set_lang(lang):
    if lang in ('ar', 'tr', 'en'):
        session['lang'] = lang
    return redirect(request.referrer or url_for('dashboard'))

@app.context_processor
def inject_lang():
    lang = session.get('lang', 'ar')
    return dict(t=TRANSLATIONS[lang], lang=lang)

# ══════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════

# فحص الامتداد + المحتوى الفعلي للصورة (magic bytes)
_IMG_MAGIC = {
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG":      "png",
    b"RIFF":         "webp",
    b"GIF8":         "gif",
}

def allowed_file(f):
    if "." not in f:
        return False
    return f.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_file_content(file_storage):
    """يفحص magic bytes الفعلية للملف، ليس فقط الامتداد"""
    header = file_storage.read(12)
    file_storage.seek(0)
    for magic, ftype in _IMG_MAGIC.items():
        if header.startswith(magic):
            return ftype in ALLOWED_EXTENSIONS
    return False


def _csrf_check():
    """يرفض POST بدون CSRF token صحيح"""
    if request.method == "POST" and not validate_csrf():
        flash("طلب غير صالح (CSRF). أعد المحاولة.", "danger")
        return redirect(request.referrer or url_for("dashboard"))


def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            flash("يجب تسجيل الدخول أولاً", "warning")
            return redirect(url_for("login"))
        err = _csrf_check()
        if err: return err
        return f(*a, **kw)
    return dec


def admin_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("هذه الصفحة للمدير فقط", "danger")
            return redirect(url_for("dashboard"))
        err = _csrf_check()
        if err: return err
        return f(*a, **kw)
    return dec


def invoices_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "accountant"):
            flash("ليس لديك صلاحية الوصول", "danger")
            return redirect(url_for("dashboard"))
        err = _csrf_check()
        if err: return err
        return f(*a, **kw)
    return dec


def data_entry_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "data_entry"):
            flash("ليس لديك صلاحية الوصول", "danger")
            return redirect(url_for("dashboard"))
        err = _csrf_check()
        if err: return err
        return f(*a, **kw)
    return dec


def observer_required(f):
    """المراقب العام: يرى فقط — لا يعدّل"""
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "accountant", "data_entry", "observer"):
            flash("ليس لديك صلاحية الوصول", "danger")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return dec


def invoices_view_required(f):
    """عرض صفحات المشتريات/المخزن: أدمن + محاسب + مراقب عام (المراقب لا يستطيع الحفظ)"""
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "accountant", "observer"):
            flash("ليس لديك صلاحية الوصول", "danger")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return dec


def data_entry_view_required(f):
    """عرض صفحة المستفيدين: أدمن + مدخل بيانات + مراقب عام (المراقب لا يستطيع الحفظ)"""
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "data_entry", "observer"):
            flash("ليس لديك صلاحية الوصول", "danger")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return dec


def programs_view_required(f):
    """عرض صفحات البرامج والمشاريع: أدمن + محاسب + مراقب عام"""
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "accountant", "observer"):
            flash("ليس لديك صلاحية الوصول", "danger")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return dec


def set_session(user, org):
    session["user_id"]   = user["id"]
    session["org_id"]    = user["org_id"]
    session["org_name"]  = org["name"]
    session["org_code"]  = org["org_code"]
    session["user"]      = user["username"]
    session["full_name"] = user["full_name"] or user["username"]
    session["role"]      = user["role"]
    session["photo"]     = user["photo"] or ""


def row_to_dict(row, fallback_keys=None):
    """تحويل sqlite3.Row لـ dict بأمان"""
    try:
        return dict(row)
    except Exception:
        if fallback_keys and row:
            return {k: (row[i] if i < len(row) else None)
                    for i, k in enumerate(fallback_keys)}
        return {}


def resequence(org_id):
    """إعادة الترقيم التسلسلي بعد الحذف"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM beneficiaries WHERE org_id=? ORDER BY id ASC", (org_id,))
    for i, row in enumerate(c.fetchall(), 1):
        c.execute("UPDATE beneficiaries SET seq_num=? WHERE id=?", (i, row["id"]))
    conn.commit()
    conn.close()


# last_seen يُحدَّث عند تسجيل الدخول فقط لتجنب database lock


# ══════════════════════════════════════════
# الصفحة الرئيسية
# ══════════════════════════════════════════
@app.route("/")
def home():
    return redirect(url_for("login"))


# ══════════════════════════════════════════
# صفحة الاختيار
# ══════════════════════════════════════════
@app.route("/register")
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("register_choice.html")


# ══════════════════════════════════════════
# تسجيل مؤسسة جديدة
# ══════════════════════════════════════════
@app.route("/register/org", methods=["GET", "POST"])
def register_org():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        org_name   = request.form.get("org_name", "").strip()
        email      = request.form.get("email", "").strip().lower()
        donor_name = request.form.get("donor_name", "").strip()
        full_name  = request.form.get("full_name", "").strip()
        id_number  = request.form.get("id_number", "").strip()
        username   = request.form.get("username", "").strip()
        password   = request.form.get("password", "")
        password2  = request.form.get("password2", "")

        if not all([org_name, email, full_name, id_number, username, password]):
            error = "يرجى تعبئة جميع الحقول الإلزامية"
        elif len(username) < 3:
            error = "اسم المستخدم يجب أن يكون 3 أحرف على الأقل"
        elif len(password) < 8:
            error = "كلمة المرور يجب أن تكون 8 أحرف على الأقل"
        elif password != password2:
            error = "كلمتا المرور غير متطابقتين"
        elif "@" not in email:
            error = "البريد الإلكتروني غير صحيح"
        else:
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT id FROM organizations WHERE email=?", (email,))
            if c.fetchone():
                error = "البريد الإلكتروني مسجّل لمؤسسة أخرى"
            else:
                c.execute("SELECT id FROM users WHERE username=?", (username,))
                if c.fetchone():
                    error = "اسم المستخدم مأخوذ، اختر اسماً آخر"
            conn.close()

        if not error:
            conn = get_connection()
            c = conn.cursor()
            # رمز المؤسسة فريد
            while True:
                org_code = generate_org_code()
                c.execute("SELECT id FROM organizations WHERE org_code=?", (org_code,))
                if not c.fetchone():
                    break
            # كود التحقق
            verify_code = generate_verification_code()
            expires_at  = (datetime.now() + timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("DELETE FROM verification_codes WHERE email=? AND purpose='org_register'", (email,))
            c.execute("INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?,?,?,?)",
                      (email, verify_code, "org_register", expires_at))
            conn.commit()
            conn.close()

            session["pending_org"] = {
                "org_name": org_name, "email": email, "donor_name": donor_name,
                "full_name": full_name, "id_number": id_number,
                "username": username, "password": password, "org_code": org_code,
            }

            sent = send_org_verification(email, org_name, full_name, verify_code, org_code, username)
            if sent:
                flash(f"📧 تم إرسال كود التحقق إلى {email}", "success")
            else:
                flash("⚠️ تحقق من مجلد Spam في بريدك", "warning")
            return redirect(url_for("verify_org_email"))

    return render_template("register_org.html", error=error)


# ══════════════════════════════════════════
# التحقق من كود الإيميل
# ══════════════════════════════════════════
@app.route("/register/verify", methods=["GET", "POST"])
def verify_org_email():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    pending = session.get("pending_org")
    if not pending:
        flash("انتهت الجلسة، يرجى إعادة التسجيل", "warning")
        return redirect(url_for("register_org"))

    error = None
    if request.method == "POST":
        entered_code = request.form.get("code", "").strip()
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "SELECT * FROM verification_codes WHERE email=? AND purpose='org_register' AND used=0 ORDER BY id DESC LIMIT 1",
            (pending["email"],)
        )
        row = c.fetchone()

        if not row:
            error = "الكود غير موجود، أعد التسجيل"
        elif datetime.now() > datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S"):
            error = "انتهت صلاحية الكود (3 دقائق)، اضغط إعادة الإرسال"
            c.execute("DELETE FROM verification_codes WHERE id=?", (row["id"],))
            conn.commit()
        elif entered_code != row["code"]:
            error = "الكود غير صحيح"
        else:
            c.execute("UPDATE verification_codes SET used=1 WHERE id=?", (row["id"],))
            c.execute("INSERT INTO organizations (name, email, donor_name, org_code) VALUES (?,?,?,?)",
                      (pending["org_name"], pending["email"], pending["donor_name"], pending["org_code"]))
            org_id = c.lastrowid
            hashed = generate_password_hash(pending["password"])
            c.execute(
                "INSERT INTO users (org_id, username, password, full_name, id_number, email, role, status) VALUES (?,?,?,?,?,?,?,?)",
                (org_id, pending["username"], hashed, pending["full_name"],
                 pending["id_number"], pending["email"], "admin", "approved")
            )
            conn.commit()
            conn.close()
            org_code = pending["org_code"]
            org_name = pending["org_name"]
            full_name = pending["full_name"]
            username = pending["username"]
            session.pop("pending_org", None)
            return render_template("register_success.html",
                org_name=org_name, org_code=org_code,
                full_name=full_name, username=username)
        conn.close()

    return render_template("verify_email.html", email=pending["email"], error=error)


@app.route("/register/resend")
def resend_verification():
    pending = session.get("pending_org")
    if not pending:
        return redirect(url_for("register_org"))
    verify_code = generate_verification_code()
    expires_at  = (datetime.now() + timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM verification_codes WHERE email=? AND purpose='org_register'", (pending["email"],))
    c.execute("INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?,?,?,?)",
              (pending["email"], verify_code, "org_register", expires_at))
    conn.commit()
    conn.close()
    send_org_verification(pending["email"], pending["org_name"], pending["full_name"],
                          verify_code, pending["org_code"], pending["username"])
    flash(f"📧 تم إعادة إرسال الكود إلى {pending['email']}", "success")
    return redirect(url_for("verify_org_email"))


# ══════════════════════════════════════════
# تسجيل موظف
# ══════════════════════════════════════════
@app.route("/register/staff", methods=["GET", "POST"])
def register_staff():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        org_code  = request.form.get("org_code", "").strip().upper()
        role      = request.form.get("role", "")
        full_name = request.form.get("full_name", "").strip()
        id_number = request.form.get("id_number", "").strip()
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if role not in ("accountant", "data_entry", "observer"):
            error = "يرجى اختيار نوع الحساب"
        elif not all([org_code, full_name, id_number, username, password]):
            error = "يرجى تعبئة جميع الحقول الإلزامية"
        elif len(username) < 3:
            error = "اسم المستخدم 3 أحرف على الأقل"
        elif len(password) < 8:
            error = "كلمة المرور 8 أحرف على الأقل"
        elif password != password2:
            error = "كلمتا المرور غير متطابقتين"
        else:
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM organizations WHERE org_code=? AND is_active=1", (org_code,))
            org = c.fetchone()
            if not org:
                error = "رمز المؤسسة غير صحيح"
                conn.close()
            else:
                c.execute("SELECT id FROM users WHERE username=?", (username,))
                if c.fetchone():
                    error = "اسم المستخدم مأخوذ"
                    conn.close()
                else:
                    photo_filename = None
                    photo_file = request.files.get("photo")
                    if photo_file and photo_file.filename and allowed_file(photo_file.filename) and allowed_file_content(photo_file):
                        ext = photo_file.filename.rsplit(".", 1)[1].lower()
                        photo_filename = f"user_{username}.{ext}"
                        photo_file.save(os.path.join(app.config["UPLOAD_FOLDER"], photo_filename))

                    hashed = generate_password_hash(password)
                    c.execute(
                        "INSERT INTO users (org_id, username, password, full_name, id_number, photo, role, status) VALUES (?,?,?,?,?,?,?,?)",
                        (org["id"], username, hashed, full_name, id_number, photo_filename, role, "pending")
                    )
                    conn.commit()
                    # إشعار الأدمن
                    c.execute("SELECT email, full_name FROM users WHERE org_id=? AND role='admin' LIMIT 1", (org["id"],))
                    admin = c.fetchone()
                    conn.close()
                    if admin and admin["email"]:
                        send_staff_notification(admin["email"], admin["full_name"],
                                                full_name, role, org["name"])
                    role_label = "محاسب" if role == "accountant" else "مدخل بيانات"
                    return render_template("register_pending.html",
                                           role_label=role_label, full_name=full_name)

    return render_template("register_staff.html", error=error)


# ══════════════════════════════════════════
# تسجيل الدخول / الخروج
# ══════════════════════════════════════════
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    ip = _get_ip()
    error = None

    if request.method == "POST":
        # حماية Brute Force
        if _is_blocked(ip):
            error = f"تم تجميد IP بسبب محاولات كثيرة. انتظر {BLOCK_MINUTES} دقيقة وحاول مجدداً."
            return render_template("login.html", error=error)

        org_code = request.form.get("org_code", "").strip().upper()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not org_code or not username or not password:
            error = "يرجى تعبئة جميع الحقول"
        else:
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM organizations WHERE org_code=? AND is_active=1", (org_code,))
            org = c.fetchone()
            if not org:
                _record_failed(ip)
                error = "رمز المؤسسة أو بيانات الدخول غير صحيحة"
                conn.close()
            else:
                c.execute("SELECT * FROM users WHERE username=? AND org_id=?", (username, org["id"]))
                user = c.fetchone()
                if not user or not check_password_hash(user["password"], password):
                    _record_failed(ip)
                    remaining = MAX_LOGIN_ATTEMPTS - _login_attempts.get(ip, {}).get("count", 0)
                    error = f"بيانات الدخول غير صحيحة. محاولات متبقية: {max(0, remaining)}"
                    conn.close()
                elif user["status"] == "pending":
                    error = "حسابك قيد المراجعة، انتظر موافقة المدير"
                    conn.close()
                elif user["status"] == "rejected":
                    error = "تم رفض طلبك، تواصل مع مدير المؤسسة"
                    conn.close()
                else:
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    c.execute("UPDATE users SET last_seen=? WHERE id=?", (now, user["id"]))
                    conn.commit()
                    conn.close()
                    _clear_attempts(ip)   # نجاح: امسح سجل المحاولات
                    session.clear()
                    session.permanent = True
                    set_session(user, org)
                    session["_last_active"] = datetime.now().isoformat()
                    return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


# ══════════════════════════════════════════
# الملف الشخصي
# ══════════════════════════════════════════
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session["user_id"]
    org_id  = session["org_id"]
    error   = None
    success = False

    conn = get_connection()
    c    = conn.cursor()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone     = request.form.get("phone", "").strip()
        photo_file = request.files.get("photo")

        if not full_name:
            error = "الاسم الكامل مطلوب"
        else:
            photo_filename = None
            if photo_file and photo_file.filename and allowed_file(photo_file.filename) and allowed_file_content(photo_file):
                import uuid as _uuid2
                ext = photo_file.filename.rsplit(".", 1)[1].lower()
                photo_filename = f"user_{_uuid2.uuid4().hex}.{ext}"
                photo_file.save(os.path.join(app.config["UPLOAD_FOLDER"], photo_filename))

            if photo_filename:
                c.execute("UPDATE users SET full_name=?, phone=?, photo=? WHERE id=? AND org_id=?",
                          (full_name, phone, photo_filename, user_id, org_id))
            else:
                c.execute("UPDATE users SET full_name=?, phone=? WHERE id=? AND org_id=?",
                          (full_name, phone, user_id, org_id))
            conn.commit()
            session["full_name"] = full_name
            success = True

    c.execute("SELECT full_name, username, role, phone, photo, email, created_at FROM users WHERE id=?", (user_id,))
    user = dict(c.fetchone())
    conn.close()
    return render_template("profile.html", user=user, error=error, success=success)


# ══════════════════════════════════════════
# تغيير كلمة المرور (لكل المستخدمين)
# ══════════════════════════════════════════
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    error = None
    success = False
    if request.method == "POST":
        current  = request.form.get("current_password", "")
        new_pass = request.form.get("new_password", "").strip()
        confirm  = request.form.get("confirm_password", "").strip()

        conn = get_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT password FROM users WHERE id=?", (session["user_id"],))
            user = c.fetchone()
            if not user:
                error = "لم يتم العثور على حسابك"
            elif not check_password_hash(user["password"], current):
                error = "كلمة المرور الحالية غير صحيحة"
            elif len(new_pass) < 8:
                error = "كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل"
            elif new_pass != confirm:
                error = "كلمتا المرور الجديدتان غير متطابقتين"
            else:
                hashed = generate_password_hash(new_pass)
                c.execute("UPDATE users SET password=? WHERE id=?",
                          (hashed, session["user_id"]))
                conn.commit()
                success = True
        except Exception as e:
            error = f"حدث خطأ: {str(e)}"
        finally:
            conn.close()

    return render_template("change_password.html", error=error, success=success)


@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    """حذف الحساب — الأدمن يحذف المؤسسة كاملة مع جميع بياناتها"""
    if session.get("role") != "admin":
        return jsonify({"ok": False, "err": "forbidden"}), 403

    password = request.form.get("password", "")
    org_id   = session["org_id"]
    user_id  = session["user_id"]

    conn = get_connection()
    c    = conn.cursor()
    try:
        # تحقق من كلمة السر
        c.execute("SELECT password FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
        if not row or not check_password_hash(row["password"], password):
            conn.close()
            return jsonify({"ok": False, "err": "wrong_password"}), 400

        # ── حذف جميع بيانات المؤسسة ──────────────────────────
        # message_reads لمستخدمي المؤسسة
        c.execute("SELECT id FROM users WHERE org_id=?", (org_id,))
        user_ids = [r["id"] for r in c.fetchall()]
        if user_ids:
            placeholders = ",".join("?" * len(user_ids))
            c.execute(f"DELETE FROM message_reads WHERE user_id IN ({placeholders})", user_ids)
            c.execute(f"DELETE FROM org_message_reads WHERE user_id IN ({placeholders})", user_ids)

        # بنود الفواتير (لا تحتوي org_id مباشرة)
        c.execute("SELECT id FROM incoming_invoices WHERE org_id=?", (org_id,))
        inv_ids = [r["id"] for r in c.fetchall()]
        if inv_ids:
            placeholders = ",".join("?" * len(inv_ids))
            c.execute(f"DELETE FROM incoming_invoice_items WHERE invoice_id IN ({placeholders})", inv_ids)

        c.execute("SELECT id FROM outgoing_invoices WHERE org_id=?", (org_id,))
        out_ids = [r["id"] for r in c.fetchall()]
        if out_ids:
            placeholders = ",".join("?" * len(out_ids))
            c.execute(f"DELETE FROM outgoing_invoice_items WHERE invoice_id IN ({placeholders})", out_ids)

        # الجداول ذات org_id مباشرة
        for table in [
            "program_records", "beneficiaries", "programs", "workers",
            "products", "stock_batches",
            "incoming_invoices", "outgoing_invoices",
            "messages",
        ]:
            c.execute(f"DELETE FROM {table} WHERE org_id=?", (org_id,))

        # رسائل شبكة التواصل (from أو to)
        c.execute("DELETE FROM org_messages WHERE from_org_id=? OR to_org_id=?", (org_id, org_id))

        # طلبات مشاركة المستفيدين
        c.execute("DELETE FROM beneficiary_share_requests WHERE requester_org_id=? OR owner_org_id=?", (org_id, org_id))

        # المستخدمون ثم المؤسسة
        c.execute("DELETE FROM users WHERE org_id=?", (org_id,))
        c.execute("DELETE FROM organizations WHERE id=?", (org_id,))

        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"ok": False, "err": str(e)}), 500
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # تسجيل الخروج
    session.clear()
    return jsonify({"ok": True})


# ══════════════════════════════════════════
# صفحة المراقب العام
# ══════════════════════════════════════════
@app.route("/overview")
@observer_required
def overview():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    # المخزون
    c.execute("""
        SELECT p.name, p.unit,
            COALESCE((SELECT SUM(quantity_remaining)
                      FROM stock_batches WHERE product_id=p.id AND org_id=?),0) as qty
        FROM products p WHERE p.org_id=? ORDER BY qty DESC
    """, (org_id, org_id))
    inventory = [dict(r) for r in c.fetchall()]

    # آخر 20 فاتورة صرف
    c.execute("""
        SELECT inv.invoice_number, inv.invoice_date, inv.beneficiary,
               inv.created_by, COUNT(oi.id) as items,
               COALESCE(SUM(oi.total_price),0) as total
        FROM outgoing_invoices inv
        LEFT JOIN outgoing_invoice_items oi ON oi.invoice_id=inv.id
        WHERE inv.org_id=?
        GROUP BY inv.id ORDER BY inv.invoice_date DESC LIMIT 20
    """, (org_id,))
    recent_outgoing = [dict(r) for r in c.fetchall()]

    # البرامج
    c.execute("SELECT * FROM programs WHERE org_id=? AND is_active=1 ORDER BY name", (org_id,))
    programs = [dict(r) for r in c.fetchall()]

    # إحصاءات
    c.execute("SELECT COUNT(*) FROM beneficiaries WHERE org_id=?", (org_id,))
    benef_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM outgoing_invoices WHERE org_id=?", (org_id,))
    out_count = c.fetchone()[0]

    conn.close()
    return render_template("overview.html",
        inventory=inventory, recent_outgoing=recent_outgoing,
        programs=programs, benef_count=benef_count, out_count=out_count)


@app.route("/logout")
def logout():
    # تصفير last_seen عند تسجيل الخروج
    if "user_id" in session:
        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute("UPDATE users SET last_seen=NULL WHERE id=?", (session["user_id"],))
            conn.commit()
            conn.close()
        except Exception:
            pass
    session.clear()
    return redirect(url_for("login"))


# ══════════════════════════════════════════
# لوحة التحكم
# ══════════════════════════════════════════
@app.route("/dashboard")
@login_required
def dashboard():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM products WHERE org_id=?", (org_id,))
    products_count = c.fetchone()[0]
    c.execute("SELECT COALESCE(SUM(quantity_remaining),0) FROM stock_batches WHERE org_id=?", (org_id,))
    total_stock = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM beneficiaries WHERE org_id=?", (org_id,))
    beneficiaries_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM incoming_invoices WHERE org_id=?", (org_id,))
    incoming_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM outgoing_invoices WHERE org_id=?", (org_id,))
    outgoing_count = c.fetchone()[0]
    pending_users = []
    if session.get("role") == "admin":
        c.execute(
            "SELECT id, full_name, role, id_number, photo, created_at FROM users WHERE org_id=? AND status='pending' ORDER BY id DESC",
            (org_id,)
        )
        pending_users = [dict(r) for r in c.fetchall()]

    # تنبيهات المخزون المنخفض/النافد
    c.execute("""
        SELECT p.id, p.name, p.unit,
               COALESCE(SUM(sb.quantity_remaining), 0) AS qty
        FROM products p
        LEFT JOIN stock_batches sb ON sb.product_id = p.id AND sb.org_id = p.org_id
        WHERE p.org_id = ?
        GROUP BY p.id
        HAVING qty <= 10
        ORDER BY qty ASC
    """, (org_id,))
    low_stock = [dict(r) for r in c.fetchall()]

    conn.close()
    return render_template("dashboard.html",
        products_count=products_count, total_stock=total_stock,
        beneficiaries_count=beneficiaries_count,
        incoming_count=incoming_count, outgoing_count=outgoing_count,
        pending_users=pending_users,
        low_stock=low_stock)


# ══════════════════════════════════════════
# تنبيهات المخزون المنخفض (API)
# ══════════════════════════════════════════
@app.route("/api/low_stock")
@login_required
def api_low_stock():
    """إرجاع قائمة الأصناف ذات المخزون المنخفض أو النافد بصيغة JSON"""
    if session.get("role") not in ("admin", "accountant", "observer"):
        return jsonify([])
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT p.id, p.name, p.unit,
               COALESCE(SUM(sb.quantity_remaining), 0) AS qty
        FROM products p
        LEFT JOIN stock_batches sb ON sb.product_id = p.id AND sb.org_id = p.org_id
        WHERE p.org_id = ?
        GROUP BY p.id
        HAVING qty <= 10
        ORDER BY qty ASC
    """, (org_id,))
    items = [{"id": r["id"], "name": r["name"], "unit": r["unit"] or "", "qty": r["qty"]} for r in c.fetchall()]
    conn.close()
    return jsonify(items)


# ══════════════════════════════════════════
# موافقة / رفض الموظفين
# ══════════════════════════════════════════
@app.route("/approve_user/<int:id>")
@admin_required
def approve_user(id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET status='approved' WHERE id=? AND org_id=?", (id, session["org_id"]))
    conn.commit()
    conn.close()
    flash("✅ تمت الموافقة على الحساب", "success")
    return redirect(url_for("dashboard"))


@app.route("/reject_user/<int:id>")
@admin_required
def reject_user(id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET status='rejected' WHERE id=? AND org_id=?", (id, session["org_id"]))
    conn.commit()
    conn.close()
    flash("تم رفض الحساب", "warning")
    return redirect(url_for("dashboard"))


# ══════════════════════════════════════════
# إدارة المستخدمين
# ══════════════════════════════════════════
@app.route("/users")
@admin_required
def users_list():
    conn = get_connection()
    c = conn.cursor()
    # جلب الأعمدة الأساسية فقط (last_seen قد لا يكون موجوداً في قاعدة بيانات قديمة)
    c.execute(
        "SELECT id, username, full_name, id_number, role, status, photo, created_at FROM users WHERE org_id=? ORDER BY id",
        (session["org_id"],)
    )
    rows = c.fetchall()

    # محاولة جلب last_seen بشكل منفصل آمن
    last_seen_map = {}
    try:
        c.execute("SELECT id, last_seen FROM users WHERE org_id=?", (session["org_id"],))
        for r in c.fetchall():
            last_seen_map[r["id"]] = r["last_seen"]
    except Exception:
        pass  # العمود غير موجود - لا مشكلة

    conn.close()

    def seconds_since(last_seen_str):
        if not last_seen_str:
            return 999999
        try:
            ls = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
            return int((datetime.now() - ls).total_seconds())
        except Exception:
            return 999999

    users = []
    for r in rows:
        last_seen_val = last_seen_map.get(r["id"], "")
        d = {
            "id":        r["id"],
            "username":  r["username"],
            "full_name": r["full_name"] or "",
            "id_number": r["id_number"] or "",
            "role":      r["role"],
            "status":    r["status"],
            "photo":     r["photo"] or "",
            "created_at":r["created_at"] or "",
            "last_seen": last_seen_val or "",
            "last_seen_seconds": seconds_since(last_seen_val),
        }
        users.append(d)

    return render_template("users.html", users=users)


@app.route("/add_user", methods=["GET", "POST"])
@admin_required
def add_user():
    error = None
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        id_number = request.form.get("id_number", "").strip()
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "")
        role      = request.form.get("role", "")

        if not role or role not in ("accountant", "data_entry", "observer"):
            error = "يرجى اختيار نوع الحساب (محاسب، مدخل بيانات، أو مراقب عام)"
        elif not all([full_name, id_number, username, password]):
            error = "يرجى تعبئة جميع الحقول"
        elif len(password) < 8:
            error = "كلمة المرور 8 أحرف على الأقل"
        elif id_number and (not id_number.isdigit() or len(id_number) != 9):
            error = "رقم الهوية يجب أن يكون 9 أرقام"
        else:
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE username=?", (username,))
            if c.fetchone():
                error = "اسم المستخدم مأخوذ"
                conn.close()
            else:
                hashed = generate_password_hash(password)
                c.execute(
                    "INSERT INTO users (org_id, username, password, full_name, id_number, role, status, created_by) VALUES (?,?,?,?,?,?,?,?)",
                    (session["org_id"], username, hashed, full_name, id_number, role, "approved", session["user_id"])
                )
                conn.commit()
                conn.close()
                flash(f"✅ تم إضافة '{full_name}' بنجاح", "success")
                return redirect(url_for("users_list"))

    return render_template("add_user.html", error=error)


@app.route("/edit_user/<int:id>", methods=["GET", "POST"])
@admin_required
def edit_user(id):
    if id == session["user_id"]:
        flash("لا يمكنك تعديل حسابك من هنا", "warning")
        return redirect(url_for("users_list"))

    conn = get_connection()
    c = conn.cursor()

    if request.method == "POST":
        full_name    = request.form.get("full_name", "").strip()
        role         = request.form.get("role", "")
        status       = request.form.get("status", "approved")
        new_password = request.form.get("new_password", "").strip()

        if new_password:
            if len(new_password) < 8:
                flash("كلمة المرور 8 أحرف على الأقل", "danger")
                c.execute("SELECT * FROM users WHERE id=? AND org_id=?", (id, session["org_id"]))
                user = dict(c.fetchone())
                conn.close()
                return render_template("edit_user.html", user=user)
            hashed = generate_password_hash(new_password)
            c.execute("UPDATE users SET full_name=?,role=?,status=?,password=? WHERE id=? AND org_id=?",
                      (full_name, role, status, hashed, id, session["org_id"]))
        else:
            c.execute("UPDATE users SET full_name=?,role=?,status=? WHERE id=? AND org_id=?",
                      (full_name, role, status, id, session["org_id"]))
        conn.commit()
        conn.close()
        flash("✅ تم تحديث بيانات المستخدم", "success")
        return redirect(url_for("users_list"))

    c.execute("SELECT * FROM users WHERE id=? AND org_id=?", (id, session["org_id"]))
    row = c.fetchone()
    conn.close()
    if not row:
        flash("المستخدم غير موجود", "danger")
        return redirect(url_for("users_list"))
    return render_template("edit_user.html", user=dict(row))


@app.route("/delete_user/<int:id>")
@admin_required
def delete_user(id):
    if id == session["user_id"]:
        flash("لا يمكنك حذف حسابك الخاص", "danger")
        return redirect(url_for("users_list"))
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=? AND org_id=?", (id, session["org_id"]))
    conn.commit()
    conn.close()
    flash("تم حذف المستخدم", "warning")
    return redirect(url_for("users_list"))


# ══════════════════════════════════════════
# الأصناف
# ══════════════════════════════════════════
@app.route("/products")
@observer_required
def products():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT p.id, p.name, p.unit,
            COALESCE((SELECT SUM(quantity_remaining) FROM stock_batches WHERE product_id=p.id AND org_id=?),0),
            COALESCE((SELECT unit_price FROM stock_batches WHERE product_id=p.id ORDER BY id ASC  LIMIT 1),0),
            COALESCE((SELECT unit_price FROM stock_batches WHERE product_id=p.id ORDER BY id DESC LIMIT 1),0),
            p.last_modified
        FROM products p WHERE p.org_id=? ORDER BY p.id DESC
    """, (org_id, org_id))
    data = c.fetchall()
    conn.close()
    return render_template("products.html", products=data)


@app.route("/add_product", methods=["GET", "POST"])
@invoices_required
def add_product():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        unit = request.form.get("unit", "").strip()
        if not name or not unit:
            flash("يرجى تعبئة جميع الحقول", "danger")
            return render_template("add_product.html")
        conn = get_connection()
        c = conn.cursor()
        c.execute("INSERT INTO products (org_id, name, unit) VALUES (?,?,?)",
                  (session["org_id"], name, unit))
        conn.commit()
        conn.close()
        flash("✅ تمت إضافة الصنف", "success")
        return redirect(url_for("products"))
    return render_template("add_product.html")


@app.route("/edit_product/<int:id>", methods=["GET", "POST"])
@invoices_required
def edit_product(id):
    conn = get_connection()
    c = conn.cursor()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        unit = request.form.get("unit", "").strip()
        if not name or not unit:
            flash("يرجى تعبئة جميع الحقول", "danger")
        else:
            now = datetime.now().strftime("%Y/%m/%d")
            c.execute("UPDATE products SET name=?,unit=?,last_modified=? WHERE id=? AND org_id=?",
                      (name, unit, now, id, session["org_id"]))
            conn.commit()
            flash("✅ تم تعديل الصنف", "success")
            conn.close()
            return redirect(url_for("products"))
    c.execute("SELECT * FROM products WHERE id=? AND org_id=?", (id, session["org_id"]))
    product = c.fetchone()
    conn.close()
    if not product:
        flash("الصنف غير موجود", "danger")
        return redirect(url_for("products"))
    return render_template("edit_product.html", product=product)


@app.route("/delete_product/<int:id>")
@invoices_required
def delete_product(id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM stock_batches WHERE product_id=? AND org_id=?", (id, session["org_id"]))
    c.execute("DELETE FROM products WHERE id=? AND org_id=?", (id, session["org_id"]))
    conn.commit()
    conn.close()
    flash("تم حذف الصنف", "warning")
    return redirect(url_for("products"))


# ══════════════════════════════════════════
# المستفيدون
# ══════════════════════════════════════════
BENEF_KEYS = ["id", "org_id", "seq_num", "full_name", "gender", "phone",
              "address", "address2", "camp_name", "id_number", "family_size",
              "marital_status", "children_count", "wife_pregnant", "wife_nursing",
              "has_orphans", "orphans_count", "notes", "created_at", "beneficiary_type"]


@app.route("/beneficiaries")
@data_entry_view_required
def beneficiaries():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM beneficiaries WHERE org_id=? ORDER BY id ASC", (org_id,))
    rows = c.fetchall()
    conn.close()

    data = []
    for i, row in enumerate(rows, 1):
        d = row_to_dict(row, BENEF_KEYS)
        d["seq_num"] = i
        d.setdefault("address2", "")
        d.setdefault("camp_name", "")
        d.setdefault("marital_status", "married")
        d.setdefault("gender", "male")
        d.setdefault("children_count", 0)
        d.setdefault("wife_pregnant", 0)
        d.setdefault("wife_nursing", 0)
        d.setdefault("has_orphans", 0)
        d.setdefault("orphans_count", 0)
        d.setdefault("beneficiary_type", "person")
        data.append(d)

    return render_template("beneficiaries.html", beneficiaries=data)


@app.route("/add_beneficiary", methods=["GET", "POST"])
@data_entry_required
def add_beneficiary():
    if request.method == "POST":
        full_name      = request.form.get("full_name", "").strip()
        gender         = request.form.get("gender", "male")
        phone          = request.form.get("phone", "").strip()
        address        = request.form.get("address", "").strip()
        address2       = request.form.get("address2", "").strip()
        camp_name      = request.form.get("camp_name", "").strip()
        id_number      = request.form.get("id_number", "").strip()
        family_size    = request.form.get("family_size", "1").strip()
        marital_status = request.form.get("marital_status", "married").strip()
        children_count = request.form.get("children_count", "0").strip()
        wife_pregnant  = 1 if request.form.get("wife_pregnant") else 0
        wife_nursing   = 1 if request.form.get("wife_nursing") else 0
        has_orphans    = 1 if request.form.get("has_orphans") else 0
        orphans_count    = request.form.get("orphans_count", "0").strip()
        notes            = request.form.get("notes", "").strip()
        beneficiary_type = request.form.get("beneficiary_type", "person").strip()

        errors = []
        if len(full_name.split()) < 2:
            errors.append("الاسم يجب أن يكون رباعياً (4 كلمات على الأقل)")
        if id_number and (not id_number.isdigit() or len(id_number) != 9):
            errors.append("رقم الهوية يجب أن يكون 9 أرقام فقط")
        if phone and (not phone.isdigit() or len(phone) != 10 or not phone.startswith("05")):
            errors.append("رقم الجوال يجب أن يكون 10 أرقام ويبدأ بـ 05")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("add_beneficiary.html", form_data=request.form)

        try:
            family_size    = int(family_size)
            children_count = int(children_count)
            orphans_count  = int(orphans_count) if has_orphans else 0
        except ValueError:
            family_size = 1; children_count = 0; orphans_count = 0

        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM beneficiaries WHERE org_id=?", (session["org_id"],))
        next_seq = c.fetchone()[0] + 1
        c.execute(
            """INSERT INTO beneficiaries
               (org_id, seq_num, full_name, gender, phone, address, address2, camp_name,
                id_number, family_size, marital_status, children_count,
                wife_pregnant, wife_nursing, has_orphans, orphans_count, notes, beneficiary_type)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (session["org_id"], next_seq, full_name, gender, phone, address, address2,
             camp_name, id_number, family_size, marital_status, children_count,
             wife_pregnant, wife_nursing, has_orphans, orphans_count, notes, beneficiary_type)
        )
        conn.commit()
        conn.close()
        flash("✅ تمت إضافة المستفيد بنجاح", "success")
        return redirect(url_for("beneficiaries"))

    return render_template("add_beneficiary.html", form_data={})


@app.route("/edit_beneficiary/<int:id>", methods=["GET", "POST"])
@data_entry_required
def edit_beneficiary(id):
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    if request.method == "POST":
        full_name      = request.form.get("full_name", "").strip()
        gender         = request.form.get("gender", "male")
        phone          = request.form.get("phone", "").strip()
        address        = request.form.get("address", "").strip()
        address2       = request.form.get("address2", "").strip()
        camp_name      = request.form.get("camp_name", "").strip()
        id_number      = request.form.get("id_number", "").strip()
        family_size    = request.form.get("family_size", "1").strip()
        marital_status = request.form.get("marital_status", "married").strip()
        children_count = request.form.get("children_count", "0").strip()
        wife_pregnant  = 1 if request.form.get("wife_pregnant") else 0
        wife_nursing   = 1 if request.form.get("wife_nursing") else 0
        has_orphans    = 1 if request.form.get("has_orphans") else 0
        orphans_count    = request.form.get("orphans_count", "0").strip()
        notes            = request.form.get("notes", "").strip()
        beneficiary_type = request.form.get("beneficiary_type", "person").strip()

        errors = []
        if len(full_name.split()) < 2:
            errors.append("الاسم يجب أن يكون رباعياً (4 كلمات على الأقل)")
        if id_number and (not id_number.isdigit() or len(id_number) != 9):
            errors.append("رقم الهوية يجب أن يكون 9 أرقام فقط")
        if phone and (not phone.isdigit() or len(phone) != 10 or not phone.startswith("05")):
            errors.append("رقم الجوال يجب أن يكون 10 أرقام ويبدأ بـ 05")

        if errors:
            for e in errors:
                flash(e, "danger")
            conn.close()
            # أعِد عرض البيانات المُدخلة (لا تمسحها بإعادة تحميل DB)
            b = {
                "id": id, "full_name": full_name, "gender": gender,
                "phone": phone, "address": address, "address2": address2,
                "camp_name": camp_name, "id_number": id_number,
                "family_size": family_size, "marital_status": marital_status,
                "children_count": children_count, "wife_pregnant": wife_pregnant,
                "wife_nursing": wife_nursing, "has_orphans": has_orphans,
                "orphans_count": orphans_count, "notes": notes,
                "beneficiary_type": beneficiary_type,
            }
            return render_template("edit_beneficiary.html", b=b)

        try:
            family_size    = int(family_size)
            children_count = int(children_count)
            orphans_count  = int(orphans_count) if has_orphans else 0
        except ValueError:
            family_size = 1; children_count = 0; orphans_count = 0

        c.execute(
            """UPDATE beneficiaries
               SET full_name=?,gender=?,phone=?,address=?,address2=?,camp_name=?,
                   id_number=?,family_size=?,marital_status=?,children_count=?,
                   wife_pregnant=?,wife_nursing=?,has_orphans=?,orphans_count=?,notes=?,
                   beneficiary_type=?
               WHERE id=? AND org_id=?""",
            (full_name, gender, phone, address, address2, camp_name,
             id_number, family_size, marital_status, children_count,
             wife_pregnant, wife_nursing, has_orphans, orphans_count, notes,
             beneficiary_type, id, org_id)
        )
        conn.commit()
        conn.close()
        flash("✅ تم تعديل بيانات المستفيد", "success")
        return redirect(url_for("beneficiaries"))

    c.execute("SELECT * FROM beneficiaries WHERE id=? AND org_id=?", (id, org_id))
    row = c.fetchone()
    conn.close()
    if not row:
        flash("المستفيد غير موجود", "danger")
        return redirect(url_for("beneficiaries"))
    b = row_to_dict(row, BENEF_KEYS)
    b.setdefault("address2", "")
    b.setdefault("camp_name", "")
    b.setdefault("marital_status", "married")
    b.setdefault("gender", "male")
    b.setdefault("children_count", 0)
    b.setdefault("wife_pregnant", 0)
    b.setdefault("wife_nursing", 0)
    b.setdefault("has_orphans", 0)
    b.setdefault("orphans_count", 0)
    b.setdefault("beneficiary_type", "person")
    return render_template("edit_beneficiary.html", b=b)


@app.route("/delete_beneficiary/<int:id>")
@data_entry_required
def delete_beneficiary(id):
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM beneficiaries WHERE id=? AND org_id=?", (id, org_id))
    conn.commit()
    conn.close()
    resequence(org_id)
    flash("تم حذف المستفيد وإعادة الترقيم", "warning")
    return redirect(url_for("beneficiaries"))


# ══════════════════════════════════════════
# المشتريات (فواتير الإدخال)
# ══════════════════════════════════════════

@app.route("/add_incoming_invoice", methods=["GET", "POST"])
@invoices_required
def add_incoming_invoice():
    """صفحة إضافة فاتورة مشتريات جديدة"""
    if session.get("role") == "observer":
        flash("مراقب عام: لا تملك صلاحية الإضافة", "danger")
        return redirect(url_for("incoming_invoice"))

    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    if request.method == "POST":
        supplier                 = request.form.get("supplier", "").strip()
        invoice_date             = request.form.get("invoice_date", "").strip()
        purchase_invoice_number  = request.form.get("purchase_invoice_number", "").strip()
        invoice_name             = request.form.get("invoice_name", "").strip()
        product_names   = request.form.getlist("product_name[]")
        product_units   = request.form.getlist("product_unit[]")
        quantities      = request.form.getlist("quantity[]")
        unit_prices     = request.form.getlist("unit_price[]")
        purchase_dates  = request.form.getlist("purchase_date[]")

        valid_items = [
            (nm.strip(), un.strip(), qty, price, pdate)
            for nm, un, qty, price, pdate in zip(product_names, product_units, quantities, unit_prices, purchase_dates)
            if nm.strip() and qty and price and pdate
        ]

        if not supplier:
            flash("يرجى تعبئة اسم المورد", "danger")
        elif not valid_items:
            flash("يرجى إضافة صنف واحد على الأقل ببيانات كاملة", "danger")
        else:
            c.execute("SELECT COALESCE(MAX(seq_num),0) FROM incoming_invoices WHERE org_id=?", (org_id,))
            next_seq = c.fetchone()[0] + 1

            invoice_image = None
            img_file = request.files.get("invoice_image")
            if img_file and img_file.filename and allowed_file(img_file.filename) and allowed_file_content(img_file):
                ext = img_file.filename.rsplit(".", 1)[1].lower()
                stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
                invoice_image = f"invoice_{org_id}_{stamp}.{ext}"
                img_file.save(os.path.join(app.config["UPLOAD_FOLDER"], invoice_image))

            c.execute(
                "INSERT INTO incoming_invoices (org_id, seq_num, invoice_number, invoice_date, supplier, created_by, invoice_image, purchase_invoice_number, invoice_name) VALUES (?,?,?,?,?,?,?,?,?)",
                (org_id, next_seq, str(next_seq), invoice_date or datetime.now().strftime("%Y-%m-%d"),
                 supplier, session["user"], invoice_image,
                 purchase_invoice_number or None, invoice_name or None)
            )
            invoice_id = c.lastrowid

            for pname, punit, qty, price, pdate in valid_items:
                try:
                    qty_f, price_f = float(qty), float(price)
                    c.execute("SELECT id FROM products WHERE org_id=? AND LOWER(name)=LOWER(?)", (org_id, pname))
                    row = c.fetchone()
                    if row:
                        pid = row["id"]
                        if punit:
                            c.execute("UPDATE products SET unit=?, last_modified=? WHERE id=?", (punit, pdate, pid))
                    else:
                        unit = punit or "وحدة"
                        c.execute("INSERT INTO products (org_id, name, unit, last_modified) VALUES (?,?,?,?)",
                                  (org_id, pname, unit, pdate))
                        pid = c.lastrowid
                    c.execute(
                        "INSERT INTO incoming_invoice_items (invoice_id, product_id, quantity, unit_price, total_price, purchase_date) VALUES (?,?,?,?,?,?)",
                        (invoice_id, pid, qty_f, price_f, qty_f * price_f, pdate)
                    )
                    c.execute(
                        "INSERT INTO stock_batches (org_id, product_id, quantity_remaining, unit_price, entry_date, invoice_id) VALUES (?,?,?,?,?,?)",
                        (org_id, pid, qty_f, price_f, pdate, invoice_id)
                    )
                    c.execute("UPDATE products SET last_modified=? WHERE id=?", (pdate, pid))
                except ValueError:
                    pass

            conn.commit()
            conn.close()
            flash("✅ تم حفظ فاتورة المشتريات", "success")
            return redirect(url_for("incoming_invoices_list"))

    c.execute("SELECT name, unit FROM products WHERE org_id=? ORDER BY name", (org_id,))
    existing_products = [dict(r) for r in c.fetchall()]
    today_str = datetime.now().strftime("%Y-%m-%d")
    conn.close()
    return render_template("add_incoming_invoice.html",
                           existing_products=existing_products, today_str=today_str)


@app.route("/incoming_invoice", methods=["GET"])
@invoices_view_required
def incoming_invoice():
    """كشف مختصر بكل الفواتير — hover ينقل لصفحة التفاصيل"""
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        SELECT id, seq_num, invoice_number, invoice_date, supplier,
               is_closed, is_paid, grand_total, created_at
        FROM incoming_invoices WHERE org_id=? ORDER BY COALESCE(seq_num,id) ASC
    """, (org_id,))
    all_inv_rows = c.fetchall()

    summary = []
    total_purchases = 0.0
    for inv in all_inv_rows:
        inv_d = dict(inv)
        c.execute("SELECT COALESCE(SUM(total_price),0) FROM incoming_invoice_items WHERE invoice_id=?", (inv["id"],))
        inv_total = c.fetchone()[0]
        inv_d["total"] = inv_total
        inv_d["display_num"] = inv_d.get("seq_num") or inv_d.get("invoice_number") or inv_d["id"]
        total_purchases += inv_total
        summary.append(inv_d)

    conn.close()
    return render_template("incoming_invoices.html",
        summary=summary,
        total_purchases=total_purchases)


@app.route("/incoming_invoice/<int:id>/add_items", methods=["POST"])
@invoices_required
def add_invoice_items(id):
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT is_closed FROM incoming_invoices WHERE id=? AND org_id=?", (id, org_id))
    inv = c.fetchone()
    if not inv:
        conn.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("incoming_invoice"))
    if inv["is_closed"]:
        conn.close()
        flash("الفاتورة مغلقة، لا يمكن إضافة أصناف جديدة", "danger")
        return redirect(url_for("incoming_invoice"))

    product_names  = request.form.getlist("product_name[]")
    product_units  = request.form.getlist("product_unit[]")
    quantities     = request.form.getlist("quantity[]")
    unit_prices    = request.form.getlist("unit_price[]")
    purchase_dates = request.form.getlist("purchase_date[]")

    added = 0
    for pname, punit, qty, price, pdate in zip(product_names, product_units, quantities, unit_prices, purchase_dates):
        pname = pname.strip()
        if pname and qty and price and pdate:
            try:
                qty_f, price_f = float(qty), float(price)
                c.execute("SELECT id FROM products WHERE org_id=? AND LOWER(name)=LOWER(?)", (org_id, pname))
                row = c.fetchone()
                if row:
                    pid = row["id"]
                    if punit.strip():
                        c.execute("UPDATE products SET unit=?, last_modified=? WHERE id=?", (punit.strip(), pdate, pid))
                else:
                    unit = punit.strip() or "وحدة"
                    c.execute("INSERT INTO products (org_id, name, unit, last_modified) VALUES (?,?,?,?)",
                              (org_id, pname, unit, pdate))
                    pid = c.lastrowid
                c.execute(
                    "INSERT INTO incoming_invoice_items (invoice_id, product_id, quantity, unit_price, total_price, purchase_date) VALUES (?,?,?,?,?,?)",
                    (id, pid, qty_f, price_f, qty_f * price_f, pdate)
                )
                c.execute(
                    "INSERT INTO stock_batches (org_id, product_id, quantity_remaining, unit_price, entry_date, invoice_id) VALUES (?,?,?,?,?,?)",
                    (org_id, pid, qty_f, price_f, pdate, id)
                )
                c.execute("UPDATE products SET last_modified=? WHERE id=?", (pdate, pid))
                added += 1
            except ValueError:
                pass

    conn.commit()
    conn.close()
    if added:
        flash(f"✅ تم إضافة {added} صنف للفاتورة", "success")
    else:
        flash("يرجى تعبئة بيانات الصنف كاملة (الكمية، السعر، التاريخ)", "danger")
    return redirect(url_for("incoming_invoice"))


@app.route("/incoming_invoice/<int:id>/close")
@invoices_required
def close_invoice(id):
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT is_closed FROM incoming_invoices WHERE id=? AND org_id=?", (id, org_id))
    inv = c.fetchone()
    if not inv:
        conn.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("incoming_invoice"))
    if inv["is_closed"]:
        conn.close()
        flash("الفاتورة مغلقة مسبقاً", "warning")
        return redirect(url_for("incoming_invoice"))

    c.execute("SELECT COALESCE(SUM(total_price),0) FROM incoming_invoice_items WHERE invoice_id=?", (id,))
    total = c.fetchone()[0]
    c.execute("UPDATE incoming_invoices SET is_closed=1, grand_total=? WHERE id=? AND org_id=?", (total, id, org_id))
    conn.commit()
    conn.close()
    flash(f"🔒 تم إغلاق الفاتورة نهائياً — الإجمالي: {total:.2f}", "success")
    return redirect(url_for("incoming_invoice"))


@app.route("/incoming_invoice/<int:id>/upload_image", methods=["POST"])
@invoices_required
def upload_invoice_image(id):
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT id FROM incoming_invoices WHERE id=? AND org_id=?", (id, org_id))
    if not c.fetchone():
        conn.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("incoming_invoice"))

    img_file = request.files.get("invoice_image")
    if img_file and img_file.filename and allowed_file(img_file.filename) and allowed_file_content(img_file):
        ext = img_file.filename.rsplit(".", 1)[1].lower()
        stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        filename = f"invoice_{org_id}_{stamp}.{ext}"
        img_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        c.execute("UPDATE incoming_invoices SET invoice_image=? WHERE id=? AND org_id=?", (filename, id, org_id))
        conn.commit()
        flash("✅ تم رفع صورة الفاتورة", "success")
    else:
        flash("يرجى اختيار صورة بصيغة png / jpg / jpeg / webp", "danger")

    conn.close()
    return redirect(url_for("incoming_invoice"))


@app.route("/incoming_invoice/<int:id>/upload/<img_type>", methods=["POST"])
@invoices_required
def upload_invoice_image_typed(id, img_type):
    """رفع صور الفاتورة الثلاث: invoice / receipt / attachment"""
    if img_type not in ("invoice", "receipt", "attachment"):
        flash("نوع الصورة غير صالح", "danger")
        return redirect(url_for("incoming_invoice"))

    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, is_closed FROM incoming_invoices WHERE id=? AND org_id=?", (id, org_id))
    inv = c.fetchone()
    if not inv:
        conn.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("incoming_invoice"))

    field = {"invoice": "invoice_image", "receipt": "receipt_image", "attachment": "attachment_image"}[img_type]
    img_file = request.files.get("img_file")
    if img_file and img_file.filename and allowed_file(img_file.filename) and allowed_file_content(img_file):
        ext = img_file.filename.rsplit(".", 1)[1].lower()
        stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        filename = f"{img_type}_{org_id}_{stamp}.{ext}"
        img_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        # حالة الدفع تُحدَّد تلقائياً من وجود صورة سند القبض
        if img_type == "receipt":
            c.execute(f"UPDATE incoming_invoices SET {field}=?, is_paid=1 WHERE id=? AND org_id=?", (filename, id, org_id))
        else:
            c.execute(f"UPDATE incoming_invoices SET {field}=? WHERE id=? AND org_id=?", (filename, id, org_id))
        conn.commit()
        flash("✅ تم رفع الصورة", "success")
    else:
        flash("يرجى اختيار صورة بصيغة png / jpg / jpeg / webp", "danger")

    conn.close()
    return redirect(url_for("incoming_invoice") + f"#inv-{id}")


@app.route("/incoming_invoice/<int:id>/delete")
@invoices_required
def delete_incoming_invoice(id):
    """حذف فاتورة وإعادة ترقيم الفواتير التالية"""
    if session.get("role") not in ("admin", "accountant"):
        flash("ليس لديك صلاحية حذف الفواتير", "danger")
        return redirect(url_for("incoming_invoice"))

    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT id, seq_num FROM incoming_invoices WHERE id=? AND org_id=?", (id, org_id))
    inv = c.fetchone()
    if not inv:
        conn.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("incoming_invoice"))

    deleted_seq = inv["seq_num"]

    # حذف دفعات المخزون المرتبطة بهذه الفاتورة
    c.execute("DELETE FROM stock_batches WHERE invoice_id=? AND org_id=?", (id, org_id))
    # حذف أصناف الفاتورة
    c.execute("DELETE FROM incoming_invoice_items WHERE invoice_id=?", (id,))
    # حذف الفاتورة
    c.execute("DELETE FROM incoming_invoices WHERE id=? AND org_id=?", (id, org_id))

    # إعادة ترقيم الفواتير التالية
    if deleted_seq:
        c.execute("""
            UPDATE incoming_invoices
            SET seq_num = seq_num - 1,
                invoice_number = CAST((seq_num - 1) AS TEXT)
            WHERE org_id=? AND seq_num > ?
        """, (org_id, deleted_seq))

    conn.commit()
    conn.close()
    flash("🗑️ تم حذف الفاتورة وإعادة الترقيم", "warning")
    return redirect(url_for("incoming_invoice"))


@app.route("/incoming_invoice/<int:id>/update", methods=["POST"])
@invoices_required
def update_invoice(id):
    """تعديل فاتورة مفتوحة (أدمن فقط): المورد، التاريخ، الأصناف كاملة"""
    if session.get("role") != "admin":
        flash("هذه الميزة للأدمن فقط", "danger")
        return redirect(url_for("incoming_invoices_list"))

    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT is_closed FROM incoming_invoices WHERE id=? AND org_id=?", (id, org_id))
    inv = c.fetchone()
    if not inv or inv["is_closed"]:
        conn.close()
        flash("لا يمكن تعديل فاتورة مغلقة", "danger")
        return redirect(url_for("incoming_invoices_list"))

    # تعديل رأس الفاتورة
    supplier     = request.form.get("supplier", "").strip()
    invoice_date = request.form.get("invoice_date", "").strip()
    if supplier:
        c.execute("UPDATE incoming_invoices SET supplier=?, invoice_date=? WHERE id=? AND org_id=?",
                  (supplier, invoice_date, id, org_id))

    # تعديل الأصناف (اسم + سعر + كمية + تاريخ)
    item_ids    = request.form.getlist("item_id[]")
    prod_names  = request.form.getlist("prod_name[]")
    unit_prices = request.form.getlist("unit_price[]")
    quantities  = request.form.getlist("quantity[]")
    prod_dates  = request.form.getlist("prod_date[]")

    for item_id, pname, uprice, qty_str, pdate in zip(item_ids, prod_names, unit_prices, quantities, prod_dates):
        try:
            uprice_f = float(uprice)
            new_qty  = float(qty_str)
            if new_qty <= 0:
                continue
            c.execute("SELECT product_id, quantity FROM incoming_invoice_items WHERE id=? AND invoice_id=?",
                      (item_id, id))
            row = c.fetchone()
            if not row:
                continue
            pid, old_qty = row["product_id"], row["quantity"]
            qty_diff = new_qty - old_qty   # موجب = زيادة، سالب = نقصان

            # تحديث اسم المنتج
            if pname.strip():
                c.execute("UPDATE products SET name=?, last_modified=? WHERE id=? AND org_id=?",
                          (pname.strip(), pdate, pid, org_id))

            # تحديث الصنف في الفاتورة
            c.execute("""
                UPDATE incoming_invoice_items
                SET quantity=?, unit_price=?, total_price=?, purchase_date=?
                WHERE id=?
            """, (new_qty, uprice_f, new_qty * uprice_f, pdate, item_id))

            # تحديث stock_batch: الكمية المتبقية + السعر + التاريخ
            c.execute("""
                UPDATE stock_batches
                SET quantity_remaining = quantity_remaining + ?,
                    unit_price = ?,
                    entry_date = ?
                WHERE product_id=? AND invoice_id=? AND org_id=?
            """, (qty_diff, uprice_f, pdate, pid, id, org_id))

        except (ValueError, TypeError):
            pass

    conn.commit()
    conn.close()
    flash("✅ تم حفظ التعديلات", "success")
    return redirect(url_for("incoming_invoices_list") + f"#inv-{id}")


@app.route("/incoming_invoice/item/<int:item_id>/delete")
@invoices_required
def delete_incoming_item(item_id):
    """حذف صنف من فاتورة مشتريات مفتوحة مع إزالته من المخزن (أدمن فقط)"""
    if session.get("role") != "admin":
        flash("هذه الميزة للأدمن فقط", "danger")
        return redirect(url_for("incoming_invoices_list"))
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        SELECT ii.id, ii.invoice_id, ii.product_id, ii.quantity
        FROM incoming_invoice_items ii
        JOIN incoming_invoices inv ON inv.id = ii.invoice_id
        WHERE ii.id=? AND inv.org_id=? AND COALESCE(inv.is_closed,0)=0
    """, (item_id, org_id))
    item = c.fetchone()
    if not item:
        conn.close()
        flash("الصنف غير موجود أو الفاتورة مغلقة", "danger")
        return redirect(url_for("incoming_invoices_list"))

    invoice_id = item["invoice_id"]
    product_id = item["product_id"]
    qty        = item["quantity"]

    # إزالة الكمية من المخزن (تخفيض quantity_remaining في الـ batch المرتبط بهذه الفاتورة)
    c.execute("""
        UPDATE stock_batches
        SET quantity_remaining = MAX(0, quantity_remaining - ?)
        WHERE product_id=? AND invoice_id=? AND org_id=?
    """, (qty, product_id, invoice_id, org_id))

    c.execute("DELETE FROM incoming_invoice_items WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    flash("✅ تم حذف الصنف من الفاتورة والمخزن", "success")
    return redirect(url_for("incoming_invoices_list") + f"#inv-{invoice_id}")


@app.route("/incoming_invoices_list")
@invoices_view_required
def incoming_invoices_list():
    """صفحة الفواتير المضافة — كل الفواتير (مفتوحة ومغلقة) مع فلتر"""
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        SELECT id, seq_num, invoice_number, invoice_date, supplier,
               is_closed, is_paid, invoice_image, receipt_image, attachment_image, created_at,
               purchase_invoice_number, invoice_name, notes
        FROM incoming_invoices
        WHERE org_id=?
        ORDER BY COALESCE(seq_num,id) ASC
    """, (org_id,))
    inv_rows = c.fetchall()

    invoices = []
    total_all = 0.0
    for inv in inv_rows:
        inv_d = dict(inv)
        c.execute("""
            SELECT ii.id, ii.quantity, ii.unit_price, ii.total_price, ii.purchase_date,
                   p.name AS product_name, p.unit AS product_unit, p.id AS product_id
            FROM incoming_invoice_items ii
            JOIN products p ON p.id = ii.product_id
            WHERE ii.invoice_id=? ORDER BY ii.id
        """, (inv["id"],))
        items = [dict(r) for r in c.fetchall()]
        inv_total = sum(it["total_price"] for it in items)
        inv_d["lines"] = items
        inv_d["total"] = inv_total
        inv_d["display_num"] = inv_d.get("seq_num") or inv_d.get("invoice_number") or inv_d["id"]
        total_all += inv_total
        invoices.append(inv_d)

    today_str = datetime.now().strftime("%Y-%m-%d")
    conn.close()
    return render_template("incoming_invoices_list.html",
                           invoices=invoices, total_all=total_all, today_str=today_str)


@app.route("/incoming_invoice/<int:id>/save_notes", methods=["POST"])
@invoices_required
def save_incoming_invoice_notes(id):
    """حفظ ملاحظات فاتورة الشراء — يعمل للمفتوحة والمغلقة"""
    if session.get("role") == "observer":
        flash("ليس لديك صلاحية", "danger")
        return redirect(url_for("incoming_invoices_list") + f"#inv-{id}")
    if not validate_csrf():
        flash("خطأ في التحقق", "danger")
        return redirect(url_for("incoming_invoices_list") + f"#inv-{id}")
    org_id = session["org_id"]
    notes = request.form.get("notes", "").strip()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM incoming_invoices WHERE id=? AND org_id=?", (id, org_id))
    if not c.fetchone():
        conn.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("incoming_invoices_list"))
    c.execute("UPDATE incoming_invoices SET notes=? WHERE id=? AND org_id=?", (notes, id, org_id))
    conn.commit()
    conn.close()
    flash("✅ تم حفظ الملاحظة", "success")
    return redirect(url_for("incoming_invoices_list") + f"#inv-{id}")


# ══════════════════════════════════════════
# البرامج والمشاريع (أدمن فقط)
# ══════════════════════════════════════════
DEFAULT_PROGRAMS = [
    "كفالات أيتام",
    "طرود غذائية",
    "تكية",
    "مياه حلوة",
    "وجبات ساخنة",
]

@app.route("/programs")
@programs_view_required
def programs_list():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    # إضافة البرامج الافتراضية إن لم تكن موجودة
    c.execute("SELECT COUNT(*) FROM programs WHERE org_id=?", (org_id,))
    if c.fetchone()[0] == 0:
        for p in DEFAULT_PROGRAMS:
            c.execute("INSERT INTO programs (org_id, name) VALUES (?,?)", (org_id, p))
        conn.commit()
    c.execute("SELECT * FROM programs WHERE org_id=? ORDER BY id", (org_id,))
    programs = [dict(r) for r in c.fetchall()]

    # إحصاءات الفئات المستحقة من بيانات المستفيدين
    c.execute("""
        SELECT COALESCE(SUM(orphans_count),0) as total_orphans,
               COUNT(*) as families_with_orphans
        FROM beneficiaries WHERE org_id=? AND has_orphans=1
    """, (org_id,))
    orphan_stats = dict(c.fetchone())

    c.execute("""
        SELECT COUNT(*) FROM beneficiaries
        WHERE org_id=? AND (marital_status='widowed' OR family_size=1)
    """, (org_id,))
    widows_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM beneficiaries WHERE org_id=? AND wife_pregnant=1", (org_id,))
    pregnant_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM beneficiaries WHERE org_id=? AND wife_nursing=1", (org_id,))
    nursing_count = c.fetchone()[0]

    conn.close()
    return render_template("programs.html", programs=programs,
        orphan_stats=orphan_stats, widows_count=widows_count,
        pregnant_count=pregnant_count, nursing_count=nursing_count)


@app.route("/add_program", methods=["POST"])
@admin_required
def add_program():
    name = request.form.get("name", "").strip()
    if name:
        conn = get_connection()
        c = conn.cursor()
        c.execute("INSERT INTO programs (org_id, name) VALUES (?,?)",
                  (session["org_id"], name))
        conn.commit()
        conn.close()
        flash(f"✅ تمت إضافة البرنامج '{name}'", "success")
    return redirect(url_for("programs_list"))


@app.route("/toggle_program/<int:id>")
@admin_required
def toggle_program(id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE programs SET is_active = 1 - is_active WHERE id=? AND org_id=?",
              (id, session["org_id"]))
    conn.commit()
    conn.close()
    return redirect(url_for("programs_list"))


@app.route("/delete_program/<int:id>")
@admin_required
def delete_program(id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM programs WHERE id=? AND org_id=?", (id, session["org_id"]))
    conn.commit()
    conn.close()
    flash("تم حذف البرنامج", "warning")
    return redirect(url_for("programs_list"))


# ══════════════════════════════════════════
# تفاصيل البرنامج وسجلات الاستفادة
# ══════════════════════════════════════════
@app.route("/program/<int:id>")
@programs_view_required
def program_detail(id):
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM programs WHERE id=? AND org_id=?", (id, org_id))
    program = c.fetchone()
    if not program:
        conn.close()
        flash("البرنامج غير موجود", "danger")
        return redirect(url_for("programs_list"))
    program = dict(program)

    c.execute("""
        SELECT pr.id, pr.benefit_date, pr.benefit_type, pr.quantity, pr.notes, pr.created_by,
               b.seq_num, b.full_name, b.id_number
        FROM program_records pr
        JOIN beneficiaries b ON b.id = pr.beneficiary_id
        WHERE pr.org_id=? AND pr.program_id=?
        ORDER BY pr.benefit_date DESC, pr.id DESC
    """, (org_id, id))
    records = [dict(r) for r in c.fetchall()]

    c.execute("SELECT id, seq_num, full_name FROM beneficiaries WHERE org_id=? ORDER BY full_name", (org_id,))
    beneficiaries = [dict(r) for r in c.fetchall()]

    conn.close()
    return render_template("program_detail.html",
        program=program, records=records, beneficiaries=beneficiaries)


@app.route("/program/<int:id>/add_record", methods=["POST"])
@admin_required
def add_program_record(id):
    org_id = session["org_id"]

    beneficiary_id = request.form.get("beneficiary_id", "").strip()
    benefit_date   = request.form.get("benefit_date", "").strip()
    benefit_type   = request.form.get("benefit_type", "").strip()
    quantity       = request.form.get("quantity", "").strip()
    notes          = request.form.get("notes", "").strip()

    if not beneficiary_id or not benefit_date:
        flash("يرجى اختيار المستفيد وتاريخ الاستفادة", "danger")
        return redirect(url_for("program_detail", id=id))

    conn = get_connection()
    c = conn.cursor()

    # التأكد أن البرنامج والمستفيد ينتميان لنفس المؤسسة
    c.execute("SELECT id FROM programs WHERE id=? AND org_id=?", (id, org_id))
    if not c.fetchone():
        conn.close()
        flash("البرنامج غير موجود", "danger")
        return redirect(url_for("programs_list"))

    c.execute("SELECT id FROM beneficiaries WHERE id=? AND org_id=?", (beneficiary_id, org_id))
    if not c.fetchone():
        conn.close()
        flash("المستفيد غير موجود", "danger")
        return redirect(url_for("program_detail", id=id))

    c.execute("""
        INSERT INTO program_records
            (org_id, program_id, beneficiary_id, benefit_date, benefit_type, quantity, notes, created_by)
        VALUES (?,?,?,?,?,?,?,?)
    """, (org_id, id, beneficiary_id, benefit_date, benefit_type, quantity, notes, session["user"]))
    conn.commit()
    conn.close()
    flash("✅ تم إضافة سجل الاستفادة", "success")
    return redirect(url_for("program_detail", id=id))


@app.route("/program/<int:id>/delete_record/<int:record_id>")
@admin_required
def delete_program_record(id, record_id):
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM program_records WHERE id=? AND org_id=? AND program_id=?",
              (record_id, org_id, id))
    conn.commit()
    conn.close()
    flash("تم حذف السجل", "warning")
    return redirect(url_for("program_detail", id=id))


# ══════════════════════════════════════════
# فواتير الصرف
# ══════════════════════════════════════════
@app.route("/outgoing_invoice", methods=["GET", "POST"])
@invoices_view_required
def outgoing_invoice():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    if request.method == "POST" and session.get("role") == "observer":
        flash("مراقب عام: لا تملك صلاحية الإضافة أو التعديل", "danger")
        return redirect(url_for("outgoing_invoice"))

    def get_inventory():
        c.execute("SELECT id, name, unit FROM products WHERE org_id=? ORDER BY name", (org_id,))
        prods = c.fetchall()
        inv = []
        total_val = 0.0
        for p in prods:
            c.execute("SELECT quantity_remaining, unit_price FROM stock_batches WHERE product_id=? AND org_id=? ORDER BY id", (p["id"], org_id))
            batches = c.fetchall()
            total_qty = sum(b["quantity_remaining"] for b in batches)
            if total_qty > 0:
                avg_price = sum(b["quantity_remaining"] * b["unit_price"] for b in batches) / total_qty
            elif batches:
                avg_price = batches[-1]["unit_price"]
            else:
                avg_price = 0.0
            value = total_qty * avg_price
            total_val += value
            inv.append({"id": p["id"], "name": p["name"], "unit": p["unit"],
                         "total_qty": total_qty, "avg_price": avg_price, "value": value})
        return inv, total_val

    def get_render_data():
        c.execute("SELECT id, name FROM products WHERE org_id=? ORDER BY name", (org_id,))
        pl = c.fetchall()
        c.execute("SELECT id, full_name FROM beneficiaries WHERE org_id=? ORDER BY full_name", (org_id,))
        bl = c.fetchall()
        c.execute("SELECT * FROM programs WHERE org_id=? AND is_active=1 ORDER BY name", (org_id,))
        rows = c.fetchall()
        progs = [dict(r) for r in rows]
        if not progs:
            for p in DEFAULT_PROGRAMS:
                c.execute("INSERT INTO programs (org_id, name) VALUES (?,?)", (org_id, p))
            conn.commit()
            c.execute("SELECT * FROM programs WHERE org_id=? AND is_active=1 ORDER BY name", (org_id,))
            progs = [dict(r) for r in c.fetchall()]
        return pl, bl, progs

    if request.method == "POST":
        invoice_number = request.form.get("invoice_number", "").strip()
        invoice_date   = request.form.get("invoice_date", "").strip()
        program_id     = request.form.get("program_id", "").strip()
        beneficiary    = request.form.get("beneficiary", "").strip()
        notes          = request.form.get("notes", "").strip()
        product_ids    = request.form.getlist("product_id[]")
        product_names  = request.form.getlist("product_name[]")
        quantities     = request.form.getlist("quantity[]")

        # البرنامج هو الجهة المستفيدة الرئيسية
        disbursed_to = ""
        if program_id:
            c.execute("SELECT name FROM programs WHERE id=? AND org_id=?", (program_id, org_id))
            prog = c.fetchone()
            if prog:
                disbursed_to = prog["name"]
        # لو في مستفيد محدد نضيفه للاسم
        if beneficiary:
            disbursed_to = f"{disbursed_to} — {beneficiary}" if disbursed_to else beneficiary

        if not invoice_number or not invoice_date or not disbursed_to:
            flash("يرجى تعبئة رقم الفاتورة والتاريخ والبرنامج", "danger")
            pl, bl, progs = get_render_data()
            inventory, total_value = get_inventory()
            conn.close()
            return render_template("outgoing_invoices.html",
                products=pl, beneficiaries=bl, programs=progs,
                inventory=inventory, total_value=total_value)

        c.execute(
            "INSERT INTO outgoing_invoices (org_id, invoice_number, invoice_date, beneficiary, notes, created_by) VALUES (?,?,?,?,?,?)",
            (org_id, invoice_number, invoice_date, disbursed_to, notes, session["user"])
        )
        invoice_id = c.lastrowid
        errors = []
        # ضمان نفس طول القوائم الثلاث بتعبئة الناقص بـ ''
        max_len = max(len(product_ids), len(product_names), len(quantities))
        product_ids   += [''] * (max_len - len(product_ids))
        product_names += [''] * (max_len - len(product_names))
        quantities    += [''] * (max_len - len(quantities))

        for pid, pname, qty in zip(product_ids, product_names, quantities):
            # إذا product_id فارغ ولكن في اسم، ابحث عنه بالاسم
            if not pid and pname:
                c.execute("SELECT id FROM products WHERE name=? AND org_id=?", (pname.strip(), org_id))
                row = c.fetchone()
                if row:
                    pid = str(row["id"])
            if pid and qty:
                try:
                    qty_needed = float(qty)
                    c.execute("SELECT id, quantity_remaining, unit_price FROM stock_batches WHERE product_id=? AND org_id=? AND quantity_remaining>0 ORDER BY id ASC",
                              (pid, org_id))
                    batches = c.fetchall()
                    total_available = sum(b["quantity_remaining"] for b in batches)
                    if total_available < qty_needed:
                        c.execute("SELECT name FROM products WHERE id=?", (pid,))
                        pname = c.fetchone()["name"]
                        errors.append(f"الكمية المطلوبة من '{pname}' ({qty_needed}) أكبر من المتاح ({total_available:.2f})")
                        continue
                    remaining, weighted = qty_needed, 0
                    for batch in batches:
                        if remaining <= 0:
                            break
                        take = min(remaining, batch["quantity_remaining"])
                        weighted += take * batch["unit_price"]
                        c.execute("UPDATE stock_batches SET quantity_remaining=? WHERE id=?",
                                  (batch["quantity_remaining"] - take, batch["id"]))
                        remaining -= take
                    c.execute("INSERT INTO outgoing_invoice_items (invoice_id, product_id, quantity, unit_price, total_price) VALUES (?,?,?,?,?)",
                              (invoice_id, pid, qty_needed, weighted/qty_needed, weighted))
                except ValueError:
                    pass
        conn.commit()
        conn.close()
        for err in errors:
            flash(err, "warning")
        if not errors:
            flash("✅ تم حفظ فاتورة الصرف وتم خصم الكمية من المخزن تلقائياً", "success")
            return redirect(url_for("outgoing_invoices_list"))
        return redirect(url_for("outgoing_invoice"))

    pl, bl, progs = get_render_data()
    inventory, total_value = get_inventory()
    conn.close()
    return render_template("outgoing_invoices.html",
        products=pl, beneficiaries=bl, programs=progs,
        inventory=inventory, total_value=total_value)


# ══════════════════════════════════════════
# كشف فواتير الصرف
# ══════════════════════════════════════════
@app.route("/outgoing_invoices_list")
@invoices_view_required
def outgoing_invoices_list():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT id, invoice_number, invoice_date, beneficiary, notes, created_at,
               COALESCE(is_closed,0) AS is_closed
        FROM outgoing_invoices WHERE org_id=? ORDER BY id DESC
    """, (org_id,))
    invoices_rows = c.fetchall()

    invoices = []
    total_all = 0.0
    for inv in invoices_rows:
        inv_d = dict(inv)
        c.execute("""
            SELECT oi.id, oi.quantity, oi.unit_price, oi.total_price,
                   p.name as product_name, p.unit
            FROM outgoing_invoice_items oi
            JOIN products p ON p.id = oi.product_id
            WHERE oi.invoice_id=?
            ORDER BY oi.id
        """, (inv["id"],))
        items = [dict(r) for r in c.fetchall()]
        inv_total = sum(it["total_price"] for it in items)
        inv_d["lines"] = items
        inv_d["total"] = inv_total
        total_all += inv_total
        invoices.append(inv_d)

    today_str = datetime.now().strftime("%Y-%m-%d")
    conn.close()
    return render_template("outgoing_invoices_list.html",
                           invoices=invoices, total_all=total_all, today_str=today_str)


# ══════════════════════════════════════════
# العاملين
# ══════════════════════════════════════════
@app.route("/workers")
@login_required
def workers_list():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM workers WHERE org_id=? ORDER BY id DESC", (org_id,))
    workers = [dict(r) for r in c.fetchall()]
    c.execute("SELECT name FROM programs WHERE org_id=? AND is_active=1 ORDER BY name", (org_id,))
    programs = [r["name"] for r in c.fetchall()]
    conn.close()
    return render_template("workers.html", workers=workers, programs=programs)


@app.route("/add_worker", methods=["POST"])
@login_required
def add_worker():
    if session.get("role") == "observer":
        flash("مراقب: لا تملك صلاحية الإضافة", "danger")
        return redirect(url_for("workers_list"))
    org_id = session["org_id"]
    full_name      = request.form.get("full_name", "").strip()
    id_number      = request.form.get("id_number", "").strip()
    project_name   = request.form.get("project_name", "").strip()
    job_type       = request.form.get("job_type", "").strip()
    monthly_salary = request.form.get("monthly_salary", "0").strip()
    notes          = request.form.get("notes", "").strip()
    if not full_name:
        flash("يرجى إدخال اسم العامل", "danger")
        return redirect(url_for("workers_list"))
    try:
        salary = float(monthly_salary)
    except ValueError:
        salary = 0.0
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO workers (org_id, full_name, id_number, project_name, job_type, monthly_salary, notes) VALUES (?,?,?,?,?,?,?)",
        (org_id, full_name, id_number, project_name, job_type, salary, notes)
    )
    conn.commit()
    conn.close()
    flash("✅ تم إضافة العامل", "success")
    return redirect(url_for("workers_list"))


@app.route("/delete_worker/<int:id>")
@login_required
def delete_worker(id):
    if session.get("role") not in ["admin", "accountant"]:
        flash("ليس لديك صلاحية الحذف", "danger")
        return redirect(url_for("workers_list"))
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM workers WHERE id=? AND org_id=?", (id, session["org_id"]))
    conn.commit()
    conn.close()
    flash("تم حذف العامل", "warning")
    return redirect(url_for("workers_list"))


@app.route("/edit_worker/<int:id>", methods=["POST"])
@login_required
def edit_worker(id):
    if session.get("role") not in ["admin", "accountant"]:
        return jsonify({"ok": False, "err": "forbidden"}), 403
    org_id = session["org_id"]
    full_name     = request.form.get("full_name", "").strip()
    id_number     = request.form.get("id_number", "").strip()
    project_name  = request.form.get("project_name", "").strip()
    job_type      = request.form.get("job_type", "").strip()
    monthly_salary= request.form.get("monthly_salary", "0").strip()
    notes         = request.form.get("notes", "").strip()
    if not full_name:
        return jsonify({"ok": False, "err": "name_required"}), 400
    try:
        salary = float(monthly_salary)
    except ValueError:
        salary = 0.0
    conn = get_connection()
    c    = conn.cursor()
    c.execute("""UPDATE workers
                 SET full_name=?, id_number=?, project_name=?, job_type=?, monthly_salary=?, notes=?
                 WHERE id=? AND org_id=?""",
              (full_name, id_number, project_name, job_type, salary, notes, id, org_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/outgoing_invoice/<int:id>/delete")
@invoices_required
def delete_outgoing_invoice(id):
    """حذف فاتورة صرف مع إعادة كل الكميات للمخزن (أدمن فقط)"""
    if session.get("role") != "admin":
        flash("هذا الإجراء مخصص للأدمن فقط", "danger")
        return redirect(url_for("outgoing_invoices_list"))
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM outgoing_invoices WHERE id=? AND org_id=?", (id, org_id))
    if not c.fetchone():
        conn.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("outgoing_invoices_list"))

    # إعادة كل الكميات للمخزن
    c.execute("SELECT product_id, quantity, unit_price FROM outgoing_invoice_items WHERE invoice_id=?", (id,))
    items = c.fetchall()
    for item in items:
        c.execute("""
            SELECT id FROM stock_batches
            WHERE product_id=? AND org_id=? ORDER BY id DESC LIMIT 1
        """, (item["product_id"], org_id))
        batch = c.fetchone()
        if batch:
            c.execute("UPDATE stock_batches SET quantity_remaining = quantity_remaining + ? WHERE id=?",
                      (item["quantity"], batch["id"]))
        else:
            c.execute("""
                INSERT INTO stock_batches (org_id, product_id, quantity_remaining, unit_price, entry_date)
                VALUES (?,?,?,?,date('now','localtime'))
            """, (org_id, item["product_id"], item["quantity"], item["unit_price"]))

    c.execute("DELETE FROM outgoing_invoice_items WHERE invoice_id=?", (id,))
    c.execute("DELETE FROM outgoing_invoices WHERE id=? AND org_id=?", (id, org_id))
    conn.commit()
    conn.close()
    flash("✅ تم حذف الفاتورة وإعادة جميع الكميات للمخزن", "success")
    return redirect(url_for("outgoing_invoices_list"))


@app.route("/outgoing_invoice/<int:id>/close")
@invoices_required
def close_outgoing_invoice(id):
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE outgoing_invoices SET is_closed=1 WHERE id=? AND org_id=?", (id, org_id))
    conn.commit()
    conn.close()
    flash("✅ تم إغلاق فاتورة الصرف", "success")
    return redirect(url_for("outgoing_invoices_list"))


@app.route("/outgoing_invoice/<int:id>/update", methods=["POST"])
@invoices_required
def update_outgoing_invoice(id):
    """تعديل رأس فاتورة الصرف المفتوحة + أصنافها (أدمن فقط)"""
    if session.get("role") != "admin":
        flash("هذا الإجراء مخصص للأدمن فقط", "danger")
        return redirect(url_for("outgoing_invoices_list"))
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT is_closed FROM outgoing_invoices WHERE id=? AND org_id=?", (id, org_id))
    inv = c.fetchone()
    if not inv or inv["is_closed"]:
        conn.close()
        flash("الفاتورة مغلقة أو غير موجودة", "danger")
        return redirect(url_for("outgoing_invoices_list"))

    # تعديل الرأس
    invoice_number = request.form.get("invoice_number", "").strip()
    invoice_date   = request.form.get("invoice_date", "").strip()
    beneficiary    = request.form.get("beneficiary", "").strip()
    notes          = request.form.get("notes", "").strip()
    c.execute("""
        UPDATE outgoing_invoices
        SET invoice_number=?, invoice_date=?, beneficiary=?, notes=?
        WHERE id=? AND org_id=?
    """, (invoice_number, invoice_date, beneficiary, notes, id, org_id))

    # تعديل الأصناف
    item_ids    = request.form.getlist("item_id[]")
    prod_names  = request.form.getlist("prod_name[]")
    unit_prices = request.form.getlist("unit_price[]")

    for iid, pname, uprice in zip(item_ids, prod_names, unit_prices):
        try:
            price_f = float(uprice)
            c.execute("SELECT quantity FROM outgoing_invoice_items WHERE id=? AND invoice_id=?", (iid, id))
            row = c.fetchone()
            if not row:
                continue
            qty = row["quantity"]
            # تحديث اسم الصنف في جدول المنتجات إن وجد
            c.execute("SELECT product_id FROM outgoing_invoice_items WHERE id=?", (iid,))
            pid_row = c.fetchone()
            if pid_row and pname.strip():
                c.execute("UPDATE products SET name=? WHERE id=? AND org_id=?",
                          (pname.strip(), pid_row["product_id"], org_id))
            c.execute("""
                UPDATE outgoing_invoice_items
                SET unit_price=?, total_price=?
                WHERE id=? AND invoice_id=?
            """, (price_f, qty * price_f, iid, id))
        except (ValueError, TypeError):
            pass

    conn.commit()
    conn.close()
    flash("✅ تم حفظ التعديلات", "success")
    return redirect(url_for("outgoing_invoices_list") + f"#inv-{id}")


@app.route("/outgoing_invoice/item/<int:item_id>/delete")
@invoices_required
def delete_outgoing_item(item_id):
    """حذف صنف من فاتورة الصرف المفتوحة مع إعادة كميته للمخزن"""
    if session.get("role") != "admin":
        flash("هذا الإجراء مخصص للأدمن فقط", "danger")
        return redirect(url_for("outgoing_invoices_list"))
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    # جلب بيانات الصنف + التحقق من أن الفاتورة مفتوحة
    c.execute("""
        SELECT oi.id, oi.invoice_id, oi.product_id, oi.quantity, oi.unit_price
        FROM outgoing_invoice_items oi
        JOIN outgoing_invoices inv ON inv.id = oi.invoice_id
        WHERE oi.id=? AND inv.org_id=? AND COALESCE(inv.is_closed,0)=0
    """, (item_id, org_id))
    item = c.fetchone()
    if not item:
        conn.close()
        flash("الصنف غير موجود أو الفاتورة مغلقة", "danger")
        return redirect(url_for("outgoing_invoices_list"))

    invoice_id = item["invoice_id"]
    product_id = item["product_id"]
    qty        = item["quantity"]
    price      = item["unit_price"]

    # إعادة الكمية للمخزن: أضف للدفعة الأخيرة الموجودة أو أنشئ دفعة جديدة
    c.execute("""
        SELECT id FROM stock_batches
        WHERE product_id=? AND org_id=?
        ORDER BY id DESC LIMIT 1
    """, (product_id, org_id))
    batch = c.fetchone()
    if batch:
        c.execute("UPDATE stock_batches SET quantity_remaining = quantity_remaining + ? WHERE id=?",
                  (qty, batch["id"]))
    else:
        c.execute("""
            INSERT INTO stock_batches (org_id, product_id, quantity_remaining, unit_price, entry_date)
            VALUES (?,?,?,?,date('now','localtime'))
        """, (org_id, product_id, qty, price))

    # حذف الصنف
    c.execute("DELETE FROM outgoing_invoice_items WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    flash("✅ تم حذف الصنف وإعادة الكمية للمخزن", "success")
    return redirect(url_for("outgoing_invoices_list") + f"#inv-{invoice_id}")


# ══════════════════════════════════════════
# الشات الداخلي (أدمن ↔ مراقب)
# ══════════════════════════════════════════
def _chat_allowed():
    return session.get("role") in ("admin", "observer")

@app.route("/messages")
@login_required
def messages_page():
    if not _chat_allowed():
        flash("غير مصرّح", "danger")
        return redirect(url_for("dashboard"))
    org_id  = session["org_id"]
    user_id = session["user_id"]
    conn = get_connection()
    c    = conn.cursor()
    # جلب آخر 200 رسالة
    c.execute("""
        SELECT id, sender_id, sender_name, sender_role, content, attachment,
               COALESCE(edited,0) AS edited, created_at
        FROM messages WHERE org_id=?
        ORDER BY id DESC LIMIT 200
    """, (org_id,))
    msgs = list(reversed(c.fetchall()))
    # تحديث آخر رسالة مقروءة لهذا المستخدم
    if msgs:
        last_id = msgs[-1]["id"]
        c.execute("""
            INSERT INTO message_reads(user_id, last_msg_id) VALUES(?,?)
            ON CONFLICT(user_id) DO UPDATE SET last_msg_id=excluded.last_msg_id
        """, (user_id, last_id))
        conn.commit()
    conn.close()
    return render_template("messages.html", msgs=msgs)


@app.route("/messages/data")
@login_required
def messages_data():
    """إرجاع آخر 200 رسالة كـ JSON للـ floating widget"""
    if not _chat_allowed():
        return jsonify({"ok": False}), 403
    org_id  = session["org_id"]
    user_id = session["user_id"]
    conn = get_connection()
    c    = conn.cursor()
    c.execute("""
        SELECT id, sender_id, sender_name, sender_role, content, attachment,
               COALESCE(edited,0) AS edited, created_at
        FROM messages WHERE org_id=?
        ORDER BY id DESC LIMIT 200
    """, (org_id,))
    rows = list(reversed(c.fetchall()))
    if rows:
        c.execute("""
            INSERT INTO message_reads(user_id, last_msg_id) VALUES(?,?)
            ON CONFLICT(user_id) DO UPDATE SET last_msg_id=excluded.last_msg_id
        """, (user_id, rows[-1]["id"]))
        conn.commit()
    conn.close()
    return jsonify({"ok": True, "messages": [dict(r) for r in rows]})


@app.route("/messages/send", methods=["POST"])
@login_required
def messages_send():
    if not _chat_allowed():
        return jsonify({"ok": False}), 403

    # قبول JSON أو FormData (مع ملف مرفق)
    if request.is_json:
        data    = request.json or {}
        content = data.get("content", "").strip()
        attach  = data.get("attachment", "")
    else:
        content = request.form.get("content", "").strip()
        attach  = ""
        f = request.files.get("attachment")
        if f and f.filename:
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
            if ext in ALLOWED_CHAT_EXT:
                import uuid as _uuid
                safe_name = f"{_uuid.uuid4().hex}.{ext}"
                f.save(os.path.join(CHAT_UPLOAD_FOLDER, safe_name))
                attach = safe_name

    if not content and not attach:
        return jsonify({"ok": False, "err": "empty"}), 400
    if len(content) > 2000:
        return jsonify({"ok": False, "err": "too_long"}), 400

    org_id   = session["org_id"]
    user_id  = session["user_id"]
    name     = session.get("full_name") or session.get("user", "")
    role     = session.get("role", "")
    conn = get_connection()
    c    = conn.cursor()
    c.execute("""
        INSERT INTO messages(org_id, sender_id, sender_name, sender_role, content, attachment)
        VALUES(?,?,?,?,?,?)
    """, (org_id, user_id, name, role, content, attach or None))
    new_id = c.lastrowid
    c.execute("""
        INSERT INTO message_reads(user_id, last_msg_id) VALUES(?,?)
        ON CONFLICT(user_id) DO UPDATE SET last_msg_id=excluded.last_msg_id
    """, (user_id, new_id))
    conn.commit()
    conn.close()
    from datetime import datetime as _dt
    now_str = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"ok": True, "msg": {
        "id": new_id, "sender_id": user_id, "sender_name": name,
        "sender_role": role, "content": content,
        "attachment": attach or None, "edited": 0, "created_at": now_str
    }})


@app.route("/messages/poll")
@login_required
def messages_poll():
    if not _chat_allowed():
        return jsonify({"ok": False, "messages": []}), 403
    org_id  = session["org_id"]
    user_id = session["user_id"]
    # يقبل 'last' أو 'since' للتوافق
    since = request.args.get("last", request.args.get("since", 0), type=int)
    conn = get_connection()
    c    = conn.cursor()
    c.execute("""
        SELECT id, sender_id, sender_name, sender_role, content, attachment,
               COALESCE(edited,0) AS edited, created_at
        FROM messages WHERE org_id=? AND id>?
        ORDER BY id ASC LIMIT 50
    """, (org_id, since))
    rows = c.fetchall()
    if rows:
        c.execute("""
            INSERT INTO message_reads(user_id, last_msg_id) VALUES(?,?)
            ON CONFLICT(user_id) DO UPDATE SET last_msg_id=excluded.last_msg_id
        """, (user_id, rows[-1]["id"]))
        conn.commit()
    conn.close()
    return jsonify({"ok": True, "messages": [dict(r) for r in rows]})


@app.route("/messages/unread_count")
@login_required
def messages_unread_count():
    if not _chat_allowed():
        return {"count": 0}
    org_id  = session["org_id"]
    user_id = session["user_id"]
    conn = get_connection()
    c    = conn.cursor()
    c.execute("SELECT last_msg_id FROM message_reads WHERE user_id=?", (user_id,))
    row    = c.fetchone()
    last   = row["last_msg_id"] if row else 0
    c.execute("SELECT COUNT(*) as n FROM messages WHERE org_id=? AND id>?", (org_id, last))
    count  = c.fetchone()["n"]
    conn.close()
    return {"count": count}


# ── رفع مرفق للشات ──
CHAT_UPLOAD_FOLDER = os.path.join("static", "chat_uploads")
os.makedirs(CHAT_UPLOAD_FOLDER, exist_ok=True)

ALLOWED_CHAT_EXT = {
    "jpg","jpeg","png","gif","webp","bmp",   # صور
    "pdf","doc","docx","xls","xlsx",          # مستندات
    "txt","csv","zip","rar"                   # أخرى
}

@app.route("/messages/upload", methods=["POST"])
@login_required
def messages_upload():
    if not _chat_allowed():
        return {"ok": False}, 403
    f = request.files.get("file")
    if not f or not f.filename:
        return {"ok": False, "err": "no_file"}, 400
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_CHAT_EXT:
        return {"ok": False, "err": "type_not_allowed"}, 400
    import uuid
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(CHAT_UPLOAD_FOLDER, safe_name))
    return {"ok": True, "filename": safe_name, "original": f.filename}


@app.route("/messages/<int:msg_id>/edit", methods=["POST"])
@login_required
def messages_edit(msg_id):
    if not _chat_allowed():
        return jsonify({"ok": False}), 403
    content = ((request.json or {}).get("content") if request.is_json
               else request.form.get("content", ""))
    content = (content or "").strip()
    if not content or len(content) > 2000:
        return jsonify({"ok": False, "err": "invalid"}), 400
    user_id  = session["user_id"]
    org_id   = session["org_id"]
    conn = get_connection()
    c    = conn.cursor()
    c.execute("SELECT sender_id, org_id FROM messages WHERE id=?", (msg_id,))
    row = c.fetchone()
    if not row or row["org_id"] != org_id or row["sender_id"] != user_id:
        conn.close()
        return {"ok": False, "err": "forbidden"}, 403
    c.execute("UPDATE messages SET content=?, edited=1 WHERE id=?", (content, msg_id))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.route("/messages/<int:msg_id>/delete", methods=["POST"])
@login_required
def messages_delete(msg_id):
    if not _chat_allowed():
        return {"ok": False}, 403
    user_id = session["user_id"]
    org_id  = session["org_id"]
    role    = session.get("role", "")
    conn = get_connection()
    c    = conn.cursor()
    c.execute("SELECT sender_id, org_id, attachment FROM messages WHERE id=?", (msg_id,))
    row = c.fetchone()
    if not row or row["org_id"] != org_id:
        conn.close()
        return {"ok": False, "err": "not_found"}, 404
    # يسمح للمرسل نفسه أو الأدمن بالحذف
    if row["sender_id"] != user_id and role != "admin":
        conn.close()
        return {"ok": False, "err": "forbidden"}, 403
    # حذف الملف المرفق إن وجد
    if row["attachment"]:
        try:
            os.remove(os.path.join(CHAT_UPLOAD_FOLDER, row["attachment"]))
        except Exception:
            pass
    c.execute("DELETE FROM messages WHERE id=?", (msg_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.route("/translate", methods=["POST"])
@login_required
def translate_text():
    """ترجمة نص عبر MyMemory — سيرفر سايد"""
    if not _chat_allowed():
        return jsonify({"ok": False}), 403
    data = request.json or {}
    text = data.get("text", "").strip()
    dst  = data.get("dst", "ar")
    if not text or len(text) > 1000:
        return jsonify({"ok": False, "err": "invalid"}), 400

    import re as _re, urllib.request as _ur, urllib.parse as _up, json as _json2
    # كشف لغة المصدر
    if _re.search(r'[؀-ۿ]', text):
        src = 'ar'
    elif _re.search(r'[çğışöüÇĞİŞÖÜ]', text):
        src = 'tr'
    else:
        src = 'en'

    if src == dst:
        return jsonify({"ok": True, "same": True})

    try:
        url = (
            "https://api.mymemory.translated.net/get?"
            + _up.urlencode({"q": text, "langpair": f"{src}|{dst}"})
        )
        with _ur.urlopen(url, timeout=8) as r:
            d = _json2.loads(r.read())
        t = (d.get("responseData", {}).get("translatedText") or "").strip()
        if not t or t == text or "MYMEMORY" in t.upper():
            return jsonify({"ok": False, "err": "no_result"})
        return jsonify({"ok": True, "translated": t, "src": src})
    except Exception as e:
        return jsonify({"ok": False, "err": str(e)}), 500


@app.route("/messages/clear", methods=["POST"])
@login_required
def messages_clear():
    """يمسح كامل سجل المحادثة — للأدمن والمراقب"""
    if not _chat_allowed():
        return {"ok": False}, 403
    org_id = session["org_id"]
    conn = get_connection()
    c    = conn.cursor()
    # احذف المرفقات أولاً
    c.execute("SELECT attachment FROM messages WHERE org_id=? AND attachment IS NOT NULL", (org_id,))
    for row in c.fetchall():
        try:
            os.remove(os.path.join(CHAT_UPLOAD_FOLDER, row["attachment"]))
        except Exception:
            pass
    c.execute("DELETE FROM messages WHERE org_id=?", (org_id,))
    c.execute("DELETE FROM message_reads WHERE user_id IN (SELECT id FROM users WHERE org_id=?)", (org_id,))
    conn.commit()
    conn.close()
    return {"ok": True}



# ══════════════════════════════════════════
# توحيد المستفيدين بين المؤسسات
# ══════════════════════════════════════════

@app.route("/beneficiaries/check_duplicate")
@login_required
def beneficiary_check_duplicate():
    """تحقق إذا المستفيد (اسم + رقم هوية) موجود في مؤسسة أخرى"""
    org_id   = session["org_id"]
    name     = request.args.get("name", "").strip()
    id_num   = request.args.get("id_number", "").strip()
    if not name or not id_num:
        return jsonify({"found": False})
    conn = get_connection()
    c    = conn.cursor()
    c.execute("""
        SELECT b.id, b.full_name, b.id_number, o.name AS org_name, o.id AS org_id
        FROM beneficiaries b
        JOIN organizations o ON o.id = b.org_id
        WHERE b.org_id != ?
          AND TRIM(LOWER(b.full_name))   = TRIM(LOWER(?))
          AND TRIM(b.id_number) = TRIM(?)
        LIMIT 1
    """, (org_id, name, id_num))
    row = c.fetchone()
    # هل في طلب معلق بالفعل؟
    pending = False
    if row:
        c.execute("""
            SELECT id FROM beneficiary_share_requests
            WHERE requester_org_id=? AND beneficiary_id=? AND status='pending'
        """, (org_id, row["id"]))
        pending = bool(c.fetchone())
    conn.close()
    if row:
        return jsonify({"found": True, "pending": pending,
                        "beneficiary_id": row["id"],
                        "org_name": row["org_name"],
                        "org_id": row["org_id"]})
    return jsonify({"found": False})


@app.route("/beneficiaries/request_share", methods=["POST"])
@login_required
def beneficiary_request_share():
    """إرسال طلب إضافة مستفيد من مؤسسة أخرى"""
    if session.get("role") != "admin":
        return jsonify({"ok": False}), 403
    csrf = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
    if csrf != session.get("_csrf"):
        return jsonify({"ok": False}), 403
    org_id         = session["org_id"]
    beneficiary_id = int(request.form.get("beneficiary_id", 0))
    if not beneficiary_id:
        return jsonify({"ok": False, "msg": "معرّف المستفيد مفقود"}), 400
    conn = get_connection()
    c    = conn.cursor()
    # تحقق أن المستفيد موجود في مؤسسة أخرى
    c.execute("SELECT org_id FROM beneficiaries WHERE id=?", (beneficiary_id,))
    row = c.fetchone()
    if not row or row["org_id"] == org_id:
        conn.close()
        return jsonify({"ok": False, "msg": "المستفيد غير موجود أو ينتمي لمؤسستك"}), 400
    owner_org_id = row["org_id"]
    # تحقق إنه ما في طلب معلق بالفعل
    c.execute("""
        SELECT id FROM beneficiary_share_requests
        WHERE requester_org_id=? AND beneficiary_id=? AND status='pending'
    """, (org_id, beneficiary_id))
    if c.fetchone():
        conn.close()
        return jsonify({"ok": False, "msg": "يوجد طلب معلق بالفعل"})
    from datetime import datetime as _dt
    c.execute("""
        INSERT INTO beneficiary_share_requests
            (requester_org_id, owner_org_id, beneficiary_id, status, created_at)
        VALUES (?,?,?,'pending',?)
    """, (org_id, owner_org_id, beneficiary_id, _dt.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/notifications")
@login_required
def notifications():
    if session.get("role") != "admin":
        flash("غير مصرّح", "danger")
        return redirect(url_for("dashboard"))
    org_id = session["org_id"]
    conn   = get_connection()
    c      = conn.cursor()
    # طلبات واردة — أنا المالك
    c.execute("""
        SELECT r.id, r.status, r.created_at,
               b.full_name, b.id_number,
               o.name AS requester_name
        FROM beneficiary_share_requests r
        JOIN beneficiaries b ON b.id = r.beneficiary_id
        JOIN organizations o ON o.id = r.requester_org_id
        WHERE r.owner_org_id = ?
        ORDER BY r.id DESC
    """, (org_id,))
    incoming = c.fetchall()
    # طلبات صادرة — أنا الطالب
    c.execute("""
        SELECT r.id, r.status, r.created_at,
               b.full_name, b.id_number,
               o.name AS owner_name
        FROM beneficiary_share_requests r
        JOIN beneficiaries b ON b.id = r.beneficiary_id
        JOIN organizations o ON o.id = r.owner_org_id
        WHERE r.requester_org_id = ?
        ORDER BY r.id DESC
    """, (org_id,))
    outgoing = c.fetchall()
    conn.close()
    return render_template("notifications.html",
                           incoming=incoming, outgoing=outgoing)


@app.route("/notifications/<int:req_id>/approve", methods=["POST"])
@login_required
def notification_approve(req_id):
    if session.get("role") != "admin":
        return jsonify({"ok": False}), 403
    csrf = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
    if csrf != session.get("_csrf"):
        return jsonify({"ok": False}), 403
    org_id = session["org_id"]
    conn   = get_connection()
    c      = conn.cursor()
    c.execute("""
        SELECT r.*, b.full_name, b.id_number, b.phone, b.address,
               b.family_size, b.marital_status, b.gender, b.children_count,
               b.beneficiary_type, b.notes
        FROM beneficiary_share_requests r
        JOIN beneficiaries b ON b.id = r.beneficiary_id
        WHERE r.id=? AND r.owner_org_id=? AND r.status='pending'
    """, (req_id, org_id))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "msg": "الطلب غير موجود"}), 404
    # أضف المستفيد للمؤسسة الطالبة
    from datetime import datetime as _dt
    now = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
    # احسب seq_num التالي للمؤسسة الطالبة
    c.execute("SELECT COALESCE(MAX(seq_num),0)+1 FROM beneficiaries WHERE org_id=?",
              (row["requester_org_id"],))
    next_seq = c.fetchone()[0]
    c.execute("""
        INSERT INTO beneficiaries
            (org_id, seq_num, full_name, id_number, phone, address,
             family_size, marital_status, gender, children_count,
             beneficiary_type, notes, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (row["requester_org_id"], next_seq,
          row["full_name"], row["id_number"], row["phone"], row["address"],
          row["family_size"], row["marital_status"], row["gender"],
          row["children_count"], row["beneficiary_type"], row["notes"], now))
    # حدّث حالة الطلب
    c.execute("""
        UPDATE beneficiary_share_requests
        SET status='approved', resolved_at=?
        WHERE id=?
    """, (now, req_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/notifications/<int:req_id>/reject", methods=["POST"])
@login_required
def notification_reject(req_id):
    if session.get("role") != "admin":
        return jsonify({"ok": False}), 403
    csrf = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
    if csrf != session.get("_csrf"):
        return jsonify({"ok": False}), 403
    org_id = session["org_id"]
    conn   = get_connection()
    c      = conn.cursor()
    from datetime import datetime as _dt
    c.execute("""
        UPDATE beneficiary_share_requests
        SET status='rejected', resolved_at=?
        WHERE id=? AND owner_org_id=? AND status='pending'
    """, (_dt.now().strftime("%Y-%m-%d %H:%M:%S"), req_id, org_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/notifications/unread_count")
@login_required
def notifications_unread_count():
    if session.get("role") != "admin":
        return jsonify({"count": 0})
    org_id = session["org_id"]
    conn   = get_connection()
    c      = conn.cursor()
    c.execute("""
        SELECT COUNT(*) FROM beneficiary_share_requests
        WHERE owner_org_id=? AND status='pending'
    """, (org_id,))
    count = c.fetchone()[0]
    conn.close()
    return jsonify({"count": count})


# ══════════════════════════════════════════
# الشبكة — التواصل بين المؤسسات
# ══════════════════════════════════════════

@app.route("/network")
@login_required
def network():
    if session.get("role") != "admin":
        flash("غير مصرّح", "danger")
        return redirect(url_for("dashboard"))
    org_id = session["org_id"]
    conn   = get_connection()
    c      = conn.cursor()
    # جميع المؤسسات ما عدا المؤسسة الحالية
    c.execute("SELECT id, name FROM organizations WHERE id != ? ORDER BY name", (org_id,))
    orgs = c.fetchall()
    # عدد الرسائل غير المقروءة لكل مؤسسة
    unread = {}
    for org in orgs:
        c.execute("""
            SELECT COUNT(*) FROM org_messages
            WHERE to_org_id=? AND from_org_id=?
              AND id > COALESCE(
                (SELECT last_msg_id FROM org_message_reads
                 WHERE user_id=? AND partner_org=?), 0)
        """, (org_id, org["id"], session["user_id"], org["id"]))
        unread[org["id"]] = c.fetchone()[0]
    conn.close()
    return render_template("network.html", orgs=orgs, unread=unread)


@app.route("/network/chat/<int:partner_id>")
@login_required
def network_chat(partner_id):
    if session.get("role") != "admin":
        flash("غير مصرّح", "danger")
        return redirect(url_for("dashboard"))
    org_id  = session["org_id"]
    user_id = session["user_id"]
    conn    = get_connection()
    c       = conn.cursor()
    c.execute("SELECT id, name FROM organizations WHERE id=?", (partner_id,))
    partner = c.fetchone()
    if not partner:
        conn.close()
        flash("المؤسسة غير موجودة", "danger")
        return redirect(url_for("network"))
    # جلب الرسائل بين المؤسستين
    c.execute("""
        SELECT * FROM org_messages
        WHERE (from_org_id=? AND to_org_id=?)
           OR (from_org_id=? AND to_org_id=?)
        ORDER BY id ASC LIMIT 200
    """, (org_id, partner_id, partner_id, org_id))
    messages = c.fetchall()
    # تحديث آخر قراءة
    if messages:
        last_id = messages[-1]["id"]
        c.execute("""
            INSERT INTO org_message_reads(user_id, partner_org, last_msg_id)
            VALUES(?,?,?)
            ON CONFLICT(user_id, partner_org)
            DO UPDATE SET last_msg_id=excluded.last_msg_id
        """, (user_id, partner_id, last_id))
        conn.commit()
    conn.close()
    return render_template("network_chat.html",
                           partner=partner, messages=messages,
                           my_org_id=org_id)


@app.route("/network/send/<int:partner_id>", methods=["POST"])
@login_required
def network_send(partner_id):
    if session.get("role") != "admin":
        return jsonify({"ok": False}), 403
    org_id  = session["org_id"]
    user_id = session["user_id"]
    name    = session.get("name", "")
    content = request.form.get("content", "").strip()
    if not content:
        return jsonify({"ok": False, "msg": "الرسالة فارغة"}), 400
    csrf = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
    if csrf != session.get("_csrf"):
        return jsonify({"ok": False}), 403
    conn = get_connection()
    c    = conn.cursor()
    # تحقق أن المؤسسة موجودة
    c.execute("SELECT id FROM organizations WHERE id=?", (partner_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({"ok": False, "msg": "مؤسسة غير موجودة"}), 404
    from datetime import datetime as _dt
    now = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO org_messages(from_org_id, to_org_id, sender_id, sender_name, content, created_at)
        VALUES(?,?,?,?,?,?)
    """, (org_id, partner_id, user_id, name, content, now))
    new_id = c.lastrowid
    # تحديث آخر قراءة للمُرسِل
    c.execute("""
        INSERT INTO org_message_reads(user_id, partner_org, last_msg_id)
        VALUES(?,?,?)
        ON CONFLICT(user_id, partner_org)
        DO UPDATE SET last_msg_id=excluded.last_msg_id
    """, (user_id, partner_id, new_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "msg": {
        "id": new_id, "from_org_id": org_id,
        "sender_name": name, "content": content, "created_at": now
    }})


@app.route("/network/delete_msg/<int:msg_id>", methods=["POST"])
@login_required
def network_delete_msg(msg_id):
    if session.get("role") != "admin":
        return jsonify({"ok": False}), 403
    csrf = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
    if csrf != session.get("_csrf"):
        return jsonify({"ok": False}), 403
    org_id = session["org_id"]
    conn = get_connection()
    c    = conn.cursor()
    # يسمح فقط لمن أرسل الرسالة (من مؤسسته)
    c.execute("SELECT from_org_id FROM org_messages WHERE id=?", (msg_id,))
    row = c.fetchone()
    if not row or row["from_org_id"] != org_id:
        conn.close()
        return jsonify({"ok": False, "msg": "غير مصرّح"}), 403
    c.execute("DELETE FROM org_messages WHERE id=?", (msg_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/network/clear/<int:partner_id>", methods=["POST"])
@login_required
def network_clear(partner_id):
    if session.get("role") != "admin":
        return jsonify({"ok": False}), 403
    csrf = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
    if csrf != session.get("_csrf"):
        return jsonify({"ok": False}), 403
    org_id = session["org_id"]
    conn = get_connection()
    c    = conn.cursor()
    # يحذف كل رسائل المحادثة من الطرفين
    c.execute("""
        DELETE FROM org_messages
        WHERE (from_org_id=? AND to_org_id=?)
           OR (from_org_id=? AND to_org_id=?)
    """, (org_id, partner_id, partner_id, org_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/network/poll/<int:partner_id>")
@login_required
def network_poll(partner_id):
    if session.get("role") != "admin":
        return jsonify({"ok": False}), 403
    org_id  = session["org_id"]
    user_id = session["user_id"]
    since   = int(request.args.get("since", 0))
    conn    = get_connection()
    c       = conn.cursor()
    c.execute("""
        SELECT * FROM org_messages
        WHERE ((from_org_id=? AND to_org_id=?) OR (from_org_id=? AND to_org_id=?))
          AND id > ?
        ORDER BY id ASC
    """, (org_id, partner_id, partner_id, org_id, since))
    rows = c.fetchall()
    if rows:
        c.execute("""
            INSERT INTO org_message_reads(user_id, partner_org, last_msg_id)
            VALUES(?,?,?)
            ON CONFLICT(user_id, partner_org)
            DO UPDATE SET last_msg_id=excluded.last_msg_id
        """, (user_id, partner_id, rows[-1]["id"]))
        conn.commit()
    conn.close()
    return jsonify({"ok": True, "messages": [dict(r) for r in rows]})


@app.route("/network/unread")
@login_required
def network_unread():
    if session.get("role") != "admin":
        return jsonify({"count": 0})
    org_id  = session["org_id"]
    user_id = session["user_id"]
    conn    = get_connection()
    c       = conn.cursor()
    c.execute("""
        SELECT COUNT(*) FROM org_messages m
        WHERE m.to_org_id = ?
          AND m.id > COALESCE(
            (SELECT last_msg_id FROM org_message_reads
             WHERE user_id=? AND partner_org=m.from_org_id), 0)
    """, (org_id, user_id))
    count = c.fetchone()[0]
    conn.close()
    return jsonify({"count": count})


# ══════════════════════════════════════════
# التقارير
# ══════════════════════════════════════════

@app.route("/ai_reports")
@login_required
def ai_reports():
    if session.get("role") not in ("admin", "observer"):
        flash("غير مصرّح", "danger")
        return redirect(url_for("dashboard"))
    return render_template("ai_reports.html")


@app.route("/ai_reports/generate", methods=["POST"])
@login_required
def ai_reports_generate():
    if session.get("role") not in ("admin", "observer"):
        return jsonify({"ok": False}), 403

    import io
    from datetime import datetime as _dt

    rtype  = request.form.get("rtype", "").strip()
    fmt    = request.form.get("fmt", "docx").strip()
    org_id = session["org_id"]
    lang   = session.get("lang", "ar")

    valid_types = ("purchases","outgoing","beneficiaries","workers","programs","stock","summary")
    if rtype not in valid_types:
        return jsonify({"ok": False, "msg": "نوع التقرير غير صالح"}), 400

    conn = get_connection()
    c    = conn.cursor()

    c.execute("SELECT name FROM organizations WHERE id=?", (org_id,))
    row_org  = c.fetchone()
    org_name = row_org["name"] if row_org else ""

    data = {}

    if rtype in ("purchases", "summary"):
        c.execute("""
            SELECT ii.seq_num, ii.invoice_number, ii.supplier, ii.invoice_date,
                   ii.is_closed, ii.is_paid,
                   COALESCE(SUM(iii.total_price),0) AS total
            FROM incoming_invoices ii
            LEFT JOIN incoming_invoice_items iii ON iii.invoice_id=ii.id
            WHERE ii.org_id=? GROUP BY ii.id ORDER BY ii.id
        """, (org_id,))
        data["purchases"] = c.fetchall()

    if rtype in ("outgoing", "summary"):
        c.execute("""
            SELECT oi.invoice_number, oi.invoice_date, oi.beneficiary, oi.is_closed,
                   COALESCE(SUM(oii.total_price),0) AS total
            FROM outgoing_invoices oi
            LEFT JOIN outgoing_invoice_items oii ON oii.invoice_id=oi.id
            WHERE oi.org_id=? GROUP BY oi.id ORDER BY oi.id
        """, (org_id,))
        data["outgoing"] = c.fetchall()

    if rtype in ("beneficiaries", "summary"):
        c.execute("""
            SELECT full_name, gender, id_number, phone,
                   marital_status, family_size, children_count,
                   beneficiary_type, notes
            FROM beneficiaries WHERE org_id=? ORDER BY id
        """, (org_id,))
        data["beneficiaries"] = c.fetchall()

    if rtype in ("workers", "summary"):
        c.execute("""
            SELECT full_name, id_number, project_name, job_type,
                   monthly_salary, notes
            FROM workers WHERE org_id=? ORDER BY id
        """, (org_id,))
        data["workers"] = c.fetchall()

    if rtype in ("programs", "summary"):
        c.execute("SELECT name FROM programs WHERE org_id=? ORDER BY id", (org_id,))
        data["programs"] = c.fetchall()

    if rtype in ("stock", "summary"):
        c.execute("""
            SELECT p.name, p.unit,
                   COALESCE(SUM(sb.quantity_remaining),0) AS qty
            FROM products p
            LEFT JOIN stock_batches sb ON sb.product_id=p.id AND sb.org_id=p.org_id
            WHERE p.org_id=? GROUP BY p.id ORDER BY p.name
        """, (org_id,))
        data["stock"] = c.fetchall()

    conn.close()

    T = {
        "ar": dict(title_purchases="تقرير المشتريات", title_outgoing="تقرير الصرف",
                   title_beneficiaries="تقرير المستفيدين", title_workers="تقرير العاملين",
                   title_programs="تقرير البرامج", title_stock="تقرير المخزون",
                   title_summary="التقرير الشامل",
                   no_data="لا توجد بيانات", total="الإجمالي", count="العدد الكلي",
                   open_="مفتوحة", closed="مغلقة", paid="مدفوعة", unpaid="غير مدفوعة",
                   h_purchases="فواتير المشتريات", h_outgoing="فواتير الصرف",
                   h_beneficiaries="المستفيدون", h_workers="العاملون",
                   h_programs="البرامج والمشاريع", h_stock="المخزون"),
        "tr": dict(title_purchases="Satın Alma Raporu", title_outgoing="Çıkış Faturaları Raporu",
                   title_beneficiaries="Yararlanıcılar Raporu", title_workers="Çalışanlar Raporu",
                   title_programs="Programlar Raporu", title_stock="Stok Raporu",
                   title_summary="Genel Özet Raporu",
                   no_data="Veri yok", total="Toplam", count="Toplam Sayı",
                   open_="Açık", closed="Kapalı", paid="Ödendi", unpaid="Ödenmedi",
                   h_purchases="Satın Alma Faturaları", h_outgoing="Çıkış Faturaları",
                   h_beneficiaries="Yararlanıcılar", h_workers="Çalışanlar",
                   h_programs="Programlar ve Projeler", h_stock="Stok"),
        "en": dict(title_purchases="Purchase Invoices Report", title_outgoing="Outgoing Report",
                   title_beneficiaries="Beneficiaries Report", title_workers="Workers Report",
                   title_programs="Programs Report", title_stock="Stock Report",
                   title_summary="Full Summary Report",
                   no_data="No data", total="Total", count="Total Count",
                   open_="Open", closed="Closed", paid="Paid", unpaid="Unpaid",
                   h_purchases="Purchase Invoices", h_outgoing="Outgoing Invoices",
                   h_beneficiaries="Beneficiaries", h_workers="Workers",
                   h_programs="Programs & Projects", h_stock="Stock"),
    }
    tx       = T.get(lang, T["ar"])
    title    = tx.get(f"title_{rtype}", "Report")
    now_str  = _dt.now().strftime("%Y-%m-%d %H:%M")
    is_rtl   = (lang == "ar")

    # ─────────────────────────────────────────
    # PDF — HTML يُفتح في نافذة ويُطبع
    # ─────────────────────────────────────────
    if fmt == "pdf":
        dir_attr = "rtl" if is_rtl else "ltr"
        th_align = "right" if is_rtl else "left"

        def _tbl(headers, rows, fn):
            if not rows:
                return f"<p class='nd'>{tx['no_data']}</p>"
            ths = "".join(f"<th>{h}</th>" for h in headers)
            trs = ""
            for r in rows:
                vals = fn(r)
                trs += "<tr>" + "".join(
                    f"<td>{str(v) if v is not None else ''}</td>" for v in vals
                ) + "</tr>"
            return f"<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>"

        body = ""

        if "purchases" in data:
            h = {"ar":["#","رقم الفاتورة","المورد","التاريخ","الإجمالي","الحالة","الدفع"],
                 "tr":["#","Fatura No","Tedarikçi","Tarih","Toplam","Durum","Ödeme"],
                 "en":["#","Invoice No","Supplier","Date","Total","Status","Payment"]}.get(lang,[])
            rows = data["purchases"]
            body += f"<h2>{tx['h_purchases']}</h2>"
            body += _tbl(h, rows, lambda r:[
                r["seq_num"] or"", r["invoice_number"] or"", r["supplier"] or"",
                r["invoice_date"] or"", f"{r['total']:.2f}",
                tx["closed"] if r["is_closed"] else tx["open_"],
                tx["paid"] if r["is_paid"] else tx["unpaid"]])
            body += f"<p class='sm'>{tx['total']}: {sum(r['total'] for r in rows):.2f}</p>"

        if "outgoing" in data:
            h = {"ar":["رقم الفاتورة","التاريخ","الجهة","الإجمالي","الحالة"],
                 "tr":["Fatura No","Tarih","Kurum","Toplam","Durum"],
                 "en":["Invoice No","Date","Beneficiary","Total","Status"]}.get(lang,[])
            rows = data["outgoing"]
            body += f"<h2>{tx['h_outgoing']}</h2>"
            body += _tbl(h, rows, lambda r:[
                r["invoice_number"] or"", r["invoice_date"] or"",
                r["beneficiary"] or"", f"{r['total']:.2f}",
                tx["closed"] if r["is_closed"] else tx["open_"]])
            body += f"<p class='sm'>{tx['total']}: {sum(r['total'] for r in rows):.2f}</p>"

        if "beneficiaries" in data:
            h = {"ar":["الاسم","الجنس","رقم الهوية","الجوال","الحالة","عدد الأفراد","النوع"],
                 "tr":["Ad Soyad","Cinsiyet","Kimlik","Telefon","Durum","Üye Sayısı","Tür"],
                 "en":["Name","Gender","ID","Phone","Status","Family Size","Type"]}.get(lang,[])
            rows = data["beneficiaries"]
            body += f"<h2>{tx['h_beneficiaries']}</h2>"
            body += _tbl(h, rows, lambda r:[
                r["full_name"] or"", r["gender"] or"", r["id_number"] or"",
                r["phone"] or"", r["marital_status"] or"",
                str(r["family_size"] or""), r["beneficiary_type"] or""])
            body += f"<p class='sm'>{tx['count']}: {len(rows)}</p>"

        if "workers" in data:
            h = {"ar":["الاسم","رقم الهوية","المشروع","طبيعة العمل","المكافأة","ملاحظات"],
                 "tr":["Ad","Kimlik","Proje","Görev","Maaş","Notlar"],
                 "en":["Name","ID","Project","Role","Salary","Notes"]}.get(lang,[])
            rows = data["workers"]
            body += f"<h2>{tx['h_workers']}</h2>"
            body += _tbl(h, rows, lambda r:[
                r["full_name"] or"", r["id_number"] or"", r["project_name"] or"",
                r["job_type"] or"",
                f"{r['monthly_salary']:.2f}" if r["monthly_salary"] else "0.00",
                r["notes"] or""])
            body += f"<p class='sm'>{tx['total']}: {sum((r['monthly_salary'] or 0) for r in rows):.2f}</p>"

        if "programs" in data:
            rows = data["programs"]
            body += f"<h2>{tx['h_programs']}</h2><ol>"
            for r in rows:
                body += f"<li>{r['name']}</li>"
            body += "</ol>"

        if "stock" in data:
            h = {"ar":["الصنف","الوحدة","الكمية المتاحة"],
                 "tr":["Ürün","Birim","Mevcut Miktar"],
                 "en":["Item","Unit","Available Qty"]}.get(lang,[])
            rows = data["stock"]
            body += f"<h2>{tx['h_stock']}</h2>"
            body += _tbl(h, rows, lambda r:[r["name"] or"", r["unit"] or"", f"{r['qty']:.2f}"])

        # ── بناء HTML للـ PDF ──
        dir_attr = "rtl" if is_rtl else "ltr"
        th_align = "right" if is_rtl else "left"
        sum_align = "left" if is_rtl else "right"
        ol_pad   = "right" if is_rtl else "left"

        def _tbl(headers, rows, fn):
            if not rows:
                return "<p class='nd'>" + tx["no_data"] + "</p>"
            ths = "".join("<th>" + str(h) + "</th>" for h in headers)
            trs = ""
            for r in rows:
                vals = fn(r)
                trs += "<tr>" + "".join(
                    "<td>" + (str(v) if v is not None else "") + "</td>" for v in vals
                ) + "</tr>"
            return "<table><thead><tr>" + ths + "</tr></thead><tbody>" + trs + "</tbody></table>"

        body = ""

        if "purchases" in data:
            h = {"ar":["#","رقم الفاتورة","المورد","التاريخ","الإجمالي","الحالة","الدفع"],
                 "tr":["#","Fatura No","Tedarikçi","Tarih","Toplam","Durum","Ödeme"],
                 "en":["#","Invoice No","Supplier","Date","Total","Status","Payment"]}.get(lang,[])
            rows = data["purchases"]
            body += "<h2>" + tx["h_purchases"] + "</h2>"
            body += _tbl(h, rows, lambda r:[
                r["seq_num"] or "", r["invoice_number"] or "", r["supplier"] or "",
                r["invoice_date"] or "", "%.2f" % r["total"],
                tx["closed"] if r["is_closed"] else tx["open_"],
                tx["paid"] if r["is_paid"] else tx["unpaid"]])
            body += "<p class='sm'>" + tx["total"] + ": " + ("%.2f" % sum(r["total"] for r in rows)) + "</p>"

        if "outgoing" in data:
            h = {"ar":["رقم الفاتورة","التاريخ","الجهة","الإجمالي","الحالة"],
                 "tr":["Fatura No","Tarih","Kurum","Toplam","Durum"],
                 "en":["Invoice No","Date","Beneficiary","Total","Status"]}.get(lang,[])
            rows = data["outgoing"]
            body += "<h2>" + tx["h_outgoing"] + "</h2>"
            body += _tbl(h, rows, lambda r:[
                r["invoice_number"] or "", r["invoice_date"] or "",
                r["beneficiary"] or "", "%.2f" % r["total"],
                tx["closed"] if r["is_closed"] else tx["open_"]])
            body += "<p class='sm'>" + tx["total"] + ": " + ("%.2f" % sum(r["total"] for r in rows)) + "</p>"

        if "beneficiaries" in data:
            h = {"ar":["الاسم","الجنس","رقم الهوية","الجوال","الحالة","عدد الأفراد","النوع"],
                 "tr":["Ad Soyad","Cinsiyet","Kimlik","Telefon","Durum","Üye Sayısı","Tür"],
                 "en":["Name","Gender","ID","Phone","Status","Family Size","Type"]}.get(lang,[])
            rows = data["beneficiaries"]
            body += "<h2>" + tx["h_beneficiaries"] + "</h2>"
            body += _tbl(h, rows, lambda r:[
                r["full_name"] or "", r["gender"] or "", r["id_number"] or "",
                r["phone"] or "", r["marital_status"] or "",
                str(r["family_size"] or ""), r["beneficiary_type"] or ""])
            body += "<p class='sm'>" + tx["count"] + ": " + str(len(rows)) + "</p>"

        if "workers" in data:
            h = {"ar":["الاسم","رقم الهوية","المشروع","طبيعة العمل","المكافأة","ملاحظات"],
                 "tr":["Ad","Kimlik","Proje","Görev","Maaş","Notlar"],
                 "en":["Name","ID","Project","Role","Salary","Notes"]}.get(lang,[])
            rows = data["workers"]
            body += "<h2>" + tx["h_workers"] + "</h2>"
            body += _tbl(h, rows, lambda r:[
                r["full_name"] or "", r["id_number"] or "", r["project_name"] or "",
                r["job_type"] or "",
                ("%.2f" % r["monthly_salary"]) if r["monthly_salary"] else "0.00",
                r["notes"] or ""])
            body += "<p class='sm'>" + tx["total"] + ": " + ("%.2f" % sum((r["monthly_salary"] or 0) for r in rows)) + "</p>"

        if "programs" in data:
            rows = data["programs"]
            body += "<h2>" + tx["h_programs"] + "</h2><ol>"
            for r in rows:
                body += "<li>" + r["name"] + "</li>"
            body += "</ol>"

        if "stock" in data:
            h = {"ar":["الصنف","الوحدة","الكمية المتاحة"],
                 "tr":["Ürün","Birim","Mevcut Miktar"],
                 "en":["Item","Unit","Available Qty"]}.get(lang,[])
            rows = data["stock"]
            body += "<h2>" + tx["h_stock"] + "</h2>"
            body += _tbl(h, rows, lambda r:[r["name"] or "", r["unit"] or "", "%.2f" % r["qty"]])

        css = (
            "*{box-sizing:border-box;margin:0;padding:0}"
            "body{font-family:Arial,sans-serif;font-size:12px;color:#222;padding:20px;direction:" + dir_attr + "}"
            "h1{text-align:center;color:#1a6b3a;font-size:17px;border-bottom:2px solid #1a6b3a;padding-bottom:6px;margin-bottom:4px}"
            ".meta{text-align:center;color:#888;font-size:10px;margin-bottom:18px}"
            "h2{color:#1565c0;font-size:13px;margin:18px 0 6px}"
            "table{width:100%;border-collapse:collapse;margin-bottom:8px;font-size:11px}"
            "th{background:#1a6b3a;color:#fff;padding:5px 8px;text-align:" + th_align + "}"
            "td{border:1px solid #ccc;padding:4px 8px}"
            "tr:nth-child(even) td{background:#f5f5f5}"
            ".sm{font-weight:bold;color:#c62828;margin:4px 0 14px;text-align:" + sum_align + ";font-size:11px}"
            ".nd{color:#888;font-size:11px;margin:6px 0 14px}"
            "ol{padding-" + ol_pad + ":20px;margin-bottom:14px}"
            "@media print{body{padding:10px}}"
        )
        html = (
            '<!DOCTYPE html><html lang="' + lang + '" dir="' + dir_attr + '">'
            '<head><meta charset="UTF-8"><title>' + title + '</title>'
            '<style>' + css + '</style></head>'
            '<body>'
            '<h1>' + org_name + ' — ' + title + '</h1>'
            '<div class="meta">' + now_str + '</div>'
            + body +
            '<script>window.onload=function(){window.print();}</script>'
            '</body></html>'
        )
        from flask import Response
        return Response(html, mimetype="text/html; charset=utf-8")

    # ─────────────────────────────────────────
    # Word — python-docx
    # ─────────────────────────────────────────
    try:
        from docx import Document
        from docx.shared import Pt, Cm
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from flask import send_file
    except ImportError as e:
        return jsonify({"ok": False, "msg": "python-docx missing: " + str(e)}), 500

    doc = Document()
    for sec in doc.sections:
        sec.top_margin = sec.bottom_margin = Cm(1.5)
        sec.left_margin = sec.right_margin = Cm(2)

    h0 = doc.add_heading(org_name + " — " + title, 0)
    h0.alignment = WD_ALIGN_PARAGRAPH.CENTER
    mp = doc.add_paragraph(now_str)
    mp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph()

    def _wtbl(sec_title, headers, rows, fn, footer=""):
        doc.add_heading(sec_title, 1)
        if not rows:
            doc.add_paragraph(tx["no_data"])
            doc.add_paragraph()
            return
        tbl = doc.add_table(rows=1, cols=len(headers))
        tbl.style = "Table Grid"
        for i, h in enumerate(headers):
            cell = tbl.rows[0].cells[i]
            cell.paragraphs[0].clear()
            run = cell.paragraphs[0].add_run(h)
            run.bold = True
            run.font.size = Pt(10)
        for row in rows:
            nr = tbl.add_row()
            for i, v in enumerate(fn(row)):
                nr.cells[i].text = str(v) if v is not None else ""
        if footer:
            doc.add_paragraph(footer)
        doc.add_paragraph()

    if "purchases" in data:
        h = {"ar":["#","رقم الفاتورة","المورد","التاريخ","الإجمالي","الحالة","الدفع"],
             "tr":["#","Fatura No","Tedarikçi","Tarih","Toplam","Durum","Ödeme"],
             "en":["#","Invoice No","Supplier","Date","Total","Status","Payment"]}.get(lang,[])
        rows = data["purchases"]
        _wtbl(tx["h_purchases"], h, rows,
              lambda r:[str(r["seq_num"] or ""), r["invoice_number"] or "", r["supplier"] or "",
                        r["invoice_date"] or "", "%.2f" % r["grand_total"],
                        tx["closed"] if r["is_closed"] else tx["open_"],
                        tx["paid"] if r["is_paid"] else tx["unpaid"]],
              tx["total"] + ": " + ("%.2f" % sum(r["grand_total"] for r in rows)))

    if "outgoing" in data:
        h = {"ar":["رقم الفاتورة","التاريخ","الجهة","الإجمالي","الحالة"],
             "tr":["Fatura No","Tarih","Kurum","Toplam","Durum"],
             "en":["Invoice No","Date","Beneficiary","Total","Status"]}.get(lang,[])
        rows = data["outgoing"]
        _wtbl(tx["h_outgoing"], h, rows,
              lambda r:[r["invoice_number"] or "", r["invoice_date"] or "",
                        r["beneficiary"] or "", "%.2f" % r["total"],
                        tx["closed"] if r["is_closed"] else tx["open_"]],
              tx["total"] + ": " + ("%.2f" % sum(r["total"] for r in rows)))

    if "beneficiaries" in data:
        h = {"ar":["الاسم","الجنس","رقم الهوية","الجوال","الحالة","عدد الأفراد","النوع"],
             "tr":["Ad Soyad","Cinsiyet","Kimlik","Telefon","Durum","Üye Sayısı","Tür"],
             "en":["Name","Gender","ID","Phone","Status","Family Size","Type"]}.get(lang,[])
        rows = data["beneficiaries"]
        _wtbl(tx["h_beneficiaries"], h, rows,
              lambda r:[r["full_name"] or "", r["id_number"] or "", r["gender"] or "",
                        r["phone"] or "", r["marital_status"] or "",
                        str(r["family_size"] or ""), r["beneficiary_type"] or ""],
              tx["count"] + ": " + str(len(rows)))

    if "workers" in data:
        h = {"ar":["الاسم","رقم الهوية","المشروع","طبيعة العمل","المكافأة","ملاحظات"],
             "tr":["Ad","Kimlik","Proje","Görev","Maaş","Notlar"],
             "en":["Name","ID","Project","Role","Salary","Notes"]}.get(lang,[])
        rows = data["workers"]
        _wtbl(tx["h_workers"], h, rows,
              lambda r:[r["full_name"] or "", r["id_number"] or "", r["project_name"] or "",
                        r["job_type"] or "",
                        ("%.2f" % r["monthly_salary"]) if r["monthly_salary"] else "0.00",
                        r["notes"] or ""],
              tx["total"] + ": " + ("%.2f" % sum((r["monthly_salary"] or 0) for r in rows)))

    if "programs" in data:
        rows = data["programs"]
        doc.add_heading(tx["h_programs"], 1)
        for i, row in enumerate(rows, 1):
            doc.add_paragraph(str(i) + ". " + row["name"])
        doc.add_paragraph()

    if "stock" in data:
        h = {"ar":["الصنف","الوحدة","الكمية المتاحة"],
             "tr":["Ürün","Birim","Mevcut Miktar"],
             "en":["Item","Unit","Available Qty"]}.get(lang,[])
        rows = data["stock"]
        _wtbl(tx["h_stock"], h, rows,
              lambda r:[r["name"] or "", r["unit"] or "", "%.2f" % r["qty"]])

    import io as _io
    buf = _io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    fname = "report_" + rtype + "_" + _dt.now().strftime("%Y%m%d_%H%M") + ".docx"
    return send_file(buf, as_attachment=True, download_name=fname,
                     mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


# ══════════════════════════════════════════
# SUPER ADMIN CONTROL PANEL — /om-sys-77k
# ══════════════════════════════════════════
import hashlib as _hl

_SA_USER = "MALIK_OM_HS"
_SA_HASH = "ee12cd56811902adecf1b27eaf126201ec8e27f6a575b7510d9a9bff323cccd9"
_SA_SALT = "MK_OM_SALT_7x9k2"
_SA_MAX_TRIES = 5

def _sa_check(pwd):
    return _hl.sha256((_SA_SALT + pwd).encode()).hexdigest() == _SA_HASH

def _sa_required(f):
    from functools import wraps
    @wraps(f)
    def dec(*a, **kw):
        if not session.get('_sa_auth'):
            return redirect('/om-sys-77k')
        return f(*a, **kw)
    return dec

def _sa_csrf():
    return validate_csrf()

@app.route('/om-sys-77k', methods=['GET','POST'])
def superadmin_login():
    # حماية: منع brute-force
    tries = session.get('_sa_tries', 0)
    locked = tries >= _SA_MAX_TRIES
    show_login = False
    error = ''

    if request.method == 'POST':
        show_login = True
        if locked:
            error = 'Too many attempts.'
        elif not _sa_csrf():
            error = 'Invalid request.'
        else:
            u = request.form.get('su_user','').strip()
            p = request.form.get('su_pass','')
            if u == _SA_USER and _sa_check(p):
                session['_sa_auth'] = True
                session['_sa_tries'] = 0
                return redirect('/om-sys-77k/dash')
            else:
                session['_sa_tries'] = tries + 1
                error = 'Invalid credentials.'

    if session.get('_sa_auth'):
        return redirect('/om-sys-77k/dash')

    return render_template('superadmin.html',
        error=error, locked=locked,
        show_login=show_login)

@app.route('/om-sys-77k/logout')
def superadmin_logout():
    session.pop('_sa_auth', None)
    return redirect('/om-sys-77k')

@app.route('/om-sys-77k/dash')
@_sa_required
def superadmin_dash():
    c = get_connection().cursor()
    c.execute("""
        SELECT o.*, COUNT(u.id) as user_count
        FROM organizations o
        LEFT JOIN users u ON u.org_id = o.id
        GROUP BY o.id ORDER BY o.created_at DESC
    """)
    orgs = c.fetchall()
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    return render_template('superadmin_dash.html',
        orgs=orgs, total_users=total_users)

@app.route('/om-sys-77k/suspend/<int:org_id>', methods=['POST'])
@_sa_required
def sa_suspend(org_id):
    if not _sa_csrf(): return redirect('/om-sys-77k/dash')
    conn = get_connection()
    conn.execute("UPDATE organizations SET is_active=0 WHERE id=?", (org_id,))
    conn.commit()
    flash('تم إيقاف المؤسسة مؤقتاً', 'warning')
    return redirect('/om-sys-77k/dash')

@app.route('/om-sys-77k/activate/<int:org_id>', methods=['POST'])
@_sa_required
def sa_activate(org_id):
    if not _sa_csrf(): return redirect('/om-sys-77k/dash')
    conn = get_connection()
    conn.execute("UPDATE organizations SET is_active=1 WHERE id=?", (org_id,))
    conn.commit()
    flash('تم تفعيل المؤسسة', 'success')
    return redirect('/om-sys-77k/dash')

@app.route('/om-sys-77k/delete/<int:org_id>', methods=['POST'])
@_sa_required
def sa_delete_org(org_id):
    if not _sa_csrf(): return redirect('/om-sys-77k/dash')
    conn = get_connection()
    c = conn.cursor()
    # حذف كل البيانات المرتبطة بالمؤسسة
    for tbl in ['incoming_invoice_items','outgoing_invoice_items',
                'incoming_invoices','outgoing_invoices',
                'stock_batches','products','beneficiaries',
                'program_records','programs','workers',
                'messages','org_messages','beneficiary_share_requests','users']:
        try:
            c.execute(f"DELETE FROM {tbl} WHERE org_id=?", (org_id,))
        except Exception:
            pass
    c.execute("DELETE FROM organizations WHERE id=?", (org_id,))
    conn.commit()
    flash('تم حذف المؤسسة وجميع بياناتها', 'danger')
    return redirect('/om-sys-77k/dash')

@app.route('/om-sys-77k/notify/<int:org_id>', methods=['POST'])
@_sa_required
def sa_notify_org(org_id):
    if not _sa_csrf(): return redirect('/om-sys-77k/dash')
    title = request.form.get('title','').strip()
    body  = request.form.get('body','').strip()
    if not title or not body:
        flash('الرجاء إدخال العنوان والنص', 'danger')
        return redirect('/om-sys-77k/dash')
    conn = get_connection()
    conn.execute("""
        INSERT INTO sys_notifications (org_id, title, body, created_at)
        VALUES (?, ?, ?, datetime('now','localtime'))
    """, (org_id, title, body))
    conn.commit()
    flash('تم إرسال الإشعار للمؤسسة', 'success')
    return redirect('/om-sys-77k/dash')

@app.route('/om-sys-77k/notify_all', methods=['POST'])
@_sa_required
def sa_notify_all():
    if not _sa_csrf(): return redirect('/om-sys-77k/dash')
    title = request.form.get('title','').strip()
    body  = request.form.get('body','').strip()
    if not title or not body:
        flash('الرجاء إدخال العنوان والنص', 'danger')
        return redirect('/om-sys-77k/dash')
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM organizations WHERE is_active=1")
    for row in c.fetchall():
        conn.execute("""
            INSERT INTO sys_notifications (org_id, title, body, created_at)
            VALUES (?, ?, ?, datetime('now','localtime'))
        """, (row[0], title, body))
    conn.commit()
    flash('تم إرسال الإشعار لجميع المؤسسات', 'success')
    return redirect('/om-sys-77k/dash')





@app.route("/sys_notifications/<int:nid>/delete", methods=["POST"])
@login_required
def sys_notif_delete(nid):
    if not validate_csrf(): return redirect("/sys_notifications")
    org_id = session["org_id"]
    conn = get_connection()
    conn.execute("DELETE FROM sys_notifications WHERE id=? AND (org_id=? OR org_id IS NULL)", (nid, org_id))
    conn.commit()
    conn.close()
    return redirect("/sys_notifications")

@app.route("/sys_notifications/clear_all", methods=["POST"])
@login_required
def sys_notif_clear_all():
    if not validate_csrf(): return redirect("/sys_notifications")
    org_id = session["org_id"]
    conn = get_connection()
    conn.execute("DELETE FROM sys_notifications WHERE org_id=? OR org_id IS NULL", (org_id,))
    conn.commit()
    conn.close()
    return redirect("/sys_notifications")

@app.route("/sys_notifications")
@login_required
def sys_notifications_page():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT id, title, body, is_read, created_at
        FROM sys_notifications
        WHERE org_id=? OR org_id IS NULL
        ORDER BY created_at DESC
    """, (org_id,))
    notifs = [dict(r) for r in c.fetchall()]
    # علّم كلها مقروءة
    conn.execute("UPDATE sys_notifications SET is_read=1 WHERE (org_id=? OR org_id IS NULL) AND is_read=0", (org_id,))
    conn.commit()
    conn.close()
    return render_template("sys_notifications.html", notifs=notifs)

@app.route("/api/sys_notif_count")
@login_required
def api_sys_notif_count():
    org_id = session["org_id"]
    c = get_connection().cursor()
    c.execute("SELECT COUNT(*) FROM sys_notifications WHERE (org_id=? OR org_id IS NULL) AND is_read=0", (org_id,))
    return jsonify({"count": c.fetchone()[0]})


if __name__ == "__main__":
    app.run(debug=True)
