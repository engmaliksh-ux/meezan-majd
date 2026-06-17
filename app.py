import os
import secrets
import struct
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from database import get_connection, init_db, generate_org_code
from translations import TRANSLATIONS
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from email_service import generate_verification_code, send_org_verification, send_staff_notification
from datetime import datetime, timedelta

app = Flask(__name__)

# ══════════════════════════════════════════
# 1. Secret Key من البيئة (لا تضعها في الكود أبداً)
#    في PythonAnywhere: Web → Environment variables → SECRET_KEY
#    قيمة عشوائية مثال: python3 -c "import secrets; print(secrets.token_hex(32))"
# ══════════════════════════════════════════
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# ══════════════════════════════════════════
# 2. إعدادات Session الآمنة
# ══════════════════════════════════════════
app.config["SESSION_COOKIE_HTTPONLY"]  = True   # لا يصل JavaScript للـ cookie
app.config["SESSION_COOKIE_SAMESITE"]  = "Lax"  # حماية CSRF جزئية
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
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

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

# ══════════════════════════════════════════
# Language support — AR / TR
# ══════════════════════════════════════════
@app.route("/set_lang/<lang>")
def set_lang(lang):
    if lang in ('ar', 'tr'):
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
        elif len(password) < 4:
            error = "كلمة المرور يجب أن تكون 4 أحرف على الأقل"
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
        elif len(password) < 4:
            error = "كلمة المرور 4 أحرف على الأقل"
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
            elif len(new_pass) < 4:
                error = "كلمة المرور الجديدة يجب أن تكون 4 أحرف على الأقل"
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
    conn.close()
    return render_template("dashboard.html",
        products_count=products_count, total_stock=total_stock,
        beneficiaries_count=beneficiaries_count,
        incoming_count=incoming_count, outgoing_count=outgoing_count,
        pending_users=pending_users)


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
        elif len(password) < 4:
            error = "كلمة المرور 4 أحرف على الأقل"
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
            if len(new_password) < 4:
                flash("كلمة المرور 4 أحرف على الأقل", "danger")
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
@app.route("/incoming_invoice", methods=["GET", "POST"])
@invoices_view_required
def incoming_invoice():
    org_id = session["org_id"]
    conn = get_connection()
    c = conn.cursor()

    if request.method == "POST" and session.get("role") == "observer":
        flash("مراقب عام: لا تملك صلاحية الإضافة أو التعديل", "danger")
        return redirect(url_for("incoming_invoice"))

    if request.method == "POST":
        invoice_number  = request.form.get("invoice_number", "").strip()
        supplier        = request.form.get("supplier", "").strip()
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

        if not invoice_number or not supplier:
            flash("يرجى تعبئة رقم الفاتورة واسم المورد", "danger")
        elif not valid_items:
            flash("يرجى إضافة صنف واحد على الأقل ببيانات كاملة", "danger")
        else:
            invoice_image = None
            img_file = request.files.get("invoice_image")
            if img_file and img_file.filename and allowed_file(img_file.filename) and allowed_file_content(img_file):
                ext = img_file.filename.rsplit(".", 1)[1].lower()
                stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
                invoice_image = f"invoice_{org_id}_{stamp}.{ext}"
                img_file.save(os.path.join(app.config["UPLOAD_FOLDER"], invoice_image))

            c.execute(
                "INSERT INTO incoming_invoices (org_id, invoice_number, supplier, created_by, invoice_image) VALUES (?,?,?,?,?)",
                (org_id, invoice_number, supplier, session["user"], invoice_image)
            )
            invoice_id = c.lastrowid

            for pname, punit, qty, price, pdate in valid_items:
                try:
                    qty_f, price_f = float(qty), float(price)
                    # البحث عن الصنف أو إنشائه
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
            return redirect(url_for("incoming_invoice"))

    # --- جلب الأصناف الموجودة لاقتراح التسمية (autocomplete) ---
    c.execute("SELECT name, unit FROM products WHERE org_id=? ORDER BY name", (org_id,))
    existing_products = [dict(r) for r in c.fetchall()]

    # --- جلب كل الفواتير مع أصنافها لعرض الكشف الكامل ---
    c.execute("""
        SELECT id, invoice_number, supplier, is_closed, invoice_image, grand_total, created_at
        FROM incoming_invoices WHERE org_id=? ORDER BY id DESC
    """, (org_id,))
    invoices_rows = c.fetchall()

    invoices = []
    total_purchases = 0.0
    for inv in invoices_rows:
        inv_d = dict(inv)
        c.execute("""
            SELECT ii.quantity, ii.unit_price, ii.total_price, ii.purchase_date, p.name AS product_name
            FROM incoming_invoice_items ii
            JOIN products p ON p.id = ii.product_id
            WHERE ii.invoice_id=?
            ORDER BY ii.purchase_date, ii.id
        """, (inv["id"],))
        items = [dict(r) for r in c.fetchall()]
        inv_total = sum(it["total_price"] for it in items)
        inv_d["lines"] = items
        inv_d["total"] = inv_total
        total_purchases += inv_total
        invoices.append(inv_d)

    conn.close()
    today_str = datetime.now().strftime("%Y-%m-%d")
    return render_template("incoming_invoices.html", existing_products=existing_products,
        invoices=invoices, total_purchases=total_purchases, today_str=today_str)


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
        SELECT id, invoice_number, invoice_date, beneficiary, notes, created_by, created_at
        FROM outgoing_invoices WHERE org_id=? ORDER BY id DESC
    """, (org_id,))
    invoices_rows = c.fetchall()

    invoices = []
    total_all = 0.0
    for inv in invoices_rows:
        inv_d = dict(inv)
        c.execute("""
            SELECT oi.quantity, oi.unit_price, oi.total_price,
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

    conn.close()
    return render_template("outgoing_invoices_list.html",
                           invoices=invoices, total_all=total_all)


if __name__ == "__main__":
    app.run(debug=True)