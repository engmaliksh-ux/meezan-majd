import sqlite3
import random
import string
import os
import shutil
from datetime import datetime

DB_NAME    = "database.db"
BACKUP_DIR = "backups"
MAX_BACKUPS = 20   # الحد الأقصى للنسخ الاحتياطية المحفوظة

_last_auto_backup: datetime | None = None
AUTO_BACKUP_INTERVAL = 5  # دقائق — الحد الأدنى بين نسختين تلقائيتين


def smart_backup() -> str:
    """
    ينشئ نسخة احتياطية تلقائية عند كل تغيير في البيانات،
    مع ضمان عدم إنشاء أكثر من نسخة كل AUTO_BACKUP_INTERVAL دقائق.
    """
    global _last_auto_backup
    now = datetime.now()
    if _last_auto_backup and (now - _last_auto_backup).total_seconds() < AUTO_BACKUP_INTERVAL * 60:
        return ""  # انتظر الفترة المحددة
    _last_auto_backup = now
    try:
        return create_backup("change")
    except Exception:
        return ""


def _enable_wal_persistent():
    """تفعيل WAL mode بشكل دائم على ملف الـ DB (يُنفَّذ مرة واحدة فقط عند الإنشاء/الترحيل)."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA wal_autocheckpoint=100")
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=20000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _db_is_healthy() -> bool:
    """يتحقق من سلامة قاعدة البيانات."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=5)
        result = conn.execute("PRAGMA integrity_check").fetchone()
        conn.execute("SELECT COUNT(*) FROM beneficiaries")
        conn.close()
        return result and result[0] == "ok"
    except Exception:
        return False


def _safe_checkpoint():
    """يدمج ملف WAL في الداتابيز الرئيسية بأمان."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
    except Exception:
        pass


def auto_recover() -> str:
    """
    يُنفَّذ عند كل بداية للسيرفر:
    1. يحاول checkpoint لملف WAL (دمجه في الـ DB بدل حذفه)
    2. يتحقق من سلامة DB
    3. إذا فشل checkpoint يحذف ملفات الجورنال
    4. إذا كانت DB تالفة يستعيد أفضل نسخة احتياطية
    """
    # الخطوة 1: checkpoint آمن لدمج WAL (لا نحذفه مباشرة)
    _safe_checkpoint()

    if _db_is_healthy():
        return "DB_OK"

    # الخطوة 2: checkpoint فشل أو DB تالفة — احذف ملفات الجورنال
    for ext in ("-journal", "-wal", "-shm"):
        jfile = DB_NAME + ext
        if os.path.exists(jfile):
            try:
                os.remove(jfile)
            except Exception:
                pass

    if _db_is_healthy():
        return "DB_OK_AFTER_JOURNAL_DELETE"

    # الخطوة 3: DB تالفة — استعادة أفضل نسخة
    if not os.path.exists(BACKUP_DIR):
        return "DB_CORRUPT_NO_BACKUP"

    backups = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.endswith(".db")],
        key=lambda f: os.path.getsize(os.path.join(BACKUP_DIR, f)),
        reverse=True
    )

    for bk in backups:
        bk_path = os.path.join(BACKUP_DIR, bk)
        try:
            tc = sqlite3.connect(bk_path, timeout=5)
            r  = tc.execute("PRAGMA integrity_check").fetchone()
            tc.execute("SELECT COUNT(*) FROM beneficiaries")
            tc.close()
            if not (r and r[0] == "ok"):
                continue
            shutil.copy2(bk_path, DB_NAME)
            for ext in ("-journal", "-wal", "-shm"):
                jf = DB_NAME + ext
                if os.path.exists(jf):
                    try: os.remove(jf)
                    except: pass
            return f"DB_RESTORED_FROM:{bk}"
        except Exception:
            continue

    return "DB_CORRUPT_ALL_BACKUPS_FAILED"


def create_backup(label: str = "auto") -> str:
    """
    ينشئ نسخة احتياطية من قاعدة البيانات.
    يُرجع اسم الملف المنشأ.
    """
    if not os.path.exists(DB_NAME):
        return ""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"db_{label}_{ts}.db"
    dst      = os.path.join(BACKUP_DIR, filename)
    # نسخ آمن عبر SQLite API
    src_conn = sqlite3.connect(DB_NAME)
    dst_conn = sqlite3.connect(dst)
    src_conn.backup(dst_conn)
    dst_conn.close()
    src_conn.close()
    _prune_backups()
    return filename


def _prune_backups():
    """يحذف النسخ القديمة ويبقي آخر MAX_BACKUPS نسخة."""
    if not os.path.exists(BACKUP_DIR):
        return
    files = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.endswith(".db")],
        reverse=True
    )
    for old in files[MAX_BACKUPS:]:
        try:
            os.remove(os.path.join(BACKUP_DIR, old))
        except Exception:
            pass


def list_backups():
    """يُرجع قائمة النسخ الاحتياطية مرتبة من الأحدث."""
    if not os.path.exists(BACKUP_DIR):
        return []
    files = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.endswith(".db")],
        reverse=True
    )
    result = []
    for f in files:
        path = os.path.join(BACKUP_DIR, f)
        size_kb = round(os.path.getsize(path) / 1024, 1)
        mtime   = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
        result.append({"filename": f, "size_kb": size_kb, "created_at": mtime})
    return result


def restore_backup(filename: str) -> bool:
    """يستعيد نسخة احتياطية. يُرجع True إذا نجح."""
    src = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(src) or ".." in filename or "/" in filename:
        return False
    # نسخة احتياطية قبل الاستعادة
    if os.path.exists(DB_NAME):
        create_backup("pre_restore")
    dst_conn = sqlite3.connect(DB_NAME)
    src_conn = sqlite3.connect(src)
    src_conn.backup(dst_conn)
    dst_conn.close()
    src_conn.close()
    return True


def generate_org_code():
    """ينشئ رمزاً فريداً للمؤسسة مثل: MK-A3F9"""
    chars = string.ascii_uppercase + string.digits
    suffix = ''.join(random.choices(chars, k=4))
    return f"MK-{suffix}"


def init_db():
    _enable_wal_persistent()
    conn = get_connection()
    c = conn.cursor()
    c.execute("PRAGMA foreign_keys = ON")

    # جدول المؤسسات
    c.execute("""
    CREATE TABLE IF NOT EXISTS organizations (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT    NOT NULL,
        email      TEXT    NOT NULL UNIQUE,
        donor_name TEXT,
        org_code   TEXT    NOT NULL UNIQUE,
        is_active  INTEGER NOT NULL DEFAULT 1,
        created_at TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    # جدول المستخدمين
    # role:   admin | accountant | data_entry
    # status: pending | approved | rejected
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id     INTEGER NOT NULL DEFAULT 1,
        username   TEXT    NOT NULL UNIQUE,
        password   TEXT    NOT NULL,
        full_name  TEXT    NOT NULL DEFAULT '',
        id_number  TEXT,
        email      TEXT,
        photo      TEXT,
        role       TEXT    NOT NULL DEFAULT 'pending',
        status     TEXT    NOT NULL DEFAULT 'pending',
        created_by INTEGER,
        created_at TEXT    DEFAULT (datetime('now','localtime')),
        last_seen  TEXT,
        FOREIGN KEY (org_id) REFERENCES organizations(id)
    )
    """)

    # الأصناف
    c.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id        INTEGER NOT NULL DEFAULT 1,
        name          TEXT    NOT NULL,
        unit          TEXT    NOT NULL,
        last_modified TEXT,
        FOREIGN KEY (org_id) REFERENCES organizations(id)
    )
    """)

    # دفعات المخزون
    c.execute("""
    CREATE TABLE IF NOT EXISTS stock_batches (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id             INTEGER NOT NULL DEFAULT 1,
        product_id         INTEGER NOT NULL,
        quantity_remaining REAL    NOT NULL DEFAULT 0,
        unit_price         REAL    NOT NULL DEFAULT 0,
        entry_date         TEXT,
        invoice_id         INTEGER,
        FOREIGN KEY (product_id) REFERENCES products(id)
    )
    """)

    # فواتير الإدخال
    c.execute("""
    CREATE TABLE IF NOT EXISTS incoming_invoices (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id         INTEGER NOT NULL DEFAULT 1,
        invoice_number TEXT,
        invoice_date   TEXT,
        supplier       TEXT,
        grand_total    REAL    DEFAULT 0,
        created_by     TEXT,
        notes          TEXT,
        is_closed      INTEGER NOT NULL DEFAULT 0,
        invoice_image  TEXT,
        created_at     TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS incoming_invoice_items (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_id    INTEGER NOT NULL,
        product_id    INTEGER NOT NULL,
        quantity      REAL    NOT NULL,
        unit_price    REAL    NOT NULL,
        total_price   REAL    NOT NULL,
        purchase_date TEXT
    )
    """)

    # فواتير الصرف
    c.execute("""
    CREATE TABLE IF NOT EXISTS outgoing_invoices (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id         INTEGER NOT NULL DEFAULT 1,
        invoice_number TEXT,
        invoice_date   TEXT,
        beneficiary    TEXT,
        grand_total    REAL    DEFAULT 0,
        created_by     TEXT,
        notes          TEXT,
        created_at     TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS outgoing_invoice_items (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_id  INTEGER NOT NULL,
        product_id  INTEGER NOT NULL,
        quantity    REAL    NOT NULL,
        unit_price  REAL    NOT NULL,
        total_price REAL    NOT NULL
    )
    """)

    # البرامج والمشاريع
    c.execute("""
    CREATE TABLE IF NOT EXISTS programs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id     INTEGER NOT NULL DEFAULT 1,
        name       TEXT    NOT NULL,
        is_active  INTEGER NOT NULL DEFAULT 1,
        created_at TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    # المستفيدون
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiaries (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id         INTEGER NOT NULL DEFAULT 1,
        seq_num        INTEGER,
        full_name      TEXT    NOT NULL,
        gender         TEXT    DEFAULT 'male',
        phone          TEXT,
        address        TEXT,
        address2       TEXT,
        camp_name      TEXT,
        id_number      TEXT,
        family_size    INTEGER DEFAULT 1,
        marital_status TEXT    DEFAULT 'married',
        children_count INTEGER DEFAULT 0,
        wife_pregnant  INTEGER DEFAULT 0,
        wife_nursing   INTEGER DEFAULT 0,
        has_orphans    INTEGER DEFAULT 0,
        orphans_count  INTEGER DEFAULT 0,
        notes          TEXT,
        created_at     TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    # جدول أكواد التحقق بالإيميل
    c.execute("""
    CREATE TABLE IF NOT EXISTS verification_codes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        email      TEXT    NOT NULL,
        code       TEXT    NOT NULL,
        purpose    TEXT    NOT NULL DEFAULT 'org_register',
        expires_at TEXT    NOT NULL,
        used       INTEGER NOT NULL DEFAULT 0,
        created_at TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    # جدول سجل استفادة المستفيدين من البرامج
    c.execute("""
    CREATE TABLE IF NOT EXISTS program_records (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id           INTEGER NOT NULL,
        program_id       INTEGER NOT NULL,
        distribution_id  INTEGER,
        beneficiary_id   INTEGER NOT NULL,
        camp_entity_id   INTEGER,
        benefit_date     TEXT    NOT NULL,
        benefit_type     TEXT,
        quantity         TEXT,
        value_desc       TEXT,
        received         INTEGER NOT NULL DEFAULT 1,
        notes            TEXT,
        created_by       TEXT,
        created_at       TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (program_id)     REFERENCES programs(id),
        FOREIGN KEY (beneficiary_id) REFERENCES beneficiaries(id)
    )
    """)

    # جدول أحداث التوزيع
    c.execute("""
    CREATE TABLE IF NOT EXISTS program_distributions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id          INTEGER NOT NULL,
        program_id      INTEGER NOT NULL,
        dist_date       TEXT    NOT NULL,
        aid_type        TEXT    NOT NULL,
        quantity        TEXT,
        value_desc      TEXT,
        target_type     TEXT    NOT NULL DEFAULT 'individuals',
        target_category TEXT,
        notes           TEXT,
        created_by      TEXT,
        created_at      TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (program_id) REFERENCES programs(id)
    )
    """)


    # أفراد الأسرة (زوجة + أطفال)
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_family_members (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id INTEGER NOT NULL,
        org_id         INTEGER NOT NULL,
        member_type    TEXT    NOT NULL DEFAULT 'child',  -- wife | child
        full_name      TEXT    NOT NULL,
        birth_date     TEXT,
        is_orphan      INTEGER DEFAULT 0,
        birth_cert_img TEXT,
        created_at     TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    conn.commit()

    # جدول أفراد الأسرة
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_family_members (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id INTEGER NOT NULL,
        org_id         INTEGER NOT NULL,
        member_type    TEXT    NOT NULL DEFAULT 'child',
        full_name      TEXT    NOT NULL,
        birth_date     TEXT,
        is_orphan      INTEGER DEFAULT 0,
        birth_cert_img TEXT,
        created_at     TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)
    conn.commit()

    conn.close()
    migrate_db()


def migrate_db():
    """يضيف الأعمدة والجداول الجديدة لقواعد البيانات القديمة بأمان"""
    conn = get_connection()
    c = conn.cursor()

    # إنشاء جدول programs إن لم يكن موجوداً (للقواعد القديمة)
    c.execute("""
    CREATE TABLE IF NOT EXISTS programs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id     INTEGER NOT NULL DEFAULT 1,
        name       TEXT    NOT NULL,
        is_active  INTEGER NOT NULL DEFAULT 1,
        created_at TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)
    conn.commit()
    migrations = [
        ("beneficiaries",     "id_number",       "TEXT"),
        ("program_records",    "quantity",        "TEXT"),
        ("beneficiaries",     "gender",           "TEXT DEFAULT 'male'"),
        ("beneficiaries",     "children_count",   "INTEGER DEFAULT 0"),
        ("beneficiaries",     "wife_pregnant",    "INTEGER DEFAULT 0"),
        ("beneficiaries",     "wife_nursing",     "INTEGER DEFAULT 0"),
        ("beneficiaries",     "has_orphans",      "INTEGER DEFAULT 0"),
        ("beneficiaries",     "orphans_count",    "INTEGER DEFAULT 0"),
        ("outgoing_invoices",  "program_id",  "INTEGER"),
        ("outgoing_invoices",  "disbursed_to","TEXT"),
        ("beneficiaries",     "family_size", "INTEGER DEFAULT 1"),
        ("beneficiaries",     "org_id",      "INTEGER NOT NULL DEFAULT 1"),
        ("products",          "last_modified","TEXT"),
        ("beneficiaries",     "seq_num",     "INTEGER"),
        ("beneficiaries",     "address2",    "TEXT"),
        ("beneficiaries",     "camp_name",   "TEXT"),
        ("beneficiaries",     "marital_status", "TEXT DEFAULT 'married'"),
        ("products",          "org_id",      "INTEGER NOT NULL DEFAULT 1"),
        ("stock_batches",     "org_id",      "INTEGER NOT NULL DEFAULT 1"),
        ("incoming_invoices", "org_id",      "INTEGER NOT NULL DEFAULT 1"),
        ("outgoing_invoices", "org_id",      "INTEGER NOT NULL DEFAULT 1"),
        ("users",             "org_id",      "INTEGER NOT NULL DEFAULT 1"),
        ("users",             "id_number",   "TEXT"),
        ("users",             "email",       "TEXT"),
        ("users",             "photo",       "TEXT"),
        ("users",             "status",      "TEXT NOT NULL DEFAULT 'approved'"),
        ("users",             "full_name",   "TEXT NOT NULL DEFAULT ''"),
        ("users",             "last_seen",   "TEXT"),
        ("products",          "last_modified", "TEXT"),
        ("incoming_invoices",  "is_closed",     "INTEGER NOT NULL DEFAULT 0"),
        ("incoming_invoices",  "invoice_image", "TEXT"),
        ("incoming_invoice_items", "purchase_date",    "TEXT"),
        ("beneficiaries",         "beneficiary_type", "TEXT DEFAULT 'person'"),
        ("incoming_invoices",     "seq_num",          "INTEGER"),
        ("incoming_invoices",     "invoice_date",     "TEXT"),
        ("incoming_invoices",     "receipt_image",    "TEXT"),
        ("incoming_invoices",     "attachment_image", "TEXT"),
        ("incoming_invoices",     "is_paid",          "INTEGER DEFAULT 0"),
        ("outgoing_invoices",     "is_closed",        "INTEGER NOT NULL DEFAULT 0"),
        ("workers",               "project_name",     "TEXT"),
        ("incoming_invoices",     "purchase_invoice_number", "TEXT"),
        ("incoming_invoices",     "invoice_name",     "TEXT"),
        ("users",                 "phone",            "TEXT"),
        ("incoming_invoices",     "notes",            "TEXT"),
        ("outgoing_invoices",     "notes",            "TEXT"),
        ("beneficiaries", "camp_manager_name",    "TEXT"),
        ("beneficiaries", "camp_coordinator",     "TEXT"),
        ("beneficiaries", "camp_coordinator_phone","TEXT"),
        ("beneficiaries", "camp_address",         "TEXT"),
        ("beneficiaries", "camp_family_count",    "INTEGER"),
        ("beneficiaries", "wife_name",           "TEXT"),
        ("beneficiaries", "personal_photo",      "TEXT"),
        ("beneficiaries", "death_cert_image",    "TEXT"),
        ("beneficiaries", "guardianship_image",  "TEXT"),
        ("beneficiaries", "guardian_whatsapp",   "TEXT"),
        ("beneficiaries", "guardian_name",       "TEXT"),
        ("beneficiaries", "guardian_id_number",  "TEXT"),
        ("beneficiaries", "displacement_date",    "TEXT"),
        ("beneficiaries", "original_address",     "TEXT"),
        ("beneficiaries", "shelter_type",         "TEXT"),
        ("products",          "is_temp",        "INTEGER NOT NULL DEFAULT 0"),
        ("products",          "is_deleted",     "INTEGER NOT NULL DEFAULT 0"),
        ("incoming_invoices", "payment_date",   "TEXT"),
    ]

    # إنشاء جدول العاملين إن لم يكن موجوداً
    c.execute("""
    CREATE TABLE IF NOT EXISTS workers (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id         INTEGER NOT NULL DEFAULT 1,
        full_name      TEXT    NOT NULL,
        id_number      TEXT,
        project_name   TEXT,
        job_type       TEXT,
        monthly_salary REAL    DEFAULT 0,
        notes          TEXT,
        created_at     TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)
    # جدول رسائل الشات الداخلي (أدمن ↔ مراقب)
    c.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id      INTEGER NOT NULL,
        sender_id   INTEGER NOT NULL,
        sender_name TEXT    NOT NULL,
        sender_role TEXT    NOT NULL,
        content     TEXT    NOT NULL,
        created_at  TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)
    # جدول آخر قراءة لكل مستخدم (لحساب الرسائل غير المقروءة)
    c.execute("""
    CREATE TABLE IF NOT EXISTS message_reads (
        user_id     INTEGER PRIMARY KEY,
        last_msg_id INTEGER NOT NULL DEFAULT 0
    )
    """)

    # شات بين المؤسسات
    c.execute("""
    CREATE TABLE IF NOT EXISTS org_messages (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        from_org_id  INTEGER NOT NULL,
        to_org_id    INTEGER NOT NULL,
        sender_id    INTEGER NOT NULL,
        sender_name  TEXT    NOT NULL,
        content      TEXT    NOT NULL,
        created_at   TEXT    DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (from_org_id) REFERENCES organizations(id),
        FOREIGN KEY (to_org_id)   REFERENCES organizations(id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS org_message_reads (
        user_id      INTEGER NOT NULL,
        partner_org  INTEGER NOT NULL,
        last_msg_id  INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, partner_org)
    )
    """)

    # طلبات مشاركة المستفيدين بين المؤسسات
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_share_requests (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        requester_org_id INTEGER NOT NULL,
        owner_org_id     INTEGER NOT NULL,
        beneficiary_id   INTEGER NOT NULL,
        status           TEXT    NOT NULL DEFAULT 'pending',
        created_at       TEXT    DEFAULT (datetime('now','localtime')),
        resolved_at      TEXT,
        FOREIGN KEY (requester_org_id) REFERENCES organizations(id),
        FOREIGN KEY (owner_org_id)     REFERENCES organizations(id),
        FOREIGN KEY (beneficiary_id)   REFERENCES beneficiaries(id)
    )
    """)

    # أعمدة الشات الجديدة (attachment, edited)
    for _col, _def in [("attachment", "TEXT"), ("edited", "INTEGER DEFAULT 0")]:
        try:
            c.execute(f"ALTER TABLE messages ADD COLUMN {_col} {_def}")
        except Exception:
            pass
    conn.commit()

    for table, col, defn in migrations:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
        except Exception:
            pass
    conn.commit()

    # جدول إشعارات النظام (من لوحة التحكم الإدارية)
    c.execute("""
    CREATE TABLE IF NOT EXISTS sys_notifications (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id     INTEGER,
        title      TEXT NOT NULL,
        body       TEXT NOT NULL,
        is_read    INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    )
    """)
    conn.commit()

    # جدول بنود المصروفات التشغيلية
    c.execute("""
    CREATE TABLE IF NOT EXISTS expense_items (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id       INTEGER NOT NULL,
        category     TEXT    NOT NULL,
        expense_date TEXT,
        amount       REAL    NOT NULL DEFAULT 0,
        notes        TEXT,
        proof_image  TEXT,
        period_id    INTEGER,
        created_at   TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    # جدول فترات المصروفات (نظام الإغلاق)
    c.execute("""
    CREATE TABLE IF NOT EXISTS expense_periods (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id      INTEGER NOT NULL,
        start_date  TEXT    NOT NULL,
        end_date    TEXT,
        closed_at   TEXT,
        closed_by   TEXT,
        notes       TEXT,
        created_at  TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)
    conn.commit()

    # ترقيم تسلسلي للفواتير القديمة التي لم يُعيَّن لها seq_num
    fix_invoice_seq_nums(conn)

    # جدول أفراد الأسرة
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_family_members (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id INTEGER NOT NULL,
        org_id         INTEGER NOT NULL,
        member_type    TEXT NOT NULL DEFAULT 'child',
        full_name      TEXT NOT NULL,
        birth_date     TEXT,
        is_orphan      INTEGER DEFAULT 0,
        birth_cert_img TEXT,
        created_at     TEXT
    )
    """)
    conn.commit()

    # جدول مكافآت العاملين
    c.execute("""
    CREATE TABLE IF NOT EXISTS worker_bonuses (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        worker_id   INTEGER NOT NULL,
        org_id      INTEGER NOT NULL,
        amount      REAL    NOT NULL DEFAULT 0,
        bonus_date  TEXT    NOT NULL,
        notes       TEXT,
        created_at  TEXT
    )
    """)
    # عمود family_entity_id للمستفيد (عائلتو — مستقل عن المخيم/اللجنة)
    try:
        c.execute("ALTER TABLE beneficiaries ADD COLUMN family_entity_id INTEGER DEFAULT NULL")
        conn.commit()
    except Exception:
        pass

    # شعار/صورة الكيان (مخيم/لجنة/عائلة)
    try:
        c.execute("ALTER TABLE camp_entities ADD COLUMN logo_image TEXT DEFAULT NULL")
        conn.commit()
    except Exception:
        pass

    # قيد UNIQUE على (beneficiary_id, camp_entity_id) في طلبات الانضمام المقبولة
    # يمنع تكرار نفس المستفيد داخل نفس الكيان
    try:
        c.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS ux_join_approved
            ON camp_join_requests (beneficiary_id, camp_entity_id)
            WHERE status = 'approved'
        """)
        conn.commit()
    except Exception:
        pass

    conn.commit()

    # ══════════════════════════════════════════════════════════
    # Phase 1 — توحيد بيانات المستفيدين (رقم الهوية المحور الأساسي)
    # ══════════════════════════════════════════════════════════
    try:
        # 1. جدول ربط المستفيد بأكثر من مؤسسة
        c.execute("""
        CREATE TABLE IF NOT EXISTS org_beneficiary_links (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id         INTEGER NOT NULL,
            beneficiary_id INTEGER NOT NULL,
            added_at       TEXT DEFAULT (datetime('now','localtime')),
            added_by       INTEGER,
            notes          TEXT,
            UNIQUE(org_id, beneficiary_id),
            FOREIGN KEY (beneficiary_id) REFERENCES beneficiaries(id)
        )
        """)
        conn.commit()

        # 2. حذف الهويات الوهمية (000000000 أو فارغة) — مع استثناء المخيمات التي لا تحتاج هوية
        c.execute("""
            DELETE FROM beneficiary_family_members
            WHERE beneficiary_id IN (
                SELECT id FROM beneficiaries
                WHERE (id_number IS NULL OR id_number='' OR id_number='000000000')
                  AND (beneficiary_type IS NULL OR beneficiary_type != 'camp')
            )
        """)
        c.execute("""
            DELETE FROM beneficiaries
            WHERE (id_number IS NULL OR id_number='' OR id_number='000000000')
              AND (beneficiary_type IS NULL OR beneficiary_type != 'camp')
        """)
        conn.commit()

        # 3. إزالة التكرار: احتفظ بالأحدث فقط لكل هوية مكررة
        c.execute("""
            DELETE FROM beneficiaries WHERE id NOT IN (
                SELECT MAX(id) FROM beneficiaries
                WHERE id_number IS NOT NULL AND id_number != ''
                GROUP BY id_number
            ) AND id_number IS NOT NULL AND id_number != ''
        """)
        conn.commit()

        # 4. UNIQUE INDEX على id_number
        try:
            c.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS ux_beneficiary_id_number
                ON beneficiaries(id_number)
                WHERE id_number IS NOT NULL AND id_number != ''
            """)
            conn.commit()
        except Exception:
            pass

        # 5. اربط كل مستفيد موجود بمؤسسته في جدول الربط
        c.execute("""
            INSERT OR IGNORE INTO org_beneficiary_links (org_id, beneficiary_id)
            SELECT org_id, id FROM beneficiaries
            WHERE org_id IS NOT NULL
        """)
        conn.commit()
    except Exception as _ph1_err:
        # لا توقف التطبيق إذا فشلت الهجرة — ستُعاد عند التشغيل التالي
        try:
            conn.rollback()
        except Exception:
            pass
    # ══════════════════════════════════════════════════════════

    conn.close()
    init_camp_tables()


def fix_invoice_seq_nums(conn):
    """يُرقّم الفواتير الموجودة التي seq_num فيها NULL بترتيب id تصاعدي لكل org"""
    c = conn.cursor()
    c.execute("SELECT DISTINCT org_id FROM incoming_invoices")
    orgs = [r[0] for r in c.fetchall()]
    for org_id in orgs:
        c.execute("""
            SELECT id FROM incoming_invoices
            WHERE org_id=? AND (seq_num IS NULL OR seq_num = 0)
            ORDER BY id ASC
        """, (org_id,))
        rows = c.fetchall()
        if not rows:
            continue
        c.execute("SELECT COALESCE(MAX(seq_num),0) FROM incoming_invoices WHERE org_id=? AND seq_num > 0", (org_id,))
        base = c.fetchone()[0]
        for i, row in enumerate(rows, start=base + 1):
            c.execute(
                "UPDATE incoming_invoices SET seq_num=?, invoice_number=? WHERE id=?",
                (i, str(i), row[0])
            )
    conn.commit()


def init_camp_tables():
    """إنشاء جداول المخيمات والعلاقات"""
    conn = get_connection()
    c = conn.cursor()

    # كيانات المخيمات/اللجان/العائلات
    c.execute("""
    CREATE TABLE IF NOT EXISTS camp_entities (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type         TEXT    NOT NULL DEFAULT 'camp',
        name                TEXT    NOT NULL,
        manager_name        TEXT    NOT NULL,
        id_number           TEXT,
        mobile              TEXT,
        whatsapp            TEXT,
        email               TEXT    UNIQUE NOT NULL,
        email_verified      INTEGER NOT NULL DEFAULT 0,
        governorate         TEXT,
        city                TEXT,
        street              TEXT,
        registered_families INTEGER DEFAULT 0,
        password            TEXT,
        is_active           INTEGER NOT NULL DEFAULT 1,
        created_at          TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    # طلبات انضمام مستفيد لمخيم
    c.execute("""
    CREATE TABLE IF NOT EXISTS camp_join_requests (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id  INTEGER NOT NULL,
        camp_entity_id  INTEGER NOT NULL,
        status          TEXT    NOT NULL DEFAULT 'pending',
        notes           TEXT,
        created_at      TEXT    DEFAULT (datetime('now','localtime')),
        resolved_at     TEXT,
        FOREIGN KEY (beneficiary_id) REFERENCES beneficiaries(id),
        FOREIGN KEY (camp_entity_id) REFERENCES camp_entities(id)
    )
    """)

    # روابط المؤسسات بالمخيمات (many-to-many)
    c.execute("""
    CREATE TABLE IF NOT EXISTS institution_camp_links (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id          INTEGER NOT NULL,
        camp_entity_id  INTEGER NOT NULL,
        status          TEXT    NOT NULL DEFAULT 'pending',
        created_at      TEXT    DEFAULT (datetime('now','localtime')),
        resolved_at     TEXT,
        UNIQUE(org_id, camp_entity_id),
        FOREIGN KEY (org_id) REFERENCES organizations(id),
        FOREIGN KEY (camp_entity_id) REFERENCES camp_entities(id)
    )
    """)

    conn.commit()

    # أعمدة جديدة للمستفيدين
    # جدول محاولات الدخول
    c.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier   TEXT NOT NULL,
        attempt_type TEXT DEFAULT 'beneficiary',
        ip_address   TEXT,
        success      INTEGER DEFAULT 0,
        created_at   TEXT DEFAULT (datetime('now','localtime'))
    )
    """)
    conn.commit()

    new_cols = [
        ("beneficiaries", "camp_entity_id",    "INTEGER"),
        ("beneficiaries", "self_registered",   "INTEGER DEFAULT 0"),
        ("beneficiaries", "beneficiary_status","TEXT DEFAULT 'independent'"),
        ("beneficiaries", "governorate",       "TEXT"),
        ("beneficiaries", "family_last_name",  "TEXT"),
        ("beneficiaries", "self_reg_password", "TEXT"),
        ("beneficiaries", "email",             "TEXT"),
        ("beneficiaries", "failed_attempts",   "INTEGER DEFAULT 0"),
        ("beneficiaries", "locked_until",      "TEXT"),
        ("beneficiaries", "birth_date",        "TEXT"),
        ("beneficiaries", "avatar_path",       "TEXT"),
        ("beneficiaries", "id_card_path",     "TEXT"),
        ("camp_entities",  "failed_attempts",  "INTEGER DEFAULT 0"),
        ("camp_entities",  "locked_until",     "TEXT"),
        ("beneficiaries", "city",              "TEXT"),
        ("beneficiaries", "neighborhood",      "TEXT"),
        ("beneficiaries", "street",            "TEXT"),
    ]
    for table, col, defn in new_cols:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
        except Exception:
            pass

    # ── جدول الاستفادة من المخيم ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS camp_benefits (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        camp_entity_id INTEGER NOT NULL,
        beneficiary_id INTEGER NOT NULL,
        benefit_type   TEXT NOT NULL,
        value          TEXT,
        quantity       TEXT,
        notes          TEXT,
        benefit_date   TEXT DEFAULT (date('now','localtime')),
        created_at     TEXT DEFAULT (datetime('now','localtime'))
    )
    """)
    conn.commit()

    # ── جدول بيانات الزوجة ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_spouse (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id  INTEGER NOT NULL UNIQUE,
        full_name       TEXT, id_number TEXT,
        birth_date      TEXT, marriage_date TEXT,
        pregnant        INTEGER DEFAULT 0,
        nursing         INTEGER DEFAULT 0,
        updated_at      TEXT DEFAULT (datetime('now','localtime'))
    )""")
    # ── جدول الأبناء ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_children (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id INTEGER NOT NULL,
        full_name TEXT, birth_date TEXT, sort_order INTEGER DEFAULT 0
    )""")
    # ── جدول الحالة الصحية ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_health (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id INTEGER NOT NULL,
        condition_type TEXT, notes TEXT,
        condition_date TEXT, report_path TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    )""")
    # ── جدول الأرمل/الأرملة ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_widowed (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id INTEGER NOT NULL UNIQUE,
        death_type TEXT, death_date TEXT,
        updated_at TEXT DEFAULT (datetime('now','localtime'))
    )""")
    # ── جدول الأيتام ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_orphans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id INTEGER NOT NULL,
        full_name TEXT, martyrdom_date TEXT,
        birth_cert_path TEXT, death_cert_path TEXT, custody_path TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    )""")
    # ── جدول من يعيلهم ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS beneficiary_dependents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        beneficiary_id INTEGER NOT NULL,
        full_name TEXT, birth_date TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    )""")

    conn.commit()

    # ══ نظام إدارة المخيم الكامل ══
    c.execute("""CREATE TABLE IF NOT EXISTS camp_inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        camp_entity_id INTEGER NOT NULL,
        donor_name TEXT NOT NULL,
        donor_type TEXT DEFAULT 'organization',
        item_name TEXT NOT NULL,
        quantity REAL NOT NULL DEFAULT 0,
        unit TEXT DEFAULT 'وحدة',
        receive_date TEXT NOT NULL,
        notes TEXT, proof_image TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime')))""")

    c.execute("""CREATE TABLE IF NOT EXISTS camp_distributions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        camp_entity_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        distribution_date TEXT NOT NULL,
        donor_name TEXT,
        filter_type TEXT DEFAULT 'all',
        filter_value TEXT,
        status TEXT DEFAULT 'draft',
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime')))""")

    c.execute("""CREATE TABLE IF NOT EXISTS camp_dist_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        distribution_id INTEGER NOT NULL,
        camp_entity_id INTEGER NOT NULL,
        beneficiary_id INTEGER NOT NULL,
        item_name TEXT, quantity TEXT, value TEXT,
        received INTEGER DEFAULT 0,
        received_at TEXT, notes TEXT,
        UNIQUE(distribution_id, beneficiary_id))""")

    c.execute("""CREATE TABLE IF NOT EXISTS camp_activities (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
        camp_entity_id INTEGER NOT NULL,
        activity_date TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        activity_type TEXT DEFAULT 'general',
        created_at TEXT DEFAULT (datetime('now','localtime')))""")

    c.execute("""CREATE TABLE IF NOT EXISTS camp_activity_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        activity_id INTEGER NOT NULL,
        beneficiary_id INTEGER NOT NULL,
        item_name TEXT, quantity TEXT, value TEXT,
        notes TEXT,
        UNIQUE(activity_id, beneficiary_id))""")

    # جدول فترات المصروفات (للقواعد القديمة)
    c.execute("""
    CREATE TABLE IF NOT EXISTS expense_periods (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id      INTEGER NOT NULL,
        start_date  TEXT    NOT NULL,
        end_date    TEXT,
        closed_at   TEXT,
        closed_by   TEXT,
        notes       TEXT,
        created_at  TEXT    DEFAULT (datetime('now','localtime'))
    )
    """)

    # عمود period_id في expense_items
    try:
        c.execute("ALTER TABLE expense_items ADD COLUMN period_id INTEGER")
    except Exception:
        pass

    # أعمدة جديدة في program_records
    for col, defn in [
        ("distribution_id", "INTEGER"),
        ("camp_entity_id",  "INTEGER"),
        ("value_desc",      "TEXT"),
        ("received",        "INTEGER NOT NULL DEFAULT 1"),
    ]:
        try:
            c.execute(f"ALTER TABLE program_records ADD COLUMN {col} {defn}")
        except Exception:
            pass

    # جدول أحداث التوزيع
    c.execute("""
    CREATE TABLE IF NOT EXISTS program_distributions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id          INTEGER NOT NULL,
        program_id      INTEGER NOT NULL,
        dist_date       TEXT    NOT NULL,
        aid_type        TEXT    NOT NULL,
        quantity        TEXT,
        value_desc      TEXT,
        target_type     TEXT    NOT NULL DEFAULT 'individuals',
        target_category TEXT,
        notes           TEXT,
        created_by      TEXT,
        created_at      TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (program_id) REFERENCES programs(id)
    )
    """)

    conn.commit()

    # أعمدة إضافية لكيانات المخيم
    extra_cols = [
        ("camp_entities", "logo_image",       "TEXT"),
        ("camp_entities", "cover_image",      "TEXT"),
        ("camp_entities", "about",            "TEXT"),
        ("camp_entities", "facebook",         "TEXT"),
        ("camp_entities", "telegram",         "TEXT"),
        ("institution_camp_links", "notes", "TEXT"),
        ("camp_entities", "total_families",   "INTEGER DEFAULT 0"),
        ("camp_entities", "total_members",    "INTEGER DEFAULT 0"),
    ]
    for table, col, defn in extra_cols:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
        except Exception:
            pass

    conn.commit()

    # جدول

    # جدول مرفقات الأنشطة (كان مفقوداً)
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS camp_activity_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            activity_id INTEGER NOT NULL,
            file_path TEXT,
            file_name TEXT,
            uploaded_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (activity_id) REFERENCES camp_activities(id)
        )""")
        conn.commit()
    except Exception:
        pass

    # جدول طلبات انضمام المستفيدين للمخيمات
    # إذا الجدول موجود بمخطط قديم (بدون id_number) نحذفه ونعيد إنشاؤه
    try:
        c.execute("SELECT id_number FROM camp_join_requests LIMIT 1")
    except Exception:
        c.execute("DROP TABLE IF EXISTS camp_join_requests")
        conn.commit()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS camp_join_requests (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            camp_entity_id   INTEGER NOT NULL,
            beneficiary_id   INTEGER DEFAULT NULL,
            id_number        TEXT    NOT NULL,
            full_name        TEXT    NOT NULL,
            status           TEXT    NOT NULL DEFAULT 'pending',
            notes            TEXT,
            created_at       TEXT    DEFAULT (datetime('now','localtime')),
            responded_at     TEXT    DEFAULT NULL,
            FOREIGN KEY (camp_entity_id) REFERENCES camp_entities(id),
            FOREIGN KEY (beneficiary_id) REFERENCES beneficiaries(id),
            UNIQUE(camp_entity_id, id_number)
        )""")
        conn.commit()
    except Exception:
        pass

    # عمود camp_entity_id للمستفيدين (مخيم واحد فقط)
    try:
        c.execute("ALTER TABLE beneficiaries ADD COLUMN camp_entity_id INTEGER DEFAULT NULL")
        conn.commit()
    except Exception:
        pass
    # استلام المستفيد لسجلات البرامج
    try:
        c.execute("ALTER TABLE program_records ADD COLUMN ben_confirmed INTEGER DEFAULT 0")
        conn.commit()
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE program_records ADD COLUMN ben_confirmed_at TEXT")
        conn.commit()
    except Exception:
        pass

    # جدول تسليمات المؤسسة للمخيمات
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS org_camp_deliveries (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id          INTEGER NOT NULL,
            camp_entity_id  INTEGER NOT NULL,
            delivery_date   TEXT    NOT NULL,
            title           TEXT    NOT NULL,
            items           TEXT,
            quantity        TEXT,
            notes           TEXT,
            confirmed       INTEGER DEFAULT 0,
            confirmed_at    TEXT,
            confirmed_by    TEXT,
            created_by      TEXT,
            created_at      TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (org_id)         REFERENCES organizations(id),
            FOREIGN KEY (camp_entity_id) REFERENCES camp_entities(id)
        )""")
        conn.commit()
    except Exception:
        pass

    # إشعارات المؤسسات للمخيمات (عند تنفيذ توزيع)
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS camp_org_notifications (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            camp_entity_id  INTEGER NOT NULL,
            org_id          INTEGER NOT NULL,
            distribution_id INTEGER,
            program_name    TEXT,
            aid_type        TEXT,
            dist_date       TEXT,
            ben_count       INTEGER DEFAULT 0,
            pers_count      INTEGER DEFAULT 0,
            is_read         INTEGER DEFAULT 0,
            created_at      TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (camp_entity_id) REFERENCES camp_entities(id),
            FOREIGN KEY (org_id)         REFERENCES organizations(id)
        )""")
        conn.commit()
    except Exception:
        pass

    conn.close()
