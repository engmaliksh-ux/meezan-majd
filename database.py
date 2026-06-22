import sqlite3
import random
import string

DB_NAME = "database.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def generate_org_code():
    """ينشئ رمزاً فريداً للمؤسسة مثل: MK-A3F9"""
    chars = string.ascii_uppercase + string.digits
    suffix = ''.join(random.choices(chars, k=4))
    return f"MK-{suffix}"


def init_db():
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
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id         INTEGER NOT NULL,
        program_id     INTEGER NOT NULL,
        beneficiary_id INTEGER NOT NULL,
        benefit_date   TEXT    NOT NULL,
        benefit_type   TEXT,
        quantity       TEXT,
        notes          TEXT,
        created_by     TEXT,
        created_at     TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (program_id)     REFERENCES programs(id),
        FOREIGN KEY (beneficiary_id) REFERENCES beneficiaries(id)
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
        created_at   TEXT    DEFAULT (datetime('now','localtime'))
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
    conn.commit()

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
        ("beneficiaries", "city",              "TEXT"),
        ("beneficiaries", "neighborhood",      "TEXT"),
        ("beneficiaries", "street",            "TEXT"),
    ]
    for table, col, defn in new_cols:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
        except Exception:
            pass

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
    conn.close()
