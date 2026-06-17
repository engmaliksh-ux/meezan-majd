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
    ]
    for table, col, defn in migrations:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
        except Exception:
            pass
    conn.commit()
    conn.close()