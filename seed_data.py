"""
seed_data.py — بيانات تجريبية شبه حقيقية لمنصة ميزان مجد
شغّله على السيرفر: python3 seed_data.py
"""
import sqlite3, sys
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

DB = "/home/MalikMohs/meezan-majd/database.db"

def get_conn():
    conn = sqlite3.connect(DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    return conn

def run():
    conn = get_conn()
    c = conn.cursor()

    print("═══ ميزان مجد — إدخال البيانات التجريبية ═══\n")

    # ══════════════════════════════════════════
    # 1. المؤسسة الأولى — جمعية الرحمة للإغاثة
    # ══════════════════════════════════════════
    c.execute("SELECT id FROM organizations WHERE email='rahma@relief.org' LIMIT 1")
    org1 = c.fetchone()
    if not org1:
        c.execute("""INSERT INTO organizations
            (name, email, phone, address, area, org_code, is_active, is_verified)
            VALUES (?,?,?,?,?,?,1,1)""",
            ("جمعية الرحمة للإغاثة", "rahma@relief.org", "0911234567",
             "دمشق - الميدان", "دمشق", "RAHMA01"))
        org1_id = c.lastrowid
        print(f"✅ المؤسسة 1: جمعية الرحمة للإغاثة (id={org1_id})")
    else:
        org1_id = org1["id"]
        print(f"ℹ️  المؤسسة 1 موجودة (id={org1_id})")

    # مدير المؤسسة 1
    c.execute("SELECT id FROM users WHERE email='admin@rahma.org' LIMIT 1")
    if not c.fetchone():
        c.execute("""INSERT INTO users
            (org_id, username, password, full_name, email, role, status)
            VALUES (?,?,?,?,?,?,?)""",
            (org1_id, "admin_rahma",
             generate_password_hash("Rahma@2024"),
             "أحمد محمود السيد", "admin@rahma.org", "admin", "approved"))
        print(f"✅ مدير المؤسسة 1: admin@rahma.org / Rahma@2024")

    # موظف بيانات في المؤسسة 1
    c.execute("SELECT id FROM users WHERE email='data@rahma.org' LIMIT 1")
    if not c.fetchone():
        c.execute("""INSERT INTO users
            (org_id, username, password, full_name, email, role, status)
            VALUES (?,?,?,?,?,?,?)""",
            (org1_id, "data_rahma",
             generate_password_hash("Data@2024"),
             "سارة عبد الله حسن", "data@rahma.org", "data_entry", "approved"))
        print(f"✅ موظف بيانات المؤسسة 1: data@rahma.org / Data@2024")

    # ══════════════════════════════════════════
    # 2. المؤسسة الثانية — منظمة أمل للتنمية
    # ══════════════════════════════════════════
    c.execute("SELECT id FROM organizations WHERE email='amal@ngo.org' LIMIT 1")
    org2 = c.fetchone()
    if not org2:
        c.execute("""INSERT INTO organizations
            (name, email, phone, address, area, org_code, is_active, is_verified)
            VALUES (?,?,?,?,?,?,1,1)""",
            ("منظمة أمل للتنمية", "amal@ngo.org", "0921234567",
             "حلب - الشعار", "حلب", "AMAL02"))
        org2_id = c.lastrowid
        print(f"✅ المؤسسة 2: منظمة أمل للتنمية (id={org2_id})")
    else:
        org2_id = org2["id"]
        print(f"ℹ️  المؤسسة 2 موجودة (id={org2_id})")

    # مدير المؤسسة 2
    c.execute("SELECT id FROM users WHERE email='admin@amal.org' LIMIT 1")
    if not c.fetchone():
        c.execute("""INSERT INTO users
            (org_id, username, password, full_name, email, role, status)
            VALUES (?,?,?,?,?,?,?)""",
            (org2_id, "admin_amal",
             generate_password_hash("Amal@2024"),
             "خالد يوسف النور", "admin@amal.org", "admin", "approved"))
        print(f"✅ مدير المؤسسة 2: admin@amal.org / Amal@2024")

    conn.commit()

    # ══════════════════════════════════════════
    # 3. المخيم — مخيم النور للنازحين
    # ══════════════════════════════════════════
    c.execute("SELECT id FROM camp_entities WHERE email='nour@camp.sy' LIMIT 1")
    camp1 = c.fetchone()
    if not camp1:
        c.execute("""INSERT INTO camp_entities
            (entity_type, name, manager_name, mobile, email, governorate, city,
             password, is_active, registered_families)
            VALUES (?,?,?,?,?,?,?,?,1,0)""",
            ("camp", "مخيم النور للنازحين", "محمد خالد العمر",
             "0931234567", "nour@camp.sy",
             "دمشق", "جرمانا",
             generate_password_hash("Camp@2024")))
        camp1_id = c.lastrowid
        print(f"✅ المخيم: مخيم النور للنازحين (id={camp1_id})")
    else:
        camp1_id = camp1["id"]
        print(f"ℹ️  المخيم موجود (id={camp1_id})")

    conn.commit()

    # ══════════════════════════════════════════
    # 4. المنتجات والمخزون — المؤسسة 1
    # ══════════════════════════════════════════
    products_data = [
        ("طحين 25 كغ", "كيس", 10, org1_id),
        ("زيت نباتي 5 لتر", "عبوة", 15, org1_id),
        ("سكر 5 كغ", "كيس", 20, org1_id),
        ("بطانيات شتوية", "قطعة", 5, org1_id),
        ("حفاضات أطفال", "كرتون", 10, org1_id),
    ]
    prod_ids = []
    for pname, unit, min_stock, oid in products_data:
        c.execute("SELECT id FROM products WHERE name=? AND org_id=?", (pname, oid))
        row = c.fetchone()
        if not row:
            c.execute("""INSERT INTO products (org_id, name, unit, min_stock, category)
                VALUES (?,?,?,?,'غذاء')""", (oid, pname, unit, min_stock))
            pid = c.lastrowid
        else:
            pid = row["id"]
        prod_ids.append(pid)

    # فاتورة واردة وإضافة مخزون
    c.execute("SELECT id FROM incoming_invoices WHERE invoice_number='INV-RAHMA-001' LIMIT 1")
    if not c.fetchone():
        c.execute("""INSERT INTO incoming_invoices
            (org_id, invoice_number, supplier_name, invoice_date, total_amount, status, notes)
            VALUES (?,?,?,?,?,?,?)""",
            (org1_id, "INV-RAHMA-001", "شركة الوفاء للتوريد",
             "2024-11-01", 2500000, "closed", "دفعة إغاثة الشتاء"))
        inv_id = c.lastrowid
        # إضافة أصناف وتحديث المخزون
        for i, pid in enumerate(prod_ids):
            qty = [50, 40, 60, 30, 25][i]
            price = [12500, 25000, 8000, 35000, 18000][i]
            c.execute("""INSERT INTO incoming_invoice_items
                (invoice_id, product_id, quantity, unit_price, total)
                VALUES (?,?,?,?,?)""", (inv_id, pid, qty, price, qty*price))
            c.execute("""INSERT INTO stock_batches
                (product_id, org_id, quantity_in, quantity_remaining, unit_price, source)
                VALUES (?,?,?,?,?,'فاتورة واردة')""",
                (pid, org1_id, qty, qty, price))
        print(f"✅ فاتورة واردة + مخزون للمؤسسة 1")

    conn.commit()

    # ══════════════════════════════════════════
    # 5. المستفيدون (5 أسر)
    # ══════════════════════════════════════════
    beneficiaries_data = [
        {
            "full_name": "محمد حسن علي الأحمد",
            "id_number": "9001234567",
            "phone": "0941234561",
            "gender": "male",
            "family_size": 6,
            "governorate": "دمشق",
            "city": "جرمانا",
            "family_last_name": "الأحمد",
            "has_orphans": 1,
            "orphans_count": 2,
            "camp_entity_id": camp1_id,
        },
        {
            "full_name": "أحمد سليم ناصر الخطيب",
            "id_number": "9002345678",
            "phone": "0941234562",
            "gender": "male",
            "family_size": 4,
            "governorate": "دمشق",
            "city": "جرمانا",
            "family_last_name": "الخطيب",
            "wife_pregnant": 1,
            "camp_entity_id": camp1_id,
        },
        {
            "full_name": "خالد محمود ريد العمر",
            "id_number": "9003456789",
            "phone": "0941234563",
            "gender": "male",
            "family_size": 8,
            "governorate": "دمشق",
            "city": "جرمانا",
            "family_last_name": "العمر",
            "has_orphans": 1,
            "orphans_count": 3,
            "camp_entity_id": camp1_id,
        },
        {
            "full_name": "سامر عبد الرحمن يوسف السعيد",
            "id_number": "9004567890",
            "phone": "0941234564",
            "gender": "male",
            "family_size": 5,
            "governorate": "دمشق",
            "city": "المزة",
            "family_last_name": "السعيد",
            "wife_nursing": 1,
        },
        {
            "full_name": "عمر فريد جابر النعسان",
            "id_number": "9005678901",
            "phone": "0941234565",
            "gender": "male",
            "family_size": 3,
            "governorate": "حلب",
            "city": "الشعار",
            "family_last_name": "النعسان",
        },
    ]

    ben_ids = []
    for bd in beneficiaries_data:
        c.execute("SELECT id FROM beneficiaries WHERE id_number=?", (bd["id_number"],))
        row = c.fetchone()
        if not row:
            c.execute("""INSERT INTO beneficiaries
                (org_id, full_name, id_number, phone, gender, family_size,
                 governorate, city, family_last_name,
                 has_orphans, orphans_count, wife_pregnant, wife_nursing,
                 camp_entity_id, beneficiary_type, beneficiary_status, self_registered)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'person','active',0)""",
                (org1_id,
                 bd["full_name"], bd["id_number"], bd["phone"],
                 bd["gender"], bd["family_size"],
                 bd["governorate"], bd["city"], bd["family_last_name"],
                 bd.get("has_orphans", 0), bd.get("orphans_count", 0),
                 bd.get("wife_pregnant", 0), bd.get("wife_nursing", 0),
                 bd.get("camp_entity_id")))
            bid = c.lastrowid
            # ربط بالمؤسسة 1
            c.execute("""INSERT OR IGNORE INTO org_beneficiary_links (org_id, beneficiary_id)
                VALUES (?,?)""", (org1_id, bid))
            print(f"✅ مستفيد: {bd['full_name']} ({bd['id_number']})")
        else:
            bid = row["id"]
            print(f"ℹ️  مستفيد موجود: {bd['full_name']}")
        ben_ids.append(bid)

    conn.commit()

    # ربط مستفيد 5 بالمؤسسة 2 أيضاً (لاختبار التوحيد)
    c.execute("""INSERT OR IGNORE INTO org_beneficiary_links (org_id, beneficiary_id)
        VALUES (?,?)""", (org2_id, ben_ids[4]))
    print(f"✅ ربط المستفيد الخامس بالمؤسسة 2 أيضاً (اختبار التوحيد)")

    # ══════════════════════════════════════════
    # 6. مستفيد واحد مسجّل ذاتياً (للاختبار)
    # ══════════════════════════════════════════
    c.execute("SELECT id FROM beneficiaries WHERE id_number='9099887766' LIMIT 1")
    if not c.fetchone():
        c.execute("""INSERT INTO beneficiaries
            (org_id, full_name, id_number, phone, gender, family_size,
             governorate, city, family_last_name,
             beneficiary_type, beneficiary_status, self_registered, self_reg_password)
            VALUES (?,?,?,?,?,?,?,?,?,'person','independent',1,?)""",
            (1, "نور محمد أحمد الزهراء", "9099887766", "0941111111",
             "female", 3, "دمشق", "جرمانا", "الزهراء",
             generate_password_hash("Nour@2024")))
        self_ben_id = c.lastrowid
        c.execute("""INSERT OR IGNORE INTO org_beneficiary_links (org_id, beneficiary_id)
            VALUES (?,?)""", (org1_id, self_ben_id))
        print(f"✅ مستفيد ذاتي: 9099887766 / Nour@2024")

    conn.commit()

    # ══════════════════════════════════════════
    # 7. برنامج وسجلات استفادة
    # ══════════════════════════════════════════
    c.execute("SELECT id FROM programs WHERE org_id=? AND name='برنامج السلة الغذائية' LIMIT 1", (org1_id,))
    prog = c.fetchone()
    if not prog:
        c.execute("""INSERT INTO programs (org_id, name, description, is_active)
            VALUES (?,?,?,1)""",
            (org1_id, "برنامج السلة الغذائية",
             "توزيع سلة غذائية شهرية تشمل طحين وزيت وسكر"))
        prog_id = c.lastrowid
        print(f"✅ برنامج: السلة الغذائية")
    else:
        prog_id = prog["id"]

    # سجلات استفادة للمستفيدين الثلاثة الأوائل
    for i, bid in enumerate(ben_ids[:3]):
        c.execute("""SELECT id FROM program_records
            WHERE program_id=? AND beneficiary_id=? LIMIT 1""", (prog_id, bid))
        if not c.fetchone():
            c.execute("""INSERT INTO program_records
                (org_id, program_id, beneficiary_id, benefit_date, benefit_type, quantity, notes)
                VALUES (?,?,?,?,?,?,?)""",
                (org1_id, prog_id, bid,
                 f"2024-{11+i:02d}-15", "سلة غذائية", "1 سلة",
                 "توزيع شهري منتظم"))

    conn.commit()

    # ══════════════════════════════════════════
    # 8. توزيع في المخيم
    # ══════════════════════════════════════════
    c.execute("SELECT id FROM camp_distributions WHERE camp_entity_id=? LIMIT 1", (camp1_id,))
    if not c.fetchone():
        c.execute("""INSERT INTO camp_distributions
            (camp_entity_id, title, distribution_date, donor_name, status, notes)
            VALUES (?,?,?,?,?,?)""",
            (camp1_id, "توزيع الشتاء الأول", "2024-12-01",
             "جمعية الرحمة للإغاثة", "closed",
             "توزيع بطانيات ومستلزمات شتاء"))
        dist_id = c.lastrowid
        # سجلات التوزيع للمستفيدين في المخيم
        camp_bens = [bid for i, bid in enumerate(ben_ids) if beneficiaries_data[i].get("camp_entity_id") == camp1_id]
        for bid in camp_bens:
            c.execute("""INSERT OR IGNORE INTO camp_dist_records
                (distribution_id, camp_entity_id, beneficiary_id, item_name, quantity, value, received)
                VALUES (?,?,?,?,?,?,1)""",
                (dist_id, camp1_id, bid, "بطانية شتوية + حقيبة إغاثة", "1 طقم", "35000"))
        print(f"✅ توزيع المخيم: بطانيات الشتاء ({len(camp_bens)} مستفيد)")

    conn.commit()

    # ══════════════════════════════════════════
    # 9. نشاط في المخيم
    # ══════════════════════════════════════════
    c.execute("SELECT id FROM camp_activities WHERE camp_entity_id=? LIMIT 1", (camp1_id,))
    if not c.fetchone():
        c.execute("""INSERT INTO camp_activities
            (camp_entity_id, activity_date, title, description, activity_type)
            VALUES (?,?,?,?,?)""",
            (camp1_id, "2024-12-05", "فحص طبي مجاني",
             "زيارة فريق طبي تطوعي لفحص سكان المخيم وتوزيع الأدوية",
             "medical"))
        print(f"✅ نشاط: فحص طبي مجاني")

    # ══════════════════════════════════════════
    # 10. طلب انضمام معلّق للمخيم
    # ══════════════════════════════════════════
    # المستفيد الرابع (خارج المخيم) يطلب الانضمام
    c.execute("""SELECT id FROM camp_join_requests
        WHERE beneficiary_id=? AND camp_entity_id=? LIMIT 1""",
        (ben_ids[3], camp1_id))
    if not c.fetchone():
        c.execute("""INSERT INTO camp_join_requests
            (beneficiary_id, camp_entity_id, status)
            VALUES (?,?,'pending')""", (ben_ids[3], camp1_id))
        print(f"✅ طلب انضمام معلّق للمخيم (المستفيد 4)")

    conn.commit()
    conn.close()

    print("\n═══ اكتمل إدخال البيانات ═══\n")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("🏢 المؤسسة 1:  admin@rahma.org     / Rahma@2024  (مدير)")
    print("🏢 المؤسسة 1:  data@rahma.org      / Data@2024   (موظف بيانات)")
    print("🏢 المؤسسة 2:  admin@amal.org      / Amal@2024   (مدير)")
    print("🏕️  المخيم:     nour@camp.sy        / Camp@2024")
    print("👤 مستفيد ذاتي: رقم الهوية 9099887766 / Nour@2024")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

if __name__ == "__main__":
    run()
