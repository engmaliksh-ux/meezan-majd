"""
seed_data.py — بيانات تجريبية لمنصة ميزان مجد
شغّله: python3 seed_data.py
"""
import sqlite3
from werkzeug.security import generate_password_hash

DB = "/home/MalikMohs/meezan-majd/database.db"

def conn():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=15000")
    return c

def col_exists(db, table, col):
    cur = db.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())

def safe_insert(db, sql, params):
    try:
        db.execute(sql, params)
        return db.execute("SELECT last_insert_rowid()").fetchone()[0]
    except Exception as e:
        print(f"  ⚠️  {e}")
        return None

def run():
    db = conn()
    print("═══ ميزان مجد — إدخال البيانات التجريبية ═══\n")

    # ── تحقق من الأعمدة المتاحة ──
    orgs_cols   = [r[1] for r in db.execute("PRAGMA table_info(organizations)").fetchall()]
    users_cols  = [r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()]
    prods_cols  = [r[1] for r in db.execute("PRAGMA table_info(products)").fetchall()]
    stock_cols  = [r[1] for r in db.execute("PRAGMA table_info(stock_batches)").fetchall()]
    inv_cols    = [r[1] for r in db.execute("PRAGMA table_info(incoming_invoices)").fetchall()]
    ben_cols    = [r[1] for r in db.execute("PRAGMA table_info(beneficiaries)").fetchall()]
    camp_cols   = [r[1] for r in db.execute("PRAGMA table_info(camp_entities)").fetchall()]

    print(f"✅ تحقق من Schema — organizations: {orgs_cols[:5]}...")

    # ══════════════════════════════════════════
    # 1. المؤسسة الأولى
    # ══════════════════════════════════════════
    row = db.execute("SELECT id FROM organizations WHERE email='rahma@relief.org'").fetchone()
    if not row:
        # أدرج فقط الأعمدة الموجودة
        base = {"name": "جمعية الرحمة للإغاثة", "email": "rahma@relief.org", "org_code": "RAHMA01"}
        extra = {}
        if "phone"       in orgs_cols: extra["phone"]       = "0911234567"
        if "address"     in orgs_cols: extra["address"]     = "دمشق - الميدان"
        if "area"        in orgs_cols: extra["area"]        = "دمشق"
        if "is_active"   in orgs_cols: extra["is_active"]   = 1
        if "is_verified" in orgs_cols: extra["is_verified"] = 1
        all_data = {**base, **extra}
        cols_str = ", ".join(all_data.keys())
        vals_str = ", ".join(["?"] * len(all_data))
        db.execute(f"INSERT INTO organizations ({cols_str}) VALUES ({vals_str})", list(all_data.values()))
        db.commit()
        org1_id = db.execute("SELECT id FROM organizations WHERE email='rahma@relief.org'").fetchone()["id"]
        print(f"✅ المؤسسة 1: جمعية الرحمة للإغاثة (id={org1_id})")
    else:
        org1_id = row["id"]
        print(f"ℹ️  المؤسسة 1 موجودة (id={org1_id})")

    # مدير المؤسسة 1
    if not db.execute("SELECT id FROM users WHERE email='admin@rahma.org'").fetchone():
        udata = {"org_id": org1_id, "username": "admin_rahma",
                 "password": generate_password_hash("Rahma@2024"),
                 "full_name": "أحمد محمود السيد", "role": "admin", "status": "approved"}
        if "email" in users_cols: udata["email"] = "admin@rahma.org"
        cols_str = ", ".join(udata.keys())
        vals_str = ", ".join(["?"] * len(udata))
        db.execute(f"INSERT INTO users ({cols_str}) VALUES ({vals_str})", list(udata.values()))
        db.commit()
        print("✅ مدير المؤسسة 1: admin@rahma.org / Rahma@2024")

    # موظف بيانات
    if not db.execute("SELECT id FROM users WHERE email='data@rahma.org'").fetchone():
        udata = {"org_id": org1_id, "username": "data_rahma",
                 "password": generate_password_hash("Data@2024"),
                 "full_name": "سارة عبد الله حسن", "role": "data_entry", "status": "approved"}
        if "email" in users_cols: udata["email"] = "data@rahma.org"
        cols_str = ", ".join(udata.keys())
        vals_str = ", ".join(["?"] * len(udata))
        db.execute(f"INSERT INTO users ({cols_str}) VALUES ({vals_str})", list(udata.values()))
        db.commit()
        print("✅ موظف بيانات: data@rahma.org / Data@2024")

    # ══════════════════════════════════════════
    # 2. المؤسسة الثانية
    # ══════════════════════════════════════════
    row = db.execute("SELECT id FROM organizations WHERE email='amal@ngo.org'").fetchone()
    if not row:
        base = {"name": "منظمة أمل للتنمية", "email": "amal@ngo.org", "org_code": "AMAL02"}
        extra = {}
        if "phone"       in orgs_cols: extra["phone"]       = "0921234567"
        if "area"        in orgs_cols: extra["area"]        = "حلب"
        if "is_active"   in orgs_cols: extra["is_active"]   = 1
        if "is_verified" in orgs_cols: extra["is_verified"] = 1
        all_data = {**base, **extra}
        cols_str = ", ".join(all_data.keys())
        vals_str = ", ".join(["?"] * len(all_data))
        db.execute(f"INSERT INTO organizations ({cols_str}) VALUES ({vals_str})", list(all_data.values()))
        db.commit()
        org2_id = db.execute("SELECT id FROM organizations WHERE email='amal@ngo.org'").fetchone()["id"]
        print(f"✅ المؤسسة 2: منظمة أمل للتنمية (id={org2_id})")
    else:
        org2_id = row["id"]
        print(f"ℹ️  المؤسسة 2 موجودة (id={org2_id})")

    if not db.execute("SELECT id FROM users WHERE email='admin@amal.org'").fetchone():
        udata = {"org_id": org2_id, "username": "admin_amal",
                 "password": generate_password_hash("Amal@2024"),
                 "full_name": "خالد يوسف النور", "role": "admin", "status": "approved"}
        if "email" in users_cols: udata["email"] = "admin@amal.org"
        cols_str = ", ".join(udata.keys())
        vals_str = ", ".join(["?"] * len(udata))
        db.execute(f"INSERT INTO users ({cols_str}) VALUES ({vals_str})", list(udata.values()))
        db.commit()
        print("✅ مدير المؤسسة 2: admin@amal.org / Amal@2024")

    # ══════════════════════════════════════════
    # 3. المخيم
    # ══════════════════════════════════════════
    row = db.execute("SELECT id FROM camp_entities WHERE email='nour@camp.sy'").fetchone()
    if not row:
        cdata = {
            "name": "مخيم النور للنازحين",
            "manager_name": "محمد خالد العمر",
            "email": "nour@camp.sy",
            "password": generate_password_hash("Camp@2024"),
            "is_active": 1,
        }
        if "entity_type"  in camp_cols: cdata["entity_type"]  = "camp"
        if "mobile"       in camp_cols: cdata["mobile"]       = "0931234567"
        if "governorate"  in camp_cols: cdata["governorate"]  = "دمشق"
        if "city"         in camp_cols: cdata["city"]         = "جرمانا"
        cols_str = ", ".join(cdata.keys())
        vals_str = ", ".join(["?"] * len(cdata))
        db.execute(f"INSERT INTO camp_entities ({cols_str}) VALUES ({vals_str})", list(cdata.values()))
        db.commit()
        camp1_id = db.execute("SELECT id FROM camp_entities WHERE email='nour@camp.sy'").fetchone()["id"]
        print(f"✅ المخيم: مخيم النور للنازحين (id={camp1_id})")
    else:
        camp1_id = row["id"]
        print(f"ℹ️  المخيم موجود (id={camp1_id})")

    # ══════════════════════════════════════════
    # 4. المنتجات والمخزون
    # ══════════════════════════════════════════
    products_data = [
        ("طحين 25 كغ", "كيس"), ("زيت نباتي 5 لتر", "عبوة"),
        ("سكر 5 كغ", "كيس"), ("بطانيات شتوية", "قطعة"), ("حفاضات أطفال", "كرتون"),
    ]
    prod_ids = []
    for pname, unit in products_data:
        row = db.execute("SELECT id FROM products WHERE name=? AND org_id=?", (pname, org1_id)).fetchone()
        if not row:
            pdata = {"org_id": org1_id, "name": pname, "unit": unit}
            if "min_stock" in prods_cols: pdata["min_stock"] = 10
            if "category"  in prods_cols: pdata["category"]  = "غذاء"
            cols_str = ", ".join(pdata.keys())
            vals_str = ", ".join(["?"] * len(pdata))
            db.execute(f"INSERT INTO products ({cols_str}) VALUES ({vals_str})", list(pdata.values()))
            db.commit()
            pid = db.execute("SELECT id FROM products WHERE name=? AND org_id=?", (pname, org1_id)).fetchone()["id"]
        else:
            pid = row["id"]
        prod_ids.append(pid)
    print(f"✅ {len(prod_ids)} منتجات")

    # فاتورة واردة
    if not db.execute("SELECT id FROM incoming_invoices WHERE org_id=? LIMIT 1", (org1_id,)).fetchone():
        # تحديد اسم عمود المورد والإجمالي والحالة
        sup_col   = "supplier_name" if "supplier_name" in inv_cols else "supplier"
        total_col = "total_amount"  if "total_amount"  in inv_cols else "grand_total"

        inv_data = {"org_id": org1_id, "invoice_number": "INV-RAHMA-001",
                    "invoice_date": "2024-11-01", "notes": "دفعة إغاثة الشتاء"}
        inv_data[sup_col]   = "شركة الوفاء للتوريد"
        inv_data[total_col] = 2500000

        if "status"    in inv_cols: inv_data["status"]    = "closed"
        if "is_closed" in inv_cols: inv_data["is_closed"] = 1

        cols_str = ", ".join(inv_data.keys())
        vals_str = ", ".join(["?"] * len(inv_data))
        db.execute(f"INSERT INTO incoming_invoices ({cols_str}) VALUES ({vals_str})", list(inv_data.values()))
        db.commit()
        inv_id = db.execute("SELECT id FROM incoming_invoices WHERE org_id=? LIMIT 1", (org1_id,)).fetchone()["id"]

        qtys   = [50, 40, 60, 30, 25]
        prices = [12500, 25000, 8000, 35000, 18000]
        for i, pid in enumerate(prod_ids):
            qty, price = qtys[i], prices[i]
            # items
            item_data = {"invoice_id": inv_id, "product_id": pid,
                         "quantity": qty, "unit_price": price}
            if "total_price" in [r[1] for r in db.execute("PRAGMA table_info(incoming_invoice_items)").fetchall()]:
                item_data["total_price"] = qty * price
            elif "total" in [r[1] for r in db.execute("PRAGMA table_info(incoming_invoice_items)").fetchall()]:
                item_data["total"] = qty * price
            cols_str = ", ".join(item_data.keys())
            vals_str = ", ".join(["?"] * len(item_data))
            db.execute(f"INSERT INTO incoming_invoice_items ({cols_str}) VALUES ({vals_str})", list(item_data.values()))

            # مخزون
            sb_data = {"product_id": pid, "org_id": org1_id,
                       "quantity_remaining": qty, "unit_price": price}
            if "quantity_in" in stock_cols: sb_data["quantity_in"] = qty
            if "source"      in stock_cols: sb_data["source"]      = "فاتورة واردة"
            if "entry_date"  in stock_cols: sb_data["entry_date"]  = "2024-11-01"
            cols_str = ", ".join(sb_data.keys())
            vals_str = ", ".join(["?"] * len(sb_data))
            db.execute(f"INSERT INTO stock_batches ({cols_str}) VALUES ({vals_str})", list(sb_data.values()))
        db.commit()
        print("✅ فاتورة واردة + مخزون")

    # ══════════════════════════════════════════
    # 5. المستفيدون
    # ══════════════════════════════════════════
    beneficiaries_input = [
        {"full_name": "محمد حسن علي الأحمد",         "id_number": "9001234567", "phone": "0941234561",
         "family_size": 6, "has_orphans": 1, "orphans_count": 2, "in_camp": True},
        {"full_name": "أحمد سليم ناصر الخطيب",        "id_number": "9002345678", "phone": "0941234562",
         "family_size": 4, "wife_pregnant": 1, "in_camp": True},
        {"full_name": "خالد محمود ريد العمر",          "id_number": "9003456789", "phone": "0941234563",
         "family_size": 8, "has_orphans": 1, "orphans_count": 3, "in_camp": True},
        {"full_name": "سامر عبد الرحمن يوسف السعيد",  "id_number": "9004567890", "phone": "0941234564",
         "family_size": 5, "wife_nursing": 1, "in_camp": False},
        {"full_name": "عمر فريد جابر النعسان",         "id_number": "9005678901", "phone": "0941234565",
         "family_size": 3, "in_camp": False},
    ]

    ben_ids = []
    for bd in beneficiaries_input:
        row = db.execute("SELECT id FROM beneficiaries WHERE id_number=?", (bd["id_number"],)).fetchone()
        if not row:
            parts = bd["full_name"].split()
            last_name = parts[3] if len(parts) >= 4 else parts[-1]
            bdata = {
                "org_id": org1_id, "full_name": bd["full_name"],
                "id_number": bd["id_number"], "phone": bd["phone"],
                "gender": "male", "family_size": bd["family_size"],
                "has_orphans": bd.get("has_orphans", 0),
                "orphans_count": bd.get("orphans_count", 0),
                "wife_pregnant": bd.get("wife_pregnant", 0),
                "wife_nursing": bd.get("wife_nursing", 0),
            }
            if "family_last_name"   in ben_cols: bdata["family_last_name"]   = last_name
            if "governorate"        in ben_cols: bdata["governorate"]        = "دمشق"
            if "city"               in ben_cols: bdata["city"]               = "جرمانا"
            if "beneficiary_type"   in ben_cols: bdata["beneficiary_type"]   = "person"
            if "beneficiary_status" in ben_cols: bdata["beneficiary_status"] = "active"
            if "self_registered"    in ben_cols: bdata["self_registered"]    = 0
            if bd.get("in_camp") and "camp_entity_id" in ben_cols:
                bdata["camp_entity_id"] = camp1_id

            cols_str = ", ".join(bdata.keys())
            vals_str = ", ".join(["?"] * len(bdata))
            db.execute(f"INSERT INTO beneficiaries ({cols_str}) VALUES ({vals_str})", list(bdata.values()))
            db.commit()
            bid = db.execute("SELECT id FROM beneficiaries WHERE id_number=?", (bd["id_number"],)).fetchone()["id"]
            # ربط بالمؤسسة
            try:
                db.execute("INSERT OR IGNORE INTO org_beneficiary_links (org_id, beneficiary_id) VALUES (?,?)",
                           (org1_id, bid))
                db.commit()
            except Exception:
                pass
            print(f"✅ مستفيد: {bd['full_name']}")
        else:
            bid = row["id"]
            print(f"ℹ️  موجود: {bd['full_name']}")
        ben_ids.append(bid)

    # ربط المستفيد الخامس بالمؤسسة 2 أيضاً
    try:
        db.execute("INSERT OR IGNORE INTO org_beneficiary_links (org_id, beneficiary_id) VALUES (?,?)",
                   (org2_id, ben_ids[4]))
        db.commit()
        print("✅ ربط المستفيد 5 بالمؤسسة 2 (اختبار التوحيد)")
    except Exception as e:
        print(f"  ⚠️  org_beneficiary_links: {e}")

    # ══════════════════════════════════════════
    # 6. مستفيد مسجّل ذاتياً
    # ══════════════════════════════════════════
    if not db.execute("SELECT id FROM beneficiaries WHERE id_number='9099887766'").fetchone():
        bdata = {
            "org_id": 1, "full_name": "نور محمد أحمد الزهراء",
            "id_number": "9099887766", "phone": "0941111111",
            "gender": "female", "family_size": 3,
        }
        if "family_last_name"   in ben_cols: bdata["family_last_name"]   = "الزهراء"
        if "beneficiary_type"   in ben_cols: bdata["beneficiary_type"]   = "person"
        if "beneficiary_status" in ben_cols: bdata["beneficiary_status"] = "independent"
        if "self_registered"    in ben_cols: bdata["self_registered"]    = 1
        if "self_reg_password"  in ben_cols: bdata["self_reg_password"]  = generate_password_hash("Nour@2024")
        if "governorate"        in ben_cols: bdata["governorate"]        = "دمشق"
        if "city"               in ben_cols: bdata["city"]               = "جرمانا"
        cols_str = ", ".join(bdata.keys())
        vals_str = ", ".join(["?"] * len(bdata))
        db.execute(f"INSERT INTO beneficiaries ({cols_str}) VALUES ({vals_str})", list(bdata.values()))
        db.commit()
        self_bid = db.execute("SELECT id FROM beneficiaries WHERE id_number='9099887766'").fetchone()["id"]
        try:
            db.execute("INSERT OR IGNORE INTO org_beneficiary_links (org_id, beneficiary_id) VALUES (?,?)",
                       (org1_id, self_bid))
            db.commit()
        except Exception:
            pass
        print("✅ مستفيد ذاتي: 9099887766 / Nour@2024")

    # ══════════════════════════════════════════
    # 7. برنامج وسجلات استفادة
    # ══════════════════════════════════════════
    prog_cols = [r[1] for r in db.execute("PRAGMA table_info(programs)").fetchall()]
    row = db.execute("SELECT id FROM programs WHERE org_id=? AND name='برنامج السلة الغذائية'", (org1_id,)).fetchone()
    if not row:
        pdata = {"org_id": org1_id, "name": "برنامج السلة الغذائية", "is_active": 1}
        if "description" in prog_cols: pdata["description"] = "توزيع سلة غذائية شهرية"
        cols_str = ", ".join(pdata.keys())
        vals_str = ", ".join(["?"] * len(pdata))
        db.execute(f"INSERT INTO programs ({cols_str}) VALUES ({vals_str})", list(pdata.values()))
        db.commit()
        prog_id = db.execute("SELECT id FROM programs WHERE org_id=? AND name='برنامج السلة الغذائية'", (org1_id,)).fetchone()["id"]
        print("✅ برنامج: السلة الغذائية")
    else:
        prog_id = row["id"]

    for i, bid in enumerate(ben_ids[:3]):
        if not db.execute("SELECT id FROM program_records WHERE program_id=? AND beneficiary_id=?",
                          (prog_id, bid)).fetchone():
            db.execute("""INSERT INTO program_records
                (org_id, program_id, beneficiary_id, benefit_date, benefit_type, quantity, notes)
                VALUES (?,?,?,?,?,?,?)""",
                (org1_id, prog_id, bid, f"2024-{11+i:02d}-15", "سلة غذائية", "1 سلة", "توزيع شهري"))
    db.commit()

    # ══════════════════════════════════════════
    # 8. توزيع في المخيم
    # ══════════════════════════════════════════
    dist_cols = [r[1] for r in db.execute("PRAGMA table_info(camp_distributions)").fetchall()]
    if not db.execute("SELECT id FROM camp_distributions WHERE camp_entity_id=?", (camp1_id,)).fetchone():
        ddata = {"camp_entity_id": camp1_id, "title": "توزيع الشتاء الأول",
                 "distribution_date": "2024-12-01", "status": "closed", "notes": "بطانيات ومستلزمات"}
        if "donor_name" in dist_cols: ddata["donor_name"] = "جمعية الرحمة للإغاثة"
        cols_str = ", ".join(ddata.keys())
        vals_str = ", ".join(["?"] * len(ddata))
        db.execute(f"INSERT INTO camp_distributions ({cols_str}) VALUES ({vals_str})", list(ddata.values()))
        db.commit()
        dist_id = db.execute("SELECT id FROM camp_distributions WHERE camp_entity_id=?", (camp1_id,)).fetchone()["id"]
        camp_bens = ben_ids[:3]
        for bid in camp_bens:
            try:
                db.execute("""INSERT OR IGNORE INTO camp_dist_records
                    (distribution_id, camp_entity_id, beneficiary_id, item_name, quantity, value, received)
                    VALUES (?,?,?,?,?,?,1)""",
                    (dist_id, camp1_id, bid, "بطانية شتوية + حقيبة إغاثة", "1 طقم", "35000"))
            except Exception as e:
                print(f"  ⚠️  dist_record: {e}")
        db.commit()
        print(f"✅ توزيع المخيم: {len(camp_bens)} مستفيد")

    # ══════════════════════════════════════════
    # 9. نشاط في المخيم
    # ══════════════════════════════════════════
    if not db.execute("SELECT id FROM camp_activities WHERE camp_entity_id=?", (camp1_id,)).fetchone():
        try:
            db.execute("""INSERT INTO camp_activities
                (camp_entity_id, activity_date, title, description, activity_type)
                VALUES (?,?,?,?,?)""",
                (camp1_id, "2024-12-05", "فحص طبي مجاني",
                 "زيارة فريق طبي تطوعي لفحص سكان المخيم", "medical"))
            db.commit()
            print("✅ نشاط: فحص طبي مجاني")
        except Exception as e:
            print(f"  ⚠️  activity: {e}")

    # ══════════════════════════════════════════
    # 10. طلب انضمام معلّق
    # ══════════════════════════════════════════
    if not db.execute("SELECT id FROM camp_join_requests WHERE beneficiary_id=? AND camp_entity_id=?",
                      (ben_ids[3], camp1_id)).fetchone():
        try:
            db.execute("INSERT INTO camp_join_requests (beneficiary_id, camp_entity_id, status) VALUES (?,?,'pending')",
                       (ben_ids[3], camp1_id))
            db.commit()
            print("✅ طلب انضمام معلّق (المستفيد 4)")
        except Exception as e:
            print(f"  ⚠️  join_request: {e}")

    db.close()

    print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("🏢 المؤسسة 1 (مدير):    admin@rahma.org  / Rahma@2024")
    print("🏢 المؤسسة 1 (بيانات):  data@rahma.org   / Data@2024")
    print("🏢 المؤسسة 2 (مدير):    admin@amal.org   / Amal@2024")
    print("🏕️  المخيم:              nour@camp.sy     / Camp@2024")
    print("👤 مستفيد ذاتي:         هوية 9099887766  / Nour@2024")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

if __name__ == "__main__":
    run()
