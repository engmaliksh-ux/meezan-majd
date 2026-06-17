"""
خدمة الإيميل عبر SendGrid API
================================
الإعداد (مجاني - 100 إيميل/يوم):
1. سجّل مجاناً على sendgrid.com
2. Settings → API Keys → Create API Key → Full Access
3. في PythonAnywhere: Web → Environment variables
   أضف: SENDGRID_API_KEY = مفتاحك
        SENDER_EMAIL     = إيميلك الموثّق
4. Settings → Sender Authentication → Single Sender Verification
"""
import os
import requests
import re
import secrets
import string

# ═══════════════════════════════════════════════════════
# ✅ الأمان: المفاتيح تُقرأ من متغيرات البيئة فقط
#    لا تضع أي مفتاح مباشرة في الكود!
# ═══════════════════════════════════════════════════════
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
SENDER_EMAIL     = os.environ.get("SENDER_EMAIL", "")
SENDER_NAME      = "مخزن الخير"
# ═══════════════════════════════════════════════════════

DEV_MODE = not SENDGRID_API_KEY
SENDGRID_URL = "https://api.sendgrid.com/v3/mail/send"


def generate_verification_code(length=6):
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def _send(to_email: str, to_name: str, subject: str, html: str) -> bool:
    if DEV_MODE:
        codes = re.findall(r'font-family:monospace[^>]*>([0-9]{6})<', html)
        print("\n" + "="*55)
        print(f"  [DEV] إيميل إلى : {to_email}")
        if codes:
            print(f"\n  >>>  كود التحقق : {codes[0]}  <<<\n")
        print("="*55 + "\n")
        return True

    try:
        resp = requests.post(
            SENDGRID_URL,
            json={
                "personalizations": [{"to": [{"email": to_email, "name": to_name}]}],
                "from": {"email": SENDER_EMAIL, "name": SENDER_NAME},
                "subject": subject,
                "content": [{"type": "text/html", "value": html}],
            },
            headers={
                "Authorization": f"Bearer {SENDGRID_API_KEY}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        success = resp.status_code == 202
        if not success:
            print(f"[SendGrid Error] {resp.status_code}: {resp.text[:200]}")
        return success
    except Exception as e:
        print(f"[Email Error] {e}")
        return False


def send_org_verification(to_email, org_name, admin_name, code, org_code, username):
    subject = f"تأكيد تسجيل {org_name} في مخزن الخير"
    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8">
<style>
  body{{font-family:Arial,sans-serif;background:#f4f7f5;margin:0;padding:20px;direction:rtl;}}
  .box{{max-width:520px;margin:0 auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1);}}
  .hd{{background:linear-gradient(135deg,#1a6b3a,#2d9e5a);padding:28px 24px;text-align:center;color:#fff;}}
  .hd h2{{margin:0;font-size:20px;}}
  .bd{{padding:24px;}}
  .code-box{{background:#f4f7f5;border:2px dashed #1a6b3a;border-radius:12px;padding:20px;text-align:center;margin:18px 0;}}
  .code-val{{font-size:38px;font-weight:900;color:#1a6b3a;letter-spacing:8px;font-family:monospace;}}
  .code-exp{{font-size:12px;color:#f0a500;margin-top:6px;}}
  .info{{background:#e8f5ee;border-radius:10px;padding:14px 16px;margin:14px 0;}}
  .row{{display:flex;justify-content:space-between;padding:5px 0;font-size:13px;border-bottom:1px solid #d8e8de;}}
  .row:last-child{{border-bottom:none;}}
  .org-code{{font-size:1.4rem;font-weight:900;letter-spacing:3px;font-family:monospace;color:#1a6b3a;}}
  .warn{{background:#fff3cd;border-radius:8px;padding:10px 14px;font-size:12px;color:#856404;margin:14px 0;}}
  .ft{{background:#f4f7f5;padding:14px;text-align:center;font-size:11px;color:#aaa;}}
</style></head>
<body>
<div class="box">
  <div class="hd"><h2>🏪 مخزن الخير</h2><p>تأكيد تسجيل المؤسسة</p></div>
  <div class="bd">
    <p>مرحباً <strong>{admin_name}</strong>،</p>
    <p style="font-size:13px;color:#6c7a72;">أدخل كود التحقق لإتمام تسجيل <strong>{org_name}</strong>:</p>
    <div class="code-box">
      <div style="font-size:13px;color:#6c7a72;margin-bottom:8px;">كود التحقق</div>
      <div class="code-val">{code}</div>
      <div class="code-exp">⏱ صالح لمدة 3 دقائق فقط</div>
    </div>
    <div class="info">
      <div style="font-weight:700;margin-bottom:8px;color:#1a6b3a;">📋 بيانات حسابك</div>
      <div class="row"><span style="color:#6c7a72;">المؤسسة</span><strong>{org_name}</strong></div>
      <div class="row"><span style="color:#6c7a72;">اسم المستخدم</span><strong>{username}</strong></div>
      <div class="row"><span style="color:#6c7a72;">رمز المؤسسة</span><strong class="org-code">{org_code}</strong></div>
    </div>
    <div class="warn">⚠️ احفظ رمز المؤسسة <strong>({org_code})</strong> — يحتاجه موظفوك عند التسجيل والدخول.</div>
  </div>
  <div class="ft">مخزن الخير – نظام إدارة المخزون الخيري</div>
</div>
</body></html>"""
    return _send(to_email, admin_name, subject, html)


def send_staff_notification(to_email, admin_name, staff_name, staff_role, org_name):
    role_ar = "محاسب" if staff_role == "accountant" else "مدخل بيانات"
    subject = f"طلب تسجيل جديد في {org_name}"
    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8">
<style>
  body{{font-family:Arial,sans-serif;background:#f4f7f5;margin:0;padding:20px;direction:rtl;}}
  .box{{max-width:480px;margin:0 auto;background:#fff;border-radius:14px;overflow:hidden;}}
  .hd{{background:linear-gradient(135deg,#d4880a,#f0a500);padding:22px 24px;text-align:center;color:#fff;}}
  .bd{{padding:22px;}}
  .card{{background:#f4f7f5;border-radius:10px;padding:14px;margin:14px 0;}}
  .row{{display:flex;justify-content:space-between;padding:5px 0;font-size:13px;border-bottom:1px solid #e0e0e0;}}
  .row:last-child{{border-bottom:none;}}
  .ft{{background:#f4f7f5;padding:12px;text-align:center;font-size:11px;color:#aaa;}}
</style></head>
<body>
<div class="box">
  <div class="hd"><h2 style="margin:0;">🔔 طلب تسجيل جديد</h2></div>
  <div class="bd">
    <p>مرحباً <strong>{admin_name}</strong>،</p>
    <div class="card">
      <div class="row"><span style="color:#6c7a72;">الاسم</span><strong>{staff_name}</strong></div>
      <div class="row"><span style="color:#6c7a72;">الدور</span><strong>{role_ar}</strong></div>
      <div class="row"><span style="color:#6c7a72;">المؤسسة</span><strong>{org_name}</strong></div>
    </div>
    <p style="font-size:12px;color:#6c7a72;">سجّل الدخول للوحة التحكم للموافقة أو الرفض.</p>
  </div>
  <div class="ft">مخزن الخير – نظام إدارة المخزون الخيري</div>
</div>
</body></html>"""
    return _send(to_email, admin_name, subject, html)
