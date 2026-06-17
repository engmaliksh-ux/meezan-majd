import os

html = r"""{% extends 'base.html' %}
{% block title %}المشتريات – ميزان مجد{% endblock %}
{% block content %}

<div class="page-header">
  <h2 class="page-title"><i class="fas fa-cart-shopping"></i> المشتريات</h2>
  <button type="button" class="btn btn-primary" id="toggle-add-invoice">
    <i class="fas fa-plus me-1"></i> إضافة فاتورة جديدة
  </button>
</div>

<div class="card mb-4" id="add-invoice-card" style="display:none;">
  <div class="card-header"><i class="fas fa-file-invoice" style="color:#1565c0;"></i> فاتورة مشتريات جديدة</div>
  <div class="card-body">
    <form method="POST" action="/incoming_invoice" enctype="multipart/form-data">
      <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
      <div class="row g-3 mb-3">
        <div class="col-md-4">
          <label class="form-label">رقم الفاتورة <span class="text-danger">*</span></label>
          <input class="form-control" name="invoice_number" placeholder="INV-001" required>
        </div>
        <div class="col-md-4">
          <label class="form-label">المورد <span class="text-danger">*</span></label>
          <input class="form-control" name="supplier" placeholder="اسم المورد" required>
        </div>
        <div class="col-md-4">
          <label class="form-label">صورة الفاتورة <span style="color:#aaa;font-size:.74rem;">(اختياري)</span></label>
          <input type="file" class="form-control" name="invoice_image" accept="image/png,image/jpeg,image/webp">
        </div>
      </div>
      <div class="table-responsive">
        <table class="table table-bordered m-0">
          <thead>
            <tr>
              <th style="width:28%;">اسم الصنف</th>
              <th style="width:12%;">الوحدة</th>
              <th>الكمية</th>
              <th>سعر الوحدة</th>
              <th>التاريخ</th>
              <th>الإجمالي</th>
              <th style="width:50px;"></th>
            </tr>
          </thead>
          <tbody id="new-items-body">
            <tr class="item-row">
              <td><input type="text" class="form-control form-control-sm pname" name="product_name[]" list="products-datalist" placeholder="اسم الصنف..." required></td>
              <td><input type="text" class="form-control form-control-sm unit-input" name="product_unit[]" placeholder="كيلو..."></td>
              <td><input type="number" class="form-control form-control-sm qty-input" name="quantity[]" step="0.01" min="0.01" placeholder="0" required></td>
              <td><input type="number" class="form-control form-control-sm price-input" name="unit_price[]" step="0.01" min="0" placeholder="0.00" required></td>
              <td><input type="date" class="form-control form-control-sm" name="purchase_date[]" value="{{ today_str }}" required></td>
              <td><input type="text" class="form-control form-control-sm row-total" readonly placeholder="0.00" style="background:#f8f9fa;"></td>
              <td class="text-center"><button type="button" class="btn btn-danger btn-sm remove-row" disabled><i class="fas fa-times"></i></button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <datalist id="products-datalist">
        {% for p in existing_products %}
        <option value="{{ p.name }}" data-unit="{{ p.unit }}">{{ p.unit }}</option>
        {% endfor %}
      </datalist>
      <div class="d-flex justify-content-between align-items-center mt-3">
        <button type="button" class="btn btn-outline-primary btn-sm" id="add-row-btn"><i class="fas fa-plus me-1"></i> إضافة صنف</button>
        <div style="font-weight:700;">الإجمالي: <span id="grand-total" style="color:#1a6b3a;font-size:1.1rem;margin-right:6px;">0.00</span></div>
      </div>
      <div class="mt-3">
        <button type="submit" class="btn btn-primary"><i class="fas fa-save me-1"></i> حفظ الفاتورة</button>
      </div>
    </form>
  </div>
</div>

{% if invoices %}
{% for inv in invoices %}
<div class="invoice-report-card {% if inv.is_closed %}invoice-closed{% endif %}">
  <div class="invoice-report-header">
    <div class="invoice-report-title">
      <i class="fas fa-file-invoice me-2" style="color:#1565c0;"></i>
      فاتورة رقم <strong>{{ inv.invoice_number }}</strong>
      <span class="invoice-supplier">— المورد: {{ inv.supplier }}</span>
      <span style="font-size:.78rem;color:#aaa;margin-right:8px;">{{ inv.created_at[:10] if inv.created_at else '' }}</span>
    </div>
    <div>
      {% if inv.is_closed %}
      <span class="badge invoice-badge-closed"><i class="fas fa-lock me-1"></i>مغلقة</span>
      {% else %}
      <span class="badge invoice-badge-open"><i class="fas fa-lock-open me-1"></i>مفتوحة</span>
      {% endif %}
    </div>
  </div>
  <div class="table-responsive">
    <table class="table table-sm table-hover m-0">
      <thead><tr><th>الصنف</th><th>الكمية</th><th>سعر الوحدة</th><th>التاريخ</th><th>الإجمالي</th></tr></thead>
      <tbody>
        {% for item in inv.lines %}
        <tr>
          <td style="font-weight:700;text-align:right;">{{ item.product_name }}</td>
          <td>{{ "%.2f"|format(item.quantity) }}</td>
          <td>{{ "%.2f"|format(item.unit_price) }}</td>
          <td>{{ item.purchase_date or '—' }}</td>
          <td class="fw-bold" style="color:#1a6b3a;">{{ "%.2f"|format(item.total_price) }}</td>
        </tr>
        {% else %}
        <tr><td colspan="5" class="text-center text-muted py-3">لا توجد أصناف</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  {% if not inv.is_closed %}
  <div class="add-items-section">
    <div class="add-items-title"><i class="fas fa-plus-circle me-1"></i> إضافة أصناف لهذه الفاتورة</div>
    <form method="POST" action="/incoming_invoice/{{ inv.id }}/add_items">
      <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
      <div class="table-responsive">
        <table class="table table-bordered table-sm m-0">
          <thead><tr><th style="width:28%;">اسم الصنف</th><th style="width:12%;">الوحدة</th><th>الكمية</th><th>سعر الوحدة</th><th>التاريخ</th><th>الإجمالي</th><th style="width:50px;"></th></tr></thead>
          <tbody id="add-items-body-{{ inv.id }}">
            <tr class="item-row">
              <td><input type="text" class="form-control form-control-sm pname" name="product_name[]" list="products-datalist" placeholder="اسم الصنف..." required></td>
              <td><input type="text" class="form-control form-control-sm unit-input" name="product_unit[]" placeholder="كيلو..."></td>
              <td><input type="number" class="form-control form-control-sm qty-input" name="quantity[]" step="0.01" min="0.01" placeholder="0" required></td>
              <td><input type="number" class="form-control form-control-sm price-input" name="unit_price[]" step="0.01" min="0" placeholder="0.00" required></td>
              <td><input type="date" class="form-control form-control-sm" name="purchase_date[]" value="{{ today_str }}" required></td>
              <td><input type="text" class="form-control form-control-sm row-total" readonly placeholder="0.00" style="background:#f8f9fa;"></td>
              <td class="text-center"><button type="button" class="btn btn-danger btn-sm remove-row" disabled><i class="fas fa-times"></i></button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="d-flex justify-content-between mt-2">
        <button type="button" class="btn btn-outline-primary btn-sm add-row-btn-inv" data-inv="{{ inv.id }}"><i class="fas fa-plus me-1"></i> إضافة صنف</button>
        <div style="font-weight:700;font-size:.9rem;">إجمالي الإضافة: <span class="add-total-inv" data-inv="{{ inv.id }}" style="color:#1a6b3a;">0.00</span></div>
      </div>
      <div class="mt-2">
        <button type="submit" class="btn btn-primary btn-sm"><i class="fas fa-save me-1"></i> حفظ الأصناف</button>
      </div>
    </form>
  </div>
  {% endif %}

  <div class="invoice-image-section">
    <div class="invoice-image-title"><i class="fas fa-camera me-1"></i> صورة الفاتورة</div>
    {% if inv.invoice_image %}
    <a href="{{ url_for('static', filename='uploads/' + inv.invoice_image) }}" target="_blank">
      <img src="{{ url_for('static', filename='uploads/' + inv.invoice_image) }}" class="invoice-image-thumb" alt="صورة الفاتورة">
    </a>
    {% else %}
    <span class="text-muted" style="font-size:.82rem;">لم يتم إرفاق صورة</span>
    {% endif %}
    <form method="POST" action="/incoming_invoice/{{ inv.id }}/upload_image" enctype="multipart/form-data" class="invoice-image-form">
      <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
      <input type="file" name="invoice_image" accept="image/png,image/jpeg,image/webp" class="form-control form-control-sm">
      <button type="submit" class="btn btn-secondary btn-sm"><i class="fas fa-upload me-1"></i> {{ 'تغيير' if inv.invoice_image else 'رفع الصورة' }}</button>
    </form>
  </div>

  <div class="invoice-total-row">
    <div class="invoice-total-value"><i class="fas fa-coins me-1" style="color:#f0a500;"></i> إجمالي الفاتورة: <span>{{ "%.2f"|format(inv.total) }}</span></div>
    {% if inv.is_closed %}
    <span class="badge invoice-badge-closed" style="font-size:.85rem;padding:8px 14px;"><i class="fas fa-lock me-1"></i>مغلقة نهائياً</span>
    {% else %}
    <a href="/incoming_invoice/{{ inv.id }}/close" class="btn btn-danger btn-sm" onclick="return confirm('سيتم إغلاق الفاتورة نهائياً. هل أنت متأكد؟')"><i class="fas fa-lock me-1"></i> إغلاق الفاتورة</a>
    {% endif %}
  </div>
</div>
{% endfor %}
{% else %}
<div class="text-center py-5" style="color:#6c7a72;">
  <i class="fas fa-file-invoice fa-3x mb-3" style="color:#d8e8de;"></i>
  <p class="fw-bold">لا توجد فواتير مشتريات حتى الآن</p>
</div>
{% endif %}

<div class="total-purchases-box">
  <i class="fas fa-warehouse me-2"></i> إجمالي سعر المشتريات لحد الآن
  <span class="total-purchases-value">{{ "%.2f"|format(total_purchases) }}</span>
</div>

{% endblock %}

{% block scripts %}
<script>
const todayStr = "{{ today_str }}";
function newRow() {
  return '<tr class="item-row">'
    + '<td><input type="text" class="form-control form-control-sm pname" name="product_name[]" list="products-datalist" placeholder="اسم الصنف..." required></td>'
    + '<td><input type="text" class="form-control form-control-sm unit-input" name="product_unit[]" placeholder="كيلو..."></td>'
    + '<td><input type="number" class="form-control form-control-sm qty-input" name="quantity[]" step="0.01" min="0.01" placeholder="0" required></td>'
    + '<td><input type="number" class="form-control form-control-sm price-input" name="unit_price[]" step="0.01" min="0" placeholder="0.00" required></td>'
    + '<td><input type="date" class="form-control form-control-sm" name="purchase_date[]" value="' + todayStr + '" required></td>'
    + '<td><input type="text" class="form-control form-control-sm row-total" readonly placeholder="0.00" style="background:#f8f9fa;"></td>'
    + '<td class="text-center"><button type="button" class="btn btn-danger btn-sm remove-row"><i class="fas fa-times"></i></button></td>'
    + '</tr>';
}
function setupTable(tbodyId, addBtnId, totId) {
  const tbody = document.getElementById(tbodyId);
  const addBtn = document.getElementById(addBtnId);
  const totEl = totId ? document.getElementById(totId) : null;
  if (!tbody || !addBtn) return;
  function calcTotal() {
    if (!totEl) return;
    let t = 0;
    tbody.querySelectorAll('.row-total').forEach(e => t += parseFloat(e.value) || 0);
    totEl.textContent = t.toFixed(2);
  }
  function calcRow(row) {
    const q = parseFloat(row.querySelector('.qty-input').value) || 0;
    const p = parseFloat(row.querySelector('.price-input').value) || 0;
    row.querySelector('.row-total').value = (q * p).toFixed(2);
    calcTotal();
  }
  function updateBtns() {
    const rows = tbody.querySelectorAll('.item-row');
    rows.forEach(r => r.querySelector('.remove-row').disabled = rows.length === 1);
  }
  addBtn.addEventListener('click', () => { tbody.insertAdjacentHTML('beforeend', newRow()); updateBtns(); });
  tbody.addEventListener('input', e => { const r = e.target.closest('.item-row'); if (r) calcRow(r); });
  tbody.addEventListener('click', e => { if (e.target.closest('.remove-row')) { e.target.closest('.item-row').remove(); calcTotal(); updateBtns(); } });
  updateBtns();
}
setupTable('new-items-body', 'add-row-btn', 'grand-total');
document.querySelectorAll('.add-row-btn-inv').forEach(btn => {
  const id = btn.dataset.inv;
  const tbody = document.getElementById('add-items-body-' + id);
  const totEl = document.querySelector('.add-total-inv[data-inv="' + id + '"]');
  if (!tbody) return;
  function calcTotal() { if (!totEl) return; let t=0; tbody.querySelectorAll('.row-total').forEach(e=>t+=parseFloat(e.value)||0); totEl.textContent=t.toFixed(2); }
  function updateBtns() { const rows=tbody.querySelectorAll('.item-row'); rows.forEach(r=>r.querySelector('.remove-row').disabled=rows.length===1); }
  btn.addEventListener('click', () => { tbody.insertAdjacentHTML('beforeend', newRow()); updateBtns(); });
  tbody.addEventListener('input', e => { const r=e.target.closest('.item-row'); if(r){const q=parseFloat(r.querySelector('.qty-input').value)||0;const p=parseFloat(r.querySelector('.price-input').value)||0;r.querySelector('.row-total').value=(q*p).toFixed(2);calcTotal();} });
  tbody.addEventListener('click', e => { if(e.target.closest('.remove-row')){e.target.closest('.item-row').remove();calcTotal();updateBtns();} });
  updateBtns();
});
document.getElementById('toggle-add-invoice').addEventListener('click', () => {
  const card = document.getElementById('add-invoice-card');
  const show = card.style.display === 'none';
  card.style.display = show ? 'block' : 'none';
  if (show) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
});
</script>
{% endblock %}
"""

path = '/home/MalikMohs/makhzan_alkhair/templates/incoming_invoices.html'
with open(path, 'w', encoding='utf-8') as f:
    f.write(html)
print("تم كتابة الملف بنجاح")