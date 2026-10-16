// ============================================================================
//  Store — POS counter, inventory, bill history and sales reports.
// ============================================================================
import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  esc, fmt, toast, openModal, confirmDialog, emptyState, on, withAuth, $,
  downloadCSV, lineChart, hbars,
} from "../ui.js";
import { refresh } from "../app.js";

const TAX_PCT = 5;

const v = {
  tab: "counter",
  q: "",
  category: "All",
  billQ: "",
  cart: [],          // { product, qty }
  discountPct: 0,
  payment: "Cash",
  customer: "",
  phone: "",
};

export async function storeView(host) {
  host.innerHTML = `
    <div class="view">
      <div class="row between mb" style="gap:12px">
        <div class="segmented">
          <button data-tab="counter"   class="${v.tab === "counter" ? "on" : ""}">Counter</button>
          <button data-tab="inventory" class="${v.tab === "inventory" ? "on" : ""}">Inventory</button>
          <button data-tab="bills"     class="${v.tab === "bills" ? "on" : ""}">Bills</button>
          <button data-tab="reports"   class="${v.tab === "reports" ? "on" : ""}">Reports</button>
        </div>
        <div class="row" style="gap:9px">
          <button class="btn btn-ghost" id="stExport">${icon("download")} <span class="hidden-sm">Export</span></button>
          <button class="btn btn-primary" id="stAdd">${icon("plus")} Add product</button>
        </div>
      </div>

      <div class="stat-grid" id="stStats"></div>
      <div id="stBody"></div>
    </div>`;

  renderStats(host.querySelector("#stStats"), await api.storeStats());

  on(host, "click", "[data-tab]", (e, el) => { v.tab = el.dataset.tab; paint(host); });

  host.querySelector("#stAdd").addEventListener("click", () => productForm(null, () => paint(host)));
  host.querySelector("#stExport").addEventListener("click", async () => {
    const res = await api.products(v.q, v.category);
    downloadCSV("store-inventory.csv", res.products.map((p) => ({
      SKU: p.sku ?? "", Name: p.name, Category: p.category, Price: p.price,
      Stock: p.stock, ReorderAt: p.reorder_level, Supplier: p.supplier ?? "", State: p.stock_state,
    })));
  });

  await paint(host);
}

function renderStats(host, s) {
  const cards = [
    ["var(--violet)", "box", "Products", s.products, `${s.units} units on shelves`],
    ["var(--green)", "coin", "Inventory value", s.inventoryValue, "at current unit price", 2],
    ["var(--blue)", "receipt", "Bills today", s.billsToday, `${fmt.money0(s.revenueToday)} collected`],
    ["var(--amber)", "alert", "Reorder alerts", s.lowStock, `${s.outOfStock} out of stock`],
  ];
  host.innerHTML = cards.map(([accent, ic, label, value, foot, dec]) => `
    <div class="stat" style="--accent:${accent}">
      <div class="stat-top"><div class="stat-icon">${icon(ic)}</div><div class="stat-label">${label}</div></div>
      <div class="stat-value">${dec ? fmt.money0(value) : fmt.num(value)}</div>
      <div class="stat-foot">${esc(foot)}</div>
    </div>`).join("");
}

/* ============================================================== paint ==== */
async function paint(host) {
  const body = host.querySelector("#stBody");
  body.innerHTML = `<div class="card"><div class="card-body"><div class="skeleton" style="height:220px"></div></div></div>`;

  if (v.tab === "counter")        await paintCounter(host, body);
  else if (v.tab === "inventory") await paintInventory(host, body);
  else if (v.tab === "bills")     await paintBills(host, body);
  else                            await paintReports(host, body);
}

/* ------------------------------------------------------- 1. COUNTER ----- */
async function paintCounter(host, body) {
  const [res, cats] = await Promise.all([api.products(v.q, v.category), api.productCategories()]);

  const cart = v.cart;
  const subtotal = cart.reduce((s, l) => s + l.product.price * l.qty, 0);
  const discount = (subtotal * v.discountPct) / 100;
  const tax = ((subtotal - discount) * TAX_PCT) / 100;
  const total = subtotal - discount + tax;

  body.innerHTML = `
    <div class="pos-grid">
      <div class="card">
        <div class="card-head" style="flex-wrap:wrap;gap:10px">
          <h4>Menu</h4>
          <div class="searchbox" style="margin-left:8px;width:230px">
            ${icon("search")}
            <input id="sq" type="search" placeholder="Search products…" value="${esc(v.q)}">
          </div>
          <select class="select" id="scat" style="width:auto;min-width:150px">
            ${["All", ...cats.categories.map((c) => c.category)].map((c) =>
              `<option ${v.category === c ? "selected" : ""}>${esc(c)}</option>`).join("")}
          </select>
          <span class="spacer"></span>
          ${cart.length ? `<button class="btn btn-sm btn-danger" id="clearCart">${icon("trash")} Clear</button>` : ""}
        </div>
        <div class="card-body">
          ${res.products.length ? `
            <div class="product-grid">
              ${res.products.map((p) => {
                const out = p.stock === 0;
                return `<div class="product-card" data-add="${p.id}" style="${out ? "opacity:.5;cursor:not-allowed" : ""}">
                  <div class="pc-top">
                    <div class="pc-name">${esc(p.name)}</div>
                    <span class="badge ${p.stock_state === "ok" ? "ok" : p.stock_state === "low" ? "warn" : "danger"}">
                      ${out ? "Out" : p.stock}</span>
                  </div>
                  <div class="tiny faint">${esc(p.category)}${p.sku ? " · " + esc(p.sku) : ""}</div>
                  <div class="pc-foot">
                    <span class="pc-price">${fmt.money(p.price)}</span>
                    <span class="tiny faint">${esc(p.supplier ?? "")}</span>
                  </div>
                </div>`;
              }).join("")}
            </div>` : emptyState("No products match", "box")}
        </div>
      </div>

      <div class="card" style="align-self:start;position:sticky;top:0">
        <div class="card-head"><h4>Current bill</h4><span class="spacer"></span>
          <span class="badge violet">${cart.length} line${cart.length === 1 ? "" : "s"}</span></div>
        <div class="card-body">
          <div class="col" style="gap:12px;margin-bottom:14px">
            <div class="field">
              <label for="bCust">Customer name</label>
              <input class="input" id="bCust" value="${esc(v.customer)}" placeholder="e.g. Rahul Kumar">
            </div>
            <div class="field">
              <label for="bPhone">Phone</label>
              <input class="input mono" id="bPhone" value="${esc(v.phone)}" placeholder="10-digit mobile">
            </div>
          </div>

          ${cart.length ? `
            <div class="cart-lines">
              ${cart.map((l, i) => `
                <div class="cart-line">
                  <div>
                    <div class="cl-name">${esc(l.product.name)}</div>
                    <div class="cl-meta">${fmt.money(l.product.price)} × ${l.qty}</div>
                  </div>
                  <div class="row" style="gap:8px">
                    <div class="qty-ctl">
                      <button data-dec="${i}" ${l.qty <= 1 ? "disabled" : ""}>−</button>
                      <span>${l.qty}</span>
                      <button data-inc="${i}" ${l.qty >= l.product.stock ? "disabled" : ""}>+</button>
                    </div>
                    <strong class="nowrap">${fmt.money(l.product.price * l.qty)}</strong>
                  </div>
                </div>`).join("")}
            </div>` : emptyState("Tap a product to start a bill", "cart")}

          <div class="col" style="gap:10px;margin-top:14px">
            <div class="row" style="gap:9px">
              <div class="field" style="flex:1">
                <label for="bDisc">Discount %</label>
                <input class="input" id="bDisc" type="number" min="0" max="40" value="${v.discountPct}">
              </div>
              <div class="field" style="flex:1">
                <label for="bPay">Payment</label>
                <select class="select" id="bPay">
                  ${["Cash", "Card", "UPI"].map((p) =>
                    `<option ${v.payment === p ? "selected" : ""}>${p}</option>`).join("")}
                </select>
              </div>
            </div>

            <div class="score-row"><span>Subtotal</span><span>${fmt.money(subtotal)}</span></div>
            <div class="score-row"><span>Discount (${v.discountPct}%)</span><span>− ${fmt.money(discount)}</span></div>
            <div class="score-row"><span>GST (${TAX_PCT}%)</span><span>${fmt.money(tax)}</span></div>
            <div class="score-row total"><span>Total</span><span>${fmt.money(total)}</span></div>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn btn-primary" id="checkout" style="flex:1" ${cart.length ? "" : "disabled"}>
            ${icon("checkCircle")} Generate bill
          </button>
        </div>
      </div>
    </div>`;

  /* filters */
  let t;
  body.querySelector("#sq").addEventListener("input", (e) => {
    clearTimeout(t);
    t = setTimeout(() => { v.q = e.target.value.trim(); paintCounter(host, body); }, 300);
  });
  body.querySelector("#scat").addEventListener("change", (e) => { v.category = e.target.value; paintCounter(host, body); });

  body.querySelector("#bCust").addEventListener("input", (e) => { v.customer = e.target.value; });
  body.querySelector("#bPhone").addEventListener("input", (e) => { v.phone = e.target.value; });
  body.querySelector("#bDisc").addEventListener("input", (e) => {
    v.discountPct = Math.max(0, Math.min(40, Number(e.target.value) || 0));
    paintCounter(host, body);
  });
  body.querySelector("#bPay").addEventListener("change", (e) => { v.payment = e.target.value; });

  body.querySelectorAll("[data-add]").forEach((el) =>
    el.addEventListener("click", () => {
      const p = res.products.find((x) => x.id === Number(el.dataset.add));
      if (!p || p.stock === 0) return toast("Out of stock", "warn");
      const line = v.cart.find((l) => l.product.id === p.id);
      if (line) {
        if (line.qty >= p.stock) return toast(`Only ${p.stock} in stock`, "warn");
        line.qty += 1;
      } else v.cart.push({ product: p, qty: 1 });
      paintCounter(host, body);
    }));

  body.querySelectorAll("[data-inc]").forEach((el) =>
    el.addEventListener("click", () => {
      const l = v.cart[Number(el.dataset.inc)];
      if (l.qty < l.product.stock) l.qty += 1;
      paintCounter(host, body);
    }));
  body.querySelectorAll("[data-dec]").forEach((el) =>
    el.addEventListener("click", () => {
      const i = Number(el.dataset.dec);
      if (v.cart[i].qty > 1) v.cart[i].qty -= 1; else v.cart.splice(i, 1);
      paintCounter(host, body);
    }));
  body.querySelector("#clearCart")?.addEventListener("click", async () => {
    if (await confirmDialog({ title: "Clear the cart?", message: "All lines will be removed.", confirmText: "Clear", danger: true })) {
      v.cart = []; v.discountPct = 0; paintCounter(host, body);
    }
  });

  body.querySelector("#checkout").addEventListener("click", async () => {
    if (!v.customer.trim()) { toast("Enter the customer's name", "warn"); body.querySelector("#bCust").focus(); return; }
    const btn = body.querySelector("#checkout");
    btn.disabled = true;
    btn.innerHTML = icon("spinner") + " Processing…";
    const res = await withAuth(() => api.makeBill({
      customer: v.customer.trim(),
      phone: v.phone.trim(),
      payment: v.payment,
      discountPct: v.discountPct,
      items: v.cart.map((l) => ({ productId: l.product.id, qty: l.qty })),
    }));
    if (!res.ok) { btn.disabled = false; btn.innerHTML = icon("checkCircle") + " Generate bill"; return; }

    v.cart = []; v.discountPct = 0; v.customer = ""; v.phone = "";
    toast(res.data.message, "success", "Bill generated");

    const bills = await api.bills();
    const made = bills.bills.find((b) => b.bill_no === res.data.billNo);
    if (made) showReceipt(made.id);
    await paint(host);
  });
}

/* ---------------------------------------------------- 2. INVENTORY ------ */
async function paintInventory(host, body) {
  const [res, cats] = await Promise.all([api.products(v.q, v.category), api.productCategories()]);
  const products = res.products;

  body.innerHTML = `
    <div class="card">
      <div class="card-head" style="flex-wrap:wrap;gap:10px">
        <div class="searchbox" style="margin-left:0;width:280px">
          ${icon("search")}
          <input id="pq" type="search" placeholder="Search name, SKU, supplier…" value="${esc(v.q)}">
        </div>
        <select class="select" id="pcat" style="width:auto;min-width:160px">
          ${["All", ...cats.categories.map((c) => c.category)].map((c) =>
            `<option ${v.category === c ? "selected" : ""}>${esc(c)}</option>`).join("")}
        </select>
        <span class="spacer"></span>
        <span class="section-sub">${products.length} products</span>
      </div>
      <div class="card-body" style="padding:0">
        ${products.length ? `
          <div class="table-wrap">
            <table class="data">
              <thead><tr>
                <th>Product</th><th>Category</th><th>Supplier</th>
                <th class="num">Price</th><th class="num">Stock</th><th>Health</th><th></th>
              </tr></thead>
              <tbody>
                ${products.map((p) => `<tr>
                  <td>
                    <div class="cell-main">${esc(p.name)}</div>
                    <div class="cell-sub mono">${esc(p.sku ?? "—")}</div>
                  </td>
                  <td><span class="badge">${esc(p.category)}</span></td>
                  <td class="small">${esc(p.supplier ?? "—")}</td>
                  <td class="num strong">${fmt.money(p.price)}</td>
                  <td class="num">
                    <div class="strong">${p.stock}</div>
                    <div class="tiny faint">reorder at ${p.reorder_level}</div>
                  </td>
                  <td><span class="badge ${p.stock_state === "ok" ? "ok" : p.stock_state === "low" ? "warn" : "danger"}">
                    ${p.stock_state === "ok" ? "In stock" : p.stock_state === "low" ? "Low" : "Out of stock"}</span></td>
                  <td><div class="actions">
                    <button class="btn btn-sm btn-ghost" data-restock="${p.id}" title="Add stock">${icon("plus")}</button>
                    <button class="btn btn-sm btn-ghost" data-editp="${p.id}" title="Edit">${icon("edit")}</button>
                    <button class="btn btn-sm btn-danger" data-delp="${p.id}" title="Archive">${icon("trash")}</button>
                  </div></td>
                </tr>`).join("")}
              </tbody>
            </table>
          </div>` : emptyState("No products match", "box")}
      </div>
    </div>`;

  let t;
  body.querySelector("#pq").addEventListener("input", (e) => {
    clearTimeout(t);
    t = setTimeout(() => { v.q = e.target.value.trim(); paintInventory(host, body); }, 300);
  });
  body.querySelector("#pcat").addEventListener("change", (e) => { v.category = e.target.value; paintInventory(host, body); });

  body.querySelectorAll("[data-restock]").forEach((el) =>
    el.addEventListener("click", async () => {
      const p = products.find((x) => x.id === Number(el.dataset.restock));
      const m = openModal({
        title: "Replenish stock",
        subtitle: p.name,
        body: `
          <form id="rs" class="col" style="gap:14px">
            <div class="row" style="gap:14px">
              <div class="field" style="flex:1">
                <label for="rCur">Currently in stock</label>
                <input class="input" id="rCur" value="${p.stock}" disabled>
              </div>
              <div class="field" style="flex:1">
                <label for="rAdd">Units to add <span style="color:var(--red)">*</span></label>
                <input class="input" id="rAdd" type="number" min="1" max="9999" placeholder="50">
              </div>
            </div>
            <div class="alert info">${icon("info")} Reorder level is ${p.reorder_level} units.</div>
          </form>`,
        footer: `<button class="btn btn-ghost" data-close>Cancel</button>
                 <button class="btn btn-primary" id="rsGo">${icon("check")} Add stock</button>`,
      });
      m.el.querySelector("#rsGo").addEventListener("click", async () => {
        const add = Number(m.el.querySelector("#rAdd").value);
        if (!add || add < 1) return toast("Enter how many units to add", "warn");
        const r = await withAuth(() => api.restock(p.id, add));
        if (!r.ok) return;
        m.close();
        toast(r.data.message, "success");
        await paint(host);
      });
    }));

  body.querySelectorAll("[data-editp]").forEach((el) =>
    el.addEventListener("click", () => productForm(products.find((x) => x.id === Number(el.dataset.editp)), () => paint(host))));

  body.querySelectorAll("[data-delp]").forEach((el) =>
    el.addEventListener("click", async () => {
      const p = products.find((x) => x.id === Number(el.dataset.delp));
      const ok = await confirmDialog({
        title: "Archive product?",
        message: `“${p.name}” will be hidden from the counter and inventory. Past bills keep their record.`,
        confirmText: "Archive", danger: true,
      });
      if (!ok) return;
      const r = await withAuth(async () => {
        const res = await api.archiveProduct(p.id);
        await paint(host);
        return res;
      });
      if (r.ok) toast(r.data.message, "success");
    }));
}

/* -------------------------------------------------------- 3. BILLS ------ */
async function paintBills(host, body) {
  const res = await api.bills(v.billQ);

  body.innerHTML = `
    <div class="card">
      <div class="card-head" style="flex-wrap:wrap;gap:10px">
        <h4>Bills</h4>
        <div class="searchbox" style="margin-left:8px;width:280px">
          ${icon("search")}
          <input id="blq" type="search" placeholder="Search bill no., customer, phone…" value="${esc(v.billQ)}">
        </div>
        <span class="spacer"></span>
        <span class="badge violet">Next ${esc(res.nextBillNo)}</span>
      </div>
      <div class="card-body" style="padding:0">
        ${res.bills.length ? `
          <div class="table-wrap">
            <table class="data">
              <thead><tr>
                <th>Bill no.</th><th>Customer</th><th>Items</th><th>Payment</th>
                <th class="num">Subtotal</th><th class="num">Discount</th><th class="num">Total</th><th>Date</th><th></th>
              </tr></thead>
              <tbody>
                ${res.bills.map((b) => `<tr>
                  <td class="mono strong">${esc(b.bill_no)}</td>
                  <td>
                    <div>${esc(b.customer)}</div>
                    ${b.phone ? `<div class="cell-sub mono">${esc(b.phone)}</div>` : ""}
                  </td>
                  <td class="num">${b.item_count}</td>
                  <td><span class="badge ${b.payment === "UPI" ? "info" : b.payment === "Card" ? "violet" : "ok"}">${esc(b.payment)}</span></td>
                  <td class="num">${fmt.money(b.subtotal)}</td>
                  <td class="num">${b.discount ? "− " + fmt.money(b.discount) : "—"}</td>
                  <td class="num strong">${fmt.money(b.total)}</td>
                  <td class="small nowrap">${esc(fmt.dateTime(b.created_at))}</td>
                  <td><div class="actions">
                    <button class="btn btn-sm btn-ghost" data-view="${b.id}" title="View receipt">${icon("receipt")}</button>
                  </div></td>
                </tr>`).join("")}
              </tbody>
            </table>
          </div>` : emptyState("No bills found", "receipt")}
      </div>
    </div>`;

  let t;
  body.querySelector("#blq").addEventListener("input", (e) => {
    clearTimeout(t);
    t = setTimeout(() => { v.billQ = e.target.value.trim(); paintBills(host, body); }, 300);
  });
  body.querySelectorAll("[data-view]").forEach((el) =>
    el.addEventListener("click", () => showReceipt(Number(el.dataset.view))));
}

/* ------------------------------------------------------- 4. REPORTS ----- */
async function paintReports(host, body) {
  const [an, stats, lowRes] = await Promise.all([api.analytics(14), api.storeStats(), api.lowStock()]);
  const low = lowRes.products;

  body.innerHTML = `
    <div class="view">
      <div class="grid-2 mb">
        <div class="card">
          <div class="card-head"><h4>Revenue trend</h4><span class="spacer"></span>
            <span class="section-sub">14 days</span></div>
          <div class="card-body">
            ${lineChart(an.series.map((s) => ({ label: fmt.dateShort(s.date), value: s.amount })), { height: 250 })}
          </div>
        </div>
        <div class="card">
          <div class="card-head"><h4>Top products</h4><span class="spacer"></span>
            <span class="section-sub">90 days</span></div>
          <div class="card-body">
            ${an.top.length ? hbars(an.top.map((t) => ({ label: t.name, value: t.qty }))) : emptyState("No sales yet", "chart")}
          </div>
        </div>
      </div>

      <div class="grid-2 mb">
        <div class="card">
          <div class="card-head"><h4>Payment mix</h4></div>
          <div class="card-body">
            ${stats.paymentMix.length
              ? hbars(stats.paymentMix.map((p) => ({ label: p.payment, value: p.amt })), { format: (x) => fmt.money0(x) })
              : emptyState("No bills yet", "coin")}
          </div>
        </div>
        <div class="card">
          <div class="card-head"><h4>Reorder list</h4><span class="spacer"></span>
            <span class="badge ${stats.lowStock ? "warn" : "ok"}">${stats.lowStock} item${stats.lowStock === 1 ? "" : "s"}</span></div>
          <div class="card-body">
            ${low.length ? `<div class="col" style="gap:9px">
              ${low.map((p) => `<div class="alert ${p.stock === 0 ? "danger" : "warn"}">
                ${icon(p.stock === 0 ? "alert" : "clock")}
                <span style="flex:1">${esc(p.name)}</span>
                <span class="strong">${p.stock} / ${p.reorder_level}</span>
              </div>`).join("")}</div>`
              : emptyState("Stock levels are healthy", "checkCircle")}
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h4>Category performance</h4></div>
        <div class="card-body" style="padding:0">
          ${an.top.length ? `<div class="table-wrap"><table class="data">
            <thead><tr><th>Product</th><th class="num">Units sold</th><th class="num">Revenue</th><th style="width:34%">Share</th></tr></thead>
            <tbody>
              ${an.top.map((t) => {
                const maxQ = Math.max(...an.top.map((x) => x.qty), 1);
                return `<tr>
                  <td class="cell-main">${esc(t.name)}</td>
                  <td class="num">${fmt.num(t.qty)}</td>
                  <td class="num strong">${fmt.money(t.revenue)}</td>
                  <td><div class="bar"><i style="width:${(t.qty / maxQ) * 100}%"></i></div></td>
                </tr>`;
              }).join("")}
            </tbody></table></div>` : emptyState("No sales data yet", "chart")}
        </div>
      </div>
    </div>`;
}

/* -------------------------------------------------------- receipt ------- */
export async function showReceipt(id) {
  const { bill } = await api.bill(id);
  const m = openModal({
    title: `Bill ${bill.bill_no}`,
    subtitle: fmt.dateTime(bill.created_at),
    body: `
      <div class="receipt" id="receipt">
        <h4>CAMPUS NEXUS</h4>
        <div class="r-sub">Campus Store · Counter ${esc(bill.payment)}</div>
        <hr/>
        <div class="r-line"><span>Bill</span><span>${esc(bill.bill_no)}</span></div>
        <div class="r-line"><span>Customer</span><span>${esc(bill.customer)}</span></div>
        ${bill.phone ? `<div class="r-line"><span>Phone</span><span>${esc(bill.phone)}</span></div>` : ""}
        <div class="r-line"><span>Date</span><span>${esc(fmt.dateTime(bill.created_at))}</span></div>
        <hr/>
        ${bill.items.map((i) => `
          <div class="r-line"><span>${esc(i.name)}<br/><span style="color:var(--text-faint)">${i.qty} × ${fmt.money(i.rate)}</span></span>
          <span>${fmt.money(i.amount)}</span></div>`).join("")}
        <hr/>
        <div class="r-line"><span>Subtotal</span><span>${fmt.money(bill.subtotal)}</span></div>
        <div class="r-line"><span>Discount</span><span>− ${fmt.money(bill.discount)}</span></div>
        <div class="r-line"><span>GST (${TAX_PCT}%)</span><span>${fmt.money(bill.tax)}</span></div>
        <hr/>
        <div class="r-line r-total"><span>TOTAL</span><span>${fmt.money(bill.total)}</span></div>
        <div class="r-foot">Paid by ${esc(bill.payment)} · Thank you for shopping at Campus Nexus!</div>
      </div>`,
    footer: `
      <span class="spacer"></span>
      <button class="btn btn-ghost" data-close>Close</button>
      <button class="btn btn-primary" id="printBtn">${icon("print")} Print receipt</button>`,
    onMount: ({ el }) => {
      $("#printBtn", el).addEventListener("click", () => window.print());
    },
  });
  return m;
}

/* ---------------------------------------------------- product form ------ */
async function productForm(existing, done) {
  const cats = ["Stationery", "Electronics", "Merch", "Food", "Sports", "Misc"];
  const p = existing ?? {};
  const editing = !!existing;

  const m = openModal({
    title: editing ? "Edit product" : "Add a product",
    subtitle: editing ? p.name : "New inventory entry",
    wide: true,
    body: `
      <form id="pf" class="form-grid">
        <div class="field span-2">
          <label for="pName">Product name <span style="color:var(--red)">*</span></label>
          <input class="input" id="pName" value="${esc(p.name ?? "")}" placeholder="e.g. Campus Notebook A4" required>
        </div>
        <div class="field">
          <label for="pSku">SKU / code</label>
          <input class="input mono" id="pSku" value="${esc(p.sku ?? "")}" placeholder="CN-1001">
        </div>
        <div class="field">
          <label for="pCat">Category</label>
          <select class="select" id="pCat">
            ${cats.map((c) => `<option ${p.category === c ? "selected" : ""}>${c}</option>`).join("")}
          </select>
        </div>
        <div class="field">
          <label for="pPrice">Unit price (₹) <span style="color:var(--red)">*</span></label>
          <input class="input" id="pPrice" type="number" min="0.01" step="0.01" value="${p.price ?? ""}" placeholder="149.00" required>
        </div>
        <div class="field">
          <label for="pStock">Units in stock</label>
          <input class="input" id="pStock" type="number" min="0" value="${p.stock ?? 0}">
        </div>
        <div class="field">
          <label for="pReorder">Reorder level</label>
          <input class="input" id="pReorder" type="number" min="0" value="${p.reorder_level ?? 5}">
          <div class="hint">Flagged as “low” at or below this.</div>
        </div>
        <div class="field">
          <label for="pSup">Supplier</label>
          <input class="input" id="pSup" value="${esc(p.supplier ?? "")}" placeholder="e.g. Techline Distributors">
        </div>
        <div class="field span-2">
          <label for="pDesc">Description</label>
          <textarea class="input" id="pDesc" rows="2" placeholder="Optional description">${esc(p.description ?? "")}</textarea>
        </div>
      </form>`,
    footer: `
      <button class="btn btn-ghost" data-close>Cancel</button>
      <button class="btn btn-primary" id="pfSave">${icon("check")} ${editing ? "Save changes" : "Add product"}</button>`,
  });

  const val = (id) => m.el.querySelector("#p" + id).value.trim();
  m.el.querySelector("#pfSave").addEventListener("click", async () => {
    const payload = {
      name: val("Name"), sku: val("Sku"), category: val("Cat"),
      price: Number(val("Price")), stock: Number(val("Stock")) || 0,
      reorderLevel: Number(val("Reorder")) || 0,
      supplier: val("Sup"), description: val("Desc"),
    };
    if (!payload.name) return toast("Product name is required", "warn");
    if (!(payload.price > 0)) return toast("Enter a price greater than 0", "warn");

    const btn = m.el.querySelector("#pfSave");
    btn.disabled = true;
    const res = await withAuth(() => editing ? api.editProduct(p.id, payload) : api.addProduct(payload));
    if (!res.ok) { btn.disabled = false; return; }
    m.close();
    toast(res.data.message, "success");
    await done?.();
  });
}