// ============================================================================
//  Store / Billing module  —  derived from the "Shopping Mall" Java Swing + MySQL
//  project.  Fixes from the original: ONE database (was split across
//  `departmental` and `bazar`), server-side stock validation, and transactional
//  bill creation.
// ============================================================================
import { db, logActivity } from "../db.js";
import { fail, readJson } from "../http.js";
import { validate, V, safeText, identifier } from "../security/validate.js";
import { encryptField, decryptField, blindIndex } from "../security/fieldcrypto.js";

export const TAX_PCT = 5;        // GST
export const MAX_DISCOUNT_PCT = 40;
const money = (n) => Math.round(n * 100) / 100;

// `num` coerces route params and analytics inputs; strings are handled by the
// schema validator, so there is no ad-hoc `str()` helper any more.
const num = (v, def = 0) => (Number.isFinite(Number(v)) ? Number(v) : def);

/* -------------------------------------------------------------- schemas -- */
const PRODUCT_SCHEMA = V.object({
  name: safeText(160),
  sku: identifier(20),
  category: safeText(60),
  price: V.number({ min: 0, max: 10_000_000, fallback: 0 }),
  stock: V.int({ min: 0, max: 1_000_000, fallback: 0 }),
  reorderLevel: V.int({ min: 0, max: 1_000_000, fallback: 0 }),
  supplier: safeText(120),
  description: V.string({ max: 400 }),
}, { strict: true });

/** Validate and return { ok, value } — `res.json` is provided by the server. */
function check(res, input, schema) {
  const parsed = validate(input, schema);
  if (!parsed.ok) {
    res.json({ ok: false, error: "Validation failed", errors: parsed.errors }, 400);
    return null;
  }
  return parsed.value;
}

/* ------------------------------------------------------------------ stats -- */
export function storeStats() {
  const inv = db
    .prepare(
      `SELECT COUNT(*)                       AS products,
              IFNULL(SUM(stock), 0)          AS units,
              IFNULL(SUM(stock * price), 0)  AS value,
              IFNULL(SUM(CASE WHEN stock = 0 THEN 1 ELSE 0 END), 0)         AS out_of_stock,
              IFNULL(SUM(CASE WHEN stock <= reorder_level THEN 1 ELSE 0 END), 0) AS low_stock
       FROM products WHERE active = 1`
    )
    .get();

  const sales = db
    .prepare(
      `SELECT COUNT(*) AS bills,
              IFNULL(SUM(total), 0) AS revenue,
              IFNULL(SUM(discount), 0) AS discount_given
       FROM bills WHERE date(created_at) >= date('now','localtime','-30 day')`
    )
    .get();

  const todayRow = db
    .prepare(
      `SELECT COUNT(*) AS n, IFNULL(SUM(total),0) AS amt
       FROM bills WHERE date(created_at) = date('now','localtime')`
    )
    .get();

  const bestSeller = db
    .prepare(
      `SELECT bi.name, SUM(bi.qty) AS qty
       FROM bill_items bi GROUP BY bi.name ORDER BY qty DESC LIMIT 1`
    )
    .get();

  const payMix = db
    .prepare(`SELECT payment, COUNT(*) AS n, SUM(total) AS amt FROM bills GROUP BY payment`)
    .all();

  return {
    products: inv.products,
    units: inv.units,
    inventoryValue: money(inv.value),
    outOfStock: inv.out_of_stock,
    lowStock: inv.low_stock,
    bills30d: sales.bills,
    revenue30d: money(sales.revenue),
    discount30d: money(sales.discount_given),
    billsToday: todayRow.n,
    revenueToday: money(todayRow.amt),
    bestSeller: bestSeller ?? null,
    paymentMix: payMix.map((p) => ({ ...p, amt: money(p.amt) })),
  };
}

/* -------------------------------------------------------------- products -- */
export function listProducts(q = "", category = "") {
  const where = ["active = 1"];
  const args = [];
  if (q) {
    where.push("(name LIKE ? OR sku LIKE ? OR supplier LIKE ? OR description LIKE ?)");
    const like = `%${q}%`;
    args.push(like, like, like, like);
  }
  if (category && category !== "All") {
    where.push("category = ?");
    args.push(category);
  }
  return db
    .prepare(
      `SELECT *, CASE WHEN stock = 0 THEN 'out'
                       WHEN stock <= reorder_level THEN 'low'
                       ELSE 'ok' END AS stock_state
       FROM products WHERE ${where.join(" AND ")} ORDER BY name COLLATE NOCASE`
    )
    .all(...args);
}

export function productCategories() {
  return db
    .prepare(`SELECT category, COUNT(*) AS n FROM products WHERE active=1 GROUP BY category ORDER BY category`)
    .all();
}

export async function createProduct(req, res) {
  const raw = await readJson(req);
  const p = check(res, raw, PRODUCT_SCHEMA);
  if (!p) return;

  if (!p.name) return fail(res, "Product name is required");
  if (!(p.price > 0)) return fail(res, "Price must be greater than 0");

  const sku = p.sku.toUpperCase();
  if (sku) {
    const dup = db.prepare("SELECT id FROM products WHERE sku=?").get(sku);
    if (dup) return fail(res, `SKU ${sku} is already in the inventory`, 409);
  }

  const r = db
    .prepare(
      `INSERT INTO products (sku, name, category, price, stock, reorder_level, supplier, description)
       VALUES (?,?,?,?,?,?,?,?)`
    )
    .run(
      sku || null, p.name, p.category || "General", money(p.price),
      p.stock, p.reorderLevel, p.supplier, p.description
    );
  logActivity("store", "Product added", `${p.name} (₹${p.price.toFixed(2)})`);
  res.json({ ok: true, id: r.lastInsertRowid, message: `${p.name} added to inventory` }, 201);
}

export async function updateProduct(req, res, { id }) {
  const raw = await readJson(req);
  const p = check(res, raw, PRODUCT_SCHEMA);
  if (!p) return;

  const prod = db.prepare("SELECT * FROM products WHERE id=?").get(num(id));
  if (!prod) return fail(res, "Product not found", 404);
  if (!p.name) return fail(res, "Product name is required");
  if (!(p.price > 0)) return fail(res, "Price must be greater than 0");

  const sku = p.sku.toUpperCase();
  if (sku && sku !== prod.sku) {
    const dup = db.prepare("SELECT id FROM products WHERE sku=? AND id<>?").get(sku, prod.id);
    if (dup) return fail(res, `SKU ${sku} is already in the inventory`, 409);
  }
  db.prepare(
    `UPDATE products SET sku=?, name=?, category=?, price=?, stock=?, reorder_level=?,
            supplier=?, description=? WHERE id=?`
  ).run(
    sku || null, p.name, p.category || prod.category, money(p.price),
    p.stock, p.reorderLevel, p.supplier, p.description, prod.id
  );
  logActivity("store", "Product updated", prod.name);
  res.json({ ok: true, message: `${prod.name} updated` });
}

export function deleteProduct(req, res, { id }) {
  const prod = db.prepare("SELECT * FROM products WHERE id=?").get(num(id));
  if (!prod) return fail(res, "Product not found", 404);
  // Soft delete so historic bill items stay intact.
  db.prepare("UPDATE products SET active=0 WHERE id=?").run(prod.id);
  logActivity("store", "Product archived", prod.name);
  res.json({ ok: true, message: `${prod.name} archived (past bills preserved)` });
}

export function lowStock() {
  return db
    .prepare(
      `SELECT id, sku, name, stock, reorder_level, price, category
       FROM products WHERE active=1 AND stock <= reorder_level
       ORDER BY (stock - reorder_level), name`
    )
    .all();
}

export async function restock(req, res, { id }) {
  const body = check(res, await readJson(req),
    V.object({ add: V.int({ min: 1, max: 1_000_000, fallback: 0 }) }, { strict: true }));
  if (!body) return;
  const prod = db.prepare("SELECT * FROM products WHERE id=?").get(num(id));
  if (!prod) return fail(res, "Product not found", 404);

  db.prepare("UPDATE products SET stock = stock + ? WHERE id=?").run(body.add, prod.id);
  logActivity("store", "Stock replenished", `${prod.name} +${body.add} units`);
  res.json({ ok: true, message: `${prod.name}: +${body.add} units in stock` });
}

/* ------------------------------------------------------------------ bills -- */
export function nextBillNo() {
  const row = db
    .prepare(
      `SELECT bill_no FROM bills
       WHERE bill_no GLOB 'CNX-[0-9]*' ORDER BY CAST(substr(bill_no,5) AS INTEGER) DESC LIMIT 1`
    )
    .get();
  const last = row ? parseInt(row.bill_no.slice(4), 10) : 100000;
  return `CNX-${String((Number.isFinite(last) ? last : 100000) + 1).padStart(6, "0")}`;
}

export function listBills(q = "", from = "", to = "") {
  const where = [];
  const args = [];

  if (q) {
    // `phone` is ciphertext, so it cannot be matched with LIKE. An exact lookup
    // goes through the deterministic blind index instead; everything else still
    // uses LIKE on the clear-text columns.
    const idx = blindIndex(q);
    where.push("(bill_no LIKE ? OR customer LIKE ? OR (phone_idx IS NOT NULL AND phone_idx = ?))");
    args.push(`%${q}%`, `%${q}%`, idx);
  }
  if (from) { where.push("date(created_at) >= date(?)"); args.push(from); }
  if (to) { where.push("date(created_at) <= date(?)"); args.push(to); }
  const clause = where.length ? "WHERE " + where.join(" AND ") : "";

  return db
    .prepare(
      `SELECT b.*, (SELECT COUNT(*) FROM bill_items i WHERE i.bill_id = b.id) AS item_count
       FROM bills b ${clause} ORDER BY b.created_at DESC, b.id DESC LIMIT 200`
    )
    .all(...args)
    .map((b) => ({ ...b, phone: decryptField(b.phone), phone_idx: undefined }));
}

export function getBill(id) {
  const bill = db.prepare("SELECT * FROM bills WHERE id=?").get(num(id));
  if (!bill) return null;
  bill.phone = decryptField(bill.phone);
  delete bill.phone_idx;                 // never expose the blind index
  bill.items = db.prepare("SELECT * FROM bill_items WHERE bill_id=? ORDER BY id").all(bill.id);
  return bill;
}

export async function createBill(req, res) {
  const raw = await readJson(req);
  const b = check(res, raw, V.object({
    customer: safeText(120),
    phone: V.string({ max: 20, pattern: /^[0-9+()\- ]{0,20}$/, patternHint: "phone may only contain digits, spaces, +, - and ()" }),
    payment: V.enum(["Cash", "Card", "UPI"], { fallback: "Cash" }),
    discountPct: V.number({ min: 0, max: MAX_DISCOUNT_PCT, fallback: 0 }),
    items: V.array(
      V.object({
        productId: V.int({ min: 1, max: 1_000_000 }),
        qty: V.int({ min: 1, max: 999, fallback: 1 }),
      }, { strict: true }),
      { min: 1, max: 200 }
    ),
  }, { strict: true }));
  if (!b) return;

  const customer = b.customer;
  if (!customer) return fail(res, "Customer name is required");
  if (!b.items.length) return fail(res, "Add at least one item to the bill");

  const payment = b.payment;
  const discountPct = b.discountPct;

  // ---- validate + price every line against live DB stock & price -----------
  const lines = [];
  let subtotal = 0;
  for (const it of b.items) {
    const prod = db.prepare("SELECT * FROM products WHERE id=? AND active=1").get(it.productId);
    if (!prod) return fail(res, "One of the items is no longer available in the inventory");
    if (prod.stock < it.qty) {
      return fail(res, `Only ${prod.stock} unit(s) of “${prod.name}” left in stock`, 409);
    }
    const amount = money(prod.price * it.qty);
    subtotal += amount;
    lines.push({ prod, qty: it.qty, rate: prod.price, amount });
  }

  const discount = money((subtotal * discountPct) / 100);
  const taxable = subtotal - discount;
  const tax = money((taxable * TAX_PCT) / 100);
  const total = money(taxable + tax);

  // ---- atomic write ------------------------------------------------------
  db.exec("BEGIN IMMEDIATE");
  try {
    const billNo = nextBillNo();
    const r = db
      .prepare(
        `INSERT INTO bills (bill_no, customer, phone, phone_idx, payment, subtotal, discount, tax, total)
         VALUES (?,?,?,?,?,?,?,?,?)`
      )
      .run(
        billNo, customer, encryptField(b.phone), blindIndex(b.phone), payment,
        money(subtotal), discount, tax, total
      );

    const insItem = db.prepare(
      `INSERT INTO bill_items (bill_id, product_id, name, qty, rate, amount)
       VALUES (?,?,?,?,?,?)`
    );
    const decStock = db.prepare(`UPDATE products SET stock = stock - ? WHERE id=?`);
    for (const l of lines) {
      insItem.run(r.lastInsertRowid, l.prod.id, l.prod.name, l.qty, l.rate, l.amount);
      decStock.run(l.qty, l.prod.id);
    }
    db.exec("COMMIT");

    const units = lines.reduce((s, l) => s + l.qty, 0);
    logActivity("store", "Bill generated", `${billNo} · ${customer} · ₹${total.toFixed(2)} · ${units} unit(s)`);
    res.json(
      { ok: true, billNo, total, tax, discount, message: `Bill ${billNo} created — ₹${total.toFixed(2)}` },
      201
    );
  } catch (e) {
    db.exec("ROLLBACK");
    fail(res, "Could not create the bill — " + e.message, 500);
  }
}

/* ------------------------------------------------------- sales analytics --- */
export function salesSeries(days = 14) {
  const rows = db
    .prepare(
      `SELECT date(created_at) AS d, COUNT(*) AS bills, IFNULL(SUM(total),0) AS amount
       FROM bills WHERE date(created_at) >= date('now','localtime', '-' || ? || ' day')
       GROUP BY date(created_at) ORDER BY d`
    )
    .all(days);
  const map = new Map(rows.map((r) => [r.d, r]));
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const hit = map.get(key);
    out.push({ date: key, bills: hit?.bills ?? 0, amount: money(hit?.amount ?? 0) });
  }
  return out;
}

export function topProducts(limit = 6) {
  return db
    .prepare(
      `SELECT bi.name, SUM(bi.qty) AS qty, SUM(bi.amount) AS revenue
       FROM bill_items bi
       JOIN bills b ON b.id = bi.bill_id
       WHERE date(b.created_at) >= date('now','localtime','-90 day')
       GROUP BY bi.name ORDER BY qty DESC LIMIT ?`
    )
    .all(limit);
}