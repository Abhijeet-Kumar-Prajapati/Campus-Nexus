// ============================================================================
//  CAMPUS NEXUS · end-to-end smoke test   →   npm test
//  Exercises every route group against a live server on http://localhost:3000
//  Start the server first (npm start) in another terminal.
// ============================================================================
const BASE = process.env.BASE ?? "http://localhost:3000";

let pass = 0;
let fail = 0;

const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

const jar = new Map();
function saveCookies(res) {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const [pair] = c.split(";");
    const i = pair.indexOf("=");
    jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
}
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const csrfToken = () => (jar.get("cnx_csrf") ? decodeURIComponent(jar.get("cnx_csrf")) : null);

/** A browser loads the page before it can POST; that GET hands out the CSRF cookie. */
async function prime() {
  if (jar.has("cnx_csrf")) return;
  await fetch(BASE + "/api/system/health").then((r) => saveCookies(r));
}

async function call(method, path, body) {
  const unsafe = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
  if (unsafe) await prime();

  const headers = { "Content-Type": "application/json" };
  if (jar.size) headers.Cookie = cookieHeader();
  if (unsafe && csrfToken()) headers["X-CSRF-Token"] = csrfToken();

  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  saveCookies(res);
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, data };
}

function check(label, condition, extra = "") {
  if (condition) {
    pass++;
    console.log(`${green("  PASS")}  ${label}${extra ? dim("  " + extra) : ""}`);
  } else {
    fail++;
    console.log(`${red("  FAIL")}  ${label}${extra ? red("  " + extra) : ""}`);
  }
}
const section = (name) => console.log(`\n\x1b[1m${name}\x1b[0m`);

/* ----------------------------------------------------------------- run --- */
// A per-run suffix keeps the suite re-runnable against a database that already
// contains data from a previous run (SKU/ISBN uniqueness would otherwise trip).
const RUN = Math.random().toString(36).slice(2, 8).toUpperCase();
const TEST_SKU = `TST-${RUN}`;
const TEST_NAME = `Smoke Test Widget ${RUN}`;
// ISBNs are digits only (a trailing X is also valid), so generate numerically.
const TEST_ISBN = "978" + String(Math.floor(Math.random() * 1e9)).padStart(9, "0");

console.log(`\nTesting ${BASE}   (run ${RUN})\n${"─".repeat(58)}`);

/* ---------------------------------------------------------------- system -- */
section("System / dashboard");
{
  const { status, data } = await call("GET", "/api/system/health");
  check("GET  /api/system/health", status === 200 && data.ok, `node ${data?.node}`);

  const d = (await call("GET", "/api/system/dashboard")).data;
  check("GET  /api/system/dashboard", d?.ok === true);
  check("dashboard merges all three modules", d?.library && d?.store && d?.arcade);
  check("dashboard has a sales series", Array.isArray(d?.salesSeries) && d.salesSeries.length === 14);
  check("dashboard surfaces low-stock alerts", Array.isArray(d?.alerts));
  console.log(dim(`        ${d?.totals?.books} books · ${d?.totals?.products} products · ₹${d?.totals?.revenue} billed`));

  const s = (await call("GET", "/api/system/search?q=clean")).data;
  check("GET  /api/system/search", s?.books?.length > 0, `found "${s?.books?.[0]?.title}"`);
}

/* ------------------------------------------------------------------ auth -- */
section("Auth");
{
  const anon = await call("POST", "/api/library/books", { title: "Hack", author: "Nobody" });
  check("write blocked without login", anon.status === 401, `got ${anon.status}`);

  const bad = await call("POST", "/api/auth/login", { username: "admin", password: "nope", hp: "", _t: Date.now() - 2000 });
  check("wrong password rejected", bad.status === 401, `got ${bad.status}`);

  // `_t` mimics the client timestamp the server uses to reject instant bot
  // submissions; `hp` is the honeypot field, which must stay empty.
  const ok = await call("POST", "/api/auth/login", { username: "admin", password: "admin123", hp: "", _t: Date.now() - 2000 });
  check("valid login succeeds", ok.status === 200 && ok.data.user?.role === "admin", ok.data?.user?.full_name);

  const me = await call("GET", "/api/auth/me");
  check("GET  /api/auth/me reflects the session", me.data?.user?.username === "admin");
}

/* --------------------------------------------------------------- library -- */
section("Library");
let testBookId;
{
  const cats = (await call("GET", "/api/library/categories")).data;
  check("GET  /api/library/categories", Array.isArray(cats?.categories) && cats.categories.length > 0);

  const list = (await call("GET", "/api/library/books")).data;
  check("GET  /api/library/books", list?.books?.length > 0, `${list?.books?.length} titles`);

  const filtered = (await call("GET", "/api/library/books?q=clean")).data;
  check("book search filters correctly", filtered.books.length < list.books.length, `${filtered.books.length} match "clean"`);

  const created = await call("POST", "/api/library/books", {
    title: `Smoke Test Driven ${RUN}`, author: "QA Bot", isbn: TEST_ISBN, copiesTotal: 2, shelf: "TST",
  });
  check("POST /api/library/books", created.status === 201, created.data?.message ?? created.data?.errors?.join("; "));
  testBookId = created.data?.id;

  const dup = await call("POST", "/api/library/books", { title: "Dup", author: "X", isbn: TEST_ISBN });
  check("duplicate ISBN rejected", dup.status === 409, `got ${dup.status}`);

  const invalid = await call("POST", "/api/library/books", { author: "No Title" });
  check("missing title rejected", invalid.status === 400);

  const issued = await call("POST", "/api/library/loans", { bookId: testBookId, borrower: "Test Reader", rollNo: "T-001" });
  check("POST /api/library/loans (issue)", issued.status === 201, issued.data?.message);

  const loans = (await call("GET", "/api/library/loans")).data;
  const mine = loans.loans.find((l) => l.book_id === testBookId);
  check("loan appears with a due date", !!mine?.due_date);

  const returned = await call("POST", `/api/library/loans/${mine.id}/return`);
  check("POST /api/library/loans/:id/return", returned.status === 200, returned.data?.message);

  const twice = await call("POST", `/api/library/loans/${mine.id}/return`);
  check("double return rejected", twice.status === 409, `got ${twice.status}`);

  const del = await call("DELETE", `/api/library/books/${testBookId}`);
  check("DELETE /api/library/books/:id", del.status === 200, del.data?.message);
}

/* ----------------------------------------------------------------- store -- */
section("Store & billing");
{
  const cats = (await call("GET", "/api/store/categories")).data;
  check("GET  /api/store/categories", Array.isArray(cats?.categories) && cats.categories.length > 0);

  const list = (await call("GET", "/api/store/products")).data;
  check("GET  /api/store/products", list?.products?.length > 0, `${list?.products?.length} products`);
  check("stock health flag computed", list.products.every((p) => ["ok", "low", "out"].includes(p.stock_state)));

  const created = await call("POST", "/api/store/products", {
    sku: TEST_SKU, name: TEST_NAME, category: "Misc", price: 100, stock: 5, reorderLevel: 2,
  });
  check("POST /api/store/products", created.status === 201, created.data?.message ?? created.data?.errors?.join("; "));
  const pid = created.data?.id;

  const dup = await call("POST", "/api/store/products", { sku: TEST_SKU, name: "Dup", price: 10 });
  check("duplicate SKU rejected", dup.status === 409, `got ${dup.status}`);

  const stockBefore = (await call("GET", `/api/store/products?q=${encodeURIComponent(TEST_NAME)}`)).data.products[0]?.stock;

  const bill = await call("POST", "/api/store/bills", {
    customer: "Smoke Tester", payment: "UPI", discountPct: 10,
    items: [{ productId: pid, qty: 2 }],
  });
  check("POST /api/store/bills", bill.status === 201, bill.data?.message);
  // 200 subtotal − 20 discount = 180 taxable + 9 tax = 189
  check("bill maths is correct (₹200 −10% +5% = ₹189)", bill.data?.total === 189, `got ₹${bill.data?.total}`);

  const stockAfter = (await call("GET", "/api/store/products?q=Smoke Test Widget")).data.products[0].stock;
  check("stock decremented by the sale", stockAfter === stockBefore - 2, `${stockBefore} → ${stockAfter}`);

  const bills = (await call("GET", "/api/store/bills")).data;
  check("GET  /api/store/bills", bills?.bills?.length > 0, `${bills?.bills?.length} bills`);
  check("next bill number is offered", /^CNX-\d{6}$/.test(bills?.nextBillNo ?? ""), bills?.nextBillNo);

  const mine = bills.bills.find((x) => x.bill_no === bill.data.billNo);
  const full = (await call("GET", `/api/store/bills/${mine.id}`)).data;
  check("GET  /api/store/bills/:id returns line items", full?.bill?.items?.length === 1);

  // Ask for more units than remain. The quantity stays inside the schema's
  // allowed range so we are testing the STOCK check (409), not the range
  // validation (400).
  const remaining = stockAfter;
  const oversell = await call("POST", "/api/store/bills", {
    customer: "Greedy", items: [{ productId: pid, qty: remaining + 5 }],
  });
  check("overselling rejected", oversell.status === 409,
        `got ${oversell.status} ${oversell.data?.error ?? ""} ${(oversell.data?.errors ?? []).join("; ")}`);

  const tooMany = await call("POST", "/api/store/bills", {
    customer: "Greedy", items: [{ productId: pid, qty: 100000 }],
  });
  check("absurd quantity rejected by validation", tooMany.status === 400, `got ${tooMany.status}`);

  const empty = await call("POST", "/api/store/bills", { customer: "Nobody", items: [] });
  check("empty bill rejected", empty.status === 400);

  const restocked = await call("POST", `/api/store/products/${pid}/restock`, { add: 50 });
  check("POST restock", restocked.status === 200, restocked.data?.message);

  const archived = await call("DELETE", `/api/store/products/${pid}`);
  check("DELETE product archives (soft)", archived.status === 200, archived.data?.message);

  const low = (await call("GET", "/api/store/lowstock")).data;
  check("GET  /api/store/lowstock", Array.isArray(low?.products));
}

/* --------------------------------------------------------------- arcade --- */
section("Arcade");
{
  const board = (await call("GET", "/api/arcade/leaderboard")).data;
  check("GET  /api/arcade/leaderboard", Array.isArray(board?.entries) && board.entries.length > 0);
  check("per-game summary present", board?.summary?.length === 2);

  const stats = (await call("GET", "/api/arcade/stats")).data;
  check("GET  /api/arcade/stats", stats?.games === 2, `${stats?.plays} plays`);

  const saved = await call("POST", "/api/arcade/score", {
    game: "guess", player: "Smoke Bot", score: 120, detail: "Range 1-100 · 2 attempts",
  });
  check("POST /api/arcade/score", saved.status === 201, saved.data?.message);

  const bad = await call("POST", "/api/arcade/score", { game: "guess", player: "X", score: 0 });
  check("zero score rejected", bad.status === 400);
}

/* ---------------------------------------------------------------- logout -- */
section("Session");
{
  await call("POST", "/api/auth/logout");
  check("logout reports success", jar.get("cnx_sid") === "" || !jar.get("cnx_sid"), "session cookie cleared");
  // Logging out also clears the CSRF cookie, so the next request gets a fresh
  // one on its priming GET — exactly what a real page reload does.
  jar.delete("cnx_csrf");
  await prime();
  const after = await call("POST", "/api/store/products", { name: "After Logout", price: 5, stock: 0 });
  check("session revoked after logout", after.status === 401, `got ${after.status}`);
}

/* -------------------------------------------------------------- summary --- */
console.log(`\n${"─".repeat(58)}`);
console.log(`  ${green(`${pass} passed`)}` + (fail ? `, ${red(`${fail} failed`)}` : `, ${dim("0 failed")}`));
console.log("");
process.exit(fail ? 1 : 0);