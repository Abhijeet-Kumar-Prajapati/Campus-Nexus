/* ============================================================================
   Campus Nexus - browser-only demo backend.

   WHY THIS EXISTS
   ---------------
   GitHub Pages serves static files. Campus Nexus is a Node server with a
   SQLite file, so Pages cannot host the real thing - that is a property of
   Pages, not something to configure away. What Pages *can* do is serve the
   application's own bundle, and that bundle is a client-rendered app whose
   every screen reads from /api/*.

   So this file answers those /api/* calls from a snapshot of the real
   demo dataset, taken from a running server (site-demo/data.json). The
   application code is untouched - the same minified bundle that
   `npm run serve:prod` serves is what loads here.

   WHAT IS REAL AND WHAT IS NOT
   ----------------------------
   Real:  the interface, every screen, the navigation, the charts, the
          arcade games, the data - it is a snapshot of the actual seed
          catalogue rather than made-up filler.
   Not:   the server. There is no scrypt, no AES-256-GCM, no hash chain,
          no rate limiter, no session binding, nothing enforced. Those are
          properties of the Node process, and a page in a browser cannot
          have them. The Security Centre therefore reports sample posture,
          not a live one.

   The page says so. This file does not pretend otherwise.
   ========================================================================== */

(function () {
  "use strict";

  /* The snapshot sits beside this file, so it is resolved against this
     script's own URL. The application bundle lives at the repository root,
     one level up, so that is resolved against ROOT instead. */
  const HERE = document.currentScript ? document.currentScript.src : location.href;
  const ROOT = new URL("../", HERE).href;
  const DATA_URL = new URL("data.json", HERE).href;

  /* ------------------------------------------------------------- state --- */
  const S = {
    user: null,
    books: [],
    products: [],
    loans: [],
    bills: [],
    scores: [],
    events: [],
    chainBlocks: [],
    posture: null,
    analytics: null,
    dashboard: null,
    raw: {},
    loaded: false,
  };

  /* --------------------------------------------------------- utilities --- */
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const nowIso = () => new Date().toISOString().slice(0, 19).replace("T", " ");
  const today = () => new Date().toISOString().slice(0, 10);

  function plusDays(n) {
    const d = new Date();
    d.setDate(d.getDate() + n);
    return d.toISOString().slice(0, 10);
  }

  function json(body, status = 200) {
    return new Response(JSON.stringify(body), {
      status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      },
    });
  }

  const fail = (error, status = 400, extra = {}) =>
    json({ ok: false, error, ...extra }, status);

  const needAuth = () =>
    fail("Please sign in to perform this action", 401, { requiresAuth: true });

  function money(n) {
    return Math.round((Number(n) + Number.EPSILON) * 100) / 100;
  }

  /* -------------------------------------------------------- recomputes --- */
  function libraryStats() {
    const active = S.books.filter((b) => b.active !== 0);
    return {
      ok: true,
      titles: active.length,
      copies: active.reduce((s, b) => s + b.copies_total, 0),
      available: active.reduce((s, b) => s + b.copies_available, 0),
      issued: S.loans.filter((l) => l.status === "issued").length,
      overdue: S.loans.filter(
        (l) => l.status === "issued" && l.due_date && l.due_date < today()
      ).length,
      returned: S.loans.filter((l) => l.status === "returned").length,
      finePending: money(
        S.loans
          .filter((l) => l.status === "issued" && Number(l.fine) > 0)
          .reduce((a, l) => a + Number(l.fine), 0)
      ),
      fineCollected: money(
        S.loans
          .filter((l) => l.status === "returned" && Number(l.fine) > 0)
          .reduce((a, l) => a + Number(l.fine), 0)
      ),
      utilisation: (() => {
        const copies = active.reduce((a, b) => a + b.copies_total, 0);
        const free = active.reduce((a, b) => a + b.copies_available, 0);
        return copies === 0 ? 0 : Math.round(((copies - free) / copies) * 100);
      })(),
    };
  }

  function storeStats() {
    const live = S.products.filter((p) => p.active !== 0);
    const stamp = today();
    const todays = S.bills.filter((b) => String(b.created_at || "").slice(0, 10) === stamp);

    const paymentMix = [];
    for (const mode of ["Cash", "Card", "UPI"]) {
      const rows = S.bills.filter((b) => (b.payment || "Cash") === mode);
      if (!rows.length) continue;
      paymentMix.push({ payment: mode, n: rows.length, amt: money(rows.reduce((a, b) => a + Number(b.total || 0), 0)) });
    }

    const best = {};
    for (const b of S.bills) {
      for (const it of b.items || []) best[it.name] = (best[it.name] || 0) + it.qty;
    }
    const top = Object.entries(best).sort((a, b) => b[1] - a[1])[0];

    return {
      ok: true,
      products: live.length,
      units: live.reduce((s, p) => s + p.stock, 0),
      inventoryValue: money(live.reduce((s, p) => s + p.stock * p.price, 0)),
      outOfStock: live.filter((p) => p.stock === 0).length,
      lowStock: live.filter((p) => p.stock > 0 && p.stock <= p.reorder_level).length,
      bills30d: S.bills.length,
      revenue30d: money(S.bills.reduce((a, b) => a + Number(b.total || 0), 0)),
      discount30d: money(S.bills.reduce((a, b) => a + Number(b.discount || 0), 0)),
      billsToday: todays.length,
      revenueToday: money(todays.reduce((a, b) => a + Number(b.total || 0), 0)),
      bestSeller: top ? { name: top[0], qty: top[1] } : null,
      paymentMix,
    };
  }

  function stockState(p) {
    if (p.stock === 0) return "out";
    return p.stock <= p.reorder_level ? "low" : "ok";
  }

  function decorate(list, key, extra) {
    return { ok: true, [key]: list.map((x) => ({ ...extra(x) })) };
  }

  /* ------------------------------------------------------- the handlers --- */
  const GET = {
    "/api/system/health": () => ({ ok: true, uptime: 0, tables: 20, node: "browser demo" }),

    "/api/system/dashboard": () => S.dashboard,

    "/api/system/activity": () => ({ ok: true, activity: S.raw.activity?.activity ?? [] }),

    "/api/auth/me": () =>
      S.user
        ? { ok: true, user: S.user, session: { idleMinutes: 30, absoluteMinutes: 480 } }
        : (() => { throw Object.assign(new Error("Not signed in"), { status: 401 }); })(),

    "/api/auth/users": () =>
      S.user?.role === "admin"
        ? { ok: true, users: S.raw.users?.users ?? [] }
        : { ok: false, error: "Administrators only" },

    "/api/library/stats": libraryStats,
    "/api/library/books": () => ({ ok: true, books: S.books.map((b) => ({ ...b })) }),
    "/api/library/categories": () => ({
      ok: true,
      categories: [...new Set(S.books.map((b) => b.category).filter(Boolean))].sort(),
    }),
    "/api/library/loans": () => ({ ok: true, loans: S.loans.map((l) => ({ ...l })) }),

    "/api/store/stats": storeStats,
    "/api/store/products": () => ({
      ok: true,
      products: S.products.map((p) => ({ ...p, stock_state: stockState(p) })),
    }),
    "/api/store/categories": () => ({
      ok: true,
      categories: [...new Set(S.products.map((p) => p.category).filter(Boolean))].sort(),
    }),
    "/api/store/lowstock": () => ({
      ok: true,
      products: S.products
        .filter((p) => p.active !== 0 && p.stock <= p.reorder_level)
        .map((p) => ({ ...p, stock_state: stockState(p) })),
    }),
    "/api/store/bills": () => ({
      ok: true,
      bills: S.bills.map((b) => ({ ...b })),
      nextBillNo: nextBillNo(),
    }),
    "/api/store/analytics": () => S.analytics,

    "/api/arcade/stats": () => ({
      ok: true,
      plays: S.raw.arcadeStats?.plays ?? 0,
      players: S.raw.arcadeStats?.players ?? 0,
      games: S.raw.arcadeStats?.games ?? [],
    }),
    "/api/arcade/leaderboard": (url) => leaderboard(url.searchParams.get("game") || "guess"),

    "/api/security/posture": () => S.posture,
    "/api/security/events": () => S.raw.events ?? { ok: true, events: [], summary: {} },
    "/api/security/chain": () => S.raw.chain ?? { ok: true, height: 0, verified: true },
    "/api/security/chain/blocks": () => ({ ok: true, blocks: S.chainBlocks }),
  };

  function nextBillNo() {
    let max = 100000;
    for (const b of S.bills) {
      const n = parseInt(String(b.bill_no || "").slice(4), 10);
      if (Number.isFinite(n) && n > max) max = n;
    }
    return "CNX-" + String(max + 1).padStart(6, "0");
  }

  function leaderboard(game) {
    const rows = S.scores
      .filter((s) => s.game === game)
      .sort((a, b) => b.score - a.score)
      .slice(0, 20)
      .map((s, i) => ({ ...s, rank: i + 1 }));
    return { ok: true, entries: rows, summary: summarise(rows) };
  }

  function summarise(rows) {
    const out = {};
    for (const r of rows) {
      out[r.game] ??= { plays: 0, best: 0, top: null };
      out[r.game].plays += 1;
      if (r.score > out[r.game].best) { out[r.game].best = r.score; out[r.game].top = r.player; }
    }
    return Object.entries(out).map(([game, v]) => ({ game, ...v }));
  }

  function record(kind, detail) {
    S.events.unshift({
      id: Date.now() + Math.random(),
      event_type: kind,
      severity: "info",
      detail,
      at: nowIso(),
      ip: "browser demo",
    });
    S.events = S.events.slice(0, 300);
  }

  /* -------------------------------------------------------------- POST --- */
  const POST = {
    "/api/auth/login": async (_url, body) => {
      const { username, password } = body || {};
      if (!username || !password) return fail("Enter a username and password");
      // The honeypot and the minimum-submit-time check belong to the server.
      // They are reproduced so the demo behaves the same way, not skipped.
      if (body.hp) return fail("Sign-in failed", 401);
      const elapsed = Date.now() - Number(body._t ?? Date.now());
      if (elapsed >= 0 && elapsed < 1200) {
        return fail("Please take a moment and try again", 429, { limited: true, retryAfter: 2 });
      }
      const known = [
        { username: "admin", password: "admin123", full_name: "Abhijeet Kumar Prajapati", role: "admin" },
        { username: "staff", password: "staff123", full_name: "Counter Staff", role: "staff" },
      ];
      const u = known.find((x) => x.username === username);
      // Unknown users pay the same cost and get the same message.
      if (!u || u.password !== password) {
        record("failed-signin", `Failed sign-in for "${username}"`);
        return fail("Sign-in failed", 401);
      }
      S.user = { username: u.username, full_name: u.full_name, role: u.role };
      record("signin", `${u.full_name} signed in`);
      return {
        ok: true,
        user: S.user,
        message: `Welcome back, ${u.full_name.split(" ")[0]}!`,
        session: { idleMinutes: 30, absoluteMinutes: 480 },
      };
    },

    "/api/auth/logout": async () => {
      S.user = null;
      return { ok: true, message: "Signed out" };
    },

    "/api/auth/password-check": async () => ({ ok: true, strong: true }),

    "/api/auth/change-password": async () => {
      if (!S.user) return needAuth();
      return { ok: true, message: "Password changed (demo - nothing was stored)" };
    },

    "/api/auth/users/:id/unlock": async (url) => {
      if (S.user?.role !== "admin") return fail("Administrators only", 403);
      record("admin-unlock", "Administrator unlocked an account");
      return { ok: true, message: "Account unlocked" };
    },

    "/api/security/reset": async () => {
      if (S.user?.role !== "admin") return fail("Administrators only", 403);
      record("security-reset", "Administrator cleared all rate limits");
      return { ok: true, message: "All rate limits cleared, 1 account(s) unlocked" };
    },

    "/api/security/revoke-sessions": async () => {
      if (S.user?.role !== "admin") return fail("Administrators only", 403);
      record("mass-logout", "Administrator revoked every live session");
      return { ok: true, message: "Session(s) revoked - everyone must sign in again", revoked: 1 };
    },

    "/api/library/books": async (_url, body) => {
      if (!S.user) return needAuth();
      const b = body || {};
      if (!b.title) return fail("Book title is required");
      if (!b.author) return fail("Author is required");
      if (b.isbn) {
        const dup = S.books.find((x) => x.isbn === b.isbn);
        if (dup) return fail(`ISBN ${b.isbn} already exists in the catalogue`, 409);
      }
      const total = Number(b.copiesTotal) || 1;
      const book = {
        id: nextId(S.books),
        isbn: b.isbn || null,
        title: b.title,
        author: b.author,
        publisher: b.publisher ?? null,
        category: b.category || "General",
        edition: b.edition ?? null,
        year: b.year ?? null,
        copies_total: total,
        copies_available: total,
        shelf: b.shelf ?? null,
        notes: b.notes ?? null,
        created_at: nowIso(),
        active_loans: 0,
      };
      S.books.push(book);
      record("book-added", `Added “${book.title}”`);
      return json({ ok: true, id: book.id, book, message: `“${book.title}” added` }, 201);
    },

    "/api/library/loans": async (_url, body) => {
      if (!S.user) return needAuth();
      const b = body || {};
      if (!b.bookId) return fail("A bookId is required");
      const book = S.books.find((x) => x.id === Number(b.bookId));
      if (!book) return fail("Book not found", 404);
      if (book.copies_available < 1) return fail(`No copy of “${book.title}” is currently available`, 409);
      if (!b.borrower) return fail("Borrower name is required");
      const due = b.dueDate || plusDays(Number(b.days) || 15);
      const loan = {
        id: nextId(S.loans),
        book_id: book.id,
        borrower: b.borrower,
        roll_no: b.rollNo ?? null,
        contact: b.contact ?? null,
        issue_date: today(),
        due_date: due,
        status: "issued",
      };
      S.loans.unshift(loan);
      book.copies_available -= 1;
      book.active_loans = (book.active_loans || 0) + 1;
      record("book-issued", `“${book.title}” → ${b.borrower}`);
      return json({ ok: true, id: loan.id, message: `“${book.title}” issued to ${b.borrower}`, due }, 201);
    },

    "/api/library/loans/:id/return": async (url) => {
      if (!S.user) return needAuth();
      const loan = S.loans.find((x) => x.id === Number(url.pathname.split("/").pop()));
      if (!loan) return fail("Loan not found", 404);
      if (loan.status === "returned") return fail("That copy is already returned", 409);
      loan.status = "returned";
      loan.returned_at = nowIso();
      const book = S.books.find((x) => x.id === loan.book_id);
      if (book) { book.copies_available += 1; book.active_loans = Math.max(0, (book.active_loans || 1) - 1); }
      record("book-returned", `${loan.borrower} returned a copy`);
      return { ok: true, message: "Returned. Thank you." };
    },

    "/api/store/products": async (_url, body) => {
      if (!S.user) return needAuth();
      const p = body || {};
      if (!p.name) return fail("Product name is required");
      if (!p.sku) return fail("SKU is required");
      if (S.products.some((x) => x.sku === p.sku && x.active !== 0)) {
        return fail(`SKU ${p.sku} is already in the catalogue`, 409);
      }
      if (!(Number(p.price) >= 0)) return fail("price must be a number");
      const prod = {
        id: nextId(S.products),
        sku: p.sku,
        name: p.name,
        category: p.category || "General",
        price: Number(p.price),
        stock: Number(p.stock) || 0,
        reorder_level: Number(p.reorderLevel) || 0,
        supplier: p.supplier ?? null,
        description: p.description ?? null,
        active: 1,
        created_at: nowIso(),
      };
      S.products.push(prod);
      record("product-added", `Added ${prod.name}`);
      return json({ ok: true, id: prod.id, product: prod, message: `${prod.name} added` }, 201);
    },

    "/api/store/products/:id/restock": async (url, body) => {
      if (!S.user) return needAuth();
      const id = Number(url.pathname.split("/")[4]);
      const prod = S.products.find((x) => x.id === id);
      if (!prod) return fail("Product not found", 404);
      const add = Number(body?.add);
      // The server-side guard that was missing: a restock with no quantity
      // must not answer 200 and change nothing.
      if (!add || add < 1) return fail("Restock quantity is required");
      prod.stock += Math.trunc(add);
      record("restock", `${prod.name} +${add} units`);
      return { ok: true, message: `${prod.name}: +${add} units in stock` };
    },

    "/api/store/bills": async (_url, body) => {
      if (!S.user) return needAuth();
      const items = body?.items;
      if (!Array.isArray(items) || !items.length) return fail("Add at least one item to the bill");
      if (!body.customer) return fail("Customer name is required");
      const discountPct = Number(body.discountPct) || 0;

      const lines = [];
      let subtotal = 0;
      for (const it of items) {
        if (!it.productId) return fail("Every item needs a productId");
        const prod = S.products.find((x) => x.id === Number(it.productId) && x.active !== 0);
        if (!prod) return fail("One of the items is no longer available in the inventory");
        const qty = Math.trunc(Number(it.qty) || 1);
        if (qty < 1) return fail("Quantity must be at least 1");
        if (prod.stock < qty) {
          return fail(`Only ${prod.stock} unit(s) of “${prod.name}” left in stock`, 409);
        }
        const amount = money(prod.price * qty);
        subtotal += amount;
        lines.push({ product_id: prod.id, name: prod.name, sku: prod.sku, qty, rate: prod.price, amount });
      }

      const discount = money((subtotal * discountPct) / 100);
      const taxable = money(subtotal - discount);
      const tax = money(taxable * 0.05);
      const total = money(taxable + tax);

      for (const l of lines) {
        const prod = S.products.find((x) => x.id === l.product_id);
        prod.stock -= l.qty;
      }

      const bill = {
        id: nextId(S.bills),
        bill_no: nextBillNo(),
        customer: body.customer,
        phone: body.phone ?? null,
        payment: body.payment || "Cash",
        subtotal: money(subtotal),
        discount: money(discount),
        tax,
        total,
        items: lines,
        created_at: nowIso(),
      };
      S.bills.unshift(bill);
      record("bill-created", `${bill.bill_no} · ₹${total}`);
      return json({ ok: true, id: bill.id, bill, message: `Bill ${bill.bill_no} created` }, 201);
    },

    "/api/arcade/score": async (_url, body) => {
      if (!S.user) return needAuth();
      const s = body || {};
      const score = Number(s.score);
      if (!s.game) return fail("game is required");
      if (!(score > 0)) return fail("Score must be greater than zero");
      if (!s.player) return fail("Enter a player name");
      const entry = {
        id: nextId(S.scores),
        game: s.game,
        player: String(s.player).slice(0, 40),
        score: Math.trunc(score),
        detail: s.detail ?? null,
        at: nowIso(),
      };
      S.scores.push(entry);
      const rank = leaderboard(s.game).entries.findIndex((e) => e.id === entry.id) + 1;
      record("arcade-score", `${entry.player} scored ${entry.score} in ${s.game}`);
      return json({ ok: true, id: entry.id, rank, message: `${entry.player} — ${entry.score} pts (rank #${rank} in ${s.game})` }, 201);
    },
  };

  const PUT = {
    "/api/library/books/:id": async (url, body) => {
      if (!S.user) return needAuth();
      const book = S.books.find((x) => x.id === Number(url.pathname.split("/").pop()));
      if (!book) return fail("Book not found", 404);
      const b = body || {};
      if (!b.title) return fail("Book title is required");
      if (!b.author) return fail("Author is required");
      const onLoan = book.copies_total - book.copies_available;
      const total = Number(b.copiesTotal) || 1;
      if (total < onLoan) {
        return fail(`${onLoan} copy/copies are currently issued — total cannot go below ${onLoan}`);
      }
      if (b.isbn && b.isbn !== book.isbn && S.books.some((x) => x.isbn === b.isbn && x.id !== book.id)) {
        return fail(`ISBN ${b.isbn} already exists in the catalogue`, 409);
      }
      Object.assign(book, {
        isbn: b.isbn || null,
        title: b.title,
        author: b.author,
        publisher: b.publisher ?? null,
        category: b.category || book.category,
        edition: b.edition ?? null,
        year: b.year ?? book.year,
        copies_total: total,
        copies_available: total - onLoan,
        shelf: b.shelf ?? null,
        notes: b.notes ?? null,
      });
      record("book-updated", `Updated “${book.title}”`);
      return { ok: true, message: `“${book.title}” updated` };
    },

    "/api/store/products/:id": async (url, body) => {
      if (!S.user) return needAuth();
      const prod = S.products.find((x) => x.id === Number(url.pathname.split("/").pop()));
      if (!prod) return fail("Product not found", 404);
      const p = body || {};
      if (!p.name) return fail("Product name is required");
      if (!p.sku) return fail("SKU is required");
      if (S.products.some((x) => x.sku === p.sku && x.id !== prod.id && x.active !== 0)) {
        return fail(`SKU ${p.sku} is already in the catalogue`, 409);
      }
      Object.assign(prod, {
        sku: p.sku, name: p.name, category: p.category || prod.category,
        price: Number(p.price), stock: Number(p.stock) || 0,
        reorder_level: Number(p.reorderLevel) || 0,
        supplier: p.supplier ?? prod.supplier,
        description: p.description ?? prod.description,
      });
      record("product-updated", `Updated ${prod.name}`);
      return { ok: true, message: `${prod.name} updated` };
    },
  };

  const DELETE = {
    "/api/library/books/:id": async (url) => {
      if (!S.user) return needAuth();
      const id = Number(url.pathname.split("/").pop());
      const book = S.books.find((x) => x.id === id);
      if (!book) return fail("Book not found", 404);
      if (book.active_loans > 0) {
        return fail("That title has copies on loan. Return them before removing it.", 409);
      }
      book.active = 0;
      record("book-archived", `Archived “${book.title}”`);
      return { ok: true, message: `“${book.title}” archived` };
    },

    "/api/store/products/:id": async (url) => {
      if (!S.user) return needAuth();
      const id = Number(url.pathname.split("/").pop());
      const prod = S.products.find((x) => x.id === id);
      if (!prod) return fail("Product not found", 404);
      prod.active = 0;
      record("product-archived", `Archived ${prod.name}`);
      return { ok: true, message: `${prod.name} archived. Past bills keep their record.` };
    },
  };

  function nextId(list) {
    return list.reduce((m, x) => Math.max(m, Number(x.id) || 0), 0) + 1;
  }

  /* -------------------------------------------------------- search ------- */
  function search(q) {
    const needle = String(q || "").trim().toLowerCase();
    if (!needle) return { ok: true, results: [] };
    const out = [];
    const push = (kind, id, title, sub) => {
      if (String(title).toLowerCase().includes(needle)) out.push({ kind, id, title, sub });
    };
    for (const b of S.books) push("book", b.id, b.title, `${b.author} · ${b.category}`);
    for (const p of S.products) if (p.active !== 0) push("product", p.id, p.name, `${p.sku} · ${p.category}`);
    for (const c of S.bills) push("bill", c.id, c.bill_no, `${c.customer} · ₹${c.total}`);
    return { ok: true, results: out.slice(0, 40) };
  }

  /* ------------------------------------------------------- dispatch ------ */
  async function route(method, path, url, body) {
    if (method === "GET") {
      if (path === "/api/system/search") return search(url.searchParams.get("q"));
      if (path.startsWith("/api/store/bills/")) {
        const id = Number(path.split("/").pop());
        const bill = S.bills.find((x) => x.id === id);
        return bill ? { ok: true, bill: { ...bill } } : fail("Bill not found", 404);
      }
      const h = GET[path];
      if (!h) return fail("Not found", 404);
      try { return await h(url); } catch (e) { return fail("Not signed in", 401, { requiresAuth: true }); }
    }
    const table = { POST, PUT, DELETE }[method];
    if (table) {
      for (const [pattern, fn] of Object.entries(table)) {
        const rx = new RegExp("^" + pattern.replace(/:id/g, "\\d+") + "$");
        if (rx.test(path)) {
          try { return await fn(url, body); } catch (e) { return fail(e.message || "Something went wrong", 500); }
        }
      }
    }
    return fail("Not found", 404);
  }

  /* --------------------------------------------------------- install ----- */
  function install() {
    const real = window.fetch.bind(window);

    window.fetch = async function (input, init) {
      let raw = typeof input === "string" ? input : input.url;
      let method = (init?.method || (typeof input === "object" && input.method) || "GET").toUpperCase();
      let body = init?.body;
      if (body && typeof body === "string") { try { body = JSON.parse(body); } catch { body = null; } }

      // Anything not aimed at the API goes to the network untouched.
      if (!raw.startsWith("/api/")) return real(input, init);

      const url = new URL(raw, location.origin);
      if (!S.loaded) return json({ ok: false, error: "Demo data is still loading" }, 503);

      let out;
      try {
        out = await route(method, url.pathname, url, body);
      } catch (e) {
        out = fail(e?.message || "Demo backend error", 500);
      }
      return out instanceof Response ? out : json(out);
    };
  }

  /* The client reads its CSRF token out of document.cookie and refuses to
     send a write without it. There is no server here to mint a signed one,
     so a placeholder is set - the demo has no CSRF attack surface to
     protect, because it has no server to protect. */
  function fakeCsrfCookie() {
    if (!document.cookie.includes("cnx_csrf=")) {
      document.cookie = "cnx_csrf=browser-demo-placeholder; path=/; SameSite=Strict";
    }
  }

  async function boot() {
    let raw;
    try {
      const res = await realFetch(DATA_URL);
      raw = await res.json();
    } catch (e) {
      document.documentElement.innerHTML =
        '<body style="background:#0a0d14;color:#e9edf7;font:15px system-ui;padding:60px">' +
        "<h1>Demo data failed to load</h1><p>" + String(e.message || e) + "</p></body>";
      return;
    }

    S.raw = raw;
    S.books = clone(raw.books?.books ?? []);
    S.products = clone(raw.products?.products ?? []);
    S.loans = clone(raw.loans?.loans ?? []);
    S.bills = clone(raw.bills?.bills ?? []);
    S.events = clone(raw.events?.events ?? []);
    S.chainBlocks = (raw.chainBlocks?.blocks ?? []).slice(0, 24);
    S.posture = raw.posture ?? null;
    S.analytics = raw.analytics ?? null;
    S.dashboard = raw.dashboard ?? null;

    // Seed the leaderboards from the snapshot so they are not empty on load.
    for (const [key, game] of [["leaderboard", "guess"], ["leaderboardSwg", "swg"]]) {
      for (const e of raw[key]?.entries ?? []) {
        S.scores.push({ id: S.scores.length + 1, game, player: e.player, score: e.score, detail: e.detail, at: nowIso() });
      }
    }

    fakeCsrfCookie();
    install();
    S.loaded = true;

    // Let the application boot once the backend is answering.
    document.documentElement.setAttribute("data-demo-ready", "1");
    const m = document.createElement("script");
    m.type = "module";
    m.src = new URL("public/dist/js/app.min.js", ROOT).href;
    document.body.appendChild(m);
    await awaitMount();
    installBanner();
  }

  /* ------------------------------------------------------------ banner ---
     The application mounts with document.body.innerHTML = ..., so anything
     demo.html placed in the body is destroyed on boot. The honesty notice is
     not optional enough to lose to a detail like that, so the style and the
     bar are re-added once the sidebar proves the app has rendered. */
  const BANNER_CSS = [
    ".demo-bar{position:fixed;top:0;left:0;right:0;z-index:999;display:flex;align-items:center;",
    "justify-content:center;gap:10px;flex-wrap:wrap;padding:7px 14px;",
    "background:linear-gradient(90deg,#6d28d9,#2563eb);color:#fff;",
    "font:600 12.5px/1.4 system-ui,-apple-system,sans-serif;text-align:center}",
    ".demo-bar b{font-weight:800}",
    ".demo-bar a{color:#fff;text-decoration:underline;text-underline-offset:2px}",
    "#content,.main{padding-top:42px}",
    "@media (max-width:640px){.demo-bar{font-size:11.5px;padding:6px 10px}}",
  ].join("");

  function installBanner() {
    if (document.querySelector(".demo-bar")) return;
    const style = document.createElement("style");
    style.textContent = BANNER_CSS;
    document.head.appendChild(style);

    const bar = document.createElement("div");
    bar.className = "demo-bar";
    const strong = document.createElement("b");
    strong.textContent = "Live demo";
    bar.appendChild(strong);
    bar.appendChild(
      document.createTextNode(
        "Running entirely in your browser against a snapshot of the demo data" +
        " \u2014 no server, so encryption, the hash chain and rate limiting are the" +
        " real application's, not this page's."
      )
    );
    const a = document.createElement("a");
    a.href = "https://github.com/Abhijeet-Kumar-Prajapati/Campus-Nexus";
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = "See the source";
    bar.appendChild(a);
    document.body.prepend(bar);
  }

  /* Waits for the application to render rather than guessing a delay. */
  function awaitMount() {
    return new Promise((resolve) => {
      const have = () => !!document.querySelector(".sidebar, #app .app");
      if (have()) return resolve();
      const io = new MutationObserver(() => {
        if (have()) { io.disconnect(); resolve(); }
      });
      io.observe(document.documentElement, { childList: true, subtree: true });
      // Never hang the demo on a missing hook.
      setTimeout(() => { io.disconnect(); resolve(); }, 8000);
    });
  }

  const realFetch = window.fetch.bind(window);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
