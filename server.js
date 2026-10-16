// ============================================================================
//   CAMPUS NEXUS  ·  application server
//   Node's built-in http + node:sqlite only — no npm install required.
//
//     node server.js        →  http://localhost:3000
//
//   One application that fuses three original projects:
//     · Library Management System   (Java Swing + MySQL)
//     · Shopping Mall / Billing     (Java Swing + MySQL)
//     · C-language Arcade           (Number Guessing + Snake-Water-Gun)
//
//   SECURITY PIPELINE (applied to every request, in order):
//     1. security headers      5. CSRF verification
//     2. request size guard    6. session resolution + rotation
//     3. global rate limit     7. routing
//     4. tiered rate limit
// ============================================================================
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { networkInterfaces } from "node:os";

import { DB_PATH, db } from "./src/db.js";
import { Router, json, fail, serveStatic, parseCookies } from "./src/http.js";

import * as auth from "./src/routes/auth.routes.js";
import * as lib from "./src/routes/library.routes.js";
import * as store from "./src/routes/store.routes.js";
import * as arcade from "./src/routes/arcade.routes.js";
import * as system from "./src/routes/system.routes.js";
import * as sec from "./src/routes/security.routes.js";

import * as mw from "./src/security/middleware.js";
import * as audit from "./src/security/audit.js";
import { CONFIG } from "./src/security/config.js";
import { applyApiHeaders } from "./src/security/headers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "public");
const PORT = Number(process.env.PORT) || 3000;

mw.bindDatabase(db);

/* ---------------------------------------------------------------- routes --- */
const r = new Router();

/* ---- public reads ---- */
r.get("/api/system/health", (req, res) => json(res, system.health()));
r.get("/api/system/dashboard", (req, res) => json(res, system.dashboard()));
r.get("/api/system/search", (req, res, _p, url) =>
  json(res, { ok: true, ...system.globalSearch((url.searchParams.get("q") ?? "").trim()) })
);
r.get("/api/system/activity", (req, res, _p, url) =>
  json(res, {
    ok: true,
    activity: db
      .prepare(`SELECT * FROM activity ORDER BY created_at DESC, id DESC LIMIT ?`)
      .all(Math.min(100, Math.max(1, Number(url.searchParams.get("limit") ?? 30)))),
  })
);

/* ---- auth ---- */
r.post("/api/auth/login", auth.login);
r.post("/api/auth/logout", auth.logout);
r.get("/api/auth/me", auth.me);
r.post("/api/auth/change-password", auth.changePassword);
r.post("/api/auth/password-check", auth.passwordCheck);
r.get("/api/auth/users", auth.listUsers);
r.post("/api/auth/users/:id/unlock", auth.unlockUser);

/* ---- security ---- */
r.get("/api/security/posture", sec.posture);
r.get("/api/security/events", sec.events);
r.get("/api/security/chain", sec.chainStatus);
r.get("/api/security/chain/blocks", sec.chainBlocks);
r.post("/api/security/reset", sec.emergencyReset);
r.post("/api/security/revoke-sessions", sec.revokeAllSessions);

/* ---- library ---- */
r.get("/api/library/stats", (req, res) => json(res, { ok: true, ...lib.libraryStats() }));
r.get("/api/library/books", (req, res, _p, url) =>
  json(res, { ok: true, books: lib.listBooks(url.searchParams.get("q") ?? "", url.searchParams.get("category") ?? "") })
);
r.get("/api/library/categories", (req, res) => json(res, { ok: true, categories: lib.bookCategories() }));
r.post("/api/library/books", mw.requireAuth, lib.createBook);
r.put("/api/library/books/:id", mw.requireAuth, lib.updateBook);
r.delete("/api/library/books/:id", mw.requireAuth, lib.deleteBook);
r.get("/api/library/loans", (req, res, _p, url) =>
  json(res, { ok: true, loans: lib.listLoans(url.searchParams.get("status") ?? "all") })
);
r.post("/api/library/loans", mw.requireAuth, lib.issueBook);
r.post("/api/library/loans/:id/return", mw.requireAuth, lib.returnBook);

/* ---- store ---- */
r.get("/api/store/stats", (req, res) => json(res, { ok: true, ...store.storeStats() }));
r.get("/api/store/products", (req, res, _p, url) =>
  json(res, { ok: true, products: store.listProducts(url.searchParams.get("q") ?? "", url.searchParams.get("category") ?? "") })
);
r.get("/api/store/categories", (req, res) => json(res, { ok: true, categories: store.productCategories() }));
r.get("/api/store/lowstock", (req, res) => json(res, { ok: true, products: store.lowStock() }));
r.post("/api/store/products", mw.requireAuth, store.createProduct);
r.put("/api/store/products/:id", mw.requireAuth, store.updateProduct);
r.delete("/api/store/products/:id", mw.requireAuth, store.deleteProduct);
r.post("/api/store/products/:id/restock", mw.requireAuth, store.restock);
r.get("/api/store/bills", (req, res, _p, url) =>
  json(res, {
    ok: true,
    bills: store.listBills(url.searchParams.get("q") ?? "", url.searchParams.get("from") ?? "", url.searchParams.get("to") ?? ""),
    nextBillNo: store.nextBillNo(),
  })
);
r.get("/api/store/bills/:id", (req, res, { id }) => {
  const bill = store.getBill(id);
  return bill ? json(res, { ok: true, bill }) : fail(res, "Bill not found", 404);
});
r.post("/api/store/bills", mw.requireAuth, store.createBill);
r.get("/api/store/analytics", (req, res, _p, url) =>
  json(res, {
    ok: true,
    series: store.salesSeries(Number(url.searchParams.get("days") ?? 14)),
    top: store.topProducts(6),
    taxPct: store.TAX_PCT,
  })
);

/* ---- arcade ---- */
r.get("/api/arcade/stats", (req, res) => json(res, { ok: true, ...arcade.arcadeStats() }));
r.get("/api/arcade/leaderboard", (req, res, _p, url) =>
  json(res, { ok: true, ...arcade.leaderboard(url.searchParams.get("game") ?? "all", 20) })
);
r.post("/api/arcade/score", arcade.saveScore);

/* --------------------------------------------------------------- server --- */
const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
  const { pathname } = url;

  // Convenience helpers so route handlers stay terse.
  res.json = (data, status = 200) => {
    applyApiHeaders(res, { csrfToken: req.csrfToken });
    json(res, data, status);
  };
  res.fail = (message, status = 400, extra = {}) => res.json({ ok: false, error: message, ...extra }, status);

  try {
    /* ---- 1–6: security pipeline -------------------------------------- */
    // Each stage may end the response itself (headers, limits, CSRF, session).
    // `runStage` makes that explicit: a stage must either answer the client or
    // return undefined. Returning a value is treated as "stop here", and a
    // stage that stops without answering is caught as a bug rather than
    // hanging the browser until it times out.
    const runStage = (stage) => {
      const result = stage(req, res);
      if (result !== undefined && !res.writableEnded) {
        console.error(`✖ middleware ${stage.name} returned without ending the response`);
        res.json({ ok: false, error: "Request blocked" }, 500);
      }
      return res.writableEnded;
    };

    if (runStage(mw.securityHeaders)) return;
    if (runStage(mw.sizeGuard)) return;
    if (runStage(mw.globalLimit)) return;
    if (runStage(mw.tierLimit)) return;
    if (runStage(mw.csrfGuard)) return;
    if (runStage(mw.attachSession)) return;

    /* ---- 7: routing -------------------------------------------------- */
    if (pathname.startsWith("/api/")) {
      const hit = r.match(req.method, pathname);
      if (!hit) {
        audit.info("route-not-found", "system", `${req.method} ${pathname}`, req);
        return res.json({ ok: false, error: `No such endpoint: ${req.method} ${pathname}` }, 404);
      }
      for (const handler of hit.handlers) {
        const proceed = await handler(req, res, hit.params, url);
        // Middleware ends the request early (auth failures, validation…).
        if (proceed === false || res.writableEnded) break;
      }
      // An injection-shaped payload was flagged during body parsing. The
      // request is still safe (every query is parameterised) but it is recorded
      // so the Security Centre shows it.
      if (req.injectionProbe) {
        audit.high("sql-injection-attempt", "security",
          `Injection-shaped input on ${req.method} ${pathname}: ${req.injectionProbe}`, req);
      }
      // A handler chain that never responded would hang the browser.
      if (!res.writableEnded) res.json({ ok: false, error: "Handler produced no response" }, 500);
      return;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      return res.json({ ok: false, error: "Method not allowed" }, 405);
    }
    return await serveStatic(res, PUBLIC_DIR, pathname);
  } catch (err) {
    // A 4xx raised deliberately (malformed JSON, oversized body, …) is the
    // client's fault and gets a clean message. Anything else is ours: log it
    // in full but return nothing that could help an attacker.
    const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 600
      ? err.status : 500;
    if (status >= 500) {
      console.error("✖", req.method, pathname, "→", err);
      audit.warn("unhandled-error", "system", `${req.method} ${pathname}: ${err.message}`, req);
    } else {
      audit.info("bad-request", "system", `${req.method} ${pathname}: ${err.message}`, req);
    }
    if (!res.headersSent) {
      applyApiHeaders(res);
      res.json({ ok: false, error: err.message || "Bad request" }, status);
    }
  }
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(
      `\n  ✖ Port ${PORT} is already in use.\n` +
      `    Another CAMPUS NEXUS (or another app) is already running there.\n` +
      `    Close it and try again, or start on a different port:\n\n` +
      `        $env:PORT=4000; node server.js\n`
    );
    process.exit(1);
  }
  throw err;
});

server.listen(PORT, () => {
  const addrs = ["localhost"];
  for (const list of Object.values(networkInterfaces())) {
    for (const ni of list ?? []) {
      if (ni.family === "IPv4" && !ni.internal) addrs.push(ni.address);
    }
  }
  console.log("");
  console.log("  ╔══════════════════════════════════════════════════════════╗");
  console.log("  ║   C A M P U S   N E X U S                               ║");
  console.log("  ║   Library  ·  Store / Billing  ·  Arcade                ║");
  console.log("  ╚══════════════════════════════════════════════════════════╝");
  console.log("");
  console.log("   Running on  " + addrs.map((a) => `http://${a}:${PORT}`).join("\n                "));
  console.log(`   Database    ${DB_PATH}`);
  console.log("   Demo login  admin / admin123     ·     staff / staff123");
  console.log("");
  console.log("   Security    " + CONFIG.limits.auth.max + " sign-in attempts / 10 min per IP");
  console.log("               scrypt N=" + CONFIG.password.scrypt.N + " + HMAC pepper, CSRF tokens enforced");
  console.log("               ledger chain, rate limiting and account lockout active");
  console.log("");
});

process.on("SIGINT", () => {
  console.log("\n  Shutting down CAMPUS NEXUS…");
  server.close(() => process.exit(0));
});