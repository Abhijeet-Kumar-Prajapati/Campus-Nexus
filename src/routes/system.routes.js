// ============================================================================
//  System routes  —  the unified dashboard, global search and audit trail.
//  This layer is what genuinely fuses the three original projects into one
//  application instead of three separate programs.
// ============================================================================
import { db } from "../db.js";
import { libraryStats } from "./library.routes.js";
import { storeStats, salesSeries, topProducts, lowStock, TAX_PCT } from "./store.routes.js";
import { arcadeStats, leaderboard } from "./arcade.routes.js";
import { FINE_PER_DAY, LOAN_DAYS } from "./library.routes.js";

export function dashboard() {
  const library = libraryStats();
  const store = storeStats();
  const arcade = arcadeStats();
  const boards = leaderboard("all", 5);

  const revenueAll = db.prepare(`SELECT COUNT(*) n, IFNULL(SUM(total),0) amt FROM bills`).get();
  const alerts = [
    ...lowStock().slice(0, 6).map((p) => ({
      module: "store",
      level: p.stock === 0 ? "danger" : "warn",
      text: `${p.name} — ${p.stock === 0 ? "out of stock" : `only ${p.stock} left`}`,
    })),
    ...(library.overdue > 0
      ? [{ module: "library", level: "warn", text: `${library.overdue} book(s) overdue — fines pending` }]
      : []),
    ...(library.titles === 0
      ? [{ module: "library", level: "danger", text: "Catalogue is empty" }]
      : []),
  ];

  return {
    ok: true,
    library,
    store,
    arcade,
    totals: {
      bills: revenueAll.n,
      revenue: Math.round(revenueAll.amt * 100) / 100,
      books: library.titles,
      products: store.products,
      players: arcade.players,
    },
    salesSeries: salesSeries(14),
    topProducts: topProducts(5),
    leaderboards: boards.summary,
    leaderboardTop: boards.entries,
    activity: db
      .prepare(`SELECT * FROM activity ORDER BY created_at DESC, id DESC LIMIT 12`)
      .all(),
    alerts,
    config: { finePerDay: FINE_PER_DAY, loanDays: LOAN_DAYS, taxPct: TAX_PCT },
  };
}

/** One search box across books, products and bills. */
export function globalSearch(q) {
  const like = `%${q}%`;
  return {
    query: q,
    books: db
      .prepare(
        `SELECT id, title, author, category FROM books
         WHERE title LIKE ? OR author LIKE ? OR isbn LIKE ? LIMIT 6`
      )
      .all(like, like, like),
    products: db
      .prepare(
        `SELECT id, name, category, price, stock FROM products
         WHERE active=1 AND (name LIKE ? OR sku LIKE ?) LIMIT 6`
      )
      .all(like, like),
    bills: db
      .prepare(
        `SELECT id, bill_no, customer, total, created_at FROM bills
         WHERE bill_no LIKE ? OR customer LIKE ? LIMIT 6`
      )
      .all(like, like),
  };
}

export function health() {
  const r = db.prepare(`SELECT COUNT(*) AS n FROM books`).get();
  return { ok: true, uptime: Math.round(process.uptime()), tables: r.n, node: process.version };
}