// ============================================================================
//  Security audit trail.
//
//  Two sinks:
//   1. `security_events` — a queryable, human-readable log for the dashboard.
//   2. the hash-chained ledger — the tamper-evident record.
//
//  Nothing is written directly by route handlers; they call `audit.record()`.
// ============================================================================
import { db, logActivity } from "../db.js";
import { CONFIG } from "./config.js";
import { normaliseIp } from "./crypto.js";
import { buildBlock, verifyChain, writeSeal } from "./ledger.js";

/** Ring buffer of the newest events so the UI can stream them instantly. */
const recent = [];
const RECENT_MAX = 200;

/* --------------------------------------------------------------- store --- */
/** Adapter shape the ledger expects. Injected to keep concerns separated. */
const ledgerStore = {
  head() {
    const row = db
      .prepare(`SELECT "index", hash FROM ledger ORDER BY "index" DESC LIMIT 1`)
      .get();
    return row ?? { index: -1, hash: "0".repeat(64) };
  },
  all() {
    return db.prepare(`SELECT * FROM ledger ORDER BY "index" ASC`).all();
  },
  insert(block) {
    // "index" is a SQL keyword and must stay quoted in both the column list and
    // the SELECTs that read it back.
    db.prepare(
      `INSERT INTO ledger
         ("index", timestamp, event_type, module, actor, severity, payload,
          payload_hash, prev_hash, merkle_root, difficulty, nonce, hash)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).run(
      block.index, block.timestamp, block.event_type, block.module, block.actor,
      block.severity, JSON.stringify({}), block.payload_hash, block.prev_hash,
      block.merkle_root, block.difficulty, block.nonce, block.hash
    );
  },
};

/* -------------------------------------------------------------- record --- */
/**
 * Record a security or business event.
 * `severity` one of info | warn | high | critical.
 */
export function record(severity, event_type, module = "system", detail = "", req = null, extra = {}) {
  const ip = req ? normaliseIp(req.socket?.remoteAddress ?? req.headers?.["x-forwarded-for"]) : null;
  const ua = req?.headers?.["user-agent"] ?? null;
  const path = req ? (req.url ?? "").split("?")[0].slice(0, 200) : null;

  const payload = {
    detail: String(detail).slice(0, 500),
    ip,
    path,
    ...extra,
  };

  try {
    db.prepare(
      `INSERT INTO security_events (severity, event_type, module, detail, ip, path, user_agent)
       VALUES (?,?,?,?,?,?,?)`
    ).run(severity, event_type, String(module), payload.detail, ip, path, ua ? String(ua).slice(0, 200) : null);
  } catch { /* never let logging break the request */ }

  try {
    const block = buildBlock(ledgerStore, { event_type, module, actor: extra.actor ?? "system", severity, payload });
    ledgerStore.insert(block);
    writeSeal(block.hash, block.index + 1);
  } catch (err) {
    console.error("✖ ledger append failed:", err.message);
  }

  const event = {
    severity,
    event_type,
    module,
    detail: payload.detail,
    ip,
    at: new Date().toISOString(),
  };
  recent.unshift(event);
  if (recent.length > RECENT_MAX) recent.pop();
  return event;
}

export const info  = (t, m, d, r, e) => record("info", t, m, d, r, e);
export const warn  = (t, m, d, r, e) => record("warn", t, m, d, r, e);
export const high  = (t, m, d, r, e) => record("high", t, m, d, r, e);
export const critical = (t, m, d, r, e) => record("critical", t, m, d, r, e);

/* -------------------------------------------------------------- reads ---- */
export function recentEvents(limit = 40) {
  return db
    .prepare(
      `SELECT severity, event_type, module, detail, ip, created_at
       FROM security_events ORDER BY id DESC LIMIT ?`
    )
    .all(Math.min(200, limit));
}

/** Counts by severity over a window — drives the dashboard's threat meter. */
export function summary(hours = 24) {
  const rows = db
    .prepare(
      `SELECT severity, COUNT(*) AS n FROM security_events
       WHERE created_at >= datetime('now','localtime', '-' || ? || ' hour')
       GROUP BY severity`
    )
    .all(hours);
  const bySeverity = { info: 0, warn: 0, high: 0, critical: 0 };
  for (const r of rows) bySeverity[r.severity] = r.n;

  const top = db
    .prepare(
      `SELECT event_type, COUNT(*) AS n FROM security_events
       WHERE created_at >= datetime('now','localtime','-' || ? || ' hour')
       GROUP BY event_type ORDER BY n DESC LIMIT 8`
    )
    .all(hours);

  const uniqueIps = db
    .prepare(
      `SELECT COUNT(DISTINCT ip) AS n FROM security_events
       WHERE ip IS NOT NULL AND created_at >= datetime('now','localtime','-' || ? || ' hour')`
    )
    .get(hours).n;

  const total = Object.values(bySeverity).reduce((a, b) => a + b, 0);
  const score = Math.min(100, bySeverity.critical * 25 + bySeverity.high * 8 + bySeverity.warn * 2);

  return {
    windowHours: hours,
    total,
    bySeverity,
    score,
    posture: score === 0 ? "nominal" : score < 15 ? "guarded" : score < 40 ? "elevated" : "critical",
    topEvents: top,
    uniqueIps,
    live: recent.slice(0, 20),
  };
}

/* ---------------------------------------------------------- integrity ---- */
export const verify = () => verifyChain(ledgerStore);

/** Count of ledger blocks (cheap, for the dashboard header). */
export function height() {
  return db.prepare(`SELECT COUNT(*) AS n FROM ledger`).get().n;
}

export { ledgerStore };