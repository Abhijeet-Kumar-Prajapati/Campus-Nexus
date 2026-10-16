// ============================================================================
//  Security routes — the self-monitoring surface.
//  Everything here is read-only except the two administrative actions.
// ============================================================================
import { CONFIG } from "../security/config.js";
import * as audit from "../security/audit.js";
import * as ratelimit from "../security/ratelimit.js";
import * as sessions from "../security/session.js";
import { certificate, verifyChain } from "../security/ledger.js";
import { status as fieldCryptoStatus } from "../security/fieldcrypto.js";
import { requireAuth, requireRole } from "../security/middleware.js";
import { db } from "../db.js";

/* --------------------------------------------------------- posture ----- */
/**
 * The list of protections actually running, so the UI can show the operator
 * exactly what is switched on rather than making them trust a claim.
 */
const CONTROLS = [
  { id: "rate-limit",     name: "Tiered rate limiting",        detail: `Per-IP buckets: ${CONFIG.limits.global.max}/60s global, ${CONFIG.limits.read.max}/60s read, ${CONFIG.limits.search.max}/60s search, ${CONFIG.limits.write.max}/60s write, ${CONFIG.limits.auth.max}/10min sign-in`, layer: "network" },
  { id: "backoff",        name: "Exponential backoff",         detail: "Every rate-limit trip doubles the window, capped at 30 minutes", layer: "network" },
  { id: "account-lock",   name: "Progressive account lockout", detail: `${CONFIG.account.maxFailedLogins} failures locks the account; each extra failure doubles the wait to a 1-hour ceiling`, layer: "identity" },
  { id: "enumeration",    name: "Username-enumeration defence",detail: "Unknown users still pay full scrypt cost and get an identical error message", layer: "identity" },
  { id: "csrf",           name: "Signed CSRF tokens",          detail: "HMAC-signed double-submit token required on every POST/PUT/DELETE", layer: "request" },
  { id: "session-token",  name: "Split session tokens",        detail: "Store keeps only publicId + SHA-256(secret); a stolen store cannot be replayed", layer: "session" },
  { id: "session-fp",     name: "Session fingerprint binding", detail: "Tokens are bound to IP + User-Agent; a replay from another client is destroyed", layer: "session" },
  { id: "session-timeout",name: "Idle + absolute timeouts",    detail: "30 minutes idle, 8 hours absolute, token rotated at least every 15 minutes", layer: "session" },
  { id: "cookies",        name: "Hardened cookies",            detail: "HttpOnly, SameSite=Strict, Path=/, Secure under TLS, generic cookie name", layer: "session" },
  { id: "csrf-cookie",    name: "SameSite cookie defence",     detail: "Session cookie is SameSite=Strict — cross-site requests never carry it", layer: "session" },
  { id: "headers",        name: "Security response headers",   detail: "CSP, HSTS, nosniff, frame-deny, no-referrer, permissions-policy, COOP/CORP/COEP", layer: "response" },
  { id: "fingerprint",    name: "Technology fingerprinting removed", detail: "X-Powered-By and Server headers stripped; CSP advertises no third parties", layer: "response" },
  { id: "password",       name: "scrypt + pepper hashing",     detail: "N=2^16, r=8, p=2 (64 MiB) followed by an HMAC pepper held outside the database", layer: "identity" },
  { id: "password-policy",name: "Password strength policy",    detail: "12+ characters, mixed case, digit and symbol; common-password and pattern penalties", layer: "identity" },
  { id: "password-history",name: "Password reuse prevention",  detail: "The last 3 hashes cannot be reused", layer: "identity" },
  { id: "pii-crypto",    name: "PII encryption at rest",      detail: "Phone numbers and borrower contacts are sealed with AES-256-GCM under a key held outside the database", layer: "audit" },
  { id: "blind-index",    name: "Searchable encrypted fields", detail: "Exact phone lookups use a deterministic HMAC blind index, so ciphertext is never pattern-matched", layer: "audit" },
  { id: "validation",     name: "Schema input validation",     detail: "Every write body validated against a typed schema; unknown and privileged keys rejected", layer: "request" },
  { id: "sqli",           name: "SQL injection defence",       detail: "All queries use bound parameters; a tripwire pattern additionally flags injection attempts", layer: "request" },
  { id: "xss",            name: "Output encoding",             detail: "Script-src locked to 'self', frame-ancestors 'none', and every value escaped on render", layer: "response" },
  { id: "traversal",      name: "Path traversal defence",      detail: "Static file paths normalised and verified to sit inside the public root", layer: "request" },
  { id: "body-limit",     name: "Request size limits",         detail: "256 KiB body, 2048-character URL, 100 headers", layer: "network" },
  { id: "bot-trap",       name: "Bot detection",               detail: "Honeypot field plus a minimum submit time; both fail silently with a generic error", layer: "identity" },
  { id: "mass-assignment",name: "Mass-assignment defence",    detail: "role, id, pass_hash and prototype keys are refused from client payloads", layer: "request" },
  { id: "ledger",         name: "Tamper-evident audit chain",  detail: "SHA-256 hash chain + Merkle tree + proof-of-work, sealed outside the database", layer: "audit" },
  { id: "concurrent",     name: "Concurrent session cap",      detail: "A user may hold at most 5 live sessions; older ones are evicted", layer: "session" },
  { id: "revocation",     name: "Global session revocation",  detail: "Password change or account unlock terminates every active session", layer: "session" },
  { id: "reauth",         name: "Risk-event reauthentication", detail: "Privilege changes force a new session; fingerprint anomalies force re-authentication", layer: "session" },
  { id: "privilege",      name: "Role-based authorisation",    detail: "Admin-only actions are gated server-side; attempts are logged as privilege escalation", layer: "identity" },
];

export function posture(req, res) {
  if (!requireAuth(req, res)) return;

  const events = audit.summary(24);
  const chain = verifyChain(audit.ledgerStore);
  const limiter = ratelimit.snapshot();
  const sess = sessions.snapshot();
  const accounts = db
    .prepare(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN active=1 THEN 1 ELSE 0 END) AS active,
              SUM(CASE WHEN locked_until IS NOT NULL AND locked_until > datetime('now','localtime') THEN 1 ELSE 0 END) AS locked
       FROM users`
    )
    .get();

  res.json({
    ok: true,
    controls: CONTROLS,
    controlCount: CONTROLS.length,
    events,
    chain: {
      height: chain.height,
      verified: chain.ok,
      issues: chain.issues,
      head: chain.head,
      seal: chain.seal,
      ms: chain.ms,
    },
    limiter,
    sessions: sess,
    accounts,
    config: {
      limits: CONFIG.limits,
      session: {
        idleMinutes: Math.round(CONFIG.session.idleTimeoutMs / 60000),
        absoluteHours: Math.round(CONFIG.session.absoluteTimeoutMs / 3600000),
        rotationMinutes: Math.round(CONFIG.session.renewalIntervalMs / 60000),
        bindToFingerprint: CONFIG.session.bindToFingerprint,
        sameSite: CONFIG.session.sameSite,
      },
      password: {
        algorithm: "scrypt",
        N: CONFIG.password.scrypt.N,
        r: CONFIG.password.scrypt.r,
        p: CONFIG.password.scrypt.p,
        memoryMiB: Math.round((128 * CONFIG.password.scrypt.N * CONFIG.password.scrypt.r) / (1024 * 1024)),
        peppered: true,
        minLength: CONFIG.password.minLength,
        recommendedLength: CONFIG.password.recommendedLength,
      },
      fieldEncryption: fieldCryptoStatus(),
      account: CONFIG.account,
      headers: {
        csp: CONFIG.headers.csp.split("; ").slice(0, 6),
        hsts: CONFIG.headers.hsts,
      },
    },
    runtime: {
      node: process.version,
      uptimeSeconds: Math.round(process.uptime()),
      heapMb: Math.round((process.memoryUsage().heapUsed / 1048576) * 10) / 10,
      pid: process.pid,
    },
  });
}

/* ------------------------------------------------------------ events ---- */
export function events(req, res) {
  if (!requireAuth(req, res)) return;
  const limit = Math.min(200, Math.max(1, Number(req.url.split("limit=")[1]) || 60));
  res.json({ ok: true, events: audit.recentEvents(limit), summary: audit.summary(24) });
}

/* ------------------------------------------------------------- chain ---- */
export function chainStatus(req, res) {
  if (!requireAuth(req, res)) return;
  res.json({ ok: true, ...verifyChain(audit.ledgerStore), certificate: certificate(audit.ledgerStore) });
}

export function chainBlocks(req, res) {
  if (!requireAuth(req, res)) return;
  const blocks = db
    .prepare(
      `SELECT "index", timestamp, event_type, module, actor, severity, prev_hash, hash, nonce, difficulty
       FROM ledger ORDER BY "index" DESC LIMIT 40`
    )
    .all();
  res.json({
    ok: true,
    blocks: blocks.map((b) => ({
      index: b.index,
      timestamp: b.timestamp,
      type: b.event_type,
      module: b.module,
      actor: b.actor,
      severity: b.severity,
      prev: b.prev_hash,
      hash: b.hash,
      nonce: b.nonce,
      difficulty: b.difficulty,
      links: b.prev_hash,
    })),
  });
}

/* -------------------------------------------------------------- reset --- */
/** Administrative: wipe rate-limit buckets and unlock every account. */
export function emergencyReset(req, res) {
  if (!requireRole("admin")(req, res)) return;
  ratelimit._resetAll();
  const n = db.prepare(`UPDATE users SET failed_logins=0, locked_until=NULL`).run().changes;
  db.prepare(`DELETE FROM login_failures`).run();
  audit.info("security-reset", "security", `Administrator cleared all rate limits and unlocked ${n} account(s)`, req, {
    actor: req.user.username,
  });
  res.json({ ok: true, message: `All rate limits cleared, ${n} account(s) unlocked` });
}

/** Administrative: destroy every live session (incident response). */
export function revokeAllSessions(req, res) {
  if (!requireRole("admin")(req, res)) return;
  const n = sessions.destroyAll();
  audit.info("mass-logout", "security", `Administrator revoked ${n} live session(s)`, req, { actor: req.user.username });
  res.json({ ok: true, message: `${n} session(s) revoked — everyone must sign in again`, revoked: n });
}