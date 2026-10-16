// ============================================================================
//  Hardened session store.
//
//  Hardening applied (OWASP Session Management cheat sheet):
//   • CSPRNG token with 256 bits of entropy, generic cookie name (no
//     "JSESSIONID"-style fingerprint).
//   • Split token: the store keeps only publicId + SHA-256(secret), so a
//     database/store leak cannot be replayed.
//   • Bound to an IP+User-Agent fingerprint; a cookie replayed from a
//     different client is destroyed.
//   • Idle timeout (30 min) *and* absolute timeout (8 h).
//   • Rotated on privilege change and at least every 15 minutes.
//   • Concurrent-session cap per user.
//   • HttpOnly + SameSite=Strict + Path=/ and Secure when on TLS.
// ============================================================================
import { CONFIG } from "./config.js";
import { clientFingerprint, issueSessionToken, splitSessionToken, sha256, safeEqual } from "./crypto.js";

const S = CONFIG.session;

/** publicId -> session record */
const store = new Map();

function sweep(now = Date.now()) {
  for (const [id, s] of store) {
    if (s.expiresAt <= now || s.absoluteExpiresAt <= now) store.delete(id);
  }
}
setInterval(sweep, 60_000).unref?.();

/* --------------------------------------------------------------------- -- */

/** Create a brand-new session (used at login and on rotation). */
export function create({ userId, username, role, ip, userAgent, now = Date.now() } = {}) {
  sweep(now);
  const { cookieValue, publicId, secretHash } = issueSessionToken();
  const session = {
    publicId,
    secretHash,
    userId,
    username,
    role,
    fingerprint: S.bindToFingerprint ? clientFingerprint(ip, userAgent) : null,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + S.idleTimeoutMs,
    absoluteExpiresAt: now + S.absoluteTimeoutMs,
    rotatedAt: now,
    // Safety counters surfaced to the security dashboard.
    handoffCount: 0,
    lastIp: ip ?? null,
    events: [],
  };
  store.set(publicId, session);
  enforceConcurrency(userId, session.publicId);
  return { session, cookieValue };
}

/** Keep only the newest N sessions per user. */
function enforceConcurrency(userId, keepPublicId) {
  const mine = [...store.values()]
    .filter((s) => s.userId === userId)
    .sort((a, b) => b.lastSeenAt - a.lastSeenAt);
  for (const old of mine.slice(S.maxConcurrentPerUser)) {
    if (old.publicId !== keepPublicId) store.delete(old.publicId);
  }
}

/**
 * Validate a raw cookie value.
 * Returns { ok, session, reason } — `reason` is machine-readable so the caller
 * can log the precise failure to the security ledger.
 */
export function resolve(cookieValue, { ip, userAgent, now = Date.now() } = {}) {
  const parts = splitSessionToken(cookieValue ?? "");
  if (!parts) return { ok: false, reason: "malformed" };

  const session = store.get(parts.publicId);
  if (!session) return { ok: false, reason: "unknown" };

  // Secret comparison is constant-time and fails fast on hash mismatch.
  if (!safeEqual(sha256(parts.secret), session.secretHash)) {
    destroy(session.publicId);
    return { ok: false, reason: "bad-secret" };
  }

  if (now >= session.expiresAt) { destroy(session.publicId); return { ok: false, reason: "idle-expired" }; }
  if (now >= session.absoluteExpiresAt) { destroy(session.publicId); return { ok: false, reason: "absolute-expired" }; }

  // Fingerprint binding: a stolen cookie used elsewhere is detected & killed.
  if (S.bindToFingerprint && session.fingerprint) {
    const fp = clientFingerprint(ip, userAgent);
    if (fp !== session.fingerprint) {
      session.events.push({ at: now, kind: "fingerprint-mismatch" });
      destroy(session.publicId);
      return { ok: false, reason: "fingerprint-mismatch" };
    }
  }

  session.lastSeenAt = now;
  session.expiresAt = now + S.idleTimeoutMs;      // slide the idle window
  session.lastIp = ip ?? session.lastIp;

  // Opportunistic rotation keeps a long-lived token from ageing indefinitely.
  if (now - session.rotatedAt >= S.renewalIntervalMs) {
    return { ok: true, session, rotate: true };
  }
  return { ok: true, session, rotate: false };
}

/** Destroy a session by publicId or by its in-memory record. */
export function destroy(publicId) {
  if (typeof publicId === "object" && publicId?.publicId) publicId = publicId.publicId;
  return store.delete(publicId);
}

/** Invalidate every session belonging to a user (password change, lockout). */
export function revokeUser(userId, { except } = {}) {
  let n = 0;
  for (const [id, s] of store) {
    if (s.userId === userId && id !== except) { store.delete(id); n++; }
  }
  return n;
}

export function destroyAll() {
  const n = store.size;
  store.clear();
  return n;
}

/** Introspection for the security dashboard. */
export function snapshot(now = Date.now()) {
  sweep(now);
  const list = [...store.values()];
  return {
    live: list.length,
    uniqueUsers: new Set(list.map((s) => s.userId)).size,
    oldestMs: list.length ? now - Math.min(...list.map((s) => s.createdAt)) : 0,
    // Anything flagged with a fingerprint mismatch is a probable token theft.
    suspicious: list.filter((s) => s.events.length > 0).length,
    details: list
      .sort((a, b) => b.lastSeenAt - a.lastSeenAt)
      .slice(0, 15)
      .map((s) => ({
        user: s.username,
        role: s.role,
        idleSeconds: Math.floor((now - s.lastSeenAt) / 1000),
        ageMinutes: Math.floor((now - s.createdAt) / 60000),
        anomalies: s.events.length,
      })),
  };
}

/* ------------------------------------------------------- cookie helpers -- */
/** True when the connection is encrypted, so `Secure` can be set safely. */
export function isTls(req) {
  return req.socket?.encrypted === true ||
    req.headers["x-forwarded-proto"]?.split(",")[0].trim() === "https";
}

export function sessionCookieOptions(req, { maxAge } = {}) {
  return {
    httpOnly: true,
    path: S.cookiePath,
    sameSite: S.sameSite,
    secure: S.secureWhenTls && isTls(req),
    ...(maxAge !== undefined ? { maxAge } : {}),
  };
}