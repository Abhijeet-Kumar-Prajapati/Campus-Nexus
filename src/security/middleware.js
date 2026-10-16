// ============================================================================
//  Security middleware pipeline.
//
//  Order matters, and mirrors how a reverse proxy/WAF would be layered:
//
//   1. headers    — security headers on every response, before anything else
//   2. size       — URL length, header count, body size
//   3. global     — coarse per-IP ceiling
//   4. tiered     — auth / write / read / search buckets
//   5. csrf       — double-submit token on unsafe methods
//   6. session    — validate, slide the idle window, optionally rotate
// ============================================================================
import { CONFIG } from "./config.js";
import { normaliseIp } from "./crypto.js";
import * as ratelimit from "./ratelimit.js";
import * as csrf from "./csrf.js";
import * as session from "./session.js";
import { applySecurityHeaders } from "./headers.js";
import * as audit from "./audit.js";
import { parseCookies } from "../http.js";

/** Pick a bucket tier for the request. */
export function tierFor(req, pathname) {
  // req.url carries the query string; the tier map is keyed on the path only.
  const path = (pathname ?? req.url ?? "").split("?")[0];
  if (path.startsWith("/api/auth/login")) return "auth";
  if (path === "/api/system/search") return "search";
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return "write";
  if (path.startsWith("/api/")) return "read";
  return "global";
}

/* ------------------------------------------------------- 1. headers ------ */
/**
 * Sets the security headers on every response.
 *
 * It also solves the CSRF bootstrap problem: a browser cannot hold a CSRF token
 * before its first request, so any response that arrives without one is issued
 * a fresh signed token immediately. The client then always has a valid token by
 * the time it needs to POST.
 */
export const securityHeaders = (req, res) => {
  applySecurityHeaders(req, res);
  if (!res.getHeader("X-CSRF-Token") && !parseCookies(req)[CONFIG.session.csrfCookieName]) {
    const token = csrf.issue();
    appendCookie(res, csrfCookieValue(req, token));
    res.setHeader("X-CSRF-Token", token);
  }
};

/* ------------------------------------------------------- cookie helper --- */
/**
 * Append to the multi-valued Set-Cookie header, replacing any existing cookie
 * with the same name. Without this a response can carry two `cnx_csrf` values
 * and the browser's choice between them becomes undefined.
 */
function appendCookie(res, value) {
  const name = value.slice(0, value.indexOf("=")).trim();
  const existing = res.getHeader("Set-Cookie");
  const list = existing === undefined ? [] : Array.isArray(existing) ? [...existing] : [existing];
  const kept = list.filter((c) => c.trim().slice(0, c.indexOf("=")) !== name);
  res.setHeader("Set-Cookie", [...kept, value]);
}

function csrfCookieValue(req, token) {
  const opts = session.sessionCookieOptions(req);
  const bits = [
    `${CONFIG.session.csrfCookieName}=${encodeURIComponent(token)}`,
    `Path=${opts.path}`,
    `SameSite=${opts.sameSite}`,
  ];
  if (opts.secure) bits.push("Secure");
  return bits.join("; ");
}

/** Publish the rate-limit quota as soon as it is known, so every response path
 *  (including routes that call the bare `json()` helper) carries it. */
function publishRateLimit(res, verdict) {
  if (!verdict) return;
  res.setHeader("X-RateLimit-Limit", String(verdict.limit ?? 0));
  res.setHeader("X-RateLimit-Remaining", String(verdict.remaining ?? 0));
  res.setHeader("X-RateLimit-Reset", String(verdict.reset ?? 0));
}

/* ---------------------------------------------------------- 2. size ----- */
export function sizeGuard(req, res) {
  const url = req.url ?? "";
  if (url.length > CONFIG.request.maxUrlLength) {
    audit.high("oversized-url", "system", `URL length ${url.length} exceeds ${CONFIG.request.maxUrlLength}`, req);
    return res.json({ ok: false, error: "Request URL is too long" }, 414);
  }
  const headerCount = Object.keys(req.headers).length;
  if (headerCount > CONFIG.request.maxHeaderCount) {
    audit.high("header-flood", "system", `${headerCount} headers exceeds ${CONFIG.request.maxHeaderCount}`, req);
    return res.json({ ok: false, error: "Too many headers" }, 431);
  }
  const declared = Number(req.headers["content-length"] ?? 0);
  if (declared > CONFIG.request.maxBodyBytes) {
    audit.high("oversized-body", "system", `Declared body ${declared}B exceeds limit`, req);
    return res.json({ ok: false, error: "Payload too large" }, 413);
  }
}

/* --------------------------------------------------------- 3. global ---- */
export function globalLimit(req, res) {
  const ip = normaliseIp(req.socket?.remoteAddress ?? req.headers["x-forwarded-for"]);
  const verdict = ratelimit.consume("global", ip);
  stamp(req, verdict);
  publishRateLimit(res, verdict);
  if (!verdict.allowed) return tooMany(req, res, verdict);
}

/* ---------------------------------------------------------- 4. tiered --- */
/**
 * Applies the per-tier bucket. Returns undefined on success so the caller can
 * keep processing; a falsy-vs-truthy "did it stop the chain?" signal is the
 * contract every middleware in this file follows.
 */
export function tierLimit(req, res) {
  const ip = normaliseIp(req.socket?.remoteAddress ?? req.headers["x-forwarded-for"]);
  const tier = tierFor(req, req.url ?? "");
  const verdict = ratelimit.consume(tier, ip);

  // Chain the per-tier verdict onto the global one.
  const merged = { ...stamp(req, verdict), tier };
  publishRateLimit(res, merged);
  if (!merged.allowed) {
    audit.warn(`rate-limit.${tier}`, "security", `Bucket "${tier}" tripped for ${ip}; retry in ${verdict.retryAfter}s`, req, {
      retryAfter: verdict.retryAfter,
      trips: verdict.tripped ?? 0,
    });
    return tooMany(req, res, merged);
  }
  // NOTE: deliberately no return value — see the contract above.
}

/** Attach the verdict so route handlers can surface remaining quota. */
function stamp(req, verdict) {
  req.rateLimit = verdict;
  return verdict;
}

/** Standard 429 response with Retry-After and a safe message. */
function tooMany(req, res, verdict) {
  const retry = verdict.retryAfter ?? verdict.reset ?? 60;
  res.setHeader("Retry-After", String(retry));
  res.setHeader("X-RateLimit-Limit", String(verdict.limit ?? 0));
  res.setHeader("X-RateLimit-Remaining", "0");
  res.setHeader("X-RateLimit-Reset", String(retry));
  res.json(
    {
      ok: false,
      error:
        verdict.tier === "auth"
          ? `Too many sign-in attempts. Try again in ${formatWait(retry)}.`
          : `Request limit reached. Try again in ${formatWait(retry)}.`,
      retryAfter: retry,
      tier: verdict.tier,
      limited: true,
    },
    429
  );
}

const formatWait = (s) => (s >= 3600 ? `${Math.round(s / 3600)}h` : s >= 60 ? `${Math.round(s / 60)}m` : `${s}s`);

/* ----------------------------------------------------------- 5. CSRF ---- */
export function csrfGuard(req, res) {
  if (!csrf.verify(req)) {
    audit.high("csrf-rejected", "security", `Missing or invalid CSRF token on ${req.method} ${(req.url ?? "").split("?")[0]}`, req);
    return res.json({ ok: false, error: "Security token missing or invalid — refresh the page and try again", csrf: true }, 403);
  }
}

/* -------------------------------------------------------- 6. session ---- */
/**
 * Resolve the session cookie (if any) and attach `req.session` / `req.user`.
 * Never rejects — authorisation is a separate concern (see `requireAuth`).
 */
export function attachSession(req, res) {
  req.cookies = parseCookies(req);
  const token = req.cookies[CONFIG.session.cookieName];

  // The fingerprint MUST be computed from the same normalised address that
  // `login` used when the session was created — otherwise IPv4-mapped IPv6
  // (`::1` vs `127.0.0.1`) would make every session look like a replay.
  const ip = normaliseIp(req.socket?.remoteAddress ?? req.headers["x-forwarded-for"]);
  req.clientIp = ip;

  const result = session.resolve(token, {
    ip,
    userAgent: req.headers["user-agent"],
  });

  if (!result.ok) {
    if (result.reason && result.reason !== "unknown" && token) {
      audit.high(`session-${result.reason}`, "security", `Session rejected: ${result.reason}`, req);
    }
    req.session = null;
    req.user = null;
    return;
  }

  req.session = result.session;

  if (result.rotate) {
    // Rotate proactively; the old token dies immediately. The replacement must
    // reuse the already-normalised IP so its fingerprint still matches.
    const { cookieValue, session: fresh } = session.create({
      userId: result.session.userId,
      username: result.session.username,
      role: result.session.role,
      ip,
      userAgent: req.headers["user-agent"],
    });
    session.destroy(result.session.publicId);
    req.session = fresh;
    issueSessionCookies(res, req, cookieValue);
  }

  if (req.session) {
    req.user = db_user(req.session.userId);
  }
}

// Lazy lookup keeps a single import of the database handle in this module.
let _db = null;
function db_user(userId) {
  if (!_db) return null;
  const row = _db.prepare(`SELECT id, username, full_name, role FROM users WHERE id=? AND active=1`).get(userId);
  return row ?? null;
}
export function bindDatabase(db) { _db = db; }

/* ------------------------------------------------- cookie issuing ------- */
export function issueSessionCookies(res, req, cookieValue, csrfToken) {
  const opts = session.sessionCookieOptions(req);
  const bits = [
    `${CONFIG.session.cookieName}=${encodeURIComponent(cookieValue)}`,
    `Path=${opts.path}`,
    "HttpOnly",
    `SameSite=${opts.sameSite}`,
  ];
  if (opts.secure) bits.push("Secure");
  appendCookie(res, bits.join("; "));

  if (csrfToken) {
    const csrfBits = [
      `${CONFIG.session.csrfCookieName}=${encodeURIComponent(csrfToken)}`,
      `Path=${opts.path}`,
      `SameSite=${opts.sameSite}`,
    ];
    if (opts.secure) csrfBits.push("Secure");
    appendCookie(res, csrfBits.join("; "));
    res.setHeader("X-CSRF-Token", csrfToken);
  }
}

export function clearSessionCookies(res, req) {
  const opts = session.sessionCookieOptions(req);
  res.setHeader("Set-Cookie", [
    `${CONFIG.session.cookieName}=; Path=${opts.path}; Max-Age=0; HttpOnly; SameSite=${opts.sameSite}`,
    `${CONFIG.session.csrfCookieName}=; Path=${opts.path}; Max-Age=0; SameSite=${opts.sameSite}`,
  ]);
}

/** Authorisation guard for write endpoints. */
export function requireAuth(req, res) {
  if (!req.user) {
    audit.warn("auth-required", "security", `Unauthenticated write to ${(req.url ?? "").split("?")[0]}`, req);
    res.json({ ok: false, error: "Please sign in to perform this action", requiresAuth: true }, 401);
    return false;
  }
  return true;
}

/** Role gate — used by user-management endpoints. */
export function requireRole(role) {
  return function (req, res) {
    if (!req.user) {
      res.json({ ok: false, error: "Authentication required", requiresAuth: true }, 401);
      return false;
    }
    if (role === "admin" && req.user.role !== "admin") {
      audit.high("privilege-escalation", "security", `User ${req.user.username} (${req.user.role}) tried an admin-only action`, req);
      res.json({ ok: false, error: "Administrator access required" }, 403);
      return false;
    }
    return true;
  };
}

export { csrf, session, ratelimit, audit };