// ============================================================================
//  CSRF protection — signed double-submit token (OWASP CSRF cheat sheet).
//
//  The cookie holds `<payload>.<hmac>`; the client echoes the whole value in
//  the X-CSRF-Token header. Because the HMAC is keyed with the server-side
//  pepper, an attacker on another origin can neither read nor forge it.
//  This is defence-in-depth alongside SameSite=Strict cookies.
// ============================================================================
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { CONFIG } from "./config.js";
import { PEPPER } from "./crypto.js";

const { headerName, cookieName, methods } = { ...CONFIG.csrf, cookieName: CONFIG.session.csrfCookieName };

const sign = (payload) =>
  createHmac("sha256", PEPPER).update("csrf:" + payload).digest("base64url");

/** Mint a fresh token. The payload carries a nonce and an issue time. */
export function issue() {
  const payload = Buffer.from(
    JSON.stringify({ n: randomBytes(12).toString("hex"), t: Date.now() })
  ).toString("base64url");
  return `${payload}.${sign(payload)}`;
}

/**
 * Verify the header against the cookie.
 * Safe methods pass through; everything else needs a matching, valid signature.
 */
export function verify(req) {
  const method = req.method?.toUpperCase();
  if (!methods.includes(method)) return true;

  const cookieToken = parseCookies(req)[cookieName];
  const headerToken = req.headers[headerName];

  if (typeof cookieToken !== "string" || typeof headerToken !== "string") return false;
  if (!constantEqual(cookieToken, headerToken)) return false;

  const dot = cookieToken.lastIndexOf(".");
  if (dot <= 0) return false;
  return constantEqual(cookieToken.slice(dot + 1), sign(cookieToken.slice(0, dot)));
}

export { cookieName, headerName };

/* ------------------------------------------------------------- helpers --- */
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function constantEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}