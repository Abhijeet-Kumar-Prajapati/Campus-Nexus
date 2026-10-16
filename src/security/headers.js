// ============================================================================
//  Security response headers (OWASP HTTP Headers cheat sheet).
//
//  Also removes the fingerprinting headers Node emits by default and hides the
//  internal error text from clients (details go to the console / audit log).
// ============================================================================
import { CONFIG } from "./config.js";
import { isTls } from "./session.js";

const H = CONFIG.headers;

/**
 * Build the CSP for this particular request.
 *
 * `upgrade-insecure-requests` is only meaningful — and only safe — when the
 * connection is already encrypted. Emitting it over plain HTTP makes the browser
 * rewrite every script/style URL to https://, which fails outright on a
 * non-TLS host (a LAN demo, or this app before a reverse proxy is in front).
 * HSTS already covers real deployments, so we add the directive only when it
 * can actually work.
 */
function cspFor(req) {
  const parts = H.csp.split("; ").filter((d) => d !== "upgrade-insecure-requests");
  if (isTls(req)) parts.push("upgrade-insecure-requests");
  return parts.join("; ");
}

export function applySecurityHeaders(req, res) {
  const base = {
    "Content-Security-Policy": cspFor(req),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": H.frameOptions,
    "Referrer-Policy": H.referrerPolicy,
    "Permissions-Policy": H.permissionsPolicy,
    "Cross-Origin-Opener-Policy": H.crossOriginOpenerPolicy,
    "Cross-Origin-Resource-Policy": H.crossOriginResourcePolicy,
    "Cross-Origin-Embedder-Policy": H.crossOriginEmbedderPolicy,
    // Stop caches (and therefore shared proxies) from storing anything.
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    Pragma: "no-cache",
    Expires: "0",
    // Defensive: browsers must not sniff content away from our declared type.
    "X-Download-Options": "noopen",
    "X-Permitted-Cross-Domain-Policies": "none",
    // Do not advertise the technology stack.
    "X-Powered-By": "",
    Server: "",
  };
  if (isTls(req)) base["Strict-Transport-Security"] = H.hsts;
  else base["Strict-Transport-Security"] = "max-age=0"; // never cache a downgraded TLS session

  for (const [k, v] of Object.entries(base)) {
    if (v === "") res.removeHeader(k);
    else res.setHeader(k, v);
  }
}

/**
 * Headers for API responses. Rate-limit headers are published earlier by the
 * middleware (so they ride along on every response path, including routes that
 * call the bare `json()` helper); this only adds the content type and the CSRF
 * token a freshly loaded page needs to start writing immediately.
 */
export function applyApiHeaders(res, { csrfToken } = {}) {
  applySecurityHeaders({ headers: {}, socket: {} }, res);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  if (csrfToken) res.setHeader("X-CSRF-Token", csrfToken);
}