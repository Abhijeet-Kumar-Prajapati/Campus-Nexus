// ============================================================================
//  CAMPUS NEXUS  ·  tiny zero-dependency HTTP toolkit
// ============================================================================
import { readFile, stat } from "node:fs/promises";
import { join, normalize, extname } from "node:path";
import { findInjection } from "./security/validate.js";

export const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
  ".pdf": "application/pdf",
};

/* ------------------------------------------------------------- responses --- */
export function json(res, data, status = 200) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  res.end(body);
}
export function fail(res, message, status = 400, extra = {}) {
  json(res, { ok: false, error: message, ...extra }, status);
}

/* ---------------------------------------------------------------- cookies --- */
export function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
export function setCookie(res, name, value, { maxAge = 60 * 60 * 8, httpOnly = false, sameSite = "Lax" } = {}) {
  const bits = [`${name}=${encodeURIComponent(value)}`, "Path=/", `Max-Age=${maxAge}`];
  if (httpOnly) bits.push("HttpOnly");
  bits.push(`SameSite=${sameSite}`);
  const prev = res.getHeader("Set-Cookie");
  const list = prev ? (Array.isArray(prev) ? prev : [prev]) : [];
  res.setHeader("Set-Cookie", [...list, bits.join("; ")]);
}

/* ------------------------------------------------------------------- body --- */
export async function readJson(req, limitBytes = 1024 * 512) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limitBytes) throw new Error("Payload too large");
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text.trim()) return {};

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    const err = new Error("Malformed JSON body");
    err.status = 400;
    throw err;
  }

  // SQL-injection tripwire. Every query here is parameterised, so this cannot
  // actually inject anything — but a match means injection-shaped input
  // reached us, which is exactly what an operator needs to see. Flagged on the
  // request; server.js records it in the audit trail.
  const probe = findInjection(parsed);
  if (probe) req.injectionProbe = probe;

  return parsed;
}

/* ------------------------------------------------------------------ route --- */
export class Router {
  constructor() {
    this.routes = [];
  }

  /**
   * add(method, pattern, ...handlers)
   * Every handler except the last is treated as middleware: it may end the
   * response itself, and returning `false` stops the chain.
   */
  add(method, pattern, ...handlers) {
    const keys = [];
    const rx = new RegExp(
      "^" +
        pattern
          .split("/")
          .map((seg) => {
            if (seg.startsWith(":")) {
              keys.push(seg.slice(1));
              return "([^/]+)";
            }
            return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          })
          .join("/") +
        "$"
    );
    this.routes.push({ method, rx, keys, handlers });
    return this;
  }
  get(p, ...h) { return this.add("GET", p, ...h); }
  post(p, ...h) { return this.add("POST", p, ...h); }
  put(p, ...h) { return this.add("PUT", p, ...h); }
  delete(p, ...h) { return this.add("DELETE", p, ...h); }

  match(method, pathname) {
    for (const r of this.routes) {
      if (r.method !== method) continue;
      const m = r.rx.exec(pathname);
      if (!m) continue;
      const params = {};
      r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
      return { handlers: r.handlers, params };
    }
    return null;
  }
}

/* ----------------------------------------------------------------- static --- */
/**
 * Serve a file from `rootDir`.
 *
 * Directory requests fall back to `index.html` inside them, so `/dist/` resolves
 * to the built bundle instead of 404-ing on the directory itself.
 */
export async function serveStatic(res, rootDir, urlPath) {
  let rel = decodeURIComponent(urlPath.split("?")[0]);
  if (rel === "/" || rel === "") rel = "index.html";
  if (rel.endsWith("/")) rel += "index.html";

  // Normalise + block traversal outside the public root.
  const root = normalize(rootDir);
  let target = normalize(join(root, rel));
  if (!target.startsWith(root)) {
    return fail(res, "Forbidden", 403);
  }

  try {
    let st = await stat(target);
    if (st.isDirectory()) {
      target = join(target, "index.html");
      st = await stat(target);
    }
    const buf = await readFile(target);
    res.writeHead(200, {
      "Content-Type": MIME[extname(target).toLowerCase()] || "application/octet-stream",
      "Content-Length": buf.length,
      "Cache-Control": "no-cache",
    });
    res.end(buf);
  } catch {
    fail(res, "Not found", 404);
  }
}