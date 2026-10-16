// ============================================================================
//  CAMPUS NEXUS · cryptographic helpers
//  Everything here uses Node's built-in `node:crypto` — no dependencies.
// ============================================================================
import {
  randomBytes, createHash, createHmac, timingSafeEqual,
  scryptSync, randomInt,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CONFIG } from "./config.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SECRET_DIR = join(__dirname, "..", "..", "SECURITY");

/* ------------------------------------------------------------- pepper ---- */
/**
 * The pepper is a server-side secret that never enters the database.
 * Per the OWASP Password Storage cheat sheet it acts as a second factor an
 * attacker needs even if they steal the whole `.db` file.
 *
 * In production this would live in a secret vault / HSM; here it is written
 * once to a gitignored file with owner-only permissions.
 */
function loadPepper() {
  const file = join(SECRET_DIR, "pepper.key");
  if (existsSync(file)) return readFileSync(file, "utf8").trim();

  const value = randomBytes(48).toString("hex");
  mkdirSync(SECRET_DIR, { recursive: true });
  writeFileSync(file, value, { encoding: "utf8", mode: 0o600 });
  try { chmodSync(file, 0o600); } catch { /* Windows ACLs differ — fine. */ }
  return value;
}
export const PEPPER = process.env.CNX_PEPPER || loadPepper();

/* ------------------------------------------------------------- digests --- */
export const sha256 = (input) =>
  createHash("sha256").update(typeof input === "string" ? input : JSON.stringify(input)).digest("hex");

/** HMAC keyed with the pepper — used as the post-hash pepper step. */
export const pepperHmac = (input) =>
  createHmac("sha256", PEPPER).update(String(input)).digest("hex");

/**
 * Constant-time comparison that never throws on length mismatch.
 * Returns false immediately if lengths differ, which leaks length only —
 * acceptable because every value we compare here is a fixed-size digest.
 */
export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a, "hex");
  const bufB = Buffer.from(b, "hex");
  if (bufA.length === 0 || bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/* -------------------------------------------------------------- tokens --- */
/** URL-safe, high-entropy token (default 256 bits). */
export function secureToken(bytes = CONFIG.session.tokenBytes) {
  return randomBytes(bytes).toString("base64url");
}

/**
 * Split-token session identifier (OWASP Session Management §Server-Side
 * Session Token Storage): the cookie carries `publicId.secret`, the server
 * stores only the public id plus a hash of the secret. A leaked store therefore
 * cannot be replayed — only the raw cookie can.
 */
export function issueSessionToken() {
  const publicId = randomBytes(16).toString("hex");
  const secret = secureToken(24);
  return { cookieValue: `${publicId}.${secret}`, publicId, secretHash: sha256(secret) };
}
export function splitSessionToken(cookieValue) {
  if (typeof cookieValue !== "string") return null;
  const i = cookieValue.indexOf(".");
  if (i <= 0 || i === cookieValue.length - 1) return null;
  return { publicId: cookieValue.slice(0, i), secret: cookieValue.slice(i + 1) };
}

/* ----------------------------------------------------------- passwords --- */
/**
 * scrypt with the OWASP-recommended cost, then an HMAC pepper pass.
 * The salt is stored alongside the hash; the pepper never is.
 */
export function hashPassword(plain, salt = randomBytes(CONFIG.password.saltBytes).toString("hex")) {
  const { N, r, p, keylen } = CONFIG.password.scrypt;
  const derived = scryptSync(plain.normalize("NFKC"), salt, keylen, { N, r, p, maxmem: 256 * 1024 * 1024 });
  return { salt, hash: pepperHmac(derived.toString("hex")) };
}

/** Constant-time verification. Never throws, never short-circuits on input. */
export function verifyPassword(plain, salt, expected) {
  try {
    const { hash } = hashPassword(plain, salt);
    return safeEqual(hash, expected);
  } catch {
    return false;
  }
}

/**
 * Burn roughly the same amount of CPU as a real verification when the account
 * does not exist. Without this, response time reveals which usernames are real
 * (user enumeration).
 */
const DUMMY_SALT = "00000000000000000000000000000000";
export function fakeVerifyDelay() {
  try { hashPassword("timing-equaliser", DUMMY_SALT); } catch { /* noop */ }
}

/* --------------------------------------------------------- fingerprints -- */
/**
 * A stable, non-reversible fingerprint of the client, used to bind sessions.
 * We deliberately hash rather than store the raw IP so the session store holds
 * no personal data.
 */
export function clientFingerprint(ip, userAgent) {
  return sha256(`${ip ?? ""}|${(userAgent ?? "").slice(0, 200)}`).slice(0, 32);
}

/* ------------------------------------------------------------ requests --- */
/** Normalises IPv4-mapped IPv6 (::ffff:127.0.0.1) and IPv6 loopback. */
export function normaliseIp(raw) {
  if (!raw) return "unknown";
  let ip = String(raw).trim();
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  if (ip === "::1") ip = "127.0.0.1";
  if (ip === "::") return "unknown";
  return ip.slice(0, 45);
}

/* ---------------------------------------------------------------- misc ---- */
export const randomDigit = () => randomInt(0, 10);

export { SECRET_DIR };