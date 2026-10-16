// ============================================================================
//  Field-level encryption for personally identifiable data.
//
//  Why this exists
//  ---------------
//  The pepper already protects passwords, and the session store keeps only
//  hashes. But the database still holds customer phone numbers and borrower
//  contact details in clear text. If somebody copies `campus-nexus.db` off the
//  machine — a stolen laptop, a backup, a misconfigured file share — every one
//  of those numbers is readable. This module closes that gap.
//
//  Scheme
//  ------
//  AES-256-GCM with a random 96-bit IV per value and the data key derived from a
//  dedicated secret in SECURITY/data.key (never stored in the database, and
//  gitignored). GCM is authenticated, so tampering with a ciphertext is detected
//  on decrypt rather than silently returning garbage.
//
//  Envelope:  v1:<iv-b64url>:<tag-b64url>:<ciphertext-b64url>
//
//  Search
//  ------
//  A random IV means the same phone number encrypts differently every time, so
//  `LIKE '%123%'` can never match a ciphertext. Exact lookups therefore go
//  through a deterministic HMAC "blind index" column (`*_idx`), which is
//  searchable and still reveals nothing without the key.
//
//  This is deliberately a *separate* key from the password pepper: rotating one
//  must not require re-encrypting the other.
// ============================================================================
import {
  createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");
const KEY_FILE = join(ROOT, "SECURITY", "data.key");

const ALGO = "aes-256-gcm";
const IV_BYTES = 12;      // 96-bit IV, the size GCM is specified for
const TAG_BYTES = 16;
const VERSION = "v1";

/* ------------------------------------------------------------------ key --- */
/**
 * Load (or create once) the data-encryption key.
 * Override in production with the CNX_DATA_KEY environment variable so the
 * secret lives in a vault rather than on disk.
 */
function loadKey() {
  if (process.env.CNX_DATA_KEY) return Buffer.from(process.env.CNX_DATA_KEY, "hex");
  if (existsSync(KEY_FILE)) {
    const hex = readFileSync(KEY_FILE, "utf8").trim();
    if (hex.length >= 64) return Buffer.from(hex, "hex");
  }
  const key = randomBytes(32);
  mkdirSync(dirname(KEY_FILE), { recursive: true });
  writeFileSync(KEY_FILE, key.toString("hex"), { encoding: "utf8", mode: 0o600 });
  try { chmodSync(KEY_FILE, 0o600); } catch { /* Windows ACLs differ */ }
  return key;
}

let KEY = null;
const key = () => (KEY ??= loadKey());

/* --------------------------------------------------------------- helpers -- */
const enc64 = (buf) => Buffer.from(buf).toString("base64url");
const dec64 = (str) => Buffer.from(str, "base64url");

/** Deterministic index for exact-match search over encrypted values. */
export function blindIndex(plain) {
  if (plain === null || plain === undefined || String(plain).trim() === "") return null;
  return createHmac("sha256", key()).update("idx:" + normaliseForIndex(plain)).digest("hex");
}

/**
 * Phones are compared digit-only so "+91 98765 43210" and "9876543210" find the
 * same person. Any other value falls back to a trimmed lowercase form.
 */
function normaliseForIndex(value) {
  const digits = String(value).replace(/\D/g, "");
  if (digits.length >= 7) return "n:" + digits;
  return "s:" + String(value).trim().toLowerCase();
}

/* -------------------------------------------------------------- encrypt --- */
export function encryptField(plain) {
  if (plain === null || plain === undefined) return null;
  const text = String(plain);
  if (text === "") return text;                 // keep empties readable
  if (isEnvelope(text)) return text;            // never double-encrypt

  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, key(), iv);
  const ct = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, enc64(iv), enc64(tag), enc64(ct)].join(":");
}

/* -------------------------------------------------------------- decrypt --- */
export function decryptField(stored) {
  if (stored === null || stored === undefined) return null;
  const text = String(stored);
  if (!isEnvelope(text)) return text;           // legacy plaintext passes through

  try {
    const [, ivB64, tagB64, ctB64] = text.split(":");
    const decipher = createDecipheriv(ALGO, key(), dec64(ivB64));
    decipher.setAuthTag(dec64(tagB64));
    return Buffer.concat([decipher.update(dec64(ctB64)), decipher.final()]).toString("utf8");
  } catch {
    // Auth failure means either the key rotated or the row was tampered with.
    // Returning a sentinel is safer than leaking ciphertext into the UI.
    return "[undecryptable]";
  }
}

const isEnvelope = (s) =>
  typeof s === "string" && s.startsWith(VERSION + ":") && s.split(":").length === 4;

/* ------------------------------------------------------------ diagnostics - */
/** True when the column holds ciphertext rather than a legacy clear value. */
export const isEncrypted = (s) => isEnvelope(s);

/** Never log a ciphertext or a key — only shapes and counts. */
export function status() {
  return {
    algorithm: `AES-256-GCM`,
    keySource: process.env.CNX_DATA_KEY ? "environment (CNX_DATA_KEY)" : "SECURITY/data.key",
    keyBytes: key().length * 8,
    ivBytes: IV_BYTES * 8,
    envelope: VERSION,
    encryptedFields: [
      "loans.contact", "bills.phone",
    ],
    searchableFields: [
      "bills.phone_idx (deterministic HMAC blind index)",
    ],
  };
}

/** Constant-time comparison helper for tests. */
export function blindIndexMatches(a, b) {
  const x = Buffer.from(String(a ?? ""), "hex");
  const y = Buffer.from(String(b ?? ""), "hex");
  return x.length > 0 && x.length === y.length && timingSafeEqual(x, y);
}