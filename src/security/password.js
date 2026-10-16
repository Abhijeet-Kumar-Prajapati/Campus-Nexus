// ============================================================================
//  Password policy + strength estimation (NIST SP 800-63B aligned).
// ============================================================================
import { CONFIG } from "./config.js";
import { hashPassword } from "./crypto.js";

const COMMON = new Set(CONFIG.password.common);

/**
 * Scores a candidate password 0–4 and explains what is missing.
 * Deliberately dependency-free: length dominates, character variety helps,
 * repetition and dictionary hits hurt.
 */
export function assess(plain) {
  const issues = [];
  const suggestions = [];
  const pw = String(plain ?? "");
  const len = pw.length;

  if (!len) {
    return { score: 0, label: "Empty", issues: ["Password required"], suggestions: [], acceptable: false };
  }

  /* ---- hard requirements ---- */
  if (len < CONFIG.password.minLength) {
    issues.push(`At least ${CONFIG.password.minLength} characters`);
    suggestions.push(`Add ${CONFIG.password.minLength - len} more character${CONFIG.password.minLength - len === 1 ? "" : "s"}`);
  }
  const hasUpper = /[A-Z]/.test(pw);
  const hasLower = /[a-z]/.test(pw);
  const hasDigit = /[0-9]/.test(pw);
  const hasSymbol = /[^A-Za-z0-9]/.test(pw);
  if (CONFIG.password.requireUpper && !hasUpper) { issues.push("An uppercase letter"); suggestions.push("Add an uppercase letter (A–Z)"); }
  if (CONFIG.password.requireLower && !hasLower) { issues.push("A lowercase letter"); suggestions.push("Add a lowercase letter (a–z)"); }
  if (CONFIG.password.requireDigit && !hasDigit) { issues.push("A number"); suggestions.push("Add a number (0–9)"); }
  if (CONFIG.password.requireSymbol && !hasSymbol) { issues.push("A symbol"); suggestions.push("Add a symbol (! @ # …)"); }
  if (len > CONFIG.password.maxLength) issues.push(`Longer than ${CONFIG.password.maxLength} characters`);

  /* ---- dictionary / pattern penalties ---- */
  const lowered = pw.toLowerCase();
  if (COMMON.has(lowered)) {
    issues.push("Appears in the common-password list");
    suggestions.push("Avoid well-known passwords");
  }
  if (/^(.)\1+$/.test(pw)) {
    issues.push("A single repeated character");
    suggestions.push("Mix up the characters");
  }
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|qwerty|asdf)/i.test(lowered)) {
    issues.push("Contains a keyboard or number sequence");
    suggestions.push("Avoid keyboard runs like “qwerty” or “1234”");
  }
  if (/(.)\1{2,}/.test(pw)) {
    issues.push("Has repeated characters");
    suggestions.push("Avoid repeating the same character 3+ times");
  }
  const uniq = new Set(pw).size;
  if (uniq <= Math.max(2, len * 0.25) && len > 4) {
    issues.push("Very few distinct characters");
    suggestions.push("Use more varied characters");
  }

  /* ---- score ---- */
  let bits = 0;
  if (len >= 8)  bits += 12;
  if (len >= 12) bits += 16;
  if (len >= 15) bits += 18;
  if (len >= 20) bits += 16;
  if (hasUpper && hasLower) bits += 8;
  if (hasDigit) bits += 6;
  if (hasSymbol) bits += 10;
  if (uniq >= 8) bits += 6;
  if (len >= CONFIG.password.recommendedLength) bits += 8;
  if (COMMON.has(lowered)) bits = Math.min(bits, 8);
  if (/^(.)\1+$/.test(pw)) bits = Math.min(bits, 6);
  if (/^(0123|1234|2345|3456|4567|5678|6789|abcd|qwerty)/i.test(lowered)) bits = Math.min(bits, 16);

  const score = bits >= 78 ? 4 : bits >= 56 ? 3 : bits >= 34 ? 2 : bits >= 18 ? 1 : 0;
  const label = ["Very weak", "Weak", "Fair", "Strong", "Excellent"][score];

  return {
    score,
    label,
    bits,
    issues,
    suggestions: [...new Set(suggestions)],
    acceptable: score >= 2 && issues.length === 0,
    recommended: score >= 3 && len >= CONFIG.password.recommendedLength,
  };
}

/**
 * Full validation for a new/changed password.
 * Returns { ok, error, strength } — `error` is a safe, user-facing sentence.
 */
export function validate(plain, { username = "", fullName = "" } = {}) {
  const report = assess(plain);

  if (report.issues.length) {
    return { ok: false, error: "Password must include: " + report.issues.join(", ").toLowerCase(), strength: report };
  }

  // Reject passwords that merely contain the username — the most common
  // self-inflicted weakness.
  const haystack = `${username} ${fullName}`.toLowerCase().replace(/[^a-z]/g, "");
  if (haystack.length >= 3) {
    const bare = String(plain).toLowerCase().replace(/[^a-z]/g, "");
    if (bare.includes(haystack) || haystack.includes(bare)) {
      return {
        ok: false,
        error: "Password must not contain your username or name",
        strength: { ...report, acceptable: false },
      };
    }
  }
  return { ok: true, error: null, strength: report };
}

/** True when the new password matches any of the previous ones. */
export function reused(plain, previousHashes = []) {
  if (!previousHashes.length) return false;
  const { hash } = hashPassword(plain);
  return previousHashes.includes(hash);
}