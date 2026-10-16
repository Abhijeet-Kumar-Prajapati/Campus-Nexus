// ============================================================================
//  Field-encryption tests — verifies PII really is unreadable in the database
//  file itself, and that the application still behaves correctly.
//      node scripts/fieldcrypto-test.js
// ============================================================================
import { DB_PATH } from "../src/db.js";
import { db } from "../src/db.js";
import { encryptField, decryptField, blindIndex, isEncrypted, blindIndexMatches, status }
  from "../src/security/fieldcrypto.js";

let pass = 0, fail = 0;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const check = (label, ok, extra = "") => {
  if (ok) { pass++; console.log(`${green("  PASS")}  ${label}${extra ? `\x1b[2m  ${extra}\x1b[0m` : ""}`); }
  else { fail++; console.log(`${red("  FAIL")}  ${label}${extra ? red(`  ${extra}`) : ""}`); }
};

console.log(`\nField encryption · ${DB_PATH}\n${"─".repeat(62)}`);

/* ---- round trip ---- */
const SECRET = "9876543210";
const enc = encryptField(SECRET);
check("encrypts to a v1 envelope", isEncrypted(enc), enc.slice(0, 28) + "…");
check("ciphertext differs from plaintext", !enc.includes(SECRET));
check("decrypts back to the original", decryptField(enc) === SECRET);
check("iv and tag are present", enc.split(":").length === 4 && enc.split(":")[1].length >= 16);

const enc2 = encryptField(SECRET);
check("same value encrypts differently each time (random IV)", enc !== enc2);
check("both ciphertexts still decrypt", decryptField(enc2) === SECRET);

check("is idempotent (never double-encrypts)", encryptField(enc) === enc);
check("empty string stays empty", encryptField("") === "");
check("null stays null", encryptField(null) === null);
check("legacy plaintext passes through", decryptField("plain@old.com") === "plain@old.com");

/* ---- tamper detection ---- */
const tampered = enc.slice(0, -4) + (enc.slice(-4) === "AAAA" ? "BBBB" : "AAAA");
check("tampered ciphertext is detected (GCM auth)", decryptField(tampered) === "[undecryptable]");

/* ---- unicode ---- */
check("unicode round-trips", decryptField(encryptField("कॉलेज ವಿದ್ಯಾರ್ಹಿ")) === "कॉलेज ವಿದ್ಯಾರ್ಹಿ");

/* ---- blind index ---- */
const a = blindIndex("9876543210");
const b = blindIndex("98 765 43210");          // same number, spaces for readability
check("blind index is deterministic", blindIndex("9876543210") === a);
check("blind index normalises spacing inside a number", blindIndexMatches(a, b));
check("blind index differs for a different number", !blindIndexMatches(a, blindIndex("9000000000")));
check("blind index of empty is null", blindIndex("") === null);
check("blind index never contains the plaintext", !a.includes("9876543210"));

/* ---- status reporting ---- */
const st = status();
check("reports AES-256-GCM", st.algorithm.includes("AES-256-GCM"), st.algorithm);
check("uses a 256-bit key", st.keyBytes === 256, `${st.keyBytes}-bit`);
check("uses a 96-bit IV", st.ivBytes === 96, `${st.ivBytes}-bit`);

/* ---- what is actually on disk ---- */
// Only rows that actually hold a value; a NULL phone is not a leak.
const phoneRows = db.prepare(`SELECT phone FROM bills WHERE phone IS NOT NULL AND phone <> '' LIMIT 10`).all();
if (phoneRows.length) {
  check("stored bill phones are ciphertext in the DB",
        phoneRows.every((r) => isEncrypted(r.phone)),
        `${phoneRows.length} row(s) checked`);
} else {
  console.log("\x1b[2m  (no bills with a phone number yet)\x1b[0m");
}
const contactRows = db.prepare(`SELECT contact FROM loans WHERE contact IS NOT NULL AND contact <> '' LIMIT 10`).all();
if (contactRows.length) {
  check("stored borrower contacts are ciphertext in the DB",
        contactRows.every((r) => isEncrypted(r.contact)),
        `${contactRows.length} row(s) checked`);
} else {
  console.log("\x1b[2m  (no loans with a contact yet)\x1b[0m");
}

console.log(`\n${"─".repeat(62)}`);
console.log(`  ${green(`${pass} passed`)}${fail ? `, ${red(`${fail} failed`)}` : ""}\n`);
process.exit(fail ? 1 : 0);