// Proves PII is unreadable by scanning the raw database file and its WAL.
//   node scripts/pii-scan.js
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { DB_PATH } from "../src/db.js";

const parts = [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`].filter(existsSync);
const blobs = parts.map((p) => {
  const b = readFileSync(p);
  // Decode as latin1 so every byte maps to a character we can search for.
  return { path: p, text: b.toString("latin1") };
});

const SECRETS = {
  "bill phone  · 9876543210": "9876543210",
  "bill phone  · 9812345678": "9812345678",
  "bill phone  · 9900112233": "9900112233",
  "bill phone  · 9654321098": "9654321098",
  "borrower email · aarav@campus.edu": "aarav@campus.edu",
  "borrower email · diya@campus.edu": "diya@campus.edu",
  "borrower email · meera@campus.edu": "meera@campus.edu",
  "borrower email · kabir@campus.edu": "kabir@campus.edu",
};

console.log(`\nPII at-rest scan · ${parts.length} file(s) on disk`);
console.log("─".repeat(62));

let leaked = 0;
for (const [label, value] of Object.entries(SECRETS)) {
  const found = blobs.filter((b) => b.text.includes(value));
  if (found.length) {
    leaked++;
    console.log(`  \x1b[31mLEAKED \x1b[0m  ${label}  ← ${found.map((f) => f.path.split("\\").pop()).join(", ")}`);
  } else {
    console.log(`  \x1b[32msealed \x1b[0m  ${label}`);
  }
}

console.log("─".repeat(62));
console.log(
  leaked
    ? `  \x1b[31m${leaked} plaintext value(s) recoverable from the database files\x1b[0m\n`
    : `  \x1b[32mNo plaintext PII recoverable from the database files\x1b[0m\n`
);
process.exit(leaked ? 1 : 0);