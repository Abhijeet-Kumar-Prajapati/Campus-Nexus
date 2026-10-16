// Deletes the database so the next `node server.js` re-seeds a fresh demo.
// NOTE: the path is computed locally on purpose — importing ../src/db.js would
// open (and lock) the very file we are trying to delete.
import { rmSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, "..", "data");
const DB_PATH = join(DATA_DIR, "campus-nexus.db");

const files = [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`];
let removed = 0;
for (const f of files) {
  if (existsSync(f)) {
    try {
      rmSync(f, { force: true });
      removed++;
    } catch (e) {
      console.error(`✖ Could not delete ${f}: ${e.code ?? e.message}`);
      console.error("  Tip: close any running server first (Ctrl+C) and try again.");
      process.exitCode = 1;
    }
  }
}
if (!removed) {
  console.log("Nothing to reset — no database file found.");
} else if (!process.exitCode) {
  console.log(`✔ Database reset (${removed} file(s) removed). Run "npm start" to re-seed.`);
}
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });