// ============================================================================
//  Break-glass account recovery.
//
//  If the only administrator locks themselves out of brute-force protection,
//  there is no HTTP route that can help — deliberately, since any such route
//  would itself be an attack surface. Recovery is a local, deliberate action.
//
//      node scripts/unlock-admin.js            unlock every account
//      node scripts/unlock-admin.js admin      unlock one account
// ============================================================================
import { db } from "../src/db.js";

const target = process.argv[2]?.trim();

const locked = db
  .prepare(
    `SELECT username, count, locked_until FROM login_failures
     WHERE locked_until IS NOT NULL`
  )
  .all();

if (!locked.length) {
  console.log("No accounts are currently locked.");
} else {
  console.log("Locked accounts:");
  for (const l of locked) console.log(`  · ${l.username} (${l.count} failed attempts)`);
}

if (target) {
  db.prepare(`DELETE FROM login_failures WHERE username=?`).run(target);
  db.prepare(`UPDATE users SET failed_logins=0, locked_until=NULL WHERE username=?`).run(target);
  console.log(`\n✔ Unlocked "${target}".`);
} else {
  const changed = db.prepare(`UPDATE users SET failed_logins=0, locked_until=NULL`).run().changes;
  db.prepare(`DELETE FROM login_failures`).run();
  console.log(`\n✔ Unlocked ${changed} account(s) and cleared all failure counters.`);
}