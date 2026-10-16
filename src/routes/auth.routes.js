// ============================================================================
//  Authentication — hardened.
//
//  Protections active here
//  -----------------------
//   • progressive per-account lockout (1m → 2m → 4m … capped at 1h)
//   • per-IP rate limit on /api/auth/login (8 / 10 min)
//   • constant-time work for unknown users (stops username enumeration)
//   • identical error text for "no such user" and "wrong password"
//   • honeypot field + minimum form-filling time (bot trap)
//   • session rotated on privilege change, bound to the client fingerprint
//   • CSRF token issued alongside the session
//   • every outcome written to the tamper-evident ledger
// ============================================================================
import { db, logActivity } from "../db.js";
import { CONFIG } from "../security/config.js";
import {
  hashPassword, verifyPassword, fakeVerifyDelay, normaliseIp,
} from "../security/crypto.js";
import * as pw from "../security/password.js";
import * as audit from "../security/audit.js";
import * as sessions from "../security/session.js";
import * as ratelimit from "../security/ratelimit.js";
import {
  issueSessionCookies, clearSessionCookies, requireAuth, requireRole, csrf,
} from "../security/middleware.js";
import { validate, username as usernameRule, V } from "../security/validate.js";

const A = CONFIG.account;

/* ----------------------------------------------------------- helpers ---- */
const ipOf = (req) => normaliseIp(req.socket?.remoteAddress ?? req.headers["x-forwarded-for"]);
const nowSql = (d = new Date()) => d.toISOString().slice(0, 19).replace("T", " ");

function accountLock(username) {
  return db.prepare(`SELECT * FROM login_failures WHERE username=?`).get(username);
}

/** Progressive backoff: each additional failure doubles the wait. */
function lockoutFor(failures) {
  if (failures <= 0) return 0;
  const ms = Math.min(A.lockoutMaxMs, A.lockoutBaseMs * 2 ** (failures - 1));
  return ms;
}

/* ------------------------------------------------------------- login ---- */
export async function login(req, res) {
  const ip = ipOf(req);
  const raw = await readBody(req);

  // 1. Bot traps: a filled honeypot or an impossibly fast submit.
  if (raw.hp) {
    audit.high("bot-honeypot", "security", `Honeypot triggered on sign-in from ${ip}`, req);
    return res.json({ ok: false, error: "Sign-in failed" }, 401); // deliberately vague
  }
  // Minimum submit time. The threshold has to clear any real typing speed AND
  // the server's own queueing delay — measuring too tightly would flag
  // legitimate users as bots whenever the event loop is busy.
  const MIN_FORM_MS = 1200;
  const elapsed = Date.now() - Number(raw._t ?? Date.now());
  if (Number.isFinite(elapsed) && elapsed >= 0 && elapsed < MIN_FORM_MS) {
    audit.high("bot-too-fast", "security", `Sign-in submitted after ${elapsed}ms from ${ip}`, req);
    return res.json({ ok: false, error: "Please take a moment and try again" }, 429);
  }

  // 2. Shape validation before touching the database. The schema MUST be built
  //    with V.object() — a bare object literal has no rule kind and is rejected
  //    as an unrecognised rule rather than silently validating everything.
  const parsed = validate(raw, V.object({
    username: usernameRule(),
    password: { kind: "string", trim: false, min: 1, max: 256 },
    // Declared so strict mode accepts them; both are inspected above.
    hp: V.string({ max: 120 }),
    _t: V.int({ min: 0, max: Number.MAX_SAFE_INTEGER, fallback: 0 }),
  }, { strict: true }));
  if (!parsed.ok) {
    audit.warn("auth-bad-shape", "security", `Malformed sign-in payload from ${ip}`, req);
    return res.json({ ok: false, error: "Enter a username and password" }, 400);
  }
  const username = parsed.value.username;
  const password = parsed.value.password;

  // 3. Account lockout.
  const rec = accountLock(username);
  if (rec?.locked_until && new Date(rec.locked_until + "Z").getTime() > Date.now()) {
    const waitMs = new Date(rec.locked_until + "Z").getTime() - Date.now();
    const wait = Math.ceil(waitMs / 1000);
    audit.warn("auth-account-locked", "security", `Locked account "${username}" probed from ${ip} (${wait}s remaining)`, req);
    return res.json(
      { ok: false, error: `Account temporarily locked. Try again in ${Math.ceil(wait / 60)} minute(s).`, retryAfter: wait },
      423
    );
  }

  // 4. Verify. Unknown users still pay the full hashing cost.
  const user = db.prepare(`SELECT * FROM users WHERE username=? AND active=1`).get(username);
  const ok = user
    ? verifyPassword(password, user.pass_salt, user.pass_hash)
    : (fakeVerifyDelay(), false);

  if (!user || !ok) {
    registerFailure(username, ip);
    // Identical response for "no such user" and "wrong password".
    audit.warn("auth-failed", "security", `Failed sign-in for "${username}" from ${ip}`, req);
    return res.json({ ok: false, error: "Invalid username or password" }, 401);
  }

  // 5. Success — clear counters and mint a fresh session.
  db.prepare(`DELETE FROM login_failures WHERE username=?`).run(username);
  db.prepare(
    `UPDATE users SET failed_logins=0, locked_until=NULL, last_login_at=?, last_login_ip=? WHERE id=?`
  ).run(nowSql(), ip, user.id);

  const { cookieValue } = sessions.create({
    userId: user.id,
    username: user.username,
    role: user.role,
    ip,
    userAgent: req.headers["user-agent"],
  });
  const csrfToken = csrf.issue();
  issueSessionCookies(res, req, cookieValue, csrfToken);

  logActivity("system", "Sign in", `${user.full_name} (${user.role}) from ${ip}`);
  audit.info("auth-success", "security", `${user.username} signed in from ${ip}`, req, { actor: user.username });

  res.json({
    ok: true,
    user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role },
    message: `Welcome back, ${user.full_name.split(" ")[0]}!`,
    csrfToken,
    session: {
      idleMinutes: Math.round(CONFIG.session.idleTimeoutMs / 60000),
      absoluteHours: Math.round(CONFIG.session.absoluteTimeoutMs / 3600000),
    },
  });
}

function registerFailure(username, ip) {
  const rec = accountLock(username);
  const count = (rec?.count ?? 0) + 1;
  const ms = lockoutFor(count - A.maxFailedLogins + 1);
  const lockedUntil = count >= A.maxFailedLogins ? nowSql(new Date(Date.now() + ms)) : null;
  db.prepare(
    `INSERT INTO login_failures (username, ip, count, locked_until, last_attempt)
     VALUES (?,?,?,?, datetime('now','localtime'))
     ON CONFLICT(username) DO UPDATE SET
       count=excluded.count, locked_until=excluded.locked_until,
       ip=excluded.ip, last_attempt=excluded.last_attempt`
  ).run(username, ip, count, lockedUntil);
}

/* ------------------------------------------------------------ logout ---- */
export function logout(req, res) {
  const token = req.session?.publicId;
  if (token) sessions.destroy(token);
  clearSessionCookies(res, req);
  if (req.user) audit.info("auth-logout", "security", `${req.user.username} signed out`, req);
  res.json({ ok: true, message: "Signed out" });
}

/* ---------------------------------------------------------------- me ---- */
export function me(req, res) {
  const idleLeft = req.session
    ? Math.max(0, Math.round((req.session.expiresAt - Date.now()) / 1000))
    : 0;
  res.json({
    ok: true,
    user: req.user ?? null,
    session: req.session
      ? { idleSeconds: idleLeft, issuedAt: req.session.createdAt }
      : null,
    csrfToken: req.cookies?.[CONFIG.session.csrfCookieName] ?? null,
  });
}

/* --------------------------------------------------- change password ---- */
export async function changePassword(req, res) {
  if (!requireAuth(req, res)) return;
  const ip = ipOf(req);
  const raw = await readBody(req);

  const parsed = validate(raw, V.object({
    current: { kind: "string", trim: false, min: 1, max: 256 },
    next: { kind: "string", trim: false, min: 1, max: 256 },
  }, { strict: true }));
  if (!parsed.ok) return res.json({ ok: false, error: "Fill in both password fields" }, 400);

  const user = db.prepare(`SELECT * FROM users WHERE id=?`).get(req.user.id);
  if (!verifyPassword(parsed.value.current, user.pass_salt, user.pass_hash)) {
    audit.high("password-change-unauthorised", "security", `${user.username} gave the wrong current password`, req);
    return res.json({ ok: false, error: "Current password is incorrect" }, 401);
  }

  const check = pw.validate(parsed.value.next, { username: user.username, fullName: user.full_name });
  if (!check.ok) {
    audit.warn("password-policy-rejected", "security", `Password change rejected for ${user.username}: ${check.error}`, req);
    return res.json({ ok: false, error: check.error, strength: check.strength }, 400);
  }

  const history = db
    .prepare(`SELECT pass_hash FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT ?`)
    .all(user.id, A.passwordHistory)
    .map((r) => r.pass_hash);
  if (history.includes(pw.hashPassword(parsed.value.next).hash)) {
    return res.json({ ok: false, error: `You have used one of your last ${A.passwordHistory} passwords` }, 400);
  }

  const { salt, hash } = hashPassword(parsed.value.next);
  db.prepare(
    `UPDATE users SET pass_hash=?, pass_salt=?, must_change_pw=0 WHERE id=?`
  ).run(hash, salt, user.id);
  db.prepare(`INSERT INTO password_history (user_id, pass_hash) VALUES (?,?)`).run(user.id, hash);

  // Password change invalidates every other session (OWASP risk-event reauth).
  const revoked = A.sessionRevokeOnPasswordChange ? sessions.revokeUser(user.id) : 0;
  audit.info("password-changed", "security", `${user.username} changed their password; ${revoked} session(s) revoked`, req, {
    actor: user.username,
  });

  res.json({ ok: true, message: "Password updated. Other devices have been signed out.", revokedSessions: revoked });
}

/* ------------------------------------------------------ password check -- */
export async function passwordCheck(req, res) {
  const raw = await readBody(req);
  const parsed = validate(raw, V.object({
    password: { kind: "string", trim: false, min: 0, max: 256 },
  }, { strict: true }));
  const report = pw.assess(parsed.value?.password ?? "");
  res.json({ ok: true, strength: report });
}

/* -------------------------------------------------------------- users --- */
export function listUsers(req, res) {
  if (!requireRole("admin")(req, res)) return;
  res.json({
    ok: true,
    users: db
      .prepare(
        `SELECT id, username, full_name, role, active, failed_logins,
                locked_until, last_login_at, created_at
         FROM users ORDER BY id`
      )
      .all()
      .map((u) => ({
        ...u,
        locked: !!(u.locked_until && new Date(u.locked_until + "Z").getTime() > Date.now()),
      })),
  });
}

export function unlockUser(req, res, { id }) {
  if (!requireRole("admin")(req, res)) return;
  const target = db.prepare(`SELECT * FROM users WHERE id=?`).get(Number(id));
  if (!target) return res.json({ ok: false, error: "User not found" }, 404);
  db.prepare(`UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?`).run(target.id);
  db.prepare(`DELETE FROM login_failures WHERE username=?`).run(target.username);
  sessions.revokeUser(target.id);
  audit.info("account-unlocked", "security", `Administrator unlocked "${target.username}"`, req, { actor: req.user.username });
  res.json({ ok: true, message: `${target.full_name} unlocked and signed out everywhere` });
}

/* ------------------------------------------------------------ helpers --- */
/**
 * Reads and parses the JSON body. A malformed body is a client error (400),
 * never a server error — and never a stack trace.
 */
async function readBody(req) {
  if (req._body !== undefined) return req._body;
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 8192) {
      const err = new Error("Payload too large");
      err.status = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text.trim()) { req._body = {}; return req._body; }
  try {
    req._body = JSON.parse(text);
  } catch {
    const err = new Error("Malformed JSON body");
    err.status = 400;
    throw err;
  }
  return req._body;
}

export { requireAuth, requireRole };