# 🎓 CAMPUS NEXUS

### *Library · Store · Arcade* — three original projects, rebuilt as one application.

---

## What this is

This project **merges four separate student projects** into a single, modern web
application running on **one database, one login and one dashboard**.

| Original project | Tech it was written in | Where it lives now |
|---|---|---|
| **I_P** — "THE CITADEL" Library Management System | Java Swing + MySQL | **Library** module |
| **Shopping Mall** — Billing / Inventory System | Java Swing + MySQL | **Store** module |
| **Project 1** — Number Guessing Game | C | **Arcade** → Number Guessing |
| **Project 2** — Snake · Water · Gun | C | **Arcade** → Snake·Water·Gun |

The old versions were four programs that knew nothing about each other, each
needing its own database and its own login. Campus Nexus runs all of them side by
side and adds a unified dashboard that reads live numbers from all three areas at
once.

---

## ✨ Highlights

- **Zero installation.** No `npm install`, no MySQL server, no Java, no JDK.
  Uses Node's built-in `node:sqlite` and `node:http`.
- **One database.** The original Shopping Mall project pointed at *two* different
  databases (`departmental` and `bazar`); here there is exactly one.
- **Real money maths.** Bills are computed server-side inside a transaction:
  discount → GST → total, with stock decremented atomically.
- **Library fines.** Overdue books are detected automatically and fined at
  ₹2/day; you cannot delete a title that still has copies on loan.
- **Sessions & security.** Passwords hashed with `scrypt`, HTTP-only cookies,
  IP-based brute-force lockout, and server-side validation on every write.
- **Dark + light theme**, responsive down to mobile, printable receipts.
- **43 automated tests** covering every endpoint (`npm test`).

---

## 🚀 Running it

You need **Node.js 22.5 or newer** — `node:sqlite` does not exist before that. Check with `node --version`.

```bash
npm start          # http://localhost:3000
```

or just **double-click `start.bat`** on Windows.

Other commands:

```bash
npm run dev        # auto-restart on file changes
npm test           # run the full API test suite (server must be running)
npm run reset      # wipe the database and re-seed fresh demo data
```

Use a different port if 3000 is taken:

```bash
# Windows PowerShell
$env:PORT=4000; node server.js
# macOS / Linux
PORT=4000 node server.js
```

### Demo logins

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `admin123` |
| Counter staff | `staff` | `staff123` |

Browsing is open to everyone; **issuing books, editing stock and billing require
a sign-in**.

---

## 🧩 Modules

### 📚 Library
Stock list with search and category filters · add / edit / remove titles ·
issue and return with automatic due dates · **₹2/day overdue fines** · return
history · copy-availability guards (no deleting an issued title) · CSV export.

### 🛒 Store
Point-of-sale counter with a live cart · discount + 5% GST · print/duplicate
receipts · inventory management with reorder levels · low-stock alerts ·
bill search by number, customer or phone · sales reports (14-day revenue
trend, best sellers, payment mix, category performance) · CSV export.

### 🎮 Arcade
**Number Guessing** — four difficulty ranges (1–10 to 1–500), configurable
attempt limits, higher/lower hints, speed-bonus scoring.
**Snake · Water · Gun** — best-of-3/5/7/9 matches, streak bonuses.
Both save to one shared, persistent leaderboard with global search.

### 🏠 Dashboard
Live figures from all three modules at once: catalogue size, overdue count,
inventory value, 30-day revenue, reorder alerts, arcade players — plus a revenue
chart, best sellers, per-module health bars and a full activity feed.

### 🛡️ Security Centre
A self-monitoring surface at **/security** that reports the *live* state of all
**29 controls**, grouped into six defence layers — plus the current threat score,
every rate-limit bucket, live sessions, the recent event stream, and the audit
chain with a one-click re-verify.

---

## 🔐 Security

Campus Nexus ships with a defensive layer built in rather than bolted on. The
full write-up — including an honest **residual-risk section** — is in
[`SECURITY.md`](./SECURITY.md).

### Highlights

| Area | What is enforced |
|---|---|
| **Rate limiting** | Tiered per-IP buckets (600/60s global, 400/60s read, 90/60s search, 60/60s write, 40/10min sign-in) with **exponential backoff** — every trip doubles the window, capped at 30 min |
| **Account lockout** | 5 failures locks the account; each extra failure doubles the wait to a 1-hour ceiling, with an exact countdown returned. **Per-account**, so one user locking out never locks out the campus behind the same NAT |
| **Passwords** | `scrypt` at N=2¹⁶, r=8, p=2 (**64 MiB per hash**) followed by an **HMAC pepper** stored outside the database |
| **Password policy** | 12+ chars (15 recommended), mixed case + digit + symbol, common-password and pattern penalties, last-3 reuse blocked, live strength meter |
| **Sessions** | 256-bit split tokens (`publicId.secret`; the store keeps only a hash), bound to IP + User-Agent, 30 min idle / 8 h absolute, rotated every 15 min, max 5 per user |
| **CSRF** | HMAC-signed double-submit token required on every POST/PUT/PATCH/DELETE, layered on top of `SameSite=Strict` cookies |
| **Headers** | Strict CSP (`script-src 'self'`), HSTS, nosniff, frame-deny, no-referrer, restrictive Permissions-Policy, COOP/CORP/COEP, `X-Powered-By` stripped |
| **Input validation** | Every write body validated against a typed schema; unknown keys refused |
| **Mass assignment** | `role`, `id`, `pass_hash`, `__proto__` and friends are rejected — you cannot promote yourself to admin by sending `"role":"admin"` |
| **Bot traps** | Honeypot field + minimum submit time; both fail silently with a generic error |
| **Enumeration** | Unknown users still pay the full `scrypt` cost and receive an identical error message |
| **PII encryption** | Phone numbers and borrower contacts are sealed with **AES-256-GCM** under a key held outside the database; exact phone lookup uses a deterministic HMAC blind index so ciphertext is never pattern-matched |
| **Production build** | `npm run build` → minified bundle with **sha384 SRI**; the browser refuses to execute any file changed after the build |
| **Audit chain** | Every event appended to a SHA-256 **hash chain + Merkle tree + proof-of-work**, sealed outside the database |

### Is the code "hidden"?

Straight answer: **no, and it should not be.**

- The readable source stays in `public/` — it is what a reviewer audits and what
  you show a teacher.
- `npm run build` writes a minified copy to `public/dist/`. That shrinks the
  payload and removes comments, and SRI stops anyone tampering with it after the
  build (verified: append one byte to the bundle and the app refuses to boot).
- But **anything the browser executes, a user can eventually read.** Putting an
  "encrypted" secret inside a bundle is worse than useless, because the key has
  to ship with it. Every real secret in this project — the password pepper and
  the data-encryption key — lives in `SECURITY/`, is gitignored, and never
  reaches the client. That, not minification, is the actual protection.

### The audit chain

Each block stores its own digest, the previous block's digest, a Merkle root over
its events, and a proof-of-work nonce:

```
hash = SHA256( index ‖ timestamp ‖ type ‖ module ‖ actor ‖ severity
              ‖ HMAC_pepper(payload) ‖ prevHash ‖ merkleRoot ‖ difficulty ‖ nonce )
```

Editing, deleting or reordering any historical row breaks the chain and is
reported with the exact block index. Rebuilding the entire database is caught by
the external seal file.

> **Honest caveat:** this is an *append-only, self-verifying audit log*, not a
> distributed blockchain. There is no peer network and no consensus, so it
> cannot defend against someone with write access to the whole host. See
> [SECURITY.md §2.13](./SECURITY.md) for exactly what it does and does not prove.

### Incident response

The Security Centre offers two admin-only actions, both of which log themselves
into the chain:

- **Clear lockouts** — empty every rate-limit bucket and unlock all accounts
- **Revoke all sessions** — destroy every live session immediately

If you ever lock out the *only* administrator, recovery is deliberately a local
action rather than an HTTP route, since such a route would itself be an attack
surface:

```bash
npm run unlock          # unlock every account
npm run unlock -- admin # unlock one
```

---

## 🗂 Project structure

```
campus-nexus/
├── server.js                 HTTP server + security pipeline + routes
├── start.bat                 Windows one-click launcher
├── SECURITY.md               full security architecture + residual risks
├── src/
│   ├── schema.sql            tables, indexes, constraints, ledger
│   ├── db.js                 connection, password hashing, demo seed data
│   ├── http.js               router (with middleware), cookies, static serving
│   ├── security/
│   │   ├── config.js         every tunable in one reviewable file
│   │   ├── crypto.js         scrypt+pepper, split tokens, safe compare
│   │   ├── password.js       policy + strength scoring
│   │   ├── session.js        hardened store (hashing, binding, timeouts)
│   │   ├── ratelimit.js      sliding window + exponential backoff
│   │   ├── csrf.js           signed double-submit tokens
│   │   ├── headers.js        CSP, HSTS, COOP/CORP/COEP …
│   │   ├── validate.js       typed schema validation
│   │   ├── ledger.js         hash chain + Merkle + proof of work
│   │   ├── audit.js          event sink → table + ledger
│   │   └── middleware.js     the ordered request pipeline
│   └── routes/
│       ├── auth.routes.js    login, lockout, password change, sessions
│       ├── library.routes.js catalogue, loans, fines
│       ├── store.routes.js   inventory, POS, bills, analytics
│       ├── arcade.routes.js  scoring rules, leaderboard
│       ├── security.routes.js posture, chain, incident response
│       └── system.routes.js  dashboard aggregation, global search
├── public/                   the frontend (no build step, no framework)
│   ├── index.html
│   ├── css/style.css         design system, dark + light, print styles
│   └── js/
│       ├── app.js            shell, routing, auth, global search
│       ├── api.js            API client (CSRF, lockout cooldowns)
│       ├── ui.js             toasts, modals, formatters, SVG charts
│       ├── icons.js          inline icon set
│       └── views/            dashboard · library · store · arcade · security
├── scripts/
│   ├── smoke-test.js         45 functional API tests
│   ├── security-test.js      85 adversarial security tests
│   ├── unlock-admin.js       break-glass account recovery
│   └── reset-db.js           wipe & re-seed
├── SECURITY/                 generated: pepper.key + chain-seal.json (gitignored)
└── data/                     SQLite file is created here on first run
```

---

## 🔌 API reference

All responses are JSON. Writes require a session cookie **and** a valid CSRF token.

**Auth** — `POST /api/auth/login` · `POST /api/auth/logout` · `GET /api/auth/me` ·
`POST /api/auth/change-password` · `POST /api/auth/password-check` ·
`GET /api/auth/users` · `POST /api/auth/users/:id/unlock`

**Security** — `GET /api/security/posture` · `GET /api/security/events` ·
`GET /api/security/chain` · `GET /api/security/chain/blocks` ·
`POST /api/security/reset` · `POST /api/security/revoke-sessions`

**Library** — `GET /api/library/stats` · `GET|POST /api/library/books` ·
`PUT|DELETE /api/library/books/:id` · `GET /api/library/categories` ·
`GET /api/library/loans` · `POST /api/library/loans` · `POST /api/library/loans/:id/return`

**Store** — `GET /api/store/stats` · `GET|POST /api/store/products` ·
`PUT|DELETE /api/store/products/:id` · `POST /api/store/products/:id/restock` ·
`GET /api/store/categories` · `GET /api/store/lowstock` ·
`GET|POST /api/store/bills` · `GET /api/store/bills/:id` · `GET /api/store/analytics`

**Arcade** — `GET /api/arcade/stats` · `GET /api/arcade/leaderboard` · `POST /api/arcade/score`

**System** — `GET /api/system/health` · `GET /api/system/dashboard` ·
`GET /api/system/search?q=` · `GET /api/system/activity`

---

## 🗄 Data model

```
users ──1:N──► password_history     (last N hashes, reuse blocked)
  │
  └────────► login_failures         (per-account lockout counter)

books ──1:N──► loans                (a book cannot be deleted while copies are out)

products ──1:N──► bill_items ──N:1──► bills
                                            └─ stock decremented inside a transaction

game_scores      activity           (human-readable business audit)
security_events                    (queryable security log)
ledger                             (hash-chained, tamper-evident)
```

Reference data in the running instance: **20 titles / 77 copies**, **25 products**,
4 historical bills, 8 leaderboard entries.

---

## 🔧 What was fixed from the originals

| Problem in the old code | Fix here |
|---|---|
| Shopping Mall used two databases (`departmental` + `bazar`) | single unified schema |
| Passwords compared as plain text | `scrypt` + HMAC pepper + progressive lockout |
| No login attempt throttling | per-IP rate limit **and** per-account exponential lockout |
| Billing trusted client-sent prices | prices and stock re-read server-side |
| Overselling possible | checked against live stock, rejected with 409 |
| No transaction around billing | `BEGIN IMMEDIATE` … `COMMIT` / `ROLLBACK` |
| No fine calculation | overdue tracked, ₹2/day applied on return |
| Titles could be deleted while issued | blocked with a clear error |
| Hardcoded `root` / `annie` DB passwords | none needed — embedded SQLite |
| Games kept score in memory | persistent leaderboard in the database |
| `mysql-connector-java-5.1.0` (2013) | no external dependency at all |

---

## 🧪 Tests

```bash
# terminal 1
npm start

# terminal 2
npm test               # 45 functional API tests
npm run test:security  # 98 adversarial security tests
npm run test:validate  # input-validation edge cases
npm run test:crypto    # AES-256-GCM round-trip + tamper detection
npm run test:pii       # scans the database files for plaintext PII
npm run test:all       # everything
```

**Functional** — signs in, creates a book, issues and returns it, creates a
product, generates a bill and **asserts the arithmetic**
(`₹200 − 10% + 5% GST = ₹189`), checks that overselling and duplicate ISBNs/SKUs
are rejected, verifies stock was decremented, saves an arcade score, and confirms
the session is revoked on logout.

**Security** — does not merely check that features exist, it **attacks them**:

- floods the search endpoint until it trips and asserts the 429 contract
- forges CSRF tokens, omits them entirely, and confirms the real one works
- replays a valid session cookie from a different User-Agent and asserts it dies
- forges the secret half of the split token
- fills the honeypot and submits faster than a human could
- sends `"role": "admin"` and asserts it is refused
- sends a 300 KB body and a 2 500-character URL
- brute-forces an account until it locks, proves the *correct* password is still
  refused, and proves a **different** account is unaffected
- compares response messages for known vs unknown users
- verifies every ledger block's link and proof-of-work
- asserts staff cannot reach admin-only endpoints

---

## 🔒 Note on the demo credentials

The seeded passwords are intentionally weak so the project can be demoed with one
click. **Change them before deploying anywhere real** — the account menu has a
change-password flow that enforces the full policy, revokes every other session,
and refuses to reuse the last three.

Read [`SECURITY.md`](./SECURITY.md) §5 for the honest list of what this
application still does **not** protect against, and what to do before deploying.

---

MIT · built as a consolidation of four earlier academic projects.