# 🔐 Security Architecture — Campus Nexus

This document describes exactly what is enforced, where in the code it lives,
and — just as importantly — **what it does not protect against**.

Reference material: OWASP Cheat Sheets (Session Management, Password Storage,
CSRF, HTTP Headers, Content Security Policy), NIST SP 800-63B, RFC 9106.

---

## 1. Request pipeline

Every request, in this order, before routing:

| # | Stage | Code | Blocks |
|---|---|---|---|
| 1 | Security headers | `security/middleware.js#securityHeaders` | clickjacking, sniffing, referrer leak, framing |
| 2 | Size guard | `#sizeGuard` | oversized URL / body / header flood |
| 3 | Global rate limit | `#globalLimit` | volumetric abuse from one IP |
| 4 | Tiered rate limit | `#tierLimit` | targeted abuse of a specific endpoint class |
| 5 | CSRF verification | `#csrfGuard` | cross-site state-changing requests |
| 6 | Session resolution | `#attachSession` | stolen / replayed / expired tokens |
| 7 | Routing + authorisation | `#requireAuth` / `#requireRole` | privilege escalation, IDOR |

All stages fail closed: if a stage throws, the request is rejected rather than
allowed through.

---

## 2. Controls implemented

### 2.1 Rate limiting — `security/ratelimit.js`
Sliding-window token buckets keyed by `tier:ip`.

| Tier | Budget | Applies to |
|---|---|---|
| `global` | 600 / 60 s | every request |
| `auth` | **8 / 10 min** | `/api/auth/login` |
| `write` | 60 / 60 s | POST / PUT / PATCH / DELETE |
| `read` | 400 / 60 s | GET under `/api/` |
| `search` | 90 / 60 s | `/api/system/search` |

**Progressive backoff.** Each time a bucket trips, its window doubles
(×2, capped at 30 minutes). Repeat offenders are pushed out exponentially rather
than getting a free retry after a fixed cooldown.

Responses carry `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
`X-RateLimit-Reset` and `Retry-After`, so the UI renders an accurate countdown
instead of guessing. The login form mirrors the lockout client-side so a locked
user never even fires a request.

### 2.2 Brute-force & account lockout — `routes/auth.routes.js`
- **Per-IP:** the `auth` tier above.
- **Per-account:** 5 failures locks the account; every further failure doubles
  the wait (1m → 2m → 4m … capped at 1 hour). Locked accounts return **423
  Locked** with the exact remaining seconds.
- A successful sign-in clears the counter.
- Admins can unlock any account, which also revokes that user's sessions.

### 2.3 Username-enumeration defence
- Unknown users still execute a full `scrypt` verification against a dummy salt
  (`fakeVerifyDelay`), so response time does not reveal whether an account exists.
- Identical error text and status for *"no such user"* and *"wrong password"*.

### 2.4 Bot traps
- **Honeypot field** — hidden off-screen, labelled "leave this empty". Naive bots
  fill every input; humans never see it. Firing it logs a `high`-severity event
  and returns a deliberately vague error.
- **Minimum submit time** — the client stamps `_t`; submits arriving in under
  700 ms are refused. Humans cannot complete the form that fast.

### 2.5 Password storage — `security/crypto.js`
```
scrypt(password, per-user random salt, N=2¹⁶, r=8, p=2, len=64)   →  64 MiB per hash
HMAC-SHA256(result, pepper)                                        →  stored hash
```
- Parameters are from the OWASP scrypt table (64 MiB configuration).
- A **pepper** is mixed in afterwards and stored *outside* the database
  (`SECURITY/pepper.key`, gitignored, `chmod 600`). Stealing the `.db` alone no
  longer allows offline cracking. Override with `CNX_PEPPER`.
- Verification is constant-time (`timingSafeEqual`).

### 2.6 Password policy — `security/password.js`
- Minimum 12 characters, recommended 15 (NIST SP 800-63B).
- Requires upper, lower, digit and symbol.
- Penalises and rejects: common passwords, single-character repeats, keyboard
  runs (`qwerty`, `1234`), low character variety.
- **Reuse prevention** — the last 3 hashes are stored and rejected.
- Passwords containing the user's own username or name are refused.
- A live strength meter in the UI is backed by the *server's* scoring function,
  so the two can never disagree.

### 2.7 Sessions — `security/session.js`
| Property | Implementation |
|---|---|
| Entropy | 32 CSPRNG bytes = **256 bits** |
| Storage | **split token** — cookie carries `publicId.secret`; server stores only `publicId` + `SHA-256(secret)` |
| Fingerprint | bound to `HMAC(IP ‖ User-Agent)`; a replay from another client is **destroyed**, not just refused |
| Idle timeout | 30 minutes, slid on each request |
| Absolute timeout | 8 hours, regardless of activity |
| Rotation | every 15 minutes, and always on privilege change |
| Concurrency | max 5 live sessions per user; oldest evicted |
| Cookie | `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` under TLS, generic name `cnx_sid` |

Because only a hash of the secret is stored, **a leaked session store cannot be
replayed** — the attacker would need the raw cookie.

### 2.8 CSRF — `security/csrf.js`
Signed double-submit token. The cookie holds `payload.HMAC(payload)`; the client
echoes it in `X-CSRF-Token`. Required on `POST`, `PUT`, `PATCH`, `DELETE`.
Because the HMAC is keyed with the server pepper, an attacker on another origin
can neither read nor forge it. Comparison is constant-time.

This is layered **on top of** `SameSite=Strict` cookies — defence in depth, as
the OWASP CSRF cheat sheet requires.

### 2.9 Headers — `security/headers.js`

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
  img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none';
  frame-ancestors 'none'; base-uri 'none'; form-action 'self'; worker-src 'self';
  upgrade-insecure-requests
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff          X-Frame-Options: DENY
Referrer-Policy: no-referrer             X-Download-Options: noopen
Permissions-Policy: camera=(), microphone=(), geolocation=(), …
Cross-Origin-Opener-Policy: same-origin  Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cache-Control: no-store, no-cache, must-revalidate, private
```

`X-Powered-By` and `Server` are stripped so the stack cannot be fingerprinted.

> **`upgrade-insecure-requests` is emitted only over TLS.** Advertising it on a
> plain-HTTP origin makes the browser rewrite every script and style URL to
> `https://`, which fails outright where there is no certificate. That silently
> broke the app on any non-`localhost` origin — including the LAN address the
> server prints on start-up. HSTS already covers real deployments, so the
> directive is added only when it can actually work.
> Regression-locked by a test in `scripts/security-test.js` §16.

> **Honest caveat on CSP:** `style-src` includes `'unsafe-inline'` because the UI
> builds layout with `style` attributes. Scripts are strictly `'self'` with no
> inline allowance, which is where XSS actually does damage. Removing the style
> exception would require moving every inline style into the stylesheet.

### 2.10 Input validation — `security/validate.js`
A dependency-free, fail-closed schema validator. Every write body is validated
against a typed schema (`string`, `int`, `number`, `bool`, `enum`, `array`,
`object`) with length limits, patterns and ranges. Client control characters are
stripped.

- **Prototype pollution & mass assignment:** `__proto__`, `constructor`,
  `prototype`, `role`, `id`, `pass_hash`, `pass_salt`, `active`, `created_at`
  are rejected outright — a client cannot promote itself to admin by sending
  `"role": "admin"`.
- **SQL injection:** every query uses bound parameters. A secondary tripwire
  pattern flags injection-shaped input and records it as a security event.

### 2.11 Path traversal — `http.js#serveStatic`
Static paths are `normalize`d and verified to resolve **inside** the public root
before any read.

### 2.12 Information disclosure
- Unhandled errors are logged server-side with full detail; the client receives
  only `"Something went wrong on the server"`. Stack traces, file paths and SQL
  never leave the process.
- Unknown routes return a clean 404 that is itself recorded.

### 2.13 Tamper-evident audit chain — `security/ledger.js`

**What it is.** Every security-relevant and business event is appended to a
hash-chained ledger:

```
hash(n) = SHA256( index ‖ timestamp ‖ type ‖ module ‖ actor ‖ severity
                ‖ HMAC_pepper(payload) ‖ prevHash ‖ merkleRoot ‖ difficulty ‖ nonce )
```

- Each block stores a **Merkle root** over its events.
- Each block carries a **proof-of-work nonce** — the hash must begin with
  `difficulty` zero hex digits, and difficulty ramps with chain height.
- `prevHash` links each block to its predecessor; the first links to a fixed
  genesis value.
- The current head is **sealed to a file outside the database**
  (`SECURITY/chain-seal.json`).

**What it detects.** Editing any historical row changes that block's digest and
breaks the link to its successor — `verifyChain()` reports the exact block index
and nature of the fault. Deleting a block breaks the chain. Reordering breaks
the links. A wholesale database rebuild is caught by the external seal.

```
GET /api/security/chain      → full verification report + integrity certificate
GET /api/security/chain/blocks → the 40 most recent blocks with their links
```

**What it is NOT.** This is *not* a distributed blockchain:

- There is **no peer-to-peer network** and **no consensus mechanism**.
- A party with write access to the entire database could rebuild a valid-looking
  chain from scratch, and also rewrite the seal file.
- There is no Byzantine-fault tolerance and no incentive layer.

It is an **append-only, self-verifying audit log** — the same hash-chain
construction used inside real blockchains, minus the distributed consensus that
makes them tamper-proof against a *database owner*. For a single-node campus
system it is honest, verifiable evidence; it is not a substitute for signed,
independently replicated storage if you need resistance against the host itself.

### 2.14 Audit trail — `security/audit.js`
Two sinks: a queryable `security_events` table for the UI, and the ledger above.
Nothing is written directly by route handlers — everything goes through
`audit.info / warn / high / critical`, which guarantees every event is chained.

### 2.15 Privilege separation
Admin-only actions (`/api/auth/users`, emergency reset, mass session revocation,
account unlock) are gated by `requireRole("admin")`. Attempts by a lower role are
logged as `privilege-escalation` at `high` severity.

### 2.16 Security Centre (`/api/security/posture`)
Exposes the *live* state of every control — 29 of them — rather than a static
claim. If a control is misconfigured, the page shows the real value.

### 2.17 PII encryption at rest — `security/fieldcrypto.js`

The pepper protects passwords and the session store keeps only hashes, but the
database still held customer phone numbers and borrower contacts in clear text.
A stolen `campus-nexus.db`, a backup, or a misconfigured file share exposed every
one of them. Those columns are now sealed:

```
AES-256-GCM, random 96-bit IV per value, 128-bit auth tag
envelope:  v1:<iv-b64url>:<tag-b64url>:<ciphertext-b64url>
key:       SECURITY/data.key (or CNX_DATA_KEY) — never in the database
```

- **Encrypted:** `bills.phone`, `loans.contact`
- **Search:** a random IV means the same number encrypts differently every time,
  so `LIKE '%123%'` can never match ciphertext. Exact lookups use a
  **deterministic HMAC blind index** (`bills.phone_idx`), which is searchable and
  reveals nothing without the key. Phones are digit-normalised first, so
  `98 765 43210` finds `9876543210`.
- **Tamper-evident:** GCM is authenticated, so an edited ciphertext fails
  decryption and returns `[undecryptable]` rather than garbage.
- **Separate key** from the password pepper, so rotating one does not force
  re-encrypting the other.
- Legacy plaintext passes through unchanged, so an old database keeps working.

Verify it yourself:

```bash
npm run test:crypto   # 22 checks: round-trip, random IV, tamper detection, blind index
npm run test:pii      # scans the raw .db and .db-wal for known plaintext
```

`test:pii` is the convincing one: it reads the database files off disk and
searches for the exact phone numbers and email addresses that were inserted.
They are not there.

### 2.18 Production build & SRI — `scripts/build.js`

```bash
npm run build         # → public/dist/
```

Produces a minified copy (comments and whitespace stripped, module specifiers
rewired) with a **sha384 Subresource Integrity** hash on the entry script and the
stylesheet.

**What SRI genuinely buys:** the browser hashes the file and refuses to execute
it if the bytes changed after the build. Verified end-to-end — appending one byte
to `dist/js/app.min.js` produces:

> `Failed to find a valid digest in the 'integrity' attribute … computed SHA-384
> integrity mismatch`

and the application does not boot. That is real protection against anything that
can write to the web root after deployment.

**What it does not buy, stated plainly:** minification is *not* secrecy. Anything
the browser executes, a determined user can eventually read — that is a property
of the web platform. Shipping an "encrypted" secret inside the bundle is worse
than useless, because the key has to be in the bundle too. **All real secrets
stay in `SECURITY/` and never reach the client.**

The readable source deliberately stays in `public/`: it is what a reviewer should
audit, and it is what you show a teacher. `dist/` is only the built artefact.

Note: SRI is enforced on the entry `<script>` tag, not on modules pulled in later
by `import()` — the browser has no way to hash a dependency graph.

---

## 3. Frontend measures

| Measure | Where |
|---|---|
| Output escaping on every interpolated value | `ui.js#esc` |
| No tokens in `localStorage`/`sessionStorage` | cookies only, `HttpOnly` |
| `credentials: "same-origin"` on every request | `api.js` |
| Client cooldown mirroring the server lockout | `app.js#startCooldown` |
| Idle auto-sign-out matching the server window | `app.js#startIdleWatch` |
| Password strength meter from the server's scorer | `app.js#showChangePassword` |
| CSRF token attached to unsafe requests | `api.js#csrfToken` |
| Reusable modal/dialog helper (no `alert()`) | `ui.js` |
| Clipboard-safe: no `innerHTML` of raw API strings | all views |

---

## 4. Testing

```bash
npm test               # 45 functional API tests
npm run test:security  # 98 adversarial security tests
npm run test:validate  # input-validation edge cases
npm run test:crypto    # field-encryption round-trip and tamper detection
npm run test:pii       # scans the database files for plaintext PII
npm run test:all       # everything
```

The security suite does not merely check that the features *exist* — it
**attacks them**:

- floods the search endpoint until it trips and asserts the 429 contract
- forges CSRF tokens, omits them entirely, and confirms the real one works
- replays a valid session cookie from a different User-Agent and asserts it dies
- forges the session secret half of the split token
- fills the honeypot and submits faster than a human could
- sends `"role": "admin"` and asserts it is refused
- sends a 300 KB body and a 2 500-character URL
- brute-forces an account until it locks, then proves the *correct* password is
  still refused, and proves a **different** account is unaffected
- compares response messages and timing for known vs unknown users
- verifies every ledger block's link and proof-of-work
- asserts staff cannot reach admin-only endpoints
- **feeds it a `DROP TABLE` payload** and asserts the books table survives while
  the attempt is logged
- **asserts the CSP omits `upgrade-insecure-requests`** on plain HTTP — the
  regression that silently broke LAN access
- **asserts PII is encrypted in the database** but still searchable by phone

### The XSS test is a runtime test, not a static one

`scripts/xss-fixtures.js --inject` writes six real payloads into every
user-editable column — book titles, authors, borrowers, roll numbers, contacts,
product names, suppliers, descriptions, bill customers, phone numbers and
leaderboard entries. Loading every view and every tab afterwards must produce
`window.__cnx_xss__ === undefined` **and** zero injected elements.

It passes, and the payloads are verified to be genuinely present in the DOM as
*text* — otherwise the test would be proving nothing.

Clean up with `node scripts/xss-fixtures.js --clean`.


---

## 5. Residual risk — read this honestly

This application is a **single-node local campus system**. The following are
genuinely **not** addressed:

| Risk | Why it remains |
|---|---|
| **No TLS** | It runs on `http://localhost`. `Secure` cookies and HSTS switch on automatically under HTTPS, but without a certificate tokens travel in the clear. Terminate TLS with a reverse proxy (Caddy/nginx) before exposing it to a network. |
| **In-memory session store** | Sessions do not survive a restart and do not work across multiple processes. For multi-instance deployment, move to Redis or the database. |
| **Pepper on disk** | `SECURITY/pepper.key` and `SECURITY/data.key` protect against a database leak only. Real deployments need a secret manager or HSM — set `CNX_PEPPER` and `CNX_DATA_KEY` from one. |
| **Minification is not secrecy** | `npm run build` strips comments and adds SRI, which genuinely stops post-build tampering of the bundle. But anything the browser runs, a determined user can eventually read. Never put a secret in the frontend — that is the one rule this project cannot bend. |
| **SRI covers the entry point only** | The browser hashes `<script integrity>` and `<link integrity>` tags; it cannot hash a module dependency graph reached through `import()`. |
| **No MFA / TOTP** | A password is a single factor. For admin accounts, add a TOTP second factor. |
| **Ledger is single-writer** | See §2.13 — no consensus, so it cannot defend against a hostile host. |
| **No dependency scanning** | There are no runtime dependencies, which removes supply-chain risk almost entirely, but `npm audit` should still be run if any are ever added. |
| **Demo credentials are weak** | `admin / admin123` exists so the project can be demonstrated in one click. **Change them before deploying anywhere real** — the Security Centre's password-change flow enforces the policy for you. |
| **No WAF / DDoS layer** | Application-level limits stop abuse from a single host. A volumetric flood from a botnet needs upstream filtering. |

---

## 6. Before deploying for real

1. Serve over HTTPS behind a reverse proxy.
2. Change both demo passwords.
3. Set `CNX_PEPPER` and `CNX_DATA_KEY` from a secret manager rather than relying on the local files.
4. Replace the in-memory session store with Redis if running more than one process.
5. Add TOTP MFA for admin accounts.
6. Move the ledger seal to append-only or independently replicated storage.
7. Add real structured logging with rotation to a SIEM.
8. Run `npm run build` and serve `public/dist/` so SRI is active in production.

---

MIT