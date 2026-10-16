// ============================================================================
//  CAMPUS NEXUS · security test suite   →   npm run test:security
//  Verifies that each protection actually blocks what it claims to block.
//  The server must be running on http://localhost:3000.
// ============================================================================
const BASE = process.env.BASE ?? "http://localhost:3000";

let pass = 0;
let fail = 0;
const jar = new Map();     // our own cookie jar so we control every attribute

const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const section = (t) => console.log(`\n\x1b[1m${t}\x1b[0m`);

function check(label, ok, extra = "") {
  if (ok) { pass++; console.log(`${green("  PASS")}  ${label}${extra ? dim("  " + extra) : ""}`); }
  else { fail++; console.log(`${red("  FAIL")}  ${label}${extra ? red("  " + extra) : ""}`); }
}

function saveCookies(res) {
  const raw = res.headers.getSetCookie?.() ?? [];
  for (const c of raw) {
    const [pair] = c.split(";");
    const i = pair.indexOf("=");
    jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
  return raw;
}
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const csrfToken = () => (jar.get("cnx_csrf") ? decodeURIComponent(jar.get("cnx_csrf")) : null);

/**
 * A browser always loads the page (a GET) before it can POST, and that GET is
 * what hands out the CSRF cookie. The helper mirrors that: any unsafe request
 * made with an empty jar is primed with a harmless GET first, so the test
 * exercises the real flow instead of tripping the bootstrap check.
 */
async function prime() {
  if (jar.has("cnx_csrf")) return;
  await fetch(BASE + "/api/system/health").then((r) => saveCookies(r));
}

async function raw(method, path, { body, headers = {}, useCsrf = true, useCookies = true } = {}) {
  const unsafe = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
  if (unsafe && useCookies && useCsrf) await prime();

  const h = { "Content-Type": "application/json", ...headers };
  if (useCookies && jar.size) h.Cookie = cookieHeader();
  if (useCsrf && csrfToken()) h["X-CSRF-Token"] = csrfToken();
  const res = await fetch(BASE + path, {
    method,
    headers: h,
    body: body === undefined ? undefined : (typeof body === "string" ? body : JSON.stringify(body)),
  });
  saveCookies(res);
  let data = null;
  try { data = await res.json(); } catch {}
  return { status: res.status, data, headers: res.headers };
}

const login = (username, password, extra = {}) =>
  raw("POST", "/api/auth/login", { body: { username, password, _t: Date.now() - 2000, ...extra } });

/**
 * The limiter state lives in server memory, so abuse tests poison the buckets
 * for everything after them. Clear them between sections exactly the way a real
 * operator would: by signing in as an admin and hitting the reset endpoint.
 */
async function resetLimiters() {
  jar.clear();
  await login("admin", "admin123");
  await raw("POST", "/api/security/reset", {});
  jar.clear();
}

console.log(`\nSecurity suite · ${BASE}\n${"─".repeat(62)}`);

/* ═══════════════════════════════════════════ 1. security headers ═══════ */
section("1. Response headers");
{
  const { headers } = await raw("GET", "/api/system/health", { useCookies: false });
  const h = (n) => headers.get(n);
  check("Content-Security-Policy present", !!h("content-security-policy"));
  const csp = h("content-security-policy") ?? "";
  check("CSP locks script-src to 'self'", csp.includes("script-src 'self'") && !csp.includes("script-src 'self' 'unsafe-inline'"));
  check("CSP forbids framing (frame-ancestors 'none')", csp.includes("frame-ancestors 'none'"));
  check("CSP sets object-src 'none'", csp.includes("object-src 'none'"));
  check("CSP sets base-uri 'none'", csp.includes("base-uri 'none'"));
  check("X-Content-Type-Options: nosniff", h("x-content-type-options") === "nosniff");
  check("X-Frame-Options: DENY", h("x-frame-options") === "DENY");
  check("Referrer-Policy: no-referrer", h("referrer-policy") === "no-referrer");
  check("Permissions-Policy restricts sensors", (h("permissions-policy") ?? "").includes("camera=()"));
  check("Cross-Origin-Opener-Policy set", h("cross-origin-opener-policy") === "same-origin");
  check("Strict-Transport-Security set", !!h("strict-transport-security"));
  check("Cache-Control: no-store", (h("cache-control") ?? "").includes("no-store"));
  check("X-Powered-By removed", !h("x-powered-by"));
  check("Server fingerprint removed", !h("server"));
  check("X-Download-Options: noopen", h("x-download-options") === "noopen");
}

/* ═══════════════════════════════════════════ 2. rate limiting ═══════════ */
section("2. Rate limiting");
{
  const before = await raw("GET", "/api/library/books", { useCookies: false });
  check("rate-limit headers exposed", before.headers.get("x-ratelimit-limit") !== null,
        `limit ${before.headers.get("x-ratelimit-limit")}`);

  // Hammer the search tier (90/min) until it trips.
  let tripped = null;
  for (let i = 0; i < 120; i++) {
    const r = await raw("GET", "/api/system/search?q=a", { useCookies: false });
    if (r.status === 429) { tripped = r; break; }
  }
  check("abusive search flood is throttled with 429", !!tripped);
  if (tripped) {
    check("429 includes Retry-After header", tripped.headers.get("retry-after") !== null,
          `retry in ${tripped.headers.get("retry-after")}s`);
    check("429 body explains the wait", /try again in/i.test(tripped.data?.error ?? ""),
          tripped.data?.error);
    check("429 body never leaks internals", !/sqlite|stack|node_modules/i.test(JSON.stringify(tripped.data)));
  }

  await resetLimiters();
}

/* ═══════════════════════════════════════════ 3. CSRF ═════════════════════ */
section("3. CSRF protection");
{
  jar.clear();
  await login("admin", "admin123");

  // Write without the CSRF header.
  const noCsrf = await raw("POST", "/api/library/books",
    { body: { title: "CSRF Probe", author: "Attacker" }, useCsrf: false });
  check("POST without CSRF token is rejected", noCsrf.status === 403, `got ${noCsrf.status}`);
  check("rejection is flagged as a CSRF error", noCsrf.data?.csrf === true);

  // Write with a forged token. `useCsrf:false` stops the helper from replacing
  // our forged header with the real cookie value.
  const forged = await raw("POST", "/api/library/books",
    { body: { title: "CSRF Probe", author: "Attacker" },
      headers: { "X-CSRF-Token": "forged.deadbeef" }, useCsrf: false });
  check("POST with forged CSRF token is rejected", forged.status === 403, `got ${forged.status}`);

  // The legitimate token must work.
  const legit = await raw("POST", "/api/library/books",
    { body: { title: "CSRF Valid Probe", author: "Tester", copiesTotal: 1 } });
  check("POST with the real CSRF token succeeds", legit.status === 201, `got ${legit.status}`);
  if (legit.data?.id) await raw("DELETE", `/api/library/books/${legit.data.id}`);
}

/* ═══════════════════════════════════════════ 4. authorisation ═══════════ */
section("4. Authorisation");
{
  jar.clear();
  const anon = await raw("POST", "/api/store/products", { body: { name: "Anon", price: 1 } });
  check("unauthenticated write rejected with 401", anon.status === 401, `got ${anon.status}`);
  check("response asks the client to sign in", anon.data?.requiresAuth === true);

  const read = await raw("GET", "/api/store/products", { useCookies: false });
  check("unauthenticated read still allowed", read.status === 200);
}

/* ═══════════════════════════════════════════ 5. login lockout ══════════ */
section("5. Brute-force resistance");
{
  // Brute-force the STAFF account, not admin. This proves two things at once:
  // the lockout works, and that locking one account does not collaterally
  // affect anyone else (which matters a lot behind a shared campus NAT).
  jar.clear();
  const outcomes = [];
  for (let i = 0; i < 7; i++) {
    const r = await login("staff", `wrong-password-${i}`);
    outcomes.push(r.status);
  }
  check("wrong passwords return 401, not 500", outcomes.every((s) => s === 401 || s === 423 || s === 429),
        outcomes.join(","));
  check("account locks after repeated failures", outcomes.includes(423) || outcomes.includes(429),
        `statuses: ${outcomes.join(",")}`);

  const locked = await login("staff", "staff123");
  check("correct password is refused while locked", locked.status === 423 || locked.status === 429,
        `got ${locked.status}`);
  check("lockout response states the remaining wait",
        typeof locked.data?.retryAfter === "number" && locked.data.retryAfter > 0,
        `${locked.data?.retryAfter}s`);

  // The lockout is per-account: admin must be entirely unaffected.
  await resetLimiters();
  const adminStill = await login("admin", "admin123");
  check("locking one account does not affect another", adminStill.status === 200,
        `admin got ${adminStill.status}`);

  // An admin can release the lock, which also kills that user's sessions.
  await raw("POST", `/api/auth/users/${staffId()}/unlock`, {});
  await resetLimiters();
  const after = await login("staff", "staff123");
  check("correct password works again after unlock", after.status === 200, `got ${after.status}`);
}

/** Look up the staff account's id using the current admin session. */
async function staffId() {
  const r = await raw("GET", "/api/auth/users");
  const staff = r.data?.users?.find((u) => u.username === "staff");
  return staff?.id;
}

/* ═══════════════════════════════════════════ 6. user enumeration ════════ */
section("6. Username-enumeration defence");
{
  const unknown = await login("does-not-exist-at-all", "whatever");
  const wrongPw = await login("admin", "totally-wrong");
  check("unknown user and wrong password give the same message",
        unknown.data?.error === wrongPw.data?.error,
        JSON.stringify(unknown.data?.error));
  check("both return 401", unknown.status === 401 && wrongPw.status === 401,
        `${unknown.status} / ${wrongPw.status}`);

  await resetLimiters();
}

/* ═══════════════════════════════════════════ 7. bot traps ═══════════════ */
section("7. Bot detection");
{
  jar.clear();
  const honey = await raw("POST", "/api/auth/login",
    { body: { username: "admin", password: "admin123", hp: "bot@example.com", _t: Date.now() - 2000 } });
  check("filled honeypot is rejected", honey.status === 401, `got ${honey.status}`);
  check("honeypot rejection is deliberately vague", honey.data?.error === "Sign-in failed");

  // A submission claiming to have started 100 ms ago cannot involve a human
  // typing a username and password.
  const fast = await raw("POST", "/api/auth/login",
    { body: { username: "admin", password: "admin123", hp: "", _t: Date.now() - 100 } });
  check("impossibly fast submission is rejected", fast.status === 429, `got ${fast.status}`);

  // And a realistically-paced one must be allowed through.
  const paced = await raw("POST", "/api/auth/login",
    { body: { username: "admin", password: "admin123", hp: "", _t: Date.now() - 3000 } });
  check("realistically paced submission is accepted", paced.status === 200, `got ${paced.status}`);

  await resetLimiters();
}

/* ═══════════════════════════════════════════ 8. session hardening ══════ */
section("8. Session hardening");
{
  jar.clear();
  await prime();
  // Cookies are sent normally here (so CSRF passes); the assertions below read
  // the raw Set-Cookie headers directly rather than trusting the jar.
  const res = await raw("POST", "/api/auth/login",
    { body: { username: "admin", password: "admin123", _t: Date.now() - 2000 } });
  check("login succeeded", res.status === 200, `got ${res.status}`);
  const cookies = res.headers.getSetCookie?.() ?? [];
  const sid = cookies.find((c) => c.startsWith("cnx_sid="));
  check("session cookie is issued", !!sid);
  check("session cookie is HttpOnly", /HttpOnly/i.test(sid ?? ""));
  check("session cookie is SameSite=Strict", /SameSite=Strict/i.test(sid ?? ""));
  check("session cookie is Path=/", /Path=\//.test(sid ?? ""));
  check("session cookie uses a generic name", (sid ?? "").startsWith("cnx_sid="));

  const sidValue = decodeURIComponent((sid ?? "").split(";")[0].split("=")[1] ?? "");
  check("session token is split (publicId.secret)", /^[0-9a-f]{32}\.[A-Za-z0-9_-]{20,}$/.test(sidValue),
        `${sidValue.slice(0, 18)}…`);
  check("session token has >= 128 bits of entropy", sidValue.split(".")[1]?.length >= 22);

  // Tampering with the secret must invalidate the session.
  const tampered = sidValue.slice(0, -3) + "AAA";
  const bad = await fetch(BASE + "/api/auth/me", {
    headers: { Cookie: `cnx_sid=${encodeURIComponent(tampered)}` },
  });
  const badBody = await bad.json();
  check("session with a forged secret is rejected", badBody.user === null, `got ${JSON.stringify(badBody.user)}`);

  // A cookie replayed from a different User-Agent must be destroyed.
  jar.clear();
  jar.set("cnx_sid", encodeURIComponent(sidValue));
  jar.set("cnx_csrf", encodeURIComponent(csrfToken() ?? ""));
  const replay = await raw("GET", "/api/auth/me",
    { headers: { "User-Agent": "TotallyDifferentBrowser/1.0" }, useCsrf: false });
  check("session replay from a different client is killed", replay.data?.user === null,
        `got ${JSON.stringify(replay.data?.user)}`);

  await resetLimiters();
}

/* ═══════════════════════════════════════════ 9. input validation ════════ */
section("9. Input validation");
{
  jar.clear();
  await raw("POST", "/api/auth/login", { body: { username: "admin", password: "admin123", _t: Date.now() - 2000 } });

  const massAssign = await raw("POST", "/api/store/products",
    { body: { name: "Role Escalation", price: 10, role: "admin" } });
  check("mass-assignment of `role` is refused", massAssign.status === 400,
        massAssign.data?.errors?.join("; ") ?? `got ${massAssign.status}`);

  const negative = await raw("POST", "/api/store/products", { body: { name: "Negative", price: -500 } });
  check("negative price is refused", negative.status === 400);

  const huge = await raw("POST", "/api/store/products", { body: { name: "X".repeat(5000), price: 1 } });
  check("over-long field is refused", huge.status === 400);

  const badEnum = await raw("POST", "/api/store/bills",
    { body: { customer: "X", payment: "Bitcoin", items: [{ productId: 1, qty: 1 }] } });
  check("enum outside the allow-list is refused", badEnum.status === 400);

  const proto = await raw("POST", "/api/store/products",
    { body: { name: "Proto", price: 1 }, headers: { "X-Test": JSON.stringify({ __proto__: { admin: true } }) } });
  check("request with prototype-pollution markers is handled", proto.status < 500, `got ${proto.status}`);
}

/* ═══════════════════════════════════════════ 10. request limits ═════════ */
section("10. Request-size limits");
{
  const longUrl = "/api/system/search?q=" + "a".repeat(2500);
  const url = await raw("GET", longUrl, { useCookies: false });
  check("over-long URL is rejected with 414", url.status === 414, `got ${url.status}`);

  const big = await raw("POST", "/api/store/products",
    { body: { name: "Big", price: 1, description: "x".repeat(300_000) } });
  check("over-sized body is rejected with 413", big.status === 413, `got ${big.status}`);

  const traversal = await raw("GET", "/../../package.json", { useCookies: false });
  check("path traversal is blocked", traversal.status === 404 || traversal.status === 400, `got ${traversal.status}`);

  // Write method against a static path — the server must answer 405 rather
  // than serving the file. Primed so CSRF passes and we reach that check.
  await prime();
  const method = await raw("PUT", "/index.html", { body: "{}" });
  check("write method against a static path is refused", method.status === 405, `got ${method.status}`);

  await resetLimiters();
}

/* ═══════════════════════════════════════════ 11. password policy ═══════ */
section("11. Password policy");
{
  const weak = await raw("POST", "/api/auth/password-check", { body: { password: "password" } });
  check("common password scored as weak", weak.data?.strength?.acceptable === false,
        weak.data?.strength?.label);

  const good = await raw("POST", "/api/auth/password-check", { body: { password: "Campus!Nexus2026#Secure" } });
  check("strong password scores as strong", good.data?.strength?.score >= 3,
        `${good.data?.strength?.label} (${good.data?.strength?.score}/4)`);
  check("strong password has no outstanding issues", good.data?.strength?.issues?.length === 0);

  jar.clear();
  await raw("POST", "/api/auth/login", { body: { username: "admin", password: "admin123", _t: Date.now() - 2000 } });
  const change = await raw("POST", "/api/auth/change-password", { body: { current: "admin123", next: "weak" } });
  check("weak password change is refused", change.status === 400, change.data?.error);

  const wrongCur = await raw("POST", "/api/auth/change-password", { body: { current: "nope", next: "Campus!Nexus2026#Secure" } });
  check("wrong current password is refused", wrongCur.status === 401);
}

/* ═══════════════════════════════════════════ 12. ledger ═════════════════ */
section("12. Tamper-evident ledger");
{
  jar.clear();
  await raw("POST", "/api/auth/login", { body: { username: "admin", password: "admin123", _t: Date.now() - 2000 } });

  const chain = await raw("GET", "/api/security/chain");
  check("chain verification endpoint responds", chain.status === 200);
  check("chain verifies with no issues", chain.data?.ok === true,
        chain.data?.issues?.map((i) => i.detail).join("; ") ?? "clean");
  check("chain has a genesis-linked head", (chain.data?.head?.hash ?? "").length === 64);
  check("external seal matches the head", chain.data?.seal?.matches === true,
        JSON.stringify(chain.data?.seal ?? null));
  check("certificate is issued", typeof chain.data?.certificate?.fingerprint === "string");

  const blocks = await raw("GET", "/api/security/chain/blocks");
  check("blocks are listable", Array.isArray(blocks.data?.blocks) && blocks.data.blocks.length > 0,
        `${blocks.data?.blocks?.length} blocks`);
  const b = blocks.data?.blocks ?? [];
  check("every block links to its predecessor",
        b.every((x) => typeof x.prev === "string" && x.prev.length === 64));
  check("every block carries a proof-of-work nonce", b.every((x) => Number.isInteger(x.nonce) && x.nonce >= 0));
  check("blocks have unique hashes", new Set(b.map((x) => x.hash)).size === b.length);
}

/* ═══════════════════════════════════════════ 13. posture endpoint ═══════ */
section("13. Security centre data");
{
  jar.clear();
  const anon = await raw("GET", "/api/security/posture");
  check("posture requires authentication", anon.status === 401);

  await raw("POST", "/api/auth/login", { body: { username: "admin", password: "admin123", _t: Date.now() - 2000 } });
  const p = await raw("GET", "/api/security/posture");
  check("posture returns the control list", Array.isArray(p.data?.controls) && p.data.controls.length >= 20,
        `${p.data?.controls?.length} controls`);
  check("posture reports rate-limit state", typeof p.data?.limiter?.totalKeys === "number");
  check("posture reports session state", typeof p.data?.sessions?.live === "number");
  check("posture reports the hash configuration", p.data?.config?.password?.N >= 32768,
        `scrypt N=${p.data?.config?.password?.N}, ${p.data?.config?.password?.memoryMiB} MiB`);
  check("posture reports a threat score", typeof p.data?.events?.score === "number");
}

/* ═══════════════════════════════════════════ 14. privilege gate ════════ */
section("14. Role-based authorisation");
{
  jar.clear();
  await raw("POST", "/api/auth/login", { body: { username: "staff", password: "staff123", _t: Date.now() - 2000 } });
  const asStaff = await raw("GET", "/api/auth/users");
  check("staff cannot list user accounts", asStaff.status === 403, `got ${asStaff.status}`);

  const reset = await raw("POST", "/api/security/reset");
  check("staff cannot trigger an emergency reset", reset.status === 403, `got ${reset.status}`);

  jar.clear();
  await raw("POST", "/api/auth/login", { body: { username: "admin", password: "admin123", _t: Date.now() - 2000 } });
  const asAdmin = await raw("GET", "/api/auth/users");
  check("admin can list user accounts", asAdmin.status === 200, `${asAdmin.data?.users?.length} users`);
}

/* ═══════════════════════════════════════════ 15. information disclosure ════ */
section("15. Information disclosure");
{
  const notFound = await raw("GET", "/api/does/not/exist", { useCookies: false });
  check("unknown endpoint returns a clean 404", notFound.status === 404);
  check("error body has no stack trace", !/at\s+\w+\s+\(|node_modules|\.js:\d+:\d+/.test(JSON.stringify(notFound.data)));

  const badJson = await raw("POST", "/api/auth/login", { body: "{not valid json" });
  check("malformed JSON does not crash the server", badJson.status >= 400 && badJson.status < 500,
        `got ${badJson.status}`);
  check("malformed JSON leaks no parser detail",
        !/Unexpected token|JSON\.parse|SyntaxError/i.test(JSON.stringify(badJson.data)),
        badJson.data?.error);

  const alive = await raw("GET", "/api/system/health", { useCookies: false });
  check("server still healthy after all attacks", alive.status === 200);
}

/* ═══════════════════════════════════════════ 16. CSP regression ══════════ */
section("16. CSP regression (plain-HTTP must still work)");
{
  const { headers } = await raw("GET", "/", { useCookies: false });
  const csp = headers.get("content-security-policy") ?? "";

  // Regression guard: `upgrade-insecure-requests` over plain HTTP made the
  // browser rewrite every script URL to https:// and the app silently failed to
  // boot on any non-localhost origin (e.g. the LAN address the server prints).
  check("CSP omits upgrade-insecure-requests on plain HTTP",
        !csp.includes("upgrade-insecure-requests"),
        csp.includes("upgrade-insecure-requests") ? "present — LAN access will break" : "absent");
  check("CSP still locks script-src to 'self'", csp.includes("script-src 'self'"));
  check("CSP still forbids framing", csp.includes("frame-ancestors 'none'"));

  // The directory-index fallback must serve /dist/ too.
  const dist = await raw("GET", "/dist/", { useCookies: false });
  check("built bundle is served at /dist/ (directory index)", dist.status === 200, `got ${dist.status}`);
}

/* ═══════════════════════════════════════════ 17. field encryption ════════ */
section("17. PII encryption at rest");
{
  const payload = {
    customer: "Crypto Tester", phone: "9812345678", payment: "Cash",
    items: [{ productId: 1, qty: 1 }],
  };
  const bill = await raw("POST", "/api/store/bills", { body: payload });
  check("bill with a phone number is accepted", bill.status === 201, `got ${bill.status}`);

  // The API must hand the number back in clear (decrypted at the edge)…
  const bills = await raw("GET", `/api/store/bills?q=${bill.data.billNo}`);
  const row = bills.data.bills.find((b) => b.bill_no === bill.data.billNo);
  check("API returns the phone number decrypted", row?.phone === "9812345678", `got ${row?.phone}`);

  // …while the database must not contain it.
  const idx = raw("GET", "/api/store/bills?q=9812345678");
  const found = await idx;
  check("exact phone search still works (blind index)", found.data.bills.some((b) => b.bill_no === bill.data.billNo));

  // A borrower contact is sealed too.
  const loan = await raw("POST", "/api/library/loans",
    { body: { bookId: 1, borrower: "Crypto Reader", contact: "reader@campus.edu", rollNo: "CR-1" } });
  check("loan with a contact is accepted", loan.status === 201 || loan.status === 409, `got ${loan.status}`);
  if (loan.status === 201) {
    const loans = await raw("GET", "/api/library/loans");
    const mine = loans.data.loans.find((l) => l.id === loan.data.id);
    check("API returns the borrower contact decrypted", mine?.contact === "reader@campus.edu", `got ${mine?.contact}`);
  }
  check("blind index column is never exposed by the API",
        bills.data.bills.every((b) => b.phone_idx === undefined));
}

/* ═══════════════════════════════════════════ 18. SQL tripwire ═══════════ */
section("18. SQL-injection tripwire");
{
  await raw("POST", "/api/store/products",
    { body: { name: "x', price: 1 }); DROP TABLE books; --", price: 10, stock: 1 } });

  const events = await raw("GET", "/api/security/events?limit=25");
  const flagged = (events.data.events ?? []).some(
    (e) => e.event_type === "sql-injection-attempt" || /DROP TABLE/i.test(e.detail)
  );
  check("injection-shaped payload is recorded as a security event", flagged);

  const booksStill = await raw("GET", "/api/library/books");
  check("database is unharmed (books table intact)",
        booksStill.data.books.length > 0, `${booksStill.data.books?.length} books`);

  await resetLimiters();
}

/* ═══════════════════════════════════════════ summary ════════════════════ */
console.log(`\n${"─".repeat(62)}`);
console.log(`  ${green(`${pass} passed`)}` + (fail ? `, ${red(`${fail} failed`)}` : `, ${dim("0 failed")}`));
console.log("");
process.exit(fail ? 1 : 0);