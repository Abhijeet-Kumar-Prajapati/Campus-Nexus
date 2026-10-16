// ============================================================================
//  CAMPUS NEXUS · security configuration
//  Every tunable lives here so the whole posture can be reviewed in one file.
//  Sources: OWASP Session Management, Password Storage, CSRF and HTTP Headers
//  cheat sheets; NIST SP 800-63B for password length guidance.
// ============================================================================

export const CONFIG = {
  /* ------------------------------------------------------ rate limiting -- */
  // Sliding-window buckets, applied per (IP × tier). The tiers exist so that a
  // flood of harmless reads can never be used to exhaust the login budget.
  limits: {
    global:    { windowMs: 60_000, max: 600,  name: "global" },
    // Deliberately not tiny: a campus has hundreds of students behind a single
    // NAT address, so an aggressive per-IP sign-in limit would lock out an
    // entire building. The real brute-force defence is the per-ACCOUNT lockout
    // (config.account below), which is precise and cannot be collateral damage.
    auth:      { windowMs: 10 * 60_000, max: 40, name: "authentication" },
    write:     { windowMs: 60_000, max: 60,  name: "write" },
    read:      { windowMs: 60_000, max: 400, name: "read" },
    search:    { windowMs: 60_000, max: 90,  name: "search" },
  },

  // Every time a bucket trips, its window grows (capped). Repeat offenders
  // therefore get exponentially longer lockouts instead of a free retry.
  backoff: {
    multiplier: 2,
    maxWindowMs: 30 * 60_000,
    tripsPerWindow: 4,
  },

  /* --------------------------------------------------------- sessions ---- */
  session: {
    // OWASP: >= 64 bits of entropy required. We use 256 bits from the CSPRNG.
    tokenBytes: 32,
    idleTimeoutMs: 30 * 60_000,        // sign out after 30 min of inactivity
    absoluteTimeoutMs: 8 * 60 * 60_000, // hard ceiling regardless of activity
    renewalIntervalMs: 15 * 60_000,    // rotate the token at least this often
    // Bind the session to the client fingerprint so a stolen cookie replayed
    // from a different browser/IP is rejected.
    bindToFingerprint: true,
    cookieName: "cnx_sid",
    csrfCookieName: "cnx_csrf",
    cookiePath: "/",
    sameSite: "Strict",
    // Set `Secure` automatically when served over HTTPS.
    secureWhenTls: true,
    maxConcurrentPerUser: 5,
  },

  /* -------------------------------------------------------- passwords ---- */
  password: {
    // scrypt parameters from the OWASP table: N=2^16, r=8, p=2 (64 MiB).
    scrypt: { N: 65536, r: 8, p: 2, keylen: 64 },
    saltBytes: 16,
    // NIST SP 800-63B: 15+ characters if MFA is absent. We allow 12 minimum for
    // usability on a demo but strongly score anything under 15 as "weak".
    minLength: 12,
    recommendedLength: 15,
    maxLength: 256,
    requireUpper: true,
    requireLower: true,
    requireDigit: true,
    requireSymbol: true,
    // Small denylist — the passwords that show up first in any cracking list.
    common: [
      "password", "12345678", "123456789", "qwerty123", "letmein",
      "welcome1", "admin123", "campus123", "student123", "password1",
      "iloveyou", "abc12345", "11111111", "1234567890", "administrator",
    ],
  },

  /* ------------------------------------------------------------- CSRF ---- */
  csrf: {
    headerName: "x-csrf-token",
    tokenBytes: 32,
    methods: ["POST", "PUT", "PATCH", "DELETE"],
  },

  /* ----------------------------------------------------- request limits -- */
  request: {
    maxBodyBytes: 256 * 1024,   // 256 KiB
    maxUrlLength: 2048,
    maxHeaderCount: 100,
    // Fields we never accept from a client, even if the schema allows extras.
    forbiddenKeys: [
      "__proto__", "constructor", "prototype",
      "role", "pass_hash", "pass_salt", "id", "created_at", "active",
    ],
  },

  /* ---------------------------------------------------------- headers ---- */
  headers: {
    // `style-src` allows inline styles because the UI builds its layout with
    // style attributes; scripts stay locked to 'self' with no inline escape.
    csp: [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "manifest-src 'self'",
      "worker-src 'self'",
      "upgrade-insecure-requests",
    ].join("; "),
    hsts: "max-age=31536000; includeSubDomains; preload",
    referrerPolicy: "no-referrer",
    permissionsPolicy:
      "accelerometer=(), autoplay=(), camera=(), display-capture=(), " +
      "encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), " +
      "magnetometer=(), microphone=(), midi=(), payment=(), usb=()",
    crossOriginOpenerPolicy: "same-origin",
    crossOriginResourcePolicy: "same-origin",
    crossOriginEmbedderPolicy: "require-corp",
    frameOptions: "DENY",
  },

  /* ---------------------------------------------------------- ledger ---- */
  // Tamper-evident append-only audit chain ("blockchain" in the hash-chain
  // sense — see SECURITY.md for exactly what this does and does not provide).
  ledger: {
    difficulty: 2,          // leading hex zeros required in the proof of work
    maxDifficulty: 5,
    // Re-verify the whole chain this often.
    verifyEveryBlocks: 25,
    sealFile: "SECURITY/chain-seal.json",
    difficultyRamp: 0.02,    // +1 difficulty per 50 blocks mined
    difficultyRampBlocks: 50,
  },

  /* ------------------------------------------------- account protection -- */
  account: {
    maxFailedLogins: 5,
    // Each extra failure multiplies the lockout: 1m, 2m, 4m, 8m … capped.
    lockoutBaseMs: 60_000,
    lockoutMaxMs: 60 * 60_000,
    passwordHistory: 3,     // the last N passwords cannot be reused
    sessionRevokeOnPasswordChange: true,
  },
};

/** Severity levels used across the audit trail and the ledger. */
export const SEVERITY = {
  info:  { rank: 0, colour: "info" },
  warn:  { rank: 1, colour: "warn" },
  high:  { rank: 2, colour: "danger" },
  critical: { rank: 3, colour: "danger" },
};