-- ============================================================================
--  CAMPUS NEXUS  ·  relational schema (SQLite)
--  Library  +  Store/Billing  +  Arcade  in one database.
--  All timestamps are stored as ISO-ish SQLite strings ('YYYY-MM-DD HH:MM:SS').
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- IDENTITY --
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  username    TEXT    NOT NULL UNIQUE,
  pass_hash   TEXT    NOT NULL,
  pass_salt   TEXT    NOT NULL,
  full_name   TEXT    NOT NULL,
  role        TEXT    NOT NULL DEFAULT 'staff',   -- admin | staff
  active      INTEGER NOT NULL DEFAULT 1,
  -- security posture -------------------------------------------------
  failed_logins   INTEGER NOT NULL DEFAULT 0,
  locked_until    TEXT,
  last_login_at   TEXT,
  last_login_ip   TEXT,
  must_change_pw  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ----------------------------------------------------------------- LIBRARY --
CREATE TABLE IF NOT EXISTS books (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  isbn             TEXT    UNIQUE,
  title            TEXT    NOT NULL,
  author           TEXT    NOT NULL,
  publisher        TEXT,
  category         TEXT    NOT NULL DEFAULT 'General',
  edition          TEXT,
  year             INTEGER,
  copies_total     INTEGER NOT NULL DEFAULT 1  CHECK (copies_total  >= 0),
  copies_available INTEGER NOT NULL DEFAULT 1  CHECK (copies_available >= 0),
  shelf            TEXT,
  notes            TEXT,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_books_title ON books(title);
CREATE INDEX IF NOT EXISTS idx_books_cat   ON books(category);

CREATE TABLE IF NOT EXISTS loans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  book_id       INTEGER NOT NULL REFERENCES books(id) ON DELETE CASCADE,
  borrower      TEXT    NOT NULL,
  roll_no       TEXT,
  contact       TEXT,          -- AES-256-GCM encrypted at rest (see fieldcrypto.js)
  issue_date    TEXT    NOT NULL DEFAULT (date('now','localtime')),
  due_date      TEXT    NOT NULL,
  returned_date TEXT,
  fine          REAL    NOT NULL DEFAULT 0,
  status        TEXT    NOT NULL DEFAULT 'issued',   -- issued | returned
  remark        TEXT
);
CREATE INDEX IF NOT EXISTS idx_loans_status ON loans(status);
CREATE INDEX IF NOT EXISTS idx_loans_book   ON loans(book_id);

-- ------------------------------------------------------------------- STORE --
CREATE TABLE IF NOT EXISTS products (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  sku           TEXT    UNIQUE,
  name          TEXT    NOT NULL,
  category      TEXT    NOT NULL DEFAULT 'General',
  price         REAL    NOT NULL CHECK (price >= 0),
  stock         INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
  reorder_level INTEGER NOT NULL DEFAULT 5,
  supplier      TEXT,
  description   TEXT,
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_prod_name ON products(name);
CREATE INDEX IF NOT EXISTS idx_prod_cat  ON products(category);

CREATE TABLE IF NOT EXISTS bills (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  bill_no   TEXT    NOT NULL UNIQUE,
  customer  TEXT    NOT NULL,
  phone     TEXT,          -- AES-256-GCM encrypted at rest (see fieldcrypto.js)
  phone_idx TEXT,          -- deterministic HMAC blind index, for exact lookup only
  payment   TEXT    NOT NULL DEFAULT 'Cash',  -- Cash | Card | UPI
  subtotal  REAL    NOT NULL,
  discount  REAL    NOT NULL DEFAULT 0,
  tax       REAL    NOT NULL DEFAULT 0,
  total     REAL    NOT NULL,
  created_at TEXT   NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_bills_no  ON bills(bill_no);
CREATE INDEX IF NOT EXISTS idx_bills_date ON bills(created_at);
CREATE INDEX IF NOT EXISTS idx_bills_phone ON bills(phone_idx);

CREATE TABLE IF NOT EXISTS bill_items (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  bill_id    INTEGER NOT NULL REFERENCES bills(id) ON DELETE CASCADE,
  product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
  name       TEXT    NOT NULL,
  qty        INTEGER NOT NULL,
  rate       REAL    NOT NULL,
  amount     REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_bill ON bill_items(bill_id);

-- ------------------------------------------------------------------ ARCADE --
CREATE TABLE IF NOT EXISTS game_scores (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  game      TEXT    NOT NULL,                 -- guess | swg
  player    TEXT    NOT NULL,
  score     INTEGER NOT NULL,
  detail    TEXT,
  played_at TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_scores_game ON game_scores(game, score DESC);

-- ---------------------------------------------------------------- AUDIT ----
CREATE TABLE IF NOT EXISTS activity (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  module     TEXT    NOT NULL,                -- library | store | arcade | system
  action     TEXT    NOT NULL,
  detail     TEXT,
  created_at TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_activity_time ON activity(created_at DESC);

-- =========================================================== SECURITY =====

-- Security events: the human-readable, queryable view of what happened.
CREATE TABLE IF NOT EXISTS security_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  severity   TEXT    NOT NULL CHECK (severity IN ('info','warn','high','critical')),
  event_type TEXT    NOT NULL,
  module     TEXT    NOT NULL DEFAULT 'security',
  detail     TEXT,
  ip         TEXT,
  path       TEXT,
  user_agent TEXT,
  created_at TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_sec_time   ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sec_type   ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_sec_sev    ON security_events(severity);

-- The hash-chained ledger. `index` and `hash` are unique, which is what makes
-- any edit to history immediately visible as a constraint failure or a broken
-- link during verification.
CREATE TABLE IF NOT EXISTS ledger (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  "index"      INTEGER NOT NULL UNIQUE,
  timestamp    TEXT    NOT NULL,
  event_type   TEXT    NOT NULL,
  module       TEXT    NOT NULL DEFAULT 'system',
  actor        TEXT    NOT NULL DEFAULT 'system',
  severity     TEXT    NOT NULL DEFAULT 'info',
  payload      TEXT    NOT NULL DEFAULT '{}',
  payload_hash TEXT    NOT NULL,
  prev_hash    TEXT    NOT NULL,
  merkle_root  TEXT    NOT NULL,
  difficulty   INTEGER NOT NULL DEFAULT 2,
  nonce        INTEGER NOT NULL DEFAULT 0,
  hash         TEXT    NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_ledger_sev ON ledger(severity);

-- Per-account failed-login counters drive the progressive lockout.
CREATE TABLE IF NOT EXISTS login_failures (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT    NOT NULL UNIQUE,   -- UNIQUE so the upsert has a target
  ip           TEXT,
  count        INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  last_attempt TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_fail_locked ON login_failures(locked_until);

-- Previous password hashes, so the last N cannot be reused.
CREATE TABLE IF NOT EXISTS password_history (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pass_hash  TEXT    NOT NULL,
  created_at TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_pwhash_user ON password_history(user_id);