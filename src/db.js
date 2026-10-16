// ============================================================================
//  CAMPUS NEXUS  ·  database layer
//  Uses Node's built-in `node:sqlite` (no native modules, no MySQL server).
// ============================================================================
import { DatabaseSync } from "node:sqlite";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { hashPassword } from "./security/crypto.js";
import { buildBlock, writeSeal } from "./security/ledger.js";
import { encryptField, blindIndex } from "./security/fieldcrypto.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const DATA_DIR = join(__dirname, "..", "data");
export const DB_PATH = join(DATA_DIR, "campus-nexus.db");

/* ------------------------------------------------------------------ open --- */
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

export const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");
db.exec(readFileSync(join(__dirname, "schema.sql"), "utf8"));

/* ----------------------------------------------------------- audit trail --- */
export function logActivity(module, action, detail = "") {
  db.prepare(
    "INSERT INTO activity (module, action, detail) VALUES (?, ?, ?)"
  ).run(module, action, detail);
}

/* -------------------------------------------------------- seed on first run- */
const { c: userCount } = db.prepare("SELECT COUNT(*) c FROM users").get();
if (userCount === 0) seed();
else ensureGenesisBlock();

/**
 * The ledger must always start with a genesis block, even when the app is
 * upgraded onto an existing database. Seeding it here keeps the very first
 * audit event tamper-evident too.
 */
function ensureGenesisBlock() {
  const { n } = db.prepare(`SELECT COUNT(*) n FROM ledger`).get();
  if (n > 0) return;
  const block = buildBlock(
    { head: () => ({ index: -1, hash: "0".repeat(64) }), all: () => [] },
    {
      event_type: "genesis", module: "system", actor: "system", severity: "info",
      payload: { note: "Campus Nexus ledger initialised", version: 1 },
    }
  );
  db.prepare(
    `INSERT INTO ledger ("index", timestamp, event_type, module, actor, severity,
       payload, payload_hash, prev_hash, merkle_root, difficulty, nonce, hash)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run(
    block.index, block.timestamp, block.event_type, block.module, block.actor,
    block.severity, JSON.stringify({ note: "genesis" }), block.payload_hash,
    block.prev_hash, block.merkle_root, block.difficulty, block.nonce, block.hash
  );
  writeSeal(block.hash, block.index + 1);
}

function seed() {
  const seedUser = db.prepare(
    `INSERT INTO users (username, pass_hash, pass_salt, full_name, role)
     VALUES (?, ?, ?, ?, ?)`
  );
  seedUser.run("admin", ...pw("admin123"), "Abhijeet Kumar Prajapati", "admin");
  seedUser.run("staff", ...pw("staff123"), "Counter Staff", "staff");

  // ---------------------------------------------------------------- library --
  const insBook = db.prepare(
    `INSERT INTO books (isbn, title, author, publisher, category, edition, year,
                        copies_total, copies_available, shelf)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const books = [
    ["9780132350884", "Clean Code", "Robert C. Martin", "Prentice Hall", "Computing", "1st", 2008, 6, 6, "CS-A1"],
    ["9780134685991", "Effective Java", "Joshua Bloch", "Addison-Wesley", "Computing", "3rd", 2018, 4, 3, "CS-A2"],
    ["9780262033848", "Introduction to Algorithms", "Cormen, Leiserson, Rivest, Stein", "MIT Press", "Computing", "3rd", 2009, 3, 3, "CS-A3"],
    ["9780321125217", "Domain-Driven Design", "Eric Evans", "Addison-Wesley", "Computing", "1st", 2003, 2, 2, "CS-A4"],
    ["9780596807748", "JavaScript: The Good Parts", "Douglas Crockford", "O'Reilly", "Computing", "1st", 2008, 3, 1, "CS-A5"],
    ["9781491950357", "Building Microservices", "Sam Newman", "O'Reilly", "Computing", "2nd", 2021, 2, 2, "CS-B1"],
    ["9780131103627", "The C Programming Language", "Kernighan & Ritchie", "Prentice Hall", "Computing", "2nd", 1988, 5, 4, "CS-B2"],
    ["9780134610993", "Artificial Intelligence: A Modern Approach", "Russell & Norvig", "Pearson", "AI/ML", "4th", 2020, 3, 2, "CS-C1"],
    ["9781098125967", "Hands-On Machine Learning", "Aurélien Géron", "O'Reilly", "AI/ML", "2nd", 2019, 2, 2, "CS-C2"],
    ["9781118063330", "Operating System Concepts", "Silberschatz et al.", "Wiley", "Systems", "9th", 2012, 4, 4, "CS-D1"],
    ["9780201633610", "Design Patterns", "Gamma, Helm, Johnson, Vissides", "Addison-Wesley", "Computing", "1st", 1994, 3, 3, "CS-D2"],
    ["9780134757599", "Refactoring", "Martin Fowler", "Addison-Wesley", "Computing", "2nd", 2018, 3, 3, "CS-E3"],
    ["9780135957059", "The Pragmatic Programmer", "Hunt & Thomas", "Addison-Wesley", "Computing", "2nd", 2019, 3, 3, "GE-A2"],
    ["9780132126953", "Computer Networks", "Andrew S. Tanenbaum", "Pearson", "Systems", "5th", 2003, 5, 5, "CS-E1"],
    ["9780321127426", "Patterns of Enterprise Application Architecture", "Fowler", "Addison-Wesley", "Systems", "1st", 2002, 2, 1, "CS-E2"],
    ["9788120970006", "Concepts of Physics", "H. C. Verma", "Bharati Bhawan", "Physics", "1st", 1992, 8, 7, "PH-A1"],
    ["9788122436525", "Problems in General Physics", "I. E. Irodov", "CBS", "Physics", "1st", 1981, 4, 4, "PH-A2"],
    ["9780735211292", "Atomic Habits", "James Clear", "Avery", "Self Growth", "1st", 2018, 7, 6, "GE-A1"],
    ["9788129113488", "A Short History of Nearly Everything", "Bill Bryson", "Doubleday", "General", "1st", 2003, 6, 6, "GE-A3"],
    ["9780201835953", "The Mythical Man-Month", "Frederick P. Brooks Jr.", "Addison-Wesley", "Management", "1st", 1995, 2, 2, "MB-A1"],
  ];
  for (const b of books) insBook.run(...b);

  const insLoan = db.prepare(
    `INSERT INTO loans (book_id, borrower, roll_no, contact, issue_date, due_date, fine, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const loans = [
    [1, "Aarav Sharma", "21CS1042", "aarav@campus.edu", dateOffset(-6), dateOffset(9), 0, "issued"],
    [2, "Diya Patel", "21CS1107", "diya@campus.edu", dateOffset(-14), dateOffset(-1), 13, "issued"],
    [4, "Ishaan Verma", "22EE0031", "ishaan@campus.edu", dateOffset(-3), dateOffset(12), 0, "issued"],
    [6, "Kavya Nair", "23ME2011", "kavya@campus.edu", dateOffset(-2), dateOffset(13), 0, "issued"],
    [8, "Rohan Gupta", "21CS1077", "rohan@campus.edu", dateOffset(-1), dateOffset(14), 0, "issued"],
    [9, "Ananya Rao", "22BT0028", "ananya@campus.edu", dateOffset(-30), dateOffset(-17), 26, "issued"],
    [10, "Kabir Singh", "23EC1005", "kabir@campus.edu", dateOffset(-20), dateOffset(-7), 0, "returned"],
    [3, "Meera Joshi", "21BA1044", "meera@campus.edu", dateOffset(-40), dateOffset(-27), 0, "returned"],
  ];
  // Contact details are PII — seal them exactly as the routes do, so the demo
  // database is no less protected than a live one.
  for (const l of loans) {
    const [bookId, borrower, roll, contact, ...rest] = l;
    insLoan.run(bookId, borrower, roll, encryptField(contact), ...rest);
  }

  // ----------------------------------------------------------------- store --
  const insProd = db.prepare(
    `INSERT INTO products (sku, name, category, price, stock, reorder_level, supplier, description)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const products = [
    ["CN-1001", "Campus Notebook A4 (200 pg)", "Stationery", 149.0, 240, 40, "Bright Foods & Co", "Ruled, 80 GSM, spiral bound."],
    ["CN-1002", "Gel Pen Pack (Blue × 10)", "Stationery", 120.0, 180, 30, "Bright Foods & Co", "0.5 mm tip, smooth flow."],
    ["CN-1003", "Exam Safe Pencil Box", "Stationery", 89.0, 95, 25, "Bright Foods & Co", "Transparent body, 3 compartments."],
    ["CN-1004", "Geometry Box with Compass", "Stationery", 165.0, 60, 20, "Bright Foods & Co", "Includes scale, protractor, divider."],
    ["EL-2001", "USB-C Cable 1m", "Electronics", 349.0, 75, 20, "Techline Distributors", "Braided, 60W fast charge."],
    ["EL-2002", "Wireless Mouse", "Electronics", 649.0, 42, 15, "Techline Distributors", "2.4 GHz, 1200 DPI."],
    ["EL-2003", "Laptop Stand (Aluminium)", "Electronics", 1299.0, 18, 8, "Techline Distributors", "Adjustable height, foldable."],
    ["EL-2004", "USB Hub 4-Port", "Electronics", 899.0, 9, 10, "Techline Distributors", "Powered, Type-C."],
    ["EL-2005", "Bluetooth Earbuds", "Electronics", 1899.0, 26, 10, "Techline Distributors", "ANC, 30 h playback."],
    ["EL-2006", "Webcam 1080p", "Electronics", 2299.0, 0, 5, "Techline Distributors", "Auto light correction."],
    ["MF-3001", "Cotton T-Shirt (College Logo)", "Merch", 499.0, 120, 25, "Nexus Apparel", "Sizes S–XXL, unisex fit."],
    ["MF-3002", "Hoodie - Department Print", "Merch", 1299.0, 54, 15, "Nexus Apparel", "80% cotton, kangaroo pocket."],
    ["MF-3003", "Library Week Mug", "Merch", 299.0, 88, 20, "Nexus Apparel", "Ceramic, 350 ml."],
    ["MF-3004", "CAMPUS NEXUS Hoodie", "Merch", 1599.0, 7, 10, "Nexus Apparel", "Limited edition."],
    ["FD-4001", "Chocolates (Assorted Box)", "Food", 449.0, 70, 20, "Campus Café", "20 pieces."],
    ["FD-4002", "Cold Coffee 250 ml", "Food", 99.0, 210, 60, "Campus Café", "Chilled."],
    ["FD-4003", "Veg Puff Box (4 pcs)", "Food", 60.0, 150, 40, "Campus Café", "Freshly baked hourly."],
    ["FD-4004", "Filter Coffee Cup", "Food", 45.0, 45, 15, "Campus Café", "South Indian style."],
    ["SP-5001", "Badminton Racket", "Sports", 1199.0, 22, 8, "PlayZone", "Graphite frame, strung."],
    ["SP-5002", "Cricket Bat - Kashmir Willow", "Sports", 1899.0, 11, 5, "PlayZone", "Grain grade B."],
    ["SP-5003", "Football (Size 5)", "Sports", 899.0, 30, 10, "PlayZone", "Match-grade PU."],
    ["SP-5004", "Skipping Rope", "Sports", 249.0, 6, 12, "PlayZone", "Adjustable, cable."],
    ["ML-6001", "Lunch Box 800 ml", "Misc", 379.0, 65, 15, "Nexus Apparel", "Leak-proof, 3 containers."],
    ["ML-6002", "Water Bottle 1 L", "Misc", 259.0, 92, 20, "Nexus Apparel", "BPA free, insulated."],
    ["ML-6003", "Umbrella (Auto)", "Misc", 449.0, 3, 10, "Bright Foods & Co", "Folding, UV coated."],
  ];
  for (const p of products) insProd.run(...p);

  // Seed a couple of historic bills so the reports screen isn't empty.
  const insBill = db.prepare(
    `INSERT INTO bills (bill_no, customer, phone, phone_idx, payment, subtotal, discount, tax, total, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const insItem = db.prepare(
    `INSERT INTO bill_items (bill_id, product_id, name, qty, rate, amount) VALUES (?, ?, ?, ?, ?, ?)`
  );
  const seedBills = [
    ["CNX-100001", "Rahul Kumar", "9876543210", "UPI", 508.0, 50.0, 45.77, 503.77, stamp(-6, "10:24")],
    ["CNX-100002", "Sneha Kulkarni", "9812345678", "Cash", 248.0, 0, 22.32, 270.32, stamp(-4, "14:02")],
    ["CNX-100003", "Vikram Chauhan", "9900112233", "Card", 1348.0, 100.0, 112.32, 1360.32, stamp(-2, "09:47")],
    ["CNX-100004", "Priya Menon", "9654321098", "Cash", 1098.0, 50.0, 94.32, 1142.32, stamp(-1, "17:15")],
  ];
  const itemMap = [
    [[2, 2, 240.0], [6, 1, 268.0]],
    [[3, 3, 248.0]],
    [[7, 1, 1299.0], [10, 1, 49.0]],
    [[11, 2, 999.0], [15, 1, 99.0]],
  ];
  seedBills.forEach((b, i) => {
    const [billNo, customer, phone, payment, subtotal, discount, tax, total, createdAt] = b;
    // Phone numbers are PII: seal them and populate the blind index so the demo
    // database is no less protected than a live one.
    const r = insBill.run(
      billNo, customer, encryptField(phone), blindIndex(phone),
      payment, subtotal, discount, tax, total, createdAt
    );
    for (const [pid, qty, amount] of itemMap[i]) {
      const prod = db.prepare("SELECT name FROM products WHERE id=?").get(pid);
      insItem.run(r.lastInsertRowid, pid, prod.name, qty, amount / qty, amount);
    }
  });

  // ---------------------------------------------------------------- arcade --
  const insScore = db.prepare(
    "INSERT INTO game_scores (game, player, score, detail, played_at) VALUES (?, ?, ?, ?, ?)"
  );
  const scores = [
    ["guess", "Aarav Sharma", 96, "Range 1-100 · 4 attempts", stamp(-1, "16:20")],
    ["guess", "Diya Patel", 88, "Range 1-50 · 3 attempts", stamp(-2, "11:05")],
    ["guess", "Ishaan Verma", 74, "Range 1-100 · 7 attempts", stamp(-3, "19:40")],
    ["guess", "Kavya Nair", 61, "Range 1-100 · 9 attempts", stamp(-5, "13:12")],
    ["swg", "Rohan Gupta", 5, "Best of 9 · 7 wins", stamp(-1, "15:02")],
    ["swg", "Ananya Rao", 3, "Best of 5 · 3 wins", stamp(-4, "18:31")],
    ["swg", "Kabir Singh", 2, "Best of 7 · 2 wins", stamp(-6, "10:55")],
    ["swg", "Meera Joshi", 1, "Best of 3 · 1 win", stamp(-7, "20:10")],
  ];
  for (const s of scores) insScore.run(...s);

  logActivity("system", "Initialised", "CAMPUS NEXUS database created and seeded");
  logActivity("library", "Seed load", `${books.length} titles added to the catalogue`);
  logActivity("store", "Seed load", `${products.length} products added to the inventory`);
  logActivity("arcade", "Seed load", `${scores.length} leaderboard entries loaded`);

  ensureGenesisBlock();
  console.log("  · seeded database  (admin/admin123 · staff/staff123)");
}

function pw(plain) {
  const { salt, hash } = hashPassword(plain);
  return [hash, salt];
}
function dateOffset(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}
function stamp(daysAgo, hhmm) {
  const d = new Date();
  d.setDate(d.getDate() + daysAgo);
  return `${d.toISOString().slice(0, 10)} ${hhmm}:00`;
}