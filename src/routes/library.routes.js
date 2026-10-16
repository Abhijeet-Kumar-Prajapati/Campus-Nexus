// ============================================================================
//  Library module  —  derived from the "I_P / THE CITADEL" Java Swing project.
//  Adds: fine calculation, overdue detection, availability guard, audit log.
// ============================================================================
import { db, logActivity } from "../db.js";
import { fail, readJson } from "../http.js";
import { validate, V, safeText } from "../security/validate.js";
import { encryptField, decryptField } from "../security/fieldcrypto.js";

export const LOAN_DAYS = 15;      // standard issue period
export const FINE_PER_DAY = 2.0; // rupees charged per overdue day
export const MAX_COPIES = 50;

const today = () => new Date().toISOString().slice(0, 10);
const plusDays = (iso, n) => {
  const d = new Date(iso + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
};
const daysBetween = (a, b) =>
  Math.round((new Date(b + "T00:00:00Z") - new Date(a + "T00:00:00Z")) / 86400000);

// `num` coerces route params; user strings go through the schema validator.
const num = (v, def = 0) => (Number.isFinite(Number(v)) ? Number(v) : def);

/* -------------------------------------------------------------- schemas -- */
const BOOK_SCHEMA = V.object({
  title: safeText(160),
  author: safeText(120),
  isbn: V.string({ max: 20, pattern: /^[0-9Xx-]*$/, patternHint: "ISBN may only contain digits, hyphens and a trailing X" }),
  category: safeText(60),
  publisher: safeText(120),
  edition: V.string({ max: 30 }),
  year: V.int({ min: 1000, max: 2200, fallback: null }),
  copiesTotal: V.int({ min: 1, max: MAX_COPIES, fallback: 1 }),
  shelf: V.string({ max: 20 }),
  notes: V.string({ max: 400 }),
}, { strict: true });

/** Validate and return the parsed value, or null after replying 400. */
function check(res, input, schema) {
  const parsed = validate(input, schema);
  if (!parsed.ok) {
    res.json({ ok: false, error: "Validation failed", errors: parsed.errors }, 400);
    return null;
  }
  return parsed.value;
}

/* ------------------------------------------------------------------ stats -- */
export function libraryStats() {
  const base = db
    .prepare(
      `SELECT COUNT(*)                                AS titles,
              IFNULL(SUM(copies_total), 0)            AS copies,
              IFNULL(SUM(copies_available), 0)        AS available
       FROM books`
    )
    .get();

  const loans = db
    .prepare(
      `SELECT COUNT(*)                                        AS issued,
              IFNULL(SUM(fine), 0)                            AS fine_pending,
              IFNULL(SUM(CASE WHEN date(returned_date) IS NOT NULL THEN fine ELSE 0 END), 0) AS fine_collected
       FROM loans WHERE status = 'issued'`
    )
    .get();

  const overdue = db
    .prepare(
      `SELECT COUNT(*) AS n FROM loans
       WHERE status = 'issued' AND due_date < date('now','localtime')`
    )
    .get().n;

  const returned = db
    .prepare(`SELECT COUNT(*) AS n FROM loans WHERE status='returned'`)
    .get().n;

  return {
    titles: base.titles,
    copies: base.copies,
    available: base.available,
    issued: loans.issued,
    overdue,
    returned,
    finePending: Math.round(loans.fine_pending * 100) / 100,
    fineCollected: Math.round(loans.fine_collected * 100) / 100,
    utilisation:
      base.copies === 0 ? 0 : Math.round(((base.copies - base.available) / base.copies) * 100),
  };
}

/* ------------------------------------------------------------------ books -- */
export function listBooks(q = "", category = "") {
  const where = [];
  const args = [];
  if (q) {
    where.push("(title LIKE ? OR author LIKE ? OR isbn LIKE ? OR publisher LIKE ?)");
    const like = `%${q}%`;
    args.push(like, like, like, like);
  }
  if (category && category !== "All") {
    where.push("category = ?");
    args.push(category);
  }
  const clause = where.length ? "WHERE " + where.join(" AND ") : "";
  return db
    .prepare(
      `SELECT b.*,
              (SELECT COUNT(*) FROM loans l
                WHERE l.book_id = b.id AND l.status='issued') AS active_loans
       FROM books b ${clause}
       ORDER BY b.title COLLATE NOCASE`
    )
    .all(...args);
}

export function bookCategories() {
  return db
    .prepare(`SELECT category, COUNT(*) AS n FROM books GROUP BY category ORDER BY n DESC`)
    .all();
}

export async function createBook(req, res) {
  const b = check(res, await readJson(req), BOOK_SCHEMA);
  if (!b) return;

  if (!b.title) return fail(res, "Book title is required");
  if (!b.author) return fail(res, "Author is required");

  const isbn = b.isbn;
  if (isbn) {
    const dup = db.prepare("SELECT id FROM books WHERE isbn = ?").get(isbn);
    if (dup) return fail(res, `ISBN ${isbn} already exists in the catalogue`, 409);
  }

  const copiesTotal = b.copiesTotal;
  try {
    const r = db
      .prepare(
        `INSERT INTO books (isbn, title, author, publisher, category, edition, year,
                            copies_total, copies_available, shelf, notes)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`
      )
      .run(
        isbn || null, b.title, b.author, b.publisher, b.category || "General",
        b.edition, b.year, copiesTotal, copiesTotal, b.shelf, b.notes
      );
    logActivity("library", "Book added", `${b.title} — ${copiesTotal} cop${copiesTotal > 1 ? "ies" : "y"}`);
    res.json({ ok: true, id: r.lastInsertRowid, message: `“${b.title}” added to the catalogue` }, 201);
  } catch (e) {
    fail(res, e.message.includes("UNIQUE") ? "That ISBN is already in the catalogue" : e.message, 409);
  }
}

export async function updateBook(req, res, { id }) {
  const b = check(res, await readJson(req), BOOK_SCHEMA);
  if (!b) return;

  const book = db.prepare("SELECT * FROM books WHERE id = ?").get(num(id));
  if (!book) return fail(res, "Book not found", 404);
  if (!b.title) return fail(res, "Book title is required");
  if (!b.author) return fail(res, "Author is required");

  const copiesTotal = b.copiesTotal;
  const onLoan = book.copies_total - book.copies_available;
  if (copiesTotal < onLoan) {
    return fail(res, `${onLoan} copy/copies are currently issued — total cannot go below ${onLoan}`);
  }
  const isbn = b.isbn;
  if (isbn && isbn !== book.isbn) {
    const dup = db.prepare("SELECT id FROM books WHERE isbn = ? AND id <> ?").get(isbn, book.id);
    if (dup) return fail(res, `ISBN ${isbn} already exists in the catalogue`, 409);
  }

  db.prepare(
    `UPDATE books SET isbn=?, title=?, author=?, publisher=?, category=?, edition=?, year=?,
            copies_total=?, copies_available=?, shelf=?, notes=? WHERE id=?`
  ).run(
    isbn || null, b.title, b.author, b.publisher, b.category || book.category,
    b.edition, b.year ?? book.year, copiesTotal, copiesTotal - onLoan, b.shelf, b.notes, book.id
  );
  logActivity("library", "Book updated", book.title);
  res.json({ ok: true, message: `“${book.title}” updated` });
}

export function deleteBook(req, res, { id }) {
  const book = db.prepare("SELECT * FROM books WHERE id = ?").get(num(id));
  if (!book) return fail(res, "Book not found", 404);
  const active = db
    .prepare(`SELECT COUNT(*) AS n FROM loans WHERE book_id=? AND status='issued'`)
    .get(book.id).n;
  if (active > 0) return fail(res, `Cannot remove — ${active} copy/copies of this title are still issued`, 409);

  db.prepare("DELETE FROM books WHERE id=?").run(book.id);
  logActivity("library", "Book removed", book.title);
  res.json({ ok: true, message: `“${book.title}” removed from the catalogue` });
}

/* ------------------------------------------------------------------ loans -- */
export function listLoans(status = "all") {
  const rows = db
    .prepare(
      `SELECT l.*, b.title, b.author, b.isbn,
              CAST(julianday(date('now','localtime')) - julianday(l.due_date) AS INTEGER) AS overdue_days
       FROM loans l JOIN books b ON b.id = l.book_id
       ${status !== "all" ? "WHERE l.status = ?" : ""}
       ORDER BY (l.status='issued') DESC, l.due_date ASC`
    )
    .all(...(status !== "all" ? [status] : []))
    .map((l) => ({
      ...l,
      // Decrypt only at the edge — the ciphertext never leaves the database.
      contact: decryptField(l.contact),
      overdue_days: Math.max(0, l.overdue_days),
      projected_fine: l.status === "issued" ? Math.max(0, l.overdue_days) * FINE_PER_DAY : 0,
    }));
  return rows;
}

export async function issueBook(req, res) {
  const b = check(res, await readJson(req), V.object({
    bookId: V.int({ min: 1, max: 1_000_000 }),
    borrower: safeText(120),
    rollNo: V.string({ max: 40, pattern: /^[A-Za-z0-9/_-]*$/, patternHint: "roll number may only contain letters, digits, /, _ and -" }),
    contact: V.string({ max: 80, pattern: /^[^<>]*$/, patternHint: "angle brackets are not allowed" }),
    days: V.int({ min: 1, max: 60, fallback: LOAN_DAYS }),
    // Optional: the `?` keeps an omitted value valid while still rejecting
    // anything that looks like a malformed date.
    dueDate: V.string({ max: 10, pattern: /^(\d{4}-\d{2}-\d{2})?$/, patternHint: "due date must be YYYY-MM-DD" }),
  }, { strict: true }));
  if (!b) return;

  // A missing bookId is a malformed request, not a missing book. Without
  // this the lookup below runs with undefined and answers "Book not found",
  // so a client that forgot the field got a 404 for what was really a 400.
  if (!b.bookId) return fail(res, "A bookId is required");

  const book = db.prepare("SELECT * FROM books WHERE id=?").get(b.bookId);
  if (!book) return fail(res, "Book not found", 404);
  if (book.copies_available < 1) return fail(res, `No copy of “${book.title}” is currently available`, 409);
  if (!b.borrower) return fail(res, "Borrower name is required");

  const due = b.dueDate || plusDays(today(), b.days);

  const r = db
    .prepare(
      `INSERT INTO loans (book_id, borrower, roll_no, contact, issue_date, due_date, status)
       VALUES (?,?,?,?,?,?,'issued')`
    )
    .run(book.id, b.borrower, b.rollNo, encryptField(b.contact), today(), due);

  db.prepare("UPDATE books SET copies_available = copies_available - 1 WHERE id=?").run(book.id);
  logActivity("library", "Book issued", `${book.title} → ${b.borrower} (due ${due})`);
  res.json({ ok: true, id: r.lastInsertRowid, message: `“${book.title}” issued to ${b.borrower}`, due }, 201);
}

export function returnBook(req, res, { id }) {
  const loan = db.prepare("SELECT * FROM loans WHERE id=?").get(num(id));
  if (!loan) return fail(res, "Loan record not found", 404);
  if (loan.status === "returned") return fail(res, "This book has already been returned", 409);

  const late = Math.max(0, daysBetween(loan.due_date, today()));
  const fine = late * FINE_PER_DAY;

  db.prepare(
    `UPDATE loans SET status='returned', returned_date=?, fine=? WHERE id=?`
  ).run(today(), fine, loan.id);
  db.prepare("UPDATE books SET copies_available = MIN(copies_total, copies_available + 1) WHERE id=?")
    .run(loan.book_id);

  const book = db.prepare("SELECT title FROM books WHERE id=?").get(loan.book_id);
  logActivity(
    "library",
    "Book returned",
    `${book?.title ?? "Book"} ← ${loan.borrower}${late ? ` · ${late} day(s) late · ₹${fine} fine` : " · on time"}`
  );
  res.json({
    ok: true,
    lateDays: late,
    fine,
    message: late
      ? `Returned ${late} day(s) late — fine ₹${fine.toFixed(2)} recorded`
      : `Returned on time — no fine. Thank you!`,
  });
}

/* -------------------------------------------------------------- activity --- */
export function libraryActivity(limit = 8) {
  return db
    .prepare(
      `SELECT * FROM activity WHERE module='library'
       ORDER BY created_at DESC, id DESC LIMIT ?`
    )
    .all(limit);
}