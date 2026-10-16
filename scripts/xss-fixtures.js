// ============================================================================
//  XSS fixtures — injects hostile strings into every user-editable field so the
//  browser can verify that they render as TEXT and never as markup.
//
//      node scripts/xss-fixtures.js --inject
//      node scripts/xss-fixtures.js --clean
// ============================================================================
import { db } from "../src/db.js";

const MARK = "__cnx_xss__";

export const PAYLOADS = [
  `<script>window.${MARK}=1</script>`,
  `"><img src=x onerror="window.${MARK}=1">`,
  `</textarea><svg onload="window.${MARK}=1">`,
  `javascript:window.${MARK}=1`,
  `<img src=x onerror=window.${MARK}=1>`,
  `'"><iframe src="javascript:window.${MARK}=1"></iframe>`,
];

const p = (i) => PAYLOADS[i % PAYLOADS.length];

function inject() {
  // 1. Book titles + authors (rendered in the catalogue table and dropdowns)
  const insBook = db.prepare(
    `INSERT INTO books (isbn, title, author, publisher, category, copies_total, copies_available, shelf)
     VALUES (?,?,?,?,?,2,2,'XS')`
  );
  const bookIds = PAYLOADS.map((payload, i) =>
    insBook.run(`990000000${i}${i}`, `Book ${p(i)}`, `Author ${p(i)}`, `Pub ${p(i)}`, "Computing").lastInsertRowid
  );

  // 2. Loans — borrower, roll number and contact all reach the DOM
  const insLoan = db.prepare(
    `INSERT INTO loans (book_id, borrower, roll_no, contact, issue_date, due_date, status)
     VALUES (?,?,?,?, date('now','localtime'), date('now','localtime','+15 day'), 'issued')`
  );
  bookIds.forEach((bookId, i) =>
    insLoan.run(bookId, `Borrower ${p(i)}`, `ROLL ${p(i)}`, `c${i}${p(i)}`)
  );

  // 3. Products — name, supplier, description
  const insProd = db.prepare(
    `INSERT INTO products (sku, name, category, price, stock, reorder_level, supplier, description)
     VALUES (?,?,?,10,50,5,?,?)`
  );
  PAYLOADS.forEach((payload, i) =>
    insProd.run(`XS-${i}`, `Product ${payload}`, `Cat ${payload}`, `Supplier ${payload}`, payload)
  );

  // 4. A bill whose customer name and line-item names are hostile
  const prodId = db.prepare(`SELECT id FROM products WHERE sku='XS-0'`).get().id;
  const bill = db.prepare(
    `INSERT INTO bills (bill_no, customer, phone, payment, subtotal, discount, tax, total)
     VALUES ('CNX-900001', ?, ?, 'Cash', 10, 0, 0.5, 10.5)`
  ).run(`Customer ${PAYLOADS[0]}`, `9${PAYLOADS[1]}`).lastInsertRowid;
  db.prepare(
    `INSERT INTO bill_items (bill_id, product_id, name, qty, rate, amount) VALUES (?,?,?,1,10,10)`
  ).run(bill, prodId, `Line ${PAYLOADS[2]}`);

  // 5. Arcade leaderboard entries
  const insScore = db.prepare(
    `INSERT INTO game_scores (game, player, score, detail) VALUES (?,?,?,?)`
  );
  insScore.run("guess", `Player ${PAYLOADS[3]}`, 42, `Detail ${PAYLOADS[4]}`);
  insScore.run("swg", `Player ${PAYLOADS[5]}`, 77, `Detail ${PAYLOADS[0]}`);

  console.log(`✔ injected ${PAYLOADS.length} payloads across 5 modules`);
  console.log(`  marker to watch for: window.${MARK}`);
}

function clean() {
  const n =
    db.prepare(`DELETE FROM bill_items WHERE bill_id IN (SELECT id FROM bills WHERE bill_no='CNX-900001')`).run().changes +
    db.prepare(`DELETE FROM bills WHERE bill_no='CNX-900001'`).run().changes +
    db.prepare(`DELETE FROM loans WHERE roll_no LIKE 'ROLL %'`).run().changes +
    db.prepare(`DELETE FROM books WHERE shelf='XS'`).run().changes +
    db.prepare(`DELETE FROM products WHERE sku LIKE 'XS-%'`).run().changes +
    db.prepare(`DELETE FROM game_scores WHERE player LIKE 'Player %'`).run().changes;
  console.log(`✔ removed XSS fixtures (${n} rows)`);
}

const mode = process.argv[2] ?? "--inject";
if (mode === "--clean") clean();
else inject();