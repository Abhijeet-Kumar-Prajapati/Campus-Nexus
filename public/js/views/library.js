// ============================================================================
//  Library — stock list, add/remove, issue & return with fine calculation.
// ============================================================================
import { api } from "../api.js";
import { icon } from "../icons.js";
import {
  esc, fmt, toast, openModal, confirmDialog, emptyState, on, withAuth, $,
} from "../ui.js";
import { refresh } from "../app.js";

const v = {
  tab: "catalogue",
  q: "",
  category: "All",
  loanFilter: "issued",
};

export async function libraryView(host) {
  host.innerHTML = `
    <div class="view">
      <div class="row between mb" style="gap:12px">
        <div class="segmented">
          <button data-tab="catalogue" class="${v.tab === "catalogue" ? "on" : ""}">Catalogue</button>
          <button data-tab="loans" class="${v.tab === "loans" ? "on" : ""}">Issue / Return</button>
        </div>
        <div class="row" style="gap:9px">
          <button class="btn btn-ghost" id="libExport">${icon("download")} <span class="hidden-sm">Export</span></button>
          <button class="btn btn-primary" id="libAdd">${icon("plus")} Add book</button>
        </div>
      </div>

      <div class="stat-grid" id="libStats"></div>
      <div id="libBody"></div>
    </div>`;

  const stats = await api.libStats();
  renderStats(host.querySelector("#libStats"), stats);

  on(host, "click", "[data-tab]", (e, el) => { v.tab = el.dataset.tab; paint(host); });

  host.querySelector("#libAdd").addEventListener("click", () => bookForm(null, async () => {
    toast("Book added to the catalogue", "success");
    await paint(host);
  }));

  host.querySelector("#libExport").addEventListener("click", async () => {
    const { downloadCSV } = await import("../ui.js");
    const res = await api.books(v.q, v.category);
    downloadCSV("library-catalogue.csv", res.books.map((b) => ({
      Title: b.title, Author: b.author, ISBN: b.isbn ?? "", Category: b.category,
      Publisher: b.publisher ?? "", Copies: b.copies_total, Available: b.copies_available, Shelf: b.shelf ?? "",
    })));
  });

  await paint(host);
}

/* ------------------------------------------------------------- stats ----- */
function renderStats(host, s) {
  const cards = [
    ["var(--blue)", "books", "Titles", s.titles, `${s.copies} physical copies`],
    ["var(--green)", "checkCircle", "Available now", s.available, `${s.copies - s.available} with readers`],
    ["var(--amber)", "clock", "Currently issued", s.issued, `${s.utilisation}% utilisation`],
    ["var(--red)", "alert", "Overdue", s.overdue, `₹${fmt.money(s.finePending)} pending`],
  ];
  host.innerHTML = cards.map(([accent, ic, label, value, foot]) => `
    <div class="stat" style="--accent:${accent}">
      <div class="stat-top">
        <div class="stat-icon">${icon(ic)}</div>
        <div class="stat-label">${label}</div>
      </div>
      <div class="stat-value">${fmt.num(value)}</div>
      <div class="stat-foot">${esc(foot)}</div>
    </div>`).join("");
}

/* -------------------------------------------------------------- paint ---- */
async function paint(host) {
  const body = host.querySelector("#libBody");
  body.innerHTML = `<div class="card"><div class="card-body"><div class="skeleton" style="height:200px"></div></div></div>`;

  if (v.tab === "catalogue") {
    const [booksRes, catsRes] = await Promise.all([api.books(v.q, v.category), api.bookCategories()]);
    const books = booksRes.books;

    body.innerHTML = `
      <div class="card">
        <div class="card-head" style="flex-wrap:wrap;gap:10px">
          <div class="searchbox" style="margin-left:0;width:300px">
            ${icon("search")}
            <input id="bq" type="search" placeholder="Search title, author, ISBN…" value="${esc(v.q)}">
          </div>
          <select class="select" id="bcat" style="width:auto;min-width:170px">
            ${["All", ...catsRes.categories.map((c) => c.category)].map((c) =>
              `<option ${v.category === c ? "selected" : ""}>${esc(c)}</option>`).join("")}
          </select>
          <span class="spacer"></span>
          <span class="section-sub">${books.length} title${books.length === 1 ? "" : "s"}</span>
        </div>
        <div class="card-body" style="padding:0">
          ${books.length ? `
            <div class="table-wrap">
              <table class="data">
                <thead><tr>
                  <th>Title</th><th>Category</th><th>Shelf</th>
                  <th class="num">Copies</th><th class="num">Available</th><th>Status</th><th></th>
                </tr></thead>
                <tbody>
                  ${books.map((b) => {
                    const none = b.copies_available === 0;
                    return `<tr>
                      <td>
                        <div class="cell-main">${esc(b.title)}</div>
                        <div class="cell-sub">${esc(b.author)}${b.isbn ? " · " + esc(b.isbn) : ""}</div>
                      </td>
                      <td><span class="badge">${esc(b.category)}</span></td>
                      <td class="mono small">${esc(b.shelf ?? "—")}</td>
                      <td class="num">${b.copies_total}</td>
                      <td class="num strong">${b.copies_available}</td>
                      <td><span class="badge ${none ? "danger" : b.copies_available < b.copies_total ? "warn" : "ok"}">
                        ${none ? "All out" : b.copies_available < b.copies_total ? "Part issued" : "On shelf"}</span></td>
                      <td>
                        <div class="actions">
                          <button class="btn btn-sm btn-ghost" data-issue="${b.id}" title="Issue this book">${icon("arrowRight")}</button>
                          <button class="btn btn-sm btn-ghost" data-edit="${b.id}" title="Edit">${icon("edit")}</button>
                          <button class="btn btn-sm btn-danger" data-del="${b.id}" title="Remove">${icon("trash")}</button>
                        </div>
                      </td>
                    </tr>`;
                  }).join("")}
                </tbody>
              </table>
            </div>` : emptyState("No books match this filter", "books")}
        </div>
      </div>`;

    /* filters (debounced) */
    const bq = body.querySelector("#bq");
    let t;
    bq.addEventListener("input", () => {
      clearTimeout(t);
      t = setTimeout(() => { v.q = bq.value.trim(); paint(host); setTimeout(() => $("#bq")?.focus(), 0); }, 300);
    });
    body.querySelector("#bcat").addEventListener("change", (e) => { v.category = e.target.value; paint(host); });

    body.querySelectorAll("[data-issue]").forEach((el) =>
      el.addEventListener("click", () => issueForm(Number(el.dataset.issue), host)));
    body.querySelectorAll("[data-edit]").forEach((el) =>
      el.addEventListener("click", async () => {
        const res = await api.books();
        bookForm(res.books.find((b) => b.id === Number(el.dataset.edit)), () => paint(host));
      }));
    body.querySelectorAll("[data-del]").forEach((el) =>
      el.addEventListener("click", async () => {
        const id = Number(el.dataset.del);
        const res = await api.books();
        const b = res.books.find((x) => x.id === id);
        const ok = await confirmDialog({
          title: "Remove from catalogue?",
          message: `“${b.title}” and its loan history will be permanently removed. This cannot be undone.`,
          confirmText: "Remove book", danger: true,
        });
        if (!ok) return;
        await withAuth(async () => {
          const r = await api.removeBook(id);
          toast(r.message, "success");
          await paint(host);
        });
      }));
  }

  /* ------------------------------------------------------------ loans --- */
  else {
    const [res, cats] = await Promise.all([api.loans(v.loanFilter), api.bookCategories()]);
    const loans = res.loans;

    body.innerHTML = `
      <div class="card">
        <div class="card-head" style="flex-wrap:wrap;gap:10px">
          <div class="segmented">
            ${[["issued", "Currently issued"], ["returned", "Returned"], ["all", "All"]].map(([k, l]) =>
              `<button data-lf="${k}" class="${v.loanFilter === k ? "on" : ""}">${l}</button>`).join("")}
          </div>
          <span class="spacer"></span>
          <button class="btn btn-sm btn-primary" id="issueNew">${icon("plus")} Issue a book</button>
        </div>
        <div class="card-body" style="padding:0">
          ${loans.length ? `
            <div class="table-wrap">
              <table class="data">
                <thead><tr>
                  <th>Book</th><th>Borrower</th><th>Issued</th><th>Due</th>
                  <th class="num">Fine</th><th>Status</th><th></th>
                </tr></thead>
                <tbody>
                  ${loans.map((l) => {
                    const late = l.overdue_days > 0 && l.status === "issued";
                    const fine = l.status === "issued" ? l.projected_fine : l.fine;
                    return `<tr>
                      <td>
                        <div class="cell-main">${esc(l.title)}</div>
                        <div class="cell-sub">${esc(l.author)}</div>
                      </td>
                      <td>
                        <div>${esc(l.borrower)}</div>
                        <div class="cell-sub mono">${esc(l.roll_no ?? "—")}</div>
                      </td>
                      <td class="small">${esc(fmt.date(l.issue_date))}</td>
                      <td class="small">${esc(fmt.date(l.due_date))}
                        ${late ? `<div class="cell-sub" style="color:var(--red)">${l.overdue_days}d late</div>` : ""}
                      </td>
                      <td class="num strong" style="${fine > 0 ? "color:var(--red)" : ""}">₹${fmt.num(fine)}</td>
                      <td><span class="badge ${l.status === "returned" ? "ok" : late ? "danger" : "info"}">
                        ${l.status === "returned" ? "Returned" : late ? "Overdue" : "On loan"}</span></td>
                      <td>
                        <div class="actions">
                          ${l.status === "issued"
                            ? `<button class="btn btn-sm btn-success" data-ret="${l.id}">${icon("refresh")} Return</button>`
                            : `<span class="tiny faint">${esc(fmt.date(l.returned_date))}</span>`}
                        </div>
                      </td>
                    </tr>`;
                  }).join("")}
                </tbody>
              </table>
            </div>` : emptyState("No loan records for this filter", "clock")}
        </div>
      </div>`;

    body.querySelectorAll("[data-lf]").forEach((el) =>
      el.addEventListener("click", () => { v.loanFilter = el.dataset.lf; paint(host); }));
    body.querySelector("#issueNew").addEventListener("click", () => issueForm(null, host));
    body.querySelectorAll("[data-ret]").forEach((el) =>
      el.addEventListener("click", async () => {
        await withAuth(async () => {
          const r = await api.returnBook(Number(el.dataset.ret));
          toast(r.message, r.lateDays ? "warn" : "success", r.lateDays ? "Returned late" : "Returned");
          await paint(host);
        });
      }));
  }
}

/* --------------------------------------------------------- book form ----- */
async function bookForm(existing, done) {
  const cats = ["Computing", "AI/ML", "Systems", "Physics", "General", "Self Growth", "Management"];
  const b = existing ?? {};
  const editing = !!existing;

  const m = openModal({
    title: editing ? "Edit book" : "Add a book",
    subtitle: editing ? b.title : "New catalogue entry",
    wide: true,
    body: `
      <form id="bf" class="form-grid">
        <div class="field span-2">
          <label for="fTitle">Title <span style="color:var(--red)">*</span></label>
          <input class="input" id="fTitle" value="${esc(b.title ?? "")}" placeholder="e.g. Clean Code" required>
        </div>
        <div class="field">
          <label for="fAuthor">Author <span style="color:var(--red)">*</span></label>
          <input class="input" id="fAuthor" value="${esc(b.author ?? "")}" placeholder="e.g. Robert C. Martin" required>
        </div>
        <div class="field">
          <label for="fIsbn">ISBN</label>
          <input class="input mono" id="fIsbn" value="${esc(b.isbn ?? "")}" placeholder="9780132350884">
          <div class="hint">Digits, hyphens and a trailing X only.</div>
        </div>
        <div class="field">
          <label for="fCat">Category</label>
          <select class="select" id="fCat">
            ${cats.map((c) => `<option ${b.category === c ? "selected" : ""}>${c}</option>`).join("")}
          </select>
        </div>
        <div class="field">
          <label for="fPub">Publisher</label>
          <input class="input" id="fPub" value="${esc(b.publisher ?? "")}" placeholder="e.g. Prentice Hall">
        </div>
        <div class="field">
          <label for="fEdition">Edition</label>
          <input class="input" id="fEdition" value="${esc(b.edition ?? "")}" placeholder="e.g. 3rd">
        </div>
        <div class="field">
          <label for="fYear">Year</label>
          <input class="input" id="fYear" type="number" min="1000" max="2100" value="${b.year ?? ""}" placeholder="2021">
        </div>
        <div class="field">
          <label for="fShelf">Shelf</label>
          <input class="input mono" id="fShelf" value="${esc(b.shelf ?? "")}" placeholder="CS-A1">
        </div>
        <div class="field">
          <label for="fCopies">Copies owned</label>
          <input class="input" id="fCopies" type="number" min="0" max="50" value="${b.copies_total ?? 1}">
          ${editing ? `<div class="hint">${b.copies_total - b.copies_available} currently issued.</div>` : ""}
        </div>
        <div class="field span-2">
          <label for="fNotes">Notes</label>
          <textarea class="input" id="fNotes" rows="2" placeholder="Optional">${esc(b.notes ?? "")}</textarea>
        </div>
      </form>`,
    footer: `
      <button class="btn btn-ghost" data-close>Cancel</button>
      <button class="btn btn-primary" id="bfSave">${icon("check")} ${editing ? "Save changes" : "Add book"}</button>`,
  });

  const val = (id) => m.el.querySelector("#f" + id).value.trim();
  m.el.querySelector("#bfSave").addEventListener("click", async () => {
    const payload = {
      title: val("Title"), author: val("Author"), isbn: val("Isbn"), category: val("Cat"),
      publisher: val("Pub"), edition: val("Edition"),
      year: val("Year") ? Number(val("Year")) : null,
      shelf: val("Shelf"), copiesTotal: Number(val("Copies")) || 1, notes: val("Notes"),
    };
    if (!payload.title || !payload.author) {
      return toast("Title and author are required", "warn");
    }
    const btn = m.el.querySelector("#bfSave");
    btn.disabled = true;
    const res = await withAuth(() => editing ? api.editBook(b.id, payload) : api.addBook(payload));
    if (!res.ok) { btn.disabled = false; return; }
    m.close();
    toast(res.data.message, "success");
    await done?.();
  });
}

/* -------------------------------------------------------- issue form ----- */
async function issueForm(presetId, host) {
  const res = await api.books();
  const available = res.books.filter((b) => b.copies_available > 0);

  if (!available.length) {
    return toast("Every title is currently issued — return something first", "warn");
  }

  const m = openModal({
    title: "Issue a book",
    subtitle: "Copies stay out until they are returned · fines accrue after the due date",
    body: `
      <form id="if" class="form-grid">
        <div class="field span-2">
          <label for="iBook">Book <span style="color:var(--red)">*</span></label>
          <select class="select" id="iBook">
            ${available.map((b) => `<option value="${b.id}" ${presetId === b.id ? "selected" : ""}>
              ${esc(b.title)} — ${esc(b.author)} (${b.copies_available} free)
            </option>`).join("")}
          </select>
        </div>
        <div class="field">
          <label for="iName">Borrower <span style="color:var(--red)">*</span></label>
          <input class="input" id="iName" placeholder="e.g. Aarav Sharma" required>
        </div>
        <div class="field">
          <label for="iRoll">Roll / ID number</label>
          <input class="input mono" id="iRoll" placeholder="e.g. 21CS1042">
        </div>
        <div class="field">
          <label for="iDays">Loan period</label>
          <select class="select" id="iDays">
            ${[7, 15, 21, 30].map((d) => `<option value="${d}" ${d === 15 ? "selected" : ""}>${d} days</option>`).join("")}
          </select>
        </div>
        <div class="field">
          <label for="iContact">Contact</label>
          <input class="input" id="iContact" placeholder="e.g. aarav@campus.edu">
        </div>
      </form>`,
    footer: `
      <button class="btn btn-ghost" data-close>Cancel</button>
      <button class="btn btn-primary" id="ifGo">${icon("arrowRight")} Issue</button>`,
  });

  m.el.querySelector("#ifGo").addEventListener("click", async () => {
    const payload = {
      bookId: Number(m.el.querySelector("#iBook").value),
      borrower: m.el.querySelector("#iName").value.trim(),
      rollNo: m.el.querySelector("#iRoll").value.trim(),
      contact: m.el.querySelector("#iContact").value.trim(),
      days: Number(m.el.querySelector("#iDays").value),
    };
    if (!payload.borrower) return toast("Enter the borrower's name", "warn");

    const btn = m.el.querySelector("#ifGo");
    btn.disabled = true;
    const res = await withAuth(() => api.issueBook(payload));
    if (!res.ok) { btn.disabled = false; return; }
    m.close();
    toast(`${res.data.message} — due ${fmt.date(res.data.due)}`, "success", "Issued");
    await paint(host);
  });
}