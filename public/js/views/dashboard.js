// ============================================================================
//  Dashboard — the screen that proves all three original projects are now one
//  application: it reads live from the library, the store and the arcade at once.
// ============================================================================
import { api } from "../api.js";
import { icon } from "../icons.js";
import { esc, fmt, toast, lineChart, hbars, emptyState, countUp, withAuth } from "../ui.js";
import { state, go, refresh } from "../app.js";

const MODULE_COLOR = { library: "var(--blue)", store: "var(--violet)", arcade: "var(--pink)", system: "var(--text-faint)" };
const MODULE_ICON = { library: "books", store: "store", arcade: "gamepad", system: "info" };

function greeting() {
  const h = new Date().getHours();
  if (h < 5)  return "Burning the midnight oil";
  if (h < 12) return "Good morning";
  if (h < 17) return "Good afternoon";
  if (h < 21) return "Good evening";
  return "Winding down";
}

export async function dashboardView(host) {
  const d = await api.dashboard();
  state.moduleData.dashboard = d;

  const { library: lib, store: st, arcade: ar, totals, config } = d;

  host.innerHTML = `
    <div class="view">

      <!-- ── hero ─────────────────────────────────────────────────── -->
      <div class="card mb" style="overflow:hidden">
        <div class="card-body" style="display:grid;grid-template-columns:1fr auto;gap:22px;align-items:center">
          <div>
            <div class="row" style="gap:9px;margin-bottom:8px">
              <span class="badge violet">${icon("sparkle")} Unified platform</span>
              <span class="badge info">${esc(config.loanDays)}-day loan · ₹${config.finePerDay}/day fine · ${config.taxPct}% GST</span>
            </div>
            <h2 style="font-size:24px;letter-spacing:-.4px;margin-bottom:6px">
              ${greeting()}${state.user ? ", " + esc(state.user.full_name.split(" ")[0]) : ""} 👋
            </h2>
            <p class="muted" style="max-width:62ch">
              One application now runs the <strong>library</strong>, the <strong>campus store</strong> and the
              <strong>arcade</strong> — the three separate C / Java projects rebuilt on one database,
              one login and one dashboard.
            </p>
          </div>
          <div class="row" style="gap:10px">
            <button class="btn btn-ghost" data-go="library">${icon("library")} Library</button>
            <button class="btn btn-ghost" data-go="store">${icon("store")} Store</button>
            <button class="btn btn-primary" data-go="arcade">${icon("gamepad")} Play</button>
          </div>
        </div>
      </div>

      <!-- ── alerts ───────────────────────────────────────────────── -->
      ${d.alerts.length ? `
        <div class="grid-3 mb">
          ${d.alerts.slice(0, 4).map((a) => `
              <div class="alert ${a.level}">
                ${icon(a.level === "danger" ? "alert" : "clock")}
                <span>${esc(a.text)}</span>
              </div>`).join("")}
        </div>` : ""}

      <!-- ── stat cards ───────────────────────────────────────────── -->
      <div class="stat-grid">
        ${statCard({
          accent: "var(--blue)", ic: "books",
          label: "Library catalogue",
          value: totals.books, format: (v) => fmt.num(v),
          foot: `${fmt.num(lib.copies)} copies · ${fmt.pct(lib.utilisation)} issued`,
          onClick: "library",
        })}
        ${statCard({
          accent: "var(--red)", ic: "clock",
          label: "Overdue books",
          value: lib.overdue, format: (v) => fmt.num(v),
          foot: lib.overdue ? `₹${fmt.money(lib.finePending)} fines pending` : "Nothing overdue 🎉",
          onClick: "library",
        })}
        ${statCard({
          accent: "var(--violet)", ic: "box",
          label: "Inventory value",
          value: st.inventoryValue, format: (v) => fmt.money0(v),
          foot: `${fmt.num(st.products)} products · ${fmt.num(st.units)} units`,
          onClick: "store",
        })}
        ${statCard({
          accent: "var(--green)", ic: "trend",
          label: "Revenue · 30 days",
          value: st.revenue30d, format: (v) => fmt.money0(v),
          foot: `${fmt.num(st.bills30d)} bills · today ${fmt.money0(st.revenueToday)}`,
          onClick: "store",
        })}
        ${statCard({
          accent: "var(--amber)", ic: "alert",
          label: "Reorder alerts",
          value: st.lowStock, format: (v) => fmt.num(v),
          foot: st.outOfStock ? `${st.outOfStock} completely out of stock` : "Stock levels healthy",
          onClick: "store",
        })}
        ${statCard({
          accent: "var(--pink)", ic: "trophy",
          label: "Arcade players",
          value: ar.players, format: (v) => fmt.num(v),
          foot: `${fmt.num(ar.plays)} games played · ${ar.games} titles`,
          onClick: "arcade",
        })}
      </div>

      <!-- ── charts ───────────────────────────────────────────────── -->
      <div class="grid-2 mb">
        <div class="card">
          <div class="card-head">
            <h4>Daily revenue</h4><span class="spacer"></span>
            <span class="section-sub">last 14 days</span>
          </div>
          <div class="card-body">
            ${lineChart(
              d.salesSeries.map((s) => ({ label: fmt.dateShort(s.date), value: s.amount })),
              { height: 250 }
            )}
          </div>
        </div>

        <div class="card">
          <div class="card-head"><h4>Best sellers</h4><span class="spacer"></span>
            <span class="section-sub">units sold · 90 days</span></div>
          <div class="card-body">
            ${d.topProducts.length
              ? hbars(d.topProducts.map((p) => ({ label: p.name, value: p.qty })))
              : emptyState("No sales recorded yet", "chart")}
          </div>
        </div>
      </div>

      <!-- ── module snapshots ─────────────────────────────────────── -->
      <div class="grid-3 mb">
        ${snapshot({
          module: "library", title: "Library", foot: `${lib.titles} titles tracked`,
          big: [lib.issued, "on loan"], sub: [lib.available, "on shelf"],
          rows: [
            { label: "Shelf availability", value: `${fmt.num(lib.available)} of ${fmt.num(lib.copies)}`, ratio: lib.copies ? (lib.available / lib.copies) * 100 : 0 },
            { label: "Return rate", value: `${fmt.num(lib.returned)} returned`, ratio: (lib.issued + lib.returned) ? (lib.returned / (lib.issued + lib.returned)) * 100 : 0 },
            { label: "Overdue share", value: `${fmt.num(lib.overdue)} overdue`, ratio: lib.issued ? (lib.overdue / lib.issued) * 100 : 0, invert: true },
          ],
        })}

        ${snapshot({
          module: "store", title: "Store", foot: `${fmt.money0(st.revenue30d)} in 30 days`,
          big: [st.billsToday, "bills today"], sub: [st.bills30d, "bills · 30 days"],
          rows: (() => {
            const mixTotal = st.paymentMix.reduce((s, p) => s + p.amt, 0) || 1;
            return st.paymentMix.length
              ? st.paymentMix.map((p) => ({
                  label: `${p.payment} share`,
                  value: fmt.money0(p.amt),
                  ratio: (p.amt / mixTotal) * 100,
                }))
              : [{ label: "No bills yet", value: "—", ratio: 0 }];
          })(),
        })}

        ${snapshot({
          module: "arcade", title: "Arcade", foot: `Top: ${d.leaderboards[0]?.topPlayer ?? "—"}`,
          big: [ar.plays, "plays"], sub: [ar.players, "players"],
          rows: d.leaderboards.map((b) => ({
            label: b.label,
            value: `${fmt.num(b.topScore)} · ${esc(b.topPlayer)}`,
            ratio: (b.topScore / 130) * 100,
          })),
        })}
      </div>

      <!-- ── activity ─────────────────────────────────────────────── -->
      <div class="grid-2">
        <div class="card">
          <div class="card-head"><h4>Recent activity</h4><span class="spacer"></span>
            <span class="badge">${d.activity.length} events</span></div>
          <div class="card-body tight">
            <div class="feed">
              ${d.activity.map((a) => `
                <div class="feed-item">
                  <div class="feed-icon" style="background:color-mix(in oklab, ${MODULE_COLOR[a.module] ?? "var(--violet)"} 18%, transparent);color:${MODULE_COLOR[a.module] ?? "var(--violet)"}">
                    ${icon(MODULE_ICON[a.module] ?? "info")}
                  </div>
                  <div class="feed-text">
                    <strong>${esc(a.action)}</strong>
                    <p title="${esc(a.detail)}">${esc(a.detail)}</p>
                  </div>
                  <div class="feed-time">${esc(fmt.timeAgo(a.created_at))}</div>
                </div>`).join("")}
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><h4>Leaderboards</h4><span class="spacer"></span>
            <button class="btn btn-sm btn-ghost" data-go="arcade">Open arcade ${icon("arrowRight")}</button></div>
          <div class="card-body">
            <div class="lb-list">
              ${d.leaderboardTop.length
                ? d.leaderboardTop.map((e, i) => `
                    <div class="lb-item">
                      <div class="lb-rank ${i === 0 ? "g1" : i === 1 ? "g2" : i === 2 ? "g3" : ""}">${i + 1}</div>
                      <div class="lb-name">${esc(e.player)}
                        <div class="tiny faint">${esc(e.game === "guess" ? "Number Guessing" : "Snake · Water · Gun")}</div>
                      </div>
                      <div class="lb-score">${fmt.num(e.score)}</div>
                    </div>`).join("")
                : emptyState("No scores yet — be the first!", "trophy")}
            </div>
          </div>
        </div>
      </div>
    </div>`;

  /* stats animate + are clickable */
  host.querySelectorAll("[data-countup]").forEach((el) => {
    countUp(el, el.dataset.countup, {
      decimals: el.dataset.decimals ? Number(el.dataset.decimals) : 0,
      prefix: el.dataset.prefix ?? "",
    });
  });
  host.querySelectorAll("[data-go]").forEach((el) =>
    el.addEventListener("click", () => go(el.dataset.go))
  );
}

/* ------------------------------------------------------------ fragments -- */
function statCard({ accent, ic, label, value, format, foot, onClick }) {
  return `
    <div class="stat" style="--accent:${accent};cursor:pointer" data-go="${onClick}">
      <div class="stat-top">
        <div class="stat-icon">${icon(ic)}</div>
        <div class="stat-label">${esc(label)}</div>
      </div>
      <div class="stat-value" data-countup="${value}" data-decimals="${String(value).includes(".") ? 2 : 0}">0</div>
      <div class="stat-foot">${esc(foot)}</div>
    </div>`;
}

/**
 * A per-module summary card.
 * `rows` take { label, value (pre-formatted string), ratio (0-100), invert }.
 */
function snapshot({ module, title, foot, big, sub, rows }) {
  const accent = MODULE_COLOR[module];
  return `
    <div class="card">
      <div class="card-head">
        <div class="stat-icon" style="background:color-mix(in oklab, ${accent} 18%, transparent);color:${accent}">${icon(MODULE_ICON[module])}</div>
        <div style="flex:1;min-width:0">
          <h4>${esc(title)}</h4>
          ${foot ? `<div class="tiny faint">${foot}</div>` : ""}
        </div>
        <button class="btn btn-sm btn-ghost" data-go="${module}">Open</button>
      </div>
      <div class="card-body">
        <div class="row" style="gap:22px;margin-bottom:16px">
          <div>
            <div class="tiny faint">${esc(big[1])}</div>
            <div class="strong" style="font-size:21px;line-height:1.2">${fmt.num(big[0])}</div>
          </div>
          <div>
            <div class="tiny faint">${esc(sub[1])}</div>
            <div class="strong" style="font-size:21px;line-height:1.2">${fmt.num(sub[0])}</div>
          </div>
        </div>
        <div class="col" style="gap:12px">
          ${rows.map((r) => {
            const pct = Math.max(0, Math.min(100, Number(r.ratio) || 0));
            const tone = r.invert
              ? (pct > 15 ? "red" : "green")
              : (pct > 85 ? "amber" : "green");
            return `<div>
              <div class="row between tiny" style="margin-bottom:5px;gap:8px">
                <span class="faint">${esc(r.label)}</span>
                <span class="strong nowrap">${r.value}</span>
              </div>
              <div class="bar ${tone}"><i style="width:${pct.toFixed(1)}%"></i></div>
            </div>`;
          }).join("")}
        </div>
      </div>
    </div>`;
}