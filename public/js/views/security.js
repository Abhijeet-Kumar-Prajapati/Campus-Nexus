// ============================================================================
//  Security Centre — the self-monitoring surface.
//  Shows which protections are live, the live threat picture, the state of
//  every rate-limit bucket, active sessions, and the tamper-evident ledger.
// ============================================================================
import { api } from "../api.js";
import { icon } from "../icons.js";
import { esc, fmt, toast, confirmDialog, emptyState, on } from "../ui.js";
import { state } from "../app.js";

const SEV = {
  info:     { label: "Info",     cls: "info" },
  warn:     { label: "Warning",  cls: "warn" },
  high:     { label: "High",     cls: "danger" },
  critical: { label: "Critical", cls: "danger" },
};

const LAYER = {
  identity: { label: "Identity & access", ic: "users",   colour: "var(--violet)" },
  session:  { label: "Session safety",    ic: "clock",   colour: "var(--cyan)" },
  request:  { label: "Request integrity", ic: "filter",  colour: "var(--blue)" },
  network:  { label: "Traffic control",   ic: "trend",   colour: "var(--green)" },
  response: { label: "Browser hardening",ic: "layers",  colour: "var(--pink)" },
  audit:    { label: "Audit & evidence",  ic: "receipt", colour: "var(--amber)" },
};

export async function securityView(host) {
  if (!state.user) {
    host.innerHTML = `
      <div class="view"><div class="card"><div class="card-body">
        <div class="alert warn">${icon("lock")} Sign in to view the security centre.</div>
      </div></div></div>`;
    return;
  }

  host.innerHTML = `<div class="view"><div class="card"><div class="card-body">
    <div class="skeleton" style="height:180px"></div></div></div></div>`;

  const p = await api.posture();

  const { events, chain, limiter, sessions, accounts, config, runtime } = p;
  const postureTone =
    events.posture === "nominal" ? "ok" : events.posture === "guarded" ? "info" :
    events.posture === "elevated" ? "warn" : "danger";

  host.innerHTML = `
    <div class="view">

      <!-- ── headline ────────────────────────────────────────────── -->
      <div class="card mb" style="overflow:hidden">
        <div class="card-body" style="display:grid;grid-template-columns:1fr auto;gap:24px;align-items:center">
          <div>
            <div class="row" style="gap:9px;margin-bottom:10px">
              <span class="badge ${postureTone}">${icon("shield")} Posture: ${esc(events.posture)}</span>
              <span class="badge ok">${icon("checkCircle")} ${p.controlCount} controls active</span>
              <span class="badge ${chain.verified ? "ok" : "danger"}">
                ${icon(chain.verified ? "checkCircle" : "alert")}
                Ledger ${chain.verified ? "intact" : "BROKEN"} · ${chain.height} blocks
              </span>
            </div>
            <h2 style="font-size:23px;letter-spacing:-.3px;margin-bottom:6px">Security Centre</h2>
            <p class="muted" style="max-width:66ch">
              Every protection below is enforced server-side. Rate limiting, CSRF verification,
              session binding, password hashing and the tamper-evident audit chain are all live
              and reporting into this page.
            </p>
          </div>
          <div class="row" style="gap:9px">
            <button class="btn btn-ghost" id="secRevoke">${icon("logout")} Revoke all sessions</button>
            <button class="btn btn-danger" id="secReset">${icon("refresh")} Clear lockouts</button>
          </div>
        </div>
      </div>

      <!-- ── threat counters ─────────────────────────────────────── -->
      <div class="stat-grid">
        ${stat("var(--green)", "checkCircle", "Controls active", p.controlCount, "layers: identity → audit", 0)}
        ${stat("var(--amber)", "alert", "Events · 24 h", events.total, `${events.uniqueIps} distinct IPs`, 0)}
        ${stat("var(--red)", "shield", "High + critical", events.bySeverity.high + events.bySeverity.critical, "needs attention", 0)}
        ${stat("var(--violet)", "lock", "Accounts locked", accounts.locked ?? 0, `${accounts.active ?? 0} active of ${accounts.total}`, 0)}
        ${stat("var(--cyan)", "clock", "Live sessions", sessions.live, `${sessions.uniqueUsers} user(s)`, 0)}
        ${stat("var(--pink)", "trend", "Rate-limit blocks", limiter.blocked, `${limiter.totalKeys} tracked keys`, 0)}
      </div>

      <!-- ── controls ────────────────────────────────────────────── -->
      <div class="card mb">
        <div class="card-head">
          <h4>Active protections</h4><span class="spacer"></span>
          <span class="section-sub">grouped by defence layer</span>
        </div>
        <div class="card-body">
          ${Object.entries(LAYER).map(([key, layer]) => {
            const items = p.controls.filter((c) => c.layer === key);
            if (!items.length) return "";
            return `
              <div class="mb">
                <div class="row" style="gap:8px;margin-bottom:10px">
                  <div class="stat-icon" style="width:26px;height:26px;background:color-mix(in oklab, ${layer.colour} 18%, transparent);color:${layer.colour}">
                    ${icon(layer.ic)}
                  </div>
                  <strong class="small">${esc(layer.label)}</strong>
                  <span class="badge">${items.length}</span>
                </div>
                <div class="grid-3" style="gap:11px">
                  ${items.map((c) => `
                    <div class="control">
                      <div class="control-head">
                        ${icon("check")}
                        <strong>${esc(c.name)}</strong>
                      </div>
                      <p>${esc(c.detail)}</p>
                    </div>`).join("")}
                </div>
              </div>`;
          }).join("")}
        </div>
      </div>

      <div class="grid-2 mb">
        <!-- ── rate limits ──────────────────────────────────────── -->
        <div class="card">
          <div class="card-head"><h4>Rate-limit buckets</h4><span class="spacer"></span>
            <span class="badge ${limiter.blocked ? "warn" : "ok"}">${limiter.blocked} blocked</span></div>
          <div class="card-body" style="padding:0">
            <div class="table-wrap">
              <table class="data">
                <thead><tr><th>Tier</th><th>Client</th><th class="num">Used</th><th class="num">Limit</th><th>State</th></tr></thead>
                <tbody>
                  ${Object.entries(config.limits).map(([tier, cfg]) => {
                    const used = limiter.active.filter((a) => a.tier === tier);
                    const total = used.reduce((s, a) => s + a.used, 0);
                    const locked = used.some((a) => a.locked);
                    const pct = Math.min(100, (total / cfg.max) * 100);
                    return `<tr>
                      <td><span class="badge violet">${esc(tier)}</span></td>
                      <td class="mono tiny">${used.length ? used.map((a) => esc(a.ip)).join(", ") : "—"}</td>
                      <td class="num">${total}</td>
                      <td class="num faint">${cfg.max} / ${Math.round(cfg.windowMs / 1000)}s</td>
                      <td>
                        <div class="bar ${pct > 80 ? "amber" : "green"}" style="min-width:90px">
                          <i style="width:${pct}%"></i>
                        </div>
                        ${locked ? `<div class="tiny" style="color:var(--red);margin-top:3px">locked</div>` : ""}
                      </td>
                    </tr>`;
                  }).join("")}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- ── event stream ─────────────────────────────────────── -->
        <div class="card">
          <div class="card-head"><h4>Security events</h4><span class="spacer"></span>
            <span class="badge">last ${events.windowHours} h</span></div>
          <div class="card-body tight" style="max-height:420px;overflow-y:auto">
            <div class="feed">
              ${(await api.secEvents(60)).events.length
                ? (await api.secEvents(60)).events.map((e) => `
                    <div class="feed-item">
                      <div class="feed-icon" style="background:color-mix(in oklab, ${
                        e.severity === "critical" || e.severity === "high" ? "var(--red)" :
                        e.severity === "warn" ? "var(--amber)" : "var(--blue)"} 18%, transparent);color:${
                        e.severity === "critical" || e.severity === "high" ? "var(--red)" :
                        e.severity === "warn" ? "var(--amber)" : "var(--blue)"}">
                        ${icon(e.severity === "info" ? "info" : "alert")}
                      </div>
                      <div class="feed-text">
                        <strong class="mono" style="font-size:12px">${esc(e.event_type)}</strong>
                        <p title="${esc(e.detail)}">${esc(e.detail)}</p>
                      </div>
                      <div class="feed-time">${esc(fmt.timeAgo(e.created_at))}</div>
                    </div>`).join("")
                : emptyState("No security events recorded yet", "shield")}
            </div>
          </div>
        </div>
      </div>

      <!-- ── ledger ─────────────────────────────────────────────── -->
      <div class="card mb">
        <div class="card-head">
          <div class="stat-icon" style="background:color-mix(in oklab, var(--amber) 18%, transparent);color:var(--amber)">${icon("receipt")}</div>
          <div style="flex:1;min-width:0">
            <h4>Tamper-evident audit chain</h4>
            <div class="tiny faint">SHA-256 hash chain · Merkle tree · proof-of-work · external seal</div>
          </div>
          <span class="badge ${chain.verified ? "ok" : "danger"}">${chain.verified ? "Verified" : "Compromised"}</span>
          <span class="badge">${chain.height} blocks</span>
          <button class="btn btn-sm btn-ghost" id="chainRefresh">${icon("refresh")} Re-verify</button>
        </div>
        <div class="card-body">
          <div class="grid-3 mb" style="gap:12px">
            ${kv("Algorithm", chain.verified ? "Chain intact" : "Broken", chain.verified ? "ok" : "danger")}
            ${kv("Head hash", chain.head ? chain.head.hash.slice(0, 24) + "…" : "—")}
            ${kv("External seal", chain.seal ? (chain.seal.matches ? "Matches head" : "MISMATCH") : "No seal file", chain.seal ? (chain.seal.matches ? "ok" : "danger") : null)}
            ${kv("Verification time", `${chain.ms} ms`)}
          </div>

          ${chain.issues.length ? `
            <div class="alert danger" style="margin-bottom:12px">${icon("alert")}
              <span><strong>${chain.issues.length} integrity issue(s):</strong>
              ${chain.issues.slice(0, 3).map((i) => `block ${i.block} — ${esc(i.detail)}`).join("; ")}</span>
            </div>` : `
            <div class="alert ok" style="margin-bottom:12px">${icon("checkCircle")}
              <span>Every block hash, link and proof-of-work verifies. No history has been altered.</span>
            </div>`}

          <div id="chainBlocks"><div class="skeleton" style="height:200px"></div></div>
        </div>
      </div>

      <div class="grid-2">
        <!-- ── sessions ─────────────────────────────────────────── -->
        <div class="card">
          <div class="card-head"><h4>Active sessions</h4><span class="spacer"></span>
            <span class="badge">${sessions.live} live</span></div>
          <div class="card-body tight">
            ${sessions.details.length ? `<div class="feed">${sessions.details.map((s) => `
              <div class="feed-item">
                <div class="feed-icon" style="background:color-mix(in oklab, var(--violet) 18%, transparent);color:var(--violet)">${icon("users")}</div>
                <div class="feed-text">
                  <strong>${esc(s.user)} <span class="badge">${esc(s.role)}</span></strong>
                  <p>idle ${s.idleSeconds}s · age ${s.ageMinutes}m${s.anomalies ? ` · ${s.anomalies} anomaly` : ""}</p>
                </div>
              </div>`).join("")}</div>`
              : emptyState("No active sessions", "clock")}
          </div>
        </div>

        <!-- ── configuration ────────────────────────────────────── -->
        <div class="card">
          <div class="card-head"><h4>Hardening configuration</h4></div>
          <div class="card-body">
            <div class="score-row"><span>Password hashing</span><strong>${esc(config.password.algorithm)} (memory-hard)</strong></div>
            <div class="score-row"><span>scrypt cost (N / r / p)</span><strong>${config.password.N} · ${config.password.r} · ${config.password.p}</strong></div>
            <div class="score-row"><span>Memory per hash</span><strong>${config.password.memoryMiB} MiB</strong></div>
            <div class="score-row"><span>HMAC pepper</span><strong class="${config.password.peppered ? "ok" : ""}">${config.password.peppered ? "active (outside DB)" : "none"}</strong></div>
            <div class="score-row"><span>Session idle timeout</span><strong>${config.session.idleMinutes} min</strong></div>
            <div class="score-row"><span>Absolute timeout</span><strong>${config.session.absoluteHours} h</strong></div>
            <div class="score-row"><span>Token rotation</span><strong>${config.session.rotationMinutes} min</strong></div>
            <div class="score-row"><span>Fingerprint binding</span><strong class="${config.session.bindToFingerprint ? "ok" : ""}">${config.session.bindToFingerprint ? "on" : "off"}</strong></div>
            <div class="score-row"><span>Cookie policy</span><strong>HttpOnly · SameSite=${config.session.sameSite}</strong></div>
            <div class="score-row"><span>Account lockout after</span><strong>${config.account.maxFailedLogins} failures</strong></div>
            <div class="score-row total"><span>Runtime</span><strong>Node ${runtime.node} · up ${Math.floor(runtime.uptimeSeconds / 60)}m · ${runtime.heapMb} MB heap</strong></div>
          </div>
        </div>
      </div>
    </div>`;

  /* ------------------------------------------------------------ wiring -- */
  const loadBlocks = async () => {
    const holder = host.querySelector("#chainBlocks");
    if (!holder) return;
    const { blocks } = await api.chainBlocks();
    holder.innerHTML = blocks.length ? `
      <div class="table-wrap"><table class="data">
        <thead><tr><th>#</th><th>Event</th><th>Actor</th><th>Nonce</th><th>Links to</th><th>Hash</th></tr></thead>
        <tbody>
          ${blocks.map((b) => `<tr>
            <td class="mono">${b.index}</td>
            <td>
              <div class="cell-main mono" style="font-size:12px">${esc(b.type)}</div>
              <div class="cell-sub">${esc(b.severity)} · ${esc(fmt.timeAgo(b.timestamp))}</div>
            </td>
            <td class="small">${esc(b.actor)}</td>
            <td class="mono tiny">${b.nonce}</td>
            <td class="mono tiny" title="${esc(b.prev)}">${esc(String(b.prev).slice(0, 12))}…</td>
            <td class="mono tiny" title="${esc(b.hash)}" style="color:var(--violet)">${esc(String(b.hash).slice(0, 12))}…</td>
          </tr>`).join("")}
        </tbody>
      </table></div>` : emptyState("No blocks yet", "receipt");
  };
  await loadBlocks();

  host.querySelector("#chainRefresh")?.addEventListener("click", async () => {
    await loadBlocks();
    toast("Chain re-verified", "success");
  });

  host.querySelector("#secReset")?.addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: "Clear all lockouts?",
      message: "Every rate-limit bucket is emptied and all locked accounts are unlocked. Administrators only.",
      confirmText: "Clear everything", danger: true,
    });
    if (!ok) return;
    try {
      const r = await api.secReset();
      toast(r.message, "success");
      setTimeout(() => location.reload(), 700);
    } catch (err) { toast(err.message, "error"); }
  });

  host.querySelector("#secRevoke")?.addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: "Revoke every session?",
      message: "All users — including you — will be signed out immediately. Use this if you suspect a compromise.",
      confirmText: "Revoke all", danger: true,
    });
    if (!ok) return;
    try {
      const r = await api.revokeAll();
      toast(r.message, "warn");
      setTimeout(() => location.reload(), 900);
    } catch (err) { toast(err.message, "error"); }
  });
}

/* ---------------------------------------------------------- fragments ---- */
function stat(accent, ic, label, value, foot) {
  return `
    <div class="stat" style="--accent:${accent}">
      <div class="stat-top"><div class="stat-icon">${icon(ic)}</div><div class="stat-label">${esc(label)}</div></div>
      <div class="stat-value">${fmt.num(value)}</div>
      <div class="stat-foot">${esc(foot)}</div>
    </div>`;
}

function kv(label, value, tone) {
  return `<div class="kv">
    <span class="tiny faint">${esc(label)}</span>
    <strong class="mono small ${tone === "ok" ? "ok-text" : tone === "danger" ? "danger-text" : ""}">${esc(value)}</strong>
  </div>`;
}