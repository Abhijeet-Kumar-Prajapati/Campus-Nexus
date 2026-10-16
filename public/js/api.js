// ============================================================================
//  API client.
//
//  Security responsibilities:
//   • attaches the signed CSRF token to every unsafe request
//   • stamps outbound payloads so the server can spot bot-speed submissions
//   • surfaces 429 Retry-After so the UI can show a real countdown
//   • never stores credentials in localStorage/sessionStorage
// ============================================================================

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Read the double-submit CSRF cookie (it is intentionally not HttpOnly). */
function csrfToken() {
  const hit = document.cookie.split("; ").find((c) => c.startsWith("cnx_csrf="));
  return hit ? decodeURIComponent(hit.slice("cnx_csrf=".length)) : null;
}

async function request(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  if (UNSAFE.has(method)) {
    const token = csrfToken();
    if (token) headers["X-CSRF-Token"] = token;
  }

  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",          // never send cookies cross-origin
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw Object.assign(new Error("Cannot reach the server — is it still running?"), { status: 0 });
  }

  let data = {};
  try { data = await res.json(); } catch { /* empty body */ }

  if (!res.ok) {
    const err = Object.assign(new Error(data.error ?? `Request failed (${res.status})`), {
      status: res.status,
      requiresAuth: !!data.requiresAuth,
      retryAfter: data.retryAfter ?? Number(res.headers.get("Retry-After")) ?? 0,
      limited: !!data.limited,
      csrf: !!data.csrf,
    });
    // A rejected CSRF token usually means the page has been open a long time.
    if (err.csrf) window.dispatchEvent(new CustomEvent("cnx:csrf-expired"));
    throw err;
  }
  return data;
}

const qs = (params) => {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) u.set(k, v);
  const s = u.toString();
  return s ? `?${s}` : "";
};

export const api = {
  /* ------------------------------------------------------------- system -- */
  health:     ()             => request("GET", "/api/system/health"),
  dashboard:  ()             => request("GET", "/api/system/dashboard"),
  search:     (q)            => request("GET", "/api/system/search" + qs({ q })),
  activity:   (limit = 30)  => request("GET", "/api/system/activity" + qs({ limit })),

  /* --------------------------------------------------------------- auth -- */
  // `_t` must be the moment the sign-in form was RENDERED, not the moment it
  // was submitted. The server refuses anything under 1.2s, so stamping it here
  // left an elapsed of roughly zero and every real sign-in came back 429
  // "Rate limited" - the API worked, the app did not. showLogin() passes the
  // render timestamp.
  login:      (username, password, hp = "", renderedAt = Date.now()) =>
                 request("POST", "/api/auth/login", { username, password, hp, _t: renderedAt }),
  logout:     ()             => request("POST", "/api/auth/logout", {}),
  me:         ()             => request("GET", "/api/auth/me"),
  changePassword: (current, next) => request("POST", "/api/auth/change-password", { current, next }),
  checkPassword:  (password)       => request("POST", "/api/auth/password-check", { password }),
  users:      ()             => request("GET", "/api/auth/users"),
  unlockUser: (id)           => request("POST", `/api/auth/users/${id}/unlock`, {}),

  /* ----------------------------------------------------------- security -- */
  posture:    ()             => request("GET", "/api/security/posture"),
  secEvents:  (limit = 60)   => request("GET", "/api/security/events" + qs({ limit })),
  chain:      ()             => request("GET", "/api/security/chain"),
  chainBlocks:()             => request("GET", "/api/security/chain/blocks"),
  secReset:   ()             => request("POST", "/api/security/reset", {}),
  revokeAll:  ()             => request("POST", "/api/security/revoke-sessions", {}),

  /* ------------------------------------------------------------ library -- */
  libStats:      ()          => request("GET", "/api/library/stats"),
  books:         (q, category) => request("GET", "/api/library/books" + qs({ q, category })),
  bookCategories:()          => request("GET", "/api/library/categories"),
  addBook:       (b)        => request("POST", "/api/library/books", b),
  editBook:      (id, b)    => request("PUT", `/api/library/books/${id}`, b),
  removeBook:    (id)       => request("DELETE", `/api/library/books/${id}`),
  loans:         (status)   => request("GET", "/api/library/loans" + qs({ status })),
  issueBook:     (b)        => request("POST", "/api/library/loans", b),
  returnBook:    (id)       => request("POST", `/api/library/loans/${id}/return`, {}),

  /* -------------------------------------------------------------- store -- */
  storeStats:      ()        => request("GET", "/api/store/stats"),
  products:        (q, category) => request("GET", "/api/store/products" + qs({ q, category })),
  productCategories:()       => request("GET", "/api/store/categories"),
  lowStock:        ()        => request("GET", "/api/store/lowstock"),
  addProduct:      (p)       => request("POST", "/api/store/products", p),
  editProduct:     (id, p)   => request("PUT", `/api/store/products/${id}`, p),
  archiveProduct:  (id)      => request("DELETE", `/api/store/products/${id}`),
  restock:         (id, add) => request("POST", `/api/store/products/${id}/restock`, { add }),
  bills:           (q, from, to) => request("GET", "/api/store/bills" + qs({ q, from, to })),
  bill:            (id)      => request("GET", `/api/store/bills/${id}`),
  makeBill:        (b)       => request("POST", "/api/store/bills", b),
  analytics:       (days)    => request("GET", "/api/store/analytics" + qs({ days })),

  /* ------------------------------------------------------------- arcade -- */
  arcadeStats:  ()          => request("GET", "/api/arcade/stats"),
  leaderboard:  (game)      => request("GET", "/api/arcade/leaderboard" + qs({ game })),
  saveScore:    (s)         => request("POST", "/api/arcade/score", s),
};