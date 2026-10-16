// ============================================================================
//  Rate limiting — sliding-window buckets with exponential backoff.
//
//  Design notes
//  ------------
//  * Buckets are keyed by `tier:ip` so a flood of cheap GETs can never consume
//    the strict authentication budget, and vice versa.
//  * Every trip multiplies that key's window (1m → 2m → 4m … capped), so
//    repeatedly hammering the login form buys progressively longer lockouts.
//  * Responses carry the standard X-RateLimit-* trio plus Retry-After, which
//    lets the UI show an accurate countdown instead of guessing.
// ============================================================================
import { CONFIG } from "./config.js";

/** tier -> ip -> { hits: number[], windowMs, trips, blockedUntil } */
const buckets = new Map();
const offenders = new Map(); // tier:ip -> trip count, for backoff math

const now = () => Date.now();

function keyFor(tier, ip) {
  return `${tier}:${ip}`;
}

/** Reset a key's window so the next hit starts clean (called after success). */
function prune(bucket, windowMs) {
  const cutoff = now() - windowMs;
  while (bucket.hits.length && bucket.hits[0] <= cutoff) bucket.hits.shift();
}

/** Cleanup so abandoned IPs do not leak memory. */
let lastSweep = now();
function sweep() {
  if (now() - lastSweep < 60_000) return;
  lastSweep = now();
  for (const [k, b] of buckets) {
    prune(b, b.windowMs);
    if (!b.hits.length && (!b.blockedUntil || b.blockedUntil < now())) {
      buckets.delete(k);
      offenders.delete(k);
    }
  }
}

export function consume(tier, ip, cost = 1) {
  sweep();
  const cfg = CONFIG.limits[tier] ?? CONFIG.limits.global;
  const key = keyFor(tier, ip);

  let bucket = buckets.get(key);
  if (!bucket) {
    bucket = { hits: [], windowMs: cfg.windowMs, trips: 0, blockedUntil: 0 };
    buckets.set(key, bucket);
  }

  // Progressive backoff: each trip window grows up to the configured cap.
  const trips = offenders.get(key) ?? 0;
  if (trips > 0) {
    const grown = Math.min(
      CONFIG.backoff.maxWindowMs,
      cfg.windowMs * CONFIG.backoff.multiplier ** Math.min(trips, 8)
    );
    bucket.windowMs = grown;
  }

  prune(bucket, bucket.windowMs);

  /* ---- already locked out? ---- */
  if (bucket.blockedUntil > now()) {
    return {
      allowed: false,
      tier,
      retryAfter: Math.ceil((bucket.blockedUntil - now()) / 1000),
      remaining: 0,
      limit: cfg.max,
      reset: Math.ceil((bucket.blockedUntil - now()) / 1000),
      locked: true,
    };
  }

  if (bucket.hits.length + cost > cfg.max) {
    // Trip the breaker.
    bucket.trips += 1;
    offenders.set(key, (offenders.get(key) ?? 0) + 1);
    const cooldown = Math.min(bucket.windowMs, Math.ceil(bucket.windowMs / 2));
    bucket.blockedUntil = now() + cooldown;
    bucket.hits = [];
    return {
      allowed: false,
      tier,
      retryAfter: Math.ceil(cooldown / 1000),
      remaining: 0,
      limit: cfg.max,
      reset: Math.ceil(cooldown / 1000),
      locked: true,
      tripped: true,
    };
  }

  for (let i = 0; i < cost; i++) bucket.hits.push(now());
  const oldest = bucket.hits[0] ?? now();

  return {
    allowed: true,
    tier,
    remaining: Math.max(0, cfg.max - bucket.hits.length),
    limit: cfg.max,
    reset: Math.max(0, Math.ceil((oldest + bucket.windowMs - now()) / 1000)),
    locked: false,
  };
}

/** Clear a bucket — called after a *successful* login so honest users recover. */
export function reset(tier, ip) {
  const key = keyFor(tier, ip);
  buckets.delete(key);
  offenders.delete(key);
}

/** Introspection for the security dashboard. */
export function snapshot() {
  sweep();
  const nowTs = now();
  const active = [];
  for (const [k, b] of buckets) {
    const locked = b.blockedUntil > nowTs;
    const [tier, ip] = k.split(":");
    active.push({
      tier,
      ip,
      used: b.hits.length,
      limit: CONFIG.limits[tier]?.max ?? CONFIG.limits.global.max,
      windowMs: b.windowMs,
      trips: offenders.get(k) ?? 0,
      locked,
      retryAfter: locked ? Math.ceil((b.blockedUntil - nowTs) / 1000) : 0,
    });
  }
  active.sort((a, b) => Number(b.locked) - Number(a.locked) || b.used - a.used);
  return {
    totalKeys: buckets.size,
    lockedKeys: active.filter((a) => a.locked).length,
    blocked: active.filter((a) => a.locked).length,
    active: active.slice(0, 25),
  };
}

/** Drop everything — used by the test suite. */
export function _resetAll() {
  buckets.clear();
  offenders.clear();
}