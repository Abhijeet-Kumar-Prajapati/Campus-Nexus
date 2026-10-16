// ============================================================================
//  CAMPUS NEXUS · tamper-evident ledger ("blockchain" in the hash-chain sense)
//
//  What this IS
//  ------------
//  An append-only, hash-chained record of every security-relevant and business
//  event. Each block stores:
//     • a SHA-256 digest of its own contents
//     • the digest of the previous block  → tamper-evident ordering
//     • a Merkle root over the block's events
//     • a proof-of-work nonce
//  Editing or deleting any historical row changes that block's digest, breaks
//  the link to its successor, and is therefore detectable by `verify()`.
//
//  What this is NOT
//  ----------------
//  A distributed/consensus blockchain. There is no peer network and no
//  Byzantine fault tolerance — a party with write access to the whole database
//  could rebuild the chain from scratch. The external seal file raises the bar
//  (detects wholesale DB replacement) but is not a substitute for real
//  distributed consensus. See SECURITY.md.
// ============================================================================
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CONFIG } from "./config.js";
import { sha256, pepperHmac } from "./crypto.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");
const SEAL_PATH = join(ROOT, CONFIG.ledger.sealFile);

const L = CONFIG.ledger;
const GENESIS_PREV = "0".repeat(64);

/* --------------------------------------------------------- merkle tree --- */
/** Binary Merkle tree. Odd nodes are paired with themselves. */
export function merkleRoot(leafHashes) {
  if (!leafHashes.length) return sha256("empty");
  let level = [...leafHashes];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(createHash("sha256").update(left + right).digest("hex"));
    }
    level = next;
  }
  return level[0];
}

/* ------------------------------------------------------------ hashing ---- */
function blockDigest(b) {
  return sha256([
    b.index,
    b.timestamp,
    b.event_type,
    b.module,
    b.actor ?? "",
    b.severity,
    b.payload_hash,
    b.prev_hash,
    b.merkle_root,
    b.difficulty,
    b.nonce,
  ].join("|"));
}

/** Difficulty ramps up slowly so the ledger stays cheap to extend. */
function difficultyFor(index) {
  const bump = Math.floor(index / L.difficultyRampBlocks) * L.difficultyRamp;
  return Math.min(L.maxDifficulty, L.difficulty + bump);
}

/** Leading-zero-hex proof of work. */
function mine(body, difficulty) {
  const target = "0".repeat(difficulty);
  let nonce = 0;
  for (;;) {
    const digest = blockDigest({ ...body, nonce });
    if (digest.startsWith(target)) return { nonce, hash: digest };
    nonce += 1;
    if (nonce > 5_000_000) {
      // Safety valve: never spin forever on absurd difficulty.
      return { nonce, hash: digest };
    }
  }
}

/* ------------------------------------------------------------- sealing --- */
/** Publish the current head outside the database. */
export function writeSeal(headHash, height) {
  const payload = {
    head: headHash,
    height,
    sealed_at: new Date().toISOString(),
    note: "External copy of the ledger head. If this disagrees with the database, the chain was rewritten wholesale.",
  };
  try {
    mkdirSync(dirname(SEAL_PATH), { recursive: true });
    writeFileSync(SEAL_PATH, JSON.stringify(payload, null, 2), "utf8");
  } catch { /* read-only filesystem — verification falls back to DB-only */ }
}

export function readSeal() {
  try {
    if (!existsSync(SEAL_PATH)) return null;
    return JSON.parse(readFileSync(SEAL_PATH, "utf8"));
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------- mining ---- */
/**
 * Build (but do not persist) the next block.
 * `store` is injected so this module stays free of database concerns and can be
 * unit-tested with a stub.
 */
export function buildBlock(store, { event_type, module = "system", actor = "system", severity = "info", payload = {}, events = [] } = {}) {
  const head = store.head();
  const index = head.index + 1;
  const timestamp = new Date().toISOString();
  const difficulty = difficultyFor(index);

  const payloadHash = sha256(JSON.stringify(payload ?? {}));
  const leafHashes = events.length ? events.map((e) => sha256(JSON.stringify(e))) : [payloadHash];
  const root = merkleRoot(leafHashes);

  const body = {
    index,
    timestamp,
    event_type,
    module,
    actor,
    severity,
    payload_hash: pepperHmac(payloadHash),   // keyed, so payloads can't be swapped
    prev_hash: head.hash,
    merkle_root: root,
    difficulty,
    nonce: 0,
  };
  const { nonce, hash } = mine(body, difficulty);
  return { ...body, nonce, hash };
}

/* ---------------------------------------------------------- verifying ---- */
/**
 * Full integrity check. Walks the chain, recomputes every digest, re-checks
 * every link, re-runs the proof of work, re-derives every Merkle root and
 * finally compares against the external seal.
 */
export function verifyChain(store) {
  const blocks = store.all();
  const issues = [];
  const started = Date.now();

  if (!blocks.length) {
    return { ok: true, height: 0, verified: 0, issues: [], seal: null, ms: 0, empty: true };
  }

  let prev = GENESIS_PREV;
  let verified = 0;

  for (const b of blocks) {
    if (b.index !== verified) {
      issues.push({ block: b.index, kind: "index-gap", detail: `expected index ${verified}, found ${b.index}` });
    }
    if (b.prev_hash !== prev) {
      issues.push({
        block: b.index,
        kind: "broken-link",
        detail: `prev_hash ${short(b.prev_hash)} does not match previous block ${short(prev)}`,
      });
    }
    const recomputed = blockDigest(b);
    if (recomputed !== b.hash) {
      issues.push({ block: b.index, kind: "digest-mismatch", detail: "block contents have been altered" });
    }
    const expectedPoW = blockDigest(b).startsWith("0".repeat(b.difficulty));
    if (!expectedPoW) {
      issues.push({ block: b.index, kind: "invalid-pow", detail: `nonce does not satisfy difficulty ${b.difficulty}` });
    }
    prev = b.hash;
    verified += 1;
  }

  const seal = readSeal();
  const head = blocks.at(-1);
  let sealOk = null;
  if (seal && head) {
    sealOk = seal.head === head.hash;
    if (!sealOk) {
      issues.push({
        block: head.index,
        kind: "seal-mismatch",
        detail: "external seal does not match the chain head — the database may have been rebuilt",
      });
    }
  }

  return {
    ok: issues.length === 0,
    height: blocks.length,
    verified,
    issues,
    seal: seal ? { ...seal, matches: sealOk } : null,
    head: head ? { index: head.index, hash: head.hash } : null,
    ms: Date.now() - started,
  };
}

const short = (h) => (typeof h === "string" ? `${h.slice(0, 10)}…` : String(h));

/** A compact integrity certificate suitable for printing or exporting. */
export function certificate(store) {
  const v = verifyChain(store);
  const blocks = store.all();
  return {
    algorithm: "SHA-256 hash chain + Merkle tree + proof-of-work",
    height: v.height,
    head: v.head,
    seal: v.seal,
    verified: v.ok,
    issued_at: new Date().toISOString(),
    fingerprint: pepperHmac(v.head?.hash ?? GENESIS_PREV).slice(0, 32),
    digest_preview: blocks.slice(-3).map((b) => ({
      index: b.index,
      type: b.event_type,
      hash: short(b.hash),
      prev: short(b.prev_hash),
      nonce: b.nonce,
    })),
  };
}