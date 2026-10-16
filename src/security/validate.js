// ============================================================================
//  Input validation & sanitisation.
//  A tiny declarative schema validator: no dependencies, fail-closed.
// ============================================================================
import { CONFIG } from "./config.js";

/* --------------------------------------------------------------- types --- */
export const V = {
  string: (opts = {}) => ({
    kind: "string",
    min: opts.min ?? 0,
    max: opts.max ?? 200,
    pattern: opts.pattern ?? null,
    patternHint: opts.patternHint ?? null,
    trim: opts.trim ?? true,
    lowercase: opts.lowercase ?? false,
    allow: opts.allow ?? null,
  }),
  int: (opts = {}) => ({ kind: "int", min: opts.min ?? -Infinity, max: opts.max ?? Infinity, fallback: opts.fallback ?? null }),
  number: (opts = {}) => ({ kind: "number", min: opts.min ?? -Infinity, max: opts.max ?? Infinity, fallback: opts.fallback ?? 0 }),
  bool: (opts = {}) => ({ kind: "bool", fallback: opts.fallback ?? false }),
  enum: (values, opts = {}) => ({ kind: "enum", values, fallback: opts.fallback ?? null }),
  array: (of, opts = {}) => ({ kind: "array", of, max: opts.max ?? 100, min: opts.min ?? 0 }),
  object: (shape, opts = {}) => ({ kind: "object", shape, strict: opts.strict ?? false }),
};

const FORBIDDEN = new Set(CONFIG.request.forbiddenKeys);

/**
 * Validate `input` against `schema`.
 * Returns { ok, value, errors }. Fails closed: any unknown key under a strict
 * schema, any forbidden key, or any type mismatch is a hard error.
 */
export function validate(input, schema) {
  const errors = [];
  const value = walk(input, schema, "body", errors);
  return { ok: errors.length === 0, value, errors };
}

function walk(input, rule, path, errors) {
  if (rule === null || rule === undefined) return null;

  switch (rule.kind) {
    case "string": {
      let v = input;
      if (v === null || v === undefined) v = "";
      if (typeof v !== "string") { errors.push(`${path} must be text`); return ""; }
      if (rule.trim) v = v.trim();
      if (rule.lowercase) v = v.toLowerCase();
      // Strip C0 control characters (tab, newline and carriage-return are
      // kept because they are legitimate in text) plus DEL. Written with
      // explicit escapes: a literal control byte in source is invisible and
      // trivially corrupted by editors and copy-paste.
      v = v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
      if (v.length < rule.min) errors.push(`${path} must be at least ${rule.min} characters`);
      if (v.length > rule.max) errors.push(`${path} must be at most ${rule.max} characters`);
      if (rule.allow && !rule.allow.includes(v)) errors.push(`${path} is not an allowed value`);
      if (rule.pattern && !rule.pattern.test(v)) errors.push(rule.patternHint ?? `${path} has an invalid format`);
      return v;
    }
    case "int": {
      // A missing value is not a validation error — it simply takes the
      // fallback. Without this, every optional numeric field would fail.
      if (input === null || input === undefined || input === "") return rule.fallback;
      const n = Number(input);
      if (!Number.isFinite(n)) { errors.push(`${path} must be a whole number`); return rule.fallback; }
      const i = Math.trunc(n);
      if (i < rule.min) errors.push(`${path} must be at least ${rule.min}`);
      if (i > rule.max) errors.push(`${path} must be at most ${rule.max}`);
      return Math.min(Math.max(i, rule.min), rule.max);
    }
    case "number": {
      if (input === null || input === undefined || input === "") return rule.fallback;
      const n = Number(input);
      if (!Number.isFinite(n)) { errors.push(`${path} must be a number`); return rule.fallback; }
      if (n < rule.min) errors.push(`${path} must be at least ${rule.min}`);
      if (n > rule.max) errors.push(`${path} must be at most ${rule.max}`);
      return Math.min(Math.max(n, rule.min), rule.max);
    }
    case "bool": {
      if (typeof input === "boolean") return input;
      if (input === "true" || input === 1 || input === "1") return true;
      if (input === "false" || input === 0 || input === "0" || input === undefined || input === null) return rule.fallback;
      return Boolean(input);
    }
    case "enum": {
      const raw = input ?? "";
      const v = String(raw);
      // An omitted value takes the fallback silently. An explicit but invalid
      // value is always an error, even when a fallback exists.
      if (v === "" && rule.fallback !== null) return rule.fallback;
      if (!rule.values.includes(v)) { errors.push(`${path} must be one of: ${rule.values.join(", ")}`); return rule.fallback; }
      return v;
    }
    case "array": {
      if (!Array.isArray(input)) { errors.push(`${path} must be a list`); return []; }
      if (input.length > rule.max) { errors.push(`${path} may contain at most ${rule.max} items`); return []; }
      if (input.length < rule.min) { errors.push(`${path} needs at least ${rule.min} items`); return []; }
      return input.slice(0, rule.max).map((item, i) => walk(item, rule.of, `${path}[${i}]`, errors));
    }
    case "object": {
      if (input === null || typeof input !== "object" || Array.isArray(input)) {
        errors.push(`${path} must be an object`); return {};
      }
      const out = {};
      for (const [k, v] of Object.entries(input)) {
        if (FORBIDDEN.has(k)) { errors.push(`${path}.${k} is not an accepted field`); continue; }
        if (rule.strict && !(k in rule.shape)) { errors.push(`${path}.${k} is not an accepted field`); continue; }
      }
      for (const [key, sub] of Object.entries(rule.shape)) {
        out[key] = walk(input[key], sub, `${path}.${key}`, errors);
      }
      return out;
    }
    default:
      // Fail CLOSED. An unrecognised rule means a developer mistake, and
      // silently returning the input would turn a typo into a validation
      // bypass.
      errors.push(`${path}: unrecognised validation rule`);
      return null;
  }
}

/* ----------------------------------------------------- common shorthands -- */
export const shortText   = (max = 120) => V.string({ max });
export const longText    = (max = 400) => V.string({ max });
export const identifier  = (max = 40)  => V.string({ max, pattern: /^[A-Za-z0-9._-]+$/, patternHint: "only letters, digits, dot, underscore and hyphen" });
export const username    = () => V.string({ min: 3, max: 32, lowercase: true, pattern: /^[a-z0-9._-]+$/, patternHint: "3–32 characters: lowercase letters, digits, dot, underscore, hyphen" });
export const safeText    = (max = 200) => V.string({ max, pattern: /^[^<>]*$/, patternHint: "angle brackets are not allowed" });
export const money       = (max = 10_000_000) => V.number({ min: 0, max, fallback: 0 });
export const qty         = (max = 999) => V.int({ min: 1, max, fallback: 1 });
export const isoDate     = () => V.string({ max: 10, pattern: /^\d{4}-\d{2}-\d{2}$/, patternHint: "date must be YYYY-MM-DD" });

/* ------------------------------------------------------- SQL injection ---- */
/**
 * Defence in depth — and this one is actually wired in (http.js#readJson scans
 * every parsed body). Every query in this app uses bound parameters, so a match
 * cannot inject anything; it means injection-shaped input reached us, which is
 * precisely what an operator needs to see in the Security Centre.
 */
const SQL_TRIPWIRE = /(\b(union\s+select|insert\s+into|drop\s+table|delete\s+from|exec\s*\(|xp_cmdshell|sleep\s*\(|benchmark\s*\()\b)|(--\s*\$)|(\/\*)|(;\s*drop\s)/i;

/** Depth-limited scan of any JSON value; returns the first suspicious string. */
export function findInjection(value, depth = 0) {
  if (depth > 6 || value === null || value === undefined) return null;
  if (typeof value === "string") return SQL_TRIPWIRE.test(value) ? value.slice(0, 120) : null;
  if (typeof value !== "object") return null;
  for (const v of Array.isArray(value) ? value : Object.values(value)) {
    const hit = findInjection(v, depth + 1);
    if (hit) return hit;
  }
  return null;
}

export const looksLikeSqlInjection = (value) => findInjection(value) !== null;
