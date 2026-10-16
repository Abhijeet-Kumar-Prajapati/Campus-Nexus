// ============================================================================
//  Production build  →   npm run build
//
//  Produces public/dist/ : a hardened, minified copy of the frontend with
//  Subresource Integrity hashes wired into the HTML.
//
//  WHAT THIS IS FOR (and what it is not)
//  ------------------------------------
//  * It shrinks the payload and removes comments, so the shipped bundle is not
//    casually readable.
//  * SRI is the genuinely useful part: the browser computes a SHA-256 of every
//    script and CSS file and REFUSES to run one whose bytes changed after the
//    build. A tampered .js file on disk simply stops working.
//
//  It is NOT a security boundary. Anything the browser can execute, a user can
//  eventually read — that is a property of the web platform, not a bug to be
//  fixed by minifying. Real secrets live in SECURITY/ and never leave the
//  server (see SECURITY.md).
//
//  The readable original stays in public/ — that is the version you show a
//  teacher, and the one a reviewer can actually audit.
// ============================================================================
import {
  readdirSync, readFileSync, writeFileSync, mkdirSync, rmSync, existsSync, statSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname, extname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const SRC = join(ROOT, "public");
const OUT = join(SRC, "dist");

/* ------------------------------------------------------------- minify ---- */
/**
 * Conservative comment/whitespace stripper.
 *
 * Deliberately not an identifier-renaming minifier: renaming variables without
 * a full parser is how you ship broken JavaScript. This removes comments,
 * blank lines and indentation — a solid size win with no rename risk.
 *
 * It is string-aware, so a `//` inside a URL or a comment-looking substring in
 * a template literal is preserved.
 */
function minifyJs(code) {
  let out = "";
  let i = 0;
  const n = code.length;

  // Track whether a `/` starts a regex literal or is a division operator.
  let lastSignificant = "";

  while (i < n) {
    const ch = code[i];
    const next = code[i + 1];

    /* ---- string literals ------------------------------------------- */
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      out += ch; i++;
      while (i < n) {
        if (code[i] === "\\") { out += code[i] + (code[i + 1] ?? ""); i += 2; continue; }
        if (code[i] === quote) { out += quote; i++; break; }
        // Keep template-literal expressions intact.
        if (quote === "`" && code[i] === "$" && code[i + 1] === "{") {
          out += "${"; i += 2;
          let depth = 1;
          while (i < n && depth > 0) {
            if (code[i] === "{") depth++;
            else if (code[i] === "}") depth--;
            if (depth === 0) { out += "}"; i++; break; }
            out += code[i]; i++;
          }
          continue;
        }
        out += code[i]; i++;
      }
      lastSignificant = quote;
      continue;
    }

    /* ---- comments -------------------------------------------------- */
    if (ch === "/" && next === "/") {
      while (i < n && code[i] !== "\n") i++;            // drop to EOL
      continue;
    }
    if (ch === "/" && next === "*") {
      const end = code.indexOf("*/", i + 2);
      i = end === -1 ? n : end + 2;
      continue;
    }

    /* ---- whitespace ------------------------------------------------ */
    if (ch === "\n" || ch === "\r" || ch === " " || ch === "\t") {
      let j = i;
      let sawNewline = false;
      while (j < n && /\s/.test(code[j])) { if (code[j] === "\n") sawNewline = true; j++; }
      // Collapse a run to a single space; drop it entirely after a newline or
      // around a character where it cannot be syntactically required.
      const prev = out.at(-1) ?? "";
      const upcoming = code[j] ?? "";
      const needSpace = prev && upcoming &&
        !/[=+\-*/%<>!&|^,;?:(){}\[\]]/.test(prev) &&
        !/[=+\-*/%<>!&|^,;?:(){}\[\]]/.test(upcoming);
      if (sawNewline) { if (needSpace) out += " "; }
      else if (needSpace) out += " ";
      i = j;
      continue;
    }

    /* ---- everything else -------------------------------------------- */
    out += ch;
    if (!/\s/.test(ch)) lastSignificant = ch;
    i++;
  }

  return out.trim();
}

/** Strip CSS comments and collapse whitespace. Safe: no selector rewriting. */
function minifyCss(code) {
  return code
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\s*([{}:;,>~])\s*/g, "$1")
    .replace(/;\}/g, "}")
    .replace(/\s+/g, " ")
    .trim();
}

/* -------------------------------------------------------------- helpers -- */
function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === "dist") continue;
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

/** Rewrite relative `.js` specifiers so the minified modules still find each other. */
function rewriteImports(code) {
  return code.replace(/(from\s*["'])(\.{1,2}\/[^"']+?)(\.js)(["'])/g, "$1$2.min.js$4");
}

const sha384 = (buf) => `sha384-${createHash("sha384").update(buf).digest("base64")}`;

/* ---------------------------------------------------------------- build -- */
console.log("\n  Building production bundle → public/dist\n");

if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const files = walk(SRC);
const manifest = [];
let before = 0, after = 0;

for (const file of files) {
  const rel = relative(SRC, file);
  const ext = extname(file);

  if (ext !== ".js" && ext !== ".css") {
    // Static assets are copied verbatim.
    const dest = join(OUT, rel);
    mkdirSync(dirname(dest), { recursive: true });
    const buf = readFileSync(file);
    writeFileSync(dest, buf);
    continue;
  }

  const original = readFileSync(file);
  let content = original.toString("utf8");

  if (ext === ".js") content = rewriteImports(minifyJs(content));
  else content = minifyCss(content);

  const dest = join(OUT, rel.replace(/\.js$/, ".min.js").replace(/\.css$/, ".min.css"));
  mkdirSync(dirname(dest), { recursive: true });
  const built = Buffer.from(content, "utf8");
  writeFileSync(dest, built);

  before += original.length;
  after += built.length;
  manifest.push({
    // `source` is what index.html currently references; `path` is what we wrote.
    source: `/${rel.split("\\").join("/")}`,
    path: relative(OUT, dest).split("\\").join("/"),
    integrity: sha384(built),
    bytes: built.length,
  });
}

/* ---- index.html: point at the minified assets and add SRI -------------- */
let html = readFileSync(join(SRC, "index.html"), "utf8");

let wired = 0;
for (const entry of manifest) {
  if (entry.source === "/index.html") continue;
  const needle = `"${entry.source}"`;
  if (!html.includes(needle)) continue;
  html = html.replace(needle, `"./${entry.path}" integrity="${entry.integrity}"`);
  wired++;
}

// The noscript block describes the readable build, not the minified one.
html = html.replace(/<noscript>[\s\S]*?<\/noscript>/, "");

if (wired < manifest.length - 1) {
  console.warn(`  ! only ${wired} asset reference(s) rewired in index.html — check the paths`);
}

writeFileSync(join(OUT, "index.html"), html, "utf8");
writeFileSync(
  join(OUT, "manifest.json"),
  JSON.stringify({ builtAt: new Date().toISOString(), assets: manifest }, null, 2),
  "utf8"
);

/* ---------------------------------------------------------------- report - */
const pct = before ? Math.round((1 - after / before) * 100) : 0;
console.log(`  ${manifest.length} asset(s) built`);
console.log(`  ${(before / 1024).toFixed(1)} KB → ${(after / 1024).toFixed(1)} KB  (${pct}% smaller)`);
console.log(`  SRI: sha384 on every script and stylesheet`);
console.log(`\n  Run with:   npm run serve:prod   →   http://localhost:3000/dist/\n`);
console.log(`  Reminder: minification + SRI is tamper-evidence and size, not secrecy.`);
console.log(`  Secrets belong in SECURITY/ and never reach the browser.\n`);