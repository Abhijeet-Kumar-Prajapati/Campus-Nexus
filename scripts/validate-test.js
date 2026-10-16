// Verifies the control-character strip does not eat legitimate characters.
// Uses explicit \u escapes throughout — literal control bytes in a test file are
// invisible and get mangled by editors.
import { validate, V, safeText, identifier } from "../src/security/validate.js";

const strip = (v) => validate({ t: v }, V.object({ t: safeText(200) })).value.t;

const cases = [
  ["Clean Code & Co.",    "Clean Code & Co.",     "punctuation preserved"],
  ["CS-A1",               "CS-A1",                "hyphen preserved"],
  ["ISBN 978-0132350884", "ISBN 978-0132350884",  "digits + hyphens"],
  ["A\tB",                "A\tB",                 "tab kept (legitimate)"],
  ["A\nB",                "A\nB",                 "newline kept (legitimate)"],
  ["Café — naïve",  "Café — naïve",     "unicode preserved"],
  ["AB",               "AB",                   "BEL (0x07) stripped"],
  ["AB",               "AB",                   "DEL (0x7F) stripped"],
  ["AB",               "AB",                   "vertical tab stripped"],
  ["AB",               "AB",                   "form feed stripped"],
];

let bad = 0;
const report = (pass, label) => {
  if (!pass) bad++;
  console.log(`${pass ? "\x1b[32m  PASS\x1b[0m" : "\x1b[31m  FAIL\x1b[0m"}  ${label}`);
};

for (const [input, expected, note] of cases) {
  const got = strip(input);
  const pass = got === expected;
  if (!pass) bad++;
  console.log(
    `${pass ? "\x1b[32m  PASS\x1b[0m" : "\x1b[31m  FAIL\x1b[0m"}  ` +
    `in=${JSON.stringify(input).padEnd(24)} out=${JSON.stringify(got).padEnd(24)} ${note}`
  );
}

// The identifier rule must still accept valid codes and reject spaces.
const idOkCase = validate({ i: "CS-A1" }, V.object({ i: identifier(20) }));
const idSpace = validate({ i: "CS A1" }, V.object({ i: identifier(20) }));
const idAngle = validate({ i: "<x>" }, V.object({ i: identifier(20) }));
report(idOkCase.ok, 'identifier accepts "CS-A1"');
report(!idSpace.ok, "identifier rejects a space");
report(!idAngle.ok, "identifier rejects angle brackets");

// safeText must reject markup outright.
report(!validate({ t: "<script>" }, V.object({ t: safeText(50) })).ok, "safeText rejects <script>");

// A malformed schema must fail CLOSED, not silently accept everything.
const bogus = validate({ anything: "goes" }, { notARule: true });
report(!bogus.ok, "malformed schema fails closed instead of passing");

console.log(bad ? `\n\x1b[31m${bad} failure(s)\x1b[0m` : "\n\x1b[32mall control-character handling correct\x1b[0m");
process.exit(bad ? 1 : 0);