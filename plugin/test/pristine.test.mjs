// helpers/pristine.mjs: where the tests get Paperclip's ORIGINAL bytes. A file that only exists patched, with no backup and no
// stored original, must give null (and a loud skip text), never the patched bytes: that is what made the engine, selftest, worker
// and instance-targeting tests skip silently once a patch targeted a file without a .orig (server-utils.js).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { missingPristine, noPristineSkip, pristineOrNull, pristineSource, stockTreePath, stockTreeOrNull } from "./helpers/pristine.mjs";

const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "pristine-test-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
const REL = "node_modules/@paperclipai/adapter-utils/dist/server-utils.js";
const ORIGINAL = Buffer.from("export const x = 1;\n");
const PATCHED = Buffer.from("export const x = 1;\n// LOCAL-PATCH 0025: scrub\n");
let n = 0;
function tree(files, store = {}) {
  const root = path.join(scratch, `t-${++n}`);
  const storeDir = path.join(scratch, `s-${n}`);
  for (const [rel, bytes] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), bytes); }
  for (const [rel, bytes] of Object.entries(store)) { fs.mkdirSync(path.dirname(path.join(storeDir, "pristine", rel)), { recursive: true }); fs.writeFileSync(path.join(storeDir, "pristine", rel), bytes); }
  return { root, options: { storeDirs: [storeDir] } };
}

test("a .orig backup wins, even over an unpatched-looking file", () => {
  const t = tree({ [REL]: PATCHED, [`${REL}.orig`]: ORIGINAL });
  assert.deepEqual(pristineSource(t.root, REL, t.options), { bytes: ORIGINAL, source: "orig" });
  const u = tree({ [REL]: Buffer.from("other\n"), [`${REL}.orig`]: ORIGINAL });
  assert.equal(pristineSource(u.root, REL, u.options).source, "orig");
});

test("a file without a LOCAL-PATCH marker is its own original (never patched: server-utils.js, a 1005 install)", () => {
  const t = tree({ [REL]: ORIGINAL });
  assert.deepEqual(pristineSource(t.root, REL, t.options), { bytes: ORIGINAL, source: "unpatched" });
});

test("a patched file with no backup falls back to the engine store, and only to an unmarked stored copy", () => {
  const t = tree({ [REL]: PATCHED }, { [REL]: ORIGINAL });
  assert.deepEqual(pristineSource(t.root, REL, t.options), { bytes: ORIGINAL, source: "engine-store" });
  const bad = tree({ [REL]: PATCHED }, { [REL]: PATCHED });
  assert.equal(pristineOrNull(bad.root, REL, bad.options), null, "a stored copy that is itself patched is not an original");
});

test("a patched file with no backup and no stored original gives null, never the patched bytes", () => {
  const t = tree({ [REL]: PATCHED });
  assert.equal(pristineOrNull(t.root, REL, t.options), null);
  assert.equal(pristineSource(t.root, REL, t.options), null);
  assert.equal(pristineOrNull(tree({}).root, REL, t.options), null, "a missing file");
});

test("noPristineSkip: false when every file has an original, else a loud text that names the file and the variable to set", () => {
  const t = tree({ [REL]: ORIGINAL, "a/b.js": PATCHED });
  assert.equal(noPristineSkip(t.root, [REL], "1012", t.options), false);
  assert.deepEqual(missingPristine(t.root, [REL, "a/b.js", "c.js"], t.options), ["a/b.js", "c.js"]);
  const text = noPristineSkip(t.root, [REL, "a/b.js", "c.js"], "1012", t.options);
  assert.match(text, /^NO PRISTINE: 2 patched file\(s\)/);
  assert.ok(text.includes("a/b.js") && text.includes("PAPERCLIP_STOCK_TREE_1012") && text.includes(t.root));
});

test("stockTreePath: PAPERCLIP_STOCK_TREE_<vkey> wins over the default install; stockTreeOrNull needs the @paperclipai packages", () => {
  assert.equal(stockTreePath("1012", { PAPERCLIP_STOCK_TREE_1012: "/x/y" }), "/x/y");
  assert.equal(stockTreePath("1005", { PAPERCLIP_STOCK_TREE_1012: "/x/y" }), path.join(os.homedir(), ".paperclip", "cli", "installs", "npm", "2026.1005.0"));
  const t = tree({ "node_modules/@paperclipai/server/package.json": "{}" });
  assert.equal(stockTreeOrNull("1012", { PAPERCLIP_STOCK_TREE_1012: t.root }), fs.realpathSync(t.root));
  assert.equal(stockTreeOrNull("1012", { PAPERCLIP_STOCK_TREE_1012: path.join(scratch, "nothing-here") }), null);
});

test("no test decides to skip from the existence of .orig files any more (one definition: helpers/pristine.mjs)", () => {
  const dir = path.dirname(new URL(import.meta.url).pathname);
  const files = [...fs.readdirSync(dir).filter((f) => /\.test\.m?js$/.test(f)).map((f) => path.join(dir, f)), ...fs.readdirSync(path.join(dir, "helpers")).map((f) => path.join(dir, "helpers", f))]
    .filter((f) => f !== path.join(dir, "pristine.test.mjs") && f !== path.join(dir, "helpers", "pristine.mjs"));
  const offenders = files.filter((f) => /liveTreeOrNull|every\(\(rel\) => fs\.existsSync\(path\.join\([^)]*\.orig|`\$\{HB\}\.orig`/m.test(fs.readFileSync(f, "utf8")));
  assert.deepEqual(offenders.map((f) => path.basename(f)), []);
});
