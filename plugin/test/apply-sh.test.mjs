// host/patches/apply.sh is the command-line route to the same patch set as the plugin engine: same patches, same order, same
// bytes, on both supported Paperclip versions; and it recognises a tree it patched itself even though patches stack on one file.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createEngine, PROTECTIONS, SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { discoverPatchFiles, readPatchTarget } from "../src/engine/patches.js";
import { PATCHES } from "../src/engine/registry.js";
import { makeScratchBase } from "./helpers/scratch-tree.mjs";

const APPLY_SH = path.join(SOURCE_PATCHES_DIR, "apply.sh");
const ALL = PROTECTIONS.filter((p) => p.kind === "patch").map((p) => p.id);

test("apply.sh lists every patch of the registry, in an order the engine also uses", () => {
  const text = fs.readFileSync(APPLY_SH, "utf8");
  const listed = [...text.matchAll(/^\s+"(\d{4}[a-z]?)\|/gm)].map((m) => m[1]);
  assert.deepEqual([...listed].sort(), Object.keys(PATCHES).sort());
  // Patches on one file are listed in the engine's order (global id order), so the stack is built the same way.
  const files = discoverPatchFiles(SOURCE_PATCHES_DIR);
  const perFile = new Map();
  for (const id of listed) {
    const rel = readPatchTarget(files.get(id)[0].file);
    perFile.set(rel, [...(perFile.get(rel) ?? []), id]);
  }
  for (const [rel, ids] of perFile) assert.deepEqual([...ids].sort(), ids, `${rel}: apply.sh order differs from the engine's`);
});

for (const vkey of ["1012", "1005"]) {
  const S = makeScratchBase(`apply-sh-${vkey}-`, vkey);
  test.after(() => { if (!S.skip) S.cleanup(); });
  test(`${vkey}: apply.sh reproduces the engine's build byte for byte, is idempotent, and --check reports pending patches`, { skip: S.skip }, async () => {
    const run = (tree, ...args) => spawnSync("bash", [APPLY_SH, ...args], { encoding: "utf8", env: { ...process.env, PAPERCLIP_TREE: tree, TMPDIR: S.root } });
    const a = S.fresh();
    const b = S.fresh();
    try {
      const engine = createEngine(a.engineOptions);
      assert.equal((await engine.apply(await engine.plan(ALL))).ok, true);

      assert.equal(run(b.tree, "--check").status, 3, "a pristine tree has pending patches");
      const first = run(b.tree);
      assert.equal(first.status, 0, first.stderr);
      for (const rel of S.targets) assert.ok(fs.readFileSync(path.join(a.tree, rel)).equals(fs.readFileSync(path.join(b.tree, rel))), `${rel}: engine and apply.sh differ`);

      // Second run: everything (including the patches under a later one on the same file) counts as applied, nothing is changed.
      const before = Object.fromEntries(S.targets.map((rel) => [rel, fs.readFileSync(path.join(b.tree, rel))]));
      const second = run(b.tree);
      assert.equal(second.status, 0, second.stderr);
      assert.doesNotMatch(second.stdout, /pending|applied \(backup/);
      assert.match(second.stdout, /0003: already applied/);
      assert.match(second.stdout, /0003b: already applied/);
      assert.match(second.stdout, /0005f: already applied/);
      assert.equal(run(b.tree, "--check").status, 0);
      for (const rel of S.targets) assert.ok(fs.readFileSync(path.join(b.tree, rel)).equals(before[rel]));

      // A partly applied stack is refused, and nothing is changed: damage one line of 0003b, under which 0005f and 0005b were applied.
      const hb = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
      const patched = fs.readFileSync(path.join(b.tree, hb), "utf8");
      const broken = patched.replace(/^.*LOCAL-PATCH 0003b.*$/m, "// edited");
      fs.writeFileSync(path.join(b.tree, hb), broken);
      const bad = run(b.tree);
      assert.equal(bad.status, 1);
      assert.match(bad.stderr, /only partly applied/);
      assert.equal(fs.readFileSync(path.join(b.tree, hb), "utf8"), broken);
    } finally { a.cleanup(); b.cleanup(); }
  });
}
