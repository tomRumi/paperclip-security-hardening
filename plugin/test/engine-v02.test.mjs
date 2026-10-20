// v0.2.0 wiring of the engine: the new protections "box-claude" and "box-opencode", the dependencies that make a broken combination of patches
// impossible, a plan that notices a changed patch list or patch file, both supported Paperclip versions, and the upgrade from a
// real v0.1.1 install (its engine and its patch files are read back from the v0.1.1 tag; skipped, loudly, where git or the tag is
// missing).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createEngine, PROTECTIONS } from "../src/engine/index.js";
import { PATCHES, getProtection } from "../src/engine/registry.js";
import { discoverPatchFiles, orderCandidates, readPatchTarget, buildFile } from "../src/engine/patches.js";
import { sha256 } from "../src/engine/store.js";
import { makeScratchBase } from "./helpers/scratch-tree.mjs";
import { v011Package, importV011Engine, V011_REF, V011_DEFAULTS } from "./helpers/v011.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../..");
const PATCH_PROTECTIONS = PROTECTIONS.filter((p) => p.kind === "patch").map((p) => p.id);
const byId = (list) => Object.fromEntries(list.map((p) => [p.id, p]));
const ownerOf = (patchId) => PROTECTIONS.find((p) => p.patches.includes(patchId))?.id;

const S = { 1012: makeScratchBase("engine-v02-1012-", "1012"), 1005: makeScratchBase("engine-v02-1005-", "1005") };
test.after(() => { for (const s of Object.values(S)) if (!s.skip) s.cleanup(); });
const skip12 = S[1012].skip;

/** The scratch case with a private copy of the patch files (fresh() shares one dir between cases), for tests that edit them. */
function ownPatches(f) {
  const dir = path.join(f.dir, "patches");
  fs.cpSync(f.engineOptions.patchesDir, dir, { recursive: true });
  f.engineOptions.patchesDir = dir;
  return f;
}

/** The protections the engine switches on for `ids` (pure data: the closure over the hard `requires`; `softRequires` are switched on together by the engine but are not needed). */
function closure(ids) {
  const out = new Set();
  const visit = (id) => { if (out.has(id)) return; out.add(id); getProtection(id).requires.forEach(visit); };
  ids.forEach(visit);
  return out;
}

// ---------------------------------------------------------------------------------------------------------------- registry
test("every new patch is reachable through a protection and has a table entry", () => {
  const files = discoverPatchFiles(path.join(REPO, "host/patches"));
  const owned = new Set(PROTECTIONS.flatMap((p) => p.patches));
  for (const id of ["0003b", "0005f", "0017", "0019", "0019b", "0019c", "0019d", "0025", "0026", "0026b", "0026c", "0027"]) {
    assert.ok(owned.has(id), `${id} is in no protection`);
    assert.ok(PATCHES[id]?.marker.startsWith("// LOCAL-PATCH "), `${id} has no marker`);
  }
  // Nothing is left unwired: every patch file in host/patches belongs to a protection.
  for (const id of files.keys()) assert.ok(owned.has(id), `patch file ${id} is not wired into a protection`);
  assert.equal(ownerOf("0003b"), "own-box");
  assert.deepEqual(getProtection("only-boxed").patches, ["0005b", "0005f", "0027"]);
  assert.equal(ownerOf("0005a"), "safe-defaults");
});

test("a broken combination of patches cannot be switched on: dependencies hold for every set of switches", () => {
  // Same switch for the patches that must travel together: the env scrub never without the Claude adapter (boxed Claude would
  // lose its credentials), and the box helper and the registrations they call. OpenCode has its own switch on top of them.
  for (const id of ["0017", "0025", "0026", "0026b", "0026c"]) assert.equal(ownerOf(id), "box-claude", id);
  for (const id of ["0019", "0019b", "0019c", "0019d"]) assert.equal(ownerOf(id), "box-opencode", id);
  assert.equal(ownerOf("0027"), "only-boxed");
  const box = getProtection("box-claude");
  // The patches that sit on other patches (their context lines contain those patches' code) come with their switches.
  assert.ok(box.requires.includes("public-web"), "0017 is built on 0015");
  assert.ok(box.requires.includes("own-claude-folder"), "0026 is built on 0016");
  assert.deepEqual(getProtection("box-opencode").requires, ["box-claude"], "OpenCode uses the helper and the scrub of the Claude switch");
  const onlyBoxed = getProtection("only-boxed");
  assert.ok(onlyBoxed.requires.includes("own-box"));
  assert.ok(!onlyBoxed.requires.includes("box-claude"), "box-claude is a soft dependency of the admission rule: without it Claude agents are refused (fail closed)");
  assert.deepEqual(onlyBoxed.softRequires, ["box-claude"]);
  assert.ok(!onlyBoxed.requires.includes("box-opencode"), "the admission rule never needs the OpenCode switch: it refuses an OpenCode agent whose adapter is not boxed");

  const ids = PATCH_PROTECTIONS;
  assert.ok(ids.length <= 16);
  const needs = {
    "box-claude": ["sandbox-compat", "public-web", "own-claude-folder"],
    "box-opencode": ["sandbox-compat", "box-claude", "public-web", "own-claude-folder"],
    "only-boxed": ["sandbox-compat", "own-box"],
  };
  for (let mask = 0; mask < 1 << ids.length; mask++) {
    const picked = ids.filter((_, i) => mask & (1 << i));
    const on = closure(picked);
    const patchesOn = new Set([...on].flatMap((id) => getProtection(id).patches));
    // 0025 only with 0026 and 0017; 0005f only with 0017, 0025, 0026 and with 0003b (own-box); 0005f replaces 0005b's body.
    // OpenCode (0019*) only with the helper and the scrub; without it 0005f refuses OpenCode agents, which is the safe way to lack it.
    // (0005f needs neither the helper nor the scrub nor the Claude adapter: soft dependency, it refuses Claude agents without them.)
    const requires = { "0025": ["0026", "0017"], "0026": ["0016", "0025", "0017"], "0017": ["0015", "0025"], "0005f": ["0005b", "0003", "0003b"], "0003b": ["0003"], "0019": ["0017", "0025"], "0019d": ["0019"] };
    for (const [patch, others] of Object.entries(requires))
      if (patchesOn.has(patch)) for (const o of others) assert.ok(patchesOn.has(o), `{${picked.join(", ")}}: ${patch} is on without ${o}`);
    for (const [id, list] of Object.entries(needs)) if (on.has(id)) for (const n of list) assert.ok(on.has(n), `{${picked.join(", ")}}: ${id} without ${n}`);
  }
});

test("registry: nothing the owner reads names a patch number", () => {
  for (const id of ["box-claude", "box-opencode", "only-boxed", "own-box"]) {
    const p = getProtection(id);
    assert.doesNotMatch(`${p.title} ${p.description} ${p.risk}`, /\b\d{4}[a-z]?\b/);
  }
  assert.equal(getProtection("box-claude").title, "Box Claude agents");
  assert.equal(getProtection("box-claude").core, true);
  assert.equal(getProtection("box-claude").defaultOn, true);
  assert.equal(getProtection("box-opencode").title, "Box OpenCode agents");
  assert.equal(getProtection("box-opencode").defaultOn, true);
  assert.equal(getProtection("box-opencode").core, false, "losing it fails closed (OpenCode agents are refused), so it needs no confirmation");
});

// ---------------------------------------------------------------------------------------------------------------- stacking
test("the requires are not decorative: each stacked patch fails on a file without the patch it sits on", { skip: skip12 }, () => {
  const f = S[1012].fresh();
  try {
    const found = discoverPatchFiles(f.engineOptions.patchesDir);
    const vkey = "1012";
    const tryAlone = (id) => {
      const rel = readPatchTarget(found.get(id)[0].file);
      return buildFile({ rel, pristine: S[1012].baseFile(rel), tmpDir: S[1012].root,
        steps: [{ id, marker: PATCHES[id].marker, candidates: orderCandidates(found.get(id), vkey) }] });
    };
    // Each of these changes code that an earlier patch already changed.
    for (const id of ["0003b", "0005f", "0017", "0026"]) {
      const r = tryAlone(id);
      assert.equal(r.ok, false, `${id} applies to the original file alone; its dependency would be unnecessary`);
      assert.equal(r.failedId, id);
    }
    // Independent patches do apply alone (so the dependency list is not simply "everything").
    for (const id of ["0019", "0019b", "0019c", "0019d", "0025", "0026b", "0026c"]) assert.equal(tryAlone(id).ok, true, id);
  } finally { f.cleanup(); }
});

// ---------------------------------------------------------------------------------------------------------------- both versions
for (const vkey of ["1012", "1005"]) {
  const base = S[vkey];
  test(`${vkey}: every protection applies, the new patches carry their markers, restore is byte-identical`, { skip: base.skip }, async () => {
    const f = base.fresh();
    try {
      const engine = createEngine(f.engineOptions);
      assert.equal(engine.vkey, vkey);
      const plan = await engine.plan(PATCH_PROTECTIONS);
      for (const p of plan.protections.filter((x) => x.kind === "patch")) assert.equal(p.action, "will-apply", `${p.id}: ${p.reason}`);
      assert.equal((await engine.apply(plan)).ok, true);
      for (const id of Object.keys(PATCHES)) {
        const rel = readPatchTarget(discoverPatchFiles(f.engineOptions.patchesDir).get(id)[0].file);
        if (vkey === "1005" && PATCHES[id].notNeededOn?.includes(vkey)) continue;
        assert.ok(fs.readFileSync(path.join(f.tree, rel), "utf8").includes(PATCHES[id].marker), `${id} marker missing from ${rel}`);
      }
      // status says applied (pending restart) for the new switch, and the files carry the recorded patch list.
      const st = await engine.status({ serverStartedAt: null });
      assert.ok(["applied", "pending-restart"].includes(byId(st.protections)["box-claude"].status));
      assert.ok(["applied", "pending-restart"].includes(byId(st.protections)["box-opencode"].status));
      const sandbox = st.files.find((x) => x.rel.endsWith("adapter-utils/dist/local-process-sandbox.js"));
      assert.deepEqual(sandbox.patches.filter((id) => ["0015", "0017"].includes(id)), ["0015", "0017"]);
      assert.equal((await engine.restoreAll()).ok, true);
      for (const rel of base.targets) assert.ok(fs.readFileSync(path.join(f.tree, rel)).equals(base.baseFile(rel)), `${rel} not restored`);
    } finally { f.cleanup(); }
  });

  test(`${vkey}: asking for only-boxed alone switches on everything it needs; one patch missing leaves nothing half-applied`, { skip: base.skip }, async () => {
    const f = base.fresh();
    try {
      const engine = createEngine(f.engineOptions);
      const plan = await engine.plan(["only-boxed"]);
      assert.deepEqual([...plan.enabled].sort(), ["box-claude", "own-box", "own-claude-folder", "only-boxed", "public-web", "sandbox-compat"].sort());
      assert.deepEqual(plan.added.map((a) => a.id).sort(), ["box-claude", "own-box", "own-claude-folder", "public-web", "sandbox-compat"]);
      assert.deepEqual(plan.added.find((a) => a.id === "box-claude").neededBy, ["only-boxed"]);
    } finally { f.cleanup(); }
    // The environment scrub's patch file is gone: the whole switch (and what needs it) is unavailable, no patch of it is applied.
    const g = ownPatches(base.fresh());
    try {
      for (const name of fs.readdirSync(g.engineOptions.patchesDir).filter((n) => n.startsWith("0025-"))) fs.rmSync(path.join(g.engineOptions.patchesDir, name));
      const engine = createEngine(g.engineOptions);
      const plan = await engine.plan(PATCH_PROTECTIONS);
      const prot = byId(plan.protections);
      assert.equal(prot["box-claude"].action, "unavailable");
      assert.match(prot["box-claude"].reason, /patch 0025 has no patch file/);
      assert.equal(prot["box-opencode"].action, "unavailable", "OpenCode needs the Claude switch's helper and scrub");
      assert.equal(prot["only-boxed"].action, "will-apply", "soft dependency: the admission rule applies without the Claude box");
      assert.equal(prot["sandbox-compat"].action, "will-apply");
      assert.equal((await engine.apply(plan)).ok, true);
      for (const [id, rel] of [["0017", "adapter-utils/dist/local-process-sandbox.js"], ["0026", "adapter-claude-local/dist/server/execute.js"], ["0019", "adapter-opencode-local/dist/server/execute.js"]])
        assert.ok(!fs.readFileSync(path.join(g.tree, "node_modules/@paperclipai", rel), "utf8").includes(`LOCAL-PATCH ${id}`), `${id} applied without the rest of its switch`);
      assert.ok(fs.readFileSync(path.join(g.tree, "node_modules/@paperclipai/server/dist/services/heartbeat.js"), "utf8").includes("LOCAL-PATCH 0005f"), "the admission rule is in");
    } finally { g.cleanup(); }
  });
}

// ---------------------------------------------------------------------------------------------------------------- plan: patch list and patch bytes
test("plan: a changed patch list of an applied protection is a change (hash-only comparison missed it)", { skip: skip12 }, async () => {
  const f = S[1012].fresh();
  try {
    const engine = createEngine(f.engineOptions);
    assert.equal((await engine.apply(await engine.plan(PATCH_PROTECTIONS))).ok, true);
    const again = await engine.plan(PATCH_PROTECTIONS);
    assert.ok(again.protections.filter((p) => p.kind === "patch").every((p) => p.action === "unchanged"), "a second plan changes nothing");
    assert.equal(again.changes, 0);

    // The state as an earlier release would have left it: same built file, but its record of the patches lacks the ones this
    // release added to own-box (0003b) and only-boxed (0005f).
    const stateFile = path.join(f.engineOptions.dataDir, "state.json");
    const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    const hb = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
    assert.ok(state.files[hb].patches.includes("0003b") && state.files[hb].patches.includes("0005f"));
    state.files[hb].patches = state.files[hb].patches.filter((id) => id !== "0003b" && id !== "0005f");
    delete state.files[hb].patchShas["0003b"];
    delete state.files[hb].patchShas["0005f"];
    fs.writeFileSync(stateFile, JSON.stringify(state));
    const plan = await engine.plan(PATCH_PROTECTIONS);
    const prot = byId(plan.protections);
    assert.equal(prot["own-box"].action, "will-apply", "own-box gained a patch");
    assert.equal(prot["only-boxed"].action, "will-apply", "only-boxed gained a patch");
    // The other protections that patch the same file did not change.
    assert.equal(prot["sandbox-compat"].action, "unchanged");
    assert.equal(prot["pipeline-board-only"].action, "unchanged");
  } finally { f.cleanup(); }
});

test("plan: a patch file whose bytes changed (same id, same name) is a change; unrelated protections stay unchanged", { skip: skip12 }, async () => {
  const f = ownPatches(S[1012].fresh());
  try {
    const first = createEngine(f.engineOptions);
    assert.equal((await first.apply(await first.plan(PATCH_PROTECTIONS))).ok, true);
    const file = discoverPatchFiles(f.engineOptions.patchesDir).get("0007")[0].file;
    const lines = fs.readFileSync(file, "utf8").split("\n");
    const i = lines.findIndex((l) => l.startsWith("+") && !l.startsWith("+++") && l.includes("LOCAL-PATCH 0007"));
    assert.ok(i > 0);
    lines[i] += " (reworded)"; // one added line stays one added line: the hunk still fits
    fs.writeFileSync(file, lines.join("\n"));
    const engine = createEngine(f.engineOptions);
    await new Promise((r) => setTimeout(r, 20));
    const serverStartedAt = new Date().toISOString(); // Paperclip restarted after the first apply
    await new Promise((r) => setTimeout(r, 20));
    const plan = await engine.plan(PATCH_PROTECTIONS);
    const prot = byId(plan.protections);
    assert.equal(prot["pipeline-board-only"].action, "will-apply");
    assert.equal(plan.changes, 1);
    for (const p of plan.protections.filter((x) => x.kind === "patch" && x.id !== "pipeline-board-only")) assert.equal(p.action, "unchanged", p.id);
    const r = await engine.apply(plan);
    assert.equal(r.ok, true);
    assert.equal(r.restartNeeded, true);
    const st = await engine.status({ serverStartedAt });
    assert.equal(byId(st.protections)["pipeline-board-only"].pendingRestart, true);
    assert.equal(byId(st.protections)["own-box"].pendingRestart, false);
  } finally { f.cleanup(); }
});

// ---------------------------------------------------------------------------------------------------------------- upgrade from v0.1.1
const V011 = v011Package(V011_REF);
test.after(() => { if (V011.dir) fs.rmSync(V011.dir, { recursive: true, force: true }); });

for (const vkey of ["1012", "1005"]) {
  const base = S[vkey];
  const why = base.skip || V011.skip;
  test(`${vkey}: upgrade from a v0.1.1 state (protections already on): replan adds the new switch, restart tracking sees the changes, old patches stay byte-stable`, { skip: why }, async () => {
    const f = base.fresh();
    try {
      // 1. The v0.1.1 package itself: its engine, its registry, its patch files, its defaults.
      const old = await importV011Engine(V011, vkey);
      const oldEngine = old.createEngine({ ...f.engineOptions, patchesDir: V011.patchesDir });
      assert.equal((await oldEngine.apply(await oldEngine.plan(V011_DEFAULTS))).ok, true);
      const oldState = JSON.parse(fs.readFileSync(path.join(f.engineOptions.dataDir, "state.json"), "utf8"));
      assert.deepEqual(oldState.enabled.slice().sort(), V011_DEFAULTS.slice().sort());
      const oldBuilt = Object.fromEntries(Object.keys(oldState.files).map((rel) => [rel, fs.readFileSync(path.join(f.tree, rel))]));

      // The patch files of the v0.1.1 protections are the ones of this release, except the safe-defaults one (0005a, reworked).
      const newFiles = discoverPatchFiles(f.engineOptions.patchesDir);
      for (const [id, list] of discoverPatchFiles(V011.patchesDir)) {
        if (id === "0005a") continue;
        for (const o of list) {
          const same = newFiles.get(id).find((n) => path.basename(n.file) === path.basename(o.file));
          assert.ok(same, `${path.basename(o.file)} is gone`);
          assert.ok(fs.readFileSync(same.file).equals(fs.readFileSync(o.file)), `${path.basename(o.file)} changed since v0.1.1`);
        }
      }

      // 2. This release on the same tree and data dir. The saved switches are the v0.1.1 ones.
      const engine = createEngine(f.engineOptions);
      const plan = await engine.replan();
      assert.deepEqual(plan.requested.slice().sort(), V011_DEFAULTS.slice().sort());
      assert.deepEqual(plan.added.map((a) => a.id), ["box-claude"]);
      assert.deepEqual(plan.added[0].neededBy, ["only-boxed"]);
      const prot = byId(plan.protections);
      for (const id of PATCH_PROTECTIONS) assert.notEqual(prot[id].action, "unavailable", `${id}: ${prot[id].reason}`);
      for (const id of ["own-box", "only-boxed", "safe-defaults", "box-claude"]) assert.equal(prot[id].action, "will-apply", id);
      assert.equal(prot["box-opencode"].action, "unchanged", "not switched on by an upgrade of a v0.1.1 state (those had no OpenCode support; the owner ticks it)");
      assert.equal(plan.enabled.includes("box-opencode"), false);
      // Protections that share routes/agents.js with the new 0027 are rebuilt with it (the v0.1.1 state has no patch hashes to say that
      // their own patches are unchanged); the pipeline file is not touched by anything new.
      for (const id of ["no-permission-handing", "assign-needs-grant"]) assert.equal(prot[id].action, "will-apply", id);
      assert.equal(prot["pipeline-board-only"].action, "unchanged");
      // Files no new or changed patch touches are not rebuilt (byte-stable).
      const touched = new Set(["0003b", "0005a", "0005f", "0017", "0025", "0026", "0026b", "0026c", "0027"]
        .map((id) => readPatchTarget(newFiles.get(id)[0].file)));
      for (const entry of plan.files) if (!touched.has(entry.rel)) assert.equal(entry.change, false, `${entry.rel} would be rebuilt`);
      for (const rel of touched) assert.equal(plan.files.find((x) => x.rel === rel).change, true, rel);

      // 3. Apply: one restart covers it, and the protections that changed are the ones that wait for it.
      await new Promise((r) => setTimeout(r, 30));
      const serverStartedAt = new Date(Date.parse(oldState.appliedAt) + 5).toISOString();
      const r = await engine.apply(plan);
      assert.equal(r.ok, true, r.error);
      assert.equal(r.restartNeeded, true);
      for (const rel of base.targets) if (!touched.has(rel) && oldBuilt[rel]) assert.ok(fs.readFileSync(path.join(f.tree, rel)).equals(oldBuilt[rel]), `${rel} changed`);
      const st = await engine.status({ serverStartedAt });
      assert.equal(st.restartNeeded, true);
      const rows = byId(st.protections);
      for (const id of ["own-box", "only-boxed", "safe-defaults", "box-claude"]) assert.equal(rows[id].pendingRestart, true, id);
      assert.equal(rows["pipeline-board-only"].pendingRestart, false);
      assert.deepEqual(st.enabled.slice().sort(), [...V011_DEFAULTS, "box-claude"].sort());

      // 4. Nothing more to do, and everything can be switched off again.
      const again = await engine.replan();
      assert.equal(again.changes, 0);
      assert.ok(again.protections.filter((p) => p.kind === "patch").every((p) => p.action === "unchanged"));
      assert.equal((await engine.restoreAll()).ok, true);
      for (const rel of base.targets) assert.ok(fs.readFileSync(path.join(f.tree, rel)).equals(base.baseFile(rel)), `${rel} not restored`);
    } finally { f.cleanup(); }
  });

  test(`${vkey}: from a v0.1.1 state with the new protection's neighbours switched off, enabling only-boxed pulls them in and applies`, { skip: why }, async () => {
    const f = base.fresh();
    try {
      const old = await importV011Engine(V011, vkey);
      const oldEngine = old.createEngine({ ...f.engineOptions, patchesDir: V011.patchesDir });
      assert.equal((await oldEngine.apply(await oldEngine.plan(["sandbox-compat", "pipeline-board-only"]))).ok, true);
      const engine = createEngine(f.engineOptions);
      const plan = await engine.plan(["sandbox-compat", "pipeline-board-only", "only-boxed"]);
      assert.deepEqual(plan.enabled.slice().sort(), ["box-claude", "only-boxed", "own-box", "own-claude-folder", "pipeline-board-only", "public-web", "sandbox-compat"].sort());
      assert.equal(byId(plan.protections)["pipeline-board-only"].action, "unchanged");
      const r = await engine.apply(plan);
      assert.equal(r.ok, true, r.error);
      assert.equal((await engine.restoreAll()).ok, true);
      for (const rel of base.targets) assert.ok(fs.readFileSync(path.join(f.tree, rel)).equals(base.baseFile(rel)), `${rel} not restored`);
    } finally { f.cleanup(); }
  });
}

test("the stored state is plain data: patch hashes are the sha256 of the patch files", { skip: skip12 }, async () => {
  const f = S[1012].fresh();
  try {
    const engine = createEngine(f.engineOptions);
    assert.equal((await engine.apply(await engine.plan(["own-box"]))).ok, true);
    const state = JSON.parse(fs.readFileSync(path.join(f.engineOptions.dataDir, "state.json"), "utf8"));
    const hb = state.files["node_modules/@paperclipai/server/dist/services/heartbeat.js"];
    const file = discoverPatchFiles(f.engineOptions.patchesDir).get("0003b")[0].file;
    assert.equal(hb.patchShas["0003b"], sha256(fs.readFileSync(file)));
    assert.equal(state.schema, 1, "additive field: older engines still read the state");
  } finally { f.cleanup(); }
});
