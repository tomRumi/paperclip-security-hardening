// Engine tests against a scratch tree that holds ONLY the Paperclip files the patches target (copied from the live
// tree's pristine `.orig` backups) plus copies of the patch files. The live tree is only ever read.
//   PAPERCLIP_TREE             live tree to copy from (default: what ~/.paperclip/cli/current resolves to)
//   HARDENING_LIVE_PATCHES     patch dir the live tree was patched with by apply.sh. Without it the two tests that compare the
//                              package patches with a hand-patched install are skipped (nothing is assumed about where it lives)
//   HARDENING_TEST_SCRATCH     where scratch trees go (default: the OS temp dir)
// Without a live tree that has `.orig` backups the tests are skipped.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createEngine, detectRestart, runRestart, PROTECTIONS, DEFAULT_PATCHES_DIR } from "../src/engine/index.js";
import { PATCHES, comparePatchIds } from "../src/engine/registry.js";
import { readPatchTarget, discoverPatchFiles } from "../src/engine/patches.js";
import { writeDurable as realWrite } from "../src/engine/store.js";
import { normalizeSettings, writeHardeningConfig } from "../src/settings.js";
import { evalBlock, extractBlock, withoutBlock } from "./helpers/patch-block.mjs";
import { liveSettings } from "./helpers/live-settings.mjs";
import { liveTreeOrNull } from "./helpers/scratch-tree.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_DIR = path.resolve(HERE, "../src/engine");
const CLI = path.resolve(HERE, "../bin/hardening-engine.mjs");
const PKG_PATCHES = DEFAULT_PATCHES_DIR;
const LIVE_PATCHES = process.env.HARDENING_LIVE_PATCHES || null;
const noLivePatches = LIVE_PATCHES ? false : "HARDENING_LIVE_PATCHES is not set (the dir a hand-patched live install was patched from); comparison with it skipped";
const PATCH_IDS = PROTECTIONS.filter((p) => p.kind === "patch");
const ALL = PATCH_IDS.map((p) => p.id);

// ---------- fixture
const live = liveTreeOrNull();
const targets = [...new Set(fs.readdirSync(PKG_PATCHES).filter((n) => n.endsWith(".patch")).map((n) => readPatchTarget(path.join(PKG_PATCHES, n))))].sort();
const haveLive = Boolean(live) && targets.every((rel) => fs.existsSync(path.join(live, `${rel}.orig`)));
const skip = haveLive ? false : "no live Paperclip tree with .orig backups";

const scratchRoot = haveLive ? fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "engine-test-")) : null;
const base = scratchRoot && path.join(scratchRoot, "base");
if (haveLive) {
  for (const rel of targets) {
    fs.mkdirSync(path.dirname(path.join(base, "tree", rel)), { recursive: true });
    fs.copyFileSync(path.join(live, `${rel}.orig`), path.join(base, "tree", rel));
  }
  const pj = "node_modules/@paperclipai/server/package.json";
  fs.mkdirSync(path.dirname(path.join(base, "tree", pj)), { recursive: true });
  fs.copyFileSync(path.join(live, pj), path.join(base, "tree", pj));
  fs.cpSync(PKG_PATCHES, path.join(base, "patches"), { recursive: true, filter: (s) => s === PKG_PATCHES || s.endsWith(".patch") });
}
test.after(() => { if (scratchRoot) fs.rmSync(scratchRoot, { recursive: true, force: true }); });

let n = 0;
/** A fresh scratch tree + data dir. */
function fixture({ patchesDir = path.join(base, "patches"), io } = {}) {
  const dir = path.join(scratchRoot, `case-${++n}`);
  fs.cpSync(path.join(base, "tree"), path.join(dir, "tree"), { recursive: true });
  const opts = { treeDir: path.join(dir, "tree"), dataDir: path.join(dir, "data"), patchesDir, tmpDir: scratchRoot, systemctl: null, io };
  return { dir, tree: opts.treeDir, opts, engine: createEngine(opts), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
const read = (tree, rel) => fs.readFileSync(path.join(tree, rel));
const baseFile = (rel) => read(path.join(base, "tree"), rel);
function assertPristine(tree, msg = "") {
  for (const rel of targets) assert.ok(read(tree, rel).equals(baseFile(rel)), `${rel} is not byte-identical to the original ${msg}`);
}
const byId = (list) => Object.fromEntries(list.map((p) => [p.id, p]));

// ---------- tests that need no live tree
test("registry: patch ids, markers, dependencies and patch files are consistent", () => {
  const ids = new Set(PROTECTIONS.map((p) => p.id));
  assert.equal(ids.size, PROTECTIONS.length);
  const files = discoverPatchFiles(PKG_PATCHES);
  const seen = new Set();
  for (const p of PROTECTIONS) {
    assert.ok(p.title && p.description && !/\b\d{4}[a-z]?\b/.test(`${p.title} ${p.description}`), `${p.id}: owner text must not mention patch numbers`);
    assert.ok(["patch", "plugin-job", "host-install"].includes(p.kind));
    assert.equal(p.kind === "patch", p.patches.length > 0, `${p.id}: patches iff kind patch`);
    if (p.core) assert.ok(p.risk, `${p.id}: core protections name the risk`);
    for (const r of p.requires) assert.ok(ids.has(r), `${p.id} requires unknown ${r}`);
    for (const id of p.patches) {
      assert.ok(PATCHES[id], `no patch table entry for ${id}`);
      assert.ok(!seen.has(id), `${id} belongs to two protections`); seen.add(id);
      assert.ok(files.has(id), `no patch file for ${id} in host/patches`);
    }
    assert.deepEqual([...p.patches].sort(comparePatchIds), p.patches, `${p.id}: patches in id order`);
  }
  assert.deepEqual([...seen].sort(), Object.keys(PATCHES).sort());
});

test("engine has no npm dependencies (only node: built-ins and relative imports)", () => {
  for (const f of fs.readdirSync(ENGINE_DIR).filter((x) => x.endsWith(".js"))) {
    const src = fs.readFileSync(path.join(ENGINE_DIR, f), "utf8");
    for (const m of src.matchAll(/^\s*(?:import|export)\b[^"'\n]*?from\s+["']([^"']+)["']/gm))
      assert.ok(m[1].startsWith("node:") || m[1].startsWith("./"), `${f} imports ${m[1]}`);
  }
});

test("restart hook: disabled detection, and a systemd user unit via a fake systemctl (never restarted)", () => {
  assert.equal(detectRestart({ systemctl: null }).canRestart, false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "engine-restart-"));
  try {
    const fake = path.join(dir, "systemctl");
    const log = path.join(dir, "calls");
    fs.writeFileSync(fake, `#!/bin/sh\necho "$@" >> '${log}'\necho LoadState=loaded\necho ActiveState=active\necho ExecMainStartTimestamp=@1792270891\n`, { mode: 0o755 });
    const info = detectRestart({ systemctl: fake, unitName: "paperclipai" });
    assert.equal(info.canRestart, true);
    assert.deepEqual(info.command, ["systemctl", "--user", "restart", "paperclipai"]);
    assert.equal(info.startedAt, new Date(1792270891000).toISOString());
    assert.match(fs.readFileSync(log, "utf8"), /^--user show paperclipai /);
    fs.writeFileSync(fake, "#!/bin/sh\necho LoadState=not-found\necho ActiveState=inactive\n", { mode: 0o755 });
    assert.equal(detectRestart({ systemctl: fake, unitName: "other" }).canRestart, false);
    assert.equal(detectRestart({ systemctl: path.join(dir, "missing") }).canRestart, false);
    assert.equal(detectRestart({ systemctl: fake, unitName: "bad;name" }).canRestart, false);
    // --no-block for callers inside Paperclip (the plugin worker); only ever the fake here.
    fs.writeFileSync(fake, `#!/bin/sh\necho "$@" >> '${log}'\n`, { mode: 0o755 });
    assert.equal(runRestart({ canRestart: true, command: [fake, "--user", "restart", "paperclipai"] }, { noBlock: true }).ok, true);
    assert.match(fs.readFileSync(log, "utf8"), /^--user --no-block restart paperclipai$/m);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---------- scratch-tree tests
test("every protection on alone, then off, gives byte-identical originals", { skip }, async () => {
  const f = fixture();
  try {
    for (const p of PATCH_IDS) {
      const plan = await f.engine.plan([p.id]);
      const prot = byId(plan.protections);
      assert.equal(prot[p.id].action, "will-apply", `${p.id}: ${prot[p.id].reason}`);
      for (const r of p.requires) assert.ok(plan.enabled.includes(r));
      const r = await f.engine.apply(plan, { confirmCoreOff: true });
      assert.equal(r.ok, true, r.error);
      assert.ok(r.changed.length > 0);
      const own = new Set(p.patches.map((id) => readPatchTarget(discoverPatchFiles(f.opts.patchesDir).get(id)[0].file)));
      for (const rel of own) assert.ok(!read(f.tree, rel).equals(baseFile(rel)), `${p.id} did not change ${rel}`);
      const st = byId((await f.engine.status({ serverStartedAt: null })).protections);
      assert.ok(["applied", "pending-restart"].includes(st[p.id].status));
      const off = await f.engine.apply(await f.engine.plan([]), { confirmCoreOff: true });
      assert.equal(off.ok, true, off.error);
      assertPristine(f.tree, `after switching ${p.id} off`);
    }
  } finally { f.cleanup(); }
});

test("everything on: the engine reproduces apply.sh exactly (both with the live patch files)", { skip: skip || noLivePatches || (!fs.existsSync(path.join(LIVE_PATCHES, "apply.sh")) && "no apply.sh in HARDENING_LIVE_PATCHES") }, async () => {
  const patches = path.join(scratchRoot, "live-patches");
  fs.cpSync(LIVE_PATCHES, patches, { recursive: true });
  const f = fixture({ patchesDir: patches });
  const g = fixture({ patchesDir: patches });
  try {
    const plan = await f.engine.plan(ALL);
    assert.deepEqual(plan.protections.filter((p) => p.kind === "patch").map((p) => p.action), ALL.map(() => "will-apply"));
    assert.equal((await f.engine.apply(plan)).ok, true);
    // apply.sh itself on a second scratch copy (its own scratch goes to TMPDIR = the test scratch).
    const sh = spawnSync("bash", [path.join(patches, "apply.sh")], { encoding: "utf8", env: { ...process.env, PAPERCLIP_TREE: g.tree, TMPDIR: scratchRoot } });
    assert.equal(sh.status, 0, sh.stderr);
    for (const rel of targets) assert.ok(read(f.tree, rel).equals(read(g.tree, rel)), `${rel}: engine and apply.sh differ`);
  } finally { f.cleanup(); g.cleanup(); }
});

// The package's 0003/0005a read the site values from the settings file instead of hard-coding this server's. With the
// settings file holding the live install's own values (read back from the live patches by helpers/live-settings.mjs),
// everything on must equal the live tree: byte for byte outside the settings-reading blocks, and those blocks must
// produce the same values and decisions.
test("everything on with the package patches and the live install's settings file equals the live tree", { skip: skip || noLivePatches }, async () => {
  const f = fixture();
  try {
    const plan = await f.engine.plan(ALL);
    assert.equal((await f.engine.apply(plan)).ok, true);
    const { settings } = normalizeSettings(liveSettings(LIVE_PATCHES));
    const configFile = path.join(f.dir, "hardening", "config.json");
    writeHardeningConfig(settings, { file: configFile, instanceRoot: path.join(f.dir, "instance") });
    const env = { PAPERCLIP_HARDENING_CONFIG: configFile };
    const blockOf = { "node_modules/@paperclipai/server/dist/services/heartbeat.js": "0003", "node_modules/@paperclipai/server/dist/services/agents.js": "0005a" };
    for (const rel of targets) {
      const built = read(f.tree, rel).toString("utf8");
      const liveText = read(live, rel).toString("utf8");
      const id = blockOf[rel];
      if (!id) { assert.equal(built, liveText, `${rel}: package build and the live tree differ`); continue; }
      assert.equal(withoutBlock(built, id), withoutBlock(liveText, id), `${rel}: differs outside the ${id} settings block`);
      const ours = evalBlock(extractBlock(built, id), id, { env });
      const theirs = evalBlock(extractBlock(liveText, id), id, { env: {} });
      for (const name of ["SANDBOX_WORKSPACE_ROOTS", "NEW_AGENT_SAFE_DEFAULTS"].filter((x) => x in theirs))
        assert.deepEqual(ours[name], theirs[name], `${rel}: ${name}`);
      if (id === "0005a")
        for (const type of ["claude_local", "hermes_local", "codex_local"]) {
          const mine = ours.applyNewAgentSafeDefaults(type, { env: { HERMES_SANDBOX_RO: "/" } }, {}, "create");
          // Only difference from the older live patch: a new boxed claude_local agent starts on the CLI engine.
          if (type === "claude_local") { assert.equal(mine.adapterConfig.engine, "cli"); delete mine.adapterConfig.engine; }
          assert.deepEqual(mine, theirs.applyNewAgentSafeDefaults(type, { env: { HERMES_SANDBOX_RO: "/" } }, {}, "create"));
        }
    }
  } finally { f.cleanup(); }
});

test("package patches: everything applies on this install, with the per-version variant preferred", { skip }, async () => {
  const f = fixture();
  try {
    const plan = await f.engine.plan(ALL);
    for (const p of plan.protections.filter((x) => x.kind === "patch")) assert.equal(p.action, "will-apply", `${p.id}: ${p.reason}`);
    const used = plan.files.flatMap((x) => x.patches.map((u) => u.file));
    if (f.engine.vkey) assert.ok(used.some((u) => u.endsWith(`.${f.engine.vkey}.patch`)));
  } finally { f.cleanup(); }
});

test("no version lock: an unknown or unparseable Paperclip version still gets every protection that fits", { skip }, async () => {
  for (const version of ["2099.0101.0", "not-a-version"]) {
    const f = fixture();
    try {
      const pj = path.join(f.tree, "node_modules/@paperclipai/server/package.json");
      fs.writeFileSync(pj, JSON.stringify({ name: "@paperclipai/server", version }));
      const e = createEngine(f.opts);
      const plan = await e.plan(ALL);
      for (const p of plan.protections.filter((x) => x.kind === "patch")) assert.equal(p.action, "will-apply", `${version} ${p.id}: ${p.reason}`);
      assert.equal((await e.apply(plan)).ok, true);
    } finally { f.cleanup(); }
  }
});

test("dependencies are added automatically; switching off a needed one is reported", { skip }, async () => {
  const f = fixture();
  try {
    const plan = await f.engine.plan(["public-web"]);
    assert.deepEqual(plan.enabled, ["sandbox-compat", "own-box", "public-web"]);
    assert.deepEqual(plan.added.map((a) => a.id), ["sandbox-compat", "own-box"]);
    assert.deepEqual(plan.added[0].neededBy, ["public-web"]);
    assert.equal((await f.engine.apply(plan)).ok, true);
    // Now ask for public-web without own-box: own-box stays on and the dependents are named.
    const off = await f.engine.plan(["sandbox-compat", "public-web"]);
    assert.deepEqual(off.neededOff, [{ id: "own-box", neededBy: ["public-web"] }]);
    assert.ok(off.enabled.includes("own-box"));
    // Switching off both works, and own-box (core) asks for confirmation first.
    const both = await f.engine.plan(["sandbox-compat"]);
    assert.deepEqual(both.neededOff, []);
    assert.deepEqual(both.confirmationNeeded.map((c) => c.id), ["own-box"]);
    const refused = await f.engine.apply(both);
    assert.equal(refused.ok, false);
    assert.match(refused.error, /confirmation/);
    assert.equal((await f.engine.apply(both, { confirmCoreOff: true })).ok, true);
    assert.deepEqual((await f.engine.status({ serverStartedAt: null })).enabled, ["sandbox-compat"]);
  } finally { f.cleanup(); }
});

test("a file whose code changed shape makes only that protection and its dependents unavailable", { skip }, async () => {
  const f = fixture();
  try {
    // Change one context line of the own-box patch 0002 in routes/agents.js (the code it changes "changed upstream").
    const file0002 = discoverPatchFiles(f.opts.patchesDir).get("0002")[0].file;
    const rel = readPatchTarget(file0002);
    const lines = fs.readFileSync(file0002, "utf8").split("\n");
    const hunk = lines.findIndex((l) => l.startsWith("@@"));
    const ctx = lines.slice(hunk + 1).find((l) => l.startsWith(" ") && l.trim().length > 10).slice(1);
    const text = read(f.tree, rel).toString("utf8");
    assert.equal(text.split(ctx).length, 2, "context line must be unique");
    fs.writeFileSync(path.join(f.tree, rel), text.replace(ctx, `${ctx} /* changed upstream */`));
    const changedOriginal = read(f.tree, rel);

    const plan = await f.engine.plan(ALL);
    const prot = byId(plan.protections);
    assert.equal(prot["own-box"].action, "unavailable");
    assert.match(prot["own-box"].reason, /0002 does not fit/);
    assert.equal(prot["public-web"].action, "unavailable");
    assert.match(prot["public-web"].reason, /needs "Agents can't change their own box"/);
    for (const id of ALL.filter((x) => !["own-box", "public-web"].includes(x))) assert.equal(prot[id].action, "will-apply", `${id}: ${prot[id].reason}`);
    const r = await f.engine.apply(plan);
    assert.equal(r.ok, true);
    assert.deepEqual(Object.keys(r.unavailable).sort(), ["own-box", "public-web"]);
    const after = read(f.tree, rel).toString("utf8");
    assert.ok(!after.includes("LOCAL-PATCH 0002") && after.includes("LOCAL-PATCH 0009"), "0002 left out, the rest of the file patched");
    for (const id of ["0003", "0008", "0015"]) assert.ok(!fs.readFileSync(path.join(f.tree, readPatchTarget(discoverPatchFiles(f.opts.patchesDir).get(id)[0].file)), "utf8").includes(`LOCAL-PATCH ${id}`));
    const st = byId((await f.engine.status({ serverStartedAt: null })).protections);
    assert.equal(st["own-box"].status, "unavailable");
    assert.equal(st["public-web"].status, "unavailable");
    assert.equal(st["only-boxed"].status, "pending-restart");
    // Off again restores the (changed) original exactly.
    assert.equal((await f.engine.apply(await f.engine.plan([]), { confirmCoreOff: true })).ok, true);
    assert.ok(read(f.tree, rel).equals(changedOriginal));
  } finally { f.cleanup(); }
});

test("all-or-nothing: a write failure in either phase changes no file", { skip }, async () => {
  for (const phase of ["writeFile", "rename"]) {
    let calls = 0;
    const io = { [phase]: (...args) => { if (++calls === 3) throw new Error(`simulated ${phase} failure`); return (phase === "rename" ? fs.renameSync : realWrite)(...args); } };
    const f = fixture({ io });
    try {
      const r = await f.engine.apply(await f.engine.plan(ALL));
      assert.equal(r.ok, false);
      assert.match(r.error, new RegExp(`simulated ${phase} failure.*nothing was changed`));
      assertPristine(f.tree, `after a ${phase} failure`);
      const leftovers = targets.flatMap((rel) => fs.readdirSync(path.dirname(path.join(f.tree, rel))).filter((x) => x.includes(".hardening-")));
      assert.deepEqual(leftovers, []);
      assert.deepEqual((await f.engine.status({ serverStartedAt: null })).enabled, []);
      assert.ok(f.engine.events().some((e) => e.type === "apply-failed"));
    } finally { f.cleanup(); }
  }
});

test("a plan is refused when a file changed after planning", { skip }, async () => {
  const f = fixture();
  try {
    const plan = await f.engine.plan(["pipeline-board-only"]);
    const rel = targets[0];
    fs.appendFileSync(path.join(f.tree, rel), "\n// edited meanwhile\n");
    const r = await f.engine.apply(plan);
    assert.equal(r.ok, false);
    assert.match(r.error, /changed after the plan/);
  } finally { f.cleanup(); }
});

test("drift detection, repair, and pristine refresh after a simulated Paperclip update", { skip }, async () => {
  const f = fixture();
  try {
    assert.equal((await f.engine.apply(await f.engine.plan(ALL))).ok, true);
    const pipelines = readPatchTarget(discoverPatchFiles(f.opts.patchesDir).get("0007")[0].file);
    const portability = readPatchTarget(discoverPatchFiles(f.opts.patchesDir).get("0005d")[0].file);
    const built = read(f.tree, pipelines);

    // 1. Someone edits a built file: drifted; plan refuses to touch it; repair rebuilds it from the stored original.
    fs.appendFileSync(path.join(f.tree, pipelines), "\n// hand edit\n");
    let st = await f.engine.status({ serverStartedAt: null });
    assert.equal(st.files.find((x) => x.rel === pipelines).state, "drifted");
    assert.equal(byId(st.protections)["pipeline-board-only"].status, "drifted");
    assert.equal(byId(st.protections)["safe-defaults"].status, "pending-restart");
    let plan = await f.engine.replan();
    assert.equal(byId(plan.protections)["pipeline-board-only"].action, "unavailable");
    plan = await f.engine.replan({ repair: true });
    assert.equal(byId(plan.protections)["pipeline-board-only"].action, "will-apply");
    assert.equal((await f.engine.apply(plan)).ok, true);
    assert.ok(read(f.tree, pipelines).equals(built));

    // 2. A Paperclip update replaces a target file with a new unpatched version: it becomes the new pristine.
    const updated = Buffer.concat([baseFile(portability), Buffer.from("\n// paperclip update 2026.1099.0\n")]);
    fs.writeFileSync(path.join(f.tree, portability), updated);
    st = await f.engine.status({ serverStartedAt: null });
    assert.equal(st.files.find((x) => x.rel === portability).state, "drifted");
    assert.equal(byId(st.protections)["safe-defaults"].status, "drifted");
    plan = await f.engine.replan();
    const entry = plan.files.find((x) => x.rel === portability);
    assert.equal(entry.pristineSource, "refreshed");
    assert.equal(byId(plan.protections)["safe-defaults"].action, "will-apply");
    assert.equal((await f.engine.apply(plan)).ok, true);
    const ev = f.engine.events().filter((e) => e.type === "pristine-refreshed");
    assert.equal(ev.length, 1);
    assert.equal(ev[0].rel, portability);
    const now = read(f.tree, portability).toString("utf8");
    assert.ok(now.includes("LOCAL-PATCH 0005d") && now.includes("paperclip update 2026.1099.0"));
    const later = new Date(Date.now() + 60_000).toISOString();
    st = await f.engine.status({ serverStartedAt: later });
    assert.equal(st.restartNeeded, false);
    assert.ok(st.protections.filter((p) => p.kind === "patch").every((p) => p.status === "applied"));
    assert.equal((await f.engine.status({ serverStartedAt: "2000-01-01T00:00:00Z" })).restartNeeded, true);

    // 3. restoreAll puts back the NEW original for the updated file and the old ones elsewhere.
    assert.equal((await f.engine.restoreAll()).ok, true);
    assert.ok(read(f.tree, portability).equals(updated));
    for (const rel of targets.filter((x) => x !== portability)) assert.ok(read(f.tree, rel).equals(baseFile(rel)), rel);
  } finally { f.cleanup(); }
});

test("restoreAll is byte-identical and clears state; outside changes are left alone unless forced", { skip }, async () => {
  const f = fixture();
  try {
    assert.equal((await f.engine.apply(await f.engine.plan(ALL))).ok, true);
    const r = await f.engine.restoreAll();
    assert.equal(r.ok, true);
    assert.equal(r.restored.length, targets.length);
    assertPristine(f.tree, "after restoreAll");
    const st = await f.engine.status({ serverStartedAt: null });
    assert.deepEqual(st.enabled, []);
    assert.equal(st.restartNeeded, true);
    assert.ok(!fs.existsSync(path.join(f.opts.dataDir, "pristine")));
    assert.ok(st.protections.every((p) => p.status === "off"));

    assert.equal((await f.engine.apply(await f.engine.plan(["pipeline-board-only"]))).ok, true);
    const rel = readPatchTarget(discoverPatchFiles(f.opts.patchesDir).get("0007")[0].file);
    fs.appendFileSync(path.join(f.tree, rel), "\n// outside\n");
    const soft = await f.engine.restoreAll();
    assert.deepEqual(soft.skipped.map((s) => s.rel), [rel]);
    assert.match(read(f.tree, rel).toString("utf8"), /\/\/ outside\n$/);
    const forced = await f.engine.restoreAll({ force: true });
    assert.equal(forced.ok, true);
    assert.deepEqual(forced.restored, [rel]);
    assertPristine(f.tree, "after a forced restore");
  } finally { f.cleanup(); }
});

test("taking over a tree patched by apply.sh: verified .orig, or adoptOrig when the patch files differ", { skip }, async () => {
  const f = fixture();
  try {
    for (const rel of targets) {
      fs.copyFileSync(path.join(live, rel), path.join(f.tree, rel));
      fs.copyFileSync(path.join(live, `${rel}.orig`), path.join(f.tree, `${rel}.orig`));
    }
    const plan = await f.engine.plan(ALL);
    const reproducible = plan.files.filter((x) => x.pristineSource === "orig").map((x) => x.rel);
    const differing = plan.files.filter((x) => x.blocked).map((x) => x.rel);
    assert.equal(reproducible.length + differing.length, targets.length);
    for (const rel of differing) assert.match(plan.files.find((x) => x.rel === rel).blocked, /adopt/);
    const adopt = await f.engine.plan(ALL, { adoptOrig: true });
    for (const p of adopt.protections.filter((x) => x.kind === "patch")) assert.equal(p.action, "will-apply", `${p.id}: ${p.reason}`);
    assert.equal((await f.engine.apply(adopt)).ok, true);
    assert.equal((await f.engine.restoreAll()).ok, true);
    for (const rel of targets) assert.ok(read(f.tree, rel).equals(baseFile(rel)), `${rel} not restored to its .orig`);
  } finally { f.cleanup(); }
});

test("CLI: plan, apply, status and restore on a scratch tree", { skip }, async () => {
  const f = fixture();
  try {
    const run = (...args) => {
      const r = spawnSync(process.execPath, [CLI, ...args, "--tree", f.tree, "--data", f.opts.dataDir, "--patches", f.opts.patchesDir, "--no-systemd", "--json"],
        { encoding: "utf8", env: { ...process.env, TMPDIR: scratchRoot } });
      return { code: r.status, json: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
    };
    const p = run("plan", "--enable", "assign-needs-grant");
    assert.equal(p.code, 0, p.stderr);
    assert.equal(byId(p.json.protections)["assign-needs-grant"].action, "will-apply");
    assertPristine(f.tree, "after plan");
    const a = run("apply", "--enable", "defaults");
    assert.equal(a.code, 0, a.stderr);
    assert.equal(a.json.result.ok, true);
    const s = run("status");
    assert.equal(s.code, 0);
    assert.equal(byId(s.json.protections)["assign-needs-grant"].status, "pending-restart");
    assert.equal(run("apply", "--enable", "none").code, 1); // core switch-off without confirmation
    assert.equal(run("restore").code, 0);
    assertPristine(f.tree, "after CLI restore");
    assert.equal(run("bogus").code, 2);
  } finally { f.cleanup(); }
});
