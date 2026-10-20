// The Hardening service is bound to the Paperclip it was started by: tree, data dir, settings file and restart come from
// the target; without a target every write refuses and nothing is written. The scratch-tree cases need the live
// install's .orig backups (like worker.test.mjs) and are skipped without them.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHardening, NotAllowedError, TargetUnknownError, SETTINGS_KEY, TARGET_ALERT_KEY } from "../src/hardening.js";
import { createEngine } from "../src/engine/index.js";
import { readRunLogFile, discoverHermesDbs } from "../src/caps.js";
import { runSelfTest } from "../src/selftest.js";
import { writeHardeningConfig } from "../src/settings.js";
import { makeScratchBase, fakeTarget, hardeningFor } from "./helpers/scratch-tree.mjs";

const S = makeScratchBase("instance-test-");
const skip = S.skip;
test.after(() => { if (!skip) S.cleanup(); });
const tmp = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "instance-unit-"));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const actor = (type, userId, companyId = "c1") => ({ actor: Object.freeze({ type, userId, agentId: type === "agent" ? "a1" : null, runId: null, companyId }), companyId });
const ADMIN = actor("user", "u-admin");
const MEMBER = actor("user", "u-member");
const AGENT = actor("agent", null);

function fakeCtx({ withIssues = false } = {}) {
  const state = new Map();
  const issues = [];
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const warns = [];
  const ctx = {
    state: { get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null), set: async (key, v) => { state.set(k(key), structuredClone(v)); } },
    config: { get: async (companyId) => (companyId === "c1" ? { adminUserIds: ["u-admin"] } : {}) },
    activity: { log: async () => {} },
    logger: { info() {}, warn: (...a) => warns.push(a), error() {}, debug() {} },
    ...(withIssues ? { issues: { create: async (i) => { issues.push(i); return { id: `i${issues.length}`, identifier: `X-${issues.length}` }; } } } : {}),
  };
  return { ctx, state, issues, warns, get: (key) => state.get(k(key)) };
}

const UNKNOWN = { ok: false, code: "UNKNOWN_LAUNCHER", reason: "cannot tell which Paperclip this is: not a paperclipai run; use the command-line tool", evidence: ["script /secret/path/index.js"] };
const unknownTarget = () => UNKNOWN;
const spyEngine = (calls) => () => { calls.push("createEngine"); throw new Error("the engine must not be created without a target"); };

// ---------- no target: fail closed
test("without a target: status says why, nothing is written or created, every write refuses after the admin check", async () => {
  const fk = fakeCtx();
  const calls = [];
  const file = path.join(tmp, "nowhere", "config.json");
  const h = createHardening({ ctx: fk.ctx, resolveTargetFn: unknownTarget, createEngineFn: spyEngine(calls) });
  const st = await h.getStatus();
  assert.equal(st.available, false);
  assert.equal(st.reason, UNKNOWN.reason);
  assert.deepEqual(st.target, { ok: false, code: "UNKNOWN_LAUNCHER", reason: UNKNOWN.reason });
  assert.equal(st.configPath, null);
  assert.ok(!JSON.stringify(st).includes("/secret/path"), "evidence stays out of the page data");
  assert.equal(st.protections.length > 0, true);
  const settings = await h.getSettings();
  assert.deepEqual([settings.configPath, settings.target, settings.enabled], [null, null, null]);

  const writes = {
    applyChange: () => h.applyChange({ enabled: [] }, ADMIN),
    restart: () => h.restart({}, ADMIN),
    restoreAll: () => h.restoreAll({ confirm: true }, ADMIN),
    saveSettings: () => h.saveSettings({ settings: { baseAllowlist: ["api.anthropic.com"] } }, ADMIN),
    runSelfTest: () => h.runSelfTest({}, ADMIN),
  };
  for (const [name, call] of Object.entries(writes)) await assert.rejects(call(), (e) => e instanceof TargetUnknownError && e.targetCode === "UNKNOWN_LAUNCHER" && !/secret\/path/.test(e.message), name);
  await assert.rejects(h.planChange({ enabled: [] }, ADMIN), TargetUnknownError);
  // The admin check comes first: agents and non-admins learn nothing about the target.
  for (const [name, who] of [["agent", AGENT], ["member", MEMBER]]) {
    await assert.rejects(h.applyChange({ enabled: [] }, who), (e) => e instanceof NotAllowedError, `applyChange ${name}`);
    await assert.rejects(h.saveSettings({ settings: {} }, who), (e) => e instanceof NotAllowedError, `saveSettings ${name}`);
    await assert.rejects(h.restart({}, who), (e) => e instanceof NotAllowedError, `restart ${name}`);
    await assert.rejects(h.restoreAll({ confirm: true }, who), (e) => e instanceof NotAllowedError, `restoreAll ${name}`);
    await assert.rejects(h.runSelfTest({}, who), (e) => e instanceof NotAllowedError, `runSelfTest ${name}`);
  }
  await assert.rejects(h.planChange({ enabled: [] }, AGENT), NotAllowedError);
  assert.deepEqual(calls, [], "no engine was ever created");
  assert.equal(fk.get(SETTINGS_KEY), undefined, "no settings were stored");
  assert.equal(fs.existsSync(file), false);
  assert.deepEqual(fs.readdirSync(tmp).filter((n) => n === "nowhere"), []);
});

test("without a target the worker start changes nothing and raises one alert; the self-test after start does not run", async () => {
  const fk = fakeCtx({ withIssues: true });
  await fk.ctx.state.set(SETTINGS_KEY, { alertCompanyId: "c-alerts", baseAllowlist: ["api.anthropic.com"] });
  const h = createHardening({ ctx: fk.ctx, resolveTargetFn: unknownTarget, createEngineFn: spyEngine([]) });
  const r = await h.start();
  assert.deepEqual([r.ok, r.code, r.config], [false, "UNKNOWN_LAUNCHER", null]);
  assert.equal(fk.issues.length, 1);
  assert.match(fk.issues[0].title, /Cannot tell which Paperclip/);
  assert.deepEqual(fk.get(TARGET_ALERT_KEY), { code: "UNKNOWN_LAUNCHER" });
  await h.start();
  assert.equal(fk.issues.length, 1, "one alert per failure code");
  const st = await h.selfTestAfterStart();
  assert.deepEqual([st.ok, st.ran], [true, false]);
  assert.equal(fk.warns.length, 1, "the failure is logged once, with its evidence");
  assert.deepEqual(fk.warns[0][1].evidence, UNKNOWN.evidence);
});

test("the real default is strict too: a worker whose parent is not a paperclipai server (this test runner) has no target", async () => {
  const fk = fakeCtx();
  const h = createHardening({ ctx: fk.ctx });
  const st = await h.getStatus();
  assert.equal(st.available, false);
  assert.equal(st.target.ok, false);
  assert.ok(["UNKNOWN_LAUNCHER", "PROC_UNREADABLE", "FOREIGN_UID", "NO_PARENT"].includes(st.target.code), st.target.code);
  await assert.rejects(h.applyChange({ enabled: [] }, ADMIN), TargetUnknownError);
});

// ---------- with a target
test("the engine is built from the target and nothing else; the page shows the target", async () => {
  const fk = fakeCtx();
  const seen = [];
  const target = fakeTarget({ tree: "/t/tree", dataDir: "/t/data", instanceId: "dev", home: "/t", instanceRoot: "/t/instances/dev", restart: { unit: "paperclipai-dev.service", cgroup: "/c", pid: 7 } });
  const engine = {
    tree: "/t/tree", protections: () => [], restartInfo: () => ({ canRestart: false, reason: "r" }),
    status: async () => ({ tree: "/t/tree", paperclipVersion: "1", enabled: [], appliedAt: null, serverStartedAt: null, restartNeeded: false, protections: [], files: [] }),
    plan: async () => ({ unavailable: {} }),
  };
  const h = createHardening({ ctx: fk.ctx, ...hardeningFor(target, { patchesDir: "/p" }), createEngineFn: (o) => { seen.push(o); return engine; } });
  const st = await h.getStatus();
  assert.equal(st.available, true);
  assert.deepEqual(seen[0], { patchesDir: "/p", treeDir: "/t/tree", dataDir: "/t/data", restart: target.restart, refuseTreeChange: true });
  assert.deepEqual(st.target, { ok: true, source: "test", pid: null, tree: "/t/tree", instanceId: "dev", home: "/t", instanceRoot: "/t/instances/dev", dataDir: "/t/data",
    configPath: target.configPath, deploymentMode: null, restartUnit: "paperclipai-dev.service", restartNote: null });
  assert.equal(st.configPath, target.configPath);
  assert.equal((await h.getSettings()).target.instanceId, "dev");
  await h.getStatus();
  assert.equal(seen.length, 1, "the engine is built once per target");
});

test("the server process changing between plan and write refuses the write (nothing applied) and forgets the target", async () => {
  const fk = fakeCtx();
  const calls = [];
  let verifies = 0;
  let resolves = 0;
  const engine = {
    tree: "/t", protections: () => [], status: async () => ({ enabled: [] }),
    plan: async () => { calls.push("plan"); return { enabled: [], added: [], neededOff: [], confirmationNeeded: [], protections: [], unavailable: {}, changes: 0, restartNeededAfterApply: false }; },
    apply: async () => { calls.push("apply"); return { ok: true, changed: [], applied: [], unavailable: {} }; },
    restoreAll: async () => { calls.push("restore"); return { ok: true, restored: [], skipped: [] }; },
    restartInfo: () => ({ canRestart: false, reason: "r" }),
  };
  const h = createHardening({ ctx: fk.ctx, resolveTargetFn: () => { resolves++; return { ok: true, target: fakeTarget() }; }, createEngineFn: () => engine,
    verifyTargetFn: () => (++verifies <= 1 ? { ok: true } : { ok: false, code: "TARGET_CHANGED", reason: "the Paperclip server process (pid 1) is gone" }) });
  await assert.rejects(h.applyChange({ enabled: [] }, ADMIN), (e) => e instanceof TargetUnknownError && e.targetCode === "TARGET_CHANGED");
  assert.deepEqual(calls, ["plan"], "planned, but never applied");
  verifies = 100; // later calls fail at the first check
  await assert.rejects(h.restoreAll({ confirm: true }, ADMIN), TargetUnknownError);
  await assert.rejects(h.saveSettings({ settings: {} }, ADMIN), TargetUnknownError);
  assert.deepEqual(calls, ["plan"]);
  assert.ok(resolves >= 2, "after a changed target the next call derives it again");
});

test("runSelfTest and the page's settings file come from the target, not from the worker's environment", async () => {
  const fk = fakeCtx();
  const target = fakeTarget({ instanceRoot: path.join(tmp, "inst-st"), tree: "/t" });
  const seen = [];
  const engine = { tree: "/t", protections: () => [], restartInfo: () => ({ canRestart: false }), status: async () => ({ tree: "/t", enabled: [], restartNeeded: false, protections: [], files: [] }) };
  const h = createHardening({ ctx: fk.ctx, ...hardeningFor(target), createEngineFn: () => engine, runSelfTestFn: async (o) => { seen.push(o); return { at: "2026-10-19T00:00:00Z", results: {} }; } });
  await h.runSelfTest({}, ADMIN);
  assert.equal(seen[0].instanceRoot, target.instanceRoot);
  assert.deepEqual(seen[0].env, { PAPERCLIP_HARDENING_CONFIG: target.configPath });
  const saved = await h.saveSettings({ settings: { baseAllowlist: ["api.anthropic.com"], restartUnit: "dropped" } }, ADMIN);
  assert.equal(saved.configPath, target.configPath);
  assert.equal("restartUnit" in saved.settings, false, "the removed setting is an unknown key and is dropped");
  assert.ok(fs.existsSync(target.configPath));
});

// ---------- services that read paths
test("no home fallback in settings, self-test, caps: the paths are required", async () => {
  assert.throws(() => writeHardeningConfig({}, {}), /absolute path/);
  assert.throws(() => writeHardeningConfig({}, { file: "relative.json" }), /absolute path/);
  await assert.rejects(runSelfTest({ engine: { tree: "/t", protections: () => [] }, status: { tree: "/t", protections: [], files: [] } }), /instance root/);
  assert.deepEqual(discoverHermesDbs(null), []);
  await assert.rejects(readRunLogFile({ log_ref: "x" }), /not known/);
  const base = path.join(tmp, "rl");
  fs.mkdirSync(path.join(base, "c"), { recursive: true });
  fs.writeFileSync(path.join(base, "c/r.ndjson"), "hello");
  assert.equal(await readRunLogFile({ log_ref: "c/r.ndjson" }, { base }), "hello");
});

// ---------- two installs on one host (scratch trees)
test("two instances: the one this worker serves is changed, the other install and its data stay untouched", { skip }, async () => {
  const a = S.fresh();
  const b = S.fresh();
  try {
    const fk = fakeCtx();
    const h = createHardening({ ctx: fk.ctx, ...a.hardening });
    const r = await h.applyChange({ enabled: ["public-web"] }, ADMIN);
    assert.equal(r.ok, true, r.error);
    assert.ok(r.changed.length > 0);
    assert.equal((await h.saveSettings({ settings: { baseAllowlist: ["api.anthropic.com"] } }, ADMIN)).ok, true);
    assert.ok(fs.existsSync(a.configPath), "the settings file is written under the served instance");
    assert.ok(fs.existsSync(path.join(a.dir, "data/state.json")));
    for (const rel of S.targets) assert.ok(fs.readFileSync(path.join(b.tree, rel)).equals(S.baseFile(rel)), `${rel} of the other install was touched`);
    assert.equal(fs.existsSync(b.configPath), false);
    assert.equal(fs.existsSync(path.join(b.dir, "data")), false);
    assert.deepEqual(fs.readdirSync(b.dir).sort(), ["tree"]);
    // And the reverse: a worker serving B sees B as unmanaged and A's files are not part of its plan.
    const hb = createHardening({ ctx: fakeCtx().ctx, ...b.hardening });
    assert.deepEqual((await hb.getStatus()).enabled, []);
  } finally { a.cleanup(); b.cleanup(); }
});

test("a data dir that belongs to another live install is refused (apply and restore); a moved or vanished one is taken over", { skip }, async () => {
  const a = S.fresh();
  const b = S.fresh();
  try {
    const opts = (f, extra = {}) => ({ ...f.engineOptions, dataDir: a.engineOptions.dataDir, refuseTreeChange: true, ...extra });
    const ea = createEngine(opts(a));
    assert.equal((await ea.apply(await ea.plan(["public-web"]))).ok, true);
    const eb = createEngine(opts(b));
    const planB = await eb.plan(["public-web"]);
    const refusedApply = await eb.apply(planB);
    assert.equal(refusedApply.ok, false);
    assert.match(refusedApply.error, /belongs to the Paperclip install at .*case-\d+\/tree/);
    const refusedRestore = await eb.restoreAll();
    assert.equal(refusedRestore.ok, false);
    for (const rel of S.targets) assert.ok(fs.readFileSync(path.join(b.tree, rel)).equals(S.baseFile(rel)), `${rel} changed although refused`);
    // Without the guard (the CLI with explicit --tree/--data) the old behaviour stays: only an event is logged.
    const loose = createEngine({ ...b.engineOptions, dataDir: a.engineOptions.dataDir });
    assert.equal((await loose.apply(await loose.plan(["public-web"]))).ok, true);
    assert.ok(loose.events().some((e) => e.type === "tree-changed"));
    // A tree that is gone (the install was replaced): the data dir may move on.
    fs.rmSync(a.tree, { recursive: true });
    const c = S.fresh();
    try {
      const ec = createEngine({ ...c.engineOptions, dataDir: a.engineOptions.dataDir, refuseTreeChange: true });
      assert.equal(ec.dataDir, a.engineOptions.dataDir);
      const state = JSON.parse(fs.readFileSync(path.join(a.engineOptions.dataDir, "state.json"), "utf8"));
      assert.equal(state.tree, fs.realpathSync(b.tree));
      assert.equal((await ec.restoreAll()).ok, false, "b is a live tree, c may not restore b's originals");
      fs.rmSync(b.tree, { recursive: true });
      assert.equal((await ec.restoreAll()).ok, true);
    } finally { c.cleanup(); }
  } finally { a.cleanup(); b.cleanup(); }
});
