// Worker actions of the Hardening page (src/hardening.js via src/worker.js) with a fake plugin context. The engine
// tests run against a scratch tree (test/helpers/scratch-tree.mjs); the live tree is only read.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHardening, NotAllowedError, SETTINGS_KEY } from "../src/hardening.js";
import { register, ACTIONS, BOX_ACTIONS } from "../src/worker.js";
import { readPatchTarget, discoverPatchFiles } from "../src/engine/patches.js";
import { makeScratchBase } from "./helpers/scratch-tree.mjs";

const S = makeScratchBase("worker-test-");
const skip = S.skip;
test.after(() => { if (!skip) S.cleanup(); });
const tmp = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "worker-unit-"));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const actor = (type, userId, companyId = "c1") => ({ actor: Object.freeze({ type, userId, agentId: type === "agent" ? "a1" : null, runId: null, companyId }), companyId });
const ADMIN = actor("user", "u-admin");
const MEMBER = actor("user", "u-member");
const AGENT = actor("agent", null);
const INSTANCE_ADMIN = actor("user", "u-root", null); // company-less call: the host already required instance admin

function fakeCtx({ adminUserIds = ["u-admin"] } = {}) {
  const state = new Map();
  const logs = [];
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const reg = { data: {}, actions: {}, jobs: {} };
  const ctx = {
    state: { get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null), set: async (key, v) => { state.set(k(key), structuredClone(v)); } },
    config: { get: async (companyId) => (companyId === "c1" ? { adminUserIds } : {}) },
    activity: { log: async (e) => { logs.push(e); } },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    data: { register: (key, fn) => { reg.data[key] = fn; } },
    actions: { register: (key, fn) => { reg.actions[key] = fn; } },
    jobs: { register: (key, fn) => { reg.jobs[key] = fn; } },
    companies: { list: async () => [] },
    agents: { list: async () => [] },
  };
  return { ctx, state, logs, reg };
}
const byId = (list) => Object.fromEntries(list.map((p) => [p.id, p]));
const read = (tree, rel) => fs.readFileSync(path.join(tree, rel));
function assertPristine(tree, msg) {
  for (const rel of S.targets) assert.ok(read(tree, rel).equals(S.baseFile(rel)), `${rel} is not byte-identical to the original ${msg}`);
}
const noEngine = () => { throw new Error("no engine in this test"); };

// ---------- no tree needed
test("write actions: agents, system calls and unlisted users are refused; listed users and company-less admins pass", async () => {
  const { ctx } = fakeCtx();
  const h = createHardening({ ctx, createEngineFn: noEngine, configPath: path.join(tmp, "a", "config.json") });
  await assert.rejects(h.assertAdmin(AGENT), (e) => e instanceof NotAllowedError && /agent/.test(e.message));
  await assert.rejects(h.assertAdmin(actor("system", null)), NotAllowedError);
  await assert.rejects(h.assertAdmin(MEMBER), /u-member/);
  await assert.rejects(h.assertAdmin(undefined), NotAllowedError);
  assert.equal((await h.assertAdmin(ADMIN)).userId, "u-admin");
  assert.equal((await h.assertAdmin(INSTANCE_ADMIN)).userId, "u-root");
  // A user listed in ANOTHER company's config does not pass in c2.
  await assert.rejects(h.assertAdmin(actor("user", "u-admin", "c2")), NotAllowedError);
});

test("saveSettings: validates, stores, writes config.json (0600, only non-empty values) and logs; agents refused", async () => {
  const { ctx, state, logs } = fakeCtx();
  const file = path.join(tmp, "b", "hardening", "config.json");
  const h = createHardening({ ctx, createEngineFn: noEngine, configPath: file });
  await assert.rejects(h.saveSettings({ settings: { baseAllowlist: ["x.example"] } }, AGENT), NotAllowedError);
  assert.equal(fs.existsSync(file), false);
  const bad = await h.saveSettings({ settings: { baseAllowlist: ["*:443"], workspaceRoots: ["relative"] } }, ADMIN);
  assert.equal(bad.ok, false);
  assert.equal(bad.errors.length, 2);
  assert.equal(fs.existsSync(file), false);
  const ok = await h.saveSettings({ settings: { baseAllowlist: "api.anthropic.com\n10.0.0.5:3100", extraReadOnlyPaths: ["/opt/vault/bin"], restartUnit: "paperclip", alertCompanyId: "c1" } }, ADMIN);
  assert.equal(ok.ok, true);
  assert.equal(ok.configChanged, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), { schema: 1, writtenBy: "paperclip-sandbox-hardening", baseAllowlist: ["api.anthropic.com", "10.0.0.5:3100"], extraReadOnlyPaths: ["/opt/vault/bin"] });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(state.get(`${SETTINGS_KEY.scopeKind}::${SETTINGS_KEY.stateKey}`).restartUnit, "paperclip");
  assert.equal(logs.length, 1);
  assert.equal(logs[0].companyId, "c1");
  assert.match(logs[0].message, /settings changed/);
  // Same settings again: no rewrite, no new log entry.
  const again = await h.saveSettings({ settings: ok.settings }, ADMIN);
  assert.equal(again.configChanged, false);
  assert.equal(logs.length, 1);
  assert.deepEqual((await h.loadSettings()).baseAllowlist, ["api.anthropic.com", "10.0.0.5:3100"]);
});

test("register(): every page action and data key is wired to the service", async () => {
  const { ctx, reg } = fakeCtx();
  const calls = [];
  const fake = Object.fromEntries([...ACTIONS, "loadSettings"].map((name) => [name, async (params, context) => { calls.push([name, params, context]); return name; }]));
  register(ctx, { hardening: fake });
  assert.deepEqual(Object.keys(reg.actions).sort(), [...ACTIONS, ...BOX_ACTIONS].sort());
  assert.ok(reg.data["hardening-status"] && reg.data["hardening-settings"] && reg.data.compliance);
  assert.ok(reg.jobs["verify-sandbox-config"] && reg.jobs["daily-token-caps"]);
  assert.equal(await reg.actions.applyChange({ enabled: [] }, ADMIN), "applyChange");
  assert.deepEqual(calls.at(-1), ["applyChange", { enabled: [] }, ADMIN]);
  assert.equal(await reg.data["hardening-status"]({}), "getStatus");
});

// ---------- scratch tree
function service(f, opts = {}) {
  const fk = fakeCtx(opts);
  return { ...fk, h: createHardening({ ctx: fk.ctx, engineOptions: f.engineOptions, configPath: f.configPath }) };
}

test("planChange: dependencies are added, dependents of a switched-off protection go off too, core switch-offs are listed", { skip }, async () => {
  const f = S.fresh();
  try {
    const { h } = service(f);
    const p1 = await h.planChange({ enabled: ["public-web"] });
    assert.deepEqual(p1.enabled, ["sandbox-compat", "own-box", "public-web"]);
    assert.deepEqual(p1.added.map((a) => a.id), ["sandbox-compat", "own-box"]);
    assert.deepEqual(p1.added[0].neededBy, ["Public-web box"]);
    assert.deepEqual(p1.confirmationNeeded, []);
    assert.ok(p1.changes > 0);
    assertPristine(f.tree, "after a plan");
    assert.equal((await h.applyChange({ enabled: ["public-web"] }, ADMIN)).ok, true);
    // Switching off sandbox-compat while keeping public-web: public-web and own-box need it, so they go off as well.
    const p2 = await h.planChange({ enabled: ["own-box", "public-web"] });
    assert.deepEqual(p2.switchedOffDependents.map((d) => d.id).sort(), ["own-box", "public-web"]);
    assert.deepEqual(p2.enabled, []);
    assert.deepEqual(p2.confirmationNeeded.map((c) => c.id), ["sandbox-compat", "own-box"]);
    assert.ok(p2.confirmationNeeded.every((c) => c.risk));
    // Placeholder (non-patch) protections are ignored; unknown ids are an error.
    assert.deepEqual((await h.planChange({ enabled: ["sandbox-compat", "own-box", "public-web", "daily-caps"] })).enabled, ["sandbox-compat", "own-box", "public-web"]);
    await assert.rejects(h.planChange({ enabled: ["nope"] }), /unknown protection/);
    await assert.rejects(h.planChange({ enabled: "public-web" }), /list/);
    await assert.rejects(h.planChange({ enabled: [] }, AGENT), NotAllowedError);
  } finally { f.cleanup(); }
});

test("applyChange: admin only, refuses core switch-off without confirmation, logs every applied change", { skip }, async () => {
  const f = S.fresh();
  try {
    const { h, logs } = service(f);
    await assert.rejects(h.applyChange({ enabled: ["pipeline-board-only"] }, AGENT), NotAllowedError);
    await assert.rejects(h.applyChange({ enabled: ["pipeline-board-only"] }, MEMBER), NotAllowedError);
    assertPristine(f.tree, "after refused calls");
    assert.equal(logs.length, 0);

    const defaults = ["sandbox-compat", "own-box", "only-boxed", "safe-defaults", "no-permission-handing", "pipeline-board-only", "assign-needs-grant", "public-web", "own-claude-folder"];
    const on = await h.applyChange({ enabled: defaults }, ADMIN);
    assert.equal(on.ok, true, on.error);
    assert.ok(on.changed.length > 0);
    assert.equal(on.restartNeeded, true);
    assert.equal(logs.length, 1);
    assert.equal(logs[0].companyId, "c1");
    assert.equal(logs[0].metadata.userId, "u-admin");
    assert.equal(logs[0].metadata.turnedOn.length, defaults.length);
    const builtNow = Object.fromEntries(S.targets.map((rel) => [rel, read(f.tree, rel)]));

    let st = await h.getStatus();
    const rows = byId(st.protections);
    for (const id of defaults) assert.equal(rows[id].status, "pending-restart", id);
    for (const id of ["watchdog", "hermes-boxed"]) { assert.equal(rows[id].placeholder, true); assert.equal(rows[id].status, "placeholder"); }
    assert.equal(rows["daily-caps"].managedElsewhere, true);
    assert.equal(rows["daily-caps"].status, "on");
    assert.match(rows["daily-caps"].reason, /Agent boxes page/);
    assert.equal(st.restart.needed, true);
    assert.equal(st.restart.canRestart, false);

    // Core switch-off without confirmation: refused, nothing changes, nothing logged.
    const refused = await h.applyChange({ enabled: defaults.filter((id) => id !== "only-boxed") }, ADMIN);
    assert.equal(refused.ok, false);
    assert.match(refused.error, /confirmation/);
    assert.deepEqual(refused.plan.confirmationNeeded.map((c) => c.id), ["only-boxed"]);
    for (const rel of S.targets) assert.ok(read(f.tree, rel).equals(builtNow[rel]), `${rel} changed by a refused apply`);
    assert.equal(logs.length, 1);

    const confirmed = await h.applyChange({ enabled: defaults.filter((id) => id !== "only-boxed"), confirmCoreOff: true }, ADMIN);
    assert.equal(confirmed.ok, true, confirmed.error);
    assert.equal(logs.length, 2);
    assert.deepEqual(logs[1].metadata.turnedOff, ["only-boxed"]);
    assert.equal(logs[1].metadata.confirmCoreOff, true);
    st = await h.getStatus();
    assert.equal(byId(st.protections)["only-boxed"].status, "off");

    // Same set again: nothing changes, no log entry.
    assert.equal((await h.applyChange({ enabled: defaults.filter((id) => id !== "only-boxed") }, ADMIN)).ok, true);
    assert.equal(logs.length, 2);
  } finally { f.cleanup(); }
});

test("restoreAll: admin only, needs confirmation, gives byte-identical originals and logs", { skip }, async () => {
  const f = S.fresh();
  try {
    const { h, logs } = service(f);
    assert.equal((await h.applyChange({ enabled: ["public-web", "own-claude-folder", "assign-needs-grant"] }, ADMIN)).ok, true);
    await assert.rejects(h.restoreAll({ confirm: true }, AGENT), NotAllowedError);
    const unconfirmed = await h.restoreAll({}, ADMIN);
    assert.equal(unconfirmed.ok, false);
    assert.match(unconfirmed.error, /confirmation/);
    assert.ok(S.targets.some((rel) => !read(f.tree, rel).equals(S.baseFile(rel))));
    const r = await h.restoreAll({ confirm: true }, ADMIN);
    assert.equal(r.ok, true);
    assert.equal(r.restartNeeded, true);
    assertPristine(f.tree, "after restoreAll");
    assert.match(logs.at(-1).message, /original Paperclip files restored/);
    const st = await h.getStatus();
    assert.ok(st.protections.filter((p) => !p.placeholder && !p.managedElsewhere).every((p) => p.status === "off"));
  } finally { f.cleanup(); }
});

test("restart: without a systemd user unit the page gets the 'restart Paperclip now' text; agents refused", { skip }, async () => {
  const f = S.fresh();
  try {
    const { h, logs } = service(f);
    await assert.rejects(h.restart({}, AGENT), NotAllowedError);
    const r = await h.restart({}, ADMIN);
    assert.equal(r.ok, false);
    assert.equal(r.manual, true);
    assert.match(r.message, /^Restart Paperclip now/);
    assert.equal(logs.length, 0);
  } finally { f.cleanup(); }
});

test("start: writes config.json, leaves an unmanaged or apply.sh-patched tree alone, re-applies after a Paperclip update", { skip }, async () => {
  const f = S.fresh();
  try {
    const fk = fakeCtx();
    await fk.ctx.state.set(SETTINGS_KEY, { baseAllowlist: ["api.anthropic.com"], alertCompanyId: "c-alerts" });
    const h = createHardening({ ctx: fk.ctx, engineOptions: f.engineOptions, configPath: f.configPath });
    let r = await h.start();
    assert.equal(r.applied, false);
    assert.deepEqual(JSON.parse(fs.readFileSync(f.configPath, "utf8")).baseAllowlist, ["api.anthropic.com"]);
    assertPristine(f.tree, "after start on an unmanaged tree");

    // A tree patched by apply.sh (live files + .orig): nothing switched on in the engine, so start must not touch it.
    const g = S.fresh();
    try {
      for (const rel of S.targets) { fs.copyFileSync(path.join(S.live, rel), path.join(g.tree, rel)); fs.copyFileSync(path.join(S.live, `${rel}.orig`), path.join(g.tree, `${rel}.orig`)); }
      const hg = createHardening({ ctx: fakeCtx().ctx, engineOptions: g.engineOptions, configPath: g.configPath });
      assert.equal((await hg.start()).applied, false);
      assert.equal(fs.existsSync(g.configPath), false, "no settings saved yet: the settings file is not written");
      for (const rel of S.targets) assert.ok(read(g.tree, rel).equals(read(S.live, rel)), `${rel}: start changed an apply.sh-patched file`);
    } finally { g.cleanup(); }

    // Managed tree, then a Paperclip update replaces one target file with a new unpatched version.
    assert.equal((await h.applyChange({ enabled: ["safe-defaults"] }, ADMIN)).ok, true);
    const rel = readPatchTarget(discoverPatchFiles(f.engineOptions.patchesDir).get("0005d")[0].file);
    const updated = Buffer.concat([S.baseFile(rel), Buffer.from("\n// paperclip update\n")]);
    fs.writeFileSync(path.join(f.tree, rel), updated);
    assert.equal(byId((await h.getStatus()).protections)["safe-defaults"].status, "drifted");
    r = await h.start();
    assert.equal(r.ok, true, r.error);
    assert.equal(r.applied, true);
    assert.deepEqual(r.changed, [rel]);
    const now = read(f.tree, rel).toString("utf8");
    assert.ok(now.includes("LOCAL-PATCH 0005d") && now.includes("// paperclip update"));
    const entry = fk.logs.at(-1);
    assert.equal(entry.companyId, "c-alerts");
    assert.deepEqual(entry.metadata.refreshedOriginals, [rel]);
    assert.equal((await h.start()).applied, false, "a second start finds nothing to do");
  } finally { f.cleanup(); }
});

test("getStatus: a protection whose code changed shape shows 'unavailable on this install' while off", { skip }, async () => {
  const f = S.fresh();
  try {
    const file0007 = discoverPatchFiles(f.engineOptions.patchesDir).get("0007")[0].file;
    const rel = readPatchTarget(file0007);
    const lines = fs.readFileSync(file0007, "utf8").split("\n");
    const ctxLine = lines.slice(lines.findIndex((l) => l.startsWith("@@")) + 1).find((l) => l.startsWith(" ") && l.trim().length > 10).slice(1);
    const text = read(f.tree, rel).toString("utf8");
    fs.writeFileSync(path.join(f.tree, rel), text.replace(ctxLine, `${ctxLine} /* changed upstream */`));
    const { h } = service(f);
    const rows = byId((await h.getStatus()).protections);
    assert.equal(rows["pipeline-board-only"].status, "unavailable");
    assert.match(rows["pipeline-board-only"].reason, /0007/);
    assert.equal(rows["public-web"].status, "off");
  } finally { f.cleanup(); }
});

test("getStatus: restart needed until Paperclip has started after the change (server start time from the parent process)", { skip }, async () => {
  const f = S.fresh();
  try {
    let started = "2000-01-01T00:00:00.000Z";
    const fk = fakeCtx();
    const h = createHardening({ ctx: fk.ctx, engineOptions: f.engineOptions, configPath: f.configPath, serverStartedAt: () => started });
    assert.equal((await h.applyChange({ enabled: ["safe-defaults"] }, ADMIN)).ok, true);
    let st = await h.getStatus();
    assert.equal(st.restart.needed, true);
    assert.equal(byId(st.protections)["safe-defaults"].status, "pending-restart");
    started = new Date(Date.now() + 60_000).toISOString();
    st = await h.getStatus();
    assert.equal(st.restart.needed, false);
    assert.equal(byId(st.protections)["safe-defaults"].status, "applied");
    // A settings change read by an applied protection needs a restart again.
    assert.equal((await h.saveSettings({ settings: { baseAllowlist: ["api.anthropic.com", "10.0.0.9:3100"] } }, ADMIN)).configChanged, true);
    started = new Date(Date.now() - 1000).toISOString();
    st = await h.getStatus();
    assert.equal(st.restart.needed, true);
    assert.equal(st.restart.settingsChanged, true);
  } finally { f.cleanup(); }
});
