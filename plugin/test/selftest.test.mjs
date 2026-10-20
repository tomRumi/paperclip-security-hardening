// Self-test after restart (src/selftest.js and hardening.selfTestNow): functional checks on the built files of a
// scratch tree (test/helpers/scratch-tree.mjs; the live tree is only read), the structural fallback, the "waiting for
// restart" state, and a failure turning the row red with one activity entry and one alert issue.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHardening, NotAllowedError, SELFTEST_KEY } from "../src/hardening.js";
import { runSelfTest, structuralCheck, FUNCTIONAL_CHECKS } from "../src/selftest.js";
import { makeScratchBase } from "./helpers/scratch-tree.mjs";

const S = makeScratchBase("selftest-test-");
const skip = S.skip;
test.after(() => { if (!skip) S.cleanup(); });

const actor = (type, userId, companyId = "c1") => ({ actor: Object.freeze({ type, userId, agentId: type === "agent" ? "a1" : null, runId: null, companyId }), companyId });
const ADMIN = actor("user", "u-admin");
const AGENT = actor("agent", null);
const DEFAULTS = ["sandbox-compat", "own-box", "only-boxed", "safe-defaults", "no-permission-handing", "pipeline-board-only", "assign-needs-grant", "public-web", "own-claude-folder", "box-claude", "box-opencode"];
const FUNCTIONAL = ["sandbox-compat", "own-box", "safe-defaults", "public-web", "box-claude", "box-opencode", "only-boxed"];
const usrMerged = (() => { try { return fs.lstatSync("/bin").isSymbolicLink(); } catch { return false; } })();

function fakeCtx({ alertCompanyId = "c1", issuesFail = false } = {}) {
  const state = new Map();
  const logs = [];
  const issues = [];
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const ctx = {
    state: { get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null), set: async (key, v) => { state.set(k(key), structuredClone(v)); } },
    config: { get: async (companyId) => (companyId === "c1" ? { adminUserIds: ["u-admin"] } : {}) },
    activity: { log: async (e) => { logs.push(e); } },
    issues: { create: async (input) => { if (issuesFail) throw new Error("db down"); issues.push(input); return { id: `i-${issues.length}`, identifier: `ENG-${issues.length}` }; } },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  };
  state.set("instance::settings", { alertCompanyId, alertProjectId: "p1" });
  return { ctx, state, logs, issues };
}
const byId = (list) => Object.fromEntries(list.map((p) => [p.id, p]));

test("functional checks fail on Paperclip's original files (they test behaviour, not text)", { skip }, async () => {
  const f = S.fresh();
  try {
    const env = { env: {}, instanceRoot: "/nonexistent-instance-root" };
    for (const id of FUNCTIONAL) {
      if (id === "sandbox-compat" && !usrMerged) continue;
      await assert.rejects(FUNCTIONAL_CHECKS[id][0].run(f.tree, env), undefined, `${id} passes on the original file`);
    }
  } finally { f.cleanup(); }
});

test("after a restart every applied protection passes; six are functional, the rest structural only", { skip }, async () => {
  const f = S.fresh();
  try {
    const fk = fakeCtx();
    let started = "2000-01-01T00:00:00.000Z";
    const h = createHardening({ ctx: fk.ctx, ...f.hardening, serverStartedAt: () => started });
    assert.equal((await h.applyChange({ enabled: DEFAULTS }, ADMIN)).ok, true);
    const logsAfterApply = fk.logs.length;

    // Restart pending: the files on disk are not what Paperclip runs yet, so the self-test waits.
    const waiting = await h.selfTestAfterStart();
    assert.equal(waiting.ran, false);
    assert.match(waiting.reason, /restart/);
    assert.equal((await h.getStatus()).selfTest.waitingRestart, true);

    started = new Date(Date.now() + 60000).toISOString();
    const r = await h.selfTestAfterStart();
    assert.equal(r.ran, true);
    assert.equal(r.ok, true, JSON.stringify(r.results, null, 1));
    assert.deepEqual(Object.keys(r.results).sort(), [...DEFAULTS].sort());
    for (const id of DEFAULTS) {
      const res = r.results[id];
      assert.equal(res.mode, FUNCTIONAL.includes(id) ? "functional" : "structural only", id);
      assert.ok(res.checks.some((c) => c.kind === "structural" && c.ok), `${id} structural`);
    }
    assert.equal(fk.issues.length, 0);
    assert.equal(fk.logs.length, logsAfterApply);
    const st = await h.getStatus();
    const rows = byId(st.protections);
    for (const id of DEFAULTS) {
      assert.equal(rows[id].status, "applied", id);
      assert.equal(rows[id].selfTest.ok, true);
    }
    assert.equal(rows["own-box"].selfTest.mode, "functional");
    assert.equal(rows["pipeline-board-only"].selfTest.mode, "structural only");
    assert.equal(st.selfTest.waitingRestart, false);

    // A later change of the protection's files invalidates the stored result (status no longer claims a pass). Switching the
    // public-web box off also switches off what is built on it (the box for Claude and OpenCode agents); the admission rule is switched off here too (it would keep the Claude box, and so public-web, on).
    assert.equal((await h.applyChange({ enabled: DEFAULTS.filter((id) => id !== "public-web" && id !== "only-boxed"), confirmCoreOff: true }, ADMIN)).ok, true);
    started = new Date(Date.now() + 120000).toISOString();
    const rows2 = byId((await h.getStatus()).protections);
    assert.equal(rows2["sandbox-compat"].selfTest, null, "local-process-sandbox.js was rebuilt");
    assert.equal(rows2["own-box"].selfTest, null, "heartbeat.js was rebuilt without the admission rule");
    assert.equal(rows2["no-permission-handing"].selfTest, null, "routes/agents.js was rebuilt without the board-only test route (only boxed agents run)");
    assert.equal(rows2["pipeline-board-only"].selfTest.ok, true, "its files are unchanged");
  } finally { f.cleanup(); }
});

test("a failed self-test turns the row red, logs once per run and raises one alert issue per failure set", { skip }, async () => {
  const f = S.fresh();
  try {
    const fk = fakeCtx();
    let broken = true;
    const checks = { ...FUNCTIONAL_CHECKS, "own-box": [{ name: "a run override cannot widen the stored box (0003)", run: async () => { if (broken) throw new Error("LD_PRELOAD was not dropped"); return "ok"; } }] };
    const h = createHardening({ ctx: fk.ctx, ...f.hardening, serverStartedAt: () => new Date(Date.now() + 3600e3).toISOString(),
      runSelfTestFn: (o) => runSelfTest({ ...o, checks }) });
    assert.equal((await h.applyChange({ enabled: ["own-box"] }, ADMIN)).ok, true);
    const base = fk.logs.length;

    await assert.rejects(h.runSelfTest({}, AGENT), NotAllowedError);
    const r = await h.runSelfTest({}, ADMIN);
    assert.equal(r.ok, false);
    assert.deepEqual(r.failed, ["own-box"]);
    const row = byId((await h.getStatus()).protections)["own-box"];
    assert.equal(row.status, "selftest-failed");
    assert.match(row.reason, /LD_PRELOAD was not dropped/);
    assert.equal(byId((await h.getStatus()).protections)["sandbox-compat"].status, "applied");
    assert.equal(fk.logs.length, base + 2); // the failure entry + the alert entry
    assert.match(fk.logs[base].message, /self-test failed: Agents can't change their own box/);
    assert.equal(fk.issues.length, 1);
    assert.match(fk.issues[0].title, /^\[Security hardening\] Self-test failed: Agents can't change their own box/);
    assert.equal(fk.issues[0].companyId, "c1");
    assert.equal(fk.issues[0].projectId, "p1");
    assert.equal(fk.issues[0].assigneeAgentId, undefined);

    // Same failure again (e.g. after the next restart): logged, but no second issue.
    await h.selfTestAfterStart();
    assert.equal(fk.issues.length, 1);
    assert.equal(fk.logs.length, base + 3);

    // Fixed: passes, the recovery is logged once, and a new failure would raise a new issue.
    broken = false;
    const ok = await h.runSelfTest({}, ADMIN);
    assert.equal(ok.ok, true);
    assert.match(fk.logs.at(-1).message, /passes again/);
    assert.equal(byId((await h.getStatus()).protections)["own-box"].status, "applied");
    broken = true;
    await h.runSelfTest({}, ADMIN);
    assert.equal(fk.issues.length, 2);
  } finally { f.cleanup(); }
});

test("without an alert company (or when issue creation fails) a failure is still recorded, and retried later", { skip }, async () => {
  const f = S.fresh();
  try {
    const fk = fakeCtx({ alertCompanyId: "", issuesFail: false });
    const checks = { "own-box": [{ name: "x", run: async () => { throw new Error("broken"); } }] };
    const h = createHardening({ ctx: fk.ctx, ...f.hardening, serverStartedAt: () => new Date(Date.now() + 3600e3).toISOString(),
      runSelfTestFn: (o) => runSelfTest({ ...o, checks }) });
    assert.equal((await h.applyChange({ enabled: ["own-box"] }, ADMIN)).ok, true);
    const r = await h.runSelfTest({}, ADMIN);
    assert.equal(r.ok, false);
    assert.equal(fk.issues.length, 0);
    assert.ok(fk.logs.some((l) => /self-test failed/.test(l.message) && l.companyId === "c1")); // the admin's company
    assert.equal((await fk.ctx.state.get(SELFTEST_KEY)).alertedSignature, "", "no issue raised, so the next run tries again");
    fk.state.set("instance::settings", { alertCompanyId: "c1" });
    await h.selfTestAfterStart();
    assert.equal(fk.issues.length, 1);
  } finally { f.cleanup(); }
});

test("structural check: a file whose sha256 is not the engine's built one, or that lost a marker, fails", () => {
  const p = { id: "pipeline-board-only", patches: ["0007"], files: ["a.js"] };
  const dir = fs.mkdtempSync(`${process.env.HARDENING_TEST_SCRATCH ?? "/tmp"}/structural-`);
  try {
    fs.writeFileSync(`${dir}/a.js`, "x // LOCAL-PATCH 0007\n");
    assert.equal(structuralCheck(p, [{ rel: "a.js", currentSha: "s1", builtSha: "s1", patches: ["0007"] }], dir).ok, true);
    const changed = structuralCheck(p, [{ rel: "a.js", currentSha: "s2", builtSha: "s1", patches: ["0007"] }], dir);
    assert.equal(changed.ok, false);
    assert.match(changed.detail, /is not the built/);
    fs.writeFileSync(`${dir}/a.js`, "x\n");
    const lost = structuralCheck(p, [{ rel: "a.js", currentSha: "s1", builtSha: "s1", patches: ["0007"] }], dir);
    assert.match(lost.detail, /marker missing for 0007/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("a protection that is now part of Paperclip counts as satisfied: no functional check, no failure for the missing marker block (fail-before: it failed)", async () => {
  const dir = fs.mkdtempSync(`${process.env.HARDENING_TEST_SCRATCH ?? "/tmp"}/selftest-upstream-`);
  try {
    fs.writeFileSync(`${dir}/a.js`, "paperclip's own code, no marker\n");
    const p = { id: "no-permission-handing", kind: "patch", patches: ["0009"], files: ["a.js"] };
    const engine = { tree: dir, protections: () => [p] };
    const status = { tree: dir, protections: [{ id: p.id, status: "applied" }], files: [{ rel: "a.js", currentSha: "s1", builtSha: "s1", patches: [] }] };
    const checks = { [p.id]: [{ name: "loads the 0009 block", run: async () => { throw new Error("no LOCAL-PATCH 0009 block in the file"); } }] };
    const without = await runSelfTest({ engine, status, instanceRoot: "/x", checks });
    assert.equal(without.results[p.id].ok, false, "without the upstream note the functional check fails");
    const withNote = await runSelfTest({ engine, status, instanceRoot: "/x", checks, upstream: { [p.id]: ["0009"] } });
    assert.equal(withNote.results[p.id].ok, true);
    assert.deepEqual(withNote.results[p.id].checks.map((c) => [c.kind, c.ok]), [["upstream", true], ["structural", true]]);
    // the hardening passes the stored note on
    const seen = [];
    const fk = fakeCtx();
    fk.state.set("instance::now-upstream", { signature: "s", protections: [{ id: p.id, title: "t", patches: ["0009"] }] });
    const S2 = S.skip ? null : S.fresh();
    if (S2) {
      try {
        const h = createHardening({ ctx: fk.ctx, ...S2.hardening, serverStartedAt: () => new Date(Date.now() + 60000).toISOString(), runSelfTestFn: async (o) => { seen.push(o.upstream); return { at: new Date().toISOString(), results: {} }; } });
        await h.applyChange({ enabled: ["sandbox-compat"] }, ADMIN);
        await h.selfTestAfterStart();
        assert.deepEqual(seen, [{ [p.id]: ["0009"] }]);
      } finally { S2.cleanup(); }
    }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
