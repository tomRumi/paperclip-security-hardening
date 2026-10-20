// (1) The two box switches: "Box Claude agents" (the helper, the scrub, the Claude adapter) and "Box OpenCode agents" (on top of it).
//     Only boxed agents run needs the first, not the second: with the OpenCode switch off, OpenCode agents are refused and Claude agents
//     run (the admission rule admits a type only when its adapter registered itself as boxed in the built files).
// (2) A core protection that stops fitting on an update must never be dropped silently. The automatic re-apply on start (hardening.js
//     start()) used to rebuild the files without it (and without everything that needs it, only-boxed with the admission rule). Now such
//     a plan needs the owner's confirmation like a switch-off, so start() rebuilds NOTHING, raises a HIGH alert once and the page shows
//     "update needs admin decision".
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createHardening, NotAllowedError, SETTINGS_KEY, UPDATE_DECISION_KEY } from "../src/hardening.js";
import { createEngine, PROTECTIONS } from "../src/engine/index.js";
import { discoverPatchFiles, readPatchTarget } from "../src/engine/patches.js";
import { admissionCode, evalBlock } from "../src/patch-block.js";
import { makeScratchBase, hardeningFor } from "./helpers/scratch-tree.mjs";

const ALL = PROTECTIONS.filter((p) => p.kind === "patch").map((p) => p.id);
const DEFAULTS = PROTECTIONS.filter((p) => p.kind === "patch" && p.defaultOn).map((p) => p.id);
const HB = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
const SANDBOX = "node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js";
const ADAPTER = (pkg) => `node_modules/@paperclipai/${pkg}/dist/server/execute.js`;
const byId = (list) => Object.fromEntries(list.map((p) => [p.id, p]));
const actor = (type, userId, companyId = "c1") => ({ actor: Object.freeze({ type, userId, agentId: type === "agent" ? "a1" : null, runId: null, companyId }), companyId });
const ADMIN = actor("user", "u-admin");

const S = { 1012: makeScratchBase("box-switches-1012-", "1012"), 1005: makeScratchBase("box-switches-1005-", "1005") };
test.after(() => { for (const s of Object.values(S)) if (!s.skip) s.cleanup(); });

function fakeCtx() {
  const state = new Map();
  const logs = [];
  const issues = [];
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const ctx = {
    state: { get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null), set: async (key, v) => { state.set(k(key), structuredClone(v)); } },
    config: { get: async (companyId) => (companyId === "c1" ? { adminUserIds: ["u-admin"] } : {}) },
    activity: { log: async (e) => { logs.push(e); } },
    issues: { create: async (input) => { issues.push(input); return { id: `i-${issues.length}`, identifier: `ENG-${issues.length}` }; } },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  };
  state.set(k(SETTINGS_KEY), { alertCompanyId: "c1", alertProjectId: "p1" });
  return { ctx, state, logs, issues };
}
/** A private copy of the patch files for a case (fresh() shares one dir), and a hardening service that reads it. */
function ownPatches(base, f) {
  const dir = path.join(f.dir, "patches");
  fs.cpSync(f.engineOptions.patchesDir, dir, { recursive: true });
  f.engineOptions.patchesDir = dir;
  f.hardening = hardeningFor(f.target, { patchesDir: dir, tmpDir: f.engineOptions.tmpDir, systemctl: null });
  return dir;
}
/** Make patch `id` stop fitting: one of its context lines no longer matches what is in the file ("the code changed upstream"). */
function breakPatch(dir, id) {
  const file = discoverPatchFiles(dir).get(id)[0].file;
  const lines = fs.readFileSync(file, "utf8").split("\n");
  const i = lines.findIndex((l, n) => n > lines.findIndex((x) => x.startsWith("@@")) && l.startsWith(" ") && l.trim().length > 12);
  assert.ok(i > 0, `${id} has a context line`);
  lines[i] += " /* changed upstream */";
  fs.writeFileSync(file, lines.join("\n"));
}

for (const vkey of ["1012", "1005"]) {
  const base = S[vkey];
  const skip = base.skip;

  test(`${vkey}: OpenCode switch off: OpenCode agents are refused, Claude agents run; both on: both run`, { skip }, async () => {
    const admit = (tree, agent) => {
      // What the server process has registered: the types whose adapter file in THIS build calls registerBoxedAdapter.
      const registered = new Set();
      for (const [pkg, type] of [["adapter-claude-local", "claude_local"], ["adapter-opencode-local", "opencode_local"]])
        if (new RegExp(`^registerBoxedAdapter\\("${type}"\\);`, "m").test(fs.readFileSync(path.join(tree, ADAPTER(pkg)), "utf8"))) registered.add(type);
      const scrub = fs.readFileSync(path.join(tree, "node_modules/@paperclipai/adapter-utils/dist/server-utils.js"), "utf8").includes("LOCAL-PATCH 0025");
      const globals = { [Symbol.for("paperclip.hardening.boxedAdapters")]: registered, [Symbol.for("paperclip.hardening.envScrub")]: scrub };
      const b = evalBlock(admissionCode(fs.readFileSync(path.join(tree, HB), "utf8")), "0005f", { env: {}, instanceRoot: "/nonexistent-instance-root", globals });
      try { b.refuseUnsandboxedLocalAgent({ agent, runId: "r" }); return null; } catch (e) { return e.message; }
    };
    const box = { filesystemScope: "workspace", networkScope: "allowlist" };
    const claude = { id: "a1", adapterType: "claude_local", adapterConfig: { ...box, engine: "cli" } };
    const opencode = { id: "a2", adapterType: "opencode_local", adapterConfig: { ...box } };
    const withSwitches = async (enabled) => {
      const f = base.fresh();
      const engine = createEngine(f.engineOptions);
      const plan = await engine.plan(enabled);
      for (const p of plan.protections.filter((x) => x.enabled && x.kind === "patch")) assert.equal(p.action, "will-apply", `${p.id}: ${p.reason}`);
      assert.equal((await engine.apply(plan)).ok, true);
      return { f, plan };
    };
    // only-boxed alone: switches on the Claude box and what it needs, not the OpenCode one
    const off = await withSwitches(["only-boxed"]);
    try {
      assert.equal(off.plan.enabled.includes("box-claude"), true);
      assert.equal(off.plan.enabled.includes("box-opencode"), false);
      assert.equal(admit(off.f.tree, claude), null, "a boxed Claude agent runs");
      assert.match(admit(off.f.tree, opencode) ?? "", /opencode_local adapter is not registered as boxed/, "a boxed OpenCode agent is refused");
      assert.match(admit(off.f.tree, { ...opencode, adapterConfig: {} }) ?? "", /no filesystemScope "workspace"/, "so is an unboxed one");
      assert.ok(!fs.readFileSync(path.join(off.f.tree, ADAPTER("adapter-opencode-local")), "utf8").includes("LOCAL-PATCH 0019"), "the OpenCode adapter file is not changed");
    } finally { off.f.cleanup(); }
    const on = await withSwitches(["only-boxed", "box-opencode"]);
    try {
      assert.equal(admit(on.f.tree, claude), null);
      assert.equal(admit(on.f.tree, opencode), null, "with the OpenCode switch on a boxed OpenCode agent runs");
    } finally { on.f.cleanup(); }
  });

  test(`${vkey}: a patch of a core protection stops fitting while the tree stays built: start() rebuilds nothing, only-boxed keeps its admission rule, one HIGH alert, the page says "update needs admin decision"`, { skip }, async () => {
    const f = base.fresh();
    try {
      const fk = fakeCtx();
      ownPatches(base, f);
      const h = createHardening({ ctx: fk.ctx, ...f.hardening });
      assert.equal((await h.applyChange({ enabled: DEFAULTS }, ADMIN)).ok, true);
      const built = Object.fromEntries(base.targets.map((rel) => [rel, fs.readFileSync(path.join(f.tree, rel))]));
      assert.ok(built[HB].toString("utf8").includes("LOCAL-PATCH 0005f"));
      const before = (await h.getStatus()).enabled.slice();

      // A new patch set (or Paperclip) in which the helper patch of "Box Claude agents" does not fit any more.
      breakPatch(f.engineOptions.patchesDir, "0017");
      const h2 = createHardening({ ctx: fk.ctx, ...f.hardening });
      const r = await h2.start();
      assert.equal(r.ok, false);
      assert.equal(r.needsDecision, true);
      assert.deepEqual(r.protections.slice().sort(), ["box-claude", "box-opencode", "only-boxed"].filter((id) => r.protections.includes(id)).sort());
      assert.ok(r.protections.includes("box-claude") && r.protections.includes("only-boxed"));
      // Nothing was rebuilt: every file is byte-identical, heartbeat.js still has the admission rule (before: it was rebuilt without 0005b and 0005f).
      for (const rel of base.targets) assert.ok(fs.readFileSync(path.join(f.tree, rel)).equals(built[rel]), `${rel} was rebuilt`);
      assert.ok(fs.readFileSync(path.join(f.tree, HB), "utf8").includes("LOCAL-PATCH 0005f") && fs.readFileSync(path.join(f.tree, HB), "utf8").includes("LOCAL-PATCH 0005b"));
      assert.deepEqual((await h2.getStatus()).enabled, before, "the switches are as they were");

      // One HIGH alert, naming the protections and the reason; a second start raises no second one.
      assert.equal(fk.issues.length, 1);
      assert.equal(fk.issues[0].priority, "high");
      assert.match(fk.issues[0].title, /Box Claude agents/);
      assert.match(fk.issues[0].description, /0017/);
      assert.match(fk.issues[0].description, /Only boxed agents run/);
      assert.match(fk.issues[0].description, /changed NOTHING/);
      assert.equal((await h2.start()).needsDecision, true);
      assert.equal(fk.issues.length, 1, "no second alert for the same situation");
      assert.ok(fk.logs.some((l) => /update needs admin decision/.test(l.message)));

      // The page: the rows say so, with the reason.
      const st = await h2.getStatus();
      const rows = byId(st.protections);
      for (const id of ["box-claude", "only-boxed"]) {
        assert.equal(rows[id].status, "needs-decision", id);
        assert.equal(rows[id].enabled, true);
        assert.match(rows[id].reason, /update/i);
      }
      assert.deepEqual(st.updateDecision.protections.map((p) => p.id).sort(), r.protections.slice().sort());
      assert.notEqual(rows["no-permission-handing"].status, "needs-decision");

      // The owner's decision goes through the plan: Save lists the protections that no longer fit and refuses without the confirmation.
      const plan = await h2.planChange({ enabled: before });
      assert.ok(plan.confirmationNeeded.some((c) => c.id === "box-claude" && c.unavailable === true && /0017/.test(c.reason)));
      const refused = await h2.applyChange({ enabled: before }, ADMIN);
      assert.equal(refused.ok, false);
      assert.match(refused.error, /no longer fit/);
      for (const rel of base.targets) assert.ok(fs.readFileSync(path.join(f.tree, rel)).equals(built[rel]), `${rel} changed by a refused apply`);
      const confirmed = await h2.applyChange({ enabled: before, confirmCoreOff: true }, ADMIN);
      assert.equal(confirmed.ok, true, confirmed.error);
      assert.equal(fs.readFileSync(path.join(f.tree, HB), "utf8").includes("LOCAL-PATCH 0005f"), false, "after the owner confirmed, the rule is gone");
      assert.equal((await h2.getStatus()).updateDecision, null, "the decision is cleared");
      assert.equal(fk.state.get(`${UPDATE_DECISION_KEY.scopeKind}::${UPDATE_DECISION_KEY.stateKey}`), null);
      // and the next start does not ask again (the protection is recorded as not fitting)
      const again = await h2.start();
      assert.notEqual(again.needsDecision, true);
    } finally { f.cleanup(); }
  });

  test(`${vkey}: a Paperclip update replaces the files and a core patch no longer fits: start() changes nothing and alerts (before: it rebuilt heartbeat.js without the admission rule)`, { skip }, async () => {
    const f = base.fresh();
    try {
      const fk = fakeCtx();
      const h = createHardening({ ctx: fk.ctx, ...f.hardening });
      assert.equal((await h.applyChange({ enabled: DEFAULTS }, ADMIN)).ok, true);
      // `paperclipai update`: a new tree of original files, one of them changed where the helper patch (0017) sits.
      const patch0017 = fs.readFileSync(discoverPatchFiles(f.engineOptions.patchesDir).get("0017")[0].file, "utf8");
      const original = base.baseFile(SANDBOX).toString("utf8");
      const others = [...discoverPatchFiles(f.engineOptions.patchesDir).entries()].filter(([id]) => id !== "0017").flatMap(([, list]) => list).map((x) => fs.readFileSync(x.file, "utf8")).join("\n");
      const ctxLine = patch0017.split("\n").filter((l) => l.startsWith(" ") && l.trim().length > 14).map((l) => l.slice(1))
        .find((l) => original.split(l).length === 2 && !others.includes(l) && patch0017.split(l).length === 2);
      assert.ok(ctxLine, "a context line that only 0017 uses, in the original file exactly once");
      const updated = Object.fromEntries(base.targets.map((rel) => [rel, rel === SANDBOX ? Buffer.from(original.replace(ctxLine, `${ctxLine} /* changed upstream */`)) : base.baseFile(rel)]));
      for (const rel of base.targets) fs.writeFileSync(path.join(f.tree, rel), updated[rel]);

      const r = await h.start();
      assert.equal(r.needsDecision, true, r.error);
      for (const rel of base.targets) assert.ok(fs.readFileSync(path.join(f.tree, rel)).equals(updated[rel]), `${rel}: start() rebuilt a file`);
      assert.equal(fk.issues.length, 1);
      assert.equal(fk.issues[0].priority, "high");
      const rows = byId((await h.getStatus()).protections);
      assert.equal(rows["box-claude"].status, "needs-decision");
      assert.equal(rows["only-boxed"].status, "needs-decision");
      // Fixing the patch set (a plugin release for this Paperclip) and starting again applies everything and clears the decision.
      const fixedDir = path.join(f.dir, "fixed");
      fs.cpSync(base.root + "/base/patches", fixedDir, { recursive: true });
      const sandbox = fs.readFileSync(path.join(fixedDir, path.basename(discoverPatchFiles(fixedDir).get("0017")[0].file)), "utf8");
      fs.writeFileSync(path.join(fixedDir, path.basename(discoverPatchFiles(fixedDir).get("0017")[0].file)), sandbox.replace(ctxLine, `${ctxLine} /* changed upstream */`));
      const h2 = createHardening({ ctx: fk.ctx, ...hardeningFor(f.target, { patchesDir: fixedDir, tmpDir: f.engineOptions.tmpDir, systemctl: null }) });
      const ok = await h2.start();
      assert.equal(ok.ok, true, ok.error);
      assert.equal(ok.applied, true);
      assert.equal((await h2.getStatus()).updateDecision, null);
      assert.ok(fs.readFileSync(path.join(f.tree, HB), "utf8").includes("LOCAL-PATCH 0005f"));
    } finally { f.cleanup(); }
  });

  test(`${vkey}: a NON-core protection that stops fitting is still left out on start (as before): the rest is re-applied, no decision is asked`, { skip }, async () => {
    const f = base.fresh();
    try {
      const fk = fakeCtx();
      ownPatches(base, f);
      const h = createHardening({ ctx: fk.ctx, ...f.hardening });
      assert.equal((await h.applyChange({ enabled: DEFAULTS }, ADMIN)).ok, true);
      breakPatch(f.engineOptions.patchesDir, "0007"); // pipeline-board-only: not a core protection
      const h2 = createHardening({ ctx: fk.ctx, ...f.hardening });
      const r = await h2.start();
      assert.equal(r.ok, true, r.error);
      assert.notEqual(r.needsDecision, true);
      assert.ok(Object.keys(r.unavailable ?? {}).includes("pipeline-board-only"));
      assert.equal(fk.issues.length, 0);
      assert.ok(fs.readFileSync(path.join(f.tree, HB), "utf8").includes("LOCAL-PATCH 0005f"), "the admission rule is untouched");
    } finally { f.cleanup(); }
  });

  test(`${vkey}: engine: a first-time plan with a patch that does not fit needs no confirmation (nothing is applied yet); an applied one does`, { skip }, async () => {
    const f = base.fresh();
    try {
      const dir = path.join(f.dir, "patches");
      fs.cpSync(f.engineOptions.patchesDir, dir, { recursive: true });
      breakPatch(dir, "0017");
      const engine = createEngine({ ...f.engineOptions, patchesDir: dir });
      const first = await engine.plan(ALL);
      assert.equal(byId(first.protections)["box-claude"].action, "unavailable");
      assert.deepEqual(first.confirmationNeeded, [], "nothing was applied, so nothing is dropped");
      assert.equal((await engine.apply(first)).ok, true);
      // now nothing is applied for the broken ones: still no confirmation on the next plan
      assert.deepEqual((await engine.replan()).confirmationNeeded, []);
    } finally { f.cleanup(); }
  });
}

test("registry: the owner-facing switches read in plain words", () => {
  const titles = Object.fromEntries(PROTECTIONS.map((p) => [p.id, p.title]));
  assert.equal(titles["box-claude"], "Box Claude agents");
  assert.equal(titles["box-opencode"], "Box OpenCode agents");
  assert.equal(PROTECTIONS.some((p) => p.id === "box-adapters"), false);
});
