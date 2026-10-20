// The fail mode after a Paperclip update replaced the install tree with stock files (hardening.js start()):
//  * every protection that still fits is applied; one that does not is skipped but stays switched on, with a HIGH alert and the row
//    "update needs admin decision" (before: ONE broken patch made start() rebuild nothing, the server ran stock files with no protection);
//  * "Only boxed agents run" no longer needs "Box Claude agents" (soft dependency): its rule applies without the Claude adapter and then
//    refuses Claude agents (not registered as boxed = fails closed); if only-boxed itself does not fit there is just the alert;
//  * manual switch combinations stay enforced (the scrub 0025 never without the Claude adapter 0026: one switch);
//  * a protection whose change Paperclip now contains itself is "now part of Paperclip, no longer needed": a heads-up, no HIGH alert;
//  * the instance running in local_trusted mode raises a HIGH alert and shows a line on the page.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createHardening } from "../src/hardening.js";
import { createEngine, PROTECTIONS } from "../src/engine/index.js";
import { PATCHES } from "../src/engine/registry.js";
import { discoverPatchFiles, buildFile } from "../src/engine/patches.js";
import { makeScratchBase, hardeningFor } from "./helpers/scratch-tree.mjs";
import { SETTINGS_KEY } from "../src/hardening.js";

const DEFAULTS = PROTECTIONS.filter((p) => p.kind === "patch" && p.defaultOn).map((p) => p.id);
const HB = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
const AGENTS = "node_modules/@paperclipai/server/dist/routes/agents.js";
const SANDBOX = "node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js";
const SCRUB = "node_modules/@paperclipai/adapter-utils/dist/server-utils.js";
const byId = (list) => Object.fromEntries(list.map((p) => [p.id, p]));
const actor = (type, userId, companyId = "c1") => ({ actor: Object.freeze({ type, userId, agentId: type === "agent" ? "a1" : null, runId: null, companyId }), companyId });
const ADMIN = actor("user", "u-admin");
const S = { 1012: makeScratchBase("update-fail-1012-", "1012"), 1005: makeScratchBase("update-fail-1005-", "1005") };
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
function ownPatches(f) {
  const dir = path.join(f.dir, "patches");
  fs.cpSync(f.engineOptions.patchesDir, dir, { recursive: true });
  f.engineOptions.patchesDir = dir;
  f.hardening = hardeningFor(f.target, { patchesDir: dir, tmpDir: f.engineOptions.tmpDir, systemctl: null });
  return dir;
}
function breakPatch(dir, id) {
  const file = discoverPatchFiles(dir).get(id)[0].file;
  const lines = fs.readFileSync(file, "utf8").split("\n");
  const i = lines.findIndex((l, n) => n > lines.findIndex((x) => x.startsWith("@@")) && l.startsWith(" ") && l.trim().length > 12);
  assert.ok(i > 0, `${id} has a context line`);
  lines[i] += " /* changed upstream */";
  fs.writeFileSync(file, lines.join("\n"));
}
/** `paperclipai update`: every target is the stock file again, and `rel` has one line (only patch `id` uses it) changed where that patch sits. */
function updateTree(base, f, id, rel) {
  const patchFiles = discoverPatchFiles(f.engineOptions.patchesDir);
  const text = fs.readFileSync(patchFiles.get(id)[0].file, "utf8");
  const original = base.baseFile(rel).toString("utf8");
  const others = [...patchFiles.entries()].filter(([x]) => x !== id).flatMap(([, list]) => list).map((x) => fs.readFileSync(x.file, "utf8")).join("\n");
  const ctxLine = text.split("\n").filter((l) => l.startsWith(" ") && l.trim().length > 14).map((l) => l.slice(1))
    .find((l) => original.split(l).length === 2 && !others.includes(l) && text.split(l).length === 2);
  assert.ok(ctxLine, `a context line that only ${id} uses, in ${rel} exactly once`);
  const updated = Object.fromEntries(base.targets.map((r) => [r, r === rel ? Buffer.from(original.replace(ctxLine, `${ctxLine} /* changed upstream */`)) : base.baseFile(r)]));
  for (const r of base.targets) fs.writeFileSync(path.join(f.tree, r), updated[r]);
}
const text = (f, rel) => fs.readFileSync(path.join(f.tree, rel), "utf8");
const MARKERS = (id) => `LOCAL-PATCH ${id}`;

for (const vkey of ["1012", "1005"]) {
  const base = S[vkey];
  const skip = base.skip;
  const V = (n) => `${vkey}: ${n}`;

  test(V("update replaced the files and one box-claude patch does not fit: ALL other protections are applied, only-boxed too, one HIGH alert (before: nothing rebuilt, stock files)"), { skip }, async () => {
    const f = base.fresh();
    try {
      const fk = fakeCtx();
      ownPatches(f);
      const h = createHardening({ ctx: fk.ctx, ...f.hardening });
      assert.equal((await h.applyChange({ enabled: DEFAULTS }, ADMIN)).ok, true);
      updateTree(base, f, "0026b", "node_modules/@paperclipai/adapter-claude-local/dist/server/test.js");
      const r = await createHardening({ ctx: fk.ctx, ...f.hardening }).start();
      assert.equal(r.ok, true, r.error);
      assert.equal(r.applied, true, "the rebuild ran");
      assert.deepEqual(r.unfitting, ["box-claude"]);
      assert.equal(r.needsDecision, undefined);
      // every protection except the broken one (and box-opencode, which needs it) is in the files
      const rows = byId((await h.getStatus()).protections);
      const patchProtections = PROTECTIONS.filter((p) => p.kind === "patch");
      for (const p of patchProtections.filter((x) => !["box-claude", "box-opencode"].includes(x.id))) {
        assert.ok(["applied", "pending-restart"].includes(rows[p.id].status), `${p.id}: ${rows[p.id].status}`);
        for (const id of p.patches) {
          if (id === "0005e" && vkey === "1005") continue; // not needed on this version
          const files = createEngine(f.engineOptions).protections().find((x) => x.id === p.id).files;
          assert.ok(files.some((x) => text(f, x).includes(PATCHES[id].marker)), `${id} of ${p.id} is in the files`);
        }
      }
      assert.ok(text(f, HB).includes(MARKERS("0005f")) && text(f, HB).includes(MARKERS("0005b")), "only-boxed: the admission rule");
      assert.ok(text(f, "node_modules/@paperclipai/server/dist/routes/agents.js").includes(MARKERS("0027")));
      // the broken one is skipped as a whole (0025 never without 0026: same switch), but stays switched on
      assert.equal(text(f, SCRUB).includes(MARKERS("0025")), false);
      assert.equal(text(f, SANDBOX).includes(MARKERS("0017")), false);
      assert.equal(rows["box-claude"].enabled, true);
      assert.equal(rows["box-claude"].status, "needs-decision");
      assert.match(rows["box-claude"].reason, /skipped/);
      assert.ok((await h.getStatus()).enabled.includes("box-claude"));
      // exactly one HIGH alert, naming it and the Claude consequence is not claimed (only-boxed is applied: Claude agents are refused)
      assert.equal(fk.issues.length, 1);
      assert.equal(fk.issues[0].priority, "high");
      assert.match(fk.issues[0].title, /Box Claude agents/);
      assert.match(fk.issues[0].description, /0026b/);
      assert.match(fk.issues[0].description, /applied every other protection/);
      assert.match(fk.issues[0].description, /Claude agents are refused/);
      // a second start: same files, no second alert
      const again = await createHardening({ ctx: fk.ctx, ...f.hardening }).start();
      assert.equal(again.ok, true);
      assert.equal(fk.issues.length, 1);
    } finally { f.cleanup(); }
  });

  test(V("update replaced the files and only-boxed itself does not fit: everything else is applied (box-claude too), just the HIGH alert, no agent is touched"), { skip }, async () => {
    const f = base.fresh();
    try {
      const fk = fakeCtx();
      ownPatches(f);
      const h = createHardening({ ctx: fk.ctx, ...f.hardening });
      assert.equal((await h.applyChange({ enabled: DEFAULTS }, ADMIN)).ok, true);
      updateTree(base, f, "0027", AGENTS);
      const r = await createHardening({ ctx: fk.ctx, ...f.hardening }).start();
      assert.equal(r.ok, true, r.error);
      assert.equal(r.applied, true);
      assert.deepEqual(r.unfitting, ["only-boxed"]);
      const rows = byId((await h.getStatus()).protections);
      assert.equal(rows["only-boxed"].status, "needs-decision");
      assert.equal(rows["only-boxed"].enabled, true);
      for (const id of DEFAULTS.filter((x) => x !== "only-boxed")) assert.ok(["applied", "pending-restart"].includes(rows[id].status), `${id}: ${rows[id].status}`);
      assert.ok(text(f, SANDBOX).includes(MARKERS("0017")) && text(f, SCRUB).includes(MARKERS("0025")), "box-claude is applied");
      assert.equal(text(f, HB).includes(MARKERS("0005f")), false, "the admission rule is not in the files");
      assert.equal(text(f, AGENTS).includes(MARKERS("0027")), false);
      assert.equal(fk.issues.length, 1);
      assert.equal(fk.issues[0].priority, "high");
      assert.match(fk.issues[0].title, /Only boxed agents run/);
      // the only things the plugin did on its own: one alert issue and activity entries (the fake context has no way to pause an agent)
      assert.deepEqual(Object.keys(fk.ctx).sort(), ["activity", "config", "issues", "logger", "state"]);
    } finally { f.cleanup(); }
  });

  test(V("engine: only-boxed applies although box-claude does not fit; box-opencode (needs box-claude) does not; 0025 never without 0026"), { skip }, async () => {
    for (const broken of ["0017", "0026", "0025", "0026c"]) {
      const f = base.fresh();
      try {
        const dir = path.join(f.dir, "patches");
        fs.cpSync(f.engineOptions.patchesDir, dir, { recursive: true });
        breakPatch(dir, broken);
        const engine = createEngine({ ...f.engineOptions, patchesDir: dir });
        const plan = await engine.plan(DEFAULTS);
        const acts = byId(plan.protections);
        assert.equal(acts["box-claude"].action, "unavailable", broken);
        assert.equal(acts["box-opencode"].action, "unavailable", `${broken}: needs the Claude box (hard dependency)`);
        assert.equal(acts["only-boxed"].action, "will-apply", `${broken}: ${acts["only-boxed"].reason}`);
        assert.equal(plan.enabled.includes("box-claude"), true, "still switched on");
        assert.equal((await engine.apply(plan)).ok, true);
        assert.ok(text(f, HB).includes(MARKERS("0005f")));
        assert.equal(text(f, SCRUB).includes(MARKERS("0025")), false, `${broken}: the scrub is not applied without the Claude adapter`);
        assert.equal(text(f, "node_modules/@paperclipai/adapter-claude-local/dist/server/execute.js").includes(MARKERS("0026")), false);
      } finally { f.cleanup(); }
    }
  });

  test(V("manual switches: box-claude stays on while only-boxed is on; box-opencode and public-web stay hard dependencies"), { skip }, async () => {
    const f = base.fresh();
    try {
      const fk = fakeCtx();
      const h = createHardening({ ctx: fk.ctx, ...f.hardening });
      assert.equal((await h.applyChange({ enabled: DEFAULTS }, ADMIN)).ok, true);
      // box-claude switched off while only-boxed stays on: kept on (it is switched on together by default), only-boxed untouched
      const plan = await h.planChange({ enabled: DEFAULTS.filter((id) => id !== "box-claude") });
      assert.ok(plan.enabled.includes("only-boxed") && plan.enabled.includes("box-claude"));
      assert.ok(plan.keptOn.some((k) => k.id === "box-claude"));
      // box-opencode without box-claude in the request is switched off with it (hard)
      assert.ok(plan.switchedOffDependents.some((d) => d.id === "box-opencode"));
      // only-boxed alone pulls box-claude in by default
      const alone = await createEngine(f.engineOptions).plan(["only-boxed"]);
      assert.ok(alone.enabled.includes("box-claude"));
      assert.ok(alone.added.some((x) => x.id === "box-claude" && x.neededBy.includes("only-boxed")));
      // without only-boxed the Claude box can be switched off and stay off
      const noBoxed = await h.planChange({ enabled: DEFAULTS.filter((id) => !["only-boxed", "box-claude", "box-opencode"].includes(id)) });
      assert.equal(noBoxed.enabled.includes("box-claude"), false);
      // the hard ones: box-claude needs public-web and the Claude folder; asking for it alone brings them
      const claudeAlone = await createEngine(f.engineOptions).plan(["box-claude"]);
      for (const id of ["sandbox-compat", "public-web", "own-claude-folder", "own-box"]) assert.ok(claudeAlone.enabled.includes(id), id);
      // a broken hard dependency makes box-claude unavailable (the combination would be broken)
      const dir = ownPatches(f);
      breakPatch(dir, "0016");
      const engine = createEngine({ ...f.engineOptions, patchesDir: dir });
      const broken = byId((await engine.plan(DEFAULTS)).protections);
      assert.equal(broken["box-claude"].action, "unavailable");
      assert.notEqual(broken["only-boxed"].action, "unavailable");
    } finally { f.cleanup(); }
  });

  test(V("Paperclip now contains the change itself: no HIGH alert, the protection counts as satisfied, a heads-up; a patch that merely does not fit still alerts"), { skip }, async () => {
    const f = base.fresh();
    try {
      const fk = fakeCtx();
      ownPatches(f);
      const h = createHardening({ ctx: fk.ctx, ...f.hardening });
      assert.equal((await h.applyChange({ enabled: DEFAULTS }, ADMIN)).ok, true);
      // The new stock agents.js already has the 0009 change (the same code, written by Paperclip: no LOCAL-PATCH comments).
      const dir = f.engineOptions.patchesDir;
      const original = base.baseFile(AGENTS);
      const built = buildFile({ rel: AGENTS, pristine: original, tmpDir: f.engineOptions.tmpDir,
        steps: [{ id: "0009", marker: MARKERS("0009"), candidates: discoverPatchFiles(dir).get("0009") }] });
      assert.equal(built.ok, true);
      const origLines = new Set(original.toString("utf8").split("\n"));
      const upstream = built.content.toString("utf8").split("\n").filter((l) => origLines.has(l) || !/^\s*\/\//.test(l)).join("\n");
      assert.ok(!upstream.includes("LOCAL-PATCH") && upstream.includes("permissions_grant_board_only"));
      for (const r of base.targets) fs.writeFileSync(path.join(f.tree, r), r === AGENTS ? upstream : base.baseFile(r));
      const r = await createHardening({ ctx: fk.ctx, ...f.hardening }).start();
      assert.equal(r.ok, true, r.error);
      assert.equal(r.applied, true);
      assert.deepEqual(r.unfitting, [], "satisfied, not unfit");
      assert.equal(fk.issues.length, 0, "no alert at all");
      const st = await h.getStatus();
      const rows = byId(st.protections);
      assert.ok(["applied", "pending-restart"].includes(rows["no-permission-handing"].status), rows["no-permission-handing"].status);
      assert.match(rows["no-permission-handing"].reason, /Now part of Paperclip.*0009.*no longer needed/);
      assert.equal(st.updateDecision, null);
      assert.deepEqual(st.nowUpstream.protections.map((p) => [p.id, p.patches]), [["no-permission-handing", ["0009"]]]);
      assert.ok(fk.logs.some((l) => /now part of Paperclip, no longer needed/.test(l.message)));
      assert.equal(text(f, AGENTS).includes(MARKERS("0009")), false, "0009 is not applied twice");
      assert.ok(text(f, AGENTS).includes("permissions_grant_board_only"));
      // the heads-up is logged once per set and version
      const nLogs = fk.logs.filter((l) => /now part of Paperclip/.test(l.message)).length;
      await createHardening({ ctx: fk.ctx, ...f.hardening }).start();
      assert.equal(fk.logs.filter((l) => /now part of Paperclip/.test(l.message)).length, nLogs);

      // The control: the same file changed so that the patch only does not fit (no 0009 code in it) keeps the HIGH alert.
      const fk2 = fakeCtx();
      const f2 = base.fresh();
      try {
        ownPatches(f2);
        const h2 = createHardening({ ctx: fk2.ctx, ...f2.hardening });
        assert.equal((await h2.applyChange({ enabled: DEFAULTS }, ADMIN)).ok, true);
        updateTree(base, f2, "0009", AGENTS);
        const r2 = await createHardening({ ctx: fk2.ctx, ...f2.hardening }).start();
        assert.equal(r2.ok, true, r2.error);
        assert.deepEqual(r2.unfitting, ["no-permission-handing"]);
        assert.equal(fk2.issues.length, 1);
        assert.equal(fk2.issues[0].priority, "high");
        assert.equal((await h2.getStatus()).nowUpstream, null);
        assert.equal(byId((await h2.getStatus()).protections)["no-permission-handing"].status, "needs-decision");
      } finally { f2.cleanup(); }
    } finally { f.cleanup(); }
  });

  test(V("local_trusted: a HIGH alert once and a line on the Hardening page; authenticated: neither"), { skip }, async () => {
    for (const [mode, expected] of [["local_trusted", true], ["authenticated", false], [undefined, false]]) {
      const f = base.fresh();
      try {
        const fk = fakeCtx();
        const target = { ...f.target, deploymentMode: mode };
        const h = createHardening({ ctx: fk.ctx, ...hardeningFor(target, { patchesDir: f.engineOptions.patchesDir, tmpDir: f.engineOptions.tmpDir, systemctl: null }) });
        await h.start();
        await h.start();
        const st = await h.getStatus();
        const alerts = fk.issues.filter((i) => /local_trusted/.test(i.title));
        assert.equal(alerts.length, expected ? 1 : 0, `${mode}: one alert at most`);
        if (expected) {
          assert.equal(alerts[0].priority, "high");
          assert.match(alerts[0].description, /any caller without a token is treated as the board, including a boxed agent/);
          assert.match(st.localTrusted, /local_trusted/);
        } else assert.equal(st.localTrusted, null);
        assert.equal(st.deploymentMode, mode ?? null);
      } finally { f.cleanup(); }
    }
  });
}
