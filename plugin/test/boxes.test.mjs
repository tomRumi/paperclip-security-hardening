// Agent boxes page (src/boxes.js via src/worker.js) with a fake plugin context: full lists only (never REDACTED), the
// XOR rule, the write gate on every write action, and the rows read fresh from Paperclip.
import test from "node:test";
import assert from "node:assert/strict";
import { createHardening, NotAllowedError, SETTINGS_KEY } from "../src/hardening.js";
import { register, BOX_ACTIONS } from "../src/worker.js";
import { createBoxes, effectiveBase, buildBoxPatch, takeOverFrom, currentBox, normalizeBoxInput, syncState, assertNoRedacted, BOXES_KEY, PUBLIC_WEB, APPLY_UNSUPPORTED } from "../src/boxes.js";
import { createCaps } from "../src/caps.js";
import { fakeTarget, hardeningFor as hardeningTarget } from "./helpers/scratch-tree.mjs";

const R = "***REDACTED***";
const actor = (type, userId, companyId = "c1") => ({ actor: Object.freeze({ type, userId, agentId: type === "agent" ? "a1" : null, runId: null, companyId }), companyId });
const ADMIN = actor("user", "u-admin");
const MEMBER = actor("user", "u-member");
const AGENT = actor("agent", null);
const SYSTEM = actor("system", null);

const claude = (id, name, cfg = {}, extra = {}) => ({ id, companyId: extra.companyId ?? "c1", name, role: extra.role ?? "engineer", status: extra.status ?? "idle", adapterType: "claude_local",
  permissions: { canCreateAgents: false, canCreateSkills: false, ...(extra.permissions ?? {}) },
  adapterConfig: { model: "claude-sonnet-4-5", filesystemScope: "workspace", networkScope: "allowlist", networkAllowlist: [R, R, R], filesystemExtraPaths: ["/opt/vault/bin"], ...cfg } });

function fakeCtx({ agents, grants = [], grantsFail = false, settings = { baseAllowlist: ["api.anthropic.com", "127.0.0.1:8790"], extraReadOnlyPaths: ["/opt/vault/bin"] } } = {}) {
  const state = new Map();
  const logs = [];
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const reg = { data: {}, actions: {}, jobs: {} };
  const ctx = {
    state: { get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null), set: async (key, v) => { state.set(k(key), structuredClone(v)); } },
    config: { get: async (companyId) => (companyId === "c1" ? { adminUserIds: ["u-admin"] } : {}) },
    activity: { log: async (e) => { logs.push(e); } },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    data: { register: (key, fn) => { reg.data[key] = fn; } },
    actions: { register: (key, fn) => { reg.actions[key] = fn; } },
    jobs: { register: (key, fn) => { reg.jobs[key] = fn; } },
    companies: { list: async ({ offset } = {}) => (offset ? [] : [{ id: "c1", name: "One" }, { id: "c2", name: "Two" }]) },
    agents: {
      list: async ({ companyId, offset }) => (offset ? [] : agents.filter((a) => a.companyId === companyId)),
      get: async (id, companyId) => agents.find((a) => a.id === id && a.companyId === companyId) ?? null,
    },
    authorization: { grants: { list: async ({ companyId }) => { if (grantsFail) throw new Error("capability denied"); return grants.filter((g) => (g.companyId ?? "c1") === companyId); } } },
  };
  state.set(k(SETTINGS_KEY), settings);
  return { ctx, state, logs, reg, k };
}
const hardeningFor = (ctx) => createHardening({ ctx, createEngineFn: () => { throw new Error("no engine in this test"); }, ...hardeningTarget(fakeTarget()) });
function service(fk, opts = {}) {
  const h = hardeningFor(fk.ctx);
  const sent = [];
  const applyBox = opts.noApply ? null : async (agent, patch) => { sent.push({ id: agent.id, patch: structuredClone(patch) }); };
  return { h, sent, b: createBoxes({ ctx: fk.ctx, assertAdmin: h.assertAdmin, loadSettings: h.loadSettings, applyBox }) };
}

test("buildBoxPatch: full lists from the plugin's settings plus the base settings; public web adds the wildcards", () => {
  const settings = { baseAllowlist: ["api.anthropic.com", "127.0.0.1:8790"], extraReadOnlyPaths: ["/opt/vault/bin"] };
  const p = buildBoxPatch({ mode: "allowlist", extraHosts: ["registry.npmjs.org", "api.anthropic.com"], extraPaths: ["/srv/shared"] }, settings);
  assert.deepEqual(p, { adapterConfig: { networkScope: "allowlist", networkAllowlist: ["api.anthropic.com", "127.0.0.1:8790", "registry.npmjs.org"], filesystemExtraPaths: ["/opt/vault/bin", "/srv/shared"] } });
  const w = buildBoxPatch({ mode: "public-web", extraHosts: [], extraPaths: [] }, settings);
  assert.deepEqual(w.adapterConfig.networkAllowlist, ["api.anthropic.com", "127.0.0.1:8790", ...PUBLIC_WEB]);
  // No base allowlist in the settings: Paperclip's own default (patch 0005a), so the list is never empty.
  assert.deepEqual(buildBoxPatch({ mode: "allowlist", extraHosts: [], extraPaths: [] }, {}).adapterConfig.networkAllowlist, ["api.anthropic.com"]);
  // A REDACTED or wildcard entry can never get into stored settings or a body.
  assert.throws(() => buildBoxPatch({ mode: "allowlist", extraHosts: [R], extraPaths: [] }, settings), /invalid/);
  assert.throws(() => buildBoxPatch({ mode: "allowlist", extraHosts: ["*:443"], extraPaths: [] }, settings), /invalid/);
  assert.throws(() => assertNoRedacted({ adapterConfig: { networkAllowlist: ["a", R] } }), /REDACTED/);
  const n = normalizeBoxInput({ mode: "allowlist", extraHosts: "a.example\n***REDACTED***\n*:80", extraPaths: ["relative", "/ok/"] });
  assert.deepEqual(n.box, { mode: "allowlist", extraHosts: ["a.example"], extraPaths: ["/ok"] });
  assert.equal(n.errors.length, 2);
});

test("current box: NONE (host network) is red, wildcards mean public web, redacted hosts are hidden, never copied", () => {
  assert.equal(currentBox(claude("a", "A", { networkScope: undefined })).kind, "none");
  assert.equal(currentBox(claude("a", "A", { networkScope: undefined })).red, true);
  assert.equal(currentBox(claude("a", "A", { networkAllowlist: ["api.anthropic.com", "*:443", "*:80"] })).kind, "public-web");
  const hidden = currentBox(claude("a", "A"));
  assert.equal(hidden.kind, "hidden");
  assert.equal(hidden.hiddenHosts, 3);
  assert.deepEqual(hidden.hosts, []);
  const t = takeOverFrom(claude("a", "A", { networkAllowlist: ["api.anthropic.com", R, "pypi.org"], filesystemExtraPaths: ["/opt/vault/bin", "/srv/x"] }), { baseAllowlist: ["api.anthropic.com"], extraReadOnlyPaths: ["/opt/vault/bin"] });
  assert.deepEqual(t.box, { mode: "allowlist", extraHosts: ["pypi.org"], extraPaths: ["/srv/x"] });
  assert.match(t.notes.join(), /1 allowlist host\(s\) are hidden/);
  assert.equal(currentBox({ adapterType: "codex_local", adapterConfig: {} }).kind, "unsupported");
  assert.equal(currentBox({ adapterType: "hermes_local", adapterConfig: { command: "/usr/local/bin/hermes-sandbox" } }).kind, "hermes-wrapper");
});

test("box edits always send the full lists, never REDACTED (Paperclip returns the allowlist redacted)", async () => {
  const agents = [claude("a1", "Engineer")];
  const fk = fakeCtx({ agents });
  const { b, sent } = service(fk);
  // Not managed yet: the edit is refused until the agent is taken over.
  assert.match((await b.saveBox({ agentId: "a1", mode: "allowlist", extraHosts: "pypi.org" }, ADMIN)).error, /take this agent over/);
  const t = await b.takeOver({ agentId: "a1" }, ADMIN);
  assert.equal(t.ok, true);
  assert.ok(!JSON.stringify(fk.state.get(fk.k(BOXES_KEY("c1")))).includes("REDACTED"), "take over never stores a redacted value");
  const r = await b.saveBox({ agentId: "a1", mode: "allowlist", extraHosts: "pypi.org\nregistry.npmjs.org", extraPaths: "/srv/shared" }, ADMIN);
  assert.equal(r.ok, true, r.error);
  assert.equal(r.applied, true);
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0].patch.adapterConfig.networkAllowlist, ["api.anthropic.com", "127.0.0.1:8790", "pypi.org", "registry.npmjs.org"]);
  assert.deepEqual(sent[0].patch.adapterConfig.filesystemExtraPaths, ["/opt/vault/bin", "/srv/shared"]);
  assert.ok(!JSON.stringify(sent).includes("REDACTED"));
  // Removing one extra host still sends every remaining host (a PATCH replaces the list whole).
  await b.saveBox({ agentId: "a1", mode: "allowlist", extraHosts: "registry.npmjs.org", extraPaths: "" }, ADMIN);
  assert.deepEqual(sent[1].patch.adapterConfig.networkAllowlist, ["api.anthropic.com", "127.0.0.1:8790", "registry.npmjs.org"]);
  assert.deepEqual(sent[1].patch.adapterConfig.filesystemExtraPaths, ["/opt/vault/bin"]);
  assert.ok(!JSON.stringify(sent).includes("REDACTED"));
});

test("without an SDK agent-update capability the edit is stored and returned as the PATCH to apply by hand", async () => {
  const fk = fakeCtx({ agents: [claude("a1", "Engineer")] });
  const { b } = service(fk, { noApply: true });
  await b.takeOver({ agentId: "a1" }, ADMIN);
  const r = await b.saveBox({ agentId: "a1", mode: "allowlist", extraHosts: ["pypi.org"] }, ADMIN);
  assert.equal(r.ok, true);
  assert.equal(r.applied, false);
  assert.equal(r.note, APPLY_UNSUPPORTED);
  assert.equal(r.path, "/api/agents/a1");
  assert.deepEqual(r.patch.adapterConfig.networkAllowlist, ["api.anthropic.com", "127.0.0.1:8790", "pypi.org"]);
  const v = await b.view({}, ADMIN);
  assert.equal(v.applySupported, false);
  assert.equal(v.rows[0].managed, true);
  assert.equal(v.rows[0].sync, "unverifiable", "3 hidden hosts in Paperclip and 3 wanted: same count, contents hidden");
  assert.deepEqual(v.rows[0].hosts, ["api.anthropic.com", "127.0.0.1:8790", "pypi.org"], "the row shows the plugin's full list, not the redacted one");
});

test("XOR: public web is refused for an agent that holds or may hold tasks:assign; allowed otherwise", async () => {
  const agents = [claude("a1", "Lead"), claude("a2", "Researcher"), claude("a3", "Chief", {}, { role: "ceo" })];
  const fk = fakeCtx({ agents, grants: [{ principalType: "agent", principalId: "a1", permissionKey: "tasks:assign" }] });
  const { b, sent } = service(fk);
  for (const id of ["a1", "a2", "a3"]) assert.equal((await b.takeOver({ agentId: id }, ADMIN)).ok, true);
  const before = structuredClone(fk.state.get(fk.k(BOXES_KEY("c1"))));
  const r1 = await b.saveBox({ agentId: "a1", mode: "public-web" }, ADMIN);
  assert.equal(r1.ok, false);
  assert.equal(r1.refused, "xor");
  assert.match(r1.error, /holds tasks:assign/);
  const r3 = await b.saveBox({ agentId: "a3", mode: "public-web" }, ADMIN);
  assert.equal(r3.refused, "xor", "CEO role derives assign rights");
  assert.deepEqual(fk.state.get(fk.k(BOXES_KEY("c1"))), before, "a refused edit stores nothing");
  assert.equal(sent.length, 0, "a refused edit sends nothing");
  const r2 = await b.saveBox({ agentId: "a2", mode: "public-web" }, ADMIN);
  assert.equal(r2.ok, true, r2.error);
  assert.deepEqual(sent[0].patch.adapterConfig.networkAllowlist.slice(-2), PUBLIC_WEB);
  // Grants unreadable: tasks:assign cannot be ruled out, so public web is refused.
  const fk2 = fakeCtx({ agents: [claude("a2", "Researcher")], grantsFail: true });
  const s2 = service(fk2);
  await s2.b.takeOver({ agentId: "a2" }, ADMIN);
  assert.match((await s2.b.saveBox({ agentId: "a2", mode: "public-web" }, ADMIN)).error, /cannot be read/);
});

test("XOR conflict from elsewhere (the plugin sets no grants) is flagged red on the row", async () => {
  const agents = [claude("a1", "Lead", { networkAllowlist: ["api.anthropic.com", "*:443", "*:80"] })];
  const fk = fakeCtx({ agents, grants: [{ principalType: "agent", principalId: "a1", permissionKey: "tasks:assign" }, { principalType: "agent", principalId: "a1", permissionKey: "pipelines:write" }] });
  const { b } = service(fk);
  const row = (await b.view({}, MEMBER)).rows[0];
  assert.equal(row.box, "public-web");
  assert.deepEqual(row.permissions, { canCreateAgents: false, canCreateSkills: false, tasksAssign: true, pipelinesWrite: true });
  assert.match(row.conflicts.join(), /XOR/);
  assert.equal(row.red, true);
});

test("rows: one per agent that exists (terminated left out), fresh at every refresh, NONE flagged, model and status shown", async () => {
  const agents = [claude("a1", "Engineer"), claude("a2", "Old", {}, { status: "terminated" }), claude("a3", "Open", { networkScope: null }, { status: "paused" }),
    { id: "h1", companyId: "c1", name: "Hermes", status: "idle", adapterType: "hermes_local", permissions: {}, adapterConfig: { command: "hermes", model: "x/y" } },
    claude("b1", "Other company", {}, { companyId: "c2" })];
  const fk = fakeCtx({ agents });
  const { b } = service(fk);
  let v = await b.view({}, MEMBER);
  assert.deepEqual(v.rows.map((r) => r.name), ["Engineer", "Open", "Hermes"]);
  assert.equal(v.canEdit, false);
  const open = v.rows.find((r) => r.name === "Open");
  assert.equal(open.box, "none");
  assert.equal(open.red, true);
  assert.equal(open.status, "paused");
  assert.equal(v.rows[0].model, "claude-sonnet-4-5");
  assert.equal(v.rows.find((r) => r.name === "Hermes").boxable, false);
  agents.push(claude("a4", "New hire"));
  v = await b.view({}, ADMIN);
  assert.ok(v.rows.some((r) => r.name === "New hire"), "a new agent appears at the next refresh");
  assert.equal(v.canEdit, true);
  // The picker: an admin may read another company; a member may not.
  assert.deepEqual((await b.view({ targetCompanyId: "c2" }, ADMIN)).rows.map((r) => r.name), ["Other company"]);
  await assert.rejects(b.view({ targetCompanyId: "c2" }, MEMBER), NotAllowedError);
  await assert.rejects(b.view({}, AGENT), NotAllowedError);
});

test("every write action refuses agents, system calls and users not listed as admins; listCompanies shows members their own company only", async () => {
  const fk = fakeCtx({ agents: [claude("a1", "Engineer")] });
  register(fk.ctx, { hardening: hardeningFor(fk.ctx) });
  const writes = {
    takeOverBox: { agentId: "a1" },
    saveBox: { agentId: "a1", mode: "allowlist", extraHosts: ["pypi.org"] },
    saveCompanyCaps: { defaultCap: 1000, companyCap: 5000, mode: "enforce" },
    saveAgentCap: { agentId: "a1", cap: 1000 },
    saveCapsInstall: { template: { defaultCap: 1000, companyCap: 5000, mode: "report" } },
  };
  assert.deepEqual(Object.keys(writes).sort(), BOX_ACTIONS.filter((a) => !["listCompanies", "agentBoxes"].includes(a)).sort());
  const snapshot = () => JSON.stringify([...fk.state.entries()].sort());
  const before = snapshot();
  for (const [key, params] of Object.entries(writes)) {
    for (const who of [AGENT, SYSTEM, MEMBER, actor("user", "u-admin", "c2"), undefined]) {
      await assert.rejects(fk.reg.actions[key](params, who), NotAllowedError, `${key} must refuse ${who?.actor?.type ?? "no actor"} ${who?.actor?.userId ?? ""}`);
      await assert.rejects(fk.reg.actions[key]({ ...params, targetCompanyId: "c2" }, who), NotAllowedError);
    }
  }
  assert.equal(snapshot(), before, "refused writes change nothing");
  assert.equal(fk.logs.length, 0);
  // The admin passes every one of them.
  for (const [key, params] of Object.entries(writes)) assert.equal((await fk.reg.actions[key](params, ADMIN)).ok, true, key);
  const mine = await fk.reg.actions.listCompanies({}, MEMBER);
  assert.deepEqual(mine.companies.map((c) => c.id), ["c1"]);
  assert.equal(mine.admin, false);
  assert.deepEqual((await fk.reg.actions.listCompanies({}, ADMIN)).companies.map((c) => c.id), ["c1", "c2"]);
  await assert.rejects(fk.reg.actions.listCompanies({}, AGENT), NotAllowedError);
});

test("rows carry today's usage against the cap (caps view)", async () => {
  const fk = fakeCtx({ agents: [claude("a1", "Engineer")] });
  const h = hardeningFor(fk.ctx);
  const caps = createCaps({ ctx: fk.ctx, assertAdmin: h.assertAdmin, now: () => new Date("2026-10-18T10:00:00Z") });
  const b = createBoxes({ ctx: fk.ctx, assertAdmin: h.assertAdmin, loadSettings: h.loadSettings, capsView: caps.view });
  const v = await b.view({}, ADMIN);
  assert.equal(v.caps.defaultCap, 600000);
  assert.equal(v.caps.fromTemplate, true);
  assert.deepEqual(v.rows[0].cap, { cap: 600000, override: null, reported: false, used: null, error: null, pausedByCap: false });
  assert.equal(syncState(claude("x", "X", { networkAllowlist: ["api.anthropic.com"], filesystemExtraPaths: [] }), buildBoxPatch({ mode: "allowlist", extraHosts: [], extraPaths: [] }, {})), "in-sync");
});

// ---------- v0.2.0: opencode_local is boxable; per-type state, findings and the fix PATCH on the rows
const opencode = (id, name, cfg = {}) => ({ ...claude(id, name, {}), adapterType: "opencode_local", adapterConfig: { model: "openrouter/x", filesystemScope: "workspace", filesystemSandboxCommand: "/usr/bin/bwrap", networkScope: "allowlist", networkAllowlist: [R], ...cfg } });
const other = (id, adapterType, cfg = {}) => ({ id, companyId: "c1", name: id, role: "engineer", status: "idle", adapterType, permissions: {}, adapterConfig: cfg });

test("opencode_local base: baseAllowlists[type], else the profile's common LLM hosts (no single provider); claude keeps baseAllowlist", () => {
  assert.deepEqual(effectiveBase({}, "opencode_local").hosts, ["openrouter.ai", "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"]);
  assert.deepEqual(effectiveBase({ baseAllowlists: { opencode_local: ["openrouter.ai"] }, baseAllowlist: ["x.example"] }, "opencode_local").hosts, ["openrouter.ai"]);
  assert.deepEqual(effectiveBase({ baseAllowlist: ["x.example"], baseAllowlists: { opencode_local: ["openrouter.ai"] } }).hosts, ["x.example"]);
  const p = buildBoxPatch({ mode: "allowlist", extraHosts: ["pypi.org"], extraPaths: [] }, { baseAllowlists: { opencode_local: ["openrouter.ai"] } }, "opencode_local");
  assert.deepEqual(p.adapterConfig.networkAllowlist, ["openrouter.ai", "pypi.org"]);
});

test("rows: opencode_local is boxable and can be taken over; its findings and the fix PATCH are shown, never written", async () => {
  const bad = opencode("o1", "Coder", { filesystemScope: undefined, filesystemSandboxCommand: undefined, networkScope: undefined, networkAllowlist: undefined, env: { HOME: "/x", XDG_CACHE_HOME: "/y", OPENCODE_CONFIG: "/z", OPENROUTER_API_KEY: { type: "secret_ref" } } });
  const good = opencode("o2", "Clean", {});
  const fk = fakeCtx({ agents: [bad, good], settings: { baseAllowlists: { opencode_local: ["openrouter.ai"] } } });
  const { b, sent } = service(fk);
  const rows = Object.fromEntries((await b.view({}, ADMIN)).rows.map((r) => [r.id, r]));
  assert.equal(rows.o1.boxable, true);
  assert.equal(rows.o1.typeState, "boxed");
  assert.match(rows.o1.findings.join(), /filesystemScope/);
  assert.deepEqual(rows.o1.dropEnv, ["HOME", "XDG_CACHE_HOME", "OPENCODE_CONFIG"]);
  assert.match(rows.o1.findings.join(), /filesystemSandboxCommand is not an absolute path/);
  assert.deepEqual(rows.o1.fix, { adapterConfig: { filesystemScope: "workspace", filesystemSandboxCommand: "/usr/bin/bwrap", networkScope: "allowlist", networkAllowlist: ["openrouter.ai"] } });
  assert.equal(rows.o2.fix, null, "an agent that already has the keys gets no fix");
  assert.ok(!JSON.stringify(rows).includes("REDACTED"));
  assert.equal(sent.length, 0);
  // Taken over, the fix carries the plugin's lists (base plus extras).
  assert.equal((await b.takeOver({ agentId: "o1" }, ADMIN)).ok, true);
  assert.equal((await b.saveBox({ agentId: "o1", mode: "allowlist", extraHosts: "pypi.org" }, ADMIN)).ok, true);
  const after = (await b.view({}, ADMIN)).rows.find((r) => r.id === "o1");
  assert.deepEqual(after.fix.adapterConfig.networkAllowlist, ["openrouter.ai", "pypi.org"]);
});

test("rows: claude_local without engine cli gets the engine in its fix PATCH", async () => {
  const fk = fakeCtx({ agents: [claude("a1", "Engineer", { networkAllowlist: ["api.anthropic.com"], filesystemSandboxCommand: "/usr/bin/bwrap", engine: "acp" })] });
  const { b } = service(fk);
  const row = (await b.view({}, ADMIN)).rows[0];
  assert.match(row.findings.join(), /engine is not 'cli'/);
  assert.deepEqual(row.fix, { adapterConfig: { engine: "cli" } });
});

test("rows: the other adapter types show what this version does with them", async () => {
  const exc = [{ agentId: "r2", type: "http", reason: "r", addedBy: "u", addedAt: "2026-10-20T00:00:00.000Z" }];
  const fk = fakeCtx({ agents: [other("c1x", "codex_local"), other("r1", "http"), other("r2", "http"), other("r3", "paperclip_runner"), other("h1", "hermes_local", { command: "/usr/local/bin/hermes-sandbox" })],
    settings: { remoteExceptions: exc } });
  const { b } = service(fk);
  const rows = Object.fromEntries((await b.view({}, ADMIN)).rows.map((r) => [r.id, r]));
  assert.equal(rows.c1x.typeState, "later-version");
  assert.match(rows.c1x.typeNote, /planned for a later version/);
  assert.equal(rows.r1.typeState, "exception-needed");
  assert.match(rows.r1.typeNote, /needs a remote exception/);
  assert.equal(rows.r2.typeState, "excepted");
  assert.deepEqual(rows.r2.findings, []);
  assert.equal(rows.r3.typeState, "unsupported");
  assert.equal(rows.h1.typeState, "hermes-wrapper");
  for (const id of ["c1x", "r1", "r2", "r3", "h1"]) { assert.equal(rows[id].boxable, false); assert.equal(rows[id].fix, null); }
  assert.match((await b.takeOver({ agentId: "c1x" }, ADMIN)).error, /no box the plugin can manage/);
});
