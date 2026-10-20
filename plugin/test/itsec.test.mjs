// The plugin-managed ITSec agent (src/itsec.js, src/itsec-declarations.js, wiring in src/hardening.js, src/worker.js,
// src/alerts.js, src/recheck.js) with a fake plugin context. The fake keeps a tiny Paperclip: managed agents and
// routines created from the manifest declarations, issues, comments, documents, grants.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import manifest from "../src/manifest.js";
import { itsecAgentDeclaration, itsecRoutineDeclarations, ITSEC_REF_KEY, ITSEC_CLOSED_KEY, ITSEC_MODELS, DEFAULT_ITSEC_MODEL } from "../src/itsec-declarations.js";
import {
  createItsec, checkItsecAgent, NotHostCompanyError, PROVISION_REASON, ITSEC_STATE_KEY, ITSEC_RETIRE_KEY, STATUS_ISSUE_ORIGIN,
  ITSEC_AGENT_KEY, TRIAGE_ROUTINE_KEY, DAILY_ROUTINE_KEY, NUDGE_DEBOUNCE_MS, MAX_SWEEP_ATTEMPTS, ALERT_ORIGIN,
} from "../src/itsec.js";
import { checkAgent } from "../src/logic.js";
import { raiseAlertIssue, setAlertListener } from "../src/alerts.js";
import { createHardening, NotAllowedError } from "../src/hardening.js";
import { DEFAULT_SETTINGS, normalizeSettings } from "../src/settings.js";
import { register } from "../src/worker.js";
import { fakeTarget, hardeningFor } from "./helpers/scratch-tree.mjs";

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src");
const tmp = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "itsec-test-"));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const T0 = Date.parse("2026-10-20T08:00:00.000Z");
const MIN = 60_000;
const HOST = "host-co";
const OTHER = "other-co";

/** A fake Paperclip + plugin ctx. `settings` is mutable; `world` exposes every call for assertions. */
function setup({ settings: over = {} } = {}) {
  const settings = { ...DEFAULT_SETTINGS, itsecHostCompanyId: HOST, alertCompanyId: HOST, ...over };
  const clock = { t: T0 };
  const world = {
    agents: new Map(), routines: new Map(), issues: new Map(), comments: new Map(), docs: [], companies: new Set([HOST, OTHER, "a-co", "b-co"]),
    grants: {}, noConfig: new Set(), createCount: 0, clockTick: 0, documents: new Map(), calls: [], alerts: [], logs: [], failRun: false, failGrants: false,
  };
  const call = (name, ...args) => world.calls.push([name, ...args]);
  const calls = (name) => world.calls.filter((c) => c[0] === name);
  const state = new Map();
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const guard = (companyId) => { if (world.noConfig.has(companyId)) throw new Error("Plugin has no saved configuration for this company"); };
  // world.requestCompany imitates a page request of one company: Paperclip refuses every call that names another company while it runs.
  const scope = (companyId) => { if (world.requestCompany && companyId && companyId !== world.requestCompany) throw new Error(`requested company "${companyId}" but the current invocation is scoped to company "${world.requestCompany}"`); };
  const agentOf = (companyId) => [...world.agents.values()].find((a) => a.companyId === companyId) ?? null;
  const ctx = {
    state: { get: async (key) => { scope(key.scopeKind === "company" ? key.scopeId : null); return state.has(k(key)) ? structuredClone(state.get(k(key))) : null; }, set: async (key, v) => { scope(key.scopeKind === "company" ? key.scopeId : null); state.set(k(key), structuredClone(v)); }, delete: async (key) => { state.delete(k(key)); } },
    config: { get: async () => ({ adminUserIds: ["u-admin"] }) },
    activity: { log: async (e) => { scope(e.companyId); world.logs.push(e); } },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    companies: { get: async (id) => (world.companies.has(id) ? { id, requireBoardApprovalForNewAgents: world.requireApproval === true } : null), list: async () => [] },
    agents: {
      list: async ({ companyId }) => [...world.agents.values()].filter((a) => a.companyId === companyId).map((a) => structuredClone(a)),
      get: async (id, companyId) => { const a = world.agents.get(id); return a && a.companyId === companyId ? structuredClone(a) : null; },
      pause: async (id, companyId) => { scope(companyId); call("agents.pause", id, companyId); const a = world.agents.get(id); a.status = "paused"; a.pauseReason = "manual"; a.pausedAt = new Date(Date.UTC(2026, 0, 1) + 1000 * ++world.clockTick); /* like Paperclip: the pause instant is returned */ return structuredClone(a); },
      resume: async (id, companyId) => { call("agents.resume", id, companyId); const a = world.agents.get(id); a.status = "idle"; a.pauseReason = null; a.pausedAt = null; return structuredClone(a); },
      managed: {
        get: async (key, companyId) => { scope(companyId); call("agents.managed.get", key, companyId); const a = agentOf(companyId); return { resourceKey: key, companyId, agentId: a?.id ?? null, agent: a ? structuredClone(a) : null, status: a ? "resolved" : "missing" }; },
        reconcile: async (key, companyId) => {
          call("agents.managed.reconcile", key, companyId); guard(companyId);
          const existing = agentOf(companyId);
          if (existing) return { agent: structuredClone(existing), status: "resolved" };
          world.createCount += 1;
          const d = itsecAgentDeclaration;
          // world.createOverride imitates the safe-defaults patch, which overwrites these keys of every new claude_local agent.
          const a = { id: `ag-${world.createCount}`, companyId, name: d.displayName, adapterType: d.adapterType, adapterConfig: { ...structuredClone(d.adapterConfig), ...structuredClone(world.createOverride ?? {}) }, permissions: structuredClone(d.permissions),
            runtimeConfig: structuredClone(d.runtimeConfig), status: "paused", pauseReason: PROVISION_REASON, pausedAt: new Date(Date.UTC(2026, 0, 1) + 1000 * ++world.clockTick) };
          world.agents.set(a.id, a);
          return { agent: structuredClone(a), status: "created" };
        },
        reset: async (key, companyId) => { call("agents.managed.reset", key, companyId); const a = agentOf(companyId); Object.assign(a, { adapterConfig: structuredClone(itsecAgentDeclaration.adapterConfig) }); /* Paperclip's reset leaves the status alone */ return { agent: structuredClone(a), status: "reset" }; },
      },
    },
    routines: {
      managed: {
        get: async (key, companyId) => { const r = world.routines.get(`${companyId}:${key}`); return { routineId: r?.id ?? null, routine: r ? structuredClone(r) : null, status: r ? "resolved" : "missing" }; },
        reconcile: async (key, companyId) => {
          call("routines.managed.reconcile", key, companyId); guard(companyId);
          if (!agentOf(companyId)) return { routineId: null, routine: null, status: "missing_refs", missingRefs: [{ resourceKind: "agent", resourceKey: ITSEC_AGENT_KEY }] };
          const id = `${companyId}:${key}`;
          if (!world.routines.has(id)) {
            const d = itsecRoutineDeclarations.find((x) => x.routineKey === key);
            world.routines.set(id, { id, key, status: d.status, assigneeAgentId: agentOf(companyId).id });
            return { routineId: id, routine: structuredClone(world.routines.get(id)), status: "created" };
          }
          return { routineId: id, routine: structuredClone(world.routines.get(id)), status: "resolved" };
        },
        reset: async (key, companyId) => { call("routines.managed.reset", key, companyId); return { routineId: `${companyId}:${key}`, status: "reset" }; },
        update: async (key, companyId, patch) => { scope(companyId); call("routines.managed.update", key, companyId, patch.status); const r = world.routines.get(`${companyId}:${key}`); if (!r) throw new Error("Managed routine not found"); r.status = patch.status; return structuredClone(r); },
        run: async (key, companyId) => { call("routines.managed.run", key, companyId); if (world.failRun) throw new Error("agent is paused"); return { id: `run-${calls("routines.managed.run").length}` }; },
      },
    },
    authorization: { grants: { list: async ({ principalId }) => { if (world.failGrants) throw new Error("grants unavailable"); return structuredClone(world.grants[principalId] ?? []); } } },
    issues: {
      create: async (input) => { const id = `iss-${world.issues.size + 1}`; world.issues.set(id, { id, hiddenAt: null, ...structuredClone(input) }); call("issues.create", input.title); return { id, identifier: `ISS-${world.issues.size}` }; },
      get: async (id, companyId) => { const i = world.issues.get(id); return i && i.companyId === companyId ? structuredClone(i) : null; },
      list: async ({ companyId, originKind, status, limit }) => {
        call("issues.list", { originKind, status, limit });
        const want = status ? String(status).split(",") : null;
        return [...world.issues.values()].filter((i) => i.companyId === companyId && (!originKind || (i.originKind ?? `plugin:paperclip-security-hardening`) === originKind) && (!want || want.includes(i.status))).map((i) => structuredClone(i)).slice(0, limit ?? Infinity);
      },
      listComments: async (id) => structuredClone(world.comments.get(id) ?? []),
      // Like Paperclip's document service: an update of an existing document needs baseRevisionId, which the plugin SDK's upsert
      // cannot pass (its input has no such field and the host forwards none), so upsert works only for a key that does not exist.
      // No `get`: the plugin holds issue.documents.write only, and Paperclip refuses a read without issue.documents.read.
      documents: {
        delete: async (issueId, key) => { call("documents.delete", issueId, key); if (world.failDocDelete) throw new Error("Document is locked"); world.documents.delete(`${issueId}:${key}`); },
        upsert: async (input) => {
          call("documents.upsert", input.issueId, input.key);
          if (world.failDocUpsert) throw new Error("document store unavailable");
          const id = `${input.issueId}:${input.key}`;
          if (world.documents.has(id)) throw new Error("Document update requires baseRevisionId. GET the current document, read its body and latestRevisionId, then set baseRevisionId to that latestRevisionId when updating.");
          world.documents.set(id, { id, issueId: input.issueId, key: input.key, body: input.body });
          world.docs.push({ issueId: input.issueId, key: input.key, body: input.body });
          return input;
        },
      },
    },
  };
  const raiseAlert = async (o) => { world.alerts.push(o); return { ok: true, issue: { issueId: `al-${world.alerts.length}` } }; };
  const itsec = createItsec({ ctx, loadSettings: async () => structuredClone(settings), statusSnapshot: async () => ({ available: true, paperclipVersion: "1", restart: { needed: false }, protections: [{ title: "P", status: "applied" }], watchdog: { status: "on" } }), raiseAlert, now: () => clock.t });
  /** An alert issue of the plugin in the host company (no comment yet). */
  const addAlert = (id, over2 = {}) => world.issues.set(id, { id, companyId: HOST, title: `alert ${id}`, status: "todo", priority: "high", hiddenAt: null, ...over2 });
  const activate = async () => { const r = await itsec.ensure(HOST); assert.equal(r.ok, true, r.error); return r; };
  return { ctx, itsec, settings, world, clock, state, calls, agentOf, addAlert, activate, k };
}

const goodAgent = () => ({ adapterType: "claude_local", status: "idle", name: "ITSec", permissions: { canCreateAgents: false, canCreateSkills: false }, adapterConfig: structuredClone(itsecAgentDeclaration.adapterConfig) });

// ------------------------------------------------------------------------------------------- declarations and checks
test("declaration: claude_local on the cli engine, bwrap workspace scope, model API only, no dangerous key, nothing granted, created paused", () => {
  const a = itsecAgentDeclaration;
  const c = a.adapterConfig;
  assert.equal(a.adapterType, "claude_local");
  assert.equal(c.engine, "cli");
  assert.equal(c.filesystemScope, "workspace");
  assert.equal(c.filesystemSandboxCommand, "/usr/bin/bwrap");
  assert.deepEqual(c.filesystemExtraPaths, []);
  assert.equal(c.networkScope, "allowlist");
  assert.deepEqual(c.networkAllowlist, ["api.anthropic.com"]);
  assert.ok(!c.networkAllowlist.some((h) => h.includes("*")), "no wildcard host");
  assert.ok(!("dangerouslySkipPermissions" in c), "left unset: the adapter then skips permissions, which headless claude -p needs (false refuses Bash and MCP tools)");
  for (const k of ["dangerouslyBypassApprovalsAndSandbox", "dangerouslyBypassSandbox", "yolo", "alwaysApprove", "chrome"]) assert.ok(!(k in c), k);
  assert.equal(c.model, DEFAULT_ITSEC_MODEL);
  assert.ok(ITSEC_MODELS.includes(c.model));
  assert.deepEqual(a.permissions, { canCreateAgents: false, canCreateSkills: false });
  assert.equal(a.status, "paused");
  assert.equal(a.runtimeConfig.heartbeat.enabled, false);
  assert.equal(a.runtimeConfig.heartbeat.maxDailyRuns, 30);
  // The declaration passes the plugin's own checks as an agent.
  assert.deepEqual(checkItsecAgent({ ...goodAgent() }, []), []);
  assert.deepEqual(checkAgent({ ...goodAgent() }), []);
  assert.equal(manifest.agents.length, 1);
  assert.equal(manifest.agents[0].agentKey, "itsec");
  assert.equal(manifest.minimumHostVersion, "2026.1005.0");
  for (const cap of ["agents.managed", "routines.managed", "issue.documents.write"]) assert.ok(manifest.capabilities.includes(cap), cap);
  assert.ok(!manifest.capabilities.includes("agents.lifecycle.manage"));
  assert.ok(!manifest.capabilities.includes("authorization.grants.write"));
  assert.ok(!manifest.capabilities.includes("agents.invoke"));
});

test("routines: two registered for the agent; triage has no schedule of its own, the daily review runs at 07:00 UTC; both coalesce and start paused", () => {
  assert.equal(manifest.routines.length, 2);
  const triage = manifest.routines.find((r) => r.routineKey === TRIAGE_ROUTINE_KEY);
  const daily = manifest.routines.find((r) => r.routineKey === DAILY_ROUTINE_KEY);
  for (const r of [triage, daily]) {
    assert.deepEqual(r.assigneeRef, { resourceKind: "agent", resourceKey: "itsec" });
    assert.equal(r.concurrencyPolicy, "coalesce_if_active");
    assert.equal(r.catchUpPolicy, "skip_missed");
    assert.equal(r.status, "paused");
  }
  assert.equal(triage.triggers, undefined, "no cron: alerts start it");
  assert.equal(daily.triggers.length, 1);
  assert.deepEqual([daily.triggers[0].kind, daily.triggers[0].cronExpression, daily.triggers[0].timezone], ["schedule", "0 7 * * *", "UTC"]);
});

test("checkItsecAgent flags open web, a tasks:assign grant, skip-permissions on an unboxed agent, a wrong adapter, the wrong engine and host paths", () => {
  const bad = (patch, grants = []) => checkItsecAgent({ ...goodAgent(), ...(patch.top ?? {}), adapterConfig: { ...goodAgent().adapterConfig, ...(patch.cfg ?? {}) } }, grants).join("; ");
  assert.match(bad({ cfg: { networkAllowlist: ["api.anthropic.com", "*:443"] } }), /public web/);
  assert.match(bad({ cfg: { networkScope: "none" } }), /networkScope/);
  assert.match(bad({}, [{ principalType: "agent", permissionKey: "tasks:assign" }]), /holds the grant tasks:assign/);
  assert.equal(bad({}, [{ principalType: "agent", permissionKey: "tools:use" }]), "");
  // The declared agent (skip-permissions unset) is boxed, hence compliant; true is fine inside the box too.
  assert.equal(bad({}), "");
  assert.equal(bad({ cfg: { dangerouslySkipPermissions: true } }), "");
  assert.equal(bad({ cfg: { dangerouslySkipPermissions: false } }), "");
  // Unboxed: unset or true is flagged with its own reason.
  assert.match(bad({ cfg: { filesystemScope: null } }), /dangerouslySkipPermissions is unset .*not boxed/);
  assert.match(bad({ cfg: { filesystemScope: null, dangerouslySkipPermissions: true } }), /dangerouslySkipPermissions is enabled on an agent that is not boxed/);
  assert.match(bad({ cfg: { networkScope: "none", dangerouslySkipPermissions: true } }), /not boxed/);
  assert.doesNotMatch(bad({ cfg: { filesystemScope: null, dangerouslySkipPermissions: false } }), /dangerouslySkipPermissions/);
  assert.match(bad({ top: { adapterType: "codex_local" } }), /not claude_local/);
  assert.match(bad({ cfg: { engine: "acp" } }), /engine/);
  assert.match(bad({ cfg: { filesystemExtraPaths: ["/etc"] } }), /filesystemExtraPaths/);
  assert.match(bad({ cfg: { filesystemExtraPaths: "/etc" } }), /filesystemExtraPaths/);
  assert.match(bad({ top: { permissions: { canCreateAgents: true } } }), /canCreateAgents/);
  assert.match(bad({ cfg: { filesystemScope: null } }), /filesystemScope/);
});

test("checkItsecAgent accepts exactly the configured read-only paths (the safe-defaults patch writes them) and flags any other", () => {
  const withPaths = (paths) => ({ ...goodAgent(), adapterConfig: { ...goodAgent().adapterConfig, filesystemExtraPaths: paths } });
  const cfg = { extraReadOnlyPaths: ["/opt/kb", "/srv/docs"] };
  // Without configured paths any path is flagged; with them exactly those are fine (any order, subset, base allowlist too).
  assert.match(checkItsecAgent(withPaths(["/opt/kb"]), [], {}).join("; "), /beyond the site's read-only paths: \/opt\/kb/);
  assert.match(checkItsecAgent(withPaths(["/opt/kb"]), []).join("; "), /filesystemExtraPaths/);
  assert.deepEqual(checkItsecAgent(withPaths(["/srv/docs", "/opt/kb"]), [], cfg), []);
  assert.deepEqual(checkItsecAgent(withPaths(["/opt/kb"]), [], cfg), []);
  assert.deepEqual(checkItsecAgent(withPaths([]), [], cfg), []);
  // A path beyond the configured ones is drift, and only that path is named.
  const beyond = checkItsecAgent(withPaths(["/opt/kb", "/etc"]), [], cfg).join("; ");
  assert.match(beyond, /beyond the site's read-only paths: \/etc$/);
  assert.doesNotMatch(beyond, /\/opt\/kb/);
  // The patch also writes the site's base allowlist; the board may add a host (memory service): accepted, wildcards are not.
  const withHosts = (hosts) => ({ ...goodAgent(), adapterConfig: { ...goodAgent().adapterConfig, networkAllowlist: hosts } });
  assert.deepEqual(checkItsecAgent(withHosts(["api.anthropic.com", "mem.example.org:8443"]), [], cfg), []);
  assert.match(checkItsecAgent(withHosts(["*.example.org"]), [], cfg).join("; "), /public web/);
});

// What the shipped instructions must not contain: anything that names a server or an account. The generic patterns are
// here; terms specific to one site (host or project names) come from an optional file kept outside the repository
// (HARDENING_SCRUB_TERMS_FILE: one term per line, matched case-insensitively), and that part is skipped when it is unset.
function scrubPatterns() {
  const patterns = [
    /\b(?!(?:127|0)\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,   // IPv4 outside loopback and the documentation ranges
    /\/home\/[a-z_][\w.-]*\//i,
    /\b[\w.+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}\b/i,
    /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i,
  ];
  const file = process.env.HARDENING_SCRUB_TERMS_FILE;
  if (file) for (const term of fs.readFileSync(file, "utf8").split("\n").map((l) => l.trim()).filter(Boolean)) patterns.push(new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  return patterns;
}

test("instructions: AGENTS.md, TRIAGE.md and DAILY-REVIEW.md ship, are generic (no server specifics) and document the resolution comment format and the escalation rule", () => {
  const ins = itsecAgentDeclaration.instructions;
  assert.equal(ins.entryFile, "AGENTS.md");
  assert.deepEqual(Object.keys(ins.files).sort(), ["DAILY-REVIEW.md", "TRIAGE.md"]);
  const all = [ins.content, ...Object.values(ins.files)];
  const scrub = scrubPatterns();
  for (const text of all) for (const re of scrub) assert.doesNotMatch(text, re, `${re} in the instructions`);
  assert.match(ins.content, /Never cancel or reopen an alert, and never change its assignee or priority/);
  assert.match(ins.content, /first line must start with `Resolution:`, a later line must start with `Evidence:`/);
  assert.match(ins.content, /ONLY after you posted your own resolution comment/);
  assert.match(ins.content, /For the owner:/, "real host fixes are escalated as proposals");
  assert.doesNotMatch(all.join("\n"), /comment only|never closes|Do not close it/i, "no comment-only statements left");
  assert.match(ins.files["TRIAGE.md"], /Resolve and close/);
  assert.match(ins.files["DAILY-REVIEW.md"], /Alerts closed by the ITSec agent/);
  assert.match(ins.content, /itsec-context/);
  // Also on disk: the shipped files are what the manifest embeds.
  for (const f of ["AGENTS.md", "TRIAGE.md", "DAILY-REVIEW.md"]) for (const re of scrub) assert.doesNotMatch(fs.readFileSync(path.join(SRC, "itsec", f), "utf8"), re);
  assert.ok(JSON.parse(fs.readFileSync(path.join(SRC, "../package.json"), "utf8")).files.includes("src"));
});

test("source scan: ctx.agents.managed and ctx.routines.managed are called from src/itsec.js only", () => {
  const hits = [];
  const walk = (dir) => { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) walk(p); else if (p.endsWith(".js")) { if (/\b(agents|routines)\.managed\.(get|reconcile|reset|update|run)\b/.test(fs.readFileSync(p, "utf8").replace(/\/\/.*$/gm, ""))) hits.push(path.relative(SRC, p)); } } };
  walk(SRC);
  assert.deepEqual(hits, ["itsec.js"]);
  assert.ok(!/skills\.managed|projects\.managed|agents\.invoke|agents\.lifecycle/.test(fs.readFileSync(path.join(SRC, "itsec.js"), "utf8").replace(/\/\/.*$/gm, "")));
});

test("settings: the three ITSec keys validate (id, model allow-list, context length) and default to inert", () => {
  assert.equal(DEFAULT_SETTINGS.itsecHostCompanyId, "");
  assert.equal(normalizeSettings({}).settings.itsecHostCompanyId, "");
  const ok = normalizeSettings({ itsecHostCompanyId: " c-1 ", itsecModel: "claude-opus-5-5", itsecContext: "host: lab-1" });
  assert.deepEqual(ok.errors, []);
  assert.equal(ok.settings.itsecHostCompanyId, "c-1");
  assert.equal(normalizeSettings({ itsecHostCompanyId: "../x" }).errors.length, 1);
  assert.equal(normalizeSettings({ itsecModel: "gpt-9" }).errors.length, 1);
  assert.equal(normalizeSettings({ itsecContext: "x".repeat(8001) }).errors.length, 1);
});

// ------------------------------------------------------------------------------------------- scope: host company only
test("created only for the host company: every other company id throws and no managed call is made", async () => {
  const s = setup();
  for (const fn of [() => s.itsec.ensure(OTHER), () => s.itsec.verify(OTHER), () => s.itsec.reset(OTHER), () => s.itsec.sweep(OTHER)])
    await assert.rejects(fn, (e) => e instanceof NotHostCompanyError && e.code === "NOT_HOST_COMPANY");
  assert.equal(s.world.calls.length, 0);
  assert.equal(s.world.createCount, 0);
  // With no marking at all nothing is created anywhere, not even for the company that would be host.
  const none = setup({ settings: { itsecHostCompanyId: "" } });
  await assert.rejects(none.itsec.ensure(HOST), NotHostCompanyError);
  assert.deepEqual(await none.itsec.runJob(), { retired: [], ensure: null, sweep: null, skipped: "no host company is marked" });
  assert.equal(none.world.calls.length, 0);
  // The host company works.
  const r = await s.itsec.ensure(HOST);
  assert.equal(r.ok, true);
  assert.equal(s.world.createCount, 1);
  assert.deepEqual([...new Set(s.calls("agents.managed.reconcile").map((c) => c[2]))], [HOST]);
});

test("ensure: agent first, then the two routines; created paused, verified, then resumed and routines set active; documents written", async () => {
  const s = setup();
  const r = await s.itsec.ensure(HOST);
  assert.equal(r.ok, true);
  assert.equal(r.agent.status, "created");
  const order = s.world.calls.map((c) => c[0]);
  assert.ok(order.indexOf("agents.managed.reconcile") < order.indexOf("routines.managed.reconcile"));
  assert.deepEqual(s.calls("routines.managed.reconcile").map((c) => c[1]), [TRIAGE_ROUTINE_KEY, DAILY_ROUTINE_KEY]);
  assert.equal(s.calls("agents.resume").length, 1);
  assert.equal(s.agentOf(HOST).status, "idle");
  assert.deepEqual([...s.world.routines.values()].map((x) => x.status), ["active", "active"]);
  assert.ok(order.indexOf("agents.resume") < order.indexOf("routines.managed.update"), "routines activated after the agent was verified and resumed");
  // Status issue with the two documents, plugin origin, no assignee.
  const issue = s.world.issues.get(r.documents.issueId);
  assert.equal(issue.originKind, STATUS_ISSUE_ORIGIN);
  assert.equal(issue.assigneeAgentId, undefined);
  assert.deepEqual(s.world.docs.map((d) => d.key).sort(), ["hardening-status", "itsec-context"]);
  assert.deepEqual(await s.ctx.state.get(ITSEC_REF_KEY(HOST)).then((x) => x.agentId), s.agentOf(HOST).id);
});

test("sites with read-only paths: the patched Paperclip gives the new agent those paths and the base allowlist; it is verified, activated and not alerted", async () => {
  const paths = ["/opt/kb"];
  const t = setup({ settings: { extraReadOnlyPaths: paths, baseAllowlist: ["api.anthropic.com", "mem.example.org"] } });
  t.world.createOverride = { filesystemExtraPaths: paths, networkAllowlist: ["api.anthropic.com", "mem.example.org"] };
  const r = await t.activate();
  assert.equal(r.verify.state, "active", JSON.stringify(r.verify.findings));
  assert.equal(t.world.alerts.length, 0);
  assert.equal(t.agentOf(HOST).status, "idle");
  assert.ok([...t.world.routines.values()].every((x) => x.status === "active"));
  // A path beyond the configured ones is drift: paused, one HIGH alert naming it.
  t.agentOf(HOST).adapterConfig.filesystemExtraPaths = [...paths, "/etc"];
  const v = await t.itsec.verify(HOST);
  assert.equal(v.state, "drift");
  assert.match(v.findings.join("; "), /\/etc/);
  assert.equal(t.world.alerts.length, 1);
});

test("paused until verified: a drifted fresh agent is not resumed and its routines stay paused; resume only with the provisioning pause reason", async () => {
  // Scenario A: created agent with an open network.
  const a = setup();
  a.ctx.agents.managed.reconcile = ((orig) => async (key, companyId) => { const r = await orig(key, companyId); a.agentOf(companyId).adapterConfig.networkAllowlist = ["api.anthropic.com", "*:443"]; r.agent = structuredClone(a.agentOf(companyId)); return r; })(a.ctx.agents.managed.reconcile);
  const ra = await a.itsec.ensure(HOST);
  assert.equal(ra.verify.state, "drift");
  assert.equal(a.calls("agents.resume").length, 0);
  assert.equal(a.agentOf(HOST).status, "paused");
  assert.deepEqual([...a.world.routines.values()].map((x) => x.status), ["paused", "paused"]);
  assert.equal(a.world.alerts.length, 1);
  // Scenario B: compliant but paused by a person: never resumed, routines stay paused.
  const b = setup();
  await b.itsec.ensure(HOST);
  await b.ctx.agents.pause(b.agentOf(HOST).id, HOST);
  for (const key of [TRIAGE_ROUTINE_KEY, DAILY_ROUTINE_KEY]) await b.ctx.routines.managed.update(key, HOST, { status: "paused" });
  const resumedBefore = b.calls("agents.resume").length;
  const v = await b.itsec.verify(HOST);
  assert.equal(v.ok, true);
  assert.equal(b.calls("agents.resume").length, resumedBefore);
  assert.equal(b.agentOf(HOST).status, "paused");
});

test("idempotent: a second ensure creates nothing and resumes nothing; both status documents are written again", async () => {
  const s = setup();
  await s.itsec.ensure(HOST);
  const docs = s.world.docs.length;
  const second = await s.itsec.ensure(HOST);
  assert.equal(second.ok, true);
  assert.equal(second.agent.status, "resolved");
  assert.equal(s.world.createCount, 1);
  assert.equal(s.calls("agents.resume").length, 1);
  assert.deepEqual(s.world.docs.slice(docs).map((d) => d.key).sort(), ["hardening-status", "itsec-context"]);
  assert.equal(s.world.issues.size, 1, "one status issue");
  assert.equal([...s.world.routines.keys()].length, 2);
  // A changed operator note reaches the document.
  s.settings.itsecContext = "host label: lab";
  const before = s.world.docs.length;
  await s.itsec.ensure(HOST);
  assert.deepEqual(s.world.docs.slice(before).map((d) => d.key).sort(), ["hardening-status", "itsec-context"]);
  assert.match(s.world.docs.at(-1).body, /host label: lab/);
});

test("no saved plugin config row for the host company: nothing is created and the status says what to do", async () => {
  const s = setup();
  s.world.noConfig.add(HOST);
  const r = await s.itsec.ensure(HOST);
  assert.equal(r.ok, false);
  assert.match(r.error, /no saved configuration/);
  assert.match(r.hint, /save the plugin settings for it/);
  assert.equal(s.world.createCount, 0);
  const st = await s.itsec.status(HOST);
  assert.match(st.state.lastError.message, /no saved configuration/);
  assert.match(st.state.lastError.hint, /save the plugin settings/);
  assert.equal(st.agent, null);
  // Once the settings are saved the next run creates it.
  s.world.noConfig.clear();
  assert.equal((await s.itsec.ensure(HOST)).ok, true);
  assert.equal(s.world.createCount, 1);
});

// ------------------------------------------------------------------------------------------- drift
test("drift after activation: the agent and both routines are paused, one alert; once the agent is compliant again the plugin resumes it and switches the routines on", async () => {
  const s = setup();
  await s.activate();
  const id = s.agentOf(HOST).id;
  s.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  const v = await s.itsec.verify(HOST);
  assert.equal(v.state, "drift");
  assert.match(v.findings.join(), /wildcard|public web/);
  assert.equal(s.agentOf(HOST).status, "paused");
  assert.deepEqual([...s.world.routines.values()].map((x) => x.status), ["paused", "paused"]);
  assert.equal(s.world.alerts.length, 1);
  assert.equal(s.world.alerts[0].priority, "high");
  assert.ok(s.world.logs.some((l) => /ITSec agent not compliant, paused/.test(l.message)));
  await s.itsec.verify(HOST);
  assert.equal(s.world.alerts.length, 1, "the same drift alerts once");
  assert.equal((await s.itsec.status(HOST)).state.pausedByPlugin.reason, "drift");
  assert.match((await s.itsec.status(HOST)).attention.join(), /plugin paused this agent.*drifted/);
  // Still drifted: nothing is resumed.
  const resumes = s.calls("agents.resume").length;
  await s.itsec.verify(HOST);
  assert.equal(s.calls("agents.resume").length, resumes);
  // Fixed (board edit): the next check verifies, resumes the agent (the pause was the plugin's own) and switches the routines on.
  s.agentOf(HOST).adapterConfig.networkAllowlist = ["api.anthropic.com"];
  const v3 = await s.itsec.verify(HOST);
  assert.equal(v3.ok, true);
  assert.equal(v3.resumed, true);
  assert.equal(s.calls("agents.resume").length, resumes + 1);
  assert.equal(s.agentOf(HOST).status, "idle");
  assert.deepEqual([...s.world.routines.values()].map((x) => x.status), ["active", "active"]);
  assert.equal(s.agentOf(HOST).id, id);
  assert.equal((await s.itsec.status(HOST)).state.pausedByPlugin, null);
  assert.ok(s.world.logs.some((l) => /resumed \(the plugin had paused it: drift\)/.test(l.message)));
  // The same drift again alerts again (the dedupe was reset by the compliant check).
  s.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  await s.itsec.verify(HOST);
  assert.equal(s.world.alerts.length, 2);
});

test("a pause by the board is never lifted by the plugin: before, during or after a plugin pause", async () => {
  // The board pauses a compliant agent: no record, stays paused, routines stay as they are.
  const a = setup();
  await a.activate();
  await a.ctx.agents.pause(a.agentOf(HOST).id, HOST);
  const resumes = a.calls("agents.resume").length;
  assert.equal((await a.itsec.verify(HOST)).state, "paused");
  assert.equal(a.calls("agents.resume").length, resumes);
  assert.match((await a.itsec.status(HOST)).attention.join(), /not by the plugin.*resume it in Paperclip/);
  // The board's pause on a drifted agent that was already paused: the plugin did not pause it, so it does not resume it either.
  const b = setup();
  await b.activate();
  await b.ctx.agents.pause(b.agentOf(HOST).id, HOST);
  b.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  assert.equal((await b.itsec.verify(HOST)).state, "drift");
  assert.equal((await b.itsec.status(HOST)).state.pausedByPlugin, null);
  b.agentOf(HOST).adapterConfig.networkAllowlist = ["api.anthropic.com"];
  const r1 = b.calls("agents.resume").length;
  assert.equal((await b.itsec.verify(HOST)).state, "paused");
  assert.equal(b.calls("agents.resume").length, r1);
  // The plugin paused for drift, the board fixed and resumed it, then paused it again for its own reasons: the record was
  // cleared by the check that saw it running, so the new pause stays.
  const c = setup();
  await c.activate();
  c.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  await c.itsec.verify(HOST);
  c.agentOf(HOST).adapterConfig.networkAllowlist = ["api.anthropic.com"];
  c.agentOf(HOST).status = "idle"; c.agentOf(HOST).pauseReason = null; c.agentOf(HOST).pausedAt = null; // the board resumes it
  assert.equal((await c.itsec.verify(HOST)).state, "active");
  await c.ctx.agents.pause(c.agentOf(HOST).id, HOST); // the board pauses it again
  const r2 = c.calls("agents.resume").length;
  assert.equal((await c.itsec.verify(HOST)).state, "paused");
  assert.equal(c.calls("agents.resume").length, r2);
});

test("a board resume and a new board pause between the plugin's pause and the next check: the new pause is not the plugin's and stays (drift)", async () => {
  const s = setup();
  await s.activate();
  const id = s.agentOf(HOST).id;
  s.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  assert.equal((await s.itsec.verify(HOST)).state, "drift"); // the plugin pauses
  const mine = s.agentOf(HOST).pausedAt;
  // The board fixes the agent, resumes it and pauses it again, and NO check runs in between.
  s.agentOf(HOST).adapterConfig.networkAllowlist = ["api.anthropic.com"];
  const row = s.agentOf(HOST);
  row.status = "idle"; row.pauseReason = null; row.pausedAt = null;
  await s.ctx.agents.pause(id, HOST);
  assert.notEqual(s.agentOf(HOST).pausedAt.getTime(), mine.getTime());
  const resumes = s.calls("agents.resume").length;
  assert.equal((await s.itsec.verify(HOST)).state, "paused");
  assert.equal(s.calls("agents.resume").length, resumes, "the board's pause is not lifted");
  assert.equal(s.agentOf(HOST).status, "paused");
  assert.match((await s.itsec.status(HOST)).attention.join(), /not by the plugin/);
  // The control: with no board action in between, the plugin does lift its own pause.
  const t = setup();
  await t.activate();
  t.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  await t.itsec.verify(HOST);
  t.agentOf(HOST).adapterConfig.networkAllowlist = ["api.anthropic.com"];
  assert.equal((await t.itsec.verify(HOST)).resumed, true);
});

test("a board resume and a new board pause between the plugin's un-mark pause and marking again: the new pause stays", async () => {
  const s = setup();
  await s.activate();
  const id = s.agentOf(HOST).id;
  const marked = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = "";
  await s.itsec.applyChange(marked, structuredClone(s.settings), HOST); // the plugin pauses
  const row = s.agentOf(HOST);
  row.status = "idle"; row.pauseReason = null; row.pausedAt = null; // the board resumes it
  await s.ctx.agents.pause(id, HOST); // and pauses it again; no check in between
  const cleared = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = HOST;
  const resumes = s.calls("agents.resume").length;
  const r = await s.itsec.applyChange(cleared, structuredClone(s.settings), HOST);
  assert.equal(r.ensure.verify.state, "paused");
  assert.equal(r.ensure.verify.resumed, false);
  assert.equal(s.calls("agents.resume").length, resumes);
  assert.equal(s.agentOf(HOST).status, "paused");
  assert.deepEqual([...s.world.routines.values()].map((x) => x.status), ["paused", "paused"], "routines are switched on only for a running agent");
});

test("a pause the host does not stamp with pausedAt is never lifted by the plugin; routines the board paused are not switched on again", async () => {
  const s = setup();
  await s.activate();
  const pause = s.ctx.agents.pause;
  s.ctx.agents.pause = async (...args) => { const a = await pause(...args); delete a.pausedAt; return a; };
  s.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  await s.itsec.verify(HOST);
  s.agentOf(HOST).adapterConfig.networkAllowlist = ["api.anthropic.com"];
  const resumes = s.calls("agents.resume").length;
  assert.equal((await s.itsec.verify(HOST)).state, "paused");
  assert.equal(s.calls("agents.resume").length, resumes);
  // Routines: the plugin switches them on only while `activated` is false; a board pause of a routine of a running agent stays.
  const t = setup();
  await t.activate();
  for (const key of [TRIAGE_ROUTINE_KEY, DAILY_ROUTINE_KEY]) await t.ctx.routines.managed.update(key, HOST, { status: "paused" });
  await t.itsec.verify(HOST);
  assert.deepEqual([...t.world.routines.values()].map((x) => x.status), ["paused", "paused"]);
});

test("clearing the mark and marking the company again resumes the agent and the routines the plugin paused; a board pause in between stays", async () => {
  const s = setup();
  await s.activate();
  const id = s.agentOf(HOST).id;
  const marked = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = "";
  // Cleared from the host company's own page: paused at once.
  const r = await s.itsec.applyChange(marked, structuredClone(s.settings), HOST);
  assert.deepEqual(r.retired.done, [HOST]);
  assert.equal(s.agentOf(HOST).status, "paused");
  assert.deepEqual([...s.world.routines.values()].map((x) => x.status), ["paused", "paused"]);
  assert.equal(s.world.agents.size, 1, "nothing is deleted");
  // Marked again: relinked, verified, resumed (the pause was the plugin's), routines on.
  const cleared = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = HOST;
  const r2 = await s.itsec.applyChange(cleared, structuredClone(s.settings), HOST);
  assert.equal(r2.ensure.ok, true);
  assert.equal(r2.ensure.verify.resumed, true);
  assert.equal(s.agentOf(HOST).id, id);
  assert.equal(s.agentOf(HOST).status, "idle");
  assert.deepEqual([...s.world.routines.values()].map((x) => x.status), ["active", "active"]);
  // The board pauses it, the mark is cleared and set again: the board's pause stays.
  await s.ctx.agents.pause(id, HOST);
  s.settings.itsecHostCompanyId = "";
  await s.itsec.applyChange(structuredClone({ ...s.settings, itsecHostCompanyId: HOST }), structuredClone(s.settings), HOST);
  s.settings.itsecHostCompanyId = HOST;
  const r3 = await s.itsec.applyChange(structuredClone({ ...s.settings, itsecHostCompanyId: "" }), structuredClone(s.settings), HOST);
  assert.equal(r3.ensure.verify.state, "paused");
  assert.equal(s.agentOf(HOST).status, "paused");
});

test("reset: the plugin re-applies the declaration, verifies, and resumes the agent it had paused for drift", async () => {
  const s = setup();
  await s.activate();
  s.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  await s.itsec.verify(HOST);
  assert.equal(s.agentOf(HOST).status, "paused");
  const r = await s.itsec.reset(HOST);
  assert.equal(r.verify.ok, true);
  assert.equal(r.verify.resumed, true);
  assert.equal(s.agentOf(HOST).status, "idle");
  assert.deepEqual([...s.world.routines.values()].map((x) => x.status), ["active", "active"]);
});

test("default grants (tasks:assign) on the agent are drift: it is paused (the plugin cannot revoke); unreadable grants resume nothing", async () => {
  const s = setup();
  await s.itsec.ensure(HOST); // creates and activates
  s.world.grants[s.agentOf(HOST).id] = [{ principalType: "agent", permissionKey: "tasks:assign" }, { principalType: "agent", permissionKey: "agents:configure" }];
  const v = await s.itsec.verify(HOST);
  assert.equal(v.state, "drift");
  assert.deepEqual(v.findings.sort(), ["holds the grant agents:configure", "holds the grant tasks:assign"]);
  assert.equal(s.agentOf(HOST).status, "paused");
  // Grants that cannot be read: a fresh agent is not resumed, a running one is not paused by the failed read alone.
  const f = setup();
  f.world.failGrants = true;
  const r = await f.itsec.ensure(HOST);
  assert.equal(r.verify.state, "unverified");
  assert.equal(f.agentOf(HOST).status, "paused");
  assert.equal(f.calls("agents.resume").length, 0);
});

// ------------------------------------------------------------------------------------------- marking changes
test("changing the host company: the old agent is paused right after the request that moved the mark, by the retire watcher, without waiting for the job", async () => {
  const s = setup({ settings: { itsecHostCompanyId: "a-co" } });
  await s.itsec.ensure("a-co");
  const oldId = s.agentOf("a-co").id;
  const prev = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = "b-co";
  // The watcher runs outside any request (the worker starts it in setup); it waits for the request to end before it tries.
  let endRequest;
  const requestEnded = new Promise((r) => { endRequest = r; });
  const watcher = s.itsec.startRetireWatcher({ sleep: () => requestEnded, delaysMs: [1] });
  s.world.requestCompany = "b-co"; // the settings request of company B: calls naming a-co are refused while it runs
  const r = await s.itsec.applyChange(prev, structuredClone(s.settings), "b-co");
  assert.equal(r.retired, null, "inside the request nothing can be paused");
  assert.equal(r.ensure.ok, true);
  assert.equal(s.world.agents.get(oldId).status, "idle");
  assert.deepEqual((await s.ctx.state.get(ITSEC_RETIRE_KEY)).map((q) => q.companyId), ["a-co"]);
  // The request ends: the watcher pauses the old agent and its routines. The job (runJob) is not involved.
  s.world.requestCompany = null;
  endRequest();
  await watcher.idle();
  assert.equal(s.world.agents.get(oldId).status, "paused");
  assert.ok(s.calls("routines.managed.update").filter((c) => c[2] === "a-co" && c[3] === "paused").length >= 2);
  assert.deepEqual(await s.ctx.state.get(ITSEC_RETIRE_KEY), []);
  assert.equal(s.world.agents.size, 2);
  assert.equal(s.agentOf("b-co").status, "idle");
  assert.equal(s.calls("agents.managed.reconcile").filter((c) => c[2] === "a-co").length, 1, "the old company is not reconciled again");
  assert.ok(s.world.logs.some((l) => l.companyId === "a-co" && /ITSec agent paused/.test(l.message)));
  assert.equal((await s.itsec.status("b-co")).notice.paused[0], "a-co");
  await watcher.stop();
  // Clearing the marking from the host company's own page pauses the current one at once, in the request.
  const prev2 = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = "";
  s.world.requestCompany = "b-co";
  const r2 = await s.itsec.applyChange(prev2, structuredClone(s.settings), "b-co");
  s.world.requestCompany = null;
  assert.deepEqual(r2.retired.done, ["b-co"]);
  assert.equal(s.agentOf("b-co").status, "paused");
  await assert.rejects(s.itsec.ensure("b-co"), NotHostCompanyError);
});

test("the retire watcher retries a refused attempt, and what still fails stays queued for the job", async () => {
  const s = setup({ settings: { itsecHostCompanyId: "a-co" } });
  await s.itsec.ensure("a-co");
  const prev = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = "b-co";
  const realPause = s.ctx.agents.pause;
  let fails = 1;
  s.ctx.agents.pause = async (...a) => { if (fails-- > 0) throw new Error("another request is running"); return realPause(...a); };
  const sleeps = [];
  const watcher = s.itsec.startRetireWatcher({ sleep: async (ms) => { sleeps.push(ms); }, delaysMs: [10, 20, 30] });
  await s.itsec.applyChange(prev, structuredClone(s.settings), "b-co");
  await watcher.idle();
  assert.deepEqual(sleeps, [10, 20], "the second attempt succeeded, the third delay was not used");
  assert.equal(s.agentOf("a-co").status, "paused");
  assert.deepEqual(await s.ctx.state.get(ITSEC_RETIRE_KEY), []);
  await watcher.stop();
});

test("a retire that keeps failing stays queued and is retried by the job", async () => {
  const s = setup({ settings: { itsecHostCompanyId: "a-co" } });
  await s.itsec.ensure("a-co");
  const prev = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = "b-co";
  const realPause = s.ctx.agents.pause;
  s.ctx.agents.pause = async () => { throw new Error("no access to company a-co"); };
  const watcher = s.itsec.startRetireWatcher({ sleep: async () => {}, delaysMs: [1, 1] });
  await s.itsec.applyChange(prev, structuredClone(s.settings), "b-co");
  await watcher.idle();
  await watcher.stop();
  const queue = await s.ctx.state.get(ITSEC_RETIRE_KEY);
  assert.equal(queue.length, 1);
  assert.match(queue[0].lastError, /no access/);
  assert.equal((await s.itsec.status("b-co")).retirePending[0].companyId, "a-co");
  s.ctx.agents.pause = realPause;
  const job = await s.itsec.runJob();
  assert.deepEqual(job.retired.done, ["a-co"]);
  assert.equal((await s.ctx.state.get(ITSEC_RETIRE_KEY)).length, 0);
  assert.equal(s.agentOf("a-co").status, "paused");
});

test("host switch A -> B -> A while A's retire is still queued: the current host is not paused by the job", async () => {
  const s = setup({ settings: { itsecHostCompanyId: "a-co" } });
  await s.itsec.ensure("a-co");
  const aId = s.agentOf("a-co").id;
  let prev = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = "b-co";
  await s.itsec.applyChange(prev, structuredClone(s.settings), "b-co");
  assert.deepEqual((await s.ctx.state.get(ITSEC_RETIRE_KEY)).map((q) => q.companyId), ["a-co"]);
  prev = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = "a-co";
  await s.itsec.applyChange(prev, structuredClone(s.settings), "a-co");
  assert.deepEqual((await s.ctx.state.get(ITSEC_RETIRE_KEY)).map((q) => q.companyId), ["b-co"], "A left the queue, B was queued");
  const job = await s.itsec.runJob();
  assert.equal(s.world.agents.get(aId).status, "idle", "the current host's agent keeps running");
  assert.equal(s.calls("agents.pause").filter((c) => c[1] === aId).length, 0);
  assert.equal(s.agentOf("b-co").status, "paused");
  assert.equal(job.ensure.verify.state, "active");
  // A stale queue entry for the current host (written by an older version or another path) is dropped, not executed.
  await s.ctx.state.set(ITSEC_RETIRE_KEY, [{ companyId: "a-co", since: "2026-10-20T00:00:00.000Z" }, { companyId: "b-co", since: "2026-10-20T00:00:00.000Z" }]);
  const again = await s.itsec.runJob();
  assert.deepEqual(again.retired.done, ["b-co"]);
  assert.equal(s.world.agents.get(aId).status, "idle");
  assert.deepEqual(await s.ctx.state.get(ITSEC_RETIRE_KEY), []);
});

test("validateChange: marking needs the request to come from inside that company, and the company must exist", async () => {
  const s = setup({ settings: { itsecHostCompanyId: "" } });
  const prev = structuredClone(s.settings);
  const next = { ...prev, itsecHostCompanyId: "a-co" };
  assert.match((await s.itsec.validateChange(prev, next, "b-co"))[0], /inside the company you want to mark/);
  assert.match((await s.itsec.validateChange(prev, next, null))[0], /inside the company/);
  assert.deepEqual(await s.itsec.validateChange(prev, next, "a-co"), []);
  const ghost = { ...prev, itsecHostCompanyId: "ghost" };
  assert.match((await s.itsec.validateChange(prev, ghost, "ghost"))[0], /does not exist/);
  assert.deepEqual(await s.itsec.validateChange(prev, { ...prev, itsecContext: "x" }, "b-co"), [], "other ITSec keys need no company");
  assert.deepEqual(await s.itsec.validateChange(next, { ...next, itsecHostCompanyId: "" }, "b-co"), [], "clearing works from anywhere");
});

// ------------------------------------------------------------------------------------------- saveSettings: who may mark
function hardeningWith(s) {
  const file = path.join(tmp, `cfg-${Math.random().toString(36).slice(2)}`, "config.json");
  const ctx = { ...s.ctx, config: { get: async (companyId) => (companyId === HOST || companyId === "a-co" ? { adminUserIds: ["u-admin"] } : {}) } };
  const h = createHardening({ ctx, createEngineFn: () => { throw new Error("no engine"); }, ...hardeningFor(fakeTarget({ configPath: file })) });
  const real = createItsec({ ctx, loadSettings: () => h.loadSettings(), raiseAlert: async () => ({ ok: true }), now: () => s.clock.t });
  h.setItsec(real);
  return { h, real, ctx };
}
const actor = (type, userId, companyId) => ({ actor: Object.freeze({ type, userId, agentId: type === "agent" ? "ag-x" : null, runId: null, companyId }), companyId });

test("saveSettings: agents and non-admins are refused; an admin marks the host company only from inside it; the site form cannot change the marking", async () => {
  const s = setup({ settings: { itsecHostCompanyId: "" } });
  const { h, real } = hardeningWith(s);
  const body = { itsecHostCompanyId: HOST, itsecModel: "claude-opus-5-5", itsecContext: "host: lab" };
  await assert.rejects(h.saveSettings({ settings: body }, actor("agent", null, HOST)), NotAllowedError);
  await assert.rejects(h.saveSettings({ settings: body }, actor("user", "u-member", HOST)), /u-member/);
  await assert.rejects(h.saveSettings({ settings: body }, actor("system", null, HOST)), NotAllowedError);
  assert.equal(s.world.calls.length, 0);
  // Admin of the host company, but on another company's page: refused with the reason.
  const wrong = await h.saveSettings({ settings: { ...body, itsecHostCompanyId: "a-co" } }, actor("user", "u-admin", HOST));
  assert.equal(wrong.ok, false);
  assert.match(wrong.errors[0], /inside the company you want to mark/);
  // A company-less instance admin cannot mark either (the host admits the reconcile only inside the company).
  const noCo = await h.saveSettings({ settings: body }, actor("user", "u-root", null));
  assert.equal(noCo.ok, false);
  assert.equal(s.world.createCount, 0);
  // Inside the company: marked, agent created, activity entry written.
  const ok = await h.saveSettings({ settings: body }, actor("user", "u-admin", HOST));
  assert.equal(ok.ok, true, JSON.stringify(ok));
  assert.equal(ok.settings.itsecHostCompanyId, HOST);
  assert.equal(ok.itsec.ensure.ok, true);
  assert.equal(s.world.createCount, 1);
  assert.ok(s.world.logs.some((l) => /host company for the ITSec agent set/.test(l.message)));
  // The general site form does not carry the ITSec keys: the marking, model and notes survive.
  const site = await h.saveSettings({ settings: { baseAllowlist: ["api.anthropic.com"], alertCompanyId: HOST } }, actor("user", "u-admin", HOST));
  assert.equal(site.ok, true);
  assert.equal(site.settings.itsecHostCompanyId, HOST);
  assert.equal(site.settings.itsecModel, "claude-opus-5-5");
  assert.equal(site.settings.itsecContext, "host: lab");
  assert.equal(site.itsec, null, "no ITSec change, no ITSec work");
  // A bad model is refused with nothing stored.
  const bad = await h.saveSettings({ settings: { ...body, itsecModel: "gpt-9" } }, actor("user", "u-admin", HOST));
  assert.equal(bad.ok, false);
  // Clearing (from the host page) pauses the agent.
  const cleared = await h.saveSettings({ settings: { itsecHostCompanyId: "" } }, actor("user", "u-admin", HOST));
  assert.equal(cleared.ok, true);
  assert.equal(s.agentOf(HOST).status, "paused");
});

test("worker actions: status is for users only (notes hidden from non-admins), check and reset are admin writes and reset needs confirm", async () => {
  const s = setup();
  const reg = { actions: {}, jobs: {}, data: {} };
  const ctx = { ...s.ctx, config: { get: async () => ({ adminUserIds: ["u-admin"] }) }, data: { register: (k, f) => { reg.data[k] = f; } }, actions: { register: (k, f) => { reg.actions[k] = f; } }, jobs: { register: (k, f) => { reg.jobs[k] = f; } }, events: { on() {} } };
  const h = createHardening({ ctx, createEngineFn: () => { throw new Error("no engine"); }, ...hardeningFor(fakeTarget({ configPath: path.join(tmp, "w", "config.json") })) });
  register(ctx, { hardening: h, itsec: s.itsec, boxes: {}, caps: { runJob: async () => ({}), view: async () => ({}) }, hosts: { watchdogStatus: async () => ({}), hermesStatus: async () => ({}), checkHeartbeat: async () => {}, command: async () => ({}) }, recheck: { recordEvent: async () => {}, runJob: async () => [] } });
  assert.ok(reg.jobs["itsec-reconcile"], "job registered");
  for (const key of ["itsecStatus", "itsecCheck", "itsecReset"]) assert.ok(reg.actions[key], key);
  await assert.rejects(reg.actions.itsecStatus({}, actor("agent", null, HOST)), NotAllowedError);
  await assert.rejects(reg.actions.itsecCheck({}, actor("agent", null, HOST)), NotAllowedError);
  await assert.rejects(reg.actions.itsecReset({ confirm: true }, actor("agent", null, HOST)), NotAllowedError);
  await assert.rejects(reg.actions.itsecCheck({}, actor("user", "u-member", HOST)), /u-member/);
  await assert.rejects(reg.actions.itsecReset({ confirm: true }, actor("user", "u-member", HOST)), /u-member/);
  s.settings.itsecContext = "operator notes";
  const member = await reg.actions.itsecStatus({}, actor("user", "u-member", HOST));
  assert.equal(member.admin, false);
  assert.equal(member.context, undefined);
  const admin = await reg.actions.itsecStatus({}, actor("user", "u-admin", HOST));
  assert.equal(admin.admin, true);
  assert.equal(admin.context, "operator notes");
  assert.equal(s.world.createCount, 0, "status never creates");
  const chk = await reg.actions.itsecCheck({}, actor("user", "u-admin", HOST));
  assert.equal(chk.ok, true);
  const other = await reg.actions.itsecCheck({}, actor("user", "u-admin", OTHER));
  assert.equal(other.ok, false);
  assert.match(other.error, /different company|host company/);
  assert.equal((await reg.actions.itsecReset({}, actor("user", "u-admin", HOST))).ok, false);
  assert.equal(s.calls("agents.managed.reset").length, 0);
  const reset = await reg.actions.itsecReset({ confirm: true }, actor("user", "u-admin", HOST));
  assert.equal(reset.ok, true);
  assert.equal(s.calls("agents.managed.reset").length, 1);
  setAlertListener(null);
});

// ------------------------------------------------------------------------------------------- status: model is advisory
test("status: the live model against the advisory setting, with the PATCH for the board; the declared routine schedules", async () => {
  const s = setup();
  await s.activate();
  let st = await s.itsec.status(HOST);
  assert.equal(st.liveModel, DEFAULT_ITSEC_MODEL);
  assert.equal(st.modelPatch, null);
  s.settings.itsecModel = "claude-opus-5-5";
  st = await s.itsec.status(HOST);
  assert.deepEqual(st.modelPatch.body, { adapterConfig: { model: "claude-opus-5-5" } });
  assert.equal(st.modelPatch.path, `/api/agents/${s.agentOf(HOST).id}`);
  assert.match(st.modelPatch.note, /Not applied/);
  // routines.managed.get returns no triggers: the page gets the DECLARED schedule, never a live one.
  assert.deepEqual(st.routines.find((r) => r.key === DAILY_ROUTINE_KEY).declared, [{ kind: "schedule", cron: "0 7 * * *", timezone: "UTC" }]);
  assert.deepEqual(st.routines.find((r) => r.key === TRIAGE_ROUTINE_KEY).declared, []);
  assert.ok(st.routines.every((r) => !("triggers" in r)));
  // The board changed the model itself: the live value is read, not trusted from the setting.
  s.agentOf(HOST).adapterConfig.model = "claude-opus-5-5";
  assert.equal((await s.itsec.status(HOST)).modelPatch, null);
  // Another company gets no agent details.
  const o = await s.itsec.status(OTHER);
  assert.equal(o.here, false);
  assert.equal(o.agent, undefined);
  // An alert company that is not the host company is a visible warning.
  s.settings.alertCompanyId = OTHER;
  assert.match((await s.itsec.status(HOST)).warnings[0], /different company/);
});

// ------------------------------------------------------------------------------------------- triage nudge
test("nudge: an alert above low priority in the host company starts triage once; two alerts within 30 minutes make one run", async () => {
  const s = setup();
  await s.activate();
  const pending = [];
  setAlertListener((a) => { const p = s.itsec.onAlert(a); pending.push(p); return p; }); // the alert does not wait for it
  try {
    const raise = async (priority, companyId = HOST) => { const r = await raiseAlertIssue({ ctx: { ...s.ctx, issues: { ...s.ctx.issues, create: async (i) => s.ctx.issues.create({ ...i, companyId }) } }, settings: { alertCompanyId: companyId }, title: `a ${priority}`, description: "d", priority, now: () => s.clock.t }); await Promise.all(pending); return r; };
    await raise("high");
    assert.equal(s.calls("routines.managed.run").length, 1);
    assert.deepEqual(s.calls("routines.managed.run")[0].slice(1), [TRIAGE_ROUTINE_KEY, HOST]);
    s.clock.t += 10 * MIN;
    await raise("critical");
    assert.equal(s.calls("routines.managed.run").length, 1, "debounced: less than 30 minutes");
    s.clock.t += 21 * MIN;
    await raise("medium");
    assert.equal(s.calls("routines.managed.run").length, 2, "30 minutes passed");
  } finally { setAlertListener(null); }
});

test("nudge: a low-priority alert, an alert elsewhere, a paused agent and a failing run start nothing or fail quietly", async () => {
  const s = setup();
  await s.activate();
  assert.deepEqual(await s.itsec.onAlert({ companyId: HOST, priority: "low" }), { run: false, reason: "priority is low" });
  assert.equal((await s.itsec.onAlert({ companyId: OTHER, priority: "critical" })).run, false);
  assert.equal(s.calls("routines.managed.run").length, 0);
  // A failing run is logged, does not throw, and does not start the debounce window.
  s.world.failRun = true;
  const failed = await s.itsec.onAlert({ companyId: HOST, priority: "high" });
  assert.equal(failed.run, false);
  assert.match(failed.reason, /not started/);
  s.world.failRun = false;
  assert.equal((await s.itsec.onAlert({ companyId: HOST, priority: "high" })).run, true);
  // A drifted (paused) agent is never nudged.
  const d = setup();
  await d.activate();
  d.agentOf(HOST).adapterConfig.networkScope = "none";
  await d.itsec.verify(HOST);
  assert.equal((await d.itsec.onAlert({ companyId: HOST, priority: "critical" })).run, false);
  assert.equal(d.calls("routines.managed.run").length, 0);
  // The drift alert itself (raised while verify holds the queue) cannot deadlock the listener.
  assert.equal(d.world.alerts.length, 1);
});

test("alert listener failure never fails the alert", async () => {
  setAlertListener(() => { throw new Error("listener broke"); });
  try {
    const created = [];
    const ctx = { issues: { create: async (i) => { created.push(i); return { id: "i1", identifier: "X-1" }; } }, state: { get: async () => null, set: async () => {} }, activity: { log: async () => {} }, logger: { warn() {}, info() {} } };
    const r = await raiseAlertIssue({ ctx, settings: { alertCompanyId: "c" }, title: "t", description: "d", priority: "high" });
    assert.equal(r.ok, true);
    assert.equal(created.length, 1);
    assert.equal(created[0].originKind, undefined, "left to the host: plugin:<id>");
  } finally { setAlertListener(null); }
});

test("alert listener runs fire and forget: a slow one does not delay the alert, a rejecting one is only logged", async () => {
  const mkCtx = (warns) => ({ issues: { create: async () => ({ id: "i1", identifier: "X-1" }) }, state: { get: async () => null, set: async () => {} }, activity: { log: async () => {} }, logger: { warn: (m) => warns.push(m), info() {} } });
  let release;
  const gate = new Promise((r) => { release = r; });
  let started = false;
  setAlertListener(async () => { started = true; await gate; });
  try {
    const r = await raiseAlertIssue({ ctx: mkCtx([]), settings: { alertCompanyId: "c" }, title: "t", description: "d", priority: "high" });
    assert.equal(r.ok, true, "returned while the listener is still waiting");
    assert.equal(started, true);
  } finally { release(); setAlertListener(null); }
  const warns = [];
  setAlertListener(async () => { throw new Error("async listener broke"); });
  try {
    const r = await raiseAlertIssue({ ctx: mkCtx(warns), settings: { alertCompanyId: "c" }, title: "t", description: "d", priority: "high" });
    assert.equal(r.ok, true);
    await new Promise((res) => setImmediate(res));
    assert.ok(warns.some((m) => /alert listener failed: async listener broke/.test(m)));
  } finally { setAlertListener(null); }
});

// ------------------------------------------------------------------------------------------- safety net
test("safety net: the issue list is asked for open alerts only, so many old closed alerts do not hide an open one", async () => {
  const s = setup();
  await s.activate();
  for (let i = 0; i < 120; i += 1) s.addAlert(`old-${i}`, { status: i % 2 ? "done" : "cancelled" });
  s.addAlert("al-open");
  const r = await s.itsec.sweep(HOST);
  assert.deepEqual(r.untriaged, ["al-open"]);
  const asked = s.calls("issues.list").map((c) => c[1]).filter((q) => q.originKind === ALERT_ORIGIN).pop();
  assert.equal(asked.status, "backlog,todo,in_progress,in_review,blocked");
  assert.ok(!asked.status.includes("done") && !asked.status.includes("cancelled"));
});

test("safety net: no untriaged alert means no agent run; an open alert without an ITSec comment starts triage; a comment ends it", async () => {
  const s = setup();
  await s.activate();
  // Nothing open: no run. A closed alert, a low-priority one, the status issue and another agent's alert comments do not count.
  assert.equal((await s.itsec.sweep(HOST)).run, false);
  s.addAlert("al-closed", { status: "done" });
  s.addAlert("al-low", { priority: "low" });
  const none = await s.itsec.sweep(HOST);
  assert.equal(none.run, false);
  assert.deepEqual(none.untriaged, []);
  assert.equal(s.calls("routines.managed.run").length, 0);
  // A job run with nothing to triage starts nothing either.
  const job = await s.itsec.runJob();
  assert.equal(job.sweep.run, false);
  assert.equal(s.calls("routines.managed.run").length, 0);
  // An untriaged alert (a comment by somebody else does not count).
  s.addAlert("al-1");
  s.world.comments.set("al-1", [{ id: "c1", authorUserId: "u-1", authorAgentId: null, body: "looking" }]);
  const r = await s.itsec.sweep(HOST);
  assert.equal(r.run, true);
  assert.deepEqual(r.untriaged, ["al-1"]);
  assert.equal(s.calls("routines.managed.run").length, 1);
  // The ITSec agent commented: triaged, nothing more.
  s.clock.t += 31 * MIN;
  s.world.comments.set("al-1", [{ id: "c2", authorAgentId: s.agentOf(HOST).id, body: "verdict" }]);
  const done = await s.itsec.sweep(HOST);
  assert.equal(done.run, false);
  assert.equal(s.calls("routines.managed.run").length, 1);
});

test("safety net: respects the 30-minute debounce, and gives up on an alert after three tries without a verdict", async () => {
  const s = setup();
  await s.activate();
  s.addAlert("al-1");
  assert.equal((await s.itsec.sweep(HOST)).run, true);
  s.clock.t += 10 * MIN;
  const early = await s.itsec.sweep(HOST);
  assert.equal(early.run, false);
  assert.match(early.reason, /debounced/);
  for (let i = 0; i < MAX_SWEEP_ATTEMPTS - 1; i += 1) { s.clock.t += NUDGE_DEBOUNCE_MS + MIN; assert.equal((await s.itsec.sweep(HOST)).run, true); }
  assert.equal(s.calls("routines.managed.run").length, MAX_SWEEP_ATTEMPTS);
  s.clock.t += NUDGE_DEBOUNCE_MS + MIN;
  const stop = await s.itsec.sweep(HOST);
  assert.equal(stop.run, false);
  assert.match(stop.reason, /retried too often/);
  assert.equal(s.calls("routines.managed.run").length, MAX_SWEEP_ATTEMPTS);
  assert.equal((await s.itsec.status(HOST)).state.untriaged, 1, "still shown on the page");
});

test("safety net: an agent that is not active (not yet verified) is not nudged", async () => {
  const s = setup();
  s.world.failGrants = true;
  await s.itsec.ensure(HOST);
  s.addAlert("al-1");
  const r = await s.itsec.sweep(HOST);
  assert.equal(r.run, false);
  assert.match(r.reason, /not active/);
  assert.equal(s.calls("routines.managed.run").length, 0);
});

// ------------------------------------------------------------------------------------------- documents
test("status documents: the snapshot and the operator's notes live on one plugin status issue; a missing alert company is called out", async () => {
  const s = setup({ settings: { alertCompanyId: "", itsecContext: "Host label: lab-1\nKnowledge base project: kb" } });
  const r = await s.itsec.ensure(HOST);
  const status = s.world.docs.find((d) => d.key === "hardening-status");
  const context = s.world.docs.find((d) => d.key === "itsec-context");
  assert.equal(status.issueId, context.issueId);
  assert.equal(r.documents.issueId, status.issueId);
  assert.match(status.body, /Watchdog: on/);
  assert.match(status.body, /All 1 agents are compliant/);
  assert.match(context.body, /Host label: lab-1/);
  assert.match(context.body, /No alert company is configured/);
  // The status issue is not an alert: the safety net ignores it.
  assert.equal((await s.itsec.sweep(HOST)).run, false);
  assert.ok(await s.ctx.state.get(ITSEC_STATE_KEY(HOST)));
});

test("status document: lists every alert the ITSec agent closed (newest first, one line each), or says None", async () => {
  const s = setup();
  await s.itsec.ensure(HOST);
  assert.match(s.world.docs.findLast((d) => d.key === "hardening-status").body, /## Alerts closed by the ITSec agent\n\n[^\n]*\n\nNone\./);
  await s.ctx.state.set(ITSEC_CLOSED_KEY(HOST), [
    { issueId: "i-1", identifier: "ENG-1", title: "[Security hardening] Watchdog stopped", closedAt: "2026-10-18T10:00:00.000Z", resolution: "false alarm" },
    { issueId: "i-2", identifier: null, title: "[Security hardening] Self-test failed", closedAt: "2026-10-19T11:30:00.000Z", resolution: "line one\n## injected heading" },
  ]);
  await s.itsec.ensure(HOST);
  const body = s.world.docs.findLast((d) => d.key === "hardening-status").body;
  const section = body.split("## Alerts closed by the ITSec agent")[1].split("\n## ")[0];
  const items = section.split("\n").filter((l) => l.startsWith("- "));
  assert.deepEqual(items, [
    "- i-2: [Security hardening] Self-test failed. Closed 2026-10-19T11:30:00.000Z. Resolution: line one ## injected heading",
    "- ENG-1: [Security hardening] Watchdog stopped. Closed 2026-10-18T10:00:00.000Z. Resolution: false alarm",
  ]);
  assert.doesNotMatch(section, /\n## injected/, "the agent's text cannot start a heading");
});

// ------------------------------------------------------------------------------------------- documents on the real host
test("documents: a rewrite works on a host that needs baseRevisionId (which the SDK cannot pass): the document is deleted and created again", async () => {
  const s = setup();
  const first = await s.itsec.ensure(HOST);
  assert.deepEqual(first.documents.written.sort(), ["hardening-status", "itsec-context"]);
  const issueId = first.documents.issueId;
  assert.match(s.world.documents.get(`${issueId}:hardening-status`).body, /Last verification: compliant/);
  assert.equal(s.calls("documents.delete").length, 2, "a delete of a document that does not exist is a no-op for Paperclip");
  // Drift: the status document must follow (this is what froze at the first write on Paperclip 2026.1012.0).
  s.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  const again = await s.itsec.ensure(HOST);
  assert.equal(again.documents.error, undefined);
  assert.deepEqual(again.documents.written.sort(), ["hardening-status", "itsec-context"], "both documents are rewritten on every run");
  const body = s.world.documents.get(`${issueId}:hardening-status`).body;
  assert.match(body, /Last verification: drift/);
  assert.deepEqual(s.calls("documents.delete").map((c) => c[2]), ["hardening-status", "itsec-context", "hardening-status", "itsec-context"]);
  assert.equal([...s.world.documents.keys()].filter((k) => k.startsWith(issueId)).length, 2, "still two documents on the one status issue");
  // A changed operator note reaches the agent.
  s.settings.itsecContext = "host label: lab";
  await s.itsec.ensure(HOST);
  assert.match(s.world.documents.get(`${issueId}:itsec-context`).body, /host label: lab/);
});

test("documents: an itsec-context edited by someone on the status issue is put back at the next run, although the operator's note did not change", async () => {
  const s = setup({ settings: { itsecContext: "host label: lab" } });
  const first = await s.itsec.ensure(HOST);
  const key = `${first.documents.issueId}:itsec-context`;
  s.world.documents.get(key).body = "edited by hand";
  await s.itsec.ensure(HOST);
  assert.match(s.world.documents.get(key).body, /host label: lab/);
  s.world.documents.delete(`${first.documents.issueId}:hardening-status`);
  await s.itsec.ensure(HOST);
  assert.ok(s.world.documents.has(`${first.documents.issueId}:hardening-status`));
});

test("documents: a failed write is retried at the next check, also when the delete had worked; it never fails the ensure", async () => {
  const s = setup();
  const first = await s.itsec.ensure(HOST);
  const issueId = first.documents.issueId;
  s.settings.itsecContext = "host label: one";
  s.world.failDocUpsert = true; // the delete works, the create fails: the document is missing
  const r = await s.itsec.ensure(HOST);
  assert.equal(r.ok, true);
  assert.match(r.documents.error, /itsec-context: document store unavailable/);
  assert.equal(s.world.documents.has(`${issueId}:itsec-context`), false);
  s.world.failDocUpsert = false;
  const r2 = await s.itsec.ensure(HOST);
  assert.deepEqual(r2.documents.written.sort(), ["hardening-status", "itsec-context"]);
  assert.match(s.world.documents.get(`${issueId}:itsec-context`).body, /host label: one/);
  // The delete is refused (locked): the old document stays, the error is reported, the next check tries again.
  s.settings.itsecContext = "host label: two";
  s.world.failDocDelete = true;
  const r3 = await s.itsec.ensure(HOST);
  assert.match(r3.documents.error, /Document is locked/);
  assert.match(s.world.documents.get(`${issueId}:itsec-context`).body, /host label: one/);
  s.world.failDocDelete = false;
  assert.deepEqual((await s.itsec.ensure(HOST)).documents.written.sort(), ["hardening-status", "itsec-context"]);
});

// ------------------------------------------------------------------------------------------- company that requires board approval
/** Paperclip 2026.1012.0: creating a managed agent in such a company leaves a pending agent without instructions and throws. */
function pendingHost(s) {
  const orig = s.ctx.agents.managed.reconcile;
  s.ctx.agents.managed.reconcile = async (key, companyId) => {
    if (!s.agentOf(companyId)) {
      await orig(key, companyId);
      Object.assign(s.agentOf(companyId), { status: "pending_approval", pauseReason: null });
      s.world.needsInstructions = true;
      throw new Error("Pending approval agent configuration cannot be changed before board approval");
    }
    const r = await orig(key, companyId);
    return s.world.needsInstructions ? { ...r, defaultDrift: { entryFile: "AGENTS.md", changedFiles: ["AGENTS.md"] } } : r;
  };
  const reset = s.ctx.agents.managed.reset;
  s.ctx.agents.managed.reset = async (...a) => { s.world.needsInstructions = false; return reset(...a); };
}

test("a company that requires board approval: the half-created agent is adopted, the card says exactly what the board does, and the plugin finishes it after the approval", async () => {
  const s = setup();
  s.world.requireApproval = true;
  pendingHost(s);
  // Before anything exists the card already warns.
  assert.match((await s.itsec.status(HOST)).attention.join(), /requires board approval for new agents.*approves the agent itself/);
  const r = await s.itsec.ensure(HOST);
  assert.equal(r.ok, false);
  const id = s.agentOf(HOST).id;
  assert.match(r.error, new RegExp(`approve the agent itself in Paperclip \\(agent page, Approve; or POST /api/agents/${id}/approve\\)`));
  assert.match(r.error, /made no hire approval/);
  assert.equal(r.hint, null);
  assert.equal(r.verify.state, "pending_approval");
  assert.equal(s.world.routines.size, 0, "no routine is assigned to a pending agent");
  assert.equal(s.calls("agents.resume").length, 0);
  const st = await s.itsec.status(HOST);
  assert.equal(st.agent.status, "pending_approval");
  assert.deepEqual(st.attention.filter((t) => t.includes(`/api/agents/${id}/approve`)).length, 1);
  assert.equal(st.state.awaitingApproval, true);
  // The 15-minute job keeps saying so and creates nothing else.
  const job = await s.itsec.runJob();
  assert.equal(job.ensure.ok, false);
  assert.equal(s.world.agents.size, 1);
  assert.equal(s.world.routines.size, 0);
  // The board approves the agent (Paperclip activates it).
  s.agentOf(HOST).status = "idle";
  const done = await s.itsec.ensure(HOST);
  assert.equal(done.ok, true, done.error);
  assert.equal(s.calls("agents.managed.reset").length, 1, "the declared instructions are written once");
  assert.ok(s.world.logs.some((l) => /approved by the board; the plugin wrote its declared instructions/.test(l.message)));
  assert.equal(done.verify.state, "active");
  assert.deepEqual([...s.world.routines.values()].map((x) => x.status), ["active", "active"]);
  assert.equal((await s.itsec.status(HOST)).state.awaitingApproval, false);
  await s.itsec.ensure(HOST);
  assert.equal(s.calls("agents.managed.reset").length, 1, "no second reset");
});

test("a host that does create the hire approval: the card points at the approval, the agent is not reset afterwards", async () => {
  const s = setup();
  s.world.requireApproval = true;
  const orig = s.ctx.agents.managed.reconcile;
  s.ctx.agents.managed.reconcile = async (key, companyId) => {
    const r = await orig(key, companyId);
    if (r.status === "created") Object.assign(s.agentOf(companyId), { status: "pending_approval", pauseReason: null });
    const a = structuredClone(s.agentOf(companyId));
    return { ...r, agent: a, approvalId: "ap-1" };
  };
  const r = await s.itsec.ensure(HOST);
  assert.equal(r.ok, false);
  assert.match(r.error, /hire approval is waiting.*Approve it in Paperclip/);
  s.agentOf(HOST).status = "idle";
  assert.equal((await s.itsec.ensure(HOST)).ok, true);
  assert.equal(s.calls("agents.managed.reset").length, 0);
});

test("status: who paused the agent decides what the card tells the board", async () => {
  const s = setup();
  await s.activate();
  await s.ctx.agents.pause(s.agentOf(HOST).id, HOST);
  assert.match((await s.itsec.status(HOST)).attention.join(), /not by the plugin/);
  const t = setup();
  t.agentOf(HOST);
  await t.itsec.ensure(HOST);
  t.agentOf(HOST).adapterConfig.networkAllowlist.push("*:443");
  await t.itsec.verify(HOST);
  assert.match((await t.itsec.status(HOST)).attention.join(), /resumes the agent and switches the routines on by itself/);
});

test("the retire watcher keeps the context of the code that started it, not of the request that woke it (Paperclip carries a request's scope through AsyncLocalStorage)", async () => {
  const { AsyncLocalStorage } = await import("node:async_hooks");
  const als = new AsyncLocalStorage();
  const s = setup({ settings: { itsecHostCompanyId: "a-co" } });
  await s.itsec.ensure("a-co");
  const seen = [];
  const realPause = s.ctx.agents.pause;
  s.ctx.agents.pause = async (...a) => { seen.push(als.getStore() ?? null); return realPause(...a); };
  const watcher = s.itsec.startRetireWatcher({ sleep: async () => {}, delaysMs: [1] }); // started outside any request, like the worker's setup()
  const prev = structuredClone(s.settings);
  s.settings.itsecHostCompanyId = "b-co";
  await als.run({ invocationId: "request-of-b" }, () => s.itsec.applyChange(prev, structuredClone(s.settings), "b-co"));
  await watcher.idle();
  await watcher.stop();
  assert.deepEqual(seen, [null], "the pause ran outside the request's context");
  assert.equal(s.agentOf("a-co").status, "paused");
  // And the worker starts it in setup().
  assert.match(fs.readFileSync(path.join(SRC, "worker.js"), "utf8"), /services\.it\.startRetireWatcher\?\.\(\)/);
});
