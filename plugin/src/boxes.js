// The Agent boxes page's backend (plan step 3): one row per agent that exists in the picked company, read fresh from
// Paperclip at every refresh, with its box, hosts, read-only paths, permissions, status and daily cap. Replaces the
// per-agent overlay scripts people used to run by hand (role hosts, open-web detection, the public-web XOR check,
// never writing REDACTED values). No SDK
// imports: the plugin context (`ctx`) is passed in, so tests use a fake one.
//
// Where the box values come from. Paperclip shows allowlist hosts as "***REDACTED***", so a value read back from the
// API is never written anywhere. The plugin keeps its own per-agent box settings (company state "agent-boxes":
// mode allowlist | public-web, extra hosts, extra read-only paths). The full lists are always built from those plus
// the hardening settings' base allowlist and base read-only paths (step 2), never from what Paperclip returned.
//
// Applying. The plugin SDK of this Paperclip (2026.1012) has NO agent update capability (ctx.agents offers list, get,
// pause, resume, invoke, managed, sessions; nothing writes adapterConfig). So the box values in Paperclip are
// read-only for the plugin: saving stores the plugin-side settings and returns the exact PATCH body an admin applies
// by hand (PATCH /api/agents/:id). `applyBox` is the seam for a future SDK capability; the worker passes none.
//
// Permissions. tasks:assign and pipelines:write are grant rows, read with authorization.grants.read. The plugin does
// not set grants (least privilege; granting stays board-only, patch 0009), so "public web + tasks:assign" is refused
// when the box is edited and flagged on the row when the grant came from elsewhere.
import { validHost, validPath } from "./settings.js";
import { NotAllowedError } from "./hardening.js";
import { BOXED_TYPES, checkAgent, envRedirects, hasRemoteException, listAgents } from "./logic.js";
import { defaultHostsFor, isExceptionableType, profileFor } from "./profiles.js";
import { PLUGIN_ID } from "./manifest.js";

export const PUBLIC_WEB = Object.freeze(["*:443", "*:80"]);
/** Paperclip's own default when the hardening settings have no base allowlist (patch 0005a). */
export const DEFAULT_BASE_ALLOWLIST = Object.freeze(["api.anthropic.com"]);
export const REDACTED = "***REDACTED***";
const REDACTED_RE = /REDACTED/i;
export const BOXES_KEY = (companyId) => ({ scopeKind: "company", scopeId: String(companyId), stateKey: "agent-boxes" });
const isBoxed = (type) => BOXED_TYPES.includes(type);
const MAX_LIST = 64;
export const APPLY_UNSUPPORTED =
  "Not applied: this Paperclip's plugin SDK has no capability to change an agent's adapter configuration. Apply the PATCH shown (board UI or API); the plugin keeps these values as the source of truth.";

const plain = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
const dedupe = (list) => [...new Set(list)];
const isHidden = (v) => typeof v !== "string" || REDACTED_RE.test(v);

/** Throws if any string anywhere in `value` is a redacted placeholder (a body must never carry one). */
export function assertNoRedacted(value, where = "body") {
  const walk = (v) => {
    if (typeof v === "string") { if (REDACTED_RE.test(v)) throw new Error(`internal error: ${where} contains ${REDACTED}; a write must never be built from data Paperclip returned`); }
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v).forEach(walk);
  };
  walk(value);
  return value;
}

/**
 * Where an agent's adapter type stands in this version: boxed (claude_local, opencode_local), hermes-wrapper,
 * exception-needed / excepted (remote and generic types: refused unless listed under remote exceptions), later-version
 * (the other local types: planned) or unsupported (anything else: always refused).
 */
export function typeState(agent, cfg = {}) {
  const type = String(agent?.adapterType ?? "");
  if (isBoxed(type)) return { state: "boxed", note: null };
  if (type === "hermes_local") return { state: "hermes-wrapper", note: null };
  if (isExceptionableType(type))
    return hasRemoteException(agent, cfg) ? { state: "excepted", note: "runs outside the box under a remote exception" } : { state: "exception-needed", note: "needs a remote exception" };
  if (profileFor(type)?.scopes) return { state: "later-version", note: "planned for a later version; the server refuses to run it" };
  return { state: "unsupported", note: "not supported; the server refuses to run it" };
}

/** Open web: no network scope (host network) or a public-web wildcard entry. */
export function currentBox(agent, { hermesWrapperPath = "", remoteExceptions = [] } = {}) {
  const site = { remoteExceptions };
  const type = String(agent?.adapterType ?? "");
  const cfg = plain(agent?.adapterConfig);
  if (type === "hermes_local") {
    const want = hermesWrapperPath || "/usr/local/bin/hermes-sandbox";
    return cfg.command === want ? { kind: "hermes-wrapper", hosts: [], hiddenHosts: 0, paths: [], hiddenPaths: 0, red: false }
      : { kind: "none", hosts: [], hiddenHosts: 0, paths: [], hiddenPaths: 0, red: true, note: "Hermes without the sandbox wrapper" };
  }
  if (!isBoxed(type)) {
    const t = typeState(agent, site);
    return { kind: "unsupported", hosts: [], hiddenHosts: 0, paths: [], hiddenPaths: 0, red: t.state !== "excepted", note: `${type || "this adapter"}: ${t.note}` };
  }
  const list = Array.isArray(cfg.networkAllowlist) ? cfg.networkAllowlist : [];
  const plist = Array.isArray(cfg.filesystemExtraPaths) ? cfg.filesystemExtraPaths : [];
  const hosts = list.filter((h) => !isHidden(h));
  const paths = plist.filter((p) => !isHidden(p));
  const base = { hosts, hiddenHosts: list.length - hosts.length, paths, hiddenPaths: plist.length - paths.length };
  if (cfg.networkScope !== "allowlist") return { ...base, kind: "none", red: true, note: "NONE: host network" };
  if (hosts.some((h) => h.startsWith("*:"))) return { ...base, kind: "public-web", red: false };
  if (base.hiddenHosts) return { ...base, kind: "hidden", red: false, note: `${base.hiddenHosts} host(s) hidden by Paperclip` };
  return { ...base, kind: "allowlist", red: false };
}

/**
 * The PATCH body that brings a boxable agent's stored config to what the server admits: only the keys that are wrong
 * (null when none is). The allowlist comes from `hosts` (the plugin's lists), never from what Paperclip returned.
 * Env redirects the server drops are listed by name, not rebuilt: the stored env cannot be read back safely.
 */
export function fixBody(agent, hosts) {
  const type = String(agent?.adapterType ?? "");
  if (!isBoxed(type)) return null;
  const a = plain(agent.adapterConfig);
  const fix = {};
  if (a.filesystemScope !== "workspace") fix.filesystemScope = "workspace";
  if (typeof a.filesystemSandboxCommand !== "string" || !a.filesystemSandboxCommand.startsWith("/")) fix.filesystemSandboxCommand = "/usr/bin/bwrap"; // both boxed types: the box helper runs this command
  if (profileFor(type).engineCli && a.engine !== "cli") fix.engine = "cli";
  const list = Array.isArray(a.networkAllowlist) ? a.networkAllowlist : null;
  if (a.networkScope !== "allowlist" || !list || !list.length || list.some((h) => !isHidden(h) && h.includes("*"))) {
    fix.networkScope = "allowlist";
    fix.networkAllowlist = hosts;
  }
  return Object.keys(fix).length ? assertNoRedacted({ adapterConfig: fix }, "fix PATCH") : null;
}

/** Grant rows (authorization.grants.list) -> {agentId: Set(permissionKey)}; null when grants could not be read. */
export function grantsByAgent(rows) {
  if (!Array.isArray(rows)) return null;
  const out = {};
  for (const g of rows) {
    if (g?.principalType !== "agent" || !g.principalId || typeof g.permissionKey !== "string") continue;
    (out[g.principalId] ??= new Set()).add(g.permissionKey);
  }
  return out;
}

/**
 * The four permissions the page shows. tasksAssign: true (explicit grant), "derived" (CEO role or canCreateAgents,
 * which Paperclip turns into assign rights unless "Assigning work needs a grant" is on), false, or null (unknown).
 */
export function permissionsOf(agent, grants) {
  const perms = plain(agent?.permissions);
  const own = grants ? grants[agent.id] ?? new Set() : null;
  const derived = agent?.role === "ceo" || perms.canCreateAgents === true;
  return {
    canCreateAgents: perms.canCreateAgents === true,
    canCreateSkills: perms.canCreateSkills === true,
    tasksAssign: own === null ? (derived ? "derived" : null) : own.has("tasks:assign") ? true : derived ? "derived" : false,
    pipelinesWrite: own === null ? null : own.has("pipelines:write"),
  };
}

/** XOR rule: public web and tasks:assign never together. Unknown grants count as held (fail closed). */
export const holdsAssign = (p) => p.tasksAssign !== false;

export function normalizeBoxInput(input = {}) {
  const src = plain(input);
  const errors = [];
  const mode = src.mode === "public-web" || src.mode === "allowlist" ? src.mode : null;
  if (!mode) errors.push("mode: must be allowlist or public-web");
  const list = (key, valid, msg) => {
    const raw = typeof src[key] === "string" ? src[key].split(/[\n,]/) : Array.isArray(src[key]) ? src[key] : src[key] == null ? [] : null;
    if (!raw) { errors.push(`${key}: must be a list`); return []; }
    const items = raw.map((v) => (typeof v === "string" ? v.trim() : v)).filter((v) => v !== "");
    const bad = items.filter((v) => typeof v !== "string" || isHidden(v) || !valid(v));
    if (bad.length) errors.push(`${key}: ${msg}: ${bad.map(String).join(", ")}`);
    const clean = dedupe(items.filter((v) => !bad.includes(v)));
    if (clean.length > MAX_LIST) errors.push(`${key}: at most ${MAX_LIST} entries`);
    return clean.slice(0, MAX_LIST);
  };
  const extraHosts = list("extraHosts", validHost, "not a host or host:port (no wildcards; public web is a box mode)");
  const extraPaths = list("extraPaths", validPath, "not an absolute path (no commas, colons or ..)").map((p) => p.replace(/(.)\/+$/, "$1"));
  return { box: { mode: mode ?? "allowlist", extraHosts, extraPaths }, errors };
}

/** The base lists a new agent of the type starts with: claude_local keeps `baseAllowlist`, the other boxed types use `baseAllowlists[type]`, then the profile's default hosts. */
export function effectiveBase(settings = {}, type = "claude_local") {
  const own = type === "claude_local" ? settings.baseAllowlist : settings.baseAllowlists?.[type];
  const hosts = Array.isArray(own) && own.length ? own : type === "claude_local" ? DEFAULT_BASE_ALLOWLIST : defaultHostsFor(type);
  const paths = Array.isArray(settings.extraReadOnlyPaths) ? settings.extraReadOnlyPaths : [];
  return { hosts: [...hosts], paths: [...paths] };
}

/**
 * The PATCH body for an agent's box: full lists from the plugin's stored settings plus the base settings. Never built
 * from a value Paperclip returned; checked for redacted placeholders before it leaves this function.
 */
export function buildBoxPatch(stored, settings, type = "claude_local") {
  const { box, errors } = normalizeBoxInput(stored);
  if (errors.length) throw new Error(`stored box settings are invalid: ${errors.join("; ")}`);
  const base = effectiveBase(settings, type);
  const networkAllowlist = dedupe([...base.hosts, ...box.extraHosts, ...(box.mode === "public-web" ? PUBLIC_WEB : [])]);
  const filesystemExtraPaths = dedupe([...base.paths, ...box.extraPaths]);
  return assertNoRedacted({ adapterConfig: { networkScope: "allowlist", networkAllowlist, filesystemExtraPaths } }, "box PATCH");
}

/** Plugin-side settings taken from an agent's current state (only what is visible; redacted entries are lost). */
export function takeOverFrom(agent, settings) {
  const cur = currentBox(agent);
  const base = effectiveBase(settings, String(agent?.adapterType));
  const notes = [];
  const extraHosts = cur.hosts.filter((h) => !h.startsWith("*:") && !base.hosts.includes(h));
  const badHosts = extraHosts.filter((h) => !validHost(h));
  const extraPaths = cur.paths.filter((p) => !base.paths.includes(p));
  const badPaths = extraPaths.filter((p) => !validPath(p));
  if (cur.kind === "none") notes.push("it ran on the host network (NONE); the plugin's box is an allowlist");
  if (cur.hiddenHosts) notes.push(`${cur.hiddenHosts} allowlist host(s) are hidden by Paperclip and could not be taken over; add them as extra hosts`);
  if (cur.hiddenPaths) notes.push(`${cur.hiddenPaths} read-only path(s) are hidden by Paperclip and could not be taken over`);
  if (badHosts.length) notes.push(`left out (not a plain host): ${badHosts.join(", ")}`);
  if (badPaths.length) notes.push(`left out (not a valid path): ${badPaths.join(", ")}`);
  return {
    box: { mode: cur.kind === "public-web" ? "public-web" : "allowlist", extraHosts: extraHosts.filter((h) => !badHosts.includes(h)), extraPaths: extraPaths.filter((p) => !badPaths.includes(p)) },
    notes,
  };
}

/** Does Paperclip's current box match the plugin's? in-sync | differs | unverifiable (hosts hidden by Paperclip). */
export function syncState(agent, patch) {
  const cur = currentBox(agent);
  const want = patch.adapterConfig;
  if (cur.kind === "none" || cur.kind === "unsupported") return "differs";
  const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x));
  const cfg = plain(agent.adapterConfig);
  const curPaths = Array.isArray(cfg.filesystemExtraPaths) ? cfg.filesystemExtraPaths : [];
  if (!cur.hiddenPaths && !sameSet(curPaths, want.filesystemExtraPaths)) return "differs";
  const curHosts = Array.isArray(cfg.networkAllowlist) ? cfg.networkAllowlist : [];
  if (curHosts.length !== want.networkAllowlist.length) return "differs";
  if (cur.hosts.some((h) => !want.networkAllowlist.includes(h))) return "differs";
  return cur.hiddenHosts || cur.hiddenPaths ? "unverifiable" : "in-sync";
}

/**
 * Shared gate for the Agent boxes and caps actions. Users only (agents and system calls refused). Reading the page's
 * own company is open to its members; another company (`targetCompanyId`, the picker) and every write need an admin
 * (hardening.assertAdmin: a user listed in adminUserIds, or a company-less call the host limited to instance admins).
 * The host overwrites params.companyId with the caller's authorized company, so the picker uses targetCompanyId.
 */
export async function resolveTarget(assertAdmin, params, context, { write = false } = {}) {
  const actor = context?.actor ?? {};
  if (actor.type !== "user" || !actor.userId)
    throw new NotAllowedError(`only people can use the Agent boxes page (this request came from ${actor.type === "agent" ? "an agent" : "a non-user caller"})`);
  const own = actor.companyId ?? null;
  const t = typeof params?.targetCompanyId === "string" ? params.targetCompanyId.trim() : "";
  const companyId = t || own;
  if (!companyId) throw new Error("pick a company");
  if (!/^[A-Za-z0-9-]{1,64}$/.test(companyId)) throw new Error("invalid company id");
  if (write || companyId !== own) await assertAdmin(context);
  return { actor, companyId };
}

/**
 * @param {object} o
 * @param {object} o.ctx          plugin context (agents, authorization, state, activity, logger)
 * @param {Function} o.assertAdmin  hardening.assertAdmin
 * @param {Function} o.loadSettings hardening.loadSettings (base allowlist, base read-only paths, Hermes wrapper)
 * @param {Function} [o.applyBox]   (agent, patch, companyId) => Promise; none on this Paperclip (see header)
 * @param {Function} [o.capsView]   (companyId, agents) => caps per agent for the rows (from caps.js)
 */
export function createBoxes({ ctx, assertAdmin, loadSettings, applyBox = null, capsView = null }) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {} };
  let queue = Promise.resolve();
  const exclusive = (fn) => { const run = queue.then(fn, fn); queue = run.catch(() => {}); return run; };

  const loadStored = async (companyId) => plain(await ctx.state.get(BOXES_KEY(companyId)).catch(() => null));

  async function readGrants(companyId) {
    try { return grantsByAgent(await ctx.authorization.grants.list({ companyId, principalType: "agent" })); }
    catch (e) { log.warn(`agent grants not readable for company ${companyId}: ${e.message}`); return null; }
  }

  async function findAgent(companyId, agentId) {
    if (typeof agentId !== "string" || !agentId) throw new Error("agentId is required");
    const agent = await ctx.agents.get(agentId, companyId);
    if (!agent || String(agent.companyId ?? companyId) !== String(companyId)) throw new Error("agent not found in this company");
    return agent;
  }

  async function logActivity(companyId, message, metadata) {
    try { await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: PLUGIN_ID, metadata }); }
    catch (e) { log.warn(`activity log entry not written: ${e.message}`); }
  }

  function row(agent, { stored, grants, settings, caps, company }) {
    const cur = currentBox(agent, { hermesWrapperPath: settings.hermesWrapperPath, remoteExceptions: settings.remoteExceptions });
    const type = String(agent.adapterType ?? "");
    const perms = permissionsOf(agent, grants);
    const mine = stored[agent.id] ?? null;
    const cfg = plain(agent.adapterConfig);
    let patch = null, sync = null, error = null;
    if (mine) {
      try { patch = buildBoxPatch(mine, settings, type); sync = syncState(agent, patch); } catch (e) { error = e.message; }
    }
    const publicWeb = mine ? mine.mode === "public-web" : cur.kind === "public-web";
    const conflicts = [];
    if (publicWeb && perms.tasksAssign === true) conflicts.push("public web AND tasks:assign (XOR rule)");
    else if (publicWeb && perms.tasksAssign === "derived") conflicts.push("public web AND assign rights derived from role/canCreateAgents");
    if (cur.kind === "public-web" && !publicWeb) conflicts.push("Paperclip has public web, the plugin's box does not");
    const base = effectiveBase(settings, type);
    const state = typeState(agent, settings);
    // Paperclip returns allowlist hosts redacted; the page shows those as "hidden", so only a real wildcard is a finding here.
    const list = Array.isArray(cfg.networkAllowlist) ? cfg.networkAllowlist : [];
    const wildcard = list.some((h) => !isHidden(h) && h.includes("*"));
    const findings = checkAgent(agent, { ...company, remoteExceptions: settings.remoteExceptions, ...(settings.hermesWrapperPath ? { hermesWrapperPath: settings.hermesWrapperPath } : {}) })
      .filter((f) => wildcard || !/wildcard or redacted/.test(f));
    const fix = fixBody(agent, mine && patch ? patch.adapterConfig.networkAllowlist : base.hosts);
    return {
      id: String(agent.id), name: String(agent.name ?? ""), role: agent.role ?? null, status: String(agent.status ?? ""),
      adapterType: String(agent.adapterType ?? ""), model: typeof cfg.model === "string" ? cfg.model : "",
      boxable: isBoxed(type),
      typeState: state.state, typeNote: state.note,
      findings,
      fix, dropEnv: isBoxed(type) ? envRedirects(type, cfg) : [],
      current: cur,
      managed: Boolean(mine),
      plugin: mine ? { mode: mine.mode, extraHosts: mine.extraHosts, extraPaths: mine.extraPaths, updatedAt: mine.updatedAt ?? null, updatedBy: mine.updatedBy ?? null } : null,
      box: mine ? mine.mode : cur.kind,
      hosts: mine && patch ? patch.adapterConfig.networkAllowlist : cur.hosts,
      baseHosts: base.hosts,
      readOnlyPaths: mine && patch ? patch.adapterConfig.filesystemExtraPaths : cur.paths,
      basePaths: base.paths,
      patch, sync, error,
      permissions: perms,
      conflicts,
      red: cur.red || conflicts.length > 0,
      cap: caps?.[agent.id] ?? null,
    };
  }

  return {
    /** Rows for one company (fresh from Paperclip). Read gate: see resolveTarget. */
    async view(params = {}, context) {
      const { companyId } = await resolveTarget(assertAdmin, params, context);
      const [agents, grants, stored, settings, company] = await Promise.all([
        listAgents(ctx, companyId), readGrants(companyId), loadStored(companyId), loadSettings().catch(() => ({})),
        Promise.resolve(ctx.config?.get?.(companyId)).then((c) => plain(c), () => ({})),
      ]);
      const live = agents.filter((a) => a.status !== "terminated");
      const caps = capsView ? await capsView(companyId, live).catch((e) => { log.warn(`caps view failed: ${e.message}`); return null; }) : null;
      let canEdit = false;
      try { await assertAdmin(context); canEdit = true; } catch { canEdit = false; }
      return {
        companyId, checkedAt: new Date().toISOString(), canEdit, grantsReadable: grants !== null,
        applySupported: typeof applyBox === "function", applyNote: typeof applyBox === "function" ? null : APPLY_UNSUPPORTED,
        rows: live.map((a) => row(a, { stored, grants, settings, caps: caps?.agents ?? null, company })),
        caps: caps ? { ...caps, agents: undefined } : null,
      };
    },

    /** Store the plugin-side settings from the agent's current state (admin). */
    takeOver(params = {}, context) {
      return exclusive(async () => {
        const { actor, companyId } = await resolveTarget(assertAdmin, params, context, { write: true });
        const agent = await findAgent(companyId, params.agentId);
        if (!isBoxed(agent.adapterType)) return { ok: false, error: `${agent.adapterType} agents have no box the plugin can manage` };
        const stored = await loadStored(companyId);
        if (stored[agent.id]) return { ok: false, error: "this agent's box is already managed by the plugin" };
        const settings = await loadSettings();
        const { box, notes } = takeOverFrom(agent, settings);
        stored[agent.id] = { ...box, updatedAt: new Date().toISOString(), updatedBy: actor.userId, takenOver: true };
        await ctx.state.set(BOXES_KEY(companyId), stored);
        await logActivity(companyId, `Agent boxes: ${agent.name} taken over by the plugin`, { agentId: agent.id, userId: actor.userId, box, notes });
        return { ok: true, box, notes };
      });
    },

    /**
     * Edit a managed agent's box (admin): mode allowlist | public-web, extra hosts, extra read-only paths. Refuses
     * public web for an agent holding (or possibly holding) tasks:assign. Sends the full lists, never REDACTED.
     */
    saveBox(params = {}, context) {
      return exclusive(async () => {
        const { actor, companyId } = await resolveTarget(assertAdmin, params, context, { write: true });
        const agent = await findAgent(companyId, params.agentId);
        if (!isBoxed(agent.adapterType)) return { ok: false, error: `${agent.adapterType} agents have no box the plugin can manage` };
        const stored = await loadStored(companyId);
        if (!stored[agent.id]) return { ok: false, error: "take this agent over first (its current state becomes the plugin's settings)" };
        const { box, errors } = normalizeBoxInput(params);
        if (errors.length) return { ok: false, errors };
        if (box.mode === "public-web") {
          const perms = permissionsOf(agent, await readGrants(companyId));
          if (holdsAssign(perms))
            return { ok: false, refused: "xor", error: perms.tasksAssign === null
              ? "public web refused: the agent's grants cannot be read, so tasks:assign cannot be ruled out"
              : `public web refused: ${agent.name} ${perms.tasksAssign === true ? "holds tasks:assign" : "may assign work (CEO role or canCreateAgents)"}; an agent may have public web or assign work, never both` };
        }
        const settings = await loadSettings();
        const patch = buildBoxPatch(box, settings, agent.adapterType);
        stored[agent.id] = { ...box, updatedAt: new Date().toISOString(), updatedBy: actor.userId };
        await ctx.state.set(BOXES_KEY(companyId), stored);
        let applied = false, applyError = null;
        if (typeof applyBox === "function") {
          try { await applyBox(agent, assertNoRedacted(structuredClone(patch), "box PATCH"), companyId); applied = true; }
          catch (e) { applyError = e.message; }
        }
        await logActivity(companyId, `Agent boxes: ${agent.name} box set to ${box.mode}${applied ? " and applied" : " (plugin settings; apply by hand)"}`,
          { agentId: agent.id, userId: actor.userId, box, applied, applyError });
        return { ok: true, box, patch, applied, applyError, note: typeof applyBox === "function" ? null : APPLY_UNSUPPORTED, method: "PATCH", path: `/api/agents/${agent.id}` };
      });
    },
  };
}
