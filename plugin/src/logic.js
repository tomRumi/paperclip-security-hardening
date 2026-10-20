// Pure compliance logic (no SDK imports). Mirrors what host/patches enforce server-side, so drift is visible even if a
// patch silently stopped applying (the watchdog covers file tampering; this covers the resulting agent configuration).
const DANGEROUS_KEYS = ["dangerouslySkipPermissions", "dangerouslyBypassApprovalsAndSandbox", "dangerouslyBypassSandbox", "yolo", "alwaysApprove", "chrome"];

const plain = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});

/** -> array of finding strings (empty = compliant). */
export function checkAgent(agent, cfg = {}) {
  const f = [];
  const type = String(agent?.adapterType ?? "");
  const a = plain(agent?.adapterConfig);
  const name = String(agent?.name ?? "");
  const perms = plain(agent?.permissions);
  if (agent?.status === "terminated") return f;
  if (perms.canCreateAgents === true && !(cfg.canCreateAgentsAllowed ?? []).includes(name)) f.push("canCreateAgents is true");
  if (perms.canCreateSkills === true) f.push("canCreateSkills is true");
  if (type.endsWith("_local")) {
    let boxed = false; // claude_local only: every sandbox check below passed
    if (type === "claude_local") {
      const before = f.length;
      if (a.filesystemScope !== "workspace") f.push("filesystemScope is not 'workspace'");
      if (typeof a.filesystemSandboxCommand !== "string" || !a.filesystemSandboxCommand.startsWith("/")) f.push("filesystemSandboxCommand is not an absolute path");
      const open = (cfg.openNetworkAgentNames ?? []).includes(name);
      if (a.networkScope !== "allowlist" && !open) f.push("networkScope is not 'allowlist'");
      if (a.networkScope === "allowlist" && (!Array.isArray(a.networkAllowlist) || a.networkAllowlist.length === 0)) f.push("networkAllowlist is empty");
      if (Array.isArray(a.networkAllowlist) && a.networkAllowlist.some((h) => typeof h !== "string" || h.includes("*") || /REDACTED/i.test(h))) f.push("networkAllowlist contains a wildcard or redacted entry");
      boxed = f.length === before;
    } else if (type === "hermes_local") {
      const want = cfg.hermesWrapperPath ?? "/usr/local/bin/hermes-sandbox";
      if (a.command !== want) f.push("command is not the sandbox wrapper " + want);
    } else {
      f.push("adapter type " + type + " has no sandbox support (the fail-closed patch refuses to run it)");
    }
    // Skip-permissions is the claude_local adapter's headless mode (without it `claude -p` refuses Bash and MCP tools) and
    // its default for an unset key is true. It is acceptable only inside the box above (true or unset); on an unboxed
    // agent every tool runs on the host without approval. Other adapters have no such mode: the key is unsafe wherever true.
    const skipKey = type === "claude_local" ? "dangerouslySkipPermissions" : null;
    for (const k of DANGEROUS_KEYS) if (a[k] === true && k !== skipKey) f.push(k + " is enabled");
    if (skipKey && !boxed && a[skipKey] !== false)
      f.push(a[skipKey] === true ? "dangerouslySkipPermissions is enabled on an agent that is not boxed" : "dangerouslySkipPermissions is unset (the adapter's default is true) on an agent that is not boxed");
  }
  return f;
}

export function checkAgents(agents, cfg = {}) {
  const results = [];
  for (const ag of agents) {
    const findings = checkAgent(ag, cfg);
    results.push({ id: String(ag.id), name: String(ag.name ?? ""), adapterType: String(ag.adapterType ?? ""), compliant: findings.length === 0, findings });
  }
  return results;
}

export function signature(results) {
  return results.filter((r) => !r.compliant).map((r) => r.id + ":" + r.findings.join("|")).sort().join(";");
}

/** Every agent of a company (paged; ctx.agents.list returns at most `limit`). */
export async function listAgents(ctx, companyId) {
  const out = [];
  for (let offset = 0; ; offset += 200) {
    const page = await ctx.agents.list({ companyId, limit: 200, offset });
    out.push(...page);
    if (page.length < 200) return out;
  }
}

/** How long the host keeps a delivered event's company scope registered (plugin-worker-manager MAX_RPC_TIMEOUT_MS). */
export const EVENT_SCOPE_HOLD_MS = 15 * 60_000;
/** Instance state: the ids of the companies the plugin has seen ({ids}); used when `companies.list` is refused or known to be. */
export const KNOWN_COMPANIES_KEY = Object.freeze({ scopeKind: "instance", stateKey: "known-companies" });
const SCOPE_REFUSED = /invocation scope/i;
const rememberedIds = new WeakMap(); // ctx -> ids already stored, so an event does not cost a state read
const lastEventAt = new WeakMap();   // ctx -> time of the last delivered event

async function storeKnownCompanies(ctx, ids, { replace }) {
  try {
    const prev = (await ctx.state.get(KNOWN_COMPANIES_KEY))?.ids;
    const before = (Array.isArray(prev) ? prev.map(String) : []).sort();
    const next = [...new Set(replace ? ids.map(String) : [...before, ...ids.map(String)])].sort();
    if (next.length !== before.length || next.some((id, i) => id !== before[i])) await ctx.state.set(KNOWN_COMPANIES_KEY, { ids: next });
    rememberedIds.set(ctx, new Set(next));
  } catch { /* the registry is a fallback; the caller does not depend on it */ }
}

/** An event of a company was delivered: remember the company, and that the host now refuses "all companies" for a while. */
export async function noteCompanyEvent(ctx, companyId, now = Date.now()) {
  lastEventAt.set(ctx, now);
  if (companyId && !rememberedIds.get(ctx)?.has(String(companyId))) await storeKnownCompanies(ctx, [String(companyId)], { replace: false });
}

async function knownCompanies(ctx) {
  const known = await ctx.state.get(KNOWN_COMPANIES_KEY).catch(() => null);
  return Array.isArray(known?.ids) && known.ids.length ? known.ids.map((id) => ({ id, name: null })) : null;
}

/**
 * Every company (paged). Paperclip admits a request for ALL companies only while no company-scoped request is registered in
 * the plugin's worker (plugin-worker-manager `contextForWorkerMessage`, sdk host-client-factory `requireInvocationCompanyScope`),
 * and it keeps the scope of every event it delivers registered for 15 minutes (`issue.updated`, which the alert re-check
 * subscribes to, arrives all the time on a busy board). In that state the call is refused ("the worker referenced a missing,
 * expired, or unknown invocation scope") and the host logs an error for it. So after an event (and when a refusal happens
 * anyway, for example during a page request) the companies the plugin remembers are used instead: the ids of the last
 * successful listing plus those seen in events since. Each successful listing replaces that registry. With no registry yet
 * the host's error is passed on. `live: true` (a page request, which the host does admit it in) always asks the host, for the names.
 */
export async function listCompanies(ctx, { now = Date.now, live = false } = {}) {
  const sinceEvent = lastEventAt.has(ctx) ? now() - lastEventAt.get(ctx) : Infinity;
  if (!live && sinceEvent < EVENT_SCOPE_HOLD_MS) {
    const known = await knownCompanies(ctx);
    if (known) return known;
  }
  const out = [];
  try {
    for (let offset = 0; ; offset += 200) {
      const page = await ctx.companies.list({ limit: 200, offset });
      out.push(...page);
      if (page.length < 200) break;
    }
  } catch (e) {
    if (!SCOPE_REFUSED.test(String(e?.message))) throw e;
    const known = await knownCompanies(ctx);
    if (!known) throw e;
    ctx.logger?.info?.(`companies.list refused by the host (a company-scoped request is registered); using the ${known.length} remembered company id(s)`);
    return known;
  }
  await storeKnownCompanies(ctx, out.map((c) => c.id), { replace: true });
  return out;
}
