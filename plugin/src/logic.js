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
    if (type === "claude_local") {
      if (a.filesystemScope !== "workspace") f.push("filesystemScope is not 'workspace'");
      if (typeof a.filesystemSandboxCommand !== "string" || !a.filesystemSandboxCommand.startsWith("/")) f.push("filesystemSandboxCommand is not an absolute path");
      const open = (cfg.openNetworkAgentNames ?? []).includes(name);
      if (a.networkScope !== "allowlist" && !open) f.push("networkScope is not 'allowlist'");
      if (a.networkScope === "allowlist" && (!Array.isArray(a.networkAllowlist) || a.networkAllowlist.length === 0)) f.push("networkAllowlist is empty");
      if (Array.isArray(a.networkAllowlist) && a.networkAllowlist.some((h) => typeof h !== "string" || h.includes("*") || /REDACTED/i.test(h))) f.push("networkAllowlist contains a wildcard or redacted entry");
    } else if (type === "hermes_local") {
      const want = cfg.hermesWrapperPath ?? "/usr/local/bin/hermes-sandbox";
      if (a.command !== want) f.push("command is not the sandbox wrapper " + want);
    } else {
      f.push("adapter type " + type + " has no sandbox support (the fail-closed patch refuses to run it)");
    }
    for (const k of DANGEROUS_KEYS) if (a[k] === true) f.push(k + " is enabled");
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

/** Every company (paged). */
export async function listCompanies(ctx) {
  const out = [];
  for (let offset = 0; ; offset += 200) {
    const page = await ctx.companies.list({ limit: 200, offset });
    out.push(...page);
    if (page.length < 200) return out;
  }
}
