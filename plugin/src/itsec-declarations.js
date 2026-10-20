// The static declarations of the ITSec agent and its two routines (manifest `agents[]` and `routines[]`). Kept apart
// from itsec.js because the manifest imports them and itsec.js imports the plugin id from the manifest. No SDK imports.
//
// Paperclip reads these from the installed manifest and applies them ONCE, when the agent is created. Nothing the
// plugin can call changes an existing agent's adapter configuration or a routine's schedule (agents.managed.reconcile
// returns the existing agent as it is; routines.managed.update only takes a status). Later changes are made by the
// board in Paperclip; the plugin only verifies them (src/itsec.js).
import fs from "node:fs";

const read = (name) => fs.readFileSync(new URL(`./itsec/${name}`, import.meta.url), "utf8");

export const ITSEC_AGENT_KEY = "itsec";
export const TRIAGE_ROUTINE_KEY = "itsec-triage";
export const DAILY_ROUTINE_KEY = "itsec-daily-review";
/** Company state: {agentId, ...} of the managed ITSec agent, written by src/itsec.js (read by the alert re-check). */
export const ITSEC_REF_KEY = (companyId) => ({ scopeKind: "company", scopeId: String(companyId), stateKey: "itsec-agent" });
/** The model the agent is created with, and the models the settings page accepts as the advisory value. */
export const DEFAULT_ITSEC_MODEL = "claude-sonnet-5-5";
export const ITSEC_MODELS = Object.freeze([DEFAULT_ITSEC_MODEL, "claude-opus-5-5", "claude-sonnet-5", "claude-sonnet-4-6", "claude-haiku-4-5"]);
/** The only host the agent's network allowlist is created with: the model API. */
export const ITSEC_ALLOWLIST = Object.freeze(["api.anthropic.com"]);

export const itsecAgentDeclaration = Object.freeze({
  agentKey: ITSEC_AGENT_KEY,
  displayName: "ITSec",
  role: "general",
  title: "Host security agent",
  capabilities: "Triages the security alerts of this company and reviews the host's safety automation daily. Comments and reports findings; changes nothing.",
  // Only claude_local is modelled by the sandbox checks. adapterPreference is not used: it would pick the company's
  // most-used adapter.
  adapterType: "claude_local",
  adapterConfig: {
    engine: "cli", // filesystem and network confinement are rejected under ACP
    model: DEFAULT_ITSEC_MODEL,
    effort: "medium",
    filesystemScope: "workspace", // bubblewrap: the workspace and the Claude config are the only writable paths
    filesystemSandboxCommand: "/usr/bin/bwrap",
    filesystemExtraPaths: [], // none declared; the patched Paperclip sets the site's read-only paths, which the plugin accepts (src/itsec.js)
    networkScope: "allowlist",
    networkAllowlist: [...ITSEC_ALLOWLIST], // the model API only; the patched Paperclip may replace it with the site base allowlist
    // dangerouslySkipPermissions is left UNSET on purpose: the adapter then defaults to true, which is what a headless
    // `claude -p` needs to run Bash and MCP tools at all (with false they are refused and the agent cannot read or comment
    // on alerts). That is acceptable only because the agent is boxed (the keys above); the plugin's checks accept the
    // setting only for a boxed agent (src/logic.js).
    timeoutSec: 900,
    maxTurnsPerRun: 40,
  },
  permissions: { canCreateAgents: false, canCreateSkills: false },
  runtimeConfig: { heartbeat: { enabled: false, wakeOnDemand: true, maxConcurrentRuns: 1, maxDailyRuns: 30 } },
  status: "paused", // verified by the plugin before its first run (src/itsec.js verify)
  budgetMonthlyCents: 0, // the plugin's daily token caps apply as to any agent
  instructions: {
    entryFile: "AGENTS.md",
    content: read("AGENTS.md"),
    files: { "TRIAGE.md": read("TRIAGE.md"), "DAILY-REVIEW.md": read("DAILY-REVIEW.md") },
  },
});

const assignee = { resourceKind: "agent", resourceKey: ITSEC_AGENT_KEY };

export const itsecRoutineDeclarations = Object.freeze([
  {
    routineKey: TRIAGE_ROUTINE_KEY,
    title: "ITSec: alert triage",
    description: "Read the new security alert issues of this company and comment on each with a verdict and evidence. Started by the Security hardening plugin when an alert of medium priority or higher is raised (and by its safety-net check when an alert still has no verdict). It has no schedule of its own.",
    assigneeRef: assignee,
    status: "paused", // activated by the plugin after the agent was verified
    priority: "high",
    concurrencyPolicy: "coalesce_if_active",
    catchUpPolicy: "skip_missed",
    activityGatePolicy: "always",
    // no triggers: the plugin starts it with routines.managed.run
  },
  {
    routineKey: DAILY_ROUTINE_KEY,
    title: "ITSec: daily review",
    description: "Review the host's safety automation once a day: protections, self-tests, watchdog, sandbox compliance, alert verdicts, token caps. A run without findings still says what it verified.",
    assigneeRef: assignee,
    status: "paused", // activated by the plugin after the agent was verified
    priority: "medium",
    concurrencyPolicy: "coalesce_if_active",
    catchUpPolicy: "skip_missed",
    activityGatePolicy: "always", // a silent safety automation is itself a finding
    triggers: [{ kind: "schedule", label: "Daily 07:00 UTC", enabled: true, cronExpression: "0 7 * * *", timezone: "UTC" }],
  },
]);
