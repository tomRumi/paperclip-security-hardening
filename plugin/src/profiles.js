// Per adapter type: how Paperclip's built-in sandbox is applied to it. Pure data and lookups (no imports), shared by the
// settings validation, the Hardening page and, by a drift test, the 0005a defaults table of the patched server.
//
//   scopes               the type is boxed through filesystemScope/networkScope (bubblewrap run by Paperclip itself)
//   engineCli            the stored config must say engine "cli": the type's default engine is an ACP lane the box cannot
//                        reach, so only the CLI engine is boxed
//   acpLane              the adapter has an ACP lane at all (opencode, pi, cursor and grok have none)
//   defaultHosts         network allowlist a new agent of the type starts with; `baseAllowlists[type]` of the settings
//                        file overrides it (claude_local: `baseAllowlist`, as in v0.1.x)
//   stateEnv             variables that redirect the CLI's state or config; a run may not override them (HOME and the XDG
//                        ones are COMMON_STATE_ENV and apply to every boxed type)
//   credentialEnvNames   variables the CLI reads its API key or token from; they reach it only from the agent's own env
//                        (a company secret bound with secret_ref)
//   boxEnv               fixed environment the box sets for a run of the type (wins over the agent's env): switches that stop
//                        background network use (telemetry, update, model-list fetch) or make a headless run work
//   installTreeReadOnly  the CLI's install tree (the enclosing node_modules root of the realpath of its command) is mounted
//                        read-only into the box: Paperclip's stock mounts (dirname of the command and the nearest package.json
//                        root) miss the sibling packages of pi, kimi and codex (T0: "Cannot find package ...")
//   exceptionable        runs on someone else's machine or outside the box (remote, gateway, generic process); refused
//                        unless an admin lists the agent in `remoteExceptions`. A type absent from this table
//                        (paperclip_runner, acpx_local, adapter plugins, unknown) is always refused, with no exception.
//   hermes_local is boxed by the root-owned wrapper (host/sandbox/hermes-sandbox), not by scopes.

// ---------------------------------------------------------------------------------------------------------------------
// Values measured by the T0 discovery (2026-10-20: the seven CLIs run through Paperclip's own bubblewrap box with a BASE-only
// environment and fake keys). "measured" = seen in a logged run; "static" = read from the CLI's bundle or binary strings and
// not exercised. Only claude_local is the v0.1.x default; hermes_local is the wrapper's default.
//
// Hosts are API-key mode: what a run needs, with no telemetry, update or login host. A denied optional host is non-fatal (the
// sandbox proxy logs it); the operator adds a host in the plugin (`baseAllowlists[type]`) when a real run shows one.
const DEFAULT_HOSTS = {
  claude_local: ["api.anthropic.com"],
  codex_local: ["api.openai.com"], // measured. Non-fatal, kept off: chatgpt.com, github.com, api.github.com (startup sync, model refresh)
  // OpenCode is not tied to one provider: the common LLM API hosts (owner decision). The first two and the provider-key form were
  // measured (T0); the Paperclip API reaches the box through the adapter's trustedUrls, not through this list.
  opencode_local: ["openrouter.ai", "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"],
  gemini_local: ["generativelanguage.googleapis.com"], // measured. play.googleapis.com is usage telemetry, kept off
  // Measured minimum: the CLI contacts api2.cursor.sh and rejects a fake key there. The hosts after a VALID key are static only
  // (source uncertainty, not exercised): api3.cursor.sh (metrics), repo42.cursor.sh (codebase indexing), cursor.com (login,
  // update). They stay off; the operator adds one if a real run shows a denied CONNECT. Never `*:443`.
  cursor: ["api2.cursor.sh"],
  pi_local: [], // the provider's host per model (measured: api.anthropic.com): the operator chooses the provider
  kimi_local: ["api.moonshot.ai"], // measured. telemetry-logs.kimi.com is off through KIMI_DISABLE_TELEMETRY; api.moonshot.cn and api.kimi.com are static
  grok_local: ["api.x.ai"], // measured with a fake key; the hosts used after a valid key are static only (not exercised)
  hermes_local: ["openrouter.ai"], // HERMES_SANDBOX_ALLOW default (settings: hermesAllowlist)
};
const CREDENTIAL_ENV = {
  claude_local: ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"],
  codex_local: ["CODEX_API_KEY"], // `codex exec` 0.163.0 ignores OPENAI_API_KEY (measured 401): the agent's secret must be named CODEX_API_KEY
  opencode_local: ["OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"], // the first two measured; whichever the agent has set reaches the box
  gemini_local: ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
  cursor: ["CURSOR_API_KEY"],
  // The provider keys pi reads (ANTHROPIC_API_KEY measured, the others from pi-ai's provider table, static); the operator binds the one of the provider used.
  pi_local: ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "XAI_API_KEY", "OPENROUTER_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY", "DEEPSEEK_API_KEY"],
  kimi_local: ["KIMI_MODEL_API_KEY", "KIMI_MODEL_NAME"],
  grok_local: ["XAI_API_KEY"],
  hermes_local: ["OPENROUTER_API_KEY"],
};
// Redirects of the CLI's own state beyond HOME and XDG_* (COMMON_STATE_ENV); the box sets them under the run's own directory.
const STATE_ENV = {
  claude_local: ["CLAUDE_CONFIG_DIR"],
  codex_local: ["CODEX_HOME"], // the directory must exist before the spawn (measured)
  opencode_local: ["OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR", "PAPERCLIP_OPENCODE_PROVIDERS"], // its state follows XDG_*_HOME (measured); the OPENCODE_* ones are static
  gemini_local: ["GEMINI_CLI_HOME"],
  cursor: ["CURSOR_DATA_DIR"], // the `~/.cursor` equivalent (measured)
  pi_local: ["PI_CODING_AGENT_DIR", "PAPERCLIP_PI_PROVIDERS"],
  kimi_local: ["KIMI_CODE_HOME"],
  grok_local: ["GROK_HOME"],
  hermes_local: ["HERMES_HOME", "HERMES_SANDBOX_HOME", "HERMES_SANDBOX_ALLOW", "HERMES_SANDBOX_RO"],
};
// Fixed values the box sets for a run: switches that stop background network use or make a headless run work.
const BOX_ENV = {
  claude_local: {},
  codex_local: {},
  opencode_local: { OPENCODE_DISABLE_MODELS_FETCH: "1", OPENCODE_DISABLE_AUTOUPDATE: "1", OPENCODE_DISABLE_LSP_DOWNLOAD: "1", OPENCODE_DISABLE_PROJECT_CONFIG: "true" }, // the first measured; the others exist in the binary
  gemini_local: { GEMINI_CLI_TRUST_WORKSPACE: "true" }, // measured: without it a headless run in a fresh HOME exits 55
  cursor: {},
  pi_local: { PI_SKIP_VERSION_CHECK: "1" }, // exists in the binary; not needed in -p mode (static)
  kimi_local: { CI: "1", NO_COLOR: "1", KIMI_CODE_NO_AUTO_UPDATE: "1", KIMI_DISABLE_TELEMETRY: "1" }, // the last measured
  grok_local: {},
  hermes_local: {},
};
// ---------------------------------------------------------------------------------------------------------------------

/** Redirects of HOME and the XDG directories: dropped from a run's env for every boxed type. */
export const COMMON_STATE_ENV = Object.freeze(["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"]);

const local = (type, { engineCli = false, acpLane = false, installTreeReadOnly = false } = {}) => ({
  scopes: true,
  engineCli,
  defaultHosts: DEFAULT_HOSTS[type],
  stateEnv: STATE_ENV[type],
  credentialEnvNames: CREDENTIAL_ENV[type],
  boxEnv: BOX_ENV[type],
  installTreeReadOnly,
  acpLane,
  exceptionable: false,
});
const remote = () => ({
  scopes: false, engineCli: false, defaultHosts: [], stateEnv: [], credentialEnvNames: [], boxEnv: {}, installTreeReadOnly: false, acpLane: false, exceptionable: true,
});

const deepFreeze = (v) => {
  if (v && typeof v === "object") Object.values(v).forEach(deepFreeze);
  return Object.freeze(v);
};

/** adapter type -> profile (see the header). */
export const BOX_PROFILES = deepFreeze({
  claude_local: local("claude_local", { engineCli: true, acpLane: true }),
  codex_local: local("codex_local", { engineCli: true, acpLane: true, installTreeReadOnly: true }),
  opencode_local: local("opencode_local"),
  gemini_local: local("gemini_local", { engineCli: true, acpLane: true }),
  cursor: local("cursor"),
  pi_local: local("pi_local", { installTreeReadOnly: true }),
  kimi_local: local("kimi_local", { engineCli: true, acpLane: true, installTreeReadOnly: true }),
  grok_local: local("grok_local"),
  hermes_local: { ...local("hermes_local"), scopes: false },
  cursor_cloud: remote(),
  openclaw_gateway: remote(),
  hermes_gateway: remote(),
  http: remote(),
  process: remote(),
});

/** The profile of an adapter type, or null for a type this plugin does not know (such a type is always refused). */
export function profileFor(type) {
  return typeof type === "string" && Object.hasOwn(BOX_PROFILES, type) ? BOX_PROFILES[type] : null;
}

const typesWhere = (pred) => Object.freeze(Object.keys(BOX_PROFILES).filter((t) => pred(BOX_PROFILES[t])));

/** Types boxed through filesystemScope/networkScope. */
export const SCOPED_TYPES = typesWhere((p) => p.scopes);
/** Types an admin may exempt per agent (remote, gateway and generic process agents). */
export const EXCEPTIONABLE_TYPES = typesWhere((p) => p.exceptionable);

export const isScopedType = (type) => profileFor(type)?.scopes === true;
export const isExceptionableType = (type) => profileFor(type)?.exceptionable === true;

/** A copy of the default allowlist of a type ([] for a type without one). */
export const defaultHostsFor = (type) => [...(profileFor(type)?.defaultHosts ?? [])];
