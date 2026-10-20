// Protection registry: the one place that says which switch exists, what it means for the owner, which patch files it
// consists of, and what it needs. Pure data; the engine reads it, the UI renders it.
//
// kind:
//   "patch"        rebuilt into Paperclip files by the engine (patches listed in `patches`, applied in global id order)
//   "plugin-job"   runs inside the plugin (no Paperclip files change)
//   "host-install" installed outside Paperclip by the admin's one-line install (no Paperclip files change)
// core: switching it off must be confirmed by the owner; `risk` is the sentence the confirmation shows.
// requires: protections that are switched on automatically together with this one.

export const PROTECTIONS = [
  {
    id: "sandbox-compat",
    title: "Sandbox compatibility",
    description:
      "Makes the built-in sandbox work reliably: modern Linux layouts, git worktrees, proxy crashes, apps inside a run reachable on localhost, and wake-ups for pending interactions.",
    kind: "patch",
    core: true,
    risk: "Boxed agents may fail to start or lose network access, and the protections that need the sandbox switch off with it.",
    patches: ["0001", "0004", "0006a", "0006b", "0012", "0014"],
    requires: [],
    defaultOn: true,
  },
  {
    id: "own-box",
    title: "Agents can't change their own box",
    description:
      "Sandbox, network, commands, instructions and skills can only be changed by the board, not by agents. The stored box is enforced again at every run, and a hidden ***REDACTED*** value can never overwrite real settings.",
    kind: "patch",
    core: true,
    risk: "An agent could widen its own sandbox or network, change its commands or rewrite its instructions.",
    patches: ["0002", "0003", "0003b", "0008"],
    requires: ["sandbox-compat"],
    defaultOn: true,
  },
  {
    id: "box-claude",
    title: "Box Claude agents",
    description:
      "Claude agents run in the sandbox with their own folders, and the server's own secrets (database, keys) are not passed to them. Only what the agent itself is given (its secrets and run variables) reaches the run. This also sets up the shared sandbox helper that OpenCode agents use.",
    kind: "patch",
    core: true,
    risk: "Claude agents could run with the server's environment, including its database and API secrets, or fail to start inside the sandbox.",
    // The shared box helper builds on the public-web patch and the Claude adapter on the own-Claude-folder patch (their code is
    // changed further). The environment scrub must not be on without the Claude adapter (a boxed Claude agent would lose its
    // credentials), and the admission rule of "only-boxed" must not be on without all of them (it would refuse every Claude
    // agent): that is why they are one switch, and why "only-boxed" requires it.
    patches: ["0017", "0025", "0026", "0026b", "0026c"],
    requires: ["sandbox-compat", "public-web", "own-claude-folder"],
    defaultOn: true,
  },
  {
    id: "box-opencode",
    title: "Box OpenCode agents",
    description:
      "OpenCode agents run in the sandbox with their own folders and a cleared environment, like Claude agents. While this is off, OpenCode agents are refused by \"Only boxed agents run\" instead of running.",
    kind: "patch",
    core: false,
    // Not core: with it off (or when its patches stop fitting a new Paperclip) OpenCode agents lose nothing that was protecting them,
    // they are refused ("Only boxed agents run" admits a type only when its adapter registered itself as boxed), so switching it
    // off or losing it on an update fails closed. It uses the shared box helper and the environment scrub of "box-claude".
    patches: ["0019", "0019b", "0019c", "0019d"],
    requires: ["box-claude"],
    defaultOn: true,
  },
  {
    id: "only-boxed",
    title: "Only boxed agents run",
    description:
      "An agent without a sandbox is refused instead of running unboxed, and an agent cannot start the \"Test environment\" probe (which runs outside the sandbox). Boxed Claude agents run, and boxed OpenCode agents while \"Box OpenCode agents\" is on; other agent types are refused for now.",
    kind: "patch",
    core: true,
    risk: "An agent without a sandbox would run with full access to this server's account.",
    patches: ["0005b", "0005f", "0027"],
    // The admission rule reads the stored box that "own-box" keeps intact, and refuses a boxed agent whose adapter is not
    // set up by "box-claude" (or "box-opencode" for OpenCode: a type is admitted only when its adapter registered itself as boxed).
    requires: ["sandbox-compat", "own-box", "box-claude"],
    defaultOn: true,
  },
  {
    id: "safe-defaults",
    title: "Safe defaults for new agents",
    description:
      "Every new agent (hired, imported or joined) starts boxed, with no permissions, and unable to create agents or skills.",
    kind: "patch",
    core: true,
    risk: "New agents would start unboxed and with permissions to assign work, create agents or create skills.",
    patches: ["0005a", "0005c", "0005d", "0005e", "0010"],
    requires: ["sandbox-compat"],
    defaultOn: true,
  },
  {
    id: "no-permission-handing",
    title: "Agents can't hand out permissions",
    description: "Granting permissions, including \"may edit pipelines\", can only be done by the board.",
    kind: "patch",
    core: true,
    risk: "An agent could grant itself or other agents permissions such as creating agents or assigning work.",
    patches: ["0009", "0011a", "0011b"],
    requires: [],
    defaultOn: true,
  },
  {
    id: "pipeline-board-only",
    title: "Pipeline structure is board-only",
    description: "Agents can move work along a pipeline but cannot change its stages.",
    kind: "patch",
    core: false,
    patches: ["0007"],
    requires: [],
    defaultOn: true,
  },
  {
    id: "assign-needs-grant",
    title: "Assigning work needs a grant",
    description: "An agent may assign work to other agents or people only with an explicit grant.",
    kind: "patch",
    core: false,
    patches: ["0013a", "0013b"],
    requires: [],
    defaultOn: true,
  },
  {
    id: "public-web",
    title: "Public-web box",
    description:
      "Web-reading agents get the private network with \"any public website, nothing local\" instead of the host network.",
    kind: "patch",
    core: false,
    patches: ["0015"],
    requires: ["sandbox-compat", "own-box"],
    defaultOn: true,
  },
  {
    id: "own-claude-folder",
    title: "Own Claude folder per agent",
    description: "Each agent's Claude settings and conversations are private to it.",
    kind: "patch",
    core: false,
    patches: ["0016"],
    requires: ["sandbox-compat"],
    defaultOn: true,
  },
  {
    id: "daily-caps",
    title: "Daily token caps",
    description:
      "Pauses an agent or company that exceeds its daily token budget, posts the reason, and resumes the next day.",
    kind: "plugin-job",
    core: false,
    patches: [],
    requires: [],
    defaultOn: true,
  },
  {
    id: "watchdog",
    title: "Watchdog",
    description:
      "A separate service under its own account that watches logins, sudo, changed system files and tampering with these protections, and raises alerts as issues.",
    kind: "host-install",
    core: false,
    patches: [],
    requires: [],
    defaultOn: false,
  },
  {
    id: "hermes-boxed",
    title: "Hermes agents boxed",
    description: "Installs the root-owned sandbox wrapper for Hermes agents. Only needed if Hermes is used.",
    kind: "host-install",
    core: false,
    patches: [],
    requires: [],
    defaultOn: false,
  },
];

// Patch table: id -> marker the patched file must contain afterwards, and the Paperclip versions (vkey = 2nd field of
// the version, e.g. 1005 for 2026.1005.0) on which the patch is known to be unnecessary because the code it changes does
// not exist there. That list only ALLOWS skipping; it never refuses a version. The target file is read from the patch.
export const PATCHES = {
  "0001": { marker: "// LOCAL-PATCH 0001" },
  "0002": { marker: "// LOCAL-PATCH 0002" },
  "0003": { marker: "// LOCAL-PATCH 0003" },
  "0003b": { marker: "// LOCAL-PATCH 0003b" },
  "0004": { marker: "// LOCAL-PATCH 0004" },
  "0005a": { marker: "// LOCAL-PATCH 0005a" },
  "0005b": { marker: "// LOCAL-PATCH 0005b" },
  "0005c": { marker: "// LOCAL-PATCH 0005c" },
  "0005d": { marker: "// LOCAL-PATCH 0005d" },
  "0005e": { marker: "// LOCAL-PATCH 0005e", notNeededOn: ["1005"] },
  "0005f": { marker: "// LOCAL-PATCH 0005f" },
  "0006a": { marker: "// LOCAL-PATCH 0006" },
  "0006b": { marker: "// LOCAL-PATCH 0006" },
  "0007": { marker: "// LOCAL-PATCH 0007" },
  "0008": { marker: "// LOCAL-PATCH 0008" },
  "0009": { marker: "// LOCAL-PATCH 0009" },
  "0010": { marker: "// LOCAL-PATCH 0010" },
  "0011a": { marker: "// LOCAL-PATCH 0011" },
  "0011b": { marker: "// LOCAL-PATCH 0011" },
  "0012": { marker: "// LOCAL-PATCH 0012" },
  "0013a": { marker: "// LOCAL-PATCH 0013" },
  "0013b": { marker: "// LOCAL-PATCH 0013" },
  "0014": { marker: "// LOCAL-PATCH 0014" },
  "0015": { marker: "// LOCAL-PATCH 0015" },
  "0016": { marker: "// LOCAL-PATCH 0016" },
  "0017": { marker: "// LOCAL-PATCH 0017" },
  "0019": { marker: "// LOCAL-PATCH 0019" },
  "0019b": { marker: "// LOCAL-PATCH 0019b" },
  "0019c": { marker: "// LOCAL-PATCH 0019c" },
  "0019d": { marker: "// LOCAL-PATCH 0019d" },
  "0025": { marker: "// LOCAL-PATCH 0025" },
  "0026": { marker: "// LOCAL-PATCH 0026" },
  "0026b": { marker: "// LOCAL-PATCH 0026b" },
  "0026c": { marker: "// LOCAL-PATCH 0026c" },
  "0027": { marker: "// LOCAL-PATCH 0027" },
};

/** Any engine-made change carries this text; a target file without a stored pristine that contains it was patched by
 *  someone else (apply.sh, by hand) and is never taken as pristine. */
export const FOREIGN_MARKER = "LOCAL-PATCH ";

/** Global order of patch ids ("0005a" < "0005b" < "0006a" < "0010"; ids are zero-padded, so plain order works). */
export function comparePatchIds(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function getProtection(id) {
  return PROTECTIONS.find((p) => p.id === id) ?? null;
}
