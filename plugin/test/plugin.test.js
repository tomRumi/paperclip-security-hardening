import test from "node:test";
import assert from "node:assert/strict";
import { register } from "../src/worker.js";
import { checkAgent, envRedirects } from "../src/logic.js";

const good = { id: "1", name: "Engineer", adapterType: "claude_local", status: "idle", permissions: { canCreateAgents: false },
  adapterConfig: { filesystemScope: "workspace", filesystemSandboxCommand: "/usr/bin/bwrap", networkScope: "allowlist", engine: "cli", networkAllowlist: ["api.anthropic.com", "127.0.0.1:8790"], dangerouslySkipPermissions: false } };
const clone = (o, patch) => ({ ...o, ...patch, adapterConfig: { ...o.adapterConfig, ...(patch.adapterConfig ?? {}) } });

test("compliant agent", () => assert.deepEqual(checkAgent(good), []));
test("drift detection", () => {
  assert.match(checkAgent(clone(good, { adapterConfig: { filesystemScope: null } })).join(), /filesystemScope/);
  assert.match(checkAgent(clone(good, { adapterConfig: { networkScope: null } })).join(), /networkScope/);
  assert.match(checkAgent(clone(good, { adapterConfig: { networkAllowlist: ["*"] } })).join(), /wildcard/);
  assert.match(checkAgent(clone(good, { adapterConfig: { networkAllowlist: ["***REDACTED***"] } })).join(), /redacted/);
  assert.match(checkAgent(clone(good, { adapterConfig: { yolo: true } })).join(), /yolo is enabled/);
  assert.match(checkAgent({ ...good, permissions: { canCreateAgents: true } }).join(), /canCreateAgents/);
  assert.match(checkAgent({ ...good, permissions: { canCreateSkills: true } }).join(), /canCreateSkills/);
  assert.match(checkAgent({ ...good, adapterType: "codex_local" }).join(), /no sandbox support/);
});
test("skip-permissions (true or unset: the adapter's default is true) is accepted only on a boxed agent", () => {
  const unset = clone(good, {});
  delete unset.adapterConfig.dangerouslySkipPermissions;
  assert.deepEqual(checkAgent(good), []);                                                                    // boxed + false
  assert.deepEqual(checkAgent(unset), []);                                                                   // boxed + unset
  assert.deepEqual(checkAgent(clone(good, { adapterConfig: { dangerouslySkipPermissions: true } })), []);    // boxed + true
  assert.match(checkAgent(clone(good, { adapterConfig: { yolo: true } })).join(), /yolo is enabled/);         // the other keys are unchanged
  // unboxed: filesystemScope, sandbox command or network box missing
  for (const box of [{ filesystemScope: null }, { filesystemSandboxCommand: "bwrap" }, { networkScope: null }, { networkAllowlist: ["*"] }]) {
    const t = clone(good, { adapterConfig: { ...box, dangerouslySkipPermissions: true } });
    assert.match(checkAgent(t).join(), /dangerouslySkipPermissions is enabled on an agent that is not boxed/, JSON.stringify(box));
    const u = clone(good, { adapterConfig: box }); delete u.adapterConfig.dangerouslySkipPermissions;
    assert.match(checkAgent(u).join(), /dangerouslySkipPermissions is unset .*not boxed/, JSON.stringify(box));
    assert.deepEqual(checkAgent(clone(good, { adapterConfig: { ...box, dangerouslySkipPermissions: false } })).filter((x) => /dangerouslySkip/.test(x)), []);
  }
  // an agent with the configured open-network exception is still boxed for this purpose
  assert.deepEqual(checkAgent(clone(good, { name: "Researcher", adapterConfig: { networkScope: null, networkAllowlist: undefined } }), { openNetworkAgentNames: ["Researcher"] }), []);
  // not a claude_local key: hermes agents are not asked for it
  assert.deepEqual(checkAgent({ id: "h", name: "H", adapterType: "hermes_local", adapterConfig: { command: "/usr/local/bin/hermes-sandbox" } }), []);
});
test("configured exceptions", () => {
  const open = clone(good, { name: "Researcher", adapterConfig: { networkScope: null, networkAllowlist: undefined } });
  assert.notDeepEqual(checkAgent(open), []);
  assert.deepEqual(checkAgent(open, { openNetworkAgentNames: ["Researcher"] }), []);
  assert.deepEqual(checkAgent({ id: "h", name: "H", adapterType: "hermes_local", adapterConfig: { command: "/usr/local/bin/hermes-sandbox" } }), []);
  assert.notDeepEqual(checkAgent({ id: "h", name: "H", adapterType: "hermes_local", adapterConfig: { command: "hermes" } }), []);
});
test("job logs drift once and recovery once", async () => {
  const jobs = {}, state = new Map(), logs = [];
  let agents = [good];
  register({
    config: { get: async () => ({}) }, data: { register() {} },
    companies: { list: async ({ offset }) => (offset ? [] : [{ id: "c1" }]) }, agents: { list: async () => agents },
    state: { get: async (k) => state.get(k.scopeId) ?? null, set: async (k, v) => { state.set(k.scopeId, v); } },
    activity: { log: async (e) => { logs.push(e); } }, actions: { register() {} }, jobs: { register: (k, f) => { jobs[k] = f; } },
  }, { hardening: { loadSettings: async () => ({ hermesWrapperPath: "" }) } });
  const run = () => jobs["verify-sandbox-config"]({});
  await run(); assert.equal(logs.length, 1);                  // initial baseline entry
  await run(); assert.equal(logs.length, 1);                  // unchanged: silent
  agents = [clone(good, { adapterConfig: { filesystemScope: null } })];
  await run(); assert.equal(logs.length, 2); assert.match(logs[1].message, /drift/);
  await run(); assert.equal(logs.length, 2);
  agents = [good]; await run(); assert.equal(logs.length, 3); assert.match(logs[2].message, /compliant again/);
});
test("compliance uses the install-wide Hermes wrapper path from the hardening settings", async () => {
  const data = {};
  const hermes = { id: "h", name: "H", adapterType: "hermes_local", adapterConfig: { command: "/opt/bin/hermes-box" } };
  register({
    config: { get: async () => ({}) }, data: { register: (k, f) => { data[k] = f; } }, actions: { register() {} }, jobs: { register() {} },
    agents: { list: async () => [hermes] },
  }, { hardening: { loadSettings: async () => ({ hermesWrapperPath: "/opt/bin/hermes-box" }) } });
  assert.equal((await data.compliance({ companyId: "c1" })).nonCompliant, 0);
});

// ---------- v0.2.0: opencode_local is boxed, the other adapter types are refused by the server and flagged here
const oc = { id: "o1", name: "Coder", adapterType: "opencode_local", status: "idle", permissions: {},
  adapterConfig: { filesystemScope: "workspace", filesystemSandboxCommand: "/usr/bin/bwrap", networkScope: "allowlist", networkAllowlist: ["openrouter.ai"] } };
test("opencode_local: boxed with the claude checks that apply (no engine needed; the sandbox command must be an absolute path, as for claude_local)", () => {
  assert.deepEqual(checkAgent(oc), []);
  assert.match(checkAgent(clone(oc, { adapterConfig: { filesystemSandboxCommand: undefined } })).join(), /filesystemSandboxCommand is not an absolute path/);
  assert.match(checkAgent(clone(oc, { adapterConfig: { filesystemSandboxCommand: "bwrap" } })).join(), /filesystemSandboxCommand is not an absolute path/);
  assert.match(checkAgent(clone(oc, { adapterConfig: { filesystemScope: null } })).join(), /filesystemScope/);
  assert.match(checkAgent(clone(oc, { adapterConfig: { networkScope: null } })).join(), /networkScope/);
  assert.match(checkAgent(clone(oc, { adapterConfig: { networkAllowlist: [] } })).join(), /empty/);
  assert.match(checkAgent(clone(oc, { adapterConfig: { networkAllowlist: ["*:443"] } })).join(), /wildcard/);
  assert.match(checkAgent(clone(oc, { adapterConfig: { yolo: true } })).join(), /yolo is enabled/);
  assert.doesNotMatch(checkAgent(clone(oc, { adapterConfig: { dangerouslySkipPermissions: true } })).join(), /on an agent that is not boxed/);
  assert.match(checkAgent(clone(oc, { adapterConfig: { dangerouslySkipPermissions: true } })).join(), /dangerouslySkipPermissions is enabled/); // no such mode for opencode: unsafe wherever true
});
test("claude_local: the engine must be cli (the default engine is not boxed)", () => {
  const f = checkAgent(clone(good, { adapterConfig: { engine: "acp" } }));
  assert.match(f.join(), /engine is not 'cli'/);
  const unset = clone(good, {}); delete unset.adapterConfig.engine;
  assert.match(checkAgent(unset).join(), /engine is not 'cli'/);
  const skip = clone(good, { adapterConfig: { engine: "acp", dangerouslySkipPermissions: true } });
  assert.match(checkAgent(skip).join(), /dangerouslySkipPermissions is enabled on an agent that is not boxed/, "without the cli engine the agent is not boxed");
});
test("other local types: planned for a later version; unknown types: not supported", () => {
  for (const type of ["codex_local", "gemini_local", "cursor", "pi_local", "kimi_local", "grok_local"]) {
    const f = checkAgent({ id: "x", name: "X", adapterType: type, adapterConfig: {} });
    assert.match(f.join(), /planned for a later version/, type);
  }
  assert.match(checkAgent({ id: "x", name: "X", adapterType: "acpx_local", adapterConfig: {} }).join(), /cannot be excepted/);
  assert.match(checkAgent({ id: "x", name: "X", adapterType: "some_plugin", adapterConfig: {} }).join(), /not supported and cannot be excepted/);
});
test("remote types need a remote exception for this agent and this type", () => {
  const http = { id: "h1", name: "Hook", adapterType: "http", adapterConfig: {} };
  assert.match(checkAgent(http).join(), /needs a remote exception/);
  assert.match(checkAgent(http, { remoteExceptions: [] }).join(), /needs a remote exception/);
  assert.match(checkAgent(http, { remoteExceptions: [{ agentId: "other", type: "http" }] }).join(), /needs a remote exception/);
  assert.match(checkAgent(http, { remoteExceptions: [{ agentId: "h1", type: "process" }] }).join(), /needs a remote exception/, "the type must match too");
  assert.deepEqual(checkAgent(http, { remoteExceptions: [{ agentId: "h1", type: "http", reason: "r", addedBy: "u", addedAt: "2026-10-20T00:00:00Z" }] }), []);
  assert.deepEqual(checkAgent({ ...http, status: "terminated" }), []);
});
test("stored env redirects the server drops: HOME, XDG_* and the type's state variables", () => {
  const env = (e, base = good) => clone(base, { adapterConfig: { env: e } });
  assert.deepEqual(envRedirects("claude_local", { env: { ANTHROPIC_API_KEY: { type: "secret_ref" } } }), []);
  const f = checkAgent(env({ HOME: { type: "plain", value: "/x" }, XDG_DATA_HOME: "/y", CLAUDE_CONFIG_DIR: "/z", ANTHROPIC_API_KEY: "k" }));
  assert.equal(f.length, 1);
  assert.match(f[0], /HOME, XDG_DATA_HOME, CLAUDE_CONFIG_DIR, which the server drops/);
  assert.doesNotMatch(f[0], /ANTHROPIC_API_KEY/);
  assert.match(checkAgent(env({ OPENCODE_CONFIG: "/c", XDG_CONFIG_HOME: "/d" }, oc)).join(), /OPENCODE_CONFIG|XDG_CONFIG_HOME/);
  assert.doesNotMatch(checkAgent(env({ CLAUDE_CONFIG_DIR: "/z" }, oc)).join(), /CLAUDE_CONFIG_DIR/, "another type's variable is not a redirect here");
  assert.doesNotMatch(checkAgent(env({ HOME: "/x" })).join(), /not boxed/, "the redirect does not unbox the agent (the server just ignores it)");
});
test("hermes_local: hermesCommand must be the wrapper too (the adapter runs it before command)", () => {
  const h = (cfg) => ({ id: "h", name: "H", adapterType: "hermes_local", adapterConfig: { command: "/usr/local/bin/hermes-sandbox", ...cfg } });
  assert.deepEqual(checkAgent(h({})), []);
  assert.deepEqual(checkAgent(h({ hermesCommand: "/usr/local/bin/hermes-sandbox" })), []);
  assert.match(checkAgent(h({ hermesCommand: "hermes" })).join(), /hermesCommand is not the sandbox wrapper/);
});
