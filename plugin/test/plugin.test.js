import test from "node:test";
import assert from "node:assert/strict";
import { register } from "../src/worker.js";
import { checkAgent } from "../src/logic.js";

const good = { id: "1", name: "Engineer", adapterType: "claude_local", status: "idle", permissions: { canCreateAgents: false },
  adapterConfig: { filesystemScope: "workspace", filesystemSandboxCommand: "/usr/bin/bwrap", networkScope: "allowlist", networkAllowlist: ["api.anthropic.com", "127.0.0.1:8790"] } };
const clone = (o, patch) => ({ ...o, ...patch, adapterConfig: { ...o.adapterConfig, ...(patch.adapterConfig ?? {}) } });

test("compliant agent", () => assert.deepEqual(checkAgent(good), []));
test("drift detection", () => {
  assert.match(checkAgent(clone(good, { adapterConfig: { filesystemScope: null } })).join(), /filesystemScope/);
  assert.match(checkAgent(clone(good, { adapterConfig: { networkScope: null } })).join(), /networkScope/);
  assert.match(checkAgent(clone(good, { adapterConfig: { networkAllowlist: ["*"] } })).join(), /wildcard/);
  assert.match(checkAgent(clone(good, { adapterConfig: { networkAllowlist: ["***REDACTED***"] } })).join(), /redacted/);
  assert.match(checkAgent(clone(good, { adapterConfig: { dangerouslySkipPermissions: true } })).join(), /dangerouslySkipPermissions/);
  assert.match(checkAgent({ ...good, permissions: { canCreateAgents: true } }).join(), /canCreateAgents/);
  assert.match(checkAgent({ ...good, permissions: { canCreateSkills: true } }).join(), /canCreateSkills/);
  assert.match(checkAgent({ ...good, adapterType: "codex_local" }).join(), /no sandbox support/);
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
