// Negative test for the security reviewer: an AGENT actor can change none of the settings that decide how an agent process is
// started or boxed on ANY existing agent (itself or another): env.HERMES_SANDBOX_ALLOW / _RO / _HOME / _PASS / _BIN, env.HERMES_HOME,
// env.HOME, command, hermesCommand (and the rest of the list in patch 0002) get a 403 `execution_config_board_only`.
//
// The v0.1 patch 0002 (routes/agents.js) already covers all of these: the whole `env` object and the command keys are on its list,
// it runs in PATCH /agents/:id (on the config that would be stored, after the merge with the stored one) and in the config-revision
// rollback, and the other routes that write an agent's adapterConfig are closed to agents (skill sync, instructions path) or write
// instructions keys only. So this file adds tests, no patch. The handler bodies need a database, so the test cuts the real
// `assertAgentActorMayChangeExecutionConfig` out of the routes file the engine builds from the ORIGINAL bytes of each installed
// Paperclip version plus every patch of the package that changes it, runs it with stubs, and checks the call sites in the text.
//   HARDENING_TEST_SCRATCH  scratch parent dir (default: the OS temp dir)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { PATCHES, comparePatchIds } from "../src/engine/registry.js";
import { discoverPatchFiles, orderCandidates, readPatchTarget, buildFile } from "../src/engine/patches.js";
import { noPristineSkip, pristineOrNull, stockTreePath } from "./helpers/pristine.mjs";

const REL = "node_modules/@paperclipai/server/dist/routes/agents.js";
const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0002-neg-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
const VERSIONS = ["1005", "1012"].filter((v) => pristineOrNull(stockTreePath(v), REL));
const skip = VERSIONS.length ? false : noPristineSkip(stockTreePath("1012"), [REL], "1012");

function build(vkey) {
  const found = discoverPatchFiles(SOURCE_PATCHES_DIR);
  const steps = [...found.keys()].filter((id) => PATCHES[id] && readPatchTarget(found.get(id)[0].file) === REL)
    .filter((id) => !(PATCHES[id].notNeededOn ?? []).includes(vkey)).sort(comparePatchIds)
    .map((id) => ({ id, marker: PATCHES[id].marker, candidates: orderCandidates(found.get(id), vkey) }));
  const r = buildFile({ rel: REL, pristine: pristineOrNull(stockTreePath(vkey), REL), steps, tmpDir: scratch });
  assert.equal(r.ok, true, r.reason);
  return r.content.toString("utf8");
}

class HttpError extends Error { constructor(status, message, details) { super(message); this.status = status; this.details = details; } }
/** The real 0002 check, cut out of the built file, with stubs for what it calls. */
function loadCheck(source) {
  const keys = source.slice(source.indexOf("const AGENT_EXECUTION_ADAPTER_CONFIG_KEYS = ["), source.indexOf("export function agentRoutes("));
  const from = source.indexOf("async function assertAgentActorMayChangeExecutionConfig(");
  const to = source.indexOf("// LOCAL-PATCH 0002: instructions bundle writes", from);
  assert.ok(keys.includes("isAgentExecutionAdapterConfigKey") && from > 0 && to > from, "the 0002 code is in the built file");
  const logged = [];
  const asRecord = (v) => (v !== null && typeof v === "object" && !Array.isArray(v) ? v : null);
  // eslint-disable-next-line no-new-func
  const make = new Function("asRecord", "logger", "forbidden", `${keys}\n${source.slice(from, to)}\nreturn assertAgentActorMayChangeExecutionConfig;`);
  const check = make(asRecord, { warn: (...a) => logged.push(a) }, (message, details) => new HttpError(403, message, details));
  return { check, logged };
}

const plain = (value) => ({ type: "plain", value });
const AGENT_DIR = "/home/user/.paperclip/instances/default/companies/c1/agents/a1";
// The live shape of a typical hermes agent, and a boxed claude agent.
const hermesAgent = () => ({
  id: "target", adapterType: "hermes_local", defaultEnvironmentId: null,
  adapterConfig: {
    command: "/usr/local/bin/hermes-sandbox", model: "m",
    env: { HOME: plain(AGENT_DIR), HERMES_SANDBOX_HOME: plain(`${AGENT_DIR}/hh`), HERMES_SANDBOX_RO: plain("/opt/h"), HERMES_SANDBOX_ALLOW: plain("openrouter.ai"), OPENROUTER_API_KEY: { type: "secret_ref", secretId: "s" } },
  },
});
const claudeAgent = () => ({
  id: "target", adapterType: "claude_local", defaultEnvironmentId: null,
  adapterConfig: { engine: "cli", filesystemScope: "workspace", networkScope: "allowlist", networkAllowlist: ["api.anthropic.com"], filesystemSandboxCommand: "/usr/bin/bwrap", env: { ANTHROPIC_API_KEY: { type: "secret_ref", secretId: "s" } } },
});
const actors = {
  self: { type: "agent", agentId: "target", runId: "r1" },
  other: { type: "agent", agentId: "someone-else", runId: "r1" },
  board: { type: "board", userId: "u1" },
};
const ENV_KEYS = ["HERMES_SANDBOX_ALLOW", "HERMES_SANDBOX_RO", "HERMES_SANDBOX_HOME", "HERMES_SANDBOX_PASS", "HERMES_SANDBOX_BIN", "HERMES_HOME", "HOME"];
const COMMAND_KEYS = ["command", "hermesCommand"];

/** What PATCH /agents/:id hands the check: the config that would be stored (stored config merged with the request, or replaced). */
const withEnv = (agent, mutate) => { const env = { ...agent.adapterConfig.env }; mutate(env); return { adapterConfig: { ...agent.adapterConfig, env } }; };
const rejected = async (check, actor, agent, next) => {
  try { await check({ actor }, agent, next); } catch (e) { assert.equal(e.status, 403); return e; }
  return null;
};

for (const vkey of VERSIONS) {
  const source = build(vkey);
  const { check, logged } = loadCheck(source);

  test(`2026.${vkey}.0: an agent cannot set, add or remove HERMES_SANDBOX_* / HERMES_HOME / HOME in env on itself or another agent (403 execution_config_board_only)`, { skip }, async () => {
    for (const [who, actor] of [["itself", actors.self], ["another agent", actors.other]]) {
      for (const key of ENV_KEYS) {
        const agent = hermesAgent();
        const variants = {
          "changed": withEnv(agent, (env) => { env[key] = plain("/evil"); }),
          "removed": withEnv(agent, (env) => { delete env[key]; }),
          "as a bare string": withEnv(agent, (env) => { env[key] = "/evil"; }),
          "as a secret reference": withEnv(agent, (env) => { env[key] = { type: "secret_ref", secretId: "x" }; }),
          "emptied": withEnv(agent, (env) => { env[key] = plain(""); }),
        };
        for (const [what, next] of Object.entries(variants)) {
          const before = JSON.stringify(agent);
          const e = await rejected(check, actor, agent, next);
          // "removed" of a key the agent does not store is no change at all; the others always differ.
          if (what === "removed" && !(key in agent.adapterConfig.env)) { assert.equal(e, null, `${who}: ${key} removed (not stored)`); continue; }
          assert.ok(e, `${who}: env.${key} ${what} must be refused`);
          assert.equal(e.details.code, "execution_config_board_only");
          assert.ok(e.details.changed.includes("adapterConfig.env"), `${who}: ${key}: ${e.details.changed}`);
          assert.equal(JSON.stringify(agent), before, "the stored agent object is untouched");
        }
        // Adding a key the agent does not store yet is refused as well.
        if (!(key in agent.adapterConfig.env)) assert.ok(await rejected(check, actor, agent, withEnv(agent, (env) => { env[key] = plain("/evil"); })), `${who}: add ${key}`);
      }
    }
    assert.ok(logged.length > 0 && logged.every(([obj]) => obj.event === "agent_execution_config_denied"), "every refusal is logged");
    assert.ok(!JSON.stringify(logged).includes("/evil"), "values are never logged");
  });

  test(`2026.${vkey}.0: an agent cannot change command or hermesCommand (set, change, remove, empty) on itself or another agent`, { skip }, async () => {
    for (const actor of [actors.self, actors.other]) {
      for (const key of COMMAND_KEYS) {
        const agent = hermesAgent();
        for (const value of ["/bin/sh", "hermes", "", null, "/usr/local/bin/hermes-sandbox2", undefined]) {
          const stored = agent.adapterConfig[key];
          if (value === stored) continue;
          const cfg = { ...agent.adapterConfig };
          if (value === undefined) delete cfg[key]; else cfg[key] = value;
          const e = await rejected(check, actor, agent, { adapterConfig: cfg });
          assert.ok(e, `${key} -> ${JSON.stringify(value)}`);
          assert.equal(e.details.code, "execution_config_board_only");
          assert.deepEqual(e.details.changed, [`adapterConfig.${key}`]);
        }
      }
      // adapterType and the default environment are part of how an agent runs, too
      const agent = hermesAgent();
      assert.deepEqual((await rejected(check, actor, agent, { adapterType: "process", adapterConfig: agent.adapterConfig })).details.changed, ["adapterType"]);
      assert.deepEqual((await rejected(check, actor, agent, { defaultEnvironmentId: "env-1", adapterConfig: agent.adapterConfig })).details.changed, ["defaultEnvironmentId"]);
    }
  });

  test(`2026.${vkey}.0: the box keys of a boxed agent are as closed as the env (scopes, allowlist, extra paths, sandbox command, engine args)`, { skip }, async () => {
    const agent = claudeAgent();
    const edits = { filesystemScope: "off", networkScope: "open", networkAllowlist: ["*:443"], filesystemExtraPaths: ["/"], filesystemSandboxCommand: "/bin/sh", args: ["--x"], extraArgs: ["--y"], cwd: "/", dangerouslySkipPermissions: true };
    for (const actor of [actors.self, actors.other])
      for (const [key, value] of Object.entries(edits))
        assert.ok(await rejected(check, actor, agent, { adapterConfig: { ...agent.adapterConfig, [key]: value } }), key);
  });

  test(`2026.${vkey}.0: the check lets the board through, and lets an agent make a change that touches none of these keys`, { skip }, async () => {
    for (const agent of [hermesAgent(), claudeAgent()]) {
      for (const key of ENV_KEYS) assert.equal(await rejected(check, actors.board, agent, withEnv(agent, (env) => { env[key] = plain("/board-choice"); })), null, `board: ${key}`);
      for (const key of COMMAND_KEYS) assert.equal(await rejected(check, actors.board, agent, { adapterConfig: { ...agent.adapterConfig, [key]: "/x" } }), null, `board: ${key}`);
      for (const actor of [actors.self, actors.other]) {
        assert.equal(await rejected(check, actor, agent, { adapterConfig: { ...agent.adapterConfig, model: "other-model", thinking: "high" } }), null, "model and thinking are not execution keys");
        assert.equal(await rejected(check, actor, agent, { adapterConfig: { ...agent.adapterConfig } }), null, "an unchanged config is no change");
        assert.equal(await rejected(check, actor, agent, { name: "renamed" }), null, "no adapterConfig in the request");
      }
    }
  });

  test(`2026.${vkey}.0: the check runs before PATCH /agents/:id stores anything and before a config rollback; skill sync and the instructions path are closed to agents`, { skip }, () => {
    const at = (needle, from = 0) => { const i = source.indexOf(needle, from); assert.ok(i >= 0, needle); return i; };
    const patchRoute = at('router.patch("/agents/:id", validate(updateAgentSchema)');
    const patchCheck = at("await assertAgentActorMayChangeExecutionConfig(req, existing, patchData); // LOCAL-PATCH 0002", patchRoute);
    assert.ok(patchCheck < at("await svc.update(id, patchData,", patchRoute), "PATCH: the check precedes the store");
    const rollbackRoute = at('router.post("/agents/:id/config-revisions/:revisionId/rollback"');
    const rollbackCheck = at("await assertAgentActorMayChangeExecutionConfig(req, existing, {", rollbackRoute);
    assert.ok(rollbackCheck < at("svc.rollbackConfigRevision(", rollbackRoute), "rollback: the check precedes the store");
    const skills = at('router.post("/agents/:id/skills/sync"');
    assert.ok(at('req.actor.type === "agent"', skills) < at("await svc.update(agent.id", skills), "skill sync: refused for agents before it stores");
    const instructionsPath = at('router.patch("/agents/:id/instructions-path"');
    assert.ok(source.slice(instructionsPath, instructionsPath + 400).includes('req.actor.type !== "board"'), "instructions path (it takes any adapterConfig key): board only");
    // Every route under /agents/:id that stores an adapterConfig from a request is one of the routes above or an instructions route
    // (those write instructions keys only and are closed to agents by assertAgentInstructionsWriteScope).
    const handlers = source.split(/\n    router\./).slice(1).map((chunk) => ({ path: /^(?:patch|put|post|delete)\("([^"]+)"/.exec(chunk)?.[1], chunk }));
    const writers = handlers.filter((h) => h.path?.startsWith("/agents/:id") && /svc\.update\((?:agent\.id|id|existing\.id)(?:,\s*\{\s*adapterConfig|, patchData)|rollbackConfigRevision/.test(h.chunk));
    assert.deepEqual(writers.map((h) => h.path).sort(), [
      "/agents/:id", "/agents/:id/config-revisions/:revisionId/rollback", "/agents/:id/instructions-bundle",
      "/agents/:id/instructions-bundle/file", "/agents/:id/instructions-path", "/agents/:id/skills/sync",
    ]);
    for (const h of writers.filter((x) => x.path.includes("instructions-bundle")))
      assert.ok(h.chunk.includes("assertAgentInstructionsWriteScope(req, existing, { selfAllowed: false });"), `${h.path}: closed to agents`);
  });
}
