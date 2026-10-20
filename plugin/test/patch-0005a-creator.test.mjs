// 0005a (host/patches/0005a-new-agent-safe-defaults*.patch) removes env names that move a new agent's home, config, endpoints or
// sandbox (HOME, HERMES_HOME, HERMES_SANDBOX_*, XDG_*, CODEX_HOME, ...) from the env the CREATOR supplied, because the spawn-time
// enforcement trusts whatever is stored. Who creates matters: an AGENT (a prompt-injected CEO hiring a child) must not store them;
// the BOARD must, because a hermes_local agent is set up with HOME = its own directory and its own HERMES_SANDBOX_HOME / _RO / _ALLOW
// (the shape of a company running hermes agents).
//   create(): the two routes that create an agent for a person or an agent pass options.claudeLogin.ownerUserId = the board
//             user's id (null for an agent actor); anything else (no option: join request, approval without a pending row,
//             built-in agents) counts as not board and is filtered. A test below compares the routes' text.
//   activatePendingApproval(): a pending hire keeps only the unsafe names its pending row already stores.
// Tests: the pure functions of the block for both variants, then the call sites in the built files (text) for each installed version.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { addedText, evalBlock, blockFromPatchFile } from "./helpers/patch-block.mjs";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { PATCHES, comparePatchIds } from "../src/engine/registry.js";
import { discoverPatchFiles, orderCandidates, readPatchTarget, buildFile } from "../src/engine/patches.js";
import { pristineOrNull, stockTreePath } from "./helpers/pristine.mjs";
import { SCOPED_TYPES } from "../src/profiles.js";

const VARIANTS = ["0005a-new-agent-safe-defaults.patch", "0005a-new-agent-safe-defaults.1012.patch"];
const plain = (value) => ({ type: "plain", value });
const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0005a-creator-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
const block = (name) => evalBlock(blockFromPatchFile(path.join(SOURCE_PATCHES_DIR, name), "0005a"), "0005a", { extraExports: ["creatorIsBoard0005a"] });
const apply = (b, type, cfg, trust, source = "create") => b.applyNewAgentSafeDefaults(type, cfg, {}, source, trust);
const logOf = (b) => b.warnings.filter((w) => w.obj.event === "new_agent_defaults").at(-1).obj;

// A typical hermes agent as the board sets it up.
const LIVE_HERMES = {
  command: "/usr/local/bin/hermes-sandbox",
  env: {
    HOME: plain("/home/user/.paperclip/instances/default/companies/c1/agents/a1"),
    HERMES_SANDBOX_HOME: plain("/home/user/.paperclip/instances/default/companies/c1/agents/a1/hermes-home"),
    HERMES_SANDBOX_RO: plain("/home/user/.hermes/hermes-agent,/home/user/.hermes/tools,/home/user/shared"),
    HERMES_SANDBOX_ALLOW: plain("openrouter.ai,api.example.org"),
  },
};
const UNSAFE = {
  HERMES_SANDBOX_ALLOW: plain("evil.example"), HERMES_SANDBOX_PASS: plain("DATABASE_URL"), HERMES_SANDBOX_HOME: plain("/"), HERMES_SANDBOX_RO: plain("/"),
  HERMES_SANDBOX_BIN: plain("/bin/sh"), HERMES_HOME: plain("/home/u/.hermes"), HOME: plain("/home/u"), XDG_CONFIG_HOME: "/home/u/.config",
  OPENCODE_CONFIG: plain("/x/o.json"), CODEX_HOME: plain("/home/u/.codex"), CLAUDE_CONFIG_DIR: plain("/home/u/.claude"),
  PAPERCLIP_API_URL: plain("https://evil.example:443"), NODE_OPTIONS: plain("--require /x.js"), NODE_PATH: plain("/x"), PAPERCLIP_ADAPTER_UTILS: plain("/evil/m.js"), LD_PRELOAD: plain("/x.so"), PATH: plain("/home/u/bin"),
};
const CREDS = { ANTHROPIC_API_KEY: { type: "secret_ref", secretId: "s1" }, OPENROUTER_API_KEY: plain("sk-dummy"), KEEP: "1" };

for (const name of VARIANTS) {
  const b = block(name);
  const types = [...SCOPED_TYPES, "hermes_local"];

  test(`${name}: creatorIsBoard0005a is true only for a non-empty user id in options.claudeLogin.ownerUserId`, () => {
    assert.equal(b.creatorIsBoard0005a({ claudeLogin: { ownerUserId: "user-1" } }), true);
    assert.equal(b.creatorIsBoard0005a({ claudeLogin: { ownerUserId: "local-board" } }), true);
    for (const options of [undefined, null, {}, { claudeLogin: null }, { claudeLogin: {} }, { claudeLogin: { ownerUserId: null } }, { claudeLogin: { ownerUserId: "" } },
      { claudeLogin: { ownerUserId: 7 } }, { claudeLogin: { ownerUserId: true } }, { claudeLogin: { ownerUserId: {} } }, { claudeLogin: { ownerUserId: ["u"] } },
      { ownerUserId: "user-1" }, { claudeLogin: { storedSessionId: "x", ownerUserId: undefined, inheritedFromAgentId: "a1" } }, "user-1", 7])
      assert.equal(b.creatorIsBoard0005a(options), false, JSON.stringify(options));
  });

  for (const type of types) {
    test(`${name}: ${type}: an agent (or unknown) creator loses the flagged env, a board creator keeps all of it`, () => {
      const cfg = { model: "m", env: { ...UNSAFE, ...CREDS } };
      const stripped = [undefined, null, {}, { board: false }, { board: "true" }, { board: 1 }, { board: undefined }];
      for (const trust of stripped) {
        const out = apply(b, type, cfg, trust).adapterConfig.env;
        for (const key of Object.keys(UNSAFE).filter((k) => !(type === "hermes_local" && k === "HERMES_SANDBOX_ALLOW")))
          assert.equal(key in out, false, `${JSON.stringify(trust)}: ${key} removed`);
        for (const key of Object.keys(CREDS)) assert.deepEqual(out[key], CREDS[key], `${key} kept`);
        assert.deepEqual(logOf(b).droppedEnv.slice().sort(), Object.keys(UNSAFE).sort());
        assert.equal(logOf(b).keptEnv, undefined);
      }
      const kept = apply(b, type, cfg, { board: true }).adapterConfig;
      assert.deepEqual(kept.env, { ...UNSAFE, ...CREDS }, "a board creator's env is stored as given");
      assert.equal(logOf(b).droppedEnv, undefined);
      assert.deepEqual(logOf(b).keptEnv.slice().sort(), Object.keys(UNSAFE).sort(), "the log names what was kept (names only)");
      assert.ok(!JSON.stringify(logOf(b)).includes("evil.example"), "never values");
      // The box itself is not up to the creator, whoever it is.
      if (type === "hermes_local") assert.equal(kept.command, "/usr/local/bin/hermes-sandbox");
      else { assert.equal(kept.filesystemScope, "workspace"); assert.equal(kept.networkScope, "allowlist"); assert.equal(kept.filesystemSandboxCommand, "/usr/bin/bwrap"); }
    });
  }

  test(`${name}: the exact live hermes shape: a board creator's HOME and HERMES_SANDBOX_* stay, an agent's are replaced by the defaults`, () => {
    const boardStored = apply(b, "hermes_local", structuredClone(LIVE_HERMES), { board: true }).adapterConfig;
    assert.deepEqual(boardStored, LIVE_HERMES);
    const agentStored = apply(b, "hermes_local", structuredClone(LIVE_HERMES), undefined).adapterConfig;
    assert.deepEqual(agentStored.env, { HERMES_SANDBOX_ALLOW: plain("openrouter.ai") });
    assert.equal(agentStored.command, "/usr/local/bin/hermes-sandbox");
  });

  test(`${name}: hermes_local: the board's command is replaced by the wrapper, and missing ALLOW / RO get the defaults`, () => {
    const out = apply(b, "hermes_local", { command: "hermes", hermesCommand: "/bin/sh", env: { HOME: plain("/h") } }, { board: true }).adapterConfig;
    assert.equal(out.command, "/usr/local/bin/hermes-sandbox");
    assert.deepEqual(out.env, { HOME: plain("/h"), HERMES_SANDBOX_ALLOW: plain("openrouter.ai") }, "defaults fill in; RO stays unset without a settings value");
    assert.deepEqual(apply(b, "hermes_local", {}, { board: true }).adapterConfig.env, { HERMES_SANDBOX_ALLOW: plain("openrouter.ai") });
    assert.deepEqual(apply(b, "hermes_local", { env: "x" }, { board: true }).adapterConfig.env, { HERMES_SANDBOX_ALLOW: plain("openrouter.ai") });
  });

  test(`${name}: hermes_local with a settings read-only list: the default fills in only where the creator may not set it`, () => {
    const root = fs.mkdtempSync(path.join(scratch, "root-")); fs.chmodSync(root, 0o700);
    const file = path.join(root, "hardening", "config.json");
    fs.mkdirSync(path.dirname(file), { mode: 0o700 });
    fs.writeFileSync(file, JSON.stringify({ hermesReadOnlyPaths: ["/opt/hermes"], hermesAllowlist: ["a.example"] }), { mode: 0o600 });
    const withSettings = evalBlock(blockFromPatchFile(path.join(SOURCE_PATCHES_DIR, name), "0005a"), "0005a", { instanceRoot: root });
    const cfg = { env: { HERMES_SANDBOX_RO: plain("/mine") } };
    assert.deepEqual(apply(withSettings, "hermes_local", cfg, { board: true }).adapterConfig.env, { HERMES_SANDBOX_RO: plain("/mine"), HERMES_SANDBOX_ALLOW: plain("a.example") });
    assert.deepEqual(apply(withSettings, "hermes_local", cfg, undefined).adapterConfig.env, { HERMES_SANDBOX_ALLOW: plain("a.example"), HERMES_SANDBOX_RO: plain("/opt/hermes") });
    assert.deepEqual(apply(withSettings, "hermes_local", {}, { board: true }).adapterConfig.env, { HERMES_SANDBOX_ALLOW: plain("a.example"), HERMES_SANDBOX_RO: plain("/opt/hermes") });
  });

  test(`${name}: approval activation keeps an unsafe name only when the pending row already stores the identical binding`, () => {
    const payloadEnv = { HOME: plain("/agent/dir"), HERMES_SANDBOX_HOME: plain("/agent/dir/hh"), CODEX_HOME: plain("/evil"), NODE_OPTIONS: plain("--require /x"), KEEP: "1" };
    const stored = { HOME: plain("/agent/dir"), HERMES_SANDBOX_HOME: { value: "/agent/dir/hh", type: "plain" }, CODEX_HOME: plain("/other"), KEEP: "1" };
    const out = apply(b, "hermes_local", { env: payloadEnv }, { storedEnv: stored }, "approval_activation").adapterConfig.env;
    assert.deepEqual(out, { HOME: plain("/agent/dir"), HERMES_SANDBOX_HOME: plain("/agent/dir/hh"), KEEP: "1", HERMES_SANDBOX_ALLOW: plain("openrouter.ai") },
      "HOME / HERMES_SANDBOX_HOME equal (key order is not a difference); CODEX_HOME differs; NODE_OPTIONS is not stored");
    assert.deepEqual(logOf(b).droppedEnv.slice().sort(), ["CODEX_HOME", "NODE_OPTIONS"]);
    assert.deepEqual(logOf(b).keptEnv.slice().sort(), ["HERMES_SANDBOX_HOME", "HOME"]);
    for (const storedEnv of [null, undefined, "x", [], 7, {}]) {
      const none = apply(b, "opencode_local", { env: payloadEnv }, { storedEnv }, "approval_activation").adapterConfig.env;
      assert.deepEqual(Object.keys(none), ["KEEP"], JSON.stringify(storedEnv));
    }
  });
}

// ---------- the call sites
for (const name of VARIANTS) {
  test(`${name}: create() passes the creator, activatePendingApproval() passes the pending row's stored env`, () => {
    const text = addedText(fs.readFileSync(path.join(SOURCE_PATCHES_DIR, name), "utf8"));
    assert.ok(text.includes('applyNewAgentSafeDefaults(adapterType, adapterConfig, normalizedPermissions, "create", { board: creatorIsBoard0005a(options) })'));
    assert.ok(text.includes('"approval_activation", { storedEnv: isPlainRecord(existing.adapterConfig) ? existing.adapterConfig.env : null })'));
    assert.equal(text.split("applyNewAgentSafeDefaults(").length - 1, 3, "the definition and the two call sites, no other");
  });
}

// ---------- the routes tell create() who the creator is: compare the text of every installed version's routes
const ROUTES = "node_modules/@paperclipai/server/dist/routes/agents.js";
const OWNER = 'ownerUserId: req.actor.type === "agent" ? null : (req.actor.userId ?? null)';
const VERSIONS = ["1005", "1012"].filter((v) => pristineOrNull(stockTreePath(v), ROUTES));
function buildRoutes(vkey) {
  const found = discoverPatchFiles(SOURCE_PATCHES_DIR);
  const steps = [...found.keys()].filter((id) => PATCHES[id] && readPatchTarget(found.get(id)[0].file) === ROUTES)
    .filter((id) => !(PATCHES[id].notNeededOn ?? []).includes(vkey)).sort(comparePatchIds)
    .map((id) => ({ id, marker: PATCHES[id].marker, candidates: orderCandidates(found.get(id), vkey) }));
  const r = buildFile({ rel: ROUTES, pristine: pristineOrNull(stockTreePath(vkey), ROUTES), steps, tmpDir: scratch });
  assert.equal(r.ok, true, r.reason);
  return r.content.toString("utf8");
}
const callsOf = (text, re) => [...text.matchAll(re)].map((m) => text.slice(m.index, m.index + 2500));

for (const vkey of VERSIONS) {
  test(`2026.${vkey}.0: both routes that create an agent for a caller pass ownerUserId = null for an agent actor; no other create() caller passes claudeLogin`, () => {
    const routes = buildRoutes(vkey);
    const creates = callsOf(routes, /\bsvc\.create\(companyId, \{/g);
    assert.equal(creates.length, 2, "POST /agent-hires and POST /agents");
    for (const call of creates) {
      const options = call.slice(call.indexOf("claudeLogin:"));
      assert.ok(options.slice(0, 600).includes(OWNER), "claudeLogin.ownerUserId is the user of a non-agent actor, null for an agent actor");
    }
    // Callers that cannot say who created the agent pass no claudeLogin: they count as not board.
    for (const [rel, re] of [["node_modules/@paperclipai/server/dist/routes/access.js", /\bagents\.create\(companyId, \{/g], ["node_modules/@paperclipai/server/dist/services/approvals.js", /\bagentsSvc\.create\(updated\.companyId, \{/g]]) {
      const text = pristineOrNull(stockTreePath(vkey), rel)?.toString("utf8");
      if (!text) continue;
      const calls = callsOf(text, re);
      assert.ok(calls.length >= 1, `${rel}: a create() call`);
      for (const call of calls) assert.equal(call.slice(0, call.indexOf("});") + 3).includes("claudeLogin"), false, rel);
    }
  });
}
