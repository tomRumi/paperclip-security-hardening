// Patch 0003b (host/patches/0003b-hermes-engine-env-redirects.patch) stacks on 0003 in heartbeat.js. It makes the spawn-time
// enforcement also (a) cover a boxed Hermes agent (stored command = the sandbox wrapper), (b) keep `engine` at the stored
// value, and (c) restore or drop run-level HOME / XDG_* / OPENCODE_* / GEMINI_CLI_HOME / PI_CODING_AGENT_DIR / KIMI_CODE_HOME /
// CURSOR_HOME / CURSOR_DATA_DIR / PAPERCLIP_*_PROVIDERS env values, except, on the managed AI connection path (the server builds that run's
// home), exactly the six names the server's managedAiHomeEnvironment() sets.
// The tests build heartbeat.js from the ORIGINAL bytes (helpers/pristine.mjs; PAPERCLIP_STOCK_TREE_<vkey>) of the installed Paperclip versions with the patches (the engine's
// own buildFile, GNU patch -F0) and evaluate the 0003 block of the result, once without 0003b (what v0.1.x installs run)
// and once with it. The upgrade tests take the v0.1.1 release's patch files from git and add 0003b to an engine state made by them.
// Skipped when no installed Paperclip with .orig backups (or git history for the upgrade tests) is available.
//   HARDENING_TEST_SCRATCH  scratch parent dir (default: the OS temp dir)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { extractBlock, evalBlock, blockFromPatchFile } from "./helpers/patch-block.mjs";
import { v011Package, importV011Engine, V011_DEFAULTS } from "./helpers/v011.mjs";
import { noPristineSkip, pristineOrNull, stockTreePath } from "./helpers/pristine.mjs";
import { BOX_PROFILES, COMMON_STATE_ENV } from "../src/profiles.js";
import { SOURCE_PATCHES_DIR, createEngine } from "../src/engine/index.js";
import { PATCHES, PROTECTIONS, comparePatchIds } from "../src/engine/registry.js";
import { discoverPatchFiles, readPatchTarget, buildFile } from "../src/engine/patches.js";

const HB = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
const MARKER_0003B = "// LOCAL-PATCH 0003b";
const WRAPPER = "/usr/local/bin/hermes-sandbox";
const stockRoot = (version) => stockTreePath(version.split(".")[1]); // PAPERCLIP_STOCK_TREE_<vkey>, else the installed version
const VERSIONS = ["2026.1005.0", "2026.1012.0"].filter((v) => pristineOrNull(stockRoot(v), HB));
const skip = VERSIONS.length ? false : noPristineSkip(stockRoot("2026.1012.0"), [HB], "1012");

const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0003b-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
let n = 0;
const freshDir = () => { const d = path.join(scratch, `d-${++n}`); fs.mkdirSync(d, { mode: 0o700, recursive: true }); return d; };

const pristine = (version) => pristineOrNull(stockRoot(version), HB);
const heartbeatSteps = (patchFiles, { with0003b }) => [...patchFiles.keys()]
  .filter((id) => (PATCHES[id] || (with0003b && id === "0003b")) && readPatchTarget(patchFiles.get(id)[0].file) === HB)
  .filter((id) => with0003b || id !== "0003b")
  .sort(comparePatchIds)
  .map((id) => ({ id, marker: PATCHES[id]?.marker ?? MARKER_0003B, candidates: patchFiles.get(id) }));
/** heartbeat.js as the engine builds it from the pristine file with the package's heartbeat patches (0003b optional). */
function build(version, { with0003b }) {
  const r = buildFile({ rel: HB, pristine: pristine(version), steps: heartbeatSteps(discoverPatchFiles(SOURCE_PATCHES_DIR), { with0003b }), tmpDir: scratch });
  assert.equal(r.ok, true, r.reason);
  return r;
}
const blockOf = (content, opts = {}) => evalBlock(extractBlock(content.toString("utf8"), "0003"), "0003", { instanceRoot: freshDir(), ...opts });

const hermes = (storedExtra = {}) => ({ id: "agent-h", adapterType: "hermes_local", adapterConfig: { command: WRAPPER, ...storedExtra } });
const plain = (value) => ({ type: "plain", value });
const enforce = (b, agent, runtimeConfig, extra = {}) =>
  b.enforceStoredSandboxConfig({ agent, runId: "run-1", runtimeConfig, workspaceDirs: [], managedAi: false, ...extra });
const actions = (b) => b.warnings.map((w) => w.obj.action);

// The inputs a run-level override produces: issue assigneeAdapterOverrides, project/routine env or environment env merged
// into the agent's config (the stored values are what the board wrote).
const REDIRECTS = {
  HOME: "/evil/home", XDG_CONFIG_HOME: "/evil/cfg", XDG_DATA_HOME: "/evil/data", XDG_CACHE_HOME: "/evil/cache", XDG_STATE_HOME: "/evil/state",
  OPENCODE_CONFIG: "/evil/o.json", OPENCODE_CONFIG_DIR: "/evil/o", OPENCODE_CONFIG_CONTENT: "{}", OPENCODE_DISABLE_PROJECT_CONFIG: "false",
  GEMINI_CLI_HOME: "/evil/g", PI_CODING_AGENT_DIR: "/evil/pi", KIMI_CODE_HOME: "/evil/k", CURSOR_HOME: "/evil/c", CURSOR_DATA_DIR: "/evil/cd", HERMES_HOME: "/evil/h",
  PAPERCLIP_OPENCODE_PROVIDERS: "{\"x\":1}", PAPERCLIP_PI_PROVIDERS: "{}", PAPERCLIP_CODEX_PROVIDERS: "{}",
};
const boxed = (storedExtra = {}) => ({ id: "agent-b", adapterType: "opencode_local", adapterConfig: { filesystemScope: "workspace", networkScope: "allowlist", ...storedExtra } });

for (const version of VERSIONS) {
  test(`${version}: 0003b applies on the 0003 chain, adds its marker and changes no other file`, { skip }, () => {
    const patchFiles = discoverPatchFiles(SOURCE_PATCHES_DIR);
    assert.equal(patchFiles.get("0003b").length, 1, "one 0003b patch file serves every version");
    assert.equal(readPatchTarget(patchFiles.get("0003b")[0].file), HB);
    const before = build(version, { with0003b: false });
    const after = build(version, { with0003b: true });
    assert.deepEqual(after.used.map((u) => u.id).filter((id) => id !== "0003b"), before.used.map((u) => u.id));
    assert.ok(after.used.map((u) => u.id).indexOf("0003b") === after.used.map((u) => u.id).indexOf("0003") + 1, "0003b is applied right after 0003");
    assert.ok(!before.content.includes(MARKER_0003B));
    assert.ok(after.content.includes(MARKER_0003B));
  });

  test(`${version}: a boxed Hermes agent is enforced; a run override cannot widen HERMES_SANDBOX_ALLOW or change the command`, { skip }, async () => {
    const stored = hermes({ env: { HERMES_SANDBOX_ALLOW: plain("openrouter.ai"), KEEP: "1" } });
    const override = () => ({
      command: "/bin/sh", hermesCommand: "/tmp/evil", extraArgs: ["--yolo"], model: "x",
      env: { HERMES_SANDBOX_ALLOW: "openrouter.ai,evil.example", HERMES_SANDBOX_RO: "/", HERMES_SANDBOX_HOME: "/", HERMES_SANDBOX_PASS: "DATABASE_URL", HERMES_SANDBOX_BIN: "/bin/sh", HERMES_HOME: "/evil/h", KEEP: "1" },
    });
    const b = blockOf(build(version, { with0003b: true }).content);
    const out = await enforce(b, stored, override());
    assert.equal(out.command, WRAPPER, "command restored");
    assert.ok(!("hermesCommand" in out), "hermesCommand removed (not stored)");
    assert.ok(!("extraArgs" in out));
    assert.equal(out.model, "x", "non-enforced keys pass");
    assert.deepEqual(out.env, { HERMES_SANDBOX_ALLOW: "openrouter.ai", KEEP: "1" }, "the stored allow-list is restored; the other HERMES_SANDBOX_* and HERMES_HOME overrides are dropped");
    assert.ok(actions(b).includes("restore_env") && actions(b).includes("drop_env") && actions(b).includes("restore_config_key"));

    // The same call on the chain without 0003b passes everything through (that is what the patch fixes).
    const old = blockOf(build(version, { with0003b: false }).content);
    const same = await enforce(old, stored, override());
    assert.equal(same.command, "/bin/sh");
    assert.equal(same.env.HERMES_SANDBOX_ALLOW, "openrouter.ai,evil.example");
  });

  test(`${version}: Hermes values equal to the stored ones pass untouched; an agent that is not on the wrapper is left alone`, { skip }, async () => {
    const b = blockOf(build(version, { with0003b: true }).content);
    const stored = hermes({ env: { HERMES_SANDBOX_ALLOW: plain("openrouter.ai") } });
    const cfg = { command: WRAPPER, env: { HERMES_SANDBOX_ALLOW: "openrouter.ai", OPENROUTER_API_KEY: "dummy" } };
    assert.deepEqual(await enforce(b, stored, cfg), cfg);
    assert.deepEqual(actions(b), []);
    // Not the wrapper: 0005b refuses such an agent; 0003b does not pretend to confine it.
    for (const agent of [{ ...stored, adapterConfig: { command: "hermes" } }, { id: "x", adapterType: "hermes_local", adapterConfig: {} }, { ...stored, adapterType: "claude_local", adapterConfig: { command: WRAPPER } }]) {
      const input = { command: "/bin/sh", env: { HERMES_SANDBOX_ALLOW: "evil.example", HOME: "/evil" } };
      assert.equal(await enforce(b, agent, input), input, JSON.stringify(agent.adapterConfig));
    }
  });

  test(`${version}: the wrapper path comes from the hardening settings file when it names one`, { skip }, async () => {
    const root = freshDir();
    const file = path.join(root, "hardening", "config.json");
    fs.mkdirSync(path.dirname(file), { mode: 0o700 });
    fs.writeFileSync(file, JSON.stringify({ hermesWrapperPath: "/opt/site/hermes-box" }), { mode: 0o600 });
    const content = build(version, { with0003b: true }).content;
    const b = evalBlock(extractBlock(content.toString("utf8"), "0003"), "0003", { instanceRoot: root });
    assert.deepEqual(b.warnings, [], "the settings file is trusted here");
    const custom = { id: "a", adapterType: "hermes_local", adapterConfig: { command: "/opt/site/hermes-box" } };
    assert.equal((await enforce(b, custom, { command: "/bin/sh" })).command, "/opt/site/hermes-box");
    const dflt = { id: "a", adapterType: "hermes_local", adapterConfig: { command: WRAPPER } };
    const input = { command: "/bin/sh" };
    assert.equal(await enforce(b, dflt, input), input, "the default wrapper path is not the wrapper of this site");
  });

  test(`${version}: a run-level engine override cannot switch a boxed agent to acp; the stored engine is restored`, { skip }, async () => {
    const b = blockOf(build(version, { with0003b: true }).content);
    const claude = { id: "c", adapterType: "claude_local", adapterConfig: { filesystemScope: "workspace", engine: "cli" } };
    for (const engine of ["acp", "auto", "ACP", null, 7]) {
      const out = await enforce(b, claude, { filesystemScope: "workspace", engine });
      assert.equal(out.engine, "cli", JSON.stringify(engine));
    }
    assert.equal((await enforce(b, claude, { filesystemScope: "workspace", engine: "cli" })).engine, "cli");
    // Stored without an engine: the override is removed (the adapter default applies, and the adapter itself refuses acp under a scope).
    const noEngine = { id: "c", adapterType: "gemini_local", adapterConfig: { filesystemScope: "workspace" } };
    assert.ok(!("engine" in await enforce(b, noEngine, { filesystemScope: "workspace", engine: "acp" })));
    // Still enforced on the managed AI path.
    assert.equal((await enforce(b, claude, { filesystemScope: "workspace", engine: "acp" }, { managedAi: true })).engine, "cli");
    // Without 0003b the override goes through.
    const old = blockOf(build(version, { with0003b: false }).content);
    assert.equal((await enforce(old, claude, { filesystemScope: "workspace", engine: "acp" })).engine, "acp");
  });

  test(`${version}: HOME, XDG_*, OPENCODE_*, GEMINI/PI/KIMI/CURSOR homes and state dirs and PAPERCLIP_*_PROVIDERS overrides are dropped; the stored plain value is restored`, { skip }, async () => {
    const b = blockOf(build(version, { with0003b: true }).content);
    const stored = boxed({ env: { XDG_CONFIG_HOME: plain("/stored/cfg"), OPENROUTER_API_KEY: { type: "secret_ref", secretId: "s1" } } });
    const env = { ...REDIRECTS, OPENROUTER_API_KEY: "dummy-key", OPENCODE_AUTH_JSON: "{\"dummy\":1}", PAPERCLIP_RUN_ID: "r", FOO: "bar" };
    const out = await enforce(b, stored, { filesystemScope: "workspace", networkScope: "allowlist", env });
    assert.deepEqual(out.env, { XDG_CONFIG_HOME: "/stored/cfg", OPENROUTER_API_KEY: "dummy-key", OPENCODE_AUTH_JSON: "{\"dummy\":1}", PAPERCLIP_RUN_ID: "r", FOO: "bar" });
    for (const key of Object.keys(REDIRECTS).filter((k) => k !== "XDG_CONFIG_HOME"))
      assert.ok(b.warnings.some((w) => w.obj.action === "drop_env" && w.msg.includes(`env ${key}:`)), `${key} was dropped and logged`);
    assert.ok(b.warnings.some((w) => w.obj.action === "restore_env" && w.msg.includes("XDG_CONFIG_HOME")));

    // Values equal to the stored plain ones are the board's own and stay.
    const own = boxed({ env: { HOME: plain("/board/home"), PAPERCLIP_PI_PROVIDERS: plain("{\"p\":1}") } });
    const keep = { filesystemScope: "workspace", networkScope: "allowlist", env: { HOME: "/board/home", PAPERCLIP_PI_PROVIDERS: "{\"p\":1}" } };
    assert.deepEqual(await enforce(b, own, keep), keep);

    // Without 0003b every redirect reaches the CLI.
    const old = blockOf(build(version, { with0003b: false }).content);
    const leaked = await enforce(old, stored, { filesystemScope: "workspace", networkScope: "allowlist", env });
    for (const key of Object.keys(REDIRECTS)) assert.equal(leaked.env[key], REDIRECTS[key], `${key} reaches the CLI on v0.1.x`);
  });

  test(`${version}: the managed AI connection path keeps exactly the names managedAiHomeEnvironment sets; every other state or routing name is dropped there too`, { skip }, async () => {
    const b = blockOf(build(version, { with0003b: true }).content);
    // What managedAiHomeEnvironment (services/ai-connection-runtime.js) sets: HOME, XDG_CONFIG_HOME, XDG_DATA_HOME, CODEX_HOME, GROK_HOME, CLAUDE_CONFIG_DIR.
    const managed = {
      HOME: "/tmp/paperclip-ai-c-g-abc", XDG_CONFIG_HOME: "/tmp/paperclip-ai-c-g-abc/config", XDG_DATA_HOME: "/tmp/paperclip-ai-c-g-abc/data",
      CODEX_HOME: "/tmp/paperclip-ai-c-g-abc/provider", GROK_HOME: "/tmp/paperclip-ai-c-g-abc/provider", CLAUDE_CONFIG_DIR: "/tmp/paperclip-ai-c-g-abc/provider",
    };
    const cfg = { filesystemScope: "workspace", networkScope: "allowlist", managedAiConnection: { identity: "i" }, env: { ...managed, FOO: "bar" } };
    const out = await enforce(b, boxed(), cfg, { managedAi: true });
    assert.deepEqual(out.env, cfg.env);
    assert.deepEqual(actions(b), []);
    // The same values on a run without a server-created home are redirects and go.
    const plainRun = await enforce(b, boxed(), { filesystemScope: "workspace", networkScope: "allowlist", env: managed });
    assert.deepEqual(Object.keys(plainRun.env), []);
    // Anything else that moves the state or the provider routing is not the server's: dropped on the managed path too (before, every
    // XDG_*, OPENCODE_* and PAPERCLIP_*_PROVIDERS name was exempt there, so a run-level value could reach a managed run).
    const others = { XDG_CACHE_HOME: "/x/cache", XDG_STATE_HOME: "/x/state", OPENCODE_CONFIG: "/x/oc.json", OPENCODE_CONFIG_DIR: "/x/oc", OPENCODE_CONFIG_CONTENT: "{\"provider\":{}}",
      PAPERCLIP_OPENCODE_PROVIDERS: "x", PAPERCLIP_PI_PROVIDERS: "x", HERMES_HOME: "/x/h", GEMINI_CLI_HOME: "/x/g" };
    const mixed = await enforce(b, boxed(), { ...cfg, env: { ...managed, ...others, FOO: "bar" } }, { managedAi: true });
    assert.deepEqual(mixed.env, { ...managed, FOO: "bar" });
    for (const key of Object.keys(others)) assert.ok(b.warnings.some((w) => w.obj.action === "drop_env" && w.msg.includes(`env ${key}:`)), `${key} logged as dropped`);
    // The SANDBOX/LD_/NODE_OPTIONS rules of 0003 still apply on the managed path.
    const bad = await enforce(b, boxed(), { filesystemScope: "workspace", networkScope: "allowlist", env: { ...managed, NODE_OPTIONS: "--require /x" } }, { managedAi: true });
    assert.deepEqual(Object.keys(bad.env).sort(), Object.keys(managed).sort());
  });

  test(`${version}: a run-level PAPERCLIP_API_URL or PAPERCLIP_RUNTIME_TOOLS_* value is dropped (it would reach the box's trusted URLs); the stored value is restored`, { skip }, async () => {
    const b = blockOf(build(version, { with0003b: true }).content);
    const evil = {
      PAPERCLIP_API_URL: "https://evil.example:443", PAPERCLIP_RUNTIME_TOOLS_MCP_URL: "https://evil.example/mcp", PAPERCLIP_RUNTIME_TOOLS_CONNECTIONS_SEARCH_URL: "https://evil.example/c",
      PAPERCLIP_RUNTIME_TOOLS_CONNECTION_REQUEST_URL: "https://evil.example/r", PAPERCLIP_RUNTIME_TOOLS_TOKEN: "x", PAPERCLIP_RUNTIME_TOOLS_GUIDANCE: "x",
    };
    const cfg = (env) => ({ filesystemScope: "workspace", networkScope: "allowlist", env: { OPENROUTER_API_KEY: "dummy-key", ...env } });
    for (const managedAi of [false, true]) {
      const out = await enforce(b, boxed(), cfg(evil), { managedAi });
      assert.deepEqual(out.env, { OPENROUTER_API_KEY: "dummy-key" }, `managedAi ${managedAi}: none of them survives`);
      for (const key of Object.keys(evil)) assert.ok(b.warnings.some((w) => w.obj.action === "drop_env" && w.msg.includes(`env ${key}:`)), `${key} logged`);
    }
    // The board's own stored plain value is restored, and a run value equal to it stays.
    const stored = boxed({ env: { PAPERCLIP_API_URL: plain("http://10.0.0.5:3100") } });
    assert.equal((await enforce(b, stored, cfg({ PAPERCLIP_API_URL: "https://evil.example:443" }))).env.PAPERCLIP_API_URL, "http://10.0.0.5:3100");
    const same = cfg({ PAPERCLIP_API_URL: "http://10.0.0.5:3100" });
    assert.deepEqual(await enforce(b, stored, same), same);
    // The same for a boxed Hermes agent.
    const h = await enforce(b, hermes(), { command: WRAPPER, env: { ...evil, KEEP: "1" } });
    assert.deepEqual(h.env, { KEEP: "1" });
    // Other PAPERCLIP_ names (run ids and the like) are not touched; without 0003b all of it goes through.
    assert.equal((await enforce(b, boxed(), cfg({ PAPERCLIP_RUN_ID: "r" }))).env.PAPERCLIP_RUN_ID, "r");
    const old = blockOf(build(version, { with0003b: false }).content);
    assert.equal((await enforce(old, boxed(), cfg(evil))).env.PAPERCLIP_API_URL, "https://evil.example:443");
  });

  test(`${version}: the workspace roots are published once for the box helper (frozen, not writable); evaluating the block leaves the real global alone`, { skip }, () => {
    const KEY = Symbol.for("paperclip.hardening.workspaceRoots");
    const content = build(version, { with0003b: true }).content;
    const b = blockOf(content, { env: { PAPERCLIP_SANDBOX_WORKSPACE_ROOT: "/srv/a:relative:/srv/b/" } });
    const d = Object.getOwnPropertyDescriptor(b.globals, KEY);
    assert.deepEqual([...d.value], ["/srv/a", "/srv/b"], "the roots 0003 enforces");
    assert.ok(Object.isFrozen(d.value));
    assert.deepEqual({ writable: d.writable, configurable: d.configurable, enumerable: d.enumerable }, { writable: false, configurable: false, enumerable: false });
    assert.deepEqual(b.SANDBOX_WORKSPACE_ROOTS, [...d.value]);
    // With a settings file the roots come from it, like 0003's own list.
    const root = freshDir();
    fs.mkdirSync(path.join(root, "hardening"), { mode: 0o700 });
    fs.writeFileSync(path.join(root, "hardening", "config.json"), JSON.stringify({ workspaceRoots: ["/srv/site-root"] }), { mode: 0o600 });
    assert.deepEqual([...Object.getOwnPropertyDescriptor(evalBlock(extractBlock(content.toString("utf8"), "0003"), "0003", { instanceRoot: root }).globals, KEY).value], ["/srv/site-root"]);
    assert.equal(Object.getOwnPropertyDescriptor(globalThis, KEY), undefined, "the block never writes the real globalThis");
    // Not published by the chain without 0003b.
    assert.equal(Object.getOwnPropertyDescriptor(blockOf(build(version, { with0003b: false }).content).globals, KEY), undefined);
  });

  test(`${version}: an earlier, different roots value on the global makes the server refuse to start; the same value (a second copy of the module) is fine`, { skip }, () => {
    const KEY = Symbol.for("paperclip.hardening.workspaceRoots");
    const content = build(version, { with0003b: true }).content;
    const code = extractBlock(content.toString("utf8"), "0003");
    const lock = (globals, value, over = {}) => Object.defineProperty(globals, KEY, { value, writable: false, configurable: false, enumerable: false, ...over });
    const env = { PAPERCLIP_SANDBOX_WORKSPACE_ROOT: "/srv/a" };
    // the same roots published earlier: accepted
    assert.deepEqual([...Object.getOwnPropertyDescriptor(evalBlock(code, "0003", { env, instanceRoot: freshDir(), globals: lock({}, Object.freeze(["/srv/a"])) }).globals, KEY).value], ["/srv/a"]);
    // different roots, a longer or shorter list, a non-array: the roots the box helper mounts would not be the ones enforced here
    const refuse = (globals, why) => assert.throws(() => evalBlock(code, "0003", { env, instanceRoot: freshDir(), globals }), /workspace roots/i, why);
    refuse(lock({}, Object.freeze(["/srv/other"])), "different value");
    refuse(lock({}, Object.freeze(["/srv/a", "/srv/b"])), "longer");
    refuse(lock({}, Object.freeze([])), "empty");
    refuse(lock({}, "/srv/a"), "not an array");
    // an earlier value that was still configurable is simply replaced by the enforced roots, locked
    const replaced = Object.getOwnPropertyDescriptor(evalBlock(code, "0003", { env, instanceRoot: freshDir(), globals: lock({}, ["/srv/elsewhere"], { writable: true, configurable: true }) }).globals, KEY);
    assert.deepEqual([...replaced.value], ["/srv/a"]);
    assert.deepEqual({ writable: replaced.writable, configurable: replaced.configurable }, { writable: false, configurable: false });
  });

  test(`${version}: drift - the env names 0005a removes at creation are exactly the names the spawn-time enforcement drops from a run`, { skip }, async () => {
    const b = blockOf(build(version, { with0003b: true }).content);
    const a = evalBlock(blockFromPatchFile(path.join(SOURCE_PATCHES_DIR, "0005a-new-agent-safe-defaults.patch"), "0005a"), "0005a", { instanceRoot: freshDir() });
    // The state names come from the profile table (every profile's stateEnv, the common HOME/XDG ones) so a new profile
    // cannot add a redirect that only one of the two rules knows; the rest is a fixed list of shapes both rules must agree on.
    const stateNames = [...new Set([...COMMON_STATE_ENV, ...Object.values(BOX_PROFILES).flatMap((p) => p.stateEnv)])];
    const credentialNames = [...new Set(Object.values(BOX_PROFILES).flatMap((p) => p.credentialEnvNames))];
    assert.ok(stateNames.includes("CURSOR_DATA_DIR") && stateNames.length > 15, "the profile table feeds the list");
    const names = [...new Set([...stateNames, ...credentialNames, ...Object.keys(REDIRECTS), "HERMES_SANDBOX_ALLOW", "HERMES_SANDBOX_PASS", "HERMES_SANDBOX_HOME", "HERMES_SANDBOX_RO", "HERMES_SANDBOX_BIN", "sandbox_x", "BWRAP_ARGS", "bwrap_x",
      "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "GLIBC_TUNABLES", "NODE_OPTIONS", "NODE_PATH", "NODE_ENV", "BASH_ENV", "ENV", "http_proxy", "HTTPS_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "PROXY_URL",
      "CLAUDE_CONFIG_DIR", "CODEX_HOME", "GROK_HOME", "OPENCODE_AUTH_JSON", "OPENCODE_MODEL", "XDG_RUNTIME_DIR", "XDG_X", "PAPERCLIP_API_URL", "PAPERCLIP_API_KEY", "PAPERCLIP_RUNTIME_TOOLS_MCP_URL",
      "PAPERCLIP_RUNTIME_TOOLS_TOKEN", "PAPERCLIP_RUN_ID", "PAPERCLIP_FOO_PROVIDERS", "PAPERCLIP_PROVIDERS", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "KEEP", "HOMEBREW_X", "MYHOME"])];
    for (const [pathValue, flagged] of [["/usr/bin:/bin", false], ["/evil/bin", true], ["/usr/bin:/home/x", true], ["relative", true]]) {
      const out = await enforce(b, boxed(), { filesystemScope: "workspace", env: { PATH: pathValue } });
      const kept = a.applyNewAgentSafeDefaults("opencode_local", { env: { PATH: { type: "plain", value: pathValue } } }, {}, "create").adapterConfig.env;
      assert.equal("PATH" in out.env, !flagged, `0003 PATH=${pathValue}`);
      assert.equal("PATH" in kept, !flagged, `0005a PATH=${pathValue}`);
    }
    for (const key of names) {
      const out = await enforce(b, boxed(), { filesystemScope: "workspace", env: { [key]: "value" } });
      const kept = a.applyNewAgentSafeDefaults("opencode_local", { env: { [key]: { type: "plain", value: "value" } } }, {}, "create").adapterConfig.env;
      assert.equal(key in kept, key in out.env, `${key}: 0005a ${key in kept ? "keeps" : "removes"} it, the enforcement ${key in out.env ? "keeps" : "drops"} it`);
      // and not only equal: a state dir is never kept by either (the box sets it per agent), a credential name always is
      if (stateNames.includes(key)) assert.equal(key in out.env, false, `${key} is a state redirect: dropped from a run`);
      if (credentialNames.includes(key)) assert.equal(key in out.env, true, `${key} is a credential: kept`);
    }
  });

  test(`${version}: agents without any box are not touched (0005b refuses them separately)`, { skip }, async () => {
    const b = blockOf(build(version, { with0003b: true }).content);
    const input = { env: { HOME: "/x", XDG_CONFIG_HOME: "/x" }, engine: "acp" };
    assert.equal(await enforce(b, { id: "u", adapterType: "opencode_local", adapterConfig: { model: "m" } }, input), input);
  });
}

// ---------- upgrade from the v0.1.1 release
// The v0.1.1 patch files come from git; the install is made by the engine with them, then 0003b is added to the own-box
// protection (as the release that enables the new switch will do) and the engine rebuilds from the stored pristine file.
function releasePatches() {
  const git = (args, encoding = "utf8") => spawnSync("git", args, { cwd: SOURCE_PATCHES_DIR, encoding, maxBuffer: 64 * 1024 * 1024 });
  const listing = git(["ls-tree", "--name-only", "v0.1.1", "./"]);
  if (listing.status !== 0) return null;
  const dir = path.join(scratch, "v011-patches");
  fs.mkdirSync(dir, { recursive: true });
  for (const name of listing.stdout.split("\n").filter((x) => x.endsWith(".patch"))) {
    const blob = git(["show", `v0.1.1:./${path.basename(name)}`], "buffer");
    if (blob.status !== 0) return null;
    fs.writeFileSync(path.join(dir, path.basename(name)), blob.stdout);
  }
  return dir;
}
const releaseDir = VERSIONS.length ? releasePatches() : null;
// The v0.1.1 engine itself (its registry knows nothing of the new patches), to make the state a v0.1.1 install left.
const oldPackage = VERSIONS.length ? v011Package() : { skip: "no versions" };
test.after(() => { if (oldPackage.dir) fs.rmSync(oldPackage.dir, { recursive: true, force: true }); });
const completeInstall = (version) => releaseDir && [...new Set([...discoverPatchFiles(releaseDir).values()].flat().map((f) => readPatchTarget(f.file)))]
  .every((rel) => pristineOrNull(stockRoot(version), rel));

for (const version of VERSIONS) {
  const skipUpgrade = skip || oldPackage.skip || (!releaseDir ? "no v0.1.1 tag in git history" : !completeInstall(version) ? `NO PRISTINE: ${version} has no original for every file the v0.1.1 release patches (set PAPERCLIP_STOCK_TREE_${version.split(".")[1]} to an untouched install)` : false);
  test(`${version}: upgrade from v0.1.1 - 0003b added to an applied v0.1.1 engine state applies cleanly`, { skip: skipUpgrade }, async () => {
    const dir = freshDir();
    // A tree holding the files the release patches target (pristine .orig of the installed version).
    const patchFilesOld = discoverPatchFiles(releaseDir);
    // the files the v0.1.1 release patches, and the ones this package adds (box-claude needs the adapter files to be there)
    const targets = [...new Set([...patchFilesOld.values(), ...discoverPatchFiles(SOURCE_PATCHES_DIR).values()].flat().map((f) => readPatchTarget(f.file)))];
    const treeDir = path.join(dir, "tree");
    const installRoot = stockRoot(version);
    for (const rel of targets) {
      fs.mkdirSync(path.dirname(path.join(treeDir, rel)), { recursive: true });
      fs.writeFileSync(path.join(treeDir, rel), pristineOrNull(installRoot, rel));
    }
    const pj = "node_modules/@paperclipai/server/package.json";
    fs.mkdirSync(path.dirname(path.join(treeDir, pj)), { recursive: true });
    fs.copyFileSync(path.join(installRoot, pj), path.join(treeDir, pj));
    const options = (patchesDir) => ({ treeDir, dataDir: path.join(dir, "data"), patchesDir, tmpDir: scratch, systemctl: null });

    // 1. the v0.1.1 install: its registry, its patch files, every protection of that release on.
    const everyOn = [...V011_DEFAULTS];
    assert.ok(everyOn.every((id) => PROTECTIONS.some((p) => p.id === id)));
    const v011 = (await importV011Engine(oldPackage, `0003b-${version}`)).createEngine(options(releaseDir));
    const first = await v011.apply(await v011.plan(everyOn));
    assert.equal(first.ok, true, first.error);
    assert.deepEqual(first.unavailable, {}, "the v0.1.1 release applies everything on this version");
    const installed = fs.readFileSync(path.join(treeDir, HB));
    assert.ok(installed.includes("// LOCAL-PATCH 0003") && !installed.includes(MARKER_0003B));

    // 2. this package (own-box now carries 0003b) on the same tree and data dir: the saved switches are the v0.1.1 ones.
    const upgraded = createEngine(options(SOURCE_PATCHES_DIR));
    const plan = await upgraded.plan(everyOn);
    assert.deepEqual(plan.unavailable, {}, "nothing becomes unavailable");
    const heartbeat = plan.files.find((f) => f.rel === HB);
    assert.equal(heartbeat.change, true);
    assert.deepEqual(heartbeat.patches.map((u) => u.id).filter((id) => ["0003", "0003b", "0005b"].includes(id)), ["0003", "0003b", "0005b"]);
    assert.equal(plan.protections.find((p) => p.id === "own-box").action, "will-apply", "own-box gained a patch, so it is applied again (and waits for the restart)");
    const second = await upgraded.apply(plan);
    assert.equal(second.ok, true, second.error);
    const after = fs.readFileSync(path.join(treeDir, HB));
    assert.ok(after.includes(MARKER_0003B));
    // Same result as building from the pristine file with the new chain.
    assert.ok(after.equals(build(version, { with0003b: true }).content));
    // And the behaviour of the rebuilt file is the new one.
    const b = blockOf(after);
    assert.equal((await enforce(b, hermes(), { command: "/bin/sh" })).command, WRAPPER);
  });
}

// Without the engine's help (a hand-patched install): 0003b on top of the finished v0.1.1 heartbeat.js, after 0005b and 0006a.
for (const version of VERSIONS) {
  test(`${version}: 0003b also fits on top of the finished v0.1.1 heartbeat.js`, { skip: skip || (releaseDir ? false : "no v0.1.1 tag in git history") }, async () => {
    const old = discoverPatchFiles(releaseDir);
    const steps = [...old.keys()].filter((id) => PATCHES[id] && readPatchTarget(old.get(id)[0].file) === HB).sort(comparePatchIds)
      .map((id) => ({ id, marker: PATCHES[id].marker, candidates: old.get(id) }));
    assert.deepEqual(steps.map((x) => x.id), ["0003", "0005b", "0006a"]);
    const v011 = buildFile({ rel: HB, pristine: pristine(version), steps, tmpDir: scratch });
    assert.equal(v011.ok, true, v011.reason);
    const onTop = buildFile({
      rel: HB, pristine: v011.content, tmpDir: scratch,
      steps: [{ id: "0003b", marker: MARKER_0003B, candidates: discoverPatchFiles(SOURCE_PATCHES_DIR).get("0003b") }],
    });
    assert.equal(onTop.ok, true, onTop.reason);
    assert.equal((await enforce(blockOf(onTop.content), hermes(), { command: "/bin/sh" })).command, WRAPPER);
  });
}
