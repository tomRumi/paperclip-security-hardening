// 0005a (both variants) starts every NEW agent of a scoped local type boxed from a per-type profile table: scopes,
// /usr/bin/bwrap, the network allowlist (settings baseAllowlists[type], else the profile's default hosts; claude_local keeps
// baseAllowlist) and engine "cli" for the types whose default engine is an ACP lane the box cannot reach. The table in the
// patch must equal BOX_PROFILES (src/profiles.js). The patch's code block is evaluated as the other 0005a tests do.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { addedText, extractBlock, evalBlock, blockFromPatchFile } from "./helpers/patch-block.mjs";
import { writeHardeningConfig } from "../src/settings.js";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { BOX_PROFILES, COMMON_STATE_ENV, SCOPED_TYPES, defaultHostsFor } from "../src/profiles.js";

const VARIANTS = ["0005a-new-agent-safe-defaults.patch", "0005a-new-agent-safe-defaults.1012.patch"];
const CLI_TYPES = ["claude_local", "codex_local", "gemini_local", "kimi_local"];
const OTHER_SCOPED = ["opencode_local", "cursor", "pi_local", "grok_local"];

const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0005a-profiles-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
let n = 0;
const freshRoot = () => { const d = path.join(scratch, `root-${++n}`); fs.mkdirSync(d, { mode: 0o700 }); return d; };
const blockOf = (name) => blockFromPatchFile(path.join(SOURCE_PATCHES_DIR, name), "0005a");
/** The patched code with the settings file at <root>/hardening/config.json (written by the plugin's own writer). */
function withSettings(name, settings) {
  const root = freshRoot();
  if (settings) writeHardeningConfig(settings, { file: path.join(root, "hardening", "config.json"), instanceRoot: root });
  return evalBlock(blockOf(name), "0005a", { instanceRoot: root });
}
const hostile = { filesystemScope: null, filesystemSandboxCommand: "/bin/sh", filesystemExtraPaths: ["/"], networkScope: "open", networkAllowlist: ["*:443", "evil.example"], model: "m", env: { KEEP: "1" } };
const defaults = (b, type, cfg = hostile, source = "create") => b.applyNewAgentSafeDefaults(type, cfg, { canCreateAgents: true, canCreateSkills: true }, source);

test("the profile table has every scoped local type and nothing else of the plugin's profiles", () => {
  assert.deepEqual([...SCOPED_TYPES].sort(), [...CLI_TYPES, ...OTHER_SCOPED].sort());
});

for (const name of VARIANTS) {
  for (const type of SCOPED_TYPES) {
    test(`${name}: a new ${type} agent starts boxed with its own allowlist; creator scope values are ignored`, () => {
      const b = withSettings(name, null);
      for (const source of ["create", "approval_activation"]) {
        const r = defaults(b, type, hostile, source);
        const c = r.adapterConfig;
        assert.equal(c.filesystemScope, "workspace");
        assert.equal(c.filesystemSandboxCommand, "/usr/bin/bwrap");
        assert.deepEqual(c.filesystemExtraPaths, []);
        assert.equal(c.networkScope, "allowlist");
        assert.deepEqual(c.networkAllowlist, defaultHostsFor(type), "profile default hosts");
        assert.equal(c.networkAllowlist.includes("*:443"), false);
        assert.equal(c.model, "m", "other keys are kept");
        assert.deepEqual(c.env, { KEEP: "1" });
        assert.deepEqual(r.permissions, { canCreateAgents: false, canCreateSkills: false });
      }
    });

    test(`${name}: ${type} engine ${BOX_PROFILES[type].engineCli ? "is always cli, whatever the creator sent" : "is not touched"}`, () => {
      const b = withSettings(name, null);
      const engineOf = (cfg) => defaults(b, type, cfg).adapterConfig.engine;
      if (BOX_PROFILES[type].engineCli) {
        assert.equal(engineOf({ model: "x" }), "cli", "unset");
        for (const v of ["auto", "AUTO", "", "  ", "bogus", null, 7, true, {}, [], "cli", "CLI ", "acp", " ACP ", "Acp"]) assert.equal(engineOf({ engine: v }), "cli", JSON.stringify(v));
        assert.equal(engineOf(undefined), "cli", "no adapterConfig at all");
        assert.equal(defaults(b, type, { engine: "acp" }, "approval_activation").adapterConfig.engine, "cli", "approval path");
      } else {
        assert.equal("engine" in defaults(b, type, { model: "x" }).adapterConfig, false, "no engine key is added");
        assert.equal(engineOf({ engine: "whatever" }), "whatever");
      }
    });

    test(`${name}: ${type} allowlist comes from the settings file`, () => {
      const hosts = ["settings.example", "10.0.0.5:3100"];
      const settings = type === "claude_local" ? { baseAllowlist: hosts } : { baseAllowlists: { [type]: hosts } };
      assert.deepEqual(defaults(withSettings(name, settings), type).adapterConfig.networkAllowlist, hosts);
      // Another type's entry does not leak into this one.
      const other = SCOPED_TYPES.find((t) => t !== type && t !== "claude_local");
      const b = withSettings(name, { baseAllowlist: ["claude.example"], baseAllowlists: { [other]: ["other.example"] }, extraReadOnlyPaths: ["/opt/tools"] });
      const c = defaults(b, type).adapterConfig;
      assert.deepEqual(c.networkAllowlist, type === "claude_local" ? ["claude.example"] : type === other ? ["other.example"] : defaultHostsFor(type));
      assert.deepEqual(c.filesystemExtraPaths, ["/opt/tools"], "extra read-only paths apply to every scoped type");
    });
  }

  test(`${name}: baseAllowlists never touches claude_local, and an untrusted settings file leaves the profile defaults`, () => {
    const root = freshRoot();
    const file = path.join(root, "hardening", "config.json");
    fs.mkdirSync(path.dirname(file), { mode: 0o700 });
    fs.writeFileSync(file, JSON.stringify({ baseAllowlists: { claude_local: ["x.example"], codex_local: ["codex.example"] } }), { mode: 0o644 });
    fs.chmodSync(file, 0o644); // wrong mode: ignored as a whole
    const b = evalBlock(blockOf(name), "0005a", { instanceRoot: root });
    assert.deepEqual(b.warnings.map((w) => w.obj.action), ["ignore_hardening_config"]);
    for (const type of SCOPED_TYPES) assert.deepEqual(defaults(b, type).adapterConfig.networkAllowlist, defaultHostsFor(type), type);
    fs.chmodSync(file, 0o600);
    const ok = evalBlock(blockOf(name), "0005a", { instanceRoot: root });
    assert.deepEqual(defaults(ok, "claude_local").adapterConfig.networkAllowlist, ["api.anthropic.com"], "claude_local reads baseAllowlist only");
    assert.deepEqual(defaults(ok, "codex_local").adapterConfig.networkAllowlist, ["codex.example"]);
  });

  test(`${name}: results are fresh copies, and types outside the table are left alone`, () => {
    const b = withSettings(name, null);
    const first = defaults(b, "codex_local").adapterConfig;
    first.networkAllowlist.push("mutated.example");
    first.filesystemExtraPaths.push("/mutated");
    const second = defaults(b, "codex_local").adapterConfig;
    assert.deepEqual(second.networkAllowlist, ["api.openai.com"]);
    assert.deepEqual(second.filesystemExtraPaths, []);
    for (const type of ["cursor_cloud", "openclaw_gateway", "hermes_gateway", "http", "process", "paperclip_runner", "acpx_local", "some_plugin", "__proto__", "constructor", "toString", undefined, null, 7]) {
      const r = defaults(b, type, { model: "m", filesystemScope: null });
      assert.deepEqual(r.adapterConfig, { model: "m", filesystemScope: null }, String(type));
      assert.deepEqual(r.permissions, { canCreateAgents: false, canCreateSkills: false });
    }
    // hermes_local is still boxed by the wrapper, not by scopes.
    const hm = defaults(b, "hermes_local", { env: {} }).adapterConfig;
    assert.equal(hm.command, "/usr/local/bin/hermes-sandbox");
    assert.equal("filesystemScope" in hm, false);
    assert.equal("engine" in hm, false);
  });
}

// ---------- creator-supplied env: names the spawn-time enforcement would drop are removed at creation
// (the enforcement trusts a run value equal to the STORED value, so a stored CODEX_HOME=~/.codex, HERMES_SANDBOX_PASS=DATABASE_URL
// or HERMES_SANDBOX_HOME would stay valid for every later run)
const plainBinding = (value) => ({ type: "plain", value });
const UNSAFE_ENV = {
  HERMES_SANDBOX_ALLOW: plainBinding("evil.example"), HERMES_SANDBOX_PASS: plainBinding("DATABASE_URL"), HERMES_SANDBOX_HOME: plainBinding("/"), HERMES_SANDBOX_RO: plainBinding("/"),
  HERMES_SANDBOX_BIN: plainBinding("/bin/sh"), HERMES_HOME: plainBinding("/home/user/.hermes"), HOME: plainBinding("/home/user"), XDG_CONFIG_HOME: "/home/user/.config", XDG_DATA_HOME: plainBinding("/x"),
  OPENCODE_CONFIG: plainBinding("/x/o.json"), OPENCODE_CONFIG_DIR: plainBinding("/x"), OPENCODE_CONFIG_CONTENT: plainBinding("{}"), CODEX_HOME: plainBinding("/home/user/.codex"),
  CLAUDE_CONFIG_DIR: plainBinding("/home/user/.claude"), GROK_HOME: plainBinding("/home/user/.grok"), GEMINI_CLI_HOME: plainBinding("/x"), PI_CODING_AGENT_DIR: plainBinding("/x"),
  KIMI_CODE_HOME: plainBinding("/x"), CURSOR_HOME: plainBinding("/x"), PAPERCLIP_OPENCODE_PROVIDERS: plainBinding("{}"), PAPERCLIP_API_URL: plainBinding("https://evil.example:443"),
  PAPERCLIP_RUNTIME_TOOLS_MCP_URL: plainBinding("https://evil.example/mcp"), NODE_OPTIONS: plainBinding("--require /x.js"), NODE_PATH: plainBinding("/x"), NODE_EXTRA_CA_CERTS: plainBinding("/x.pem"), PAPERCLIP_ADAPTER_UTILS: plainBinding("/evil/m.js"), LD_PRELOAD: plainBinding("/x.so"),
  GLIBC_TUNABLES: plainBinding("glibc.malloc.check=3"), BASH_ENV: plainBinding("/x"), ENV: plainBinding("/x"), PATH: plainBinding("/home/user/bin"), http_proxy: plainBinding("http://evil:3128"),
  HTTPS_PROXY: plainBinding("http://evil:3128"), BWRAP_ARGS: plainBinding("--bind / /"),
};
const SAFE_ENV = {
  ANTHROPIC_API_KEY: { type: "secret_ref", secretId: "s1", version: "latest" }, OPENAI_API_KEY: plainBinding("sk-dummy"), OPENCODE_AUTH_JSON: plainBinding("{}"), PAPERCLIP_RUN_ID: "r",
  CLAUDE_CODE_OAUTH_TOKEN: { type: "secret_ref", secretId: "s2" }, KEEP: "1", PATH: plainBinding("/usr/bin:/bin:/opt/tools/bin"),
};
for (const name of VARIANTS) {
  for (const type of [...SCOPED_TYPES, "hermes_local"]) {
    test(`${name}: a new ${type} agent loses creator-supplied env that moves its home, config, endpoints or sandbox; credentials stay`, () => {
      const b = withSettings(name, null);
      const logs = (r) => b.warnings.filter((w) => w.obj.event === "new_agent_defaults");
      for (const source of ["create", "approval_activation"]) {
        b.warnings.length = 0;
        const r = defaults(b, type, { model: "m", env: { ...UNSAFE_ENV, ...SAFE_ENV } }, source);
        const expected = { ...SAFE_ENV };
        if (type === "hermes_local") expected.HERMES_SANDBOX_ALLOW = plainBinding("openrouter.ai"); // the defaults themselves, set after the removal
        assert.deepEqual(r.adapterConfig.env, expected, `${source}: only the credentials and harmless names remain`);
        assert.equal(r.adapterConfig.model, "m");
        const [log] = logs();
        assert.deepEqual([...log.obj.droppedEnv].sort(), Object.keys(UNSAFE_ENV).filter((k) => k !== "PATH").sort(), "the log names the removed variables (SAFE_ENV overrides PATH with a system-only one)");
        assert.ok(!JSON.stringify(log.obj).includes("DATABASE_URL") && !JSON.stringify(log.obj).includes("evil.example"), "names only, never values");
      }
      // nothing to remove: no droppedEnv field, env kept as given (copy)
      b.warnings.length = 0;
      const clean = { KEEP: "1", ANTHROPIC_API_KEY: { type: "secret_ref", secretId: "s1" } };
      const r2 = defaults(b, type, { env: clean });
      assert.equal(logs()[0].obj.droppedEnv, undefined);
      if (type !== "hermes_local") assert.deepEqual(r2.adapterConfig.env, clean);
      // no env at all, or one that is not a record, does not break creation
      for (const env of [undefined, null, "x", [], 7]) assert.doesNotThrow(() => defaults(b, type, env === undefined ? {} : { env }), JSON.stringify(env));
    });
  }

  test(`${name}: a PATH inside the system directories is kept, anything else (or a secret reference) goes`, () => {
    const b = withSettings(name, null);
    const pathOf = (binding) => defaults(b, "opencode_local", { env: { PATH: binding } }).adapterConfig.env;
    assert.deepEqual(pathOf(plainBinding("/usr/local/bin:/usr/bin")), { PATH: plainBinding("/usr/local/bin:/usr/bin") }, "/usr/local is below /usr");
    assert.deepEqual(pathOf("/bin"), { PATH: "/bin" });
    for (const bad of [plainBinding("/home/u/bin"), plainBinding("/usr/bin:/tmp/x"), plainBinding("relative/bin"), plainBinding("/usr/../tmp"), { type: "secret_ref", secretId: "s" }, plainBinding(7), null, 7])
      assert.deepEqual(pathOf(bad), {}, JSON.stringify(bad));
  });
}

// ---------- drift: the table in the patch equals profiles.js
function tableOf(name) {
  const code = extractBlock(addedText(fs.readFileSync(path.join(SOURCE_PATCHES_DIR, name), "utf8")), "0005a");
  const m = /^const NEW_AGENT_BOX_PROFILES = (\{\n[\s\S]*?\n\});$/m.exec(code);
  assert.ok(m, `${name}: no NEW_AGENT_BOX_PROFILES table`);
  return new Function(`"use strict"; return (${m[1]});`)();
}

for (const name of VARIANTS) {
  test(`${name}: its profile table equals BOX_PROFILES (types, engineCli, default hosts)`, () => {
    const table = tableOf(name);
    assert.deepEqual(Object.keys(table).sort(), [...SCOPED_TYPES].sort(), "same boxed types");
    for (const type of SCOPED_TYPES) {
      assert.deepEqual(Object.keys(table[type]).sort(), ["engineCli", "hosts"], type);
      assert.equal(table[type].engineCli, BOX_PROFILES[type].engineCli, `${type}: engineCli`);
      assert.deepEqual(table[type].hosts, [...BOX_PROFILES[type].defaultHosts], `${type}: hosts`);
    }
  });
}

// Every state-redirect name of a profile is one a new agent may not store: 0005a removes it from a creator's env.
for (const name of VARIANTS) {
  test(`${name}: every stateEnv and COMMON_STATE_ENV name of a boxed profile is removed from a creator's env; credentials are kept`, () => {
    const b = withSettings(name, null);
    for (const type of SCOPED_TYPES) {
      const p = BOX_PROFILES[type];
      const env = Object.fromEntries([...p.stateEnv, ...COMMON_STATE_ENV].map((k) => [k, { type: "plain", value: "/evil" }]));
      for (const k of p.credentialEnvNames) env[k] = { type: "plain", value: "v" };
      const kept = defaults(b, type, { env }).adapterConfig.env;
      assert.deepEqual(Object.keys(kept).sort(), [...p.credentialEnvNames].sort(), type);
    }
  });
}

test("both 0005a variants carry the same profile table", () => {
  assert.deepEqual(tableOf(VARIANTS[0]), tableOf(VARIANTS[1]));
});
