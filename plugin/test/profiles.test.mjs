// Adapter type profiles (src/profiles.js).
import test from "node:test";
import assert from "node:assert/strict";
import { BOX_PROFILES, COMMON_STATE_ENV, EXCEPTIONABLE_TYPES, SCOPED_TYPES, defaultHostsFor, isExceptionableType, isScopedType, profileFor } from "../src/profiles.js";

const FIELDS = ["acpLane", "boxEnv", "credentialEnvNames", "defaultHosts", "engineCli", "exceptionable", "installTreeReadOnly", "scopes", "stateEnv"];

test("every profile has exactly the documented fields with the right shapes", () => {
  for (const [type, p] of Object.entries(BOX_PROFILES)) {
    assert.deepEqual(Object.keys(p).sort(), FIELDS, type);
    for (const k of ["acpLane", "engineCli", "exceptionable", "installTreeReadOnly", "scopes"]) assert.equal(typeof p[k], "boolean", `${type}.${k}`);
    for (const k of ["credentialEnvNames", "defaultHosts", "stateEnv"]) {
      assert.ok(Array.isArray(p[k]) && p[k].every((v) => typeof v === "string" && v), `${type}.${k}`);
      assert.equal(new Set(p[k]).size, p[k].length, `${type}.${k} has duplicates`);
    }
    assert.ok(p.credentialEnvNames.every((n) => /^[A-Z][A-Z0-9_]*$/.test(n)), `${type} credential names`);
    assert.ok(p.stateEnv.every((n) => /^[A-Z][A-Z0-9_]*$/.test(n) && !COMMON_STATE_ENV.includes(n)), `${type} state env`);
    assert.ok(p.boxEnv && typeof p.boxEnv === "object" && !Array.isArray(p.boxEnv), `${type}.boxEnv is a record`);
    for (const [k, v] of Object.entries(p.boxEnv)) assert.ok(/^[A-Z][A-Z0-9_]*$/.test(k) && typeof v === "string" && v, `${type}.boxEnv.${k}`);
    assert.ok(!Object.keys(p.boxEnv).some((k) => COMMON_STATE_ENV.includes(k) || p.stateEnv.includes(k) || p.credentialEnvNames.includes(k)), `${type}: boxEnv is neither state nor credential`);
    assert.ok(!p.installTreeReadOnly || p.scopes, `${type}: only a boxed type mounts an install tree`);
    assert.ok(!p.exceptionable || !p.scopes, `${type}: a boxed type cannot also be exempted`);
    assert.ok(!p.engineCli || p.acpLane, `${type}: only a type with an ACP lane needs engine cli`);
  }
});

test("the local CLI types are boxed through scopes; claude, codex, gemini and kimi need engine cli", () => {
  assert.deepEqual([...SCOPED_TYPES], ["claude_local", "codex_local", "opencode_local", "gemini_local", "cursor", "pi_local", "kimi_local", "grok_local"]);
  assert.deepEqual(SCOPED_TYPES.filter((t) => BOX_PROFILES[t].engineCli), ["claude_local", "codex_local", "gemini_local", "kimi_local"]);
  assert.deepEqual(SCOPED_TYPES.filter((t) => BOX_PROFILES[t].acpLane), ["claude_local", "codex_local", "gemini_local", "kimi_local"]);
  assert.equal(BOX_PROFILES.hermes_local.scopes, false, "hermes is boxed by the wrapper, not by scopes");
  assert.equal(BOX_PROFILES.hermes_local.exceptionable, false);
});

test("claude_local keeps its v0.1.x values", () => {
  assert.deepEqual(defaultHostsFor("claude_local"), ["api.anthropic.com"]);
  assert.deepEqual(BOX_PROFILES.claude_local.stateEnv, ["CLAUDE_CONFIG_DIR"]);
  assert.ok(BOX_PROFILES.claude_local.credentialEnvNames.includes("CLAUDE_CODE_OAUTH_TOKEN"));
  assert.deepEqual(BOX_PROFILES.codex_local.stateEnv, ["CODEX_HOME"]);
  assert.deepEqual(BOX_PROFILES.hermes_local.defaultHosts, ["openrouter.ai"]);
});

test("only remote, gateway and process types can be exempted; nothing else, nothing unknown", () => {
  assert.deepEqual([...EXCEPTIONABLE_TYPES], ["cursor_cloud", "openclaw_gateway", "hermes_gateway", "http", "process"]);
  for (const t of EXCEPTIONABLE_TYPES) {
    assert.equal(isExceptionableType(t), true);
    assert.equal(isScopedType(t), false);
    assert.deepEqual(BOX_PROFILES[t].defaultHosts, []);
  }
  for (const t of [...SCOPED_TYPES, "hermes_local", "paperclip_runner", "acpx_local", "my_plugin_adapter", "", undefined, null, 5, "__proto__", "constructor", "toString"]) {
    assert.equal(isExceptionableType(t), false, String(t));
  }
});

test("profileFor: null for an unknown type, also for names that exist on every object", () => {
  for (const t of ["paperclip_runner", "acpx_local", "unknown", "__proto__", "constructor", "hasOwnProperty", "", undefined, null, {}]) assert.equal(profileFor(t), null, String(t));
  assert.equal(profileFor("cursor"), BOX_PROFILES.cursor);
  assert.equal(profileFor("cursor_local"), null, "the cursor type is named `cursor`");
  assert.deepEqual(defaultHostsFor("nope"), []);
});

test("the tables cannot be changed by a caller", () => {
  assert.ok(Object.isFrozen(BOX_PROFILES) && Object.isFrozen(BOX_PROFILES.claude_local) && Object.isFrozen(BOX_PROFILES.claude_local.defaultHosts));
  assert.throws(() => { "use strict"; BOX_PROFILES.claude_local.defaultHosts.push("evil.example"); }, TypeError);
  const hosts = defaultHostsFor("claude_local");
  hosts.push("evil.example");
  assert.deepEqual(defaultHostsFor("claude_local"), ["api.anthropic.com"], "defaultHostsFor returns a copy");
  assert.throws(() => { SCOPED_TYPES.push("x"); }, TypeError);
});

test("host defaults are plain hosts (no wildcard, no *:443) so they pass the settings validation", async () => {
  const { validHost } = await import("../src/settings.js");
  for (const [type, p] of Object.entries(BOX_PROFILES)) for (const h of p.defaultHosts) assert.equal(validHost(h), true, `${type}: ${h}`);
});

test("T0 values: no placeholder is left; credentials, state, fixed env and install-tree flag per type", () => {
  const cred = (t) => BOX_PROFILES[t].credentialEnvNames;
  assert.deepEqual(cred("codex_local"), ["CODEX_API_KEY"], "codex exec 0.163.0 ignores OPENAI_API_KEY");
  assert.deepEqual(cred("kimi_local"), ["KIMI_MODEL_API_KEY", "KIMI_MODEL_NAME"]);
  assert.deepEqual(cred("gemini_local"), ["GEMINI_API_KEY", "GOOGLE_API_KEY"]);
  assert.deepEqual(cred("grok_local"), ["XAI_API_KEY"]);
  assert.deepEqual(cred("cursor"), ["CURSOR_API_KEY"]);
  assert.deepEqual(cred("opencode_local"), ["OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]);
  assert.deepEqual(cred("pi_local"), ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "XAI_API_KEY", "OPENROUTER_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY", "DEEPSEEK_API_KEY"]);
  assert.deepEqual(BOX_PROFILES.cursor.stateEnv, ["CURSOR_DATA_DIR"], "the measured redirect, not the placeholder CURSOR_HOME");
  assert.deepEqual(BOX_PROFILES.gemini_local.stateEnv, ["GEMINI_CLI_HOME"]);
  assert.deepEqual(BOX_PROFILES.kimi_local.stateEnv, ["KIMI_CODE_HOME"]);
  assert.deepEqual(BOX_PROFILES.grok_local.stateEnv, ["GROK_HOME"]);
  assert.deepEqual(BOX_PROFILES.pi_local.stateEnv, ["PI_CODING_AGENT_DIR", "PAPERCLIP_PI_PROVIDERS"]);
  assert.deepEqual(BOX_PROFILES.gemini_local.boxEnv, { GEMINI_CLI_TRUST_WORKSPACE: "true" });
  assert.deepEqual(BOX_PROFILES.kimi_local.boxEnv, { CI: "1", NO_COLOR: "1", KIMI_CODE_NO_AUTO_UPDATE: "1", KIMI_DISABLE_TELEMETRY: "1" });
  assert.equal(BOX_PROFILES.opencode_local.boxEnv.OPENCODE_DISABLE_MODELS_FETCH, "1");
  assert.equal(BOX_PROFILES.pi_local.boxEnv.PI_SKIP_VERSION_CHECK, "1");
  for (const t of ["claude_local", "codex_local", "cursor", "grok_local", "hermes_local"]) assert.deepEqual(BOX_PROFILES[t].boxEnv, {}, t);
  assert.deepEqual(SCOPED_TYPES.filter((t) => BOX_PROFILES[t].installTreeReadOnly), ["codex_local", "pi_local", "kimi_local"], "the CLIs whose sibling packages the stock mounts miss");
  assert.deepEqual(defaultHostsFor("cursor"), ["api2.cursor.sh"]);
  for (const t of ["gemini_local", "kimi_local", "grok_local", "codex_local"]) assert.equal(defaultHostsFor(t).length, 1, t);
  assert.deepEqual(defaultHostsFor("opencode_local"), ["openrouter.ai", "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"], "opencode: the common LLM provider hosts, not one provider");
  assert.deepEqual(defaultHostsFor("pi_local"), [], "pi_local: the operator adds the provider host");
  const telemetry = ["play.googleapis.com", "telemetry-logs.kimi.com", "registry.npmjs.org", "api3.cursor.sh", "chatgpt.com", "github.com", "api.github.com"];
  for (const t of SCOPED_TYPES) for (const h of telemetry) assert.equal(defaultHostsFor(t).includes(h), false, `${t}: ${h}`);
});
