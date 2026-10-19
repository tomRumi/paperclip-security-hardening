// Patches 0003 and 0005a read the site values from the hardening settings file. These tests evaluate the code blocks
// the package patches add (test/helpers/patch-block.mjs) against settings files written by the plugin's own writer.
// The last test compares them with the live patches (~/setup/paperclip-patches, read only; skipped when absent).
//   HARDENING_LIVE_PATCHES  live patch dir (default ~/setup/paperclip-patches)
//   HARDENING_TEST_SCRATCH  scratch parent dir (default: the OS temp dir)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { blockFromPatchFile, evalBlock } from "./helpers/patch-block.mjs";
import { haveLiveSettings, liveSettings } from "./helpers/live-settings.mjs";
import { writeHardeningConfig, normalizeSettings } from "../src/settings.js";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LIVE = process.env.HARDENING_LIVE_PATCHES ?? path.join(os.homedir(), "setup", "paperclip-patches");
const P0003 = "0003-spawn-time-sandbox-enforcement.patch";
const P0005A = ["0005a-new-agent-safe-defaults.patch", "0005a-new-agent-safe-defaults.1012.patch"];

const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patched-config-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
let n = 0;
const freshRoot = () => { const d = path.join(scratch, `root-${++n}`); fs.mkdirSync(d); return d; };

const pkg0003 = () => blockFromPatchFile(path.join(SOURCE_PATCHES_DIR, P0003), "0003");
const pkg0005a = (name = P0005A[1]) => blockFromPatchFile(path.join(SOURCE_PATCHES_DIR, name), "0005a");
const creator = {
  claude: { filesystemScope: null, networkScope: "allowlist", networkAllowlist: ["*:443", "evil.example"], filesystemExtraPaths: ["/"], model: "x" },
  hermes: { command: "hermes", env: { HERMES_SANDBOX_RO: { type: "plain", value: "/" }, HERMES_SANDBOX_ALLOW: "evil.example", KEEP: "1" } },
};

test("both 0005a variants add the same block", () => {
  assert.equal(pkg0005a(P0005A[0]), pkg0005a(P0005A[1]));
});

test("no settings file: secure generic defaults", () => {
  const root = freshRoot();
  const b3 = evalBlock(pkg0003(), "0003", { instanceRoot: root });
  assert.deepEqual(b3.SANDBOX_WORKSPACE_ROOTS, [path.join(root, "workspaces"), path.join(root, "projects")]);
  const b5 = evalBlock(pkg0005a(), "0005a", { instanceRoot: root });
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS, {
    canCreateAgents: false, filesystemScope: "workspace", filesystemSandboxCommand: "/usr/bin/bwrap", filesystemExtraPaths: [],
    networkScope: "allowlist", networkAllowlist: ["api.anthropic.com"], hermesCommand: "/usr/local/bin/hermes-sandbox",
    hermesSandboxAllow: "openrouter.ai", hermesSandboxRo: null,
  });
  assert.deepEqual([...b3.warnings, ...b5.warnings], [], "a missing file is not worth a warning");
  // Creator-supplied values are still overridden; with no Hermes read-only setting the wrapper keeps its own default.
  const c = b5.applyNewAgentSafeDefaults("claude_local", creator.claude, { canCreateAgents: true, canCreateSkills: true }, "create");
  assert.deepEqual(c.adapterConfig, { ...creator.claude, filesystemScope: "workspace", filesystemSandboxCommand: "/usr/bin/bwrap", filesystemExtraPaths: [], networkScope: "allowlist", networkAllowlist: ["api.anthropic.com"] });
  assert.deepEqual(c.permissions, { canCreateAgents: false, canCreateSkills: false });
  const hm = b5.applyNewAgentSafeDefaults("hermes_local", creator.hermes, {}, "create").adapterConfig;
  assert.equal(hm.command, "/usr/local/bin/hermes-sandbox");
  assert.deepEqual(hm.env, { HERMES_SANDBOX_ALLOW: { type: "plain", value: "openrouter.ai" }, KEEP: "1" });
});

test("no settings file: PAPERCLIP_SANDBOX_WORKSPACE_ROOT still works as before", () => {
  const b3 = evalBlock(pkg0003(), "0003", { instanceRoot: freshRoot(), env: { PAPERCLIP_SANDBOX_WORKSPACE_ROOT: "/srv/a:relative:/srv/b/" } });
  assert.deepEqual(b3.SANDBOX_WORKSPACE_ROOTS, ["/srv/a", "/srv/b"]);
});

test("settings file at <instance root>/hardening/config.json, written by the plugin's writer, is used", () => {
  const root = freshRoot();
  const settings = { baseAllowlist: ["api.anthropic.com", "10.0.0.5:3100"], extraReadOnlyPaths: ["/opt/tools"], workspaceRoots: ["/srv/projects"],
    hermesWrapperPath: "/opt/bin/hermes-box", hermesAllowlist: ["openrouter.ai", "10.0.0.5:3100"], hermesReadOnlyPaths: ["/opt/hermes"] };
  const w = writeHardeningConfig(settings, { file: path.join(root, "hardening", "config.json") });
  assert.equal(w.changed, true);
  const env = { PAPERCLIP_SANDBOX_WORKSPACE_ROOT: "/ignored/when/the/file/sets/roots" };
  assert.deepEqual(evalBlock(pkg0003(), "0003", { instanceRoot: root, env }).SANDBOX_WORKSPACE_ROOTS, ["/srv/projects"]);
  const b5 = evalBlock(pkg0005a(), "0005a", { instanceRoot: root });
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.networkAllowlist, ["api.anthropic.com", "10.0.0.5:3100"]);
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.filesystemExtraPaths, ["/opt/tools"]);
  const hm = b5.applyNewAgentSafeDefaults("hermes_local", creator.hermes, {}, "create").adapterConfig;
  assert.equal(hm.command, "/opt/bin/hermes-box");
  assert.deepEqual(hm.env.HERMES_SANDBOX_ALLOW, { type: "plain", value: "openrouter.ai,10.0.0.5:3100" });
  assert.deepEqual(hm.env.HERMES_SANDBOX_RO, { type: "plain", value: "/opt/hermes" });
});

test("$PAPERCLIP_HARDENING_CONFIG wins over the instance root; an empty setting falls back to the default", () => {
  const root = freshRoot();
  writeHardeningConfig({ baseAllowlist: ["from-instance-root.example"] }, { file: path.join(root, "hardening", "config.json") });
  const other = path.join(root, "elsewhere.json");
  writeHardeningConfig({ baseAllowlist: [], extraReadOnlyPaths: ["/x"] }, { file: other });
  const b5 = evalBlock(pkg0005a(), "0005a", { instanceRoot: root, env: { PAPERCLIP_HARDENING_CONFIG: other } });
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.networkAllowlist, ["api.anthropic.com"]);
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.filesystemExtraPaths, ["/x"]);
  const b3 = evalBlock(pkg0003(), "0003", { instanceRoot: root, env: { PAPERCLIP_HARDENING_CONFIG: other } });
  assert.deepEqual(b3.SANDBOX_WORKSPACE_ROOTS, [path.join(root, "workspaces"), path.join(root, "projects")]);
});

test("an unreadable or malformed settings file gives the defaults and a warning", () => {
  for (const content of ["{not json", "[1,2]"]) {
    const root = freshRoot();
    fs.mkdirSync(path.join(root, "hardening"));
    fs.writeFileSync(path.join(root, "hardening", "config.json"), content);
    const b5 = evalBlock(pkg0005a(), "0005a", { instanceRoot: root });
    assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.networkAllowlist, ["api.anthropic.com"]);
    assert.equal(b5.warnings.length, 1);
    assert.equal(b5.warnings[0].obj.event, "hardening_config");
    const b3 = evalBlock(pkg0003(), "0003", { instanceRoot: root });
    assert.deepEqual(b3.SANDBOX_WORKSPACE_ROOTS, [path.join(root, "workspaces"), path.join(root, "projects")]);
    assert.equal(b3.warnings.length, 1);
  }
});

test("with the live install's settings the package patches behave exactly like the live patches", { skip: !haveLiveSettings(LIVE) && "no live patch dir" }, async () => {
  const { settings, errors } = normalizeSettings(liveSettings(LIVE));
  assert.deepEqual(errors, []);
  const root = freshRoot();
  writeHardeningConfig(settings, { file: path.join(root, "hardening", "config.json") });
  const env = {};
  const live5 = evalBlock(blockFromPatchFile(path.join(LIVE, P0005A[1]), "0005a"), "0005a", { env });
  const pkg5 = evalBlock(pkg0005a(), "0005a", { instanceRoot: root, env });
  assert.deepEqual(pkg5.NEW_AGENT_SAFE_DEFAULTS, live5.NEW_AGENT_SAFE_DEFAULTS);
  for (const [type, cfg] of [["claude_local", creator.claude], ["hermes_local", creator.hermes], ["codex_local", { model: "m" }], ["hermes_local", {}]])
    assert.deepEqual(pkg5.applyNewAgentSafeDefaults(type, cfg, { canAssignTasks: true }, "create"), live5.applyNewAgentSafeDefaults(type, cfg, { canAssignTasks: true }, "create"), type);
  const live3 = evalBlock(blockFromPatchFile(path.join(LIVE, P0003), "0003"), "0003", { env });
  const pkg3 = evalBlock(pkg0003(), "0003", { instanceRoot: root, env });
  assert.deepEqual(pkg3.SANDBOX_WORKSPACE_ROOTS, live3.SANDBOX_WORKSPACE_ROOTS);
  // Same enforcement result for a run inside and one outside the roots.
  const agent = { id: "a1", adapterConfig: { filesystemScope: "workspace", networkScope: "allowlist", networkAllowlist: ["api.anthropic.com"], env: {} } };
  const input = (cwd) => ({ agent, runId: "r1", runtimeConfig: { networkAllowlist: ["*:443"], cwd, env: { LD_PRELOAD: "/x.so", FOO: "1" } }, workspaceDirs: [], managedAi: false });
  const inside = path.join(settings.workspaceRoots[0], "some-project");
  assert.deepEqual(await pkg3.enforceStoredSandboxConfig(input(inside)), await live3.enforceStoredSandboxConfig(input(inside)));
  await assert.rejects(pkg3.enforceStoredSandboxConfig(input("/etc")), /outside the allowed workspace roots/);
  await assert.rejects(live3.enforceStoredSandboxConfig(input("/etc")), /outside the allowed workspace roots/);
});
