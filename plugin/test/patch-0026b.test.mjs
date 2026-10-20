// Patches 0026b (adapter-claude-local test.js) and 0026c (acp.js): the "Test environment" hello probes of a claude agent.
// They run the trusted server `claude` UNBOXED; before, in the working directory of the request, where an agent can plant project
// settings (.claude/settings.json, settings.local.json) with hooks that "claude --print" executes as the service user, and with the
// CLAUDE_CONFIG_DIR of the request, whose settings.json hooks run too. Which config is tested comes from the request alone (an agent
// without scopes in it looks "unboxed"), so now EVERY local probe loads the user settings only (--setting-sources user), runs in an empty
// private temp directory and drops a CLAUDE_CONFIG_DIR that is not the managed AI connection's home. (It is not run in the box: the
// Test also runs before an agent exists, so there is no agent runtime dir to mount.)
// The tests plant hook files in the workspace and in a config dir and run the REAL patched probe with the real `claude` CLI found on PATH
// (skipped when there is none): the hook would write a marker; fail-before is the chain without 0026b/0026c, where the marker appears.
//   PAPERCLIP_STOCK_TREE_<vkey>  install to read   HARDENING_TEST_SCRATCH  scratch parent dir
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { discoverPatchFiles, readPatchTarget, buildFile } from "../src/engine/patches.js";
import { noPristineSkip, pristineOrNull, stockTreePath } from "./helpers/pristine.mjs";
import { ADAPTERS, buildPatchedTree, importFromTree, makeWorld } from "./helpers/adapter-harness.mjs";

const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0026b-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
const versions = ["1012", "1005"].filter((v) => fs.existsSync(stockTreePath(v)));
const noVersion = versions.length ? false : "no Paperclip install found (set PAPERCLIP_STOCK_TREE_1012)";
const claudeOnPath = (process.env.PATH ?? "").split(path.delimiter).some((d) => d && fs.existsSync(path.join(d, "claude")));
const noClaude = claudeOnPath ? false : "no `claude` CLI on PATH (the probes run the trusted server claude)";
const TARGETS = { "0026b": "node_modules/@paperclipai/adapter-claude-local/dist/server/test.js", "0026c": "node_modules/@paperclipai/adapter-claude-local/dist/server/acp.js" };

const trees = new Map();
async function treeFor(version, upTo) {
  const key = `${version}/${upTo}`;
  if (!trees.has(key)) trees.set(key, await buildPatchedTree({ version, upTo, packages: [ADAPTERS.claude_local.pkg], scratch }));
  return trees.get(key);
}

/** A boxed agent's workspace with planted project settings whose hooks touch `marker` (outside the workspace and any box). */
function plant(world, marker) {
  const hook = (event) => ({ [event]: [{ hooks: [{ type: "command", command: `touch ${JSON.stringify(marker)}` }] }] });
  fs.mkdirSync(path.join(world.workspace, ".claude"), { recursive: true });
  fs.writeFileSync(path.join(world.workspace, ".claude", "settings.json"), JSON.stringify({ hooks: { ...hook("SessionStart"), ...hook("UserPromptSubmit") } }));
  fs.writeFileSync(path.join(world.workspace, ".claude", "settings.local.json"), JSON.stringify({ hooks: hook("SessionStart") }));
}
/** A Claude config dir (the CLAUDE_CONFIG_DIR of the request) whose user-level settings.json has a hook that touches `marker`. */
function plantConfigDir(dir, marker) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "settings.json"), JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: "command", command: `touch ${JSON.stringify(marker)}` }] }] } }));
  return dir;
}
/** Like plantConfigDir, but the hook writes the CLAUDE_CONFIG_DIR the probe was started with into `file`. */
function plantEnvRecorder(dir, file) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "settings.json"), JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: "command", command: `printf %s "$CLAUDE_CONFIG_DIR" > ${JSON.stringify(file)}` }] }] } }));
  return dir;
}
const probeDirs = () => fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith("paperclip-claude-probe-")).length;
const BOXED = { filesystemScope: "workspace", networkScope: "allowlist", networkAllowlist: ["api.anthropic.com"], engine: "cli", helloProbeTimeoutSec: 25, env: { CLAUDE_CODE_OAUTH_TOKEN: "fake-token-for-tests" } };

/** Run `fn` with the server env a probe sees: a scratch HOME (the real claude writes its state there). */
async function withProbeEnv(world, fn) {
  const saved = { ...process.env };
  Object.assign(process.env, { HOME: path.join(world.root, "svc-home"), PAPERCLIP_HOME: world.paperclipHome, PAPERCLIP_INSTANCE_ID: "test" });
  fs.mkdirSync(process.env.HOME, { recursive: true });
  try { return await fn(); } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
}

for (const version of versions) {
  const V = (name) => `${version}: ${name}`;
  const opts = { skip: noVersion || noClaude, timeout: 180_000 };

  test(V("0026b: the Test environment probe of a boxed agent does not run hooks planted in its workspace (fail-before: it does)"), opts, async (t) => {
    const [pre, post] = [await treeFor(version, "0026"), await treeFor(version, "0026c")];
    if (pre.skip) return t.skip(pre.skip);
    const run = async (tree, config = BOXED) => {
      const world = makeWorld(tree);
      const marker = path.join(world.root, "marker");
      plant(world, marker);
      const mod = await importFromTree(tree, "adapter-claude-local/dist/server/index.js");
      const result = await withProbeEnv(world, () => mod.testEnvironment({ companyId: world.companyId, adapterType: "claude_local", config: { ...config, cwd: world.workspace } }));
      return { marker: fs.existsSync(marker), result, world };
    };
    const old = await run(pre);
    assert.equal(old.marker, true, "fail-before: the planted project hook ran as the service user");
    const dirsBefore = probeDirs();
    const now = await run(post);
    assert.equal(now.marker, false, "the planted hook did not run");
    assert.ok(now.result.checks.some((c) => c.code.startsWith("claude_hello_probe")), `the probe itself still ran: ${now.result.checks.map((c) => c.code)}`);
    assert.equal(probeDirs(), dirsBefore, "the private probe directory is removed");
    // A request without any scope is hardened the same: the request alone says "unboxed", so it cannot be what keeps the hooks out
    // (before, an agent that omitted the scopes from the config got the workspace's hooks run).
    const unscoped = { engine: "cli", helloProbeTimeoutSec: 25, env: BOXED.env };
    assert.equal((await run(pre, unscoped)).marker, true, "fail-before: an unscoped request ran the workspace's hooks");
    const unscopedNow = await run(post, unscoped);
    assert.equal(unscopedNow.marker, false, "an unscoped request does not run them either");
    assert.ok(unscopedNow.result.checks.some((c) => c.code.startsWith("claude_hello_probe")), "and the probe still ran");
  });

  test(V("0026b: a CLAUDE_CONFIG_DIR in the request is not loaded (an agent writes that folder); the managed AI connection's own home still is"), opts, async (t) => {
    const [pre, post] = [await treeFor(version, "0026"), await treeFor(version, "0026c")];
    if (pre.skip) return t.skip(pre.skip);
    const run = async (tree, configDir, extra = {}) => {
      const world = makeWorld(tree);
      const marker = path.join(world.root, "marker");
      const dir = typeof configDir === "function" ? configDir(world, marker) : plantConfigDir(path.join(world.workspace, ".claude-home"), marker);
      const mod = await importFromTree(tree, "adapter-claude-local/dist/server/index.js");
      const config = { ...BOXED, cwd: world.workspace, ...extra, env: { ...BOXED.env, CLAUDE_CONFIG_DIR: dir } };
      const result = await withProbeEnv(world, () => mod.testEnvironment({ companyId: world.companyId, adapterType: "claude_local", config }));
      return { marker: fs.existsSync(marker), result };
    };
    assert.equal((await run(pre)).marker, true, "fail-before: the hooks of the requested config dir ran as the service user");
    const now = await run(post);
    assert.equal(now.marker, false, "the hooks of the requested config dir did not run");
    assert.ok(now.result.checks.some((c) => c.code.startsWith("claude_hello_probe")), "the probe itself still ran");
    // The credential home the server makes for a managed AI connection of this company (<tmp>/paperclip-ai-<company>-<grant>-*/provider) is kept...
    const managedHome = (company) => (world, marker) => {
      const home = fs.mkdtempSync(path.join(os.tmpdir(), `paperclip-ai-${company ?? world.companyId}-grant1-`));
      t.after(() => fs.rmSync(home, { recursive: true, force: true }));
      return plantConfigDir(path.join(home, "provider"), marker);
    };
    assert.equal((await run(post, managedHome(), { managedAiConnection: { identity: "i" } })).marker, true, "the managed home is used as the server made it");
    // ...but only for a managed request, and only the one of this company.
    assert.equal((await run(post, managedHome())).marker, false, "a lookalike folder without a managed connection is dropped");
    assert.equal((await run(post, managedHome("00000000-0000-4000-8000-0000000000ff"), { managedAiConnection: { identity: "i" } })).marker, false, "another company's managed home is dropped");
    // The home the server makes is private (mkdtemp: mode 0700, owned by the server's user). A lookalike others can enter is dropped, and
    // so is one owned by another user (not testable here without root: the check is `st.uid === process.getuid()`).
    const modeHome = (mode) => (world, marker) => {
      const home = fs.mkdtempSync(path.join(os.tmpdir(), `paperclip-ai-${world.companyId}-grant1-`));
      fs.chmodSync(home, mode);
      t.after(() => fs.rmSync(home, { recursive: true, force: true }));
      return plantConfigDir(path.join(home, "provider"), marker);
    };
    assert.equal((await run(post, modeHome(0o700), { managedAiConnection: { identity: "i" } })).marker, true, "mode 0700 is the server's own");
    assert.equal((await run(post, modeHome(0o755), { managedAiConnection: { identity: "i" } })).marker, false, "a home others can enter is dropped");
    assert.equal((await run(post, modeHome(0o770), { managedAiConnection: { identity: "i" } })).marker, false, "so is a group-writable one");
    // The probe gets the REAL path, not the string of the request (a link in the request could point elsewhere by the time claude reads it).
    const viaLink = (tree) => {
      const world = makeWorld(tree);
      const recorded = path.join(world.root, "recorded-dir");
      const home = fs.mkdtempSync(path.join(os.tmpdir(), `paperclip-ai-${world.companyId}-grant1-`));
      t.after(() => fs.rmSync(home, { recursive: true, force: true }));
      plantEnvRecorder(path.join(home, "provider"), recorded);
      const link = path.join(world.workspace, "provider-link");
      fs.symlinkSync(path.join(home, "provider"), link);
      return { world, recorded, link, real: fs.realpathSync(path.join(home, "provider")) };
    };
    for (const [tree, label] of [[pre, "fail-before (0026 only)"], [post, "with 0026b"]]) {
      const c = viaLink(tree);
      const mod = await importFromTree(tree, "adapter-claude-local/dist/server/index.js");
      await withProbeEnv(c.world, () => mod.testEnvironment({ companyId: c.world.companyId, adapterType: "claude_local", config: { ...BOXED, cwd: c.world.workspace, managedAiConnection: { identity: "i" }, env: { ...BOXED.env, CLAUDE_CONFIG_DIR: c.link } } }));
      if (tree === pre) assert.equal(fs.existsSync(c.recorded) ? fs.readFileSync(c.recorded, "utf8") : null, c.link, `${label}: the request's own string is used`);
      else assert.equal(fs.existsSync(c.recorded) ? fs.readFileSync(c.recorded, "utf8") : null, c.real, `${label}: the real path is used`);
    }
  });

  test(V("0026c: the ACP login probe of a boxed agent does not run hooks planted in its workspace (fail-before: it does)"), opts, async (t) => {
    const [pre, post] = [await treeFor(version, "0026"), await treeFor(version, "0026c")];
    if (pre.skip) return t.skip(pre.skip);
    const run = async (tree) => {
      const world = makeWorld(tree);
      const marker = path.join(world.root, "marker");
      plant(world, marker);
      const mod = await importFromTree(tree, "adapter-claude-local/dist/server/acp.js");
      const checks = await withProbeEnv(world, () => mod.probeClaudeAcpSandboxLogin({ config: { ...BOXED, cwd: world.workspace }, target: null }));
      return { marker: fs.existsSync(marker), checks };
    };
    assert.equal((await run(pre)).marker, true, "fail-before: the planted project hook ran as the service user");
    const dirsBefore = probeDirs();
    const now = await run(post);
    assert.equal(now.marker, false, "the planted hook did not run");
    assert.equal(probeDirs(), dirsBefore, "the private probe directory is removed");
    // a request without scopes is hardened too, and so is its CLAUDE_CONFIG_DIR
    const unscoped = async (tree) => {
      const world = makeWorld(tree);
      const marker = path.join(world.root, "marker");
      plant(world, marker);
      const dir = plantConfigDir(path.join(world.workspace, ".claude-home"), path.join(world.root, "marker"));
      const mod = await importFromTree(tree, "adapter-claude-local/dist/server/acp.js");
      await withProbeEnv(world, () => mod.probeClaudeAcpSandboxLogin({ config: { helloProbeTimeoutSec: 25, cwd: world.workspace, env: BOXED.env }, env: { ...BOXED.env, CLAUDE_CONFIG_DIR: dir }, target: null, companyId: world.companyId }));
      return fs.existsSync(marker);
    };
    assert.equal(await unscoped(pre), true, "fail-before: an unscoped request ran the hooks");
    assert.equal(await unscoped(post), false, "an unscoped request with a planted config dir does not");
    const configDirOnly = async (tree, managed) => {
      const world = makeWorld(tree);
      const marker = path.join(world.root, "marker");
      let dir = path.join(world.workspace, ".claude-home");
      if (managed) { const home = fs.mkdtempSync(path.join(os.tmpdir(), `paperclip-ai-${world.companyId}-grant1-`)); t.after(() => fs.rmSync(home, { recursive: true, force: true })); dir = path.join(home, "provider"); }
      plantConfigDir(dir, marker);
      const mod = await importFromTree(tree, "adapter-claude-local/dist/server/acp.js");
      await withProbeEnv(world, () => mod.probeClaudeAcpSandboxLogin({ config: { ...BOXED, cwd: world.workspace, ...(managed ? { managedAiConnection: { identity: "i" } } : {}) }, env: { ...BOXED.env, CLAUDE_CONFIG_DIR: dir }, target: null, companyId: world.companyId }));
      return fs.existsSync(marker);
    };
    assert.equal(await configDirOnly(pre, false), true, "fail-before: the requested config dir's hooks ran");
    assert.equal(await configDirOnly(post, false), false, "the requested config dir is dropped");
    assert.equal(await configDirOnly(post, true), true, "the managed AI connection's home is kept");
    // a lookalike home that others can enter is dropped
    const looseHome = async (tree) => {
      const world = makeWorld(tree);
      const marker = path.join(world.root, "marker");
      const home = fs.mkdtempSync(path.join(os.tmpdir(), `paperclip-ai-${world.companyId}-grant1-`));
      fs.chmodSync(home, 0o755);
      t.after(() => fs.rmSync(home, { recursive: true, force: true }));
      const dir = plantConfigDir(path.join(home, "provider"), marker);
      const mod = await importFromTree(tree, "adapter-claude-local/dist/server/acp.js");
      await withProbeEnv(world, () => mod.probeClaudeAcpSandboxLogin({ config: { ...BOXED, cwd: world.workspace, managedAiConnection: { identity: "i" } }, env: { ...BOXED.env, CLAUDE_CONFIG_DIR: dir }, target: null, companyId: world.companyId }));
      return fs.existsSync(marker);
    };
    assert.equal(await looseHome(post), false, "a managed-looking home with mode 0755 is dropped");
  });
}

test("0026b and 0026c each change one file and apply (GNU patch -F0) on every available version", { skip: noVersion }, async (t) => {
  const patchFiles = discoverPatchFiles(SOURCE_PATCHES_DIR);
  for (const [id, rel] of Object.entries(TARGETS)) {
    assert.equal(patchFiles.get(id)?.length, 1, `${id}: one patch file serves every version`);
    assert.equal(readPatchTarget(patchFiles.get(id)[0].file), rel);
    for (const version of versions) {
      const pristine = pristineOrNull(stockTreePath(version), rel);
      if (!pristine) { t.diagnostic(noPristineSkip(stockTreePath(version), [rel], version)); continue; }
      const r = buildFile({ rel, pristine, steps: [{ id, marker: `// LOCAL-PATCH ${id}`, candidates: patchFiles.get(id) }], tmpDir: scratch });
      assert.equal(r.ok, true, `${version} ${id}: ${r.reason}`);
      const dir = fs.mkdtempSync(path.join(scratch, "dry-"));
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), pristine);
      const d = spawnSync("patch", ["-p1", "-N", "-F0", "--batch", "--dry-run", "-s", "-d", dir, "-i", patchFiles.get(id)[0].file], { encoding: "utf8" });
      assert.equal(d.status, 0, `${version} ${id}: ${d.stdout}${d.stderr}`);
    }
  }
});
