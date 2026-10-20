// Patch 0017 (adapter-utils local-process-sandbox.js): the shared helper that boxes every local adapter
// (boxedSandboxOptions, BASE_ENV_ALLOW, ensureBoxedRuntimeDir, registerBoxedAdapter, ENGINE_CLI_TYPES, the home + instance mount guard) and the structured
// log line of a denied proxy target. Built from the PRISTINE file plus every patch up to 0017 (stock + v0.1 chain + 0017) in a
// scratch tree; the control tree stops at 0016 (what v0.1.1 ships) and must lack all of it. Two Paperclip versions: 2026.1012.0
// and 2026.1005.0 (a version without an install, or without a pristine copy of a target file, is skipped with the reason).
//   HARDENING_TEST_SCRATCH  scratch parent dir (default: the OS temp dir)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { readPatchTarget } from "../src/engine/patches.js";
import {
  ADAPTERS, BOXED_CLI, DUMMY_KEY, bwrapUnusable, buildPatchedTree, importFromTree, makeWorld, runAdapterProbe, stockTreePath,
} from "./helpers/adapter-harness.mjs";

const PATCH = path.join(SOURCE_PATCHES_DIR, "0017-boxed-sandbox-helper.patch");
const SANDBOX = "adapter-utils/dist/local-process-sandbox.js";
const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0017-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

const trees = new Map();
async function treeFor(version, upTo, packages = []) {
  const key = `${version}/${upTo}/${packages}`;
  if (!trees.has(key)) trees.set(key, await buildPatchedTree({ version, upTo, packages, scratch }));
  return trees.get(key);
}
const versions = ["1012", "1005"].filter((v) => fs.existsSync(stockTreePath(v)));
const after = (version) => treeFor(version, "0017");
const before = (version) => treeFor(version, "0016");

let sandboxModules = new Map();
async function sandbox(version, which = "after") {
  const key = `${version}/${which}`;
  if (!sandboxModules.has(key)) {
    const tree = await (which === "after" ? after : before)(version);
    sandboxModules.set(key, tree.skip ? { skip: tree.skip } : { mod: await importFromTree(tree, SANDBOX) });
  }
  return sandboxModules.get(key);
}

/** Capture what the code under test writes to process.stderr (the proxy runs in this process). */
async function captureStderr(fn) {
  const lines = [];
  const original = process.stderr.write;
  process.stderr.write = function (chunk, ...rest) { lines.push(String(chunk)); return typeof rest.at(-1) === "function" ? rest.at(-1)() : true; };
  try { await fn(); } finally { process.stderr.write = original; }
  return lines.join("").split("\n").filter(Boolean);
}
const deniedLines = (lines) => lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((o) => o?.event === "sandbox_network_denied");

test("the patch is one file, targets local-process-sandbox.js, and carries its marker", () => {
  assert.ok(fs.existsSync(PATCH));
  assert.equal(readPatchTarget(PATCH), "node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js");
  assert.ok(fs.readFileSync(PATCH, "utf8").includes("+// LOCAL-PATCH 0017"));
});

for (const version of versions) {
  test(`${version}: stock + 0001/0004/0006b/0012/0015 + 0017 applies with -F0 and the module loads`, async (t) => {
    const tree = await after(version);
    if (tree.skip) return t.skip(tree.skip);
    const entry = tree.applied.find((a) => a.rel.endsWith(`/${SANDBOX}`));
    assert.deepEqual(entry.ids, ["0001", "0004", "0006b", "0012", "0015", "0017"]);
    const text = fs.readFileSync(path.join(tree.root, entry.rel), "utf8");
    assert.ok(text.includes("// LOCAL-PATCH 0017"));
    const { mod } = await sandbox(version);
    for (const name of ["boxedSandboxOptions", "ensureBoxedRuntimeDir", "registerBoxedAdapter", "buildLocalProcessSandboxSpawnTarget"]) assert.equal(typeof mod[name], "function", name);
  });

  test(`${version}: the stock + v0.1 chain (up to 0016) has none of the exports and no denied-target log`, async (t) => {
    const tree = await before(version);
    if (tree.skip) return t.skip(tree.skip);
    const { mod } = await sandbox(version, "before");
    for (const name of ["boxedSandboxOptions", "BASE_ENV_ALLOW", "ensureBoxedRuntimeDir", "registerBoxedAdapter", "ENGINE_CLI_TYPES"]) assert.equal(mod[name], undefined, name);
    const text = fs.readFileSync(path.join(tree.root, "node_modules/@paperclipai", SANDBOX), "utf8");
    assert.ok(!text.includes("LOCAL-PATCH 0017") && !text.includes("sandbox_network_denied"));
  });
}

const needVersion = versions.length ? false : "no Paperclip install to build a scratch tree from";
const V = versions[0];

test("exports: ENGINE_CLI_TYPES and BASE_ENV_ALLOW", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  assert.deepEqual([...mod.ENGINE_CLI_TYPES], ["claude_local", "codex_local", "gemini_local", "kimi_local"]);
  assert.ok(Object.isFrozen(mod.ENGINE_CLI_TYPES) && Object.isFrozen(mod.BASE_ENV_ALLOW));
  const base = new Set(mod.BASE_ENV_ALLOW);
  assert.equal(base.size, mod.BASE_ENV_ALLOW.length, "no duplicates");
  for (const name of ["PATH", "HOME", "LANG", "TZ", "TERM", "LC_ALL", "HTTPS_PROXY", "https_proxy", "NO_PROXY"]) assert.ok(base.has(name), name);
  for (const name of ["NODE_OPTIONS", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "PYTHONPATH", "DATABASE_URL", "HARDENING_CANARY_SECRET", "PAPERCLIP_API_KEY"]) assert.ok(!base.has(name), `${name} must not be in the base list`);
});

// ---------------------------------------------------------------------------------------------------------------------
// boxedSandboxOptions

const baseInput = (over = {}) => ({
  type: "opencode_local",
  config: { filesystemScope: "workspace", networkScope: "allowlist", networkAllowlist: ["api.example.com", "api.example.com:8443"] },
  env: { PAPERCLIP_API_URL: "http://127.0.0.1:3100", PAPERCLIP_AGENT_ID: "agent-1", PAPERCLIP_RUN_ID: "run-1", OPENROUTER_API_KEY: DUMMY_KEY },
  trustedUrls: ["http://127.0.0.1:3100"], // what the adapter computed itself, never read from `env`
  workspaceDir: path.join(scratch, "ws"), runtimeDir: path.join(scratch, "agents", "a1", "opencode-runtime"),
  ...over,
});

test("boxedSandboxOptions: null without a scope, null for a remote target", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const f = mod.boxedSandboxOptions;
  assert.equal(f(baseInput({ config: {} })), null);
  assert.equal(f(baseInput({ config: undefined })), null);
  assert.equal(f(baseInput({ config: { filesystemScope: "", networkScope: null, networkAllowlist: ["x.example"] } })), null);
  assert.equal(f(baseInput({ remoteTarget: true })), null, "a remote execution target is never boxed locally");
  assert.equal(f(baseInput({ remoteTarget: true, config: { networkScope: "deny" } })), null);
  assert.throws(() => f(baseInput({ config: { filesystemScope: "everything" } })), /filesystemScope/, "an invalid scope is an error, not 'unboxed'");
  assert.throws(() => f(baseInput({ config: { networkScope: "open" } })), /networkScope/);
});

test("boxedSandboxOptions: defaults for a filesystem + network box", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const input = baseInput();
  const o = mod.boxedSandboxOptions(input);
  assert.equal(o.filesystemScope, "workspace");
  assert.equal(o.networkScope, "allowlist");
  assert.equal(o.workspaceDir, input.workspaceDir);
  assert.deepEqual(o.managedPaths, [{ path: input.runtimeDir, access: "rw" }], "managedRw defaults to the runtime dir only");
  assert.equal(o.homeDir, path.join(input.runtimeDir, "home"), "HOME is <runtimeDir>/home");
  assert.deepEqual(o.networkAllowlist, ["api.example.com", "api.example.com:8443"]);
  assert.equal(o.command, "bwrap");
  assert.deepEqual(o.extraPaths, []);
  assert.deepEqual(o.pathAliases, []);
  assert.deepEqual(o.outboundRestorePaths, []);
  assert.deepEqual(o.networkTrustedUrls, ["http://127.0.0.1:3100"]);
  assert.deepEqual(o.envPassNames, Object.keys(input.env), "the names of the adapter's own env object");
  assert.deepEqual(o.networkDenyLog, { agentId: "agent-1", runId: "run-1" });
  assert.ok(!JSON.stringify(o).includes(DUMMY_KEY), "no env VALUE is carried in the options");
});

test("boxedSandboxOptions: managedRw/managedRo, trusted URLs, command, extra paths, explicit ids", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const rw = path.join(scratch, "rw"), ro = path.join(scratch, "ro"), extra = path.join(scratch, "extra");
  const o = mod.boxedSandboxOptions(baseInput({
    config: { filesystemScope: "workspace", networkScope: "allowlist", networkAllowlist: ["x.example"], filesystemSandboxCommand: " /usr/bin/bwrap ", filesystemExtraPaths: [extra, { path: ro, access: "ro" }] },
    env: { PAPERCLIP_API_URL: "http://127.0.0.1:3100", UNRELATED_URL: "http://evil.example" },
    managedRw: [rw], managedRo: [ro], trustedUrls: ["http://127.0.0.1:3100", "http://127.0.0.1:3100/mcp", "http://127.0.0.1:4000/x", "", "http://127.0.0.1:4000/x"], agentId: "A", runId: "R",
  }));
  assert.deepEqual(o.managedPaths.map((p) => p.access), ["rw", "rw", "ro"]);
  assert.deepEqual(o.managedPaths.slice(1), [{ path: rw, access: "rw" }, { path: ro, access: "ro" }]);
  assert.deepEqual(o.networkTrustedUrls, ["http://127.0.0.1:3100", "http://127.0.0.1:3100/mcp", "http://127.0.0.1:4000/x"], "the explicit input, de-duplicated, empty entries dropped");
  assert.equal(o.command, "/usr/bin/bwrap");
  assert.deepEqual(o.extraPaths, [{ path: extra, access: "ro" }, { path: ro, access: "ro" }]);
  assert.deepEqual(o.networkDenyLog, { agentId: "A", runId: "R" });
});

test("boxedSandboxOptions: the proxy's trusted URLs come only from the trustedUrls input, never from env (exfiltration through config.env or a run override)", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  // env holds the adapter's variables, config.env entries included: an agent (or a run-level override) can set any of these names.
  const hostile = {
    PAPERCLIP_API_URL: "https://evil.example:443", PAPERCLIP_RUNTIME_TOOLS_MCP_URL: "https://evil.example/mcp",
    PAPERCLIP_RUNTIME_TOOLS_CONNECTIONS_SEARCH_URL: "https://evil.example/c", PAPERCLIP_RUNTIME_TOOLS_CONNECTION_REQUEST_URL: "https://evil.example/r",
    PAPERCLIP_AGENT_ID: "agent-1", PAPERCLIP_RUN_ID: "run-1",
  };
  const o = mod.boxedSandboxOptions(baseInput({ env: hostile, trustedUrls: ["http://127.0.0.1:3100", "http://127.0.0.1:3100/mcp"] }));
  assert.deepEqual(o.networkTrustedUrls, ["http://127.0.0.1:3100", "http://127.0.0.1:3100/mcp"]);
  assert.ok(!JSON.stringify(o.networkTrustedUrls).includes("evil.example"));
  // without an explicit input nothing is trusted extra, whatever env says
  assert.deepEqual(mod.boxedSandboxOptions(baseInput({ env: hostile, trustedUrls: undefined })).networkTrustedUrls, []);
  // an entry that is not an http(s) URL is an adapter bug: refuse, do not hand it to the proxy
  for (const bad of ["evil.example:443", "ftp://x.example/", "not a url", "file:///etc/passwd"]) assert.throws(() => mod.boxedSandboxOptions(baseInput({ trustedUrls: [bad] })), /not an http\(s\) URL/, bad);
});

test("boxedSandboxOptions: a network-only box has no HOME redirect and needs no runtime dir", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const o = mod.boxedSandboxOptions(baseInput({ config: { networkScope: "allowlist", networkAllowlist: ["x.example"] }, runtimeDir: undefined }));
  assert.equal(o.filesystemScope, null);
  assert.equal(o.homeDir, null);
  assert.deepEqual(o.managedPaths, []);
});

test("boxedSandboxOptions: relative or missing paths are errors", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  assert.throws(() => mod.boxedSandboxOptions(baseInput({ runtimeDir: undefined })), /runtimeDir/);
  assert.throws(() => mod.boxedSandboxOptions(baseInput({ runtimeDir: "relative/dir" })), /absolute/);
  assert.throws(() => mod.boxedSandboxOptions(baseInput({ workspaceDir: "ws" })), /absolute/);
  assert.throws(() => mod.boxedSandboxOptions(baseInput({ managedRw: ["rel"] })), /absolute/);
  assert.equal(mod.boxedSandboxOptions(), null, "no input at all is not a box");
});

/** Run `fn` with these process.env values set (undefined removes), then restore. */
async function withEnv(vars, fn) {
  const saved = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
}
/** The same, synchronous (nested inside a withEnv callback the restore must happen before the next statement). */
function withEnvSync(vars, fn) {
  const saved = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return fn(); } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
}
const WORKSPACE_ROOTS_KEY = Symbol.for("paperclip.hardening.workspaceRoots");
/** Whose box the runtime dirs in these tests are: <instance>/companies/c1/agents/a1/... */
const IDS = { agentId: "a1", companyId: "c1" };

test("boxedSandboxOptions never mounts the real home directory or a parent of it", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const fakeHome = path.join(scratch, "fake-home");
  await withEnv({ HOME: fakeHome, PAPERCLIP_HOME: undefined, PAPERCLIP_INSTANCE_ID: undefined, PAPERCLIP_SANDBOX_WORKSPACE_ROOT: undefined }, () => {
    for (const home of [os.homedir(), fakeHome, path.dirname(fakeHome), "/"]) {
      assert.throws(() => mod.boxedSandboxOptions(baseInput({ runtimeDir: home })), /home directory/, `runtimeDir ${home}`);
      assert.throws(() => mod.boxedSandboxOptions(baseInput({ managedRw: [home] })), /home directory/, `managedRw ${home}`);
      assert.throws(() => mod.boxedSandboxOptions(baseInput({ managedRo: [home] })), /home directory/, `managedRo ${home}`);
      assert.throws(() => mod.boxedSandboxOptions(baseInput({ workspaceDir: home })), /home directory/, `workspaceDir ${home}`);
      assert.throws(() => mod.boxedSandboxOptions(baseInput({ config: { ...baseInput().config, filesystemExtraPaths: [home] } })), /home directory/, `extra path ${home}`);
    }
    // below the home, in the instance's workspaces/projects directories or this agent's own companies/<c>/agents/<a>, is fine
    const instance = path.join(fakeHome, ".paperclip", "instances", "default");
    const runtimeDir = path.join(instance, "companies", "c1", "agents", "a1", "opencode-runtime");
    const o = mod.boxedSandboxOptions(baseInput({ ...IDS, runtimeDir, workspaceDir: path.join(instance, "workspaces", "a1") }));
    assert.equal(o.homeDir, path.join(runtimeDir, "home"));
    assert.ok(mod.boxedSandboxOptions(baseInput({ ...IDS, runtimeDir, workspaceDir: path.join(instance, "projects", "c1", "p1", "_default") })));
    // a network-only box mounts nothing, so there is nothing to refuse
    assert.ok(mod.boxedSandboxOptions(baseInput({ config: { networkScope: "deny" }, runtimeDir: "/" })));
  });
});

test("boxedSandboxOptions: inside the home only the instance's workspaces/projects, this agent's own directory and the workspace roots are allowed (extra paths included)", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const fakeHome = path.join(scratch, "fh-inside");
  const instance = path.join(fakeHome, ".paperclip", "instances", "default");
  fs.mkdirSync(path.join(fakeHome, ".ssh"), { recursive: true });
  fs.mkdirSync(path.join(instance, "secrets"), { recursive: true });
  const runtimeDir = path.join(instance, "companies", "c1", "agents", "a1", "opencode-runtime");
  const ok = (over) => mod.boxedSandboxOptions(baseInput({ ...IDS, runtimeDir, workspaceDir: path.join(instance, "workspaces", "a1"), ...over }));
  const withExtra = (extra) => ({ config: { ...baseInput().config, filesystemExtraPaths: [extra] } });
  await withEnv({ HOME: fakeHome, PAPERCLIP_HOME: undefined, PAPERCLIP_INSTANCE_ID: undefined, PAPERCLIP_SANDBOX_WORKSPACE_ROOT: undefined }, () => {
    assert.ok(ok());
    for (const bad of [path.join(fakeHome, ".ssh"), path.join(fakeHome, ".ssh", "id_ed25519"), path.join(instance, "secrets"), path.join(instance, "db"), instance, path.join(fakeHome, ".paperclip"), path.join(fakeHome, "notes")]) {
      assert.throws(() => ok({ workspaceDir: bad }), /home directory/, `workspaceDir ${bad}`);
      assert.throws(() => ok({ managedRw: [bad] }), /home directory/, `managedRw ${bad}`);
      assert.throws(() => ok({ managedRo: [bad] }), /home directory/, `managedRo ${bad}`);
      assert.throws(() => ok(withExtra(bad)), /home directory/, `extra path ${bad}`);
      assert.throws(() => ok(withExtra({ path: bad, access: "ro" })), /home directory/, `extra ro path ${bad}`);
    }
    // outside the home is not this guard's business (a tmp dir, /opt/tools)
    assert.ok(ok({ managedRo: [path.join(scratch, "elsewhere")], ...withExtra("/opt/tools") }));
    // a workspace root (published by 0003b, or the environment variable without it) opens its subtree
    const root = path.join(fakeHome, "projects");
    assert.throws(() => ok({ workspaceDir: path.join(root, "x") }), /home directory/, "not a root yet");
    withEnv({ PAPERCLIP_SANDBOX_WORKSPACE_ROOT: `${root}:relative/root` }, () => { assert.ok(ok({ workspaceDir: path.join(root, "x") })); });
    const other = path.join(fakeHome, "other-root");
    globalThis[WORKSPACE_ROOTS_KEY] = Object.freeze([other]);
    try {
      withEnv({ PAPERCLIP_SANDBOX_WORKSPACE_ROOT: root }, () => {
        assert.ok(ok({ workspaceDir: path.join(other, "x") }), "the published roots win");
        assert.throws(() => ok({ workspaceDir: path.join(root, "x") }), /home directory/, "the environment variable is ignored when roots were published");
      });
      // a "root" that holds the home or the whole instance is not accepted as one
      for (const wide of ["/", fakeHome, path.join(fakeHome, ".paperclip"), instance]) {
        globalThis[WORKSPACE_ROOTS_KEY] = Object.freeze([wide]);
        assert.throws(() => ok({ workspaceDir: path.join(fakeHome, ".ssh") }), /home directory/, `root ${wide}`);
        assert.throws(() => ok({ workspaceDir: path.join(fakeHome, "notes") }), /home directory/, `root ${wide}`);
      }
    } finally { delete globalThis[WORKSPACE_ROOTS_KEY]; }
  });
});

// Inside the instance directory an agent gets only its own box. Two layouts: the instance inside the home (the usual one) and the
// instance elsewhere (PAPERCLIP_HOME outside the home: there the home guard alone protected nothing).
const LAYOUTS = [
  { name: "instance inside the home", home: (root) => path.join(root, "fh-in"), paperclipHome: (root) => path.join(root, "fh-in", ".paperclip") },
  { name: "PAPERCLIP_HOME outside the home", home: (root) => path.join(root, "fh-out"), paperclipHome: (root) => path.join(root, "ph-out", "data") },
];

for (const layout of LAYOUTS) {
  test(`boxedSandboxOptions (${layout.name}): the instance root is guarded on its own - db, secrets, the root and its parents are never mounted, even outside the home`, { skip: needVersion }, async (t) => {
    const { mod, skip } = await sandbox(V);
    if (skip) return t.skip(skip);
    const root = path.join(scratch, `inst-${LAYOUTS.indexOf(layout)}`);
    const fakeHome = layout.home(root);
    const paperclipHome = layout.paperclipHome(root);
    const instance = path.join(paperclipHome, "instances", "default");
    for (const dir of ["db", "secrets", "logs", path.join("companies", "c1", "agents", "a1"), path.join("workspaces", "a1")]) fs.mkdirSync(path.join(instance, dir), { recursive: true });
    fs.mkdirSync(fakeHome, { recursive: true });
    fs.writeFileSync(path.join(instance, "config.json"), "{}");
    const link = path.join(root, "link-to-secrets");
    fs.rmSync(link, { force: true }); fs.symlinkSync(path.join(instance, "secrets"), link);
    const runtimeDir = path.join(instance, "companies", "c1", "agents", "a1", "opencode-runtime");
    const ok = (over) => mod.boxedSandboxOptions(baseInput({ ...IDS, runtimeDir, workspaceDir: path.join(instance, "workspaces", "a1"), ...over }));
    const withExtra = (extra) => ({ config: { ...baseInput().config, filesystemExtraPaths: [extra] } });
    await withEnv({ HOME: fakeHome, PAPERCLIP_HOME: paperclipHome, PAPERCLIP_INSTANCE_ID: undefined, PAPERCLIP_SANDBOX_WORKSPACE_ROOT: undefined }, () => {
      assert.ok(ok(), "the agent's own box and the instance's workspaces are fine");
      const bad = [path.join(instance, "db"), path.join(instance, "db", "x"), path.join(instance, "secrets"), path.join(instance, "logs"), path.join(instance, "config.json"), link,
        instance, path.join(paperclipHome, "instances"), paperclipHome, path.dirname(paperclipHome), "/"];
      for (const candidate of bad) {
        assert.throws(() => ok({ workspaceDir: candidate }), /home directory|instance/, `workspaceDir ${candidate}`);
        assert.throws(() => ok({ managedRw: [candidate] }), /home directory|instance/, `managedRw ${candidate}`);
        assert.throws(() => ok({ managedRo: [candidate] }), /home directory|instance/, `managedRo ${candidate}`);
        assert.throws(() => ok(withExtra(candidate)), /home directory|instance/, `extra path ${candidate}`);
        assert.throws(() => ok({ runtimeDir: candidate }), /home directory|instance/, `runtimeDir ${candidate}`);
      }
      // workspace roots: one outside everything opens its subtree; one that is (or holds) the instance, or lies on db/secrets, is not a root
      const outside = path.join(root, "ws-root");
      withEnvSync({ PAPERCLIP_SANDBOX_WORKSPACE_ROOT: outside }, () => { assert.ok(ok({ workspaceDir: path.join(outside, "x") })); });
      for (const wide of [instance, paperclipHome, path.dirname(paperclipHome), path.join(instance, "db"), path.join(instance, "secrets"), path.join(instance, "companies")]) {
        withEnvSync({ PAPERCLIP_SANDBOX_WORKSPACE_ROOT: wide }, () => {
          for (const candidate of [path.join(instance, "db"), path.join(instance, "secrets", "k")]) assert.throws(() => ok({ workspaceDir: candidate }), /home directory|instance/, `root ${wide} must not open ${candidate}`);
        });
      }
    });
  });

  test(`boxedSandboxOptions (${layout.name}): inside the instance an agent gets its own companies/<c>/agents/<a> directory, workspaces and projects, nobody else's box`, { skip: needVersion }, async (t) => {
    const { mod, skip } = await sandbox(V);
    if (skip) return t.skip(skip);
    const root = path.join(scratch, `own-${LAYOUTS.indexOf(layout)}`);
    const fakeHome = layout.home(root);
    const paperclipHome = layout.paperclipHome(root);
    const instance = path.join(paperclipHome, "instances", "default");
    const agentDir = (c, a) => path.join(instance, "companies", c, "agents", a);
    fs.mkdirSync(fakeHome, { recursive: true });
    for (const [c, a] of [["c1", "a1"], ["c1", "a2"], ["c2", "a1"]]) fs.mkdirSync(agentDir(c, a), { recursive: true });
    const own = path.join(agentDir("c1", "a1"), "opencode-runtime");
    const ok = (over) => mod.boxedSandboxOptions(baseInput({ ...IDS, runtimeDir: own, workspaceDir: path.join(instance, "workspaces", "a1"), ...over }));
    const withExtra = (extra) => ({ config: { ...baseInput().config, filesystemExtraPaths: [extra] } });
    await withEnv({ HOME: fakeHome, PAPERCLIP_HOME: paperclipHome, PAPERCLIP_INSTANCE_ID: undefined, PAPERCLIP_SANDBOX_WORKSPACE_ROOT: undefined }, () => {
      assert.ok(ok());
      // the agent's own directory, below it, and the instance's workspaces/projects
      assert.ok(ok({ managedRw: [path.join(agentDir("c1", "a1"), "codex-home")], managedRo: [path.join(agentDir("c1", "a1"), "instructions")] }));
      assert.ok(ok({ runtimeDir: agentDir("c1", "a1") }));
      assert.ok(ok({ workspaceDir: path.join(instance, "projects", "c1", "p1", "_default"), ...withExtra(path.join(agentDir("c1", "a1"), "skills")) }));
      const others = [
        path.join(agentDir("c1", "a2"), "opencode-runtime"), agentDir("c1", "a2"), path.join(agentDir("c2", "a1"), "opencode-runtime"), agentDir("c2", "a1"), // another agent, another company
        path.join(instance, "companies"), path.join(instance, "companies", "c1"), path.join(instance, "companies", "c1", "agents"), path.join(instance, "companies", "c1", "skills"), // the parents and company-wide files
        path.join(instance, "companies", "c1", "agents", "a1x"), path.join(instance, "companies", "c1", "agents", "a1-other"), // prefix siblings
        path.join(agentDir("c1", "a1"), "..", "a2"), // dot-dot is resolved
      ];
      for (const candidate of others) {
        assert.throws(() => ok({ runtimeDir: candidate }), /home directory|instance/, `runtimeDir ${candidate}`);
        assert.throws(() => ok({ managedRw: [candidate] }), /home directory|instance/, `managedRw ${candidate}`);
        assert.throws(() => ok({ managedRo: [candidate] }), /home directory|instance/, `managedRo ${candidate}`);
        assert.throws(() => ok({ workspaceDir: candidate }), /home directory|instance/, `workspaceDir ${candidate}`);
        assert.throws(() => ok(withExtra(candidate)), /home directory|instance/, `extra path ${candidate}`);
      }
      // who "this agent" is: the input first, the adapter's own PAPERCLIP_ ids when the input has none, otherwise nobody
      const fromEnv = { agentId: undefined, companyId: undefined, env: { ...baseInput().env, PAPERCLIP_AGENT_ID: "a1", PAPERCLIP_COMPANY_ID: "c1" } };
      assert.ok(ok(fromEnv));
      assert.throws(() => ok({ ...fromEnv, runtimeDir: path.join(agentDir("c1", "a2"), "x") }), /home directory|instance/);
      assert.throws(() => ok({ agentId: "a2", companyId: "c1" }), /home directory|instance/, "the input wins over the env");
      assert.throws(() => ok({ agentId: undefined, companyId: undefined }), /home directory|instance/, "no ids (env says agent-1): no companies/ directory is anybody's");
      assert.throws(() => ok({ companyId: undefined, env: { ...baseInput().env, PAPERCLIP_COMPANY_ID: undefined } }), /home directory|instance/, "no company id");
      for (const evil of ["../c2", "a1/../../c2/agents/a1", "a1/", "", "a 1", "*"]) {
        assert.throws(() => ok({ agentId: evil, runtimeDir: path.join(agentDir("c2", "a1"), "x") }), /home directory|instance/, `agentId ${JSON.stringify(evil)}`);
        assert.throws(() => ok({ companyId: evil, runtimeDir: path.join(agentDir("c2", "a1"), "x") }), /home directory|instance/, `companyId ${JSON.stringify(evil)}`);
      }
      // a workspace root (or the workspaces/projects directories) still opens its subtree; the company directories do not
      const wsRoot = path.join(root, "ws-root");
      withEnvSync({ PAPERCLIP_SANDBOX_WORKSPACE_ROOT: wsRoot }, () => { assert.ok(ok({ managedRo: [path.join(wsRoot, "x")] })); });
      // symbolic links are resolved first: a link inside the own directory that leads to another agent's box does not pass
      const sneaky = path.join(agentDir("c1", "a1"), "to-a2");
      fs.rmSync(sneaky, { force: true }); fs.symlinkSync(agentDir("c1", "a2"), sneaky);
      assert.throws(() => ok({ managedRo: [sneaky] }), /home directory|instance/, "link to another agent's box");
    });
  });
}

test("boxedSandboxOptions resolves symbolic links first: a link to the home or into it does not get past the guard", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const fakeHome = path.join(scratch, "fh-links");
  const instance = path.join(fakeHome, ".paperclip", "instances", "default");
  fs.mkdirSync(path.join(fakeHome, ".ssh"), { recursive: true });
  fs.mkdirSync(path.join(instance, "workspaces", "a1"), { recursive: true });
  fs.mkdirSync(path.join(scratch, "link-dir"), { recursive: true });
  const toHome = path.join(scratch, "link-dir", "to-home");
  const toSsh = path.join(scratch, "link-dir", "to-ssh");
  const insideToSsh = path.join(instance, "workspaces", "a1", "escape");
  const dangling = path.join(scratch, "link-dir", "dangling");
  for (const [link, target] of [[toHome, fakeHome], [toSsh, path.join(fakeHome, ".ssh")], [insideToSsh, path.join(fakeHome, ".ssh")], [dangling, path.join(fakeHome, "missing")]]) fs.rmSync(link, { force: true }), fs.symlinkSync(target, link);
  const runtimeDir = path.join(instance, "companies", "c1", "agents", "a1", "opencode-runtime");
  const ok = (over) => mod.boxedSandboxOptions(baseInput({ ...IDS, runtimeDir, workspaceDir: path.join(instance, "workspaces", "a1"), ...over }));
  await withEnv({ HOME: fakeHome, PAPERCLIP_HOME: undefined, PAPERCLIP_INSTANCE_ID: undefined, PAPERCLIP_SANDBOX_WORKSPACE_ROOT: undefined }, () => {
    assert.ok(ok());
    assert.throws(() => ok({ workspaceDir: toHome }), /home directory/, "a link to the home");
    assert.throws(() => ok({ managedRw: [toHome] }), /home directory/);
    assert.throws(() => ok({ managedRo: [toSsh] }), /resolves to .*\.ssh.*home directory/, "a link outside the home that leads into it");
    assert.throws(() => ok({ workspaceDir: insideToSsh }), /resolves to/, "a link inside the allowed tree that leads out of it");
    assert.throws(() => ok({ config: { ...baseInput().config, filesystemExtraPaths: [toSsh] } }), /home directory/);
    assert.throws(() => ok({ managedRo: [dangling] }), /dangling/);
    // a path below a link is resolved too
    assert.throws(() => ok({ managedRo: [path.join(toHome, ".ssh")] }), /home directory/);
    // a not yet created path is judged by its nearest existing parent
    assert.ok(ok({ workspaceDir: path.join(instance, "workspaces", "not", "yet", "created") }));
    assert.throws(() => ok({ workspaceDir: path.join(toHome, "not", "yet") }), /home directory/);
  });
});

test("the built bwrap command binds the runtime dir and the workspace, never the real home", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const input = baseInput();
  fs.mkdirSync(input.workspaceDir, { recursive: true });
  await mod.ensureBoxedRuntimeDir(input.runtimeDir);
  const target = await mod.buildLocalProcessSandboxSpawnTarget({ executable: "/usr/bin/env", args: [], cwd: input.workspaceDir, options: mod.boxedSandboxOptions(input) });
  try {
    const mounts = [];
    for (let i = 0; i < target.args.length; i += 1) if (["--bind", "--ro-bind"].includes(target.args[i])) mounts.push({ mode: target.args[i], src: target.args[i + 1], dst: target.args[i + 2] });
    assert.ok(target.args.includes("--tmpfs") && target.args.includes("--unshare-net") && target.args.includes("--unshare-pid"));
    assert.ok(mounts.some((m) => m.mode === "--bind" && m.src === input.runtimeDir), "runtime dir rw");
    assert.ok(mounts.some((m) => m.mode === "--bind" && m.src === input.workspaceDir), "workspace rw");
    for (const home of [os.homedir(), process.env.HOME].filter(Boolean)) {
      for (const m of mounts) {
        assert.ok(path.relative(m.src, home).startsWith(".."), `${m.mode} ${m.src} must not be or contain ${home}`);
      }
    }
    assert.ok(!mounts.some((m) => m.mode === "--bind" && path.resolve(m.src) === "/"), "no bind of /");
  } finally {
    await target.cleanup?.();
  }
});

// ---------------------------------------------------------------------------------------------------------------------
// ensureBoxedRuntimeDir / registerBoxedAdapter

test("ensureBoxedRuntimeDir: <dir>, home and state, mode 0700, idempotent, tightens, refuses symlinks", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const dir = path.join(scratch, "rt", "deep", "pi-runtime");
  const got = await mod.ensureBoxedRuntimeDir(dir);
  assert.deepEqual(got, { dir, homeDir: path.join(dir, "home"), stateDir: path.join(dir, "state") });
  for (const d of Object.values(got)) assert.equal(fs.statSync(d).mode & 0o777, 0o700, d);
  fs.writeFileSync(path.join(got.homeDir, "keep"), "x");
  fs.chmodSync(got.homeDir, 0o755);
  assert.deepEqual(await mod.ensureBoxedRuntimeDir(dir), got);
  assert.equal(fs.statSync(got.homeDir).mode & 0o777, 0o700, "a loosened mode is tightened again");
  assert.ok(fs.existsSync(path.join(got.homeDir, "keep")), "existing content is kept");
  const link = path.join(scratch, "rt", "linked");
  fs.mkdirSync(path.join(scratch, "rt", "elsewhere", "home"), { recursive: true });
  fs.mkdirSync(path.join(scratch, "rt", "elsewhere", "state"), { recursive: true });
  fs.symlinkSync(path.join(scratch, "rt", "elsewhere"), link);
  await assert.rejects(mod.ensureBoxedRuntimeDir(link), /not a symlink/);
  await assert.rejects(mod.ensureBoxedRuntimeDir("relative"), /absolute/);
  await assert.rejects(mod.ensureBoxedRuntimeDir(undefined), /absolute/);
});

test("registerBoxedAdapter: records the type in the shared registry, known types only", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const registry = globalThis[Symbol.for("paperclip.hardening.boxedAdapters")];
  assert.deepEqual([...mod.BOXED_ADAPTER_TYPES].sort(), ["claude_local", "codex_local", "cursor", "gemini_local", "grok_local", "kimi_local", "opencode_local", "pi_local"]);
  assert.equal(registry.has("opencode_local"), false);
  assert.equal(mod.registerBoxedAdapter("opencode_local"), "opencode_local");
  mod.registerBoxedAdapter("opencode_local");
  mod.registerBoxedAdapter("cursor");
  assert.equal(registry.has("opencode_local"), true);
  assert.equal(registry.has("cursor"), true);
  assert.equal(registry.has("pi_local"), false);
  assert.equal(registry.has(["cursor"]), false, "not a string");
  for (const bad of ["", "Codex", "a b", "../x", "__proto__", 7, null, undefined]) assert.throws(() => mod.registerBoxedAdapter(bad), /adapter type/, String(bad));
  // well formed but not a type that can be boxed: nobody can add "process", "http" or an invented type
  for (const unknown of ["process", "http", "hermes_local", "evil_local", "paperclip_runner", "constructor"]) {
    assert.throws(() => mod.registerBoxedAdapter(unknown), /not an adapter type that can run in the box/, unknown);
    assert.equal(registry.has(unknown), false, unknown);
  }
  assert.throws(() => registry.add("process"), /not an adapter type/);
});

test("registerBoxedAdapter: the registry cannot be replaced, reconfigured, extended or emptied from inside the process (fail-before: a plain Set that anyone could swap)", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const key = Symbol.for("paperclip.hardening.boxedAdapters");
  const registry = globalThis[key];
  mod.registerBoxedAdapter("grok_local");
  const d = Object.getOwnPropertyDescriptor(globalThis, key);
  assert.deepEqual({ writable: d.writable, configurable: d.configurable }, { writable: false, configurable: false });
  assert.ok(Object.isFrozen(registry));
  assert.deepEqual(Object.keys(registry).sort(), ["add", "has"]);
  assert.throws(() => { globalThis[key] = new Set(["process"]); }, TypeError, "assignment");
  assert.throws(() => Object.defineProperty(globalThis, key, { value: new Set(["process"]) }), TypeError, "redefinition");
  assert.throws(() => { delete globalThis[key]; }, TypeError, "delete");
  assert.throws(() => { registry.has = () => true; }, TypeError, "has replaced");
  assert.throws(() => { registry.extra = 1; }, TypeError, "extended");
  assert.equal(globalThis[key], registry);
  assert.equal(registry.has("grok_local"), true);
  assert.equal(registry.has("process"), false);
  // a second copy of the module (another adapter package loading it) uses the one registry instead of failing or replacing it
  const again = await import(`${pathToFileURL(path.join((await after(V)).nm, "@paperclipai", SANDBOX)).href}?second-copy`);
  assert.equal(again.registerBoxedAdapter("pi_local"), "pi_local");
  assert.equal(globalThis[key], registry);
  assert.equal(registry.has("pi_local"), true);
  assert.equal(registry.has("grok_local"), true);
});

// ---------------------------------------------------------------------------------------------------------------------
// the denied-target log

/** Start the real proxy through buildLocalProcessSandboxSpawnTarget (network-only box: nothing is run) and return a client. */
async function startProxy(mod, { allow = ["allowed.example"], denyLog, trusted = [] } = {}) {
  const target = await mod.buildLocalProcessSandboxSpawnTarget({
    executable: "/usr/bin/env", args: [], cwd: scratch,
    options: { workspaceDir: scratch, networkScope: "allowlist", networkAllowlist: allow, networkTrustedUrls: trusted, ...(denyLog === undefined ? {} : { networkDenyLog: denyLog }) },
  });
  const socketPath = target.args.find((a) => a.endsWith("/proxy.sock"));
  const exchange = (payload) => new Promise((resolve) => {
    const socket = net.connect(socketPath);
    let data = "";
    socket.on("data", (d) => { data += d; });
    socket.on("close", () => resolve(data));
    socket.on("error", () => resolve(data));
    socket.write(payload);
    setTimeout(() => socket.destroy(), 3000).unref();
  });
  return {
    connect: (hostPort) => exchange(`CONNECT ${hostPort} HTTP/1.1\r\nHost: ${hostPort}\r\n\r\n`),
    get: (url) => exchange(`GET ${url} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`),
    close: () => target.cleanup(),
  };
}

test("denied CONNECT: 403 as before, plus ONE structured stderr line with event, agentId, runId, host, port", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const proxy = await startProxy(mod, { denyLog: { agentId: "11111111-aaaa-4bbb-8ccc-222222222222", runId: "run_0001-xyz" } });
  try {
    let reply;
    const lines = await captureStderr(async () => { reply = await proxy.connect("Evil.Example:8443"); });
    assert.match(reply, /^HTTP\/1\.1 403 Forbidden/);
    assert.match(reply, /network_target_denied/);
    assert.equal(lines.length, 1, lines.join("|"));
    const entry = JSON.parse(lines[0]);
    assert.deepEqual(entry, { event: "sandbox_network_denied", agentId: "11111111-aaaa-4bbb-8ccc-222222222222", runId: "run_0001-xyz", host: "evil.example", port: 8443 });
    assert.deepEqual(Object.keys(entry), ["event", "agentId", "runId", "host", "port"]);
  } finally { await proxy.close(); }
});

test("denied plain-HTTP request: same line, host and port only (no path, no query string, no credentials)", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const proxy = await startProxy(mod, { denyLog: { agentId: "agent-9", runId: "run-9" } });
  try {
    let reply;
    const lines = await captureStderr(async () => { reply = await proxy.get("http://user:pass@leak.example/secret/path?token=abc123"); });
    assert.match(reply, /403 Forbidden/);
    assert.equal(lines.length, 1);
    assert.deepEqual(JSON.parse(lines[0]), { event: "sandbox_network_denied", agentId: "agent-9", runId: "run-9", host: "leak.example", port: 80 });
    for (const secret of ["secret", "path", "token", "abc123", "pass", "user"]) assert.ok(!lines[0].includes(secret), secret);
  } finally { await proxy.close(); }
});

test("denied log: the host is chosen by the agent, so it is sanitised and the line stays one valid JSON object", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const proxy = await startProxy(mod, { denyLog: { agentId: "agent\nforged", runId: 'run"x' } });
  try {
    const lines = await captureStderr(async () => {
      await proxy.connect("ev'il$&(x);=%0a.example:443"); // what Node's HTTP parser lets through to the proxy
      await proxy.connect(`${"a".repeat(600)}.example:443`);
    });
    assert.equal(lines.length, 2);
    const [a, b] = lines.map((l) => JSON.parse(l));
    assert.equal(a.agentId, "unknown", "an id that is not [A-Za-z0-9_-]{1,64} is replaced");
    assert.equal(a.runId, "unknown");
    assert.equal(a.host, "ev?il???x????0a.example", "anything outside [a-z0-9.:_-] becomes ?");
    assert.match(a.host, /^[a-z0-9.:_?-]+$/);
    assert.ok(b.host.length <= 255);
  } finally { await proxy.close(); }
});

test("an allowed target writes no denied line", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const server = net.createServer((s) => s.end());
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const proxy = await startProxy(mod, { allow: [`127.0.0.1:${port}`], denyLog: { agentId: "a", runId: "r-allowed" } });
  try {
    let reply;
    const lines = await captureStderr(async () => { reply = await proxy.connect(`127.0.0.1:${port}`); });
    assert.match(reply, /^HTTP\/1\.1 200 Connection Established/);
    assert.deepEqual(deniedLines(lines), []);
  } finally { await proxy.close(); server.close(); }
});

test("rate limit: at most 20 lines per run, then one rateLimited line, then silence; other runs are independent", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const first = await startProxy(mod, { denyLog: { agentId: "agent-1", runId: "run-limit" } });
  const second = await startProxy(mod, { denyLog: { agentId: "agent-1", runId: "run-limit" } }); // a second spawn of the SAME run
  const other = await startProxy(mod, { denyLog: { agentId: "agent-2", runId: "run-other" } });
  try {
    const lines = await captureStderr(async () => {
      for (let i = 0; i < 15; i += 1) await first.connect(`h${i}.example:443`);
      for (let i = 15; i < 30; i += 1) await second.connect(`h${i}.example:443`);
      await other.connect("fresh.example:443");
    });
    const all = deniedLines(lines);
    const mine = all.filter((e) => e.runId === "run-limit");
    assert.equal(mine.length, 21, "20 denials + the one rateLimited line");
    assert.deepEqual(mine.slice(0, 20).map((e) => e.host), Array.from({ length: 20 }, (_, i) => `h${i}.example`));
    assert.deepEqual(mine[20], { event: "sandbox_network_denied", agentId: "agent-1", runId: "run-limit", rateLimited: true, limit: 20 });
    const others = all.filter((e) => e.runId === "run-other");
    assert.deepEqual(others, [{ event: "sandbox_network_denied", agentId: "agent-2", runId: "run-other", host: "fresh.example", port: 443 }]);
    // the denial itself is unchanged by the limit
    let reply;
    await captureStderr(async () => { reply = await first.connect("after-limit.example:443"); });
    assert.match(reply, /403 Forbidden/);
  } finally { await first.close(); await second.close(); await other.close(); }
});

test("options without a deny-log context (stock callers) still log, with unknown ids and a per-proxy limit", { skip: needVersion }, async (t) => {
  const { mod, skip } = await sandbox(V);
  if (skip) return t.skip(skip);
  const a = await startProxy(mod);
  const b = await startProxy(mod);
  try {
    const lines = await captureStderr(async () => {
      for (let i = 0; i < 22; i += 1) await a.connect(`x${i}.example:443`);
      await b.connect("y.example:443");
    });
    const all = deniedLines(lines);
    assert.ok(all.every((e) => e.agentId === "unknown" && e.runId === "unknown"));
    assert.equal(all.length, 20 + 1 + 1);
    assert.equal(all.at(-1).host, "y.example", "the second proxy has its own counter");
  } finally { await a.close(); await b.close(); }
});

// ---------------------------------------------------------------------------------------------------------------------
// the adapter harness (reused by the adapter patch tests): the real execute of a stock adapter against a stub CLI in the real box

test("harness: stock claude_local execute runs a stub CLI in the real box; 0017 adds the denied-target log (fail-before: 0016 chain has none)", { skip: needVersion || bwrapUnusable(), timeout: 120_000 }, async (t) => {
  const run = async (upTo) => {
    const tree = await buildPatchedTree({ version: V, upTo, packages: [ADAPTERS.claude_local.pkg], scratch });
    if (tree.skip) return { skip: tree.skip };
    const world = makeWorld(tree);
    try {
      return await runAdapterProbe({
        tree, world, adapter: ADAPTERS.claude_local, config: { ...BOXED_CLI, networkAllowlist: ["api.example.com"] }, env: { ANTHROPIC_API_KEY: DUMMY_KEY },
        probe: (w) => ({ write: ["/etc/hardening-probe", path.join(w.realHome, "hardening-probe"), path.join(w.workspace, "ok")], read: [path.join(w.realHome, ".claude", "canary")], ls: ["~/.claude", "~/.gemini"], tcp: ["1.1.1.1:443"], connect: ["evil.example:443", "127.0.0.1:54329"] }),
      });
    } finally { world.cleanup(); tree.cleanup(); }
  };
  const [pre, post] = [await run("0016"), await run("0017")];
  if (pre.skip) return t.skip(pre.skip);
  for (const r of [pre, post]) {
    assert.equal(r.error, null, String(r.error?.stack));
    const p = r.probe;
    assert.equal(p.pwd, r.world.workspace);
    assert.match(p.home, /\/agents\/[^/]+\/claude-runtime\/home$/, "0016: HOME is the agent's own runtime home");
    assert.ok(p.env.includes("ANTHROPIC_API_KEY"), "the agent's own credential name reaches the child (names only are probed)");
    assert.equal(p.write[path.join(r.world.workspace, "ok")], true);
    assert.equal(r.persisted["/etc/hardening-probe"], false, "a write below / stays on the box's private tmpfs");
    assert.equal(r.persisted[path.join(r.world.realHome, "hardening-probe")], false);
    assert.equal(p.read[path.join(r.world.realHome, ".claude", "canary")], false, "the real home is invisible");
    assert.equal(p.ls["~/.gemini"], null);
    assert.equal(p.tcp["1.1.1.1:443"], false, "no direct network");
    assert.match(p.connect["evil.example:443"], /^HTTP\/1\.1 403 /);
    assert.match(p.connect["127.0.0.1:54329"], /^HTTP\/1\.1 403 /);
  }
  assert.deepEqual(deniedLines(pre.hostStderr.split("\n")), [], "fail-before: nothing is logged on the v0.1 chain");
  const logged = deniedLines(post.hostStderr.split("\n"));
  assert.deepEqual(logged.map((e) => `${e.host}:${e.port}`), ["evil.example:443", "127.0.0.1:54329"]);
  assert.ok(logged.every((e) => e.event === "sandbox_network_denied" && typeof e.agentId === "string" && typeof e.runId === "string"));
});

test("harness: the chain builder skips with a reason when a pristine copy is missing", async () => {
  const none = await buildPatchedTree({ version: "9999", upTo: "0017", scratch });
  assert.match(none.skip, /no Paperclip 2026\.9999\.0 install/);
});

test("the dry run of the whole chain through GNU patch (-F0, as apply.sh and the engine do) succeeds on every available version", { skip: needVersion }, async (t) => {
  for (const version of versions) {
    const tree = await before(version);
    if (tree.skip) { t.diagnostic(`${version}: ${tree.skip}`); continue; }
    const r = spawnSync("patch", ["-p1", "-N", "-F0", "--batch", "--dry-run", "-s", "-d", tree.root, "-i", PATCH], { encoding: "utf8" });
    assert.equal(r.status, 0, `${version}: ${r.stdout}${r.stderr}`);
  }
});

// The Claude prompt bundle (instructions file, skill links) lives in the server-managed companies/<c>/claude-prompt-cache/<key>, which
// the claude adapter mounts READ-ONLY (patch 0026). The guard allows exactly that: this agent's own company's cache, read-only.
for (const layout of LAYOUTS) {
  test(`boxedSandboxOptions (${layout.name}): the agent's own company's claude-prompt-cache may be mounted read-only; another company's, and any read-write mount of it, are refused`, { skip: needVersion }, async (t) => {
    const { mod, skip } = await sandbox(V);
    if (skip) return t.skip(skip);
    const root = path.join(scratch, `cache-${LAYOUTS.indexOf(layout)}`);
    const fakeHome = layout.home(root);
    const paperclipHome = layout.paperclipHome(root);
    const instance = path.join(paperclipHome, "instances", "default");
    const cache = (c, key = "k1") => path.join(instance, "companies", c, "claude-prompt-cache", key);
    fs.mkdirSync(fakeHome, { recursive: true });
    for (const c of ["c1", "c2"]) fs.mkdirSync(cache(c), { recursive: true });
    fs.mkdirSync(path.join(instance, "companies", "c1", "agents", "a1"), { recursive: true });
    const link = path.join(root, "link-to-other-cache");
    fs.rmSync(link, { force: true }); fs.symlinkSync(cache("c2"), link);
    const ok = (over) => mod.boxedSandboxOptions(baseInput({ ...IDS, runtimeDir: path.join(instance, "companies", "c1", "agents", "a1", "claude-runtime"), workspaceDir: path.join(instance, "workspaces", "a1"), ...over }));
    const withExtra = (path_, access) => ({ config: { ...baseInput().config, filesystemExtraPaths: [{ path: path_, access }] } });
    await withEnv({ HOME: fakeHome, PAPERCLIP_HOME: paperclipHome, PAPERCLIP_INSTANCE_ID: undefined, PAPERCLIP_SANDBOX_WORKSPACE_ROOT: undefined }, () => {
      // allowed, read-only
      const options = ok({ managedRo: [cache("c1"), path.join(instance, "companies", "c1", "claude-prompt-cache")] });
      assert.deepEqual(options.managedPaths.filter((p) => p.path.includes("claude-prompt-cache")).map((p) => p.access), ["ro", "ro"]);
      assert.ok(ok(withExtra(cache("c1"), "ro")), "a read-only extra path is a read-only mount too");
      // refused: another company's cache (also through a link and a dot-dot), read-write mounts of the own cache, the rest of the company dir
      assert.throws(() => ok({ managedRo: [cache("c2")] }), /home directory|instance/, "another company's cache");
      assert.throws(() => ok({ managedRo: [link] }), /home directory|instance/, "a link to another company's cache");
      assert.throws(() => ok({ managedRo: [path.join(cache("c1"), "..", "..", "..", "c2", "claude-prompt-cache")] }), /home directory|instance/, "dot-dot");
      assert.throws(() => ok({ managedRw: [cache("c1")] }), /home directory|instance/, "read-write cache");
      assert.throws(() => ok({ managedRw: [path.join(instance, "companies", "c1", "claude-prompt-cache")] }), /home directory|instance/, "read-write cache dir");
      assert.throws(() => ok(withExtra(cache("c1"), "rw")), /home directory|instance/, "read-write extra path");
      assert.throws(() => ok({ workspaceDir: cache("c1") }), /home directory|instance/, "the workspace is read-write");
      assert.throws(() => ok({ runtimeDir: cache("c1") }), /home directory|instance/, "the runtime dir is read-write");
      for (const other of [path.join(instance, "companies", "c1"), path.join(instance, "companies", "c1", "claude-prompt-cache-x"), path.join(instance, "companies", "c1", "skills"), path.join(instance, "companies")]) {
        assert.throws(() => ok({ managedRo: [other] }), /home directory|instance/, `managedRo ${other}`);
      }
      // without a company id nothing under companies/ is allowed
      assert.throws(() => ok({ companyId: undefined, env: { ...baseInput().env } , managedRo: [cache("c1")] }), /home directory|instance/, "no company id");
    });
  });
}
