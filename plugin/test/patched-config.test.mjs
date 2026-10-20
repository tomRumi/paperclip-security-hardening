// Patches 0003 and 0005a read the site values from the hardening settings file. These tests evaluate the code blocks
// the package patches add (test/helpers/patch-block.mjs) against settings files written by the plugin's own writer.
// The last test compares them with the patches of a hand-patched live install (read only); it runs only when
// HARDENING_LIVE_PATCHES names that patch dir and is skipped otherwise.
//   HARDENING_LIVE_PATCHES  live patch dir (no default)
//   HARDENING_TEST_SCRATCH  scratch parent dir (default: the OS temp dir)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { blockFromPatchFile, evalBlock } from "./helpers/patch-block.mjs";
import { haveLiveSettings, liveSettings } from "./helpers/live-settings.mjs";
import { writeHardeningConfig, normalizeSettings } from "../src/settings.js";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LIVE = process.env.HARDENING_LIVE_PATCHES || null;
const P0003 = "0003-spawn-time-sandbox-enforcement.patch";
const P0005A = ["0005a-new-agent-safe-defaults.patch", "0005a-new-agent-safe-defaults.1012.patch"];

const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patched-config-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
let n = 0;
const freshRoot = () => { const d = path.join(scratch, `root-${++n}`); fs.mkdirSync(d, { mode: 0o700 }); return d; };

/** A settings file as the host would have it: a directory of mode 0700 and a file of the given mode (default 0600). */
const put = (file, content, mode = 0o600) => {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content));
  fs.chmodSync(file, mode);
  return file;
};
const GOOD = { baseAllowlist: ["from-file.example"], extraReadOnlyPaths: ["/from/file"], hermesWrapperPath: "/from/file/hermes", workspaceRoots: ["/srv/from-file"] };
const UID = process.getuid();

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
  assert.deepEqual(c.adapterConfig, { ...creator.claude, engine: "cli", filesystemScope: "workspace", filesystemSandboxCommand: "/usr/bin/bwrap", filesystemExtraPaths: [], networkScope: "allowlist", networkAllowlist: ["api.anthropic.com"] });
  assert.deepEqual(c.permissions, { canCreateAgents: false, canCreateSkills: false });
  const hm = b5.applyNewAgentSafeDefaults("hermes_local", creator.hermes, {}, "create").adapterConfig;
  assert.equal(hm.command, "/usr/local/bin/hermes-sandbox");
  assert.deepEqual(hm.env, { HERMES_SANDBOX_ALLOW: { type: "plain", value: "openrouter.ai" }, KEEP: "1" });
});

// The claude_local adapter's default engine is ACP ("auto"/unset/unknown), and it refuses ACP under a filesystem or network
// scope (execution engine "requires the Claude CLI engine"). A new boxed agent therefore starts on the CLI engine unless its
// creator explicitly chose one: an explicit "cli" stays, and so does an explicit "acp" (that agent is refused at run time, which
// is safe and says how to fix it; the patch does not override a deliberate choice).
for (const name of P0005A) {
  test(`${name}: a new claude_local agent starts on the CLI engine; an explicit engine is kept`, () => {
    const b5 = evalBlock(pkg0005a(name), "0005a", { instanceRoot: freshRoot() });
    const engineOf = (cfg, source = "create") => b5.applyNewAgentSafeDefaults("claude_local", cfg, {}, source).adapterConfig.engine;
    assert.equal(engineOf({ model: "x" }), "cli", "unset");
    for (const v of ["auto", "AUTO", "", "  ", "bogus", null, 7, true, {}, []]) assert.equal(engineOf({ engine: v }), "cli", JSON.stringify(v));
    assert.equal(engineOf({ engine: "cli" }), "cli");
    assert.equal(engineOf({ engine: "acp" }), "acp");
    assert.equal(engineOf({ engine: " ACP " }), " ACP ", "kept as given (the adapter trims and lowercases too)");
    assert.equal(engineOf({ engine: "CLI " }), "CLI ");
    assert.equal(engineOf({ model: "x" }, "approval_activation"), "cli", "approval path");
    assert.equal(engineOf(undefined), "cli", "no adapterConfig at all");
    // Nothing else changes with it, and other adapter types get no engine key.
    const c = b5.applyNewAgentSafeDefaults("claude_local", creator.claude, {}, "create").adapterConfig;
    assert.deepEqual({ ...c, engine: undefined }, { ...creator.claude, engine: undefined, filesystemScope: "workspace", filesystemSandboxCommand: "/usr/bin/bwrap", filesystemExtraPaths: [], networkScope: "allowlist", networkAllowlist: ["api.anthropic.com"] });
    for (const type of ["hermes_local", "codex_local"]) assert.equal("engine" in b5.applyNewAgentSafeDefaults(type, { model: "m" }, {}, "create").adapterConfig, false, type);
  });
}

test("no settings file: PAPERCLIP_SANDBOX_WORKSPACE_ROOT still works as before", () => {
  const b3 = evalBlock(pkg0003(), "0003", { instanceRoot: freshRoot(), env: { PAPERCLIP_SANDBOX_WORKSPACE_ROOT: "/srv/a:relative:/srv/b/" } });
  assert.deepEqual(b3.SANDBOX_WORKSPACE_ROOTS, ["/srv/a", "/srv/b"]);
});

test("settings file at <instance root>/hardening/config.json, written by the plugin's writer, is used", () => {
  const root = freshRoot();
  const settings = { baseAllowlist: ["api.anthropic.com", "10.0.0.5:3100"], extraReadOnlyPaths: ["/opt/tools"], workspaceRoots: ["/srv/projects"],
    hermesWrapperPath: "/opt/bin/hermes-box", hermesAllowlist: ["openrouter.ai", "10.0.0.5:3100"], hermesReadOnlyPaths: ["/opt/hermes"] };
  const w = writeHardeningConfig(settings, { file: path.join(root, "hardening", "config.json"), instanceRoot: root });
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
  writeHardeningConfig({ baseAllowlist: ["from-instance-root.example"] }, { file: path.join(root, "hardening", "config.json"), instanceRoot: root });
  const other = path.join(root, "elsewhere.json");
  writeHardeningConfig({ baseAllowlist: [], extraReadOnlyPaths: ["/x"] }, { file: other, instanceRoot: root });
  const b5 = evalBlock(pkg0005a(), "0005a", { instanceRoot: root, env: { PAPERCLIP_HARDENING_CONFIG: other } });
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.networkAllowlist, ["api.anthropic.com"]);
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.filesystemExtraPaths, ["/x"]);
  const b3 = evalBlock(pkg0003(), "0003", { instanceRoot: root, env: { PAPERCLIP_HARDENING_CONFIG: other } });
  assert.deepEqual(b3.SANDBOX_WORKSPACE_ROOTS, [path.join(root, "workspaces"), path.join(root, "projects")]);
});

test("an unreadable or malformed settings file gives the defaults and a warning", () => {
  for (const content of ["{not json", "[1,2]"]) {
    const root = freshRoot();
    put(path.join(root, "hardening", "config.json"), content);
    const b5 = evalBlock(pkg0005a(), "0005a", { instanceRoot: root });
    assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.networkAllowlist, ["api.anthropic.com"]);
    assert.equal(b5.warnings.length, 1);
    assert.equal(b5.warnings[0].obj.event, "hardening_config");
    const b3 = evalBlock(pkg0003(), "0003", { instanceRoot: root });
    assert.deepEqual(b3.SANDBOX_WORKSPACE_ROOTS, [path.join(root, "workspaces"), path.join(root, "projects")]);
    assert.equal(b3.warnings.length, 1);
  }
});

test("with the live install's settings the package patches behave exactly like the live patches", { skip: !LIVE ? "HARDENING_LIVE_PATCHES is not set (the dir a hand-patched live install was patched from); comparison with it skipped" : !haveLiveSettings(LIVE) && "no live patch dir" }, async () => {
  const { settings, errors } = normalizeSettings(liveSettings(LIVE));
  assert.deepEqual(errors, []);
  const root = freshRoot();
  writeHardeningConfig(settings, { file: path.join(root, "hardening", "config.json"), instanceRoot: root });
  const env = {};
  const live5 = evalBlock(blockFromPatchFile(path.join(LIVE, P0005A[1]), "0005a"), "0005a", { env });
  const pkg5 = evalBlock(pkg0005a(), "0005a", { instanceRoot: root, env });
  assert.deepEqual(pkg5.NEW_AGENT_SAFE_DEFAULTS, live5.NEW_AGENT_SAFE_DEFAULTS);
  // The only difference from the (older) live patch: a new boxed claude_local agent gets engine "cli" (see the engine tests below).
  for (const [type, cfg] of [["claude_local", creator.claude], ["hermes_local", creator.hermes], ["codex_local", { model: "m" }], ["hermes_local", {}]]) {
    const ours = pkg5.applyNewAgentSafeDefaults(type, cfg, { canAssignTasks: true }, "create");
    if (type === "claude_local") { assert.equal(ours.adapterConfig.engine, "cli"); delete ours.adapterConfig.engine; }
    assert.deepEqual(ours, live5.applyNewAgentSafeDefaults(type, cfg, { canAssignTasks: true }, "create"), type);
  }
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

// ---------- the file is trusted only where no agent run can write it, owned by the service user, mode 0600
const blocksFor = (root, opts = {}) => ({
  b3: evalBlock(pkg0003(), "0003", { instanceRoot: root, ...opts }),
  b5: evalBlock(pkg0005a(), "0005a", { instanceRoot: root, ...opts }),
});
const defaultRoots = (root, env = {}) => (env.PAPERCLIP_SANDBOX_WORKSPACE_ROOT ? env.PAPERCLIP_SANDBOX_WORKSPACE_ROOT.split(path.delimiter) : [path.join(root, "workspaces"), path.join(root, "projects")]);
/** The file is ignored by BOTH patched readers: secure defaults, and one warning in the sandbox_enforcement category. */
function assertIgnored(root, opts, reason, label) {
  const { b3, b5 } = blocksFor(root, opts);
  assert.deepEqual(b3.SANDBOX_WORKSPACE_ROOTS, defaultRoots(root, opts.env), `${label}: 0003 workspace roots`);
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.networkAllowlist, ["api.anthropic.com"], `${label}: 0005a allowlist`);
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.filesystemExtraPaths, [], `${label}: 0005a read-only paths`);
  assert.equal(b5.NEW_AGENT_SAFE_DEFAULTS.hermesCommand, "/usr/local/bin/hermes-sandbox", `${label}: 0005a hermes command`);
  for (const w of [b3.warnings, b5.warnings]) {
    assert.equal(w.length, 1, `${label}: ${JSON.stringify(w)}`);
    assert.equal(w[0].obj.event, "sandbox_enforcement");
    assert.equal(w[0].obj.action, "ignore_hardening_config");
    assert.match(w[0].obj.reason, reason, label);
    assert.match(w[0].msg, /^sandbox enforcement: hardening settings file ignored, .*using the secure defaults$/);
  }
}
const assertUsed = (root, opts, label) => {
  const { b3, b5 } = blocksFor(root, opts);
  assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.networkAllowlist, GOOD.baseAllowlist, label);
  assert.deepEqual(b3.SANDBOX_WORKSPACE_ROOTS, GOOD.workspaceRoots, label);
  assert.deepEqual([...b3.warnings, ...b5.warnings], [], label);
};

test("a settings file with the wrong mode is ignored: only 0600 counts", () => {
  for (const mode of [0o644, 0o640, 0o660, 0o666, 0o604, 0o400, 0o700]) {
    const root = freshRoot();
    put(path.join(root, "hardening", "config.json"), GOOD, mode);
    assertIgnored(root, {}, /mode 0600/, `mode ${mode.toString(8)}`);
  }
  const root = freshRoot();
  put(path.join(root, "hardening", "config.json"), GOOD, 0o600);
  assertUsed(root, {}, "mode 0600");
});

test("a settings file in a directory that group or others can write, or that is not the service user's, is ignored", () => {
  for (const mode of [0o770, 0o707, 0o777, 0o720, 0o702]) {
    const root = freshRoot();
    put(path.join(root, "hardening", "config.json"), GOOD);
    fs.chmodSync(path.join(root, "hardening"), mode);
    assertIgnored(root, {}, /directory must be owned by the service user and not writable/, `dir ${mode.toString(8)}`);
  }
  const root = freshRoot();
  put(path.join(root, "hardening", "config.json"), GOOD);
  fs.chmodSync(path.join(root, "hardening"), 0o755);
  assertUsed(root, {}, "dir 0755 (only the owner can write)");
  assertIgnored(root, { uid: UID + 1 }, /owned by the service user/, "file owned by someone else");
  assertIgnored(root, { uid: null }, /ownership cannot be checked/, "no getuid");
});

test("a settings file that is not a regular file, or a path that is not absolute, is ignored", () => {
  const root = freshRoot();
  fs.mkdirSync(path.join(root, "hardening", "config.json"), { recursive: true });
  assertIgnored(root, {}, /regular file/, "a directory");
  const rel = freshRoot();
  put(path.join(rel, "hardening", "config.json"), GOOD);
  assertIgnored(rel, { env: { PAPERCLIP_HARDENING_CONFIG: "hardening/config.json" } }, /not absolute/, "relative");
});

test("a settings file inside the instance's workspaces, projects or companies directory is ignored, also through a link", () => {
  for (const sub of ["workspaces", "projects", "companies"]) {
    const root = freshRoot();
    const file = put(path.join(root, sub, "agent-1", "config.json"), GOOD);
    assertIgnored(root, { env: { PAPERCLIP_HARDENING_CONFIG: file } }, new RegExp(`inside ${path.join(root, sub)}`), sub);
  }
  // <instance root>/hardening is a link into a directory an agent can write.
  const root = freshRoot();
  put(path.join(root, "workspaces", "w", "config.json"), GOOD);
  fs.symlinkSync(path.join(root, "workspaces", "w"), path.join(root, "hardening"));
  assertIgnored(root, {}, /inside .*workspaces/, "linked directory");
  // A directory link on the way to a safe place is followed and fine (the location is judged by where the open file really is).
  const root3 = freshRoot();
  put(path.join(root3, "safe", "real.json"), GOOD);
  fs.symlinkSync(path.join(root3, "safe"), path.join(root3, "hardening"));
  assertUsed(root3, { env: { PAPERCLIP_HARDENING_CONFIG: path.join(root3, "hardening", "real.json") } }, "directory link to a safe place");
});

test("a settings file that is itself a link is ignored (never followed), whatever it points to", () => {
  const pointsAt = (target) => {
    const root = freshRoot();
    put(target(root), GOOD);
    fs.mkdirSync(path.join(root, "hardening"), { mode: 0o700 });
    fs.symlinkSync(target(root), path.join(root, "hardening", "config.json"));
    return root;
  };
  assertIgnored(pointsAt((root) => path.join(root, "projects", "p", "config.json")), {}, /symbolic link/, "link into a workspace");
  assertIgnored(pointsAt((root) => path.join(root, "safe", "real.json")), {}, /symbolic link/, "link to a safe file");
  const dangling = freshRoot();
  fs.mkdirSync(path.join(dangling, "hardening"), { mode: 0o700 });
  fs.symlinkSync(path.join(dangling, "nowhere.json"), path.join(dangling, "hardening", "config.json"));
  assertIgnored(dangling, {}, /symbolic link/, "dangling link");
  const rootFifo = freshRoot();
  fs.mkdirSync(path.join(rootFifo, "hardening"), { mode: 0o700 });
  execFileSync("mkfifo", ["-m", "600", path.join(rootFifo, "hardening", "config.json")]);
  assertIgnored(rootFifo, {}, /regular file/, "a FIFO is not opened for reading (and does not block)");
});

test("all three package patches read the settings file the same way: open without following a link, location from the open file", () => {
  const readerOf = (patchFile, id) => {
    const block = blockFromPatchFile(path.join(SOURCE_PATCHES_DIR, patchFile), id);
    const start = block.indexOf(`function readHardeningConfig${id}()`);
    assert.ok(start >= 0, patchFile);
    return block.slice(start, block.indexOf("\n}\n", start)).replaceAll(id, "ID").replaceAll("hardeningPath.", "path."); // 0005a imports node:path as hardeningPath
  };
  const readers = [readerOf(P0003, "0003"), ...P0005A.map((f) => readerOf(f, "0005a"))];
  assert.equal(readers[0], readers[1], "0003 and 0005a");
  assert.equal(readers[1], readers[2], "both 0005a variants");
  assert.match(readers[0], /O_RDONLY \| hardeningFs\.constants\.O_NOFOLLOW \| hardeningFs\.constants\.O_NONBLOCK/);
  assert.match(readers[0], /readlinkSync\(`\/proc\/self\/fd\/\$\{fd\}`\)/);
  assert.doesNotMatch(readers[0], /realpathSync/, "no path check before the open");
  assert.ok(readers[0].indexOf("fstatSync") < readers[0].indexOf("readFileSync"), "fstat before the read");
  assert.match(readers[0], /if \(st\.isFile\(\)\)\s+text = /, "only a regular file is read");
});

test("a settings file inside a workspace root (its own list, or PAPERCLIP_SANDBOX_WORKSPACE_ROOT) is ignored", () => {
  const root = freshRoot();
  const shared = path.join(root, "shared");
  const file = put(path.join(shared, "sub", "config.json"), { ...GOOD, workspaceRoots: [shared] });
  assertIgnored(root, { env: { PAPERCLIP_HARDENING_CONFIG: file } }, /inside .*shared/, "its own workspaceRoots");
  const file2 = put(path.join(shared, "other.json"), GOOD);
  const env = { PAPERCLIP_HARDENING_CONFIG: file2, PAPERCLIP_SANDBOX_WORKSPACE_ROOT: `/elsewhere${path.delimiter}${shared}` };
  assertIgnored(root, { env }, /inside .*shared/, "PAPERCLIP_SANDBOX_WORKSPACE_ROOT");
  // The file can sit next to, but not in, a root.
  assertUsed(root, { env: { PAPERCLIP_HARDENING_CONFIG: file2, PAPERCLIP_SANDBOX_WORKSPACE_ROOT: path.join(shared, "sub") } }, "outside every root");
});

test("the writer and both patched readers decide the same way for a settings file location", () => {
  const cases = [
    { name: "instance hardening dir", rel: "hardening/config.json", ok: true },
    { name: "elsewhere", rel: "elsewhere/config.json", ok: true },
    { name: "workspaces", rel: "workspaces/a/config.json", ok: false },
    { name: "projects", rel: "projects/config.json", ok: false },
    { name: "companies", rel: "companies/c/agents/a/claude-runtime/config.json", ok: false },
    { name: "a workspace root", rel: "wsroot/config.json", ok: false, workspaceRoots: ["wsroot"] },
    { name: "next to a workspace root", rel: "wsroot2/config.json", ok: true, workspaceRoots: ["wsroot"] },
  ];
  for (const c of cases) {
    const root = freshRoot();
    const file = path.join(root, c.rel);
    const settings = { ...GOOD, workspaceRoots: (c.workspaceRoots ?? ["/srv/from-file"]).map((r) => path.resolve(root, r)) };
    const env = c.rel.startsWith("hardening/") ? {} : { PAPERCLIP_HARDENING_CONFIG: file };
    if (c.ok) {
      writeHardeningConfig(settings, { file, instanceRoot: root });
      const { b5 } = blocksFor(root, { env });
      assert.deepEqual(b5.NEW_AGENT_SAFE_DEFAULTS.networkAllowlist, GOOD.baseAllowlist, c.name);
      assert.deepEqual(blocksFor(root, { env }).b3.SANDBOX_WORKSPACE_ROOTS, settings.workspaceRoots, c.name);
    } else {
      assert.throws(() => writeHardeningConfig(settings, { file, instanceRoot: root }), /lies inside/, c.name);
      put(file, { schema: 1, ...settings }); // what an agent could have planted there
      assertIgnored(root, { env }, /inside/, c.name);
    }
  }
});
