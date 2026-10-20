// Which Paperclip the engine works on (src/engine/target.js): derived from the server process's /proc entry, strict.
// A fake /proc in a temp dir stands in for the server process; the tree it points to is a stub with the two files the
// derivation looks at. Nothing here touches a real Paperclip install or process.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createEngine, detectRestart } from "../src/engine/index.js";
import {
  resolveTargetFromParent, verifyTarget, summarizeTarget, parseCmdline, parseServerCommand, parseCgroup, parseEnviron, readDotenvKey,
  describeInstanceLayout, resolveInstanceInputs, systemdServiceName, TargetError,
} from "../src/engine/target.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(HERE, "../bin/hardening-engine.mjs");
const UID = process.getuid();
const SENTINEL = "SENTINEL-SECRET-VALUE-0451";
const root = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "target-test-"));
test.after(() => fs.rmSync(root, { recursive: true, force: true }));

let seq = 0;
/** A fake machine: <root>/<n>/{home,proc}. The Paperclip tree is <home>/.paperclip/cli/installs/npm/2026.1012.0 behind cli/current. */
function machine() {
  const dir = path.join(root, `m${++seq}`);
  const home = path.join(dir, "home");
  const store = path.join(home, ".paperclip", "cli");
  const tree = path.join(store, "installs", "npm", "2026.1012.0");
  fs.mkdirSync(path.join(tree, "node_modules/paperclipai/dist"), { recursive: true });
  fs.mkdirSync(path.join(tree, "node_modules/@paperclipai/server"), { recursive: true });
  fs.writeFileSync(path.join(tree, "node_modules/paperclipai/dist/index.js"), "// stub\n");
  fs.writeFileSync(path.join(tree, "node_modules/@paperclipai/server/package.json"), JSON.stringify({ name: "@paperclipai/server", version: "2026.1012.0" }));
  fs.symlinkSync("installs/npm/2026.1012.0", path.join(store, "current"));
  fs.mkdirSync(path.join(dir, "proc"), { recursive: true });
  const procRoot = path.join(dir, "proc");
  // Machine start time in the past of "now": every symlink above is NEWER than a process started at boot + 1s, so give
  // the fake server a start time in the future unless a test wants the opposite.
  const nowSec = Math.floor(Date.now() / 1000);
  const m = { dir, home, tree, store, procRoot, script: path.join(store, "current/node_modules/paperclipai/dist/index.js"), nowSec };
  /** Add a process. argv/env/cgroup are overridable; defaults describe `node <script> run --instance default` under paperclipai.service. */
  m.server = (o = {}) => {
    const pid = o.pid ?? 4242;
    const p = path.join(procRoot, String(pid));
    fs.mkdirSync(p, { recursive: true });
    const argv = o.argv ?? ["/usr/local/bin/node", m.script, "run", "--instance", "default"];
    fs.writeFileSync(path.join(p, "cmdline"), o.cmdline ?? `${argv.join("\0")}\0`);
    const env = { HOME: home, PATH: "/usr/bin", PAPERCLIP_AGENT_JWT_SECRET: SENTINEL, ...(o.env ?? {}) };
    fs.writeFileSync(path.join(p, "environ"), `${Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\0")}\0`);
    fs.writeFileSync(path.join(p, "cgroup"), o.cgroup ?? `0::/user.slice/user-${UID}.slice/user@${UID}.service/app.slice/paperclipai.service\n`);
    const ticks = o.startTicks ?? 1000;
    fs.writeFileSync(path.join(p, "stat"), `${pid} (node) S 1 ${pid} ${pid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 ${ticks} 0 0\n`);
    fs.writeFileSync(path.join(p, "status"), `Name:\tnode\nUid:\t${o.uid ?? UID}\t${o.uid ?? UID}\t${o.uid ?? UID}\t${o.uid ?? UID}\n`);
    fs.rmSync(path.join(p, "cwd"), { force: true });
    fs.symlinkSync(o.cwd ?? home, path.join(p, "cwd"));
    fs.rmSync(path.join(p, "exe"), { force: true });
    fs.symlinkSync(o.exe ?? "/usr/local/bin/node", path.join(p, "exe"));
    // /proc/stat: boot time chosen so the process "started" at nowSec + 100 s (after every file above was created),
    // or o.startedAgoSec seconds ago.
    const start = o.startedAgoSec !== undefined ? nowSec - o.startedAgoSec : nowSec + 100;
    fs.writeFileSync(path.join(procRoot, "stat"), `cpu 0 0 0 0\nbtime ${Math.round(start - ticks / 100)}\n`);
    return pid;
  };
  m.resolve = (pid = 4242, over = {}) => resolveTargetFromParent({ pid, procRoot, uid: UID, userHome: home, ...over });
  return m;
}
const refused = (r, code) => { assert.equal(r.ok, false, JSON.stringify(r.target ?? r)); assert.equal(r.code, code, r.reason); return r; };

// ------------------------------------------------------------------------------------------------ derivation
test("default launch (`paperclipai run --instance default` as paperclipai.service): tree, instance, data, settings file, verified unit", () => {
  const m = machine();
  m.server();
  const r = m.resolve();
  assert.equal(r.ok, true, r.reason);
  const t = r.target;
  assert.equal(t.tree, fs.realpathSync(m.tree));
  assert.equal(t.home, path.join(m.home, ".paperclip"));
  assert.equal(t.instanceId, "default");
  assert.equal(t.instanceRoot, path.join(m.home, ".paperclip/instances/default"));
  assert.equal(t.dataDir, path.join(m.home, ".paperclip/sandbox-hardening"));
  assert.equal(t.configPath, path.join(m.home, ".paperclip/instances/default/hardening/config.json"));
  assert.equal(t.runLogBase, path.join(m.home, ".paperclip/instances/default/data/run-logs"));
  assert.deepEqual(t.restart, { unit: "paperclipai.service", cgroup: `/user.slice/user-${UID}.slice/user@${UID}.service/app.slice/paperclipai.service`, pid: 4242 });
  assert.equal(t.startedAt, new Date((m.nowSec + 100) * 1000).toISOString());
  assert.deepEqual(Object.keys(t.fingerprint).sort(), ["cmdlineSha", "pid", "startTicks"]);
  // No environment value other than the wanted ones is kept anywhere.
  assert.ok(!JSON.stringify(r).includes(SENTINEL));
  assert.ok(!JSON.stringify(summarizeTarget(t)).includes(SENTINEL));
});

test("--instance and --data-dir flags win over the start-up environment (as in Paperclip); short and = forms; ~ expands in the server's home", () => {
  const m = machine();
  const env = { PAPERCLIP_HOME: "/does/not/matter", PAPERCLIP_INSTANCE_ID: "fromenv" };
  m.server({ argv: ["node", m.script, "run", "--instance", "foo", "--data-dir", path.join(m.dir, "pc")], env, cgroup: `0::/user.slice/user-${UID}.slice/user@${UID}.service/app.slice/paperclipai-foo.service\n` });
  let t = m.resolve().target;
  assert.equal(t.instanceId, "foo");
  assert.equal(t.home, path.join(m.dir, "pc"));
  assert.equal(t.instanceRoot, path.join(m.dir, "pc/instances/foo"));
  assert.equal(t.dataDir, path.join(m.dir, "pc/sandbox-hardening"));
  assert.equal(t.restart.unit, "paperclipai-foo.service");
  m.server({ argv: ["node", m.script, "run", "-ifoo", "-d", "~/pc2"], env });
  t = m.resolve().target;
  assert.equal(t.instanceId, "foo");
  assert.equal(t.home, path.join(m.home, "pc2"));
  m.server({ argv: ["node", m.script, "run", "--instance=bar", "--data-dir=~", "--bind", "-i"], env });
  t = m.resolve().target; // `--bind` takes the next argument as its value, so the trailing -i is not an instance flag
  assert.equal(t.instanceId, "bar");
  assert.equal(t.home, m.home);
});

test("environment only: PAPERCLIP_HOME and PAPERCLIP_INSTANCE_ID of the server; HOME of the server decides the default home", () => {
  const m = machine();
  m.server({ argv: ["node", m.script, "run"], env: { PAPERCLIP_HOME: path.join(m.dir, "pc"), PAPERCLIP_INSTANCE_ID: "dev" } });
  const t = m.resolve().target;
  assert.equal(t.instanceId, "dev");
  assert.equal(t.instanceRoot, path.join(m.dir, "pc/instances/dev"));
  assert.equal(t.restart.unit, null); // cgroup says paperclipai.service, but Paperclip's own name for "dev" is paperclipai-dev.service
  assert.match(t.restart.reason, /paperclipai-dev\.service/);
  // Another HOME (a scratch Paperclip started by the same user): the default home follows the SERVER's HOME, not the worker's.
  const other = path.join(m.dir, "otherhome");
  fs.mkdirSync(other);
  m.server({ env: { HOME: other } });
  assert.equal(m.resolve().target.home, path.join(other, ".paperclip"));
  // No HOME at all in the server's environment: the account's passwd home, passed in here.
  m.server({ env: { HOME: "" } });
  assert.equal(m.resolve(4242, { userHome: path.join(m.dir, "passwd-home") }).target.home, path.join(m.dir, "passwd-home", ".paperclip"));
});

test("deployment mode as the server resolves it: PAPERCLIP_DEPLOYMENT_MODE (environment, else .env), else server.deploymentMode of its config.json, else local_trusted", () => {
  const mode = (setup, env = {}) => {
    const m = machine();
    m.server({ env });
    setup?.(m);
    const r = m.resolve();
    assert.equal(r.ok, true, r.reason);
    return r.target.deploymentMode;
  };
  const instance = (m) => path.join(m.home, ".paperclip/instances/default");
  const writeConfig = (m, text) => { fs.mkdirSync(instance(m), { recursive: true }); fs.writeFileSync(path.join(instance(m), "config.json"), text); };
  assert.equal(mode(), "local_trusted", "no config file: the server's default");
  assert.equal(mode((m) => writeConfig(m, JSON.stringify({ server: { deploymentMode: "authenticated" } }))), "authenticated");
  assert.equal(mode((m) => writeConfig(m, JSON.stringify({ server: { deploymentMode: "local_trusted" } }))), "local_trusted");
  assert.equal(mode((m) => writeConfig(m, JSON.stringify({ server: {} }))), "local_trusted", "the key is absent: the default");
  assert.equal(mode((m) => writeConfig(m, JSON.stringify({ server: { deploymentMode: "authenticated" } })), { PAPERCLIP_DEPLOYMENT_MODE: "local_trusted" }), "local_trusted", "the environment wins");
  assert.equal(mode((m) => writeConfig(m, JSON.stringify({ server: { deploymentMode: "local_trusted" } })), { PAPERCLIP_DEPLOYMENT_MODE: "authenticated" }), "authenticated");
  assert.equal(mode((m) => writeConfig(m, JSON.stringify({ server: { deploymentMode: "local_trusted" } })), { PAPERCLIP_DEPLOYMENT_MODE: "bogus" }), "local_trusted", "an invalid value is ignored, as the server does");
  assert.equal(mode((m) => { writeConfig(m, JSON.stringify({ server: { deploymentMode: "local_trusted" } })); fs.writeFileSync(path.join(instance(m), ".env"), "PAPERCLIP_DEPLOYMENT_MODE=authenticated\n"); }), "authenticated", "a .env the server loads gives it too");
  assert.equal(mode((m) => writeConfig(m, "{ not json")), null, "unreadable: not guessed");
  assert.equal(mode((m) => writeConfig(m, JSON.stringify({ server: { deploymentMode: "weird" } }))), null);
});

test("invalid instance id and relative home are refused", () => {
  const m = machine();
  m.server({ argv: ["node", m.script, "run", "--instance", "../x"] });
  refused(m.resolve(), "BAD_INSTANCE");
  m.server({ env: { HOME: "relative/home" } });
  refused(m.resolve(4242, { userHome: "relative/home" }), "BAD_INSTANCE");
  assert.throws(() => describeInstanceLayout({ home: "/h", instanceId: "a b" }), TargetError);
  assert.throws(() => describeInstanceLayout({ home: "h", instanceId: "ab" }), TargetError);
});

test("the server's config must be its instance's config.json (-c, PAPERCLIP_CONFIG, a .paperclip/config.json above its cwd)", () => {
  const m = machine();
  const own = path.join(m.home, ".paperclip/instances/default/config.json");
  m.server({ argv: ["node", m.script, "run", "-c", "/elsewhere/config.json"] });
  refused(m.resolve(), "CONFIG_LAYOUT");
  m.server({ argv: ["node", m.script, "run", "-c", own] });
  assert.equal(m.resolve().ok, true);
  m.server({ env: { PAPERCLIP_CONFIG: "/elsewhere/config.json" } });
  refused(m.resolve(), "CONFIG_LAYOUT");
  m.server({ env: { PAPERCLIP_CONFIG: own } });
  assert.equal(m.resolve().ok, true);
  // A repo-local config found above the cwd wins over the instance default unless --data-dir pins the default.
  const work = path.join(m.dir, "work/sub");
  fs.mkdirSync(path.join(m.dir, "work/.paperclip"), { recursive: true });
  fs.writeFileSync(path.join(m.dir, "work/.paperclip/config.json"), "{}");
  fs.mkdirSync(work, { recursive: true });
  m.server({ cwd: work });
  refused(m.resolve(), "CONFIG_LAYOUT");
  m.server({ cwd: work, argv: ["node", m.script, "run", "--data-dir", path.join(m.home, ".paperclip")] });
  assert.equal(m.resolve().ok, true);
});

test("settings file: PAPERCLIP_HARDENING_CONFIG (absolute only), else the key in the instance's .env, else <instance>/hardening/config.json", () => {
  const m = machine();
  m.server({ env: { PAPERCLIP_HARDENING_CONFIG: "/srv/pc/h.json" } });
  assert.equal(m.resolve().target.configPath, "/srv/pc/h.json");
  m.server({ env: { PAPERCLIP_HARDENING_CONFIG: "rel/h.json" } });
  refused(m.resolve(), "BAD_CONFIG_PATH");
  const instanceRoot = path.join(m.home, ".paperclip/instances/default");
  fs.mkdirSync(instanceRoot, { recursive: true });
  fs.writeFileSync(path.join(instanceRoot, ".env"), `OTHER_SECRET=${SENTINEL}\nexport PAPERCLIP_HARDENING_CONFIG="/srv/env/h.json" # c\n`);
  m.server();
  const r = m.resolve();
  assert.equal(r.target.configPath, "/srv/env/h.json");
  assert.ok(!JSON.stringify(r).includes(SENTINEL), "only the one key is read from .env");
  m.server({ env: { PAPERCLIP_HARDENING_CONFIG: "/srv/pc/h.json" } });
  assert.equal(m.resolve().target.configPath, "/srv/pc/h.json", "the process environment wins over .env (dotenv does not override)");
  fs.writeFileSync(path.join(instanceRoot, ".env"), "PAPERCLIP_HARDENING_CONFIG=relative.json\n");
  m.server();
  refused(m.resolve(), "BAD_CONFIG_PATH");
  assert.equal(readDotenvKey("A=1\nK=a\nK='b'\n", "K"), "b");
  assert.equal(readDotenvKey("K2=1\n", "K"), undefined);
});

test("PAPERCLIP_SANDBOX_WORKSPACE_ROOT (environment, else .env) is reported for the settings-file writer; nothing else is kept", () => {
  const m = machine();
  m.server();
  assert.equal(m.resolve().target.sandboxRootsEnv, "");
  m.server({ env: { PAPERCLIP_SANDBOX_WORKSPACE_ROOT: "/srv/a:/srv/b" } });
  assert.equal(m.resolve().target.sandboxRootsEnv, "/srv/a:/srv/b");
  const instanceRoot = path.join(m.home, ".paperclip/instances/default");
  fs.mkdirSync(instanceRoot, { recursive: true });
  fs.writeFileSync(path.join(instanceRoot, ".env"), `OTHER_SECRET=${SENTINEL}\nPAPERCLIP_SANDBOX_WORKSPACE_ROOT=/srv/env\n`);
  m.server();
  const r = m.resolve();
  assert.equal(r.target.sandboxRootsEnv, "/srv/env");
  assert.ok(!JSON.stringify(r).includes(SENTINEL));
});

/** Write a `.env` into <home>/.paperclip/instances/<id>/ and return its path. */
function writeEnv(m, id, lines) {
  const dir = path.join(m.home, ".paperclip/instances", id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, ".env"), `${lines.join("\n")}\n`);
  return path.join(dir, ".env");
}

test(".env files as Paperclip loads them: PAPERCLIP_HARDENING_CONFIG comes from the first loaded file that has it, the environment first", () => {
  const m = machine();
  // `run --instance foo` loads the DEFAULT instance's .env first (the config is resolved without --instance), then foo's.
  const foo = ["node", m.script, "run", "--instance", "foo"];
  const unit = `0::/user.slice/user-${UID}.slice/user@${UID}.service/app.slice/paperclipai-foo.service\n`;
  writeEnv(m, "foo", ["PAPERCLIP_HARDENING_CONFIG=/srv/foo/h.json"]);
  m.server({ argv: foo, cgroup: unit });
  assert.equal(m.resolve().target.configPath, "/srv/foo/h.json", "only the instance's own .env has it");
  writeEnv(m, "default", [`OTHER=${SENTINEL}`, "PAPERCLIP_HARDENING_CONFIG=/srv/default/h.json"]);
  const r = m.resolve();
  assert.equal(r.target.configPath, "/srv/default/h.json", "the default instance's .env is loaded first, and nothing is overridden");
  assert.ok(!JSON.stringify(r).includes(SENTINEL), "only the wanted keys are read from a .env");
  m.server({ argv: foo, cgroup: unit, env: { PAPERCLIP_HARDENING_CONFIG: "/srv/env/h.json" } });
  assert.equal(m.resolve().target.configPath, "/srv/env/h.json", "the start-up environment wins over every .env");
  m.server({ argv: foo, cgroup: unit, env: { PAPERCLIP_HARDENING_CONFIG: "" } });
  assert.equal(m.resolve().target.configPath, path.join(m.home, ".paperclip/instances/foo/hardening/config.json"), "a variable that is set, even empty, is not overridden by a .env");
  // The default instance's .env is also the first one for a plain `run --instance default`, and it is loaded once.
  m.server({ argv: ["node", m.script, "run", "--instance", "default"] });
  assert.equal(m.resolve().target.configPath, "/srv/default/h.json");
  // An unreadable .env is skipped, as dotenv skips it.
  fs.chmodSync(path.join(m.home, ".paperclip/instances/default/.env"), 0o000);
  try {
    if (process.getuid() !== 0) assert.equal(m.resolve().target.configPath, path.join(m.home, ".paperclip/instances/default/hardening/config.json"));
  } finally { fs.chmodSync(path.join(m.home, ".paperclip/instances/default/.env"), 0o600); }
});

test(".env files: PAPERCLIP_HOME, PAPERCLIP_INSTANCE_ID or PAPERCLIP_CONFIG given only by a loaded .env is a CONFIG_LAYOUT refusal, without the value", () => {
  const m = machine();
  const own = path.join(m.home, ".paperclip/instances/default/config.json");
  const defaultEnv = (lines) => writeEnv(m, "default", lines);
  const refusedKey = (key, file) => {
    const r = refused(m.resolve(), "CONFIG_LAYOUT");
    assert.ok(r.reason.includes(key) && r.reason.includes(file), r.reason);
    assert.ok(!JSON.stringify(r).includes(SENTINEL), "the value is never reported");
  };
  for (const key of ["PAPERCLIP_HOME", "PAPERCLIP_INSTANCE_ID", "PAPERCLIP_CONFIG"]) {
    const file = defaultEnv([`${key}=${key === "PAPERCLIP_INSTANCE_ID" ? SENTINEL : `/${SENTINEL}`}`]);
    m.server({ argv: ["node", m.script, "run"] });
    refusedKey(key, file);
  }
  // PAPERCLIP_HOME: `.env` first loaded for `run --instance default` (no home flag, no home in the environment).
  const home = defaultEnv([`PAPERCLIP_HOME=/${SENTINEL}`]);
  m.server();
  refusedKey("PAPERCLIP_HOME", home);
  // ... but not when the home is already given, even as an empty string, by the environment or --data-dir.
  m.server({ env: { PAPERCLIP_HOME: path.join(m.home, ".paperclip") } });
  assert.equal(m.resolve().ok, true);
  m.server({ env: { PAPERCLIP_HOME: "" } });
  assert.equal(m.resolve().ok, true, "set (even empty) is not overridden by a .env");
  m.server({ argv: ["node", m.script, "run", "--data-dir", path.join(m.home, ".paperclip")] });
  assert.equal(m.resolve().ok, true);
  // PAPERCLIP_INSTANCE_ID: only a flag or the environment keeps it from being taken from a .env.
  defaultEnv([`PAPERCLIP_INSTANCE_ID=${SENTINEL}`]);
  m.server({ argv: ["node", m.script, "run"] });
  refused(m.resolve(), "CONFIG_LAYOUT");
  m.server({ argv: ["node", m.script, "run", "-i", "default"] });
  assert.equal(m.resolve().ok, true, "--instance wins");
  m.server({ argv: ["node", m.script, "run"], env: { PAPERCLIP_INSTANCE_ID: "default" } });
  assert.equal(m.resolve().ok, true, "the environment wins");
  // PAPERCLIP_CONFIG: same, with -c or the environment.
  defaultEnv([`PAPERCLIP_CONFIG=/${SENTINEL}/config.json`]);
  m.server();
  refused(m.resolve(), "CONFIG_LAYOUT");
  m.server({ argv: ["node", m.script, "run", "-c", own] });
  assert.equal(m.resolve().ok, true, "-c wins");
  m.server({ env: { PAPERCLIP_CONFIG: own } });
  assert.equal(m.resolve().ok, true, "the environment wins");
  // The .env of the instance the server runs (loaded second) can still set the home.
  defaultEnv(["# nothing"]);
  const foo = writeEnv(m, "foo", [`PAPERCLIP_HOME=/${SENTINEL}`]);
  m.server({ argv: ["node", m.script, "run", "--instance", "foo"] });
  refusedKey("PAPERCLIP_HOME", foo);
  // An id or home that is not usable stays a plain refusal; an empty .env value changes nothing.
  writeEnv(m, "foo", ["PAPERCLIP_HOME=", "PAPERCLIP_INSTANCE_ID=", "PAPERCLIP_CONFIG="]);
  m.server({ argv: ["node", m.script, "run", "--instance", "foo"] });
  assert.equal(m.resolve().ok, true);
});

/** A working directory <m.dir>/work holding a `.env` with these lines; returns [dir, file]. */
function writeCwdEnv(m, lines) {
  const dir = path.join(m.dir, "work");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, ".env"), `${lines.join("\n")}\n`);
  return [dir, path.join(dir, ".env")];
}

test("the .env in the server's working directory is loaded last (config.js of the server), without overriding anything", () => {
  const m = machine();
  const defaultRoot = path.join(m.home, ".paperclip/instances/default");
  const [work, file] = writeCwdEnv(m, [`OTHER=${SENTINEL}`, "PAPERCLIP_HARDENING_CONFIG=/srv/cwd/h.json", "PAPERCLIP_SANDBOX_WORKSPACE_ROOT=/srv/cwd"]);
  m.server({ cwd: work });
  let r = m.resolve();
  assert.equal(r.target.configPath, "/srv/cwd/h.json");
  assert.equal(r.target.sandboxRootsEnv, "/srv/cwd");
  assert.ok(!JSON.stringify(r).includes(SENTINEL), "only the wanted keys are read");
  // The first source that has a key wins: the start-up environment, then the instance's own .env, then the working directory's.
  writeEnv(m, "default", ["PAPERCLIP_HARDENING_CONFIG=/srv/instance/h.json"]);
  assert.equal(m.resolve().target.configPath, "/srv/instance/h.json");
  m.server({ cwd: work, env: { PAPERCLIP_HARDENING_CONFIG: "/srv/env/h.json" } });
  assert.equal(m.resolve().target.configPath, "/srv/env/h.json");
  // PAPERCLIP_DISABLE_CWD_ENV_FILE must be exactly "true", in the environment or in a .env loaded before.
  fs.rmSync(path.join(defaultRoot, ".env"));
  m.server({ cwd: work, env: { PAPERCLIP_DISABLE_CWD_ENV_FILE: "true" } });
  assert.equal(m.resolve().target.configPath, path.join(defaultRoot, "hardening/config.json"));
  writeEnv(m, "default", ["PAPERCLIP_DISABLE_CWD_ENV_FILE=true"]);
  m.server({ cwd: work });
  assert.equal(m.resolve().target.configPath, path.join(defaultRoot, "hardening/config.json"), "set by the instance's .env");
  for (const v of ["TRUE", "1", " true", ""]) {
    m.server({ cwd: work, env: { PAPERCLIP_DISABLE_CWD_ENV_FILE: v } });
    assert.equal(m.resolve().target.configPath, "/srv/cwd/h.json", `'${v}' does not disable it`);
  }
  // The working directory is the instance folder itself, also through a symlink: the same file, not another source.
  fs.writeFileSync(path.join(defaultRoot, ".env"), "PAPERCLIP_HARDENING_CONFIG=/srv/instance/h.json\n");
  const link = path.join(m.dir, "link");
  fs.symlinkSync(defaultRoot, link);
  for (const cwd of [defaultRoot, link]) {
    m.server({ cwd });
    assert.equal(m.resolve().target.configPath, "/srv/instance/h.json");
  }
  assert.ok(file);
});

test("the working directory's .env cannot change the home; an instance id or config it holds is never used", () => {
  const m = machine();
  const [work, file] = writeCwdEnv(m, [`PAPERCLIP_HOME=/${SENTINEL}`]);
  m.server({ cwd: work });
  const r = refused(m.resolve(), "CONFIG_LAYOUT");
  assert.ok(r.reason.includes("PAPERCLIP_HOME") && r.reason.includes(file), r.reason);
  assert.ok(!JSON.stringify(r).includes(SENTINEL), "the value is never reported");
  m.server({ cwd: work, env: { PAPERCLIP_HOME: path.join(m.home, ".paperclip") } });
  assert.equal(m.resolve().ok, true, "already set");
  m.server({ cwd: work, argv: ["node", m.script, "run", "--data-dir", path.join(m.home, ".paperclip")] });
  assert.equal(m.resolve().ok, true, "--data-dir");
  m.server({ cwd: work, env: { PAPERCLIP_DISABLE_CWD_ENV_FILE: "true" } });
  assert.equal(m.resolve().ok, true, "disabled");
  // By then the instance and the config are set by `paperclipai run` itself, so a .env cannot supply them.
  writeCwdEnv(m, [`PAPERCLIP_INSTANCE_ID=${SENTINEL}`, `PAPERCLIP_CONFIG=/${SENTINEL}/config.json`]);
  m.server({ cwd: work });
  assert.equal(m.resolve().ok, true);
});

test("run-log directory: RUN_LOG_BASE_PATH as the server's run-log store reads it (any source, untrimmed, relative to its working directory)", () => {
  const m = machine();
  const dflt = path.join(m.home, ".paperclip/instances/default/data/run-logs");
  m.server({ env: { RUN_LOG_BASE_PATH: path.join(m.dir, "logs") } });
  assert.equal(m.resolve().target.runLogBase, path.join(m.dir, "logs"));
  m.server();
  assert.equal(m.resolve().target.runLogBase, dflt);
  // Only a .env gives it: the instance's own, or the working directory's.
  writeEnv(m, "default", [`RUN_LOG_BASE_PATH=${path.join(m.dir, "from-env-file")}`]);
  assert.equal(m.resolve().target.runLogBase, path.join(m.dir, "from-env-file"));
  m.server({ env: { RUN_LOG_BASE_PATH: path.join(m.dir, "logs") } });
  assert.equal(m.resolve().target.runLogBase, path.join(m.dir, "logs"), "the environment wins");
  fs.rmSync(path.join(m.home, ".paperclip/instances/default/.env"));
  const [work] = writeCwdEnv(m, ["RUN_LOG_BASE_PATH=rel/logs"]);
  m.server({ cwd: work });
  assert.equal(m.resolve().target.runLogBase, path.join(work, "rel/logs"), "relative to the server's working directory");
  // `??` in the server: an empty value is a value (the working directory), and nothing is trimmed or home-expanded.
  m.server({ cwd: work, env: { RUN_LOG_BASE_PATH: "" } });
  assert.equal(m.resolve().target.runLogBase, work);
  m.server({ cwd: work, env: { RUN_LOG_BASE_PATH: " ~/logs " } });
  assert.equal(m.resolve().target.runLogBase, path.join(work, " ~/logs "));
  writeCwdEnv(m, ["RUN_LOG_BASE_PATH="]);
  m.server({ cwd: work });
  assert.equal(m.resolve().target.runLogBase, work, "empty in a .env is set, too");
});

test(".env files: an empty (or blank) PAPERCLIP_HOME, PAPERCLIP_INSTANCE_ID or PAPERCLIP_CONFIG is not used by Paperclip, so not a refusal", () => {
  const m = machine();
  const own = path.join(m.home, ".paperclip/instances/default/config.json");
  for (const blank of ["", '"   "']) { // dotenv trims before it strips quotes, so a quoted value can be blank
    for (const key of ["PAPERCLIP_HOME", "PAPERCLIP_INSTANCE_ID"]) {
      writeEnv(m, "default", [`${key}=${blank}`]);
      m.server({ argv: ["node", m.script, "run"] });
      const r = m.resolve();
      assert.equal(r.ok, true, `${key}='${blank}': ${r.reason}`);
      assert.equal(r.target.instanceId, "default");
      assert.equal(r.target.serverConfigPath, own);
    }
  }
  // An empty config path is not used either (`if (process.env.PAPERCLIP_CONFIG)`).
  writeEnv(m, "default", ["PAPERCLIP_HOME=", "PAPERCLIP_INSTANCE_ID=", "PAPERCLIP_CONFIG=", 'PAPERCLIP_HARDENING_CONFIG=""']);
  m.server({ argv: ["node", m.script, "run"] });
  assert.equal(m.resolve().ok, true);
  // A blank but non-empty config path IS used by Paperclip (it is not trimmed), so it is refused like any other.
  writeEnv(m, "default", ['PAPERCLIP_CONFIG="   "']);
  m.server({ argv: ["node", m.script, "run"] });
  refused(m.resolve(), "CONFIG_LAYOUT");
  // Real values keep being refused, in the `KEY: value` form too.
  writeEnv(m, "default", ["PAPERCLIP_INSTANCE_ID: other"]);
  m.server({ argv: ["node", m.script, "run"] });
  refused(m.resolve(), "CONFIG_LAYOUT");
});

test("a value is never part of a refusal: not in the reason, not in the evidence", () => {
  const m = machine();
  const secretId = `${SENTINEL} x`; // not a valid instance id
  const everything = (r) => JSON.stringify(r);
  const check = (r, code) => { refused(r, code); assert.ok(!everything(r).includes(SENTINEL), everything(r)); };
  // invalid instance id: flag, environment, .env
  m.server({ argv: ["node", m.script, "run", "--instance", secretId] });
  check(m.resolve(), "BAD_INSTANCE");
  m.server({ env: { PAPERCLIP_INSTANCE_ID: secretId }, argv: ["node", m.script, "run"] });
  check(m.resolve(), "BAD_INSTANCE");
  writeEnv(m, "default", [`PAPERCLIP_INSTANCE_ID="${secretId}"`]);
  m.server({ argv: ["node", m.script, "run"] });
  check(m.resolve(), "BAD_INSTANCE");
  // relative home
  m.server({ env: { HOME: `${SENTINEL}/relative` } });
  check(m.resolve(4242, { userHome: `${SENTINEL}/relative` }), "BAD_INSTANCE");
  // a config outside the instance, from the environment or from a flag
  fs.rmSync(path.join(m.home, ".paperclip/instances/default/.env"));
  m.server({ env: { PAPERCLIP_CONFIG: `/${SENTINEL}/config.json` } });
  check(m.resolve(), "CONFIG_LAYOUT");
  m.server({ argv: ["node", m.script, "run", "-c", `/${SENTINEL}/config.json`] });
  check(m.resolve(), "CONFIG_LAYOUT");
  // a settings path that is not absolute
  writeEnv(m, "default", [`PAPERCLIP_HARDENING_CONFIG=${SENTINEL}.json`]);
  m.server();
  check(m.resolve(), "BAD_CONFIG_PATH");
  // a value from a .env that changes the layout (home, instance, config), from either file
  for (const key of ["PAPERCLIP_HOME", "PAPERCLIP_INSTANCE_ID", "PAPERCLIP_CONFIG"]) {
    writeEnv(m, "default", [`${key}=${key === "PAPERCLIP_INSTANCE_ID" ? "" : "/"}${SENTINEL}`]);
    m.server({ argv: ["node", m.script, "run"] });
    check(m.resolve(), "CONFIG_LAYOUT");
  }
  // runtime-info.json from another instance
  fs.rmSync(path.join(m.home, ".paperclip/instances/default/.env"));
  fs.writeFileSync(path.join(m.home, ".paperclip/instances/default/runtime-info.json"), JSON.stringify({ pid: 4242, instanceId: SENTINEL }));
  m.server();
  check(m.resolve(), "INSTANCE_MISMATCH");
  // describeInstanceLayout (the command-line tool's rules)
  for (const input of [{ home: "/h", instanceId: secretId }, { home: `${SENTINEL}/h`, instanceId: "a" }]) {
    try { describeInstanceLayout(input); assert.fail("must throw"); }
    catch (e) { assert.ok(e instanceof TargetError && !`${e.message}${JSON.stringify(e.evidence)}`.includes(SENTINEL), e.message); }
  }
});

test("readDotenvKey reads a file the way dotenv does (same pattern and value rules as dotenv 17.4.2)", () => {
  const text = [
    "A: x # comment", "B=  y z  # comment", "export C = c1", "D='it\\'s' # c", 'E="q # not a comment\\nline2"', "F=`b`", "G=", "H",
    "I=a#b", "J = 'single # not kept' trailing", "# K=comment", "  L=indented", 'M="multi', 'line"', "N=1", "N=2", "O:no-space", "export P: 5",
    "Q=\"cr\\rx\"", "R.S-T=dots", "U='a\\nb'",
  ].join("\r\n");
  const want = { A: "x", B: "y z", C: "c1", D: "it\\'s", E: "q # not a comment\nline2", F: "b", G: "", H: undefined, I: "a", J: "'single", K: undefined, L: "indented", M: "multi\nline", N: "2", O: undefined, P: "5", Q: "cr\rx", "R.S-T": "dots", U: "a\\nb" };
  for (const [k, v] of Object.entries(want)) assert.equal(readDotenvKey(text, k), v, k);
  // Differential: the installed dotenv, when present, parses the same.
  let dotenv;
  try { dotenv = createRequire(import.meta.url)(path.join(os.homedir(), ".paperclip/cli/current/node_modules/dotenv/lib/main.js")); } catch { /* not installed here */ }
  if (dotenv) {
    const parsed = dotenv.parse(text);
    for (const k of Object.keys(want)) assert.equal(readDotenvKey(text, k), parsed[k], `dotenv: ${k}`);
  }
});


test("not a plain `paperclipai run` of a managed tree: parent 1, foreign uid, other launchers, other layouts, missing tree", () => {
  const m = machine();
  refused(m.resolve(1), "NO_PARENT");
  refused(m.resolve(0), "NO_PARENT");
  refused(m.resolve(Number.NaN), "NO_PARENT");
  m.server({ uid: UID + 1 });
  refused(m.resolve(), "FOREIGN_UID");
  m.server({ exe: "/usr/bin/python3" });
  refused(m.resolve(), "UNKNOWN_LAUNCHER");
  m.server({ exe: "/usr/local/bin/node (deleted)" });
  assert.equal(m.resolve().ok, true, "node replaced on disk while running is still node");
  m.server({ argv: ["node", "--import", "tsx", m.script, "run"] });
  assert.equal(m.resolve().ok, true, "node options before the script are skipped");
  m.server({ argv: ["node", "--import", "tsx", "/srv/app/server/src/index.ts"] }); // tsx dev run
  refused(m.resolve(), "UNKNOWN_LAUNCHER");
  const other = path.join(m.dir, "app/dist");
  fs.mkdirSync(other, { recursive: true });
  fs.writeFileSync(path.join(other, "index.js"), "");
  m.server({ argv: ["node", path.join(other, "index.js"), "run"] }); // docker/pm2 style layout
  refused(m.resolve(), "UNKNOWN_LAUNCHER");
  m.server({ argv: ["node", m.script, "service", "install"] });
  refused(m.resolve(), "UNKNOWN_LAUNCHER");
  m.server({ argv: ["node", m.script] });
  refused(m.resolve(), "UNKNOWN_LAUNCHER");
  m.server({ argv: ["node", m.script, "run", "--instance"] });
  refused(m.resolve(), "UNKNOWN_LAUNCHER");
  m.server({ argv: ["node", "/gone/node_modules/paperclipai/dist/index.js", "run"] });
  refused(m.resolve(), "NO_TREE");
  fs.rmSync(path.join(m.tree, "node_modules/@paperclipai/server/package.json"));
  m.server();
  refused(m.resolve(), "NO_TREE");
});

test("command line oddities: empty, no trailing NUL, empty arguments", () => {
  assert.equal(parseCmdline(Buffer.alloc(0)), null);
  assert.deepEqual(parseCmdline(Buffer.from("a\0b")), ["a", "b"]);
  assert.deepEqual(parseCmdline(Buffer.from("a\0\0b\0")), ["a", "", "b"]);
  const m = machine();
  m.server({ cmdline: "" });
  refused(m.resolve(), "PROC_UNREADABLE");
  m.server({ cmdline: `node\0${m.script}\0run\0\0--instance\0default` });
  assert.equal(m.resolve().ok, true, "an empty argument and a missing trailing NUL are fine");
  assert.throws(() => parseServerCommand(["node"]), TargetError);
});

test("node --env-file options load variables /proc does not show: refused as an unknown launcher, without reading or reporting the file", () => {
  const m = machine();
  const file = path.join(m.dir, `${SENTINEL}.env`);
  for (const opts of [["--env-file", file], [`--env-file=${file}`], ["--env-file-if-exists", file], [`--env-file-if-exists=${file}`], ["--no-warnings", `--env-file=${file}`]]) {
    m.server({ argv: ["node", ...opts, m.script, "run", "--instance", "default"] });
    const r = refused(m.resolve(), "UNKNOWN_LAUNCHER");
    assert.match(r.reason, /--env-file/);
    assert.ok(!JSON.stringify(r).includes(SENTINEL), "the file name is not reported");
    assert.throws(() => parseServerCommand(["node", ...opts, m.script, "run"]), (e) => e instanceof TargetError && e.code === "UNKNOWN_LAUNCHER");
  }
  m.server({ argv: ["node", "--no-warnings", "--title", "--env-file-x", m.script, "run", "--instance", "default"] });
  assert.equal(m.resolve().ok, true, "an option VALUE or a different option that merely resembles it is not an env-file option");
  m.server({ argv: ["node", m.script, "run", "--instance", "default", "--env-file", file] });
  assert.equal(m.resolve().ok, true, "after the script it is an argument of paperclipai, not a node option");
});

test("dotenv vault mode: with DOTENV_KEY set, config() reads <file>.vault instead of the .env (environment or an earlier .env gives the key)", () => {
  const vaultOf = (file) => fs.writeFileSync(`${file}.vault`, "# stub\n");
  // Key in the server's environment, vault beside the instance .env.
  let m = machine();
  const own = writeEnv(m, "default", ["RUN_LOG_BASE_PATH=/x"]);
  vaultOf(own);
  m.server({ env: { DOTENV_KEY: `dotenv://:key_${SENTINEL}@dotenvx.com/vault/.env.vault?environment=production` } });
  let r = refused(m.resolve(), "CONFIG_LAYOUT");
  assert.ok(r.reason.includes("DOTENV_KEY") && r.reason.includes(`${own}.vault`), r.reason);
  assert.ok(!JSON.stringify(r).includes(SENTINEL), "the key is never reported");
  m.server({ env: { DOTENV_KEY: "" } });
  assert.equal(m.resolve().ok, true, "an empty DOTENV_KEY is no key (dotenv falls back to the plain file)");
  m.server();
  assert.equal(m.resolve().ok, true, "a vault without a key is ignored by dotenv");
  // Vault but no .env: dotenv is not called at all (the loaders check for the file first).
  m = machine();
  const vaultOnly = path.join(m.home, ".paperclip/instances/default/.env");
  fs.mkdirSync(path.dirname(vaultOnly), { recursive: true });
  vaultOf(vaultOnly);
  m.server({ env: { DOTENV_KEY: SENTINEL } });
  assert.equal(m.resolve().ok, true);
  // The key comes from an earlier loaded .env: the next file is read as a vault.
  m = machine();
  const first = writeEnv(m, "default", [`DOTENV_KEY=${SENTINEL}`]);
  const [work, cwdEnv] = writeCwdEnv(m, ["RUN_LOG_BASE_PATH=/y"]);
  vaultOf(cwdEnv);
  m.server({ cwd: work });
  r = refused(m.resolve(), "CONFIG_LAYOUT");
  assert.ok(r.reason.includes(`${cwdEnv}.vault`), r.reason);
  assert.ok(!r.reason.includes(first) && !JSON.stringify(r).includes(SENTINEL));
  m.server({ cwd: work, env: { DOTENV_KEY: "" } });
  assert.equal(m.resolve().ok, true, "set (even empty) in the environment, a .env cannot give DOTENV_KEY");
  m.server({ cwd: work, env: { PAPERCLIP_DISABLE_CWD_ENV_FILE: "true" } });
  assert.equal(m.resolve().ok, true, "the working-directory .env is not loaded");
  // parseEnviron keeps no value of DOTENV_KEY, only whether it is non-empty.
  assert.deepEqual(parseEnviron(Buffer.from(`DOTENV_KEY=${SENTINEL}\0`)), { DOTENV_KEY: "1" });
  assert.deepEqual(parseEnviron(Buffer.from("DOTENV_KEY=\0")), { DOTENV_KEY: "" });
});

test("a symlink on the way to the script changed after the server started: the files on disk are not what runs", () => {
  const m = machine();
  m.server({ startedAgoSec: 3600 }); // the cli/current link above was created just now
  const r = refused(m.resolve(), "STALE_LAUNCH");
  assert.match(r.reason, /restart Paperclip first/);
  m.server({ startedAgoSec: -100 });
  assert.equal(m.resolve().ok, true);
});

test("runtime-info.json of the server naming another instance is a mismatch (corroboration only otherwise)", () => {
  const m = machine();
  const dir = path.join(m.home, ".paperclip/instances/default");
  fs.mkdirSync(dir, { recursive: true });
  m.server();
  fs.writeFileSync(path.join(dir, "runtime-info.json"), JSON.stringify({ pid: 4242, instanceId: "other" }));
  refused(m.resolve(), "INSTANCE_MISMATCH");
  fs.writeFileSync(path.join(dir, "runtime-info.json"), JSON.stringify({ pid: 1, instanceId: "other" }));
  assert.equal(m.resolve().ok, true, "a record of another pid is ignored");
  fs.writeFileSync(path.join(dir, "runtime-info.json"), "not json");
  assert.equal(m.resolve().ok, true);
});

test("unreadable /proc entries (hidepid, gone process) refuse and say so", () => {
  const m = machine();
  refused(m.resolve(777), "PROC_UNREADABLE");
  m.server();
  fs.rmSync(path.join(m.procRoot, "4242/environ"));
  const r = refused(m.resolve(), "PROC_UNREADABLE");
  assert.match(r.reason, /hidepid/);
  m.server();
  fs.chmodSync(path.join(m.procRoot, "4242/environ"), 0o000);
  if (UID !== 0) refused(m.resolve(), "PROC_UNREADABLE");
  fs.chmodSync(path.join(m.procRoot, "4242/environ"), 0o600);
});

test("restart unit: only a .service below the user manager of this uid, only Paperclip's own name, only cgroup v2", () => {
  const u = `/user.slice/user-${UID}.slice/user@${UID}.service`;
  assert.deepEqual(parseCgroup(`0::${u}/app.slice/paperclipai.service\n`, UID),
    { path: `${u}/app.slice/paperclipai.service`, unit: "paperclipai.service", cgroup: `${u}/app.slice/paperclipai.service`, reason: null });
  assert.equal(parseCgroup(`0::${u}/app.slice/paperclipai.service/sub\n`, UID).cgroup, `${u}/app.slice/paperclipai.service`);
  for (const text of [`0::${u}/app.slice/app-gnome-x.scope\n`, `0::/user.slice/user-${UID}.slice/session-3.scope\n`, "0::/\n", "0::/system.slice/docker-abc.scope\n",
    `0::/user.slice/user-${UID + 1}.slice/user@${UID + 1}.service/app.slice/paperclipai.service\n`, "12:memory:/x\n0::/y\n", "", undefined]) {
    const c = parseCgroup(text, UID);
    assert.equal(c.unit, null, String(text));
    assert.ok(c.reason, String(text));
  }
  const m = machine();
  for (const cgroup of [`0::${u}/app.slice/session-3.scope\n`, "0::/\n", `0::${u}/app.slice/paperclipai-other.service\n`]) {
    m.server({ cgroup });
    const t = m.resolve().target;
    assert.equal(t.restart.unit, null, cgroup);
    assert.ok(t.restart.reason);
    assert.equal(summarizeTarget(t).restartUnit, null);
  }
});

test("detectRestart with an expected control group: the unit must be the one Paperclip runs in", () => {
  const dir = path.join(root, "restart");
  fs.mkdirSync(path.join(dir, "cg/user.slice/p.service"), { recursive: true });
  const fake = path.join(dir, "systemctl");
  const writeFake = (props) => fs.writeFileSync(fake, `#!/bin/sh\necho LoadState=loaded\necho ActiveState=active\n${props.map((p) => `echo '${p}'`).join("\n")}\n`, { mode: 0o755 });
  const cgroup = "/user.slice/p.service";
  const opts = { unitName: "p.service", systemctl: fake, expectCgroup: cgroup, parentPid: 4242, cgroupRoot: path.join(dir, "cg") };
  writeFake([`ControlGroup=${cgroup}`, "MainPID=4242", "ExecMainStartTimestamp=@1792270891"]);
  const ok = detectRestart(opts);
  assert.equal(ok.canRestart, true);
  assert.deepEqual(ok.command, ["systemctl", "--user", "restart", "p.service"]);
  assert.equal(ok.startedAt, new Date(1792270891000).toISOString());
  writeFake(["ControlGroup=/user.slice/other.service", "MainPID=4242"]);
  assert.match(detectRestart(opts).reason, /does not run this Paperclip/);
  writeFake([`ControlGroup=${cgroup}`, "MainPID=99"]);
  assert.match(detectRestart(opts).reason, /not part of/);
  fs.writeFileSync(path.join(dir, "cg/user.slice/p.service/cgroup.procs"), "12\n4242\n");
  assert.equal(detectRestart(opts).canRestart, true, "a member of the unit's control group counts too");
  writeFake([]);
  assert.equal(detectRestart(opts).canRestart, false, "systemd reports no control group");
  assert.equal(detectRestart({ systemctl: fake }).canRestart, false);
  assert.match(detectRestart({ systemctl: fake }).reason, /no restart unit/);
});

test("verifyTarget: the same process (pid, start time, command line); anything else is a changed target", () => {
  const m = machine();
  m.server();
  const t = m.resolve().target;
  const v = () => verifyTarget(t, { procRoot: m.procRoot });
  assert.deepEqual(v(), { ok: true });
  m.server({ startTicks: 2000 }); // pid reused by a later process
  assert.equal(v().code, "TARGET_CHANGED");
  m.server({ argv: ["node", m.script, "run", "--instance", "other"] });
  assert.equal(v().code, "TARGET_CHANGED");
  fs.rmSync(path.join(m.procRoot, "4242"), { recursive: true });
  assert.equal(v().code, "TARGET_CHANGED");
  assert.deepEqual(verifyTarget({ fingerprint: null }), { ok: true }, "an explicit target is not bound to a process");
});

test("layout helpers: Paperclip's unit names, home/instance resolution, parseEnviron keeps only the wanted names", () => {
  assert.equal(systemdServiceName("default"), "paperclipai.service");
  assert.equal(systemdServiceName("dev"), "paperclipai-dev.service");
  assert.deepEqual(resolveInstanceInputs({ flags: {}, env: {}, userHome: "/h", cwd: "/w" }), { home: "/h/.paperclip", instanceId: "default" });
  assert.deepEqual(resolveInstanceInputs({ flags: { dataDir: "~/x", instance: " i " }, env: { PAPERCLIP_HOME: "/e", PAPERCLIP_INSTANCE_ID: "e" }, userHome: "/h", cwd: "/w" }), { home: "/h/x", instanceId: "i" });
  assert.deepEqual(resolveInstanceInputs({ flags: { dataDir: "rel" }, env: {}, userHome: "/h", cwd: "/w" }).home, "/w/rel");
  const l = describeInstanceLayout({ home: "/h/.paperclip", instanceId: "default" });
  assert.equal(l.configPath, "/h/.paperclip/instances/default/hardening/config.json");
  assert.equal(l.dataDir, "/h/.paperclip/sandbox-hardening");
  assert.deepEqual(parseEnviron(Buffer.from(`HOME=/h\0SECRET=${SENTINEL}\0PAPERCLIP_HOME=/p\0NOEQUALS\0`)), { HOME: "/h", PAPERCLIP_HOME: "/p" });
});

// ------------------------------------------------------------------------------------------------ strict engine
test("the engine never guesses: treeDir and dataDir are required, and PAPERCLIP_TREE, PAPERCLIP_HARDENING_DATA and HOME are ignored", () => {
  const m = machine();
  const saved = { ...process.env };
  try {
    process.env.PAPERCLIP_TREE = m.tree;
    process.env.PAPERCLIP_HARDENING_DATA = path.join(m.dir, "data");
    process.env.HOME = m.home; // a default install right there: <home>/.paperclip/cli/current
    assert.throws(() => createEngine({}), /dataDir is required/);
    assert.throws(() => createEngine({ dataDir: path.join(m.dir, "data") }), /treeDir is required/);
    assert.throws(() => createEngine({ treeDir: m.tree }), /dataDir is required/);
    const e = createEngine({ treeDir: m.tree, dataDir: path.join(m.dir, "d2") });
    assert.equal(e.dataDir, path.join(m.dir, "d2"));
    assert.equal(e.restartInfo().canRestart, false, "no unit unless the caller names one");
    assert.match(e.restartInfo().reason, /no restart unit/);
  } finally {
    for (const k of ["PAPERCLIP_TREE", "PAPERCLIP_HARDENING_DATA", "HOME"]) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  }
});

test("the engine takes its restart from the target: a target without a unit never offers one", () => {
  const m = machine();
  const e = createEngine({ treeDir: m.tree, dataDir: path.join(m.dir, "d"), restart: { unit: null, reason: "not a systemd user service" }, systemctl: "/nonexistent/systemctl" });
  assert.deepEqual([e.restartInfo().canRestart, e.restartInfo().reason], [false, "not a systemd user service"]);
});

test("no module on the plugin's worker path falls back to the account's home or to environment variables of the worker", () => {
  const SRC = path.resolve(HERE, "../src");
  const files = [];
  (function walk(d) { for (const f of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, f.name); if (f.isDirectory()) walk(p); else if (p.endsWith(".js")) files.push(p); } })(SRC);
  assert.ok(files.length > 10);
  const allowedEnv = new Set(["engine/restart.js", "engine/patches.js", "hostinstall.js", "ui.js"]); // XDG_RUNTIME_DIR, the child env of `patch`, the install URL hint
  for (const f of files) {
    const rel = path.relative(SRC, f);
    const text = fs.readFileSync(f, "utf8").split("\n").filter((l) => !l.trimStart().startsWith("//")).join("\n");
    assert.ok(!/os\.homedir\(\)/.test(text), `${rel} calls os.homedir()`);
    assert.ok(!/PAPERCLIP_TREE|PAPERCLIP_HARDENING_DATA/.test(text), `${rel} reads a tree/data environment variable`);
    if (!allowedEnv.has(rel)) assert.ok(!/process\.env/.test(text), `${rel} reads the worker's environment`);
  }
});

// ------------------------------------------------------------------------------------------------ CLI
function runCli(args, { env = {}, cwd } = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", cwd, env: { PATH: process.env.PATH, HOME: os.homedir(), ...env } });
  return { code: r.status, out: r.stdout, err: r.stderr, json: r.stdout.trim().startsWith("{") ? JSON.parse(r.stdout) : null };
}

test("CLI: --instance/--home resolve the managed install of that instance and print the target first; explicit flags win", () => {
  const m = machine();
  const home = path.join(m.home, ".paperclip");
  const r = runCli(["status", "--instance", "foo", "--home", home, "--no-systemd"]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^target \(instance foo\):\n  tree:    .*2026\.1012\.0\n  data:    .*\/\.paperclip\/sandbox-hardening\n  config:  .*\/instances\/foo\/hardening\/config\.json\n  restart: none \(disabled \(--no-systemd\)\)\n/);
  const j = runCli(["status", "--instance", "foo", "--home", home, "--json"]);
  assert.equal(j.code, 0, j.err);
  assert.equal(j.json.target.source, "instance");
  assert.equal(j.json.target.restartUnit, "paperclipai-foo.service");
  assert.equal(j.json.target.tree, fs.realpathSync(m.tree));
  assert.equal(j.json.tree, fs.realpathSync(m.tree));
  const e = runCli(["status", "--home", home, "--instance", "default", "--tree", m.tree, "--data", path.join(m.dir, "mydata"), "--unit", "mine.service", "--json"]);
  assert.equal(e.json.target.dataDir, path.join(m.dir, "mydata"));
  assert.equal(e.json.target.restartUnit, "mine.service");
  const env = runCli(["status", "--instance", "x", "--json"], { env: { PAPERCLIP_HOME: home } });
  assert.equal(env.json.target.home, home, "--instance without --home uses the operator's PAPERCLIP_HOME");
  assert.equal(env.json.target.configPath, path.join(home, "instances/x/hardening/config.json"));
  assert.equal(runCli(["status", "--instance", "../bad"]).code, 1);
  assert.equal(runCli(["status", "--pid", "abc"]).code, 2);
  assert.equal(runCli(["status", "--pid", "5", "--instance", "x"]).code, 2);
});

test("CLI: no instance flag keeps the apply.sh default (PAPERCLIP_TREE / PAPERCLIP_HARDENING_DATA) and still prints the target", () => {
  const m = machine();
  const r = runCli(["status", "--no-systemd"], { env: { HOME: m.home, PAPERCLIP_TREE: m.tree, PAPERCLIP_HARDENING_DATA: path.join(m.dir, "legacy-data") } });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^target \(default instance\):\n/);
  assert.ok(r.out.includes(`data:    ${path.join(m.dir, "legacy-data")}`));
  const d = runCli(["status", "--json"], { env: { HOME: m.home, PAPERCLIP_TREE: m.tree } });
  assert.equal(d.json.target.dataDir, path.join(m.home, ".paperclip/sandbox-hardening"));
  assert.equal(d.json.target.restartUnit, "paperclipai.service");
  const t = runCli(["status", "--tree", m.tree, "--json"], { env: { HOME: m.home } });
  assert.equal(t.json.target.configPath, null, "with --tree the default instance's settings file is not claimed");
  assert.equal(runCli(["status"], { env: { HOME: path.join(m.dir, "nohome") } }).code, 1, "no tree there: refuse, never guess");
});

test("CLI: --pid derives the target from a running server process (a real child here), read only", async () => {
  const m = machine();
  const script = path.join(fs.realpathSync(m.tree), "node_modules/paperclipai/dist/index.js");
  fs.writeFileSync(script, "setTimeout(() => {}, 60000);\n");
  const child = spawn(process.execPath, [script, "run", "--instance", "pidtest"], { cwd: m.dir, stdio: "ignore", env: { PATH: process.env.PATH, HOME: m.home, PAPERCLIP_HOME: path.join(m.dir, "pc"), PAPERCLIP_AGENT_JWT_SECRET: SENTINEL } });
  try {
    await new Promise((r) => setTimeout(r, 300));
    const r = runCli(["status", "--pid", String(child.pid), "--json"]);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.json.target.source, "server-process");
    assert.equal(r.json.target.pid, child.pid);
    assert.equal(r.json.target.instanceId, "pidtest");
    assert.equal(r.json.target.tree, fs.realpathSync(m.tree));
    assert.equal(r.json.target.dataDir, path.join(m.dir, "pc/sandbox-hardening"));
    assert.ok(!r.out.includes(SENTINEL));
    assert.ok(!fs.existsSync(path.join(m.dir, "pc")), "nothing was created");
    // The test runner itself is not a `paperclipai run` server.
    const bad = runCli(["status", "--pid", String(process.pid)]);
    assert.equal(bad.code, 1);
    assert.match(bad.err, /paperclipai run|supported server layout/);
    assert.equal(runCli(["status", "--pid", "999999"]).code, 1);
  } finally { child.kill(); }
});
