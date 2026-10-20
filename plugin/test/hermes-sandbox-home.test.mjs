// host/sandbox/hermes-sandbox finds Paperclip's adapter-utils and its allowed roots under the ACCOUNT's home (the passwd entry,
// os.userInfo().homedir), not under $HOME. The hermes_local adapter runs the wrapper with the agent's own env, and a Studio v3
// agent stores HOME = its own directory there, so os.homedir() (which reads HOME) pointed the wrapper at a directory that holds
// no Paperclip install and no allowed root: every run failed with "cannot import ..." or "not inside an allowed root".
//
// The test is hermetic: a preload patches os.userInfo() so the "real" home is a scratch directory with a stub adapter-utils
// module (no bubblewrap, no Paperclip install), while $HOME points somewhere else. The stub records the options the wrapper hands
// to buildLocalProcessSandboxSpawnTarget and returns a target that just runs /bin/echo.
//   HARDENING_TEST_SCRATCH  scratch parent dir (default: the OS temp dir)
//   HERMES_SANDBOX_FILE     the wrapper to test (default: host/sandbox/hermes-sandbox; point it at an older copy for the fail-before run)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const WRAPPER = process.env.HERMES_SANDBOX_FILE || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "host", "sandbox", "hermes-sandbox");
const scratch = fs.realpathSync(fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "hermes-sandbox-home-")));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

const realHome = path.join(scratch, "real-home");        // the passwd home
const envHome = path.join(scratch, "agent-dir");         // what $HOME says (the agent's own directory)
const utilsDir = path.join(realHome, ".paperclip/cli/current/node_modules/@paperclipai/adapter-utils/dist");
const goodProject = path.join(realHome, "projects", "p1");
const badProject = path.join(envHome, "projects", "p1");  // a root under $HOME only
const record = path.join(scratch, "stub-options.json");
for (const d of [utilsDir, goodProject, badProject]) fs.mkdirSync(d, { recursive: true });
fs.writeFileSync(path.join(realHome, ".paperclip/cli/current/node_modules/@paperclipai/adapter-utils/package.json"), '{"type":"commonjs"}');
fs.writeFileSync(path.join(utilsDir, "local-process-sandbox.js"), `
const fs = require("node:fs");
exports.parseLocalProcessNetworkAllowlist = (list) => list;
exports.buildLocalProcessSandboxSpawnTarget = async (input) => {
  fs.writeFileSync(process.env.STUB_RECORD, JSON.stringify({ cwd: input.cwd, options: input.options, executable: input.executable }));
  return { command: "/bin/echo", args: ["wrapper-ran"], cwd: input.cwd, env: {}, cleanup: async () => {} };
};
`);
const preload = path.join(scratch, "preload.cjs");
fs.writeFileSync(preload, `require("node:os").userInfo = () => ({ homedir: ${JSON.stringify(realHome)}, username: "stub", uid: 0, gid: 0, shell: null });\n`);

function run(cwd, extraEnv = {}) {
  fs.rmSync(record, { force: true });
  const env = { PATH: "/usr/bin:/bin", HOME: envHome, STUB_RECORD: record, HERMES_SANDBOX_BIN: "/bin/echo", ...extraEnv };
  const r = spawnSync(process.execPath, ["--require", preload, WRAPPER, "chat", "-q", "hi"], { cwd, env, encoding: "utf8", timeout: 30000 });
  return { ...r, stub: fs.existsSync(record) ? JSON.parse(fs.readFileSync(record, "utf8")) : null };
}

test("HOME pointing elsewhere: the wrapper still finds adapter-utils under the passwd home and runs a cwd under the real roots", () => {
  const r = run(goodProject);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), "wrapper-ran");
  assert.equal(r.stub.cwd, goodProject);
  assert.equal(r.stub.options.workspaceDir, goodProject);
});

test("the default read-only paths come from the passwd home, not from $HOME", () => {
  const r = run(goodProject);
  assert.equal(r.status, 0, r.stderr);
  const ro = r.stub.options.extraPaths.map((p) => p.path);
  assert.deepEqual(ro, [`${realHome}/.hermes/hermes-agent`, `${realHome}/.hermes/tools`]);
  assert.ok(r.stub.options.extraPaths.every((p) => p.access === "ro"));
});

test("a cwd that is a root only under $HOME is refused (the roots belong to the passwd home)", () => {
  const r = run(badProject);
  assert.equal(r.status, 127);
  assert.match(r.stderr, /is not inside an allowed root/);
  assert.equal(r.stub, null, "nothing was built");
});

test("an explicit HERMES_SANDBOX_RO still replaces the defaults", () => {
  const r = run(goodProject, { HERMES_SANDBOX_RO: "/opt/hermes,/opt/tools" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.stub.options.extraPaths.map((p) => p.path), ["/opt/hermes", "/opt/tools"]);
});
