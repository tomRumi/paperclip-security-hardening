// The exact shape of a company running hermes agents, end to end through the patches that decide about them:
//   hermes_local, adapterConfig.command = /usr/local/bin/hermes-sandbox, NO hermesCommand,
//   env { HOME: <the agent's directory>, HERMES_SANDBOX_HOME, HERMES_SANDBOX_RO, HERMES_SANDBOX_ALLOW }
//   0005a  a board user creating it stores it as given (an agent creating it would lose HOME and HERMES_SANDBOX_*)
//   0005f  admits it (command is the wrapper; an unset hermesCommand is fine; no registration or env scrub needed)
//   0003b  keeps the stored env at the spawn-time enforcement (run values equal to the stored ones pass untouched; a run-level
//          override of HOME / HERMES_SANDBOX_* is put back to the stored value)
//   0025   does not touch the spawn: the hermes adapter calls runChildProcess without localProcessSandbox, so the child gets the
//          same environment with and without the patch (the wrapper builds its own clean env from it)
// heartbeat.js is built from the ORIGINAL bytes of each installed Paperclip version plus the package's heartbeat patches; the
// adapter-utils tree for 0025 is built from the stock install and patched with `patch -F0`, as patch-0025.test.mjs does.
//   PAPERCLIP_STOCK_TREE_1005 / _1012, HARDENING_TEST_SCRATCH  as in the other patch tests
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { admissionCode, extractBlock, evalBlock, blockFromPatchFile } from "./helpers/patch-block.mjs";
import { noPristineSkip, pristineOrNull, stockTreeOrNull, stockTreePath } from "./helpers/pristine.mjs";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { PATCHES, comparePatchIds } from "../src/engine/registry.js";
import { discoverPatchFiles, orderCandidates, readPatchTarget, buildFile } from "../src/engine/patches.js";

const HB = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
const WRAPPER = "/usr/local/bin/hermes-sandbox";
const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "live-hermes-shape-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
let n = 0;
const freshRoot = () => { const d = path.join(scratch, `root-${++n}`); fs.mkdirSync(d, { mode: 0o700, recursive: true }); return d; };

const plain = (value) => ({ type: "plain", value });
const AGENT_DIR = "/home/user/.paperclip/instances/default/companies/c1/agents/a1";
const LIVE_SHAPE = () => ({
  command: WRAPPER,
  env: {
    HOME: plain(AGENT_DIR),
    HERMES_SANDBOX_HOME: plain(`${AGENT_DIR}/hermes-home`),
    HERMES_SANDBOX_RO: plain("/home/user/.hermes/hermes-agent,/home/user/.hermes/tools,/home/user/tools-extra"),
    HERMES_SANDBOX_ALLOW: plain("openrouter.ai,api.example.org"),
  },
});
/** The env a run sees: the stored plain values resolved to strings (what the adapter's config.env holds at spawn time). */
const resolved = (env) => Object.fromEntries(Object.entries(env).map(([k, v]) => [k, v.value]));

// ---------- 0005a, 0005f, 0003b on heartbeat.js / services/agents.js of each installed version
const stockRoot = (version) => stockTreePath(version.split(".")[1]);
const VERSIONS = ["2026.1005.0", "2026.1012.0"].filter((v) => pristineOrNull(stockRoot(v), HB));
const skip = VERSIONS.length ? false : noPristineSkip(stockRoot("2026.1012.0"), [HB], "1012");
function buildHeartbeat(version) {
  const found = discoverPatchFiles(SOURCE_PATCHES_DIR);
  const steps = [...found.keys()].filter((id) => PATCHES[id] && readPatchTarget(found.get(id)[0].file) === HB)
    .filter((id) => !(PATCHES[id].notNeededOn ?? []).includes(version.split(".")[1])).sort(comparePatchIds)
    .map((id) => ({ id, marker: PATCHES[id].marker, candidates: orderCandidates(found.get(id), version.split(".")[1]) }));
  const r = buildFile({ rel: HB, pristine: pristineOrNull(stockRoot(version), HB), steps, tmpDir: scratch });
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(["0003", "0003b", "0005b", "0005f"].filter((id) => !r.used.some((u) => u.id === id)), [], "the whole hermes chain is in the build");
  return r.content.toString("utf8");
}

for (const version of VERSIONS) {
  const heartbeat = buildHeartbeat(version);
  const variant = version === "2026.1005.0" ? "0005a-new-agent-safe-defaults.patch" : "0005a-new-agent-safe-defaults.1012.patch";

  test(`${version}: a board user creating the live-shape agent stores it as given (no hermesCommand added); an agent creating it does not keep HOME or HERMES_SANDBOX_*`, { skip }, () => {
    const a = evalBlock(blockFromPatchFile(path.join(SOURCE_PATCHES_DIR, variant), "0005a"), "0005a", { instanceRoot: freshRoot() });
    const byBoard = a.applyNewAgentSafeDefaults("hermes_local", LIVE_SHAPE(), {}, "create", { board: true }).adapterConfig;
    assert.deepEqual(byBoard, LIVE_SHAPE());
    assert.equal("hermesCommand" in byBoard, false);
    const byAgent = a.applyNewAgentSafeDefaults("hermes_local", LIVE_SHAPE(), {}, "create", undefined).adapterConfig;
    assert.deepEqual(Object.keys(byAgent.env), ["HERMES_SANDBOX_ALLOW"]);
    assert.equal(byAgent.env.HERMES_SANDBOX_ALLOW.value, "openrouter.ai", "the default allowlist, not the creator's");
  });

  test(`${version}: 0005f admits the live-shape agent (unset hermesCommand, no registration, no scrub flag needed)`, { skip }, () => {
    const b = evalBlock(admissionCode(heartbeat), "0005f", { instanceRoot: freshRoot() });
    const agent = { id: "agent-h", adapterType: "hermes_local", adapterConfig: LIVE_SHAPE() };
    const BOXED = Symbol.for("paperclip.hardening.boxedAdapters"), SCRUB = Symbol.for("paperclip.hardening.envScrub");
    assert.equal(globalThis[BOXED], undefined, "the test runs with nothing registered");
    assert.equal(globalThis[SCRUB], undefined);
    for (const adapterConfig of [LIVE_SHAPE(), { ...LIVE_SHAPE(), hermesCommand: undefined }, { ...LIVE_SHAPE(), hermesCommand: null }, { ...LIVE_SHAPE(), hermesCommand: "" }, { ...LIVE_SHAPE(), hermesCommand: WRAPPER }]) {
      b.warnings.length = 0;
      assert.doesNotThrow(() => b.refuseUnsandboxedLocalAgent({ agent: { ...agent, adapterConfig }, runId: "r1" }), JSON.stringify(adapterConfig.hermesCommand));
      assert.deepEqual(b.warnings, []);
    }
    // ... and still refuses the shape with a different command or hermesCommand (the adapter runs hermesCommand first)
    assert.throws(() => b.refuseUnsandboxedLocalAgent({ agent: { ...agent, adapterConfig: { ...LIVE_SHAPE(), hermesCommand: "/bin/sh" } }, runId: "r1" }), /hermesCommand is not/);
    assert.throws(() => b.refuseUnsandboxedLocalAgent({ agent: { ...agent, adapterConfig: { ...LIVE_SHAPE(), command: "hermes" } }, runId: "r1" }), /command is not/);
  });

  test(`${version}: 0003b keeps the stored env of the live-shape agent at spawn time; run-level overrides go back to the stored values`, { skip }, async () => {
    const b = evalBlock(extractBlock(heartbeat, "0003"), "0003", { instanceRoot: freshRoot() });
    const agent = { id: "agent-h", adapterType: "hermes_local", adapterConfig: LIVE_SHAPE() };
    const enforce = (runtimeConfig) => b.enforceStoredSandboxConfig({ agent, runId: "run-1", runtimeConfig, workspaceDirs: [], managedAi: false });
    // the run config of an untouched agent: command and the resolved stored env, no hermesCommand
    const run = { command: WRAPPER, env: { ...resolved(LIVE_SHAPE().env), OPENROUTER_API_KEY: "sk-dummy-0000" }, model: "m" };
    b.warnings.length = 0;
    assert.deepEqual(await enforce(structuredClone(run)), run, "nothing is dropped or changed");
    assert.deepEqual(b.warnings, [], "and nothing is logged");
    // an override of every protected name is put back to the stored value (the stored HOME included)
    const override = { command: "/bin/sh", env: { ...run.env, HOME: "/evil/home", HERMES_HOME: "/evil/h", HERMES_SANDBOX_HOME: "/", HERMES_SANDBOX_RO: "/", HERMES_SANDBOX_ALLOW: "evil.example", HERMES_SANDBOX_PASS: "DATABASE_URL", HERMES_SANDBOX_BIN: "/bin/sh" } };
    const out = await enforce(override);
    assert.equal(out.command, WRAPPER);
    assert.deepEqual(out.env, run.env, "the stored values are back; the names the board never stored (HERMES_HOME, _PASS, _BIN) are gone");
  });
}

// ---------- 0025 leaves the hermes spawn alone
const UTILS = "node_modules/@paperclipai/adapter-utils";
const TARGET = `${UTILS}/dist/server-utils.js`;
const live = stockTreeOrNull("1012");
const distFiles = (root) => fs.readdirSync(path.join(root, UTILS, "dist")).filter((name) => name.endsWith(".js") && !name.endsWith(".test.js")).map((name) => `${UTILS}/dist/${name}`);
const skip25 = !live ? "NO STOCK TREE: no Paperclip 2026.1012.0 install found; set PAPERCLIP_STOCK_TREE_1012 to an untouched install" : noPristineSkip(live, distFiles(live), "1012");
function buildUtils(patched) {
  const root = path.join(scratch, `utils-${++n}`);
  const dist = path.join(root, UTILS, "dist");
  fs.mkdirSync(dist, { recursive: true });
  fs.copyFileSync(path.join(live, UTILS, "package.json"), path.join(root, UTILS, "package.json"));
  for (const name of fs.readdirSync(path.join(live, UTILS, "dist"))) {
    if (!name.endsWith(".js") || name.endsWith(".test.js")) continue;
    fs.writeFileSync(path.join(dist, name), pristineOrNull(live, `${UTILS}/dist/${name}`));
  }
  fs.mkdirSync(path.join(root, "node_modules/@paperclipai"), { recursive: true });
  fs.symlinkSync(fs.realpathSync(path.join(live, "node_modules/@paperclipai/shared")), path.join(root, "node_modules/@paperclipai/shared"));
  if (patched) {
    const r = spawnSync("patch", ["-p1", "-F0", "-d", root, "-i", path.join(SOURCE_PATCHES_DIR, "0025-sandbox-env-scrub.patch")], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
  }
  return import(`${pathToFileURL(path.join(root, TARGET)).href}?v=${++n}`);
}

test("0025 does not touch a hermes spawn: runChildProcess as the hermes adapter calls it (no localProcessSandbox) gives the same child env with and without the patch", { skip: skip25 }, async () => {
  const CANARY = "canary-value-live-shape";
  const server = { HARDENING_CANARY_SECRET: CANARY, DATABASE_URL: `postgres://p:${CANARY}@127.0.0.1:1/db`, PAPERCLIP_RUNTIME_API_URL: "http://server-inherited.invalid" };
  const cwd = fs.mkdtempSync(path.join(scratch, "cwd-"));
  const saved = Object.fromEntries(Object.keys(server).map((k) => [k, process.env[k]]));
  Object.assign(process.env, server);
  try {
    const envOf = async (mod) => {
      // what the adapter passes: { ...process.env, ...config.env (resolved), ...PAPERCLIP_ run variables }
      const env = Object.fromEntries(Object.entries({ ...process.env, ...resolved(LIVE_SHAPE().env), PAPERCLIP_RUN_ID: "run-1" }).filter(([, v]) => typeof v === "string"));
      const proc = await mod.runChildProcess("run-live", "env", [], { cwd, env, timeoutSec: 20, graceSec: 2, onLog: async () => {} });
      assert.equal(proc.exitCode, 0, proc.stderr);
      return Object.fromEntries(proc.stdout.split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
    };
    const stock = await envOf(await buildUtils(false));
    const patched = await envOf(await buildUtils(true));
    assert.deepEqual(patched, stock, "identical child environment");
    assert.equal(patched.HOME, AGENT_DIR, "the agent's own HOME reaches the wrapper");
    for (const [k, v] of Object.entries(resolved(LIVE_SHAPE().env))) assert.equal(patched[k], v, k);
    assert.equal(patched.HARDENING_CANARY_SECRET, CANARY, "the wrapper (not 0025) is what keeps the server env out of Hermes");
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
});
