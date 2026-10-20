// Patch 0025 (adapter-utils server-utils.js, runChildProcess): a confined child gets an explicit allowlist of environment
// variables, never the server's. The tests build a scratch copy of the adapter-utils dist from the ORIGINAL bytes of a stock
// install (helpers/pristine.mjs: .orig backup, the unpatched file, or the engine store's copy once the engine patched it),
// apply the patch with `patch -F0` and run the real runChildProcess with a
// canary server environment. A stock copy proves the fail-before: there the canary reaches the child.
// The confinement command is a stand-in that skips to `--` and execs the rest, so the tests need no bubblewrap; one more
// test runs the real bwrap when it is usable.
//   PAPERCLIP_STOCK_TREE_1012 (and _1005)  install to copy from (default: ~/.paperclip/cli/installs/npm/2026.<vkey>.0)
//   HARDENING_TEST_SCRATCH   scratch parent dir (default: the OS temp dir)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { noPristineSkip, pristineOrNull, stockTreeOrNull, stockTreePath } from "./helpers/pristine.mjs";

const PATCH = path.join(SOURCE_PATCHES_DIR, "0025-sandbox-env-scrub.patch");
const UTILS = "node_modules/@paperclipai/adapter-utils";
const TARGET = `${UTILS}/dist/server-utils.js`;
const SCRUB_FLAG = Symbol.for("paperclip.hardening.envScrub");

const live = stockTreeOrNull("1012"); // the stock install to copy the adapter-utils dist from (read only)
const distFiles = (root) => fs.readdirSync(path.join(root, UTILS, "dist")).filter((name) => name.endsWith(".js") && !name.endsWith(".test.js")).map((name) => `${UTILS}/dist/${name}`);
const skip = !live ? "NO STOCK TREE: no Paperclip 2026.1012.0 install found; set PAPERCLIP_STOCK_TREE_1012 to an untouched install"
  : noPristineSkip(live, distFiles(live), "1012");
const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0025-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

let seq = 0;
/** A scratch tree whose adapter-utils dist is stock; `patched` applies 0025 on top. */
function buildTree(sourceTree, patched) {
  const root = path.join(scratch, `tree-${++seq}`);
  const dist = path.join(root, UTILS, "dist");
  fs.mkdirSync(dist, { recursive: true });
  fs.copyFileSync(path.join(sourceTree, UTILS, "package.json"), path.join(root, UTILS, "package.json"));
  for (const name of fs.readdirSync(path.join(sourceTree, UTILS, "dist"))) {
    if (!name.endsWith(".js") || name.endsWith(".test.js")) continue;
    fs.writeFileSync(path.join(dist, name), pristineOrNull(sourceTree, `${UTILS}/dist/${name}`));
  }
  fs.mkdirSync(path.join(root, "node_modules/@paperclipai"), { recursive: true });
  fs.symlinkSync(fs.realpathSync(path.join(sourceTree, "node_modules/@paperclipai/shared")), path.join(root, "node_modules/@paperclipai/shared"));
  if (patched) {
    const r = spawnSync("patch", ["-p1", "-F0", "-d", root, "-i", PATCH], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
  }
  return root;
}
const load = (root) => import(`${pathToFileURL(path.join(root, TARGET)).href}?v=${++seq}`);

// A stand-in for bwrap: skip the sandbox arguments up to `--`, then exec the command.
const fakeBwrap = path.join(scratch, "fake-bwrap");
fs.writeFileSync(fakeBwrap, '#!/bin/sh\nwhile [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n', { mode: 0o755 });

const CANARY = "canary-value-0025";
const SERVER_ENV = {
  HARDENING_CANARY_SECRET: CANARY,
  DATABASE_URL: `postgres://paperclip:${CANARY}@127.0.0.1:1/db`,
  NODE_OPTIONS: "--max-old-space-size=64",
  LD_PRELOAD: "/nonexistent.so",
  BASH_ENV: "/nonexistent",
  PAPERCLIP_SECRETS_MASTER_KEY: CANARY,
  PAPERCLIP_RUNTIME_API_URL: "http://server-inherited.invalid",
  LANG: "C.UTF-8", LC_ALL: "C.UTF-8", TZ: "UTC", HTTPS_PROXY: "http://proxy.invalid:3128",
};

/** Runs `env` through runChildProcess with the server canary environment and returns the child's variables. */
async function childEnv(mod, { adapterEnv = {}, sandbox, remoteExecution, command = "env", args = [] } = {}) {
  const saved = {};
  for (const [k, v] of Object.entries(SERVER_ENV)) { saved[k] = process.env[k]; process.env[k] = v; }
  try {
    const cwd = fs.mkdtempSync(path.join(scratch, "cwd-"));
    // Adapters pass { ...process.env, ...env }.
    const env = Object.fromEntries(Object.entries({ ...process.env, ...adapterEnv }).filter(([, v]) => typeof v === "string"));
    const proc = await mod.runChildProcess(`run-${++seq}`, command, args, {
      cwd, env, timeoutSec: 20, graceSec: 2, onLog: async () => {},
      localProcessSandbox: sandbox === undefined ? undefined : { workspaceDir: cwd, networkScope: "deny", command: fakeBwrap, ...sandbox },
      remoteExecution,
    });
    assert.equal(proc.exitCode, 0, proc.stderr);
    return Object.fromEntries(proc.stdout.split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

const BASE_ONLY_ALLOWED = new Set(["PATH", "HOME", "LANG", "LANGUAGE", "TZ", "TERM", "PWD", "SHLVL", "_", "OLDPWD", "NO_PROXY", "no_proxy"]);
const isBase = (k) => BASE_ONLY_ALLOWED.has(k) || k.startsWith("LC_");

test("stock server-utils lets the server canary reach a confined child (fail-before)", { skip }, async () => {
  const mod = await load(buildTree(live, false));
  assert.equal(mod[SCRUB_FLAG], undefined);
  assert.equal(globalThis[SCRUB_FLAG], undefined);
  const env = await childEnv(mod, { sandbox: { envPassNames: ["AGENT_KEY"] }, adapterEnv: { AGENT_KEY: "k" } });
  assert.equal(env.HARDENING_CANARY_SECRET, CANARY);
  assert.ok(env.DATABASE_URL.includes(CANARY));
  assert.equal(env.NODE_OPTIONS, SERVER_ENV.NODE_OPTIONS);
});

test("patched: a confined child gets BASE + envPassNames only", { skip }, async () => {
  const mod = await load(buildTree(live, true));
  assert.equal(globalThis[SCRUB_FLAG], true, "the patch announces itself for the spawn-time check");
  const env = await childEnv(mod, {
    sandbox: { envPassNames: ["AGENT_CREDENTIAL", "ONLY_NAMED_NOT_SET", "NODE_OPTIONS", "LD_PRELOAD", "PYTHONSTARTUP", "BASH_ENV", "PAPERCLIP_RUN_ID", "PAPERCLIP_API_URL"], homeDir: "/box/home" },
    adapterEnv: { AGENT_CREDENTIAL: "sk-dummy-0000", UNLISTED_ADAPTER_VAR: "x", NODE_OPTIONS: "--require /x.js", PYTHONSTARTUP: "/x.py", PAPERCLIP_RUN_ID: "run-1", PAPERCLIP_API_URL: "http://127.0.0.1:3100", PAPERCLIP_SET_BY_ADAPTER_BUT_UNLISTED: "x" },
  });
  const serialized = JSON.stringify(env);
  assert.ok(!serialized.includes(CANARY), "no canary value anywhere in the child env");
  for (const k of ["HARDENING_CANARY_SECRET", "DATABASE_URL", "PAPERCLIP_SECRETS_MASTER_KEY", "PAPERCLIP_RUNTIME_API_URL", "NODE_OPTIONS", "LD_PRELOAD", "BASH_ENV", "PYTHONSTARTUP", "UNLISTED_ADAPTER_VAR", "PAPERCLIP_SET_BY_ADAPTER_BUT_UNLISTED"]) assert.equal(env[k], undefined, k);
  assert.equal(env.AGENT_CREDENTIAL, "sk-dummy-0000");
  assert.equal(env.PAPERCLIP_RUN_ID, "run-1");
  assert.equal(env.PAPERCLIP_API_URL, "http://127.0.0.1:3100");
  assert.equal(env.HOME, "/box/home");
  assert.equal(env.LANG, "C.UTF-8");
  assert.equal(env.LC_ALL, "C.UTF-8");
  assert.equal(env.TZ, "UTC");
  assert.ok(env.PATH);
  const allowed = new Set(["AGENT_CREDENTIAL", "PAPERCLIP_RUN_ID", "PAPERCLIP_API_URL"]);
  assert.deepEqual(Object.keys(env).filter((k) => !isBase(k) && !allowed.has(k)), [], "nothing outside the allowlist");
});

test("patched: envPassNames takes the value from the adapter env, never from the server env", { skip }, async () => {
  const mod = await load(buildTree(live, true));
  const env = await childEnv(mod, { sandbox: { envPassNames: ["HARDENING_CANARY_SECRET", "AGENT_KEY"] }, adapterEnv: { AGENT_KEY: "from-adapter" } });
  // HARDENING_CANARY_SECRET is in the adapter object too (adapters spread process.env), so it is the adapter's choice to list it.
  assert.equal(env.AGENT_KEY, "from-adapter");
  const unlisted = await childEnv(mod, { sandbox: { envPassNames: ["AGENT_KEY"] }, adapterEnv: { AGENT_KEY: "from-adapter" } });
  assert.equal(unlisted.HARDENING_CANARY_SECRET, undefined);
});

test("patched: missing or malformed envPassNames passes BASE only (fail closed)", { skip }, async () => {
  const mod = await load(buildTree(live, true));
  for (const sandbox of [{}, { envPassNames: undefined }, { envPassNames: null }, { envPassNames: "AGENT_KEY" }, { envPassNames: [] }, { envPassNames: [7, null, {}] }]) {
    const env = await childEnv(mod, { sandbox, adapterEnv: { AGENT_KEY: "sk-dummy-0000", PAPERCLIP_RUN_ID: "run-1" } });
    assert.deepEqual(Object.keys(env).filter((k) => !isBase(k)), [], JSON.stringify(sandbox)); // PAPERCLIP_ names included
    assert.equal(env.AGENT_KEY, undefined);
    assert.equal(env.HARDENING_CANARY_SECRET, undefined);
    assert.equal(env.PAPERCLIP_SECRETS_MASTER_KEY, undefined);
  }
});

test("patched: a PAPERCLIP_ name passes only when listed and different from the server's own value; secrets never; a listed HOME keeps the box home", { skip }, async () => {
  const mod = await load(buildTree(live, true));
  const SERVER_PAPERCLIP = { PAPERCLIP_API_URL: "http://127.0.0.1:3100", PAPERCLIP_RUN_ID: "server-run-value" };
  const saved = Object.fromEntries(Object.keys(SERVER_PAPERCLIP).map((k) => [k, process.env[k]]));
  Object.assign(process.env, SERVER_PAPERCLIP);
  try {
    const listed = ["PAPERCLIP_RUNTIME_API_URL", "PAPERCLIP_SECRETS_MASTER_KEY", "PAPERCLIP_AGENT_JWT_SECRET", "PAPERCLIP_SIGNING_PRIVATE_KEY", "PAPERCLIP_X_MASTER_KEY",
      "PAPERCLIP_RUN_ID", "PAPERCLIP_API_URL", "PAPERCLIP_API_KEY", "PAPERCLIP_TASK_ID", "GLIBC_TUNABLES", "HOME"];
    const env = await childEnv(mod, {
      sandbox: { envPassNames: listed, homeDir: "/box/home" },
      adapterEnv: {
        // listed, but equal to the server's own value (inherited into opts.env): stays out
        PAPERCLIP_RUNTIME_API_URL: SERVER_ENV.PAPERCLIP_RUNTIME_API_URL, PAPERCLIP_RUN_ID: "server-run-value",
        // listed and secret-looking: stay out even with a value of the adapter's own
        PAPERCLIP_AGENT_JWT_SECRET: "x", PAPERCLIP_SIGNING_PRIVATE_KEY: "x", PAPERCLIP_X_MASTER_KEY: "x",
        // listed and the adapter's own: pass (PAPERCLIP_API_URL may equal the server's value, it is only a URL)
        PAPERCLIP_API_KEY: "run-jwt", PAPERCLIP_TASK_ID: "task-1", PAPERCLIP_API_URL: "http://127.0.0.1:3100",
        GLIBC_TUNABLES: "glibc.malloc.check=3",
        HOME: "/evil/home",
      },
    });
    for (const k of ["PAPERCLIP_RUNTIME_API_URL", "PAPERCLIP_SECRETS_MASTER_KEY", "PAPERCLIP_AGENT_JWT_SECRET", "PAPERCLIP_SIGNING_PRIVATE_KEY", "PAPERCLIP_X_MASTER_KEY", "PAPERCLIP_RUN_ID", "GLIBC_TUNABLES"])
      assert.equal(env[k], undefined, k);
    assert.equal(env.PAPERCLIP_API_KEY, "run-jwt");
    assert.equal(env.PAPERCLIP_TASK_ID, "task-1");
    assert.equal(env.PAPERCLIP_API_URL, "http://127.0.0.1:3100");
    assert.equal(env.HOME, "/box/home", "a listed HOME does not take the adapter's value");
    // a run variable that differs from the server's value passes when listed
    const own = await childEnv(mod, { sandbox: { envPassNames: ["PAPERCLIP_RUN_ID"] }, adapterEnv: { PAPERCLIP_RUN_ID: "run-7" } });
    assert.equal(own.PAPERCLIP_RUN_ID, "run-7");
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
});

test("patched: HOME is always the box home, never the adapter's; without a box home it is the server's own HOME; PATH, locale and TZ do take the adapter's value", { skip }, async () => {
  const mod = await load(buildTree(live, true));
  const adapterEnv = { HOME: "/evil/home", PATH: "/usr/bin:/bin", LANG: "en_US.UTF-8", TZ: "Europe/Budapest" };
  const withBox = await childEnv(mod, { sandbox: { envPassNames: ["HOME"], homeDir: "/box/home" }, adapterEnv });
  assert.equal(withBox.HOME, "/box/home");
  // a network-only box has no box home: the adapter (or a stored config.env) must not choose the HOME of the confined child
  for (const envPassNames of [[], ["HOME"]]) {
    const noBox = await childEnv(mod, { sandbox: { envPassNames }, adapterEnv });
    assert.equal(noBox.HOME, process.env.HOME, `no box home, envPassNames ${JSON.stringify(envPassNames)}: the server's own HOME`);
    assert.notEqual(noBox.HOME, "/evil/home");
  }
  // not the other BASE names: these take the adapter's value (it builds them, they are no state redirect)
  assert.equal(withBox.PATH, "/usr/bin:/bin");
  assert.equal(withBox.LANG, "en_US.UTF-8");
  assert.equal(withBox.TZ, "Europe/Budapest");
});

test("patched: the scrub announcement cannot be switched off or replaced from inside the process", { skip }, async () => {
  await load(buildTree(live, true));
  const d = Object.getOwnPropertyDescriptor(globalThis, SCRUB_FLAG);
  assert.deepEqual({ value: d.value, writable: d.writable, configurable: d.configurable }, { value: true, writable: false, configurable: false });
  assert.throws(() => { globalThis[SCRUB_FLAG] = false; }, TypeError);
  assert.throws(() => Object.defineProperty(globalThis, SCRUB_FLAG, { value: false }), TypeError);
  assert.equal(globalThis[SCRUB_FLAG], true);
});

test("patched: unboxed calls are unchanged", { skip }, async () => {
  const stock = await childEnv(await load(buildTree(live, false)), { adapterEnv: { AGENT_KEY: "k" } });
  const patched = await childEnv(await load(buildTree(live, true)), { adapterEnv: { AGENT_KEY: "k" } });
  assert.equal(patched.HARDENING_CANARY_SECRET, CANARY);
  assert.equal(patched.NODE_OPTIONS, SERVER_ENV.NODE_OPTIONS);
  assert.equal(patched.AGENT_KEY, "k");
  const strip = (e) => Object.fromEntries(Object.entries(e).filter(([k]) => !["PWD", "SHLVL", "_", "OLDPWD"].includes(k)));
  assert.deepEqual(strip(patched), strip(stock));
});

test("patched: a remote execution is not scrubbed (the sandbox does not apply to it)", { skip }, async () => {
  // resolveSpawnTarget would run ssh, so check the guard in the source.
  const src = fs.readFileSync(path.join(buildTree(live, true), TARGET), "utf8");
  assert.match(src, /if \(opts\.localProcessSandbox && !opts\.remoteExecution\) \{\s*\/\/ LOCAL-PATCH 0025/);
});

test("patched: real bwrap child gets the scrubbed env too", { skip: skip || (spawnSync("bwrap", ["--ro-bind", "/", "/", "true"]).status === 0 ? false : "bwrap is not usable here") }, async () => {
  const mod = await load(buildTree(live, true));
  const env = await childEnv(mod, {
    sandbox: { command: "bwrap", networkScope: "deny", envPassNames: ["AGENT_CREDENTIAL"] },
    adapterEnv: { AGENT_CREDENTIAL: "sk-dummy-0000" }, command: "/usr/bin/env",
  });
  assert.equal(env.AGENT_CREDENTIAL, "sk-dummy-0000");
  assert.ok(!JSON.stringify(env).includes(CANARY));
  assert.equal(env.NODE_OPTIONS, undefined);
});

test("0025 applies to every stock tree that is installed (dry run, -F0)", { skip }, () => {
  const roots = ["1005", "1012"].map((vkey) => stockTreePath(vkey)).filter((r, i, all) => pristineOrNull(r, TARGET) && all.indexOf(r) === i);
  assert.ok(roots.length > 0);
  for (const r of roots) {
    const dir = path.join(scratch, `dry-${++seq}`, path.dirname(TARGET));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "server-utils.js"), pristineOrNull(r, TARGET));
    const out = spawnSync("patch", ["-p1", "-F0", "--dry-run", "-d", path.resolve(dir, "../../../.."), "-i", PATCH], { encoding: "utf8" });
    assert.equal(out.status, 0, `${r}: ${out.stdout}${out.stderr}`);
  }
});

test("the patch touches one file and carries the marker", () => {
  const text = fs.readFileSync(PATCH, "utf8");
  assert.deepEqual([...text.matchAll(/^\+\+\+ b\/(.+)$/gm)].map((m) => m[1]), [TARGET]);
  assert.ok((text.match(/^\+.*LOCAL-PATCH 0025/gm) ?? []).length >= 2);
});

test("BASE_ENV_ALLOW equals the list of patch 0017 (drift)", () => {
  const file = fs.readdirSync(SOURCE_PATCHES_DIR).find((n) => /^0017-.*\.patch$/.test(n));
  if (!file) return;
  const PROXY = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"];
  const grab = (text) => {
    const m = text.match(/^\+.*BASE_ENV_ALLOW\s*=\s*(?:Object\.freeze\()?\[([^\]]*)\]/m);
    if (!m) return null;
    const body = m[1].replace(/^\+/gm, "").replace("...PROXY_ENV_KEYS", PROXY.map((x) => `"${x}"`).join(","));
    return [...body.matchAll(/"([^"]+)"/g)].map((x) => x[1]).sort();
  };
  const mine = grab(fs.readFileSync(PATCH, "utf8"));
  const theirs = grab(fs.readFileSync(path.join(SOURCE_PATCHES_DIR, file), "utf8"));
  assert.ok(mine && mine.length > 10);
  assert.ok(theirs, "0017 must define BASE_ENV_ALLOW");
  assert.deepEqual(mine, theirs, "0025 inlines a copy of the 0017 list; keep them equal");
});
