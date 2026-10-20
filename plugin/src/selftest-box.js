// Self-test probes for the box around Claude and OpenCode agents (protections "box-claude", "box-opencode" and "only-boxed"). Credential-free:
// no adapter run, no CLI, no model call, no network beyond a loopback listener of the test itself. Each check builds the box with
// the patched code of the running install and, where it matters, runs a few shell commands in the real bubblewrap box:
//   box-claude    the spawn target of a claude_local run is a bubblewrap command (private tmpfs root, own home, no real home), the
//                 adapter registers itself and calls the shared helper;
//                 a process in the box cannot write or read outside its workspace and runtime folder;
//                 a host that is not on the allowlist gets a 403 from the proxy and ONE sandbox_network_denied log line, an
//                 allowed one gets through and logs nothing;
//                 the server's own environment (a canary, NODE_OPTIONS, LD_PRELOAD, whatever the worker holds) does not reach the
//                 child, the agent's own variables do
//   box-opencode  the same spawn-target check for an opencode_local run (the helper and the scrub are checked under box-claude)
//   only-boxed    the admission rule evaluated from the built heartbeat.js: an unboxed agent, a boxed one whose adapter is not
//                 registered, one without the environment scrub, one on the ACP engine and an unknown adapter type are refused with
//                 the missing piece named; a boxed Claude and a boxed OpenCode agent are admitted
// Bubblewrap itself unusable on this host (no user namespaces): the box checks that need it say so and pass ("not run"); the
// build-only checks and the admission check still run.
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { admissionCode, evalBlock } from "./patch-block.js";
import {
  SANDBOX_FILE, SERVER_UTILS_FILE, HEARTBEAT_FILE, CLAUDE_EXECUTE_FILE, OPENCODE_EXECUTE_FILE, importBuilt,
} from "./selftest-util.js";

const BOXED_ADAPTERS_KEY = Symbol.for("paperclip.hardening.boxedAdapters");
const ENV_SCRUB_KEY = Symbol.for("paperclip.hardening.envScrub");
const BWRAP = "/usr/bin/bwrap";
const CLAUDE_BOX_TYPE = { type: "claude_local", key: "claude", executeFile: CLAUDE_EXECUTE_FILE };
const OPENCODE_BOX_TYPE = { type: "opencode_local", key: "opencode", executeFile: OPENCODE_EXECUTE_FILE };
const CREDENTIAL = "SELFTEST_AGENT_CREDENTIAL";
const SERVER_NAMES = ["HARDENING_SELFTEST_CANARY", "DATABASE_URL", "NODE_OPTIONS", "LD_PRELOAD", "BASH_ENV", "PAPERCLIP_SECRETS_MASTER_KEY"];
const sq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
const hex = () => crypto.randomBytes(5).toString("hex");

/** Is bubblewrap usable here (unprivileged user namespaces)? null when it is, else the reason. */
function bwrapUnusable() {
  const r = spawnSync(BWRAP, ["--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--unshare-net", "/bin/sh", "-c", "exit 0"],
    { stdio: "ignore", timeout: 10_000 });
  return r.status === 0 ? null : `bubblewrap is not usable here (${BWRAP}: ${r.error?.code ?? `exit ${r.status}`})`;
}

/** A scratch world: workspace, an agent runtime folder, a folder next to them that must stay out of reach, and a canary file in it.
 *  `userHome` is the home directory of the account Paperclip runs as (from the target; null when unknown). */
function makeWorld(userHome) {
  const real = (p) => { try { return fs.realpathSync(p); } catch { return p; } };
  const tmp = real(os.tmpdir());
  const home = userHome ? real(userHome) : null;
  // The box helper never mounts anything inside the real home that is not a workspace: a TMPDIR inside it would be refused.
  const parent = home && (tmp === home || tmp.startsWith(`${home}${path.sep}`)) ? "/tmp" : tmp;
  const root = fs.mkdtempSync(path.join(parent, "hardening-selftest-box-"));
  const world = { root, workspace: path.join(root, "workspace"), outside: path.join(root, "outside"), runtime: path.join(root, "agents", "agent", "claude-runtime"), realHome: home };
  fs.mkdirSync(world.workspace, { mode: 0o700 });
  fs.mkdirSync(world.outside, { mode: 0o700 });
  fs.writeFileSync(path.join(world.outside, "canary"), "selftest-canary\n", { mode: 0o600 });
  world.cleanup = () => fs.rmSync(root, { recursive: true, force: true });
  return world;
}

function boxOptions(mod, world, { type = "claude_local", runtime = world.runtime, allowlist = ["selftest-allowed.invalid:443"], env = {}, runId = `selftest-${hex()}` } = {}) {
  if (typeof mod.boxedSandboxOptions !== "function") throw new Error("boxedSandboxOptions is missing from local-process-sandbox.js");
  const options = mod.boxedSandboxOptions({
    type, config: { filesystemScope: "workspace", networkScope: "allowlist", networkAllowlist: allowlist, filesystemSandboxCommand: BWRAP },
    env: { [CREDENTIAL]: "dummy-not-a-credential", PAPERCLIP_RUN_ID: runId, ...env },
    agentId: "selftest-agent", companyId: "selftest-company", runId, workspaceDir: world.workspace, runtimeDir: runtime,
  });
  if (!options) throw new Error("boxedSandboxOptions returned no box for an agent with a filesystem and network scope");
  return { options, runId };
}

/** Run `script` (sh) in the real box built from `options`; resolves {code, stdout, stderr}. The proxy runs in this process. */
async function runInBox(mod, options, script, { timeoutMs = 25_000 } = {}) {
  const target = await mod.buildLocalProcessSandboxSpawnTarget({ executable: "/bin/sh", args: ["-c", script], cwd: options.workspaceDir, options });
  try {
    const env = { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", HOME: options.homeDir };
    for (const [k, v] of Object.entries(target.env ?? {})) if (typeof v === "string") env[k] = v;
    return await new Promise((resolve, reject) => {
      const child = spawn(target.command, target.args, { cwd: target.cwd ?? "/", env, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "", stderr = "";
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`the probe in the box did not finish in ${timeoutMs} ms`)); }, timeoutMs);
      child.stdout.on("data", (c) => { stdout += c; });
      child.stderr.on("data", (c) => { stderr += c; });
      child.on("error", (e) => { clearTimeout(timer); reject(e); });
      child.on("close", (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
    });
  } finally {
    await target.cleanup?.();
  }
}

/** Collect the sandbox_network_denied lines of one run from this process's stderr (and keep them out of the real log). */
async function captureDenied(runId, fn) {
  const mine = [];
  const original = process.stderr.write;
  process.stderr.write = function write(chunk, ...rest) {
    const text = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    const keep = [];
    for (const line of text.split("\n")) {
      if (!line) continue;
      let entry = null;
      try { entry = JSON.parse(line); } catch { /* not ours */ }
      if (entry?.event === "sandbox_network_denied" && entry.runId === runId) mine.push(entry); else keep.push(line);
    }
    const cb = rest.find((x) => typeof x === "function");
    if (keep.length) return original.call(process.stderr, `${keep.join("\n")}\n`, ...rest);
    if (cb) cb();
    return true;
  };
  try { return { result: await fn(), lines: mine }; } finally { process.stderr.write = original; }
}

function parseProbe(stdout) {
  const out = {};
  for (const line of stdout.split("\n")) {
    const m = /^PROBE (\S+) ?(.*)$/.exec(line.trim());
    if (m) out[m[1]] = m[2];
  }
  return out;
}

const PROBE_HEAD = [
  "p() { printf 'PROBE %s %s\\n' \"$1\" \"$2\"; }",
  'tryw() { if ( : > "$2" ) 2>/dev/null; then p "$1" ok; else p "$1" fail; fi; }',
  'tryr() { if cat "$2" >/dev/null 2>&1; then p "$1" ok; else p "$1" fail; fi; }',
  // CONNECT through the box's proxy: the status line the proxy answers with
  'conn() { px=${HTTPS_PROXY#*://}; ph=${px%%:*}; pp=${px##*:}; r=$(timeout 8 bash -c \'exec 3<>/dev/tcp/\'"$ph"\'/\'"$pp"\'; printf "CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n" "$0" "$0" >&3; IFS= read -r line <&3; printf "%s" "$line"\' "$1" 2>/dev/null | tr -d "\\r"); p "$2" "${r:-none}"; }',
];

/** One real-box run shared by the write/read and the network checks of one self-test run (the env object is new per run). */
const sharedRuns = new WeakMap();
async function sharedProbe(tree, env) {
  if (!sharedRuns.has(env)) sharedRuns.set(env, runSharedProbe(tree, env.userHome ?? null));
  return sharedRuns.get(env);
}
async function runSharedProbe(tree, userHome) {
  const why = bwrapUnusable();
  if (why) return { skipped: why };
  const mod = await importBuilt(tree, SANDBOX_FILE);
  const world = makeWorld(userHome);
  const realHomeFile = world.realHome ? path.join(world.realHome, `.hardening-selftest-${hex()}`) : null;
  const server = net.createServer((s) => s.end());
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  try {
    const port = server.address().port;
    const { options, runId } = boxOptions(mod, world, { allowlist: [`127.0.0.1:${port}`] });
    fs.mkdirSync(options.homeDir, { recursive: true, mode: 0o700 });
    const script = [
      ...PROBE_HEAD,
      `WS=${sq(world.workspace)}; OUT=${sq(world.outside)}; RH=${sq(realHomeFile ?? "")}`,
      'tryw workspace "$WS/selftest"', 'tryw home "$HOME/selftest"',
      'tryw outside_write "$OUT/selftest"', 'tryw outside_overwrite "$OUT/canary"', 'tryr outside_read "$OUT/canary"',
      'tryw system_write /usr/hardening-selftest', '[ -n "$RH" ] && tryw real_home_write "$RH"',
      `conn selftest-denied.invalid:443 denied`, `conn 127.0.0.1:${port} allowed`,
    ].join("\n");
    const { lines, result } = await captureDenied(runId, () => runInBox(mod, options, script));
    const probe = parseProbe(result.stdout);
    const host = {
      outsideWrite: fs.existsSync(path.join(world.outside, "selftest")),
      outsideCanary: fs.readFileSync(path.join(world.outside, "canary"), "utf8"),
      realHomeWrite: realHomeFile ? fs.existsSync(realHomeFile) : false,
      systemWrite: fs.existsSync("/usr/hardening-selftest"),
    };
    if (realHomeFile) fs.rmSync(realHomeFile, { force: true });
    if (!probe.workspace) throw new Error(`the probe in the box printed nothing (exit ${result.code}): ${result.stderr.trim().slice(0, 300) || "no error text"}`);
    return { probe, lines, host, port, runId };
  } finally {
    server.close();
    world.cleanup();
  }
}

const skipDetail = (why) => `not run: ${why}`;

/** The spawn-target check of one adapter type: a bubblewrap command with an empty root, its own network and home, and the adapter registers itself and calls the helper. */
function spawnTargetCheck({ type, key, executeFile }, patches) {
  return {
    name: `a ${type} run gets a bubblewrap box with its own home, and the adapter uses it (${patches})`,
    async run(tree, env) {
      const mod = await importBuilt(tree, SANDBOX_FILE);
      for (const name of ["boxedSandboxOptions", "ensureBoxedRuntimeDir", "registerBoxedAdapter", "buildLocalProcessSandboxSpawnTarget"])
        if (typeof mod[name] !== "function") throw new Error(`${name} is missing from local-process-sandbox.js`);
      const world = makeWorld(env?.userHome ?? null);
      try {
        const detail = [];
        {  // one adapter type
          const runtime = path.join(world.root, "agents", type, `${key}-runtime`);
          await mod.ensureBoxedRuntimeDir(runtime);
          const { options } = boxOptions(mod, world, { type, runtime });
          const target = await mod.buildLocalProcessSandboxSpawnTarget({ executable: "/bin/sh", args: ["-c", "true"], cwd: world.workspace, options });
          try {
            const args = target.args;
            const has = (...seq) => args.some((_, i) => seq.every((s, j) => args[i + j] === s));
            if (path.basename(target.command) !== "bwrap") throw new Error(`${type}: the spawn command is ${target.command}, not bubblewrap`);
            if (!has("--tmpfs", "/")) throw new Error(`${type}: the box does not start from an empty root`);
            if (!args.includes("--unshare-net")) throw new Error(`${type}: the box shares the host network`);
            if (!has("--bind", runtime, runtime)) throw new Error(`${type}: its runtime folder is not mounted`);
            if (options.homeDir !== path.join(runtime, "home")) throw new Error(`${type}: its home is ${options.homeDir}, not inside the runtime folder`);
            if (world.realHome) {
              const inside = (parent, child) => child === parent || child.startsWith(`${parent}${path.sep}`);
              const bound = args.filter((a, i) => (args[i - 1] === "--bind" || args[i - 1] === "--ro-bind") && path.isAbsolute(a));
              const leak = bound.find((p) => inside(p, world.realHome) || inside(world.realHome, p));
              if (leak) throw new Error(`${type}: the box mounts the real home (${leak})`);
            }
            if (!options.envPassNames.includes(CREDENTIAL)) throw new Error(`${type}: the agent's own variables are not passed on`);
          } finally { await target.cleanup?.(); }
          const source = fs.readFileSync(path.join(tree, executeFile), "utf8");
          if (!new RegExp(`^registerBoxedAdapter\\("${type}"\\);`, "m").test(source)) throw new Error(`the ${type} adapter does not register itself as boxed`);
          if (!source.includes("boxedSandboxOptions({") || !source.includes(`type: "${type}"`)) throw new Error(`the ${type} adapter does not build its box with boxedSandboxOptions`);
          detail.push(type);
        }
        return `${detail.join(" and ")}: bubblewrap, empty root, own network, own home; the adapter registers and calls the helper`;
      } finally { world.cleanup(); }
    },
  };
}

export const BOX_CLAUDE_CHECKS = [
  spawnTargetCheck(CLAUDE_BOX_TYPE, "0017, 0026"),
  {
    name: "a process in the box cannot write or read outside its workspace and runtime folder (0017)",
    async run(tree, env) {
      const r = await sharedProbe(tree, env);
      if (r.skipped) return skipDetail(r.skipped);
      const { probe, host } = r;
      if (probe.workspace !== "ok" || probe.home !== "ok") throw new Error("the box does not let a run write to its own workspace and home (control failed)");
      const bad = [];
      const refused = [["outside_write", "a folder next to the workspace"], ["outside_overwrite", "a file next to the workspace"], ["outside_read", "a file next to the workspace (read)"],
        ["system_write", "/usr"], ...(probe.real_home_write === undefined ? [] : [["real_home_write", "the real home directory"]])];
      for (const [name, label] of refused) if (probe[name] !== "fail") bad.push(label);
      if (host.outsideWrite || host.realHomeWrite || host.systemWrite) bad.push("a file that exists on the host afterwards");
      if (host.outsideCanary !== "selftest-canary\n") bad.push("a canary file that was changed");
      if (bad.length) throw new Error(`a boxed process could reach: ${bad.join(", ")}`);
      return `workspace and home writable; a sibling folder, /usr${probe.real_home_write ? " and the real home" : ""} refused`;
    },
  },
  {
    name: "a host that is not on the allowlist gets 403 and a sandbox_network_denied line; an allowed one passes silently (0017)",
    async run(tree, env) {
      const r = await sharedProbe(tree, env);
      if (r.skipped) return skipDetail(r.skipped);
      const { probe, lines, port, runId } = r;
      if (!/^HTTP\/1\.[01] 403/.test(probe.denied ?? "")) throw new Error(`a host that is not on the allowlist was answered "${probe.denied ?? "nothing"}", not 403`);
      if (!/^HTTP\/1\.[01] 200/.test(probe.allowed ?? "")) throw new Error(`the allowed loopback target was answered "${probe.allowed ?? "nothing"}", not 200`);
      const denied = lines.filter((l) => l.host === "selftest-denied.invalid");
      if (denied.length !== 1) throw new Error(`expected one sandbox_network_denied line for the refused host, found ${denied.length}`);
      const [entry] = denied;
      if (entry.port !== 443 || entry.agentId !== "selftest-agent" || entry.runId !== runId) throw new Error(`the sandbox_network_denied line is wrong: ${JSON.stringify(entry)}`);
      if (lines.length !== denied.length) throw new Error(`the allowed target 127.0.0.1:${port} was logged as denied`);
      return "refused host: 403 + one sandbox_network_denied line (host, port, agent, run); allowed target: 200, no line";
    },
  },
  {
    name: "the server's environment does not reach a confined child; the agent's own variables do (0025)",
    async run(tree, env) {
      const why = bwrapUnusable();
      const source = fs.readFileSync(path.join(tree, SERVER_UTILS_FILE), "utf8");
      if (!/scrubConfinedChildEnv\(mergedEnv, opts\.env, opts\.localProcessSandbox\.envPassNames/.test(source)) throw new Error("runChildProcess does not scrub the environment of a confined child");
      const canary = `canary-${hex()}`;
      const serverEnv = { HARDENING_SELFTEST_CANARY: canary, DATABASE_URL: `postgres://paperclip:${canary}@127.0.0.1:1/db`, NODE_OPTIONS: "--max-old-space-size=64",
        LD_PRELOAD: "/nonexistent.so", BASH_ENV: "/nonexistent", PAPERCLIP_SECRETS_MASTER_KEY: canary };
      const adapterEnv = { ...serverEnv, [CREDENTIAL]: "dummy-not-a-credential", PAPERCLIP_RUN_ID: "selftest-run" };
      let mod = null;
      let how = "ran runChildProcess";
      try { mod = await importBuilt(tree, SERVER_UTILS_FILE); } catch { mod = null; }
      let seen;
      if (mod && typeof mod.runChildProcess === "function" && !why) {
        const sandbox = await importBuilt(tree, SANDBOX_FILE);
        const world = makeWorld(env?.userHome ?? null);
        try {
          await sandbox.ensureBoxedRuntimeDir(world.runtime);
          const { options } = boxOptions(sandbox, world);
          options.networkScope = "deny";
          const run = await mod.runChildProcess(`selftest-${hex()}`, "/usr/bin/env", [], { cwd: world.workspace, env: adapterEnv, timeoutSec: 20, graceSec: 2, onLog: async () => {}, localProcessSandbox: options });
          if (run.exitCode !== 0) throw new Error(`the confined test process failed (exit ${run.exitCode}): ${String(run.stderr).trim().slice(0, 300)}`);
          seen = Object.fromEntries(String(run.stdout).split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
        } finally { world.cleanup(); }
      } else {
        // The module cannot be loaded here (its dependencies are not next to it) or there is no bubblewrap: evaluate the scrub itself.
        const scrub = evalScrub(source);
        seen = scrub(adapterEnv, adapterEnv, [CREDENTIAL, "PAPERCLIP_RUN_ID"], "/box/home");
        how = mod ? `evaluated the scrub (${why})` : "evaluated the scrub (the module cannot be loaded outside Paperclip)";
      }
      const leaked = SERVER_NAMES.filter((n) => n in seen);
      if (leaked.length) throw new Error(`the child received ${leaked.join(", ")}`);
      if (JSON.stringify(seen).includes(canary)) throw new Error("the canary value reached the child");
      if (seen[CREDENTIAL] !== "dummy-not-a-credential") throw new Error("the agent's own variable did not reach the child");
      if (seen.PAPERCLIP_RUN_ID !== "selftest-run") throw new Error("the agent's run variable did not reach the child");
      const extra = Object.keys(seen).filter((n) => !/^(PATH|HOME|LANG|LANGUAGE|TZ|TERM|LC_[A-Z]+|HTTPS?_PROXY|ALL_PROXY|https?_proxy|all_proxy|NO_PROXY|no_proxy|PWD|SHLVL|_|OLDPWD)$/.test(n) && n !== CREDENTIAL && n !== "PAPERCLIP_RUN_ID");
      if (extra.length) throw new Error(`the child received variables nobody asked for: ${extra.slice(0, 5).join(", ")}`);
      return `${how}: ${SERVER_NAMES.length} server variables stopped, the agent's own two passed`;
    },
  },
];

export const BOX_OPENCODE_CHECKS = [spawnTargetCheck(OPENCODE_BOX_TYPE, "0019")];

/** The scrub function of patch 0025, evaluated from the built file's text (it reads only the server's own environment object and constants). */
function evalScrub(source) {
  const lines = source.split("\n");
  const from = lines.findIndex((l) => l.startsWith("// LOCAL-PATCH 0025: a confined"));
  const fn = lines.findIndex((l, i) => i > from && l.startsWith("function scrubConfinedChildEnv"));
  const end = lines.findIndex((l, i) => i > fn && l === "}");
  if (from < 0 || fn < 0 || end < 0) throw new Error("the environment scrub of the confined child was not found in server-utils.js");
  // eslint-disable-next-line no-new-func
  return new Function("process", `"use strict";\n${lines.slice(from, end + 1).join("\n")}\nreturn scrubConfinedChildEnv;`)({ env: {} });
}

export const ADMISSION_CHECKS = [{
  name: "an unboxed, unregistered or unscrubbed agent is refused with the missing piece named (0005f)",
  async run(tree, env) {
    const built = fs.readFileSync(path.join(tree, HEARTBEAT_FILE), "utf8");
    const code = admissionCode(built);
    const admit = (agent, { registered = ["claude_local", "opencode_local"], scrub = true } = {}) => {
      const globals = { [BOXED_ADAPTERS_KEY]: new Set(registered), [ENV_SCRUB_KEY]: scrub };
      const b = evalBlock(code, "0005f", { env: env.env, instanceRoot: env.instanceRoot, globals });
      try { b.refuseUnsandboxedLocalAgent({ agent, runId: "selftest-run" }); return null; } catch (e) { return String(e.message); }
    };
    const box = { filesystemScope: "workspace", networkScope: "allowlist" };
    const agent = (type, cfg) => ({ id: "selftest-agent", adapterType: type, adapterConfig: cfg });
    const mustRefuse = (what, message, re) => { if (!message) throw new Error(`${what} was admitted`); if (!re.test(message)) throw new Error(`${what} was refused without naming the reason: "${message.slice(0, 200)}"`); };
    mustRefuse("a claude_local agent without a box", admit(agent("claude_local", { engine: "cli" })), /no filesystemScope "workspace"/);
    mustRefuse("an opencode_local agent without a box", admit(agent("opencode_local", {})), /no filesystemScope "workspace"/);
    mustRefuse("a boxed claude_local agent on the default engine", admit(agent("claude_local", box)), /no engine "cli"/);
    mustRefuse("a boxed claude_local agent whose adapter is not registered", admit(agent("claude_local", { ...box, engine: "cli" }), { registered: ["opencode_local"] }), /claude_local adapter is not registered as boxed/);
    mustRefuse("a boxed opencode_local agent whose adapter is not registered", admit(agent("opencode_local", box), { registered: ["claude_local"] }), /opencode_local adapter is not registered as boxed/);
    mustRefuse("a boxed claude_local agent without the environment scrub", admit(agent("claude_local", { ...box, engine: "cli" }), { scrub: false }), /environment scrub .* not loaded/);
    mustRefuse("an adapter type nobody boxes", admit(agent("paperclip_runner", {})), /paperclip_runner/);
    const claude = admit(agent("claude_local", { ...box, engine: "cli" }));
    if (claude) throw new Error(`a boxed claude_local agent was refused: ${claude.slice(0, 200)}`);
    const opencode = admit(agent("opencode_local", box));
    if (opencode) throw new Error(`a boxed opencode_local agent was refused: ${opencode.slice(0, 200)}`);
    return "unboxed, wrong engine, unregistered, no scrub and unknown type refused with the reason; boxed Claude and OpenCode admitted";
  },
}];
