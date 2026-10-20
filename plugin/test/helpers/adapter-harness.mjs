// Adapter test harness: runs the REAL, patched `execute` of a Paperclip local adapter against a STUB CLI inside the real
// bubblewrap box, and reads back what the stub saw (a probe). Used by every patch test that boxes an adapter (0017 and up).
//
//   const tree = await buildPatchedTree({ version: "1012", upTo: "0018", packages: ["adapter-codex-local"] });
//   if (tree.skip) return t.skip(tree.skip);
//   const run = await runAdapterProbe({ tree, adapter: ADAPTERS.codex_local, config: { ...BOXED, engine: "cli" }, probe: {...} });
//   run.probe.home, run.probe.env (variable NAMES only), run.probe.write[path] ...
//
// buildPatchedTree: a scratch `node_modules` where the named @paperclipai packages are copied from an installed Paperclip, the
// files our patches target are rebuilt from their PRISTINE bytes plus every patch with an id <= `upTo` (the stock+v0.1 chain
// for a new patch under test: pass the id just BELOW it for the fail-before run), and everything else is a symlink to the
// install. The install itself is only read. Pristine bytes of a file (pristine.mjs): its `.orig` backup, else the installed file when it
// carries no LOCAL-PATCH marker, else the engine store's copy; none of them -> `skip` ("NO PRISTINE: ...", loud).
//   HARDENING_TEST_SCRATCH             where scratch trees go (default: the OS temp dir)
//   PAPERCLIP_STOCK_TREE_<vkey>        install to read for 2026.<vkey>.0 (default ~/.paperclip/cli/installs/npm/2026.<vkey>.0);
//                                      point it at an untouched install
//
// runAdapterProbe: process.env is global, so runs are sequential. For the duration of a run the harness sets HOME to a fake
// "real home" holding canary files and puts server canaries in the environment (HARDENING_CANARY_SECRET, a fake DATABASE_URL),
// then restores everything.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { SOURCE_PATCHES_DIR } from "../../src/engine/index.js";
import { PATCHES, comparePatchIds } from "../../src/engine/registry.js";
import { buildFile, discoverPatchFiles, orderCandidates, readPatchTarget } from "../../src/engine/patches.js";
import { noPristineSkip, pristineOrNull, stockTreePath } from "./pristine.mjs";

const NM = "node_modules/@paperclipai";
export const CANARY_ENV = Object.freeze({ HARDENING_CANARY_SECRET: "canary-secret-0000", DATABASE_URL: "postgres://canary:canary@127.0.0.1:1/canary" });
/** Dummy credential value handed to a stub run; its NAME must reach the child, its value is meaningless. */
export const DUMMY_KEY = "sk-dummy-0000";
/** A box config as 0005a gives it to a new agent (hosts are the caller's). */
export const BOXED = Object.freeze({ filesystemScope: "workspace", networkScope: "allowlist", filesystemSandboxCommand: "/usr/bin/bwrap" });
/** The same with the CLI engine, which 0005a stores for the types with an ACP lane (without it they refuse a boxed run). */
export const BOXED_CLI = Object.freeze({ ...BOXED, engine: "cli" });

/** The local adapters: package, stub binary name, config key that names the command. */
export const ADAPTERS = Object.freeze({
  claude_local: { type: "claude_local", pkg: "adapter-claude-local", stub: "claude" },
  codex_local: { type: "codex_local", pkg: "adapter-codex-local", stub: "codex" },
  opencode_local: { type: "opencode_local", pkg: "adapter-opencode-local", stub: "opencode" },
  gemini_local: { type: "gemini_local", pkg: "adapter-gemini-local", stub: "gemini" },
  cursor: { type: "cursor", pkg: "adapter-cursor-local", stub: "agent" },
  pi_local: { type: "pi_local", pkg: "adapter-pi-local", stub: "pi" },
  kimi_local: { type: "kimi_local", pkg: "adapter-kimi-local", stub: "kimi" },
  grok_local: { type: "grok_local", pkg: "adapter-grok-local", stub: "grok" },
});

// stockTreePath / pristineOrNull live in pristine.mjs (one definition for every test); re-exported for the patch tests.
export { stockTreePath, pristineOrNull };

const markerOf = (id) => PATCHES[id]?.marker ?? `// LOCAL-PATCH ${id}`;
const COPY_SKIP = /(\.map|\.d\.ts|\.orig|\.test\.js)$/;

/**
 * A scratch install: node_modules/@paperclipai/<pkg> copied for each of `packages` (adapter-utils is always included), with the
 * patched files rebuilt from pristine + patches <= upTo (all patches when upTo is omitted); everything else symlinked.
 * Returns {skip:false, root, nm, version, applied:[{rel, ids}], cleanup} or {skip:reason}.
 */
export async function buildPatchedTree({ version = "1012", upTo = null, packages = [], patchesDir = SOURCE_PATCHES_DIR, scratch = process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir() } = {}) {
  const stock = stockTreePath(version);
  if (!fs.existsSync(path.join(stock, NM))) return { skip: `no Paperclip 2026.${version}.0 install at ${stock}` };
  const pkgs = [...new Set(["adapter-utils", ...packages])];
  const byTarget = new Map();
  for (const [id, files] of discoverPatchFiles(patchesDir)) {
    if (upTo && comparePatchIds(id, upTo) > 0) continue;
    const rel = readPatchTarget(files[0].file);
    if (!pkgs.some((pkg) => rel.startsWith(`${NM}/${pkg}/`))) continue;
    byTarget.set(rel, [...(byTarget.get(rel) ?? []), { id, candidates: orderCandidates(files, version), marker: markerOf(id) }]);
  }
  // Files with a pristine to restore even when no patch <= upTo touches them: nothing to do for those, the copy is the install's
  // file. A patched install file must never leak in, so the targets of ALL patches are rebuilt (steps may be empty).
  for (const [id, files] of discoverPatchFiles(patchesDir)) {
    const rel = readPatchTarget(files[0].file);
    if (pkgs.some((pkg) => rel.startsWith(`${NM}/${pkg}/`)) && !byTarget.has(rel)) byTarget.set(rel, []);
  }
  const built = new Map();
  const applied = [];
  for (const [rel, steps] of byTarget) {
    const pristine = pristineOrNull(stock, rel);
    if (!pristine) return { skip: noPristineSkip(stock, [rel], version) };
    steps.sort((a, b) => comparePatchIds(a.id, b.id));
    const r = buildFile({ rel, pristine, steps, tmpDir: scratch });
    if (!r.ok) return { skip: `patch chain does not fit 2026.${version}.0: ${r.reason}`, failedId: r.failedId };
    built.set(rel, r.content);
    applied.push({ rel, ids: steps.map((s) => s.id) });
  }
  const root = fs.mkdtempSync(path.join(scratch, `adapter-tree-${version}-`));
  const nm = path.join(root, "node_modules");
  fs.mkdirSync(path.join(nm, "@paperclipai"), { recursive: true });
  for (const entry of fs.readdirSync(path.join(stock, "node_modules"))) {
    if (entry === "@paperclipai" || entry.startsWith(".")) continue;
    fs.symlinkSync(path.join(stock, "node_modules", entry), path.join(nm, entry));
  }
  for (const entry of fs.readdirSync(path.join(stock, NM))) {
    const dst = path.join(nm, "@paperclipai", entry);
    if (pkgs.includes(entry)) fs.cpSync(path.join(stock, NM, entry), dst, { recursive: true, filter: (src) => !COPY_SKIP.test(src) });
    else fs.symlinkSync(path.join(stock, NM, entry), dst);
  }
  for (const [rel, bytes] of built) fs.writeFileSync(path.join(root, rel), bytes);
  return { skip: false, root, nm, version, applied, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

/** Import a module of the scratch tree, e.g. importFromTree(tree, "adapter-utils/dist/local-process-sandbox.js"). */
export function importFromTree(tree, relInPackages) {
  return import(pathToFileURL(path.join(tree.nm, "@paperclipai", relInPackages)).href);
}

// ---------------------------------------------------------------------------------------------------------------------
// Stub CLI and probe

const sq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
/** Shell word for a probe path; a leading "~/" means the stub's own $HOME. */
const qp = (p) => (String(p).startsWith("~/") ? `"$HOME"${sq(String(p).slice(1))}` : sq(p));

/**
 * Source of a stub CLI (a sh script named like the real binary). It consumes stdin, then prints one `PROBE <key> <value...>`
 * line per fact; values never include environment VALUES (only names). `probe`:
 *   write [paths]    try to create a file (ok|fail). `ok` can be an ephemeral file on the box's private tmpfs (e.g. /etc/x):
 *                    the result's `persisted` says which of them also exist on the HOST (those are removed after the run)
 *   read [paths]     try to read a file (ok|fail)
 *   ls [paths]       entries in the directory (a count) or `absent`
 *   tcp ["host:port"]       direct TCP connect, no proxy (ok|fail)
 *   connect ["host:port"]   CONNECT through $HTTPS_PROXY: the status line, or `noproxy` / `fail`
 * A path starting with "~/" is relative to the HOME the stub runs with (the key in the result keeps the "~/").
 */
export function stubCliSource(probe = {}) {
  const lines = ["#!/bin/sh", "timeout 2 cat >/dev/null 2>&1 </dev/stdin || true", "p() { printf 'PROBE %s %s\\n' \"$1\" \"$2\"; }"];
  lines.push('p home "$HOME"', 'p pwd "$(pwd)"', "p env \"$(env | sed 's/=.*//' | sort | tr '\\n' ' ')\"", 'p args "$#"');
  for (const f of probe.write ?? []) lines.push(`if ( : > ${qp(f)} ) 2>/dev/null; then p write:${f} ok; else p write:${f} fail; fi`);
  for (const f of probe.read ?? []) lines.push(`if cat ${qp(f)} >/dev/null 2>&1; then p read:${f} ok; else p read:${f} fail; fi`);
  for (const d of probe.ls ?? []) lines.push(`if [ -d ${qp(d)} ]; then p ls:${d} "$(ls -A ${qp(d)} 2>/dev/null | wc -l | tr -d ' ')"; else p ls:${d} absent; fi`);
  for (const hp of probe.tcp ?? []) lines.push(`if timeout 3 bash -c 'exec 3<>/dev/tcp/${hp.split(":")[0]}/${hp.split(":")[1]}' 2>/dev/null; then p tcp:${hp} ok; else p tcp:${hp} fail; fi`);
  for (const hp of probe.connect ?? []) {
    lines.push(`p_connect() { [ -n "$HTTPS_PROXY" ] || { p connect:$1 noproxy; return; }; px=\${HTTPS_PROXY#*://}; ph=\${px%%:*}; pp=\${px##*:};` +
      ` r=$(timeout 5 bash -c 'exec 3<>/dev/tcp/'"$ph"'/'"$pp"'; printf "CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n" "$0" "$0" >&3; IFS= read -r line <&3; printf "%s" "$line"' "$1" 2>/dev/null | tr -d '\\r');` +
      ` p connect:$1 "\${r:-fail}"; }`, `p_connect ${sq(hp)}`);
  }
  return `${lines.join("\n")}\n`;
}

/** Write the stub to <dir>/<name> (mode 0755) and return its path. */
export function writeStubCli(dir, name, probe) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, name);
  fs.writeFileSync(file, stubCliSource(probe), { mode: 0o755 });
  return file;
}

export function parseProbe(text) {
  const out = { raw: [], write: {}, read: {}, ls: {}, tcp: {}, connect: {} };
  for (const line of String(text).split("\n")) {
    const m = /^PROBE (\S+) ?(.*)$/.exec(line.trim());
    if (!m) continue;
    out.raw.push(line.trim());
    const [key, value] = [m[1], m[2]];
    const [kind, ...rest] = key.split(":");
    if (rest.length && out[kind]) out[kind][rest.join(":")] = kind === "ls" ? (value === "absent" ? null : Number(value)) : kind === "connect" ? value : value === "ok";
    else if (key === "env") out.env = value.trim().split(/\s+/).filter(Boolean);
    else out[key] = value;
  }
  return out;
}

/** HOME for a run: a directory with canary credential files where a real user's CLI state would be. */
export function seedFakeRealHome(dir) {
  for (const sub of [".claude", ".codex", ".config/opencode", ".local/share/opencode", ".gemini", ".pi", ".grok", ".kimi-code", ".cursor", ".hermes"]) {
    fs.mkdirSync(path.join(dir, sub), { recursive: true });
    fs.writeFileSync(path.join(dir, sub, "canary"), "real-home-canary\n");
  }
  return dir;
}

/** `<instance root>/companies/<c>/agents/<a>/<key>-runtime` as the adapter patches lay it out. */
export function runtimeDirFor(world, key, companyId = world.companyId, agentId = world.agentId) {
  return path.join(world.instanceRoot, "companies", companyId, "agents", agentId, `${key}-runtime`);
}

/**
 * Run `execute` of the adapter in the scratch tree once, against a stub CLI, and return what happened.
 *   tree      from buildPatchedTree (it must include adapter.pkg)
 *   adapter   an ADAPTERS entry          config  adapter config (spread over {command: <stub>, cwd: <workspace>})
 *   env       the agent's own adapterConfig.env (values are strings or {type:"plain",value})
 *   probe     see stubCliSource (or a function of the world)      context  extra ctx.context fields
 *   world     from makeWorld(tree), when the probe needs its paths (real home, sibling runtime dirs)
 *   serverEnv extra server process.env for the run (the canaries are always set)
 * Returns {probe, persisted, stdout, stderr, result, error, world, spawned}. `stderr` includes what the sandbox proxy wrote to the
 * server's own stderr (the denied-network log).
 */
export async function runAdapterProbe({ tree, adapter, config = {}, env = {}, probe = {}, context = {}, serverEnv = {}, world: given = null, timeoutMs = 60_000 }) {
  const world = given ?? makeWorld(tree);
  const stubDir = path.join(world.root, "bin");
  writeStubCli(stubDir, adapter.stub, typeof probe === "function" ? probe(world) : probe);
  const agent = { id: world.agentId, companyId: world.companyId, name: "probe", adapterType: adapter.type, adapterConfig: {} };
  const logs = { stdout: "", stderr: "" };
  const spawned = [];
  const ctx = {
    runId: world.runId, agent, runtime: { sessionId: null, sessionParams: null, sessionDisplayId: null, taskKey: null },
    config: { command: path.join(stubDir, adapter.stub), cwd: world.workspace, env, ...config },
    context: { paperclipWorkspace: { cwd: world.workspace, source: "project_primary" }, ...context },
    authToken: "dummy-run-token",
    onLog: async (stream, chunk) => { logs[stream === "stderr" ? "stderr" : "stdout"] += chunk; },
    onMeta: async () => {}, onEvent: async () => {}, onSpawn: async (info) => { spawned.push(info); },
  };
  const mod = await importFromTree(tree, `${adapter.pkg}/dist/server/index.js`);
  const saved = { env: { ...process.env }, write: process.stderr.write };
  const hostStderr = [];
  Object.assign(process.env, { HOME: world.realHome, PAPERCLIP_HOME: world.paperclipHome, PAPERCLIP_INSTANCE_ID: "test", ...CANARY_ENV, ...serverEnv });
  process.stderr.write = function (chunk, ...rest) { hostStderr.push(String(chunk)); return typeof rest.at(-1) === "function" ? rest.at(-1)() : true; };
  let result = null, error = null;
  try {
    result = await Promise.race([
      mod.execute(ctx),
      new Promise((_, reject) => setTimeout(() => reject(new Error(`adapter run exceeded ${timeoutMs} ms`)), timeoutMs).unref()),
    ]);
  } catch (e) { error = e; }
  finally {
    process.stderr.write = saved.write;
    for (const k of Object.keys(process.env)) if (!(k in saved.env)) delete process.env[k];
    Object.assign(process.env, saved.env);
  }
  const parsed = parseProbe(logs.stdout);
  const persisted = {};
  for (const file of Object.keys(parsed.write)) {
    if (file.startsWith("~/")) continue; // inside the box's own home
    persisted[file] = fs.existsSync(file);
    if (persisted[file]) fs.rmSync(file, { force: true });
  }
  return { probe: parsed, persisted, stdout: logs.stdout, stderr: logs.stderr + hostStderr.join(""), hostStderr: hostStderr.join(""), result, error, world, spawned };
}

/** Directories of one run: workspace, a fake real home with canaries, the Paperclip home/instance, ids. */
export function makeWorld(tree) {
  const root = fs.mkdtempSync(path.join(path.dirname(tree.root), "world-"));
  const paperclipHome = path.join(root, "paperclip-home");
  const workspace = path.join(root, "workspace");
  fs.mkdirSync(workspace, { recursive: true });
  return {
    root, paperclipHome, workspace, realHome: seedFakeRealHome(path.join(root, "real-home")),
    instanceRoot: path.join(paperclipHome, "instances", "test"),
    companyId: "00000000-0000-4000-8000-0000000000c1", agentId: "00000000-0000-4000-8000-0000000000a1", runId: "00000000-0000-4000-8000-0000000000e1",
    cleanup: () => fs.rmSync(root, { recursive: true, force: true }),
  };
}

/** Is bubblewrap usable here (unprivileged user namespaces)? Tests that run a real box skip with the reason otherwise. */
export function bwrapUnusable(command = "/usr/bin/bwrap") {
  const r = spawnSync(command, ["--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--unshare-net", "--unshare-pid", "/bin/sh", "-c", "exit 0"], { stdio: "ignore", timeout: 10_000 });
  return r.status === 0 ? false : `bubblewrap is not usable here (${command}: ${r.error?.code ?? `exit ${r.status}`})`;
}
