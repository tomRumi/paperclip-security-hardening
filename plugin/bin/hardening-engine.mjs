#!/usr/bin/env node
// Fallback CLI for the hardening engine (when the plugin cannot run), also used by the tests.
//   hardening-engine.mjs status
//   hardening-engine.mjs plan    --enable a,b
//   hardening-engine.mjs apply   --enable a,b [--confirm-core-off] [--repair] [--adopt-orig]
//   hardening-engine.mjs restore [--force]
// --enable takes protection ids, `defaults`, `all` or `none`. --repair rebuilds files edited outside the engine from
// their stored originals. --adopt-orig takes over files patched by apply.sh (other patch files) using their .orig.
// Paperclip is never restarted here; the output says when a restart is needed.
//
// Which Paperclip is changed (every command prints the resolved target first, and --json includes it):
//   --pid N            the Paperclip server process N (derived from /proc/N like the plugin does; read-only lookup)
//   --instance ID [--home DIR]   the managed install of that instance: tree = <home>/cli/current, data = <home>/sandbox-hardening,
//                      unit = Paperclip's name for the instance (paperclipai.service / paperclipai-<id>.service). The home is
//                      --home, else $PAPERCLIP_HOME, else ~/.paperclip
//   (none of these)    the default instance: tree $PAPERCLIP_TREE or ~/.paperclip/cli/current, data $PAPERCLIP_HARDENING_DATA or
//                      ~/.paperclip/sandbox-hardening (the apply.sh rule)
//   --tree DIR, --data DIR, --unit NAME, --no-systemd   explicit values; they win over all of the above
// Other options: --patches DIR, --json.
// Exit: 0 ok | 1 error / nothing changed | 2 usage.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createEngine, PROTECTIONS, resolveTargetFromParent, describeInstanceLayout, resolveInstanceInputs, TargetError } from "../src/engine/index.js";

const USAGE = "usage: hardening-engine.mjs status|plan|apply|restore [--enable a,b|defaults|all|none] [--confirm-core-off] [--repair] [--adopt-orig] [--force] [--pid N | --instance ID [--home DIR]] [--tree DIR] [--patches DIR] [--data DIR] [--unit NAME] [--no-systemd] [--json]";

function parseArgs(argv) {
  const out = { cmd: undefined, flags: {} };
  const valued = new Set(["enable", "tree", "patches", "data", "unit", "instance", "home", "pid"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      if (out.cmd !== undefined) throw new Error(`unexpected argument ${a}`);
      out.cmd = a;
      continue;
    }
    const [k, inline] = a.slice(2).split(/=(.*)/s);
    if (valued.has(k)) {
      const v = inline ?? argv[++i];
      if (v === undefined) throw new Error(`--${k} needs a value`);
      out.flags[k] = v;
    } else out.flags[k] = true;
  }
  return out;
}

/**
 * Which Paperclip to work on: a running server process (--pid), an instance (--instance/--home) or the default instance,
 * with --tree/--data/--unit/--no-systemd as explicit overrides.
 * @returns {{target: object, engineOptions: object, serverStartedAt?: string}}
 */
function buildTarget(flags, env = process.env) {
  const userHome = os.homedir();
  let base;
  if (flags.pid !== undefined) {
    const pid = Number(flags.pid);
    if (!Number.isInteger(pid) || pid <= 1) throw new UsageError("--pid needs the process id of a running Paperclip server");
    if (flags.instance !== undefined || flags.home !== undefined) throw new UsageError("--pid cannot be combined with --instance or --home");
    const r = resolveTargetFromParent({ pid });
    if (!r.ok) throw new TargetError(r.code, r.reason, r.evidence);
    base = r.target;
  } else if (flags.instance !== undefined || flags.home !== undefined) {
    const { home, instanceId } = resolveInstanceInputs({ flags: { instance: flags.instance, dataDir: flags.home }, env, userHome, cwd: process.cwd() });
    const layout = describeInstanceLayout({ home, instanceId });
    base = { source: "instance", ...layout, tree: path.join(home, "cli", "current"), restart: { unit: layout.unit, unverified: true } };
  } else {
    const layout = describeInstanceLayout({ home: path.join(userHome, ".paperclip"), instanceId: "default" });
    base = { source: "default", ...layout, tree: env.PAPERCLIP_TREE || path.join(layout.home, "cli", "current"), dataDir: env.PAPERCLIP_HARDENING_DATA || layout.dataDir,
      restart: { unit: layout.unit, unverified: true } };
  }
  const wantedTree = flags.tree ?? base.tree;
  let tree;
  try { tree = fs.realpathSync(wantedTree); } catch { tree = wantedTree; } // the engine reports a missing tree itself
  const dataDir = flags.data ?? base.dataDir;
  const explicit = base.source === "default" && (flags.tree !== undefined || flags.data !== undefined);
  const engineOptions = { treeDir: tree, dataDir, patchesDir: flags.patches, refuseTreeChange: base.source !== "default" && flags.tree === undefined && flags.data === undefined };
  let restart;
  if (flags["no-systemd"]) { engineOptions.systemctl = null; restart = { unit: null, note: "disabled (--no-systemd)" }; }
  else if (flags.unit !== undefined) { engineOptions.unitName = flags.unit; restart = { unit: flags.unit, note: "unit chosen with --unit (not verified)" }; }
  else if (base.source === "server-process") { engineOptions.restart = base.restart; restart = base.restart.unit ? { unit: base.restart.unit, note: "verified: Paperclip runs in this unit" } : { unit: null, note: base.restart.reason }; }
  else { engineOptions.unitName = base.restart.unit; restart = { unit: base.restart.unit, note: "assumed from the instance id (not verified)" }; }
  const target = {
    source: base.source, pid: base.pid ?? null, instanceId: base.instanceId, home: base.home, tree, dataDir,
    configPath: explicit ? null : base.configPath, restartUnit: restart.unit, restartNote: restart.note,
  };
  return { target, engineOptions, serverStartedAt: base.source === "server-process" ? base.startedAt : undefined };
}

class UsageError extends Error {}

function printTarget(t) {
  const how = { "server-process": `server process ${t.pid}`, instance: `instance ${t.instanceId}`, default: "default instance" }[t.source];
  console.log(`target (${how}):`);
  console.log(`  tree:    ${t.tree}`);
  console.log(`  data:    ${t.dataDir}`);
  console.log(`  config:  ${t.configPath ?? "(not tracked with --tree/--data)"}`);
  console.log(`  restart: ${t.restartUnit ? `${t.restartUnit} (${t.restartNote})` : `none (${t.restartNote})`}`);
}

function enabledFrom(value) {
  if (value === undefined) throw new Error("--enable is required (ids, defaults, all or none)");
  if (value === "none" || value === "") return [];
  if (value === "all") return PROTECTIONS.filter((p) => p.kind === "patch").map((p) => p.id);
  if (value === "defaults") return PROTECTIONS.filter((p) => p.kind === "patch" && p.defaultOn).map((p) => p.id);
  return value.split(",").map((s) => s.trim()).filter(Boolean);
}

function printPlan(plan) {
  console.log(`tree: ${plan.tree} (paperclipai ${plan.paperclipVersion ?? "unknown"})`);
  for (const a of plan.added) if (!plan.neededOff.some((n) => n.id === a.id)) console.log(`added: ${a.id} (needed by ${a.neededBy.join(", ")})`);
  for (const n of plan.neededOff) console.log(`kept on: ${n.id} is needed by ${n.neededBy.join(", ")}; switch those off too to remove it`);
  for (const p of plan.protections) console.log(`  ${p.action.padEnd(12)} ${p.id}${p.reason ? `  (${p.reason})` : ""}`);
  for (const c of plan.confirmationNeeded) console.log(`confirm: switching off "${c.title}": ${c.risk}`);
  console.log(`${plan.changes} file(s) to rewrite`);
}

async function main() {
  let args;
  try { args = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\n${USAGE}`); return 2; }
  const { cmd, flags } = args;
  if (!["status", "plan", "apply", "restore"].includes(cmd)) { console.error(USAGE); return 2; }
  let built;
  try { built = buildTarget(flags); }
  catch (e) {
    if (e instanceof UsageError) { console.error(`${e.message}\n${USAGE}`); return 2; }
    throw e;
  }
  const { target } = built;
  if (!flags.json) printTarget(target); // before anything is read or changed
  const engine = createEngine(built.engineOptions);
  const out = (obj, text) => { if (flags.json) console.log(JSON.stringify({ ...obj, target }, null, 2)); else text(); };

  if (cmd === "status") {
    const s = await engine.status(built.serverStartedAt === undefined ? {} : { serverStartedAt: built.serverStartedAt });
    out(s, () => {
      console.log(`tree: ${s.tree} (paperclipai ${s.paperclipVersion ?? "unknown"})`);
      for (const p of s.protections) console.log(`  ${p.status.padEnd(16)} ${p.id}${p.reason ? `  (${p.reason})` : ""}`);
      for (const f of s.files) if (f.state !== "pristine" && f.state !== "built") console.log(`  file ${f.state}: ${f.rel}`);
      console.log(s.restartNeeded ? "restart needed" : "no restart needed");
    });
    return 0;
  }
  if (cmd === "restore") {
    const r = await engine.restoreAll({ force: Boolean(flags.force) });
    out(r, () => {
      for (const f of r.restored) console.log(`restored ${f}`);
      for (const f of r.skipped) console.log(`skipped ${f.rel}: ${f.reason}`);
      console.log(r.ok ? (r.restartNeeded ? "restart Paperclip now" : "nothing to restore") : r.error);
    });
    return r.ok ? 0 : 1;
  }
  let enabled;
  try { enabled = enabledFrom(flags.enable); } catch (e) { console.error(`${e.message}\n${USAGE}`); return 2; }
  const plan = await engine.plan(enabled, { repair: Boolean(flags.repair), adoptOrig: Boolean(flags["adopt-orig"]) });
  if (cmd === "plan") { out(plan, () => printPlan(plan)); return 0; }
  const r = await engine.apply(plan, { confirmCoreOff: Boolean(flags["confirm-core-off"]) });
  out({ plan, result: r }, () => {
    printPlan(plan);
    if (!r.ok) { console.error(r.error); return; }
    for (const f of r.changed) console.log(`rewrote ${f}`);
    if (r.restartNeeded) {
      const info = engine.restartInfo();
      console.log(info.canRestart ? `restart needed: ${info.commandText}` : "restart Paperclip now");
    }
  });
  return r.ok ? 0 : 1;
}

main().then((code) => { process.exitCode = code; }, (e) => { console.error(`hardening-engine: ${e.message}`); process.exitCode = 1; });
