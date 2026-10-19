#!/usr/bin/env node
// Fallback CLI for the hardening engine (when the plugin cannot run), also used by the tests.
//   hardening-engine.mjs status
//   hardening-engine.mjs plan    --enable a,b
//   hardening-engine.mjs apply   --enable a,b [--confirm-core-off] [--repair] [--adopt-orig]
//   hardening-engine.mjs restore [--force]
// --enable takes protection ids, `defaults`, `all` or `none`. --repair rebuilds files edited outside the engine from
// their stored originals. --adopt-orig takes over files patched by apply.sh (other patch files) using their .orig. Common options: --tree DIR, --patches DIR, --data DIR,
// --unit NAME, --no-systemd, --json. Paperclip is never restarted here; the output says when a restart is needed.
// Exit: 0 ok | 1 error / nothing changed | 2 usage.
import { createEngine, PROTECTIONS } from "../src/engine/index.js";

const USAGE = "usage: hardening-engine.mjs status|plan|apply|restore [--enable a,b|defaults|all|none] [--confirm-core-off] [--repair] [--adopt-orig] [--force] [--tree DIR] [--patches DIR] [--data DIR] [--unit NAME] [--no-systemd] [--json]";

function parseArgs(argv) {
  const out = { cmd: undefined, flags: {} };
  const valued = new Set(["enable", "tree", "patches", "data", "unit"]);
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
  const engine = createEngine({ treeDir: flags.tree, patchesDir: flags.patches, dataDir: flags.data, unitName: flags.unit, systemctl: flags["no-systemd"] ? null : undefined });
  const out = (obj, text) => { if (flags.json) console.log(JSON.stringify(obj, null, 2)); else text(); };

  if (cmd === "status") {
    const s = await engine.status();
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
