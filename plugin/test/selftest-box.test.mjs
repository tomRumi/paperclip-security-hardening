// Self-test probes for the box around Claude and OpenCode agents (src/selftest-box.js): they pass on the engine's build, and each
// one fails when the thing it guards is broken (fail-before on Paperclip's original files, and a deliberately broken copy of the
// built file for each guard). Credential-free; the box checks run the real bubblewrap and say "not run" where it is unusable.
//   PAPERCLIP_STOCK_TREE_1012 / _1005   installs to copy originals from (see helpers/pristine.mjs)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createEngine, PROTECTIONS } from "../src/engine/index.js";
import { FUNCTIONAL_CHECKS } from "../src/selftest.js";
import { BOX_CLAUDE_CHECKS, BOX_OPENCODE_CHECKS, ADMISSION_CHECKS } from "../src/selftest-box.js";
import { makeScratchBase } from "./helpers/scratch-tree.mjs";
import { bwrapUnusable } from "./helpers/adapter-harness.mjs";

const ALL = PROTECTIONS.filter((p) => p.kind === "patch").map((p) => p.id);
const SANDBOX = "node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js";
const UTILS = "node_modules/@paperclipai/adapter-utils/dist/server-utils.js";
const HEARTBEAT = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
const noBwrap = bwrapUnusable();
const [DENY_PROBE, WRITE_PROBE, NETWORK_PROBE, SCRUB_PROBE] = [0, 1, 2, 3].map((i) => BOX_CLAUDE_CHECKS[i]);
const [OPENCODE_PROBE] = BOX_OPENCODE_CHECKS;
const CLAUDE_EXECUTE = "node_modules/@paperclipai/adapter-claude-local/dist/server/execute.js";
const OPENCODE_EXECUTE = "node_modules/@paperclipai/adapter-opencode-local/dist/server/execute.js";
const EVERY_PROBE = [...BOX_CLAUDE_CHECKS, ...BOX_OPENCODE_CHECKS, ...ADMISSION_CHECKS];
const [ADMISSION] = ADMISSION_CHECKS;
// The home of "the account Paperclip runs as" for these runs: a scratch folder (the probes only write there if the box is broken).
const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), "selftest-box-home-"));
test.after(() => fs.rmSync(fakeHome, { recursive: true, force: true }));
const env = () => ({ env: {}, instanceRoot: "/nonexistent-instance-root", userHome: fakeHome });

/** A scratch case with every protection applied by the engine. */
async function builtCase(S) {
  const f = S.fresh();
  const engine = createEngine(f.engineOptions);
  const r = await engine.apply(await engine.plan(ALL));
  assert.equal(r.ok, true, r.error);
  return f;
}
/** The same tree made loadable: the rest of adapter-utils (its dist and the shared package) next to the built files, so the
 *  patched server-utils.js can be imported the way Paperclip imports it. */
function loadable(f, S) {
  const utils = "node_modules/@paperclipai/adapter-utils";
  const stock = S.stock;
  for (const name of fs.readdirSync(path.join(stock, utils, "dist"))) {
    if (!name.endsWith(".js") || name.endsWith(".test.js")) continue;
    const dst = path.join(f.tree, utils, "dist", name);
    if (!fs.existsSync(dst)) fs.copyFileSync(path.join(stock, utils, "dist", name), dst);
  }
  fs.copyFileSync(path.join(stock, utils, "package.json"), path.join(f.tree, utils, "package.json"));
  // The scratch tree holds only the one file of @paperclipai/shared that a patch changes: link the whole package instead (this
  // case is thrown away afterwards; removing a symlink never touches the install it points to).
  const shared = path.join(f.tree, "node_modules/@paperclipai/shared");
  fs.rmSync(shared, { recursive: true, force: true });
  fs.symlinkSync(fs.realpathSync(path.join(stock, "node_modules/@paperclipai/shared")), shared);
  return f;
}
const edit = (f, rel, from, to) => {
  const file = path.join(f.tree, rel);
  const text = fs.readFileSync(file, "utf8");
  assert.ok(text.includes(from), `${rel}: "${from.slice(0, 60)}" not found`);
  fs.writeFileSync(file, text.replace(from, to));
};

for (const vkey of ["1012", "1005"]) {
  const S = makeScratchBase(`selftest-box-${vkey}-`, vkey);
  test.after(() => { if (!S.skip) S.cleanup(); });
  const skip = S.skip;

  test(`${vkey}: every probe passes on the engine's build (real bubblewrap: ${noBwrap || "usable"})`, { skip }, async () => {
    const f = loadable(await builtCase(S), S);
    try {
      const e = env();
      for (const check of EVERY_PROBE) {
        const detail = await check.run(f.tree, e);
        assert.equal(typeof detail, "string", check.name);
        if (!noBwrap) assert.doesNotMatch(detail, /^not run/, `${check.name}: ${detail}`);
      }
      assert.match(await SCRUB_PROBE.run(f.tree, e), /^ran runChildProcess/, "the real runChildProcess is used where the module can be loaded");
      assert.match(await WRITE_PROBE.run(f.tree, e), /real home/, "the account's home is part of the probe when the target names it");
      assert.doesNotMatch(await WRITE_PROBE.run(f.tree, { ...e, userHome: null }), /real home/);
    } finally { f.cleanup(); }
  });

  test(`${vkey}: the scrub probe falls back to the scrub's own code where the module cannot be loaded (scratch tree), with the same verdict`, { skip }, async () => {
    const f = await builtCase(S);
    try {
      assert.match(await SCRUB_PROBE.run(f.tree, env()), /evaluated the scrub/);
    } finally { f.cleanup(); }
  });

  test(`${vkey}: fail-before - on Paperclip's original files every new probe fails`, { skip }, async () => {
    const f = S.fresh();
    try {
      for (const check of EVERY_PROBE) await assert.rejects(check.run(f.tree, env()), undefined, `${check.name} passes on the original files`);
    } finally { f.cleanup(); }
  });

  test(`${vkey}: fail-before - on the v0.1.1 set of protections (no box for Claude and OpenCode, old admission) the probes fail`, { skip }, async () => {
    const f = S.fresh();
    try {
      const engine = createEngine(f.engineOptions);
      // Everything except the two protections of v0.2.0 that carry the new patches' effect.
      const r = await engine.apply(await engine.plan(["sandbox-compat", "own-box", "public-web", "own-claude-folder", "safe-defaults"]));
      assert.equal(r.ok, true, r.error);
      for (const check of [DENY_PROBE, OPENCODE_PROBE, NETWORK_PROBE, SCRUB_PROBE, ADMISSION]) await assert.rejects(check.run(f.tree, env()), undefined, check.name);
    } finally { f.cleanup(); }
  });

  // One deliberately broken copy of the built file per guard: the probe that guards it must say so.
  const broken = [
    { name: "a box that mounts the host's temp folder", probe: WRITE_PROBE, bwrap: true, file: SANDBOX,
      from: 'args.push("--tmpfs", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp");',
      to: `args.push("--tmpfs", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", ${JSON.stringify(fs.realpathSync(os.tmpdir()))}, ${JSON.stringify(fs.realpathSync(os.tmpdir()))});`, re: /could reach/ },
    { name: "a box that mounts the account's home", probe: WRITE_PROBE, bwrap: true, file: SANDBOX,
      from: 'args.push("--tmpfs", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp");',
      to: `args.push("--tmpfs", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", ${JSON.stringify(fakeHome)}, ${JSON.stringify(fakeHome)});`, re: /the real home directory/ },
    { name: "a proxy that refuses without logging", probe: NETWORK_PROBE, bwrap: true, file: SANDBOX,
      from: "process.stderr.write(`${JSON.stringify(entry)}\\n`);", to: "void entry;", re: /found 0/ },
    { name: "a spawn that passes the whole server environment", probe: SCRUB_PROBE, bwrap: true, file: UTILS, loadable: true,
      from: "    return scrubbed;\n}", to: "    return { ...merged };\n}", re: /child received/ },
    { name: "a Claude adapter that does not register itself as boxed", probe: DENY_PROBE, file: CLAUDE_EXECUTE,
      from: 'registerBoxedAdapter("claude_local");', to: "", re: /claude_local adapter does not register/ },
    { name: "an OpenCode adapter that does not register itself as boxed", probe: OPENCODE_PROBE, file: OPENCODE_EXECUTE,
      from: 'registerBoxedAdapter("opencode_local");', to: "", re: /opencode_local adapter does not register/ },
    { name: "an admission that does not need the environment scrub", probe: ADMISSION, file: HEARTBEAT,
      from: 'globalThis[Symbol.for("paperclip.hardening.envScrub")] !== true', to: "false", re: /without the environment scrub was admitted/ },
    { name: "an admission that does not need the adapter to be registered", probe: ADMISSION, file: HEARTBEAT,
      from: 'typeof registered?.has !== "function" || registered.has(adapterType) !== true', to: "false", re: /not registered.*was admitted/ },
  ];
  for (const b of broken) {
    test(`${vkey}: ${b.probe.name.split(" (")[0]} - fails on ${b.name}`, { skip: skip || (b.bwrap && noBwrap) }, async () => {
      let f = await builtCase(S);
      if (b.loadable) f = loadable(f, S);
      try {
        edit(f, b.file, b.from, b.to);
        await assert.rejects(b.probe.run(f.tree, env()), (err) => { assert.match(err.message, b.re); return true; });
      } finally { f.cleanup(); }
    });
  }
}

test("the probes are registered for the protections that own the patches", () => {
  assert.equal(FUNCTIONAL_CHECKS["box-claude"], BOX_CLAUDE_CHECKS);
  assert.equal(FUNCTIONAL_CHECKS["box-opencode"], BOX_OPENCODE_CHECKS);
  assert.equal(FUNCTIONAL_CHECKS["only-boxed"], ADMISSION_CHECKS);
  assert.equal(BOX_CLAUDE_CHECKS.length, 4);
  assert.equal(BOX_OPENCODE_CHECKS.length, 1);
  assert.ok(FUNCTIONAL_CHECKS["own-box"].some((c) => /0003b/.test(c.name)));
  for (const id of Object.keys(FUNCTIONAL_CHECKS)) assert.ok(PROTECTIONS.some((p) => p.id === id), id);
});
