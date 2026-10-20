// Patch 0026 (host/patches/0026-claude-boxed-adapter.patch, task T14): claude_local runs through the shared box of 0017 and the env scrub
// of 0025. Stacked on 0016 (per-agent Claude config dir). What the tests prove, with the REAL patched `execute` of the adapter, a stub
// `claude` and the real bubblewrap box (helpers/adapter-harness.mjs; scratch trees are rebuilt from the PRISTINE bytes plus the patch chain):
//   * the server canary (HARDENING_CANARY_SECRET, DATABASE_URL) never reaches the child; the agent's credential, the PAPERCLIP_ run
//     variables (also the ones the adapter adds after the box is built) and CLAUDE_CONFIG_DIR do
//   * the live agents' shape (engine cli, workspace + allowlist, per-agent Claude dir, stored env = OAuth token + a telemetry flag)
//   * an evil PAPERCLIP_API_URL in config.env is not trusted by the proxy; the adapter's own API URL is
//   * the managed AI connection path (server-made credential home outside the instance)
//   * the bypass paths: the minimum-version probe and `claude login` run in the box with the scrubbed env, not with the server's
//   * the instructions bundle is mounted read-only straight from the company's prompt cache (allowed by the guard of 0017, read-only only)
//   * the admission of 0005f admits the boxed claude agent with the full chain (0016+0017+0025+0026 loaded, 0003b+0005f on heartbeat)
//     and refuses it on the chain without 0026 (fail-before)
// Two Paperclip versions: 2026.1012.0 and 2026.1005.0 (a version without install or pristine is skipped with the reason).
//   PAPERCLIP_STOCK_TREE_<vkey>  install to read   HARDENING_TEST_SCRATCH  scratch parent dir
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { discoverPatchFiles, readPatchTarget, buildFile } from "../src/engine/patches.js";
import { BLOCKS, extractBlock, evalBlock } from "./helpers/patch-block.mjs";
import { noPristineSkip, pristineOrNull, stockTreePath } from "./helpers/pristine.mjs";
import {
  ADAPTERS, BOXED_CLI, CANARY_ENV, buildPatchedTree, bwrapUnusable, importFromTree, makeWorld, runAdapterProbe, runtimeDirFor, stubCliSource,
} from "./helpers/adapter-harness.mjs";

const PATCH = path.join(SOURCE_PATCHES_DIR, "0026-claude-boxed-adapter.patch");
const EXECUTE = "node_modules/@paperclipai/adapter-claude-local/dist/server/execute.js";
const HB = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0026-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

const versions = ["1012", "1005"].filter((v) => fs.existsSync(stockTreePath(v)));
const noVersion = versions.length ? false : "no Paperclip install found (set PAPERCLIP_STOCK_TREE_1012)";
const noBwrap = bwrapUnusable();

const FAKE_TOKEN = "fake-oauth-token-for-0026-tests";
const TOKEN_SHA = crypto.createHash("sha256").update(FAKE_TOKEN).digest("hex");
const RUN_TOKEN = "dummy-run-token"; // ctx.authToken of the harness -> PAPERCLIP_API_KEY
const RUN_TOKEN_SHA = crypto.createHash("sha256").update(RUN_TOKEN).digest("hex");
const TELEMETRY = Object.freeze({ DISABLE_TELEMETRY: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" }); // neither 0005a nor 0016 sets one: the live agents carry their own
/** The stored env of a live agent: the OAuth token (a resolved secret_ref) and the telemetry flags. */
const LIVE_ENV = Object.freeze({ CLAUDE_CODE_OAUTH_TOKEN: FAKE_TOKEN, ...TELEMETRY });
/** A live agent's stored config shape (0005a defaults + engine cli + a model that needs the minimum-version probe). */
const LIVE_CONFIG = Object.freeze({ ...BOXED_CLI, networkAllowlist: ["api.anthropic.com"], model: "claude-fable-5-1" });

const trees = new Map();
async function treeFor(version, upTo) {
  const key = `${version}/${upTo}`;
  if (!trees.has(key)) trees.set(key, await buildPatchedTree({ version, upTo, packages: [ADAPTERS.claude_local.pkg], scratch }));
  return trees.get(key);
}
const after = (version) => treeFor(version, "0026");
const before = (version) => treeFor(version, "0025"); // the chain without 0026: 0016 + 0017 + 0025

/**
 * The stub `claude`. `--version` and `login` write what they saw to a file in the workspace (their stdout is not logged);
 * the run prints PROBE lines: values (never the credentials: a sha256), the config dir, the args.
 */
function stubSource(world, probe = {}) {
  const dump = (file) => `{ printf 'HOME=%s\\nCFG=%s\\nCANARY=%s\\nDB=%s\\nTOKEN_SHA=%s\\nENV=' "$HOME" "$CLAUDE_CONFIG_DIR" "\${HARDENING_CANARY_SECRET+set}" "\${DATABASE_URL+set}" "$(printf %s "$CLAUDE_CODE_OAUTH_TOKEN" | sha256sum | cut -c1-64)"; env | sed 's/=.*//' | sort | tr '\\n' ' '; printf '\\n'; } > "$PWD/${file}"`;
  const head = [
    "#!/bin/sh",
    `case "$1" in --version) ${dump("probe-version.txt")}; echo 2.1.300; exit 0;; login) ${dump("probe-login.txt")}; exit 0;; esac`,
  ].join("\n");
  const body = stubCliSource({ read: [path.join(world.realHome, ".claude", "canary")], ...probe }).replace(/^#!\/bin\/sh\n/, "");
  const extra = [
    "p cfg \"$CLAUDE_CONFIG_DIR\"",
    "p tokensha \"$(printf %s \"$CLAUDE_CODE_OAUTH_TOKEN\" | sha256sum | cut -c1-64)\"",
    "p apikeysha \"$(printf %s \"$PAPERCLIP_API_KEY\" | sha256sum | cut -c1-64)\"",
    "p telemetry \"${DISABLE_TELEMETRY-unset}/${CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC-unset}\"",
    "p canary \"${HARDENING_CANARY_SECRET+set}${DATABASE_URL+set}\"",
    "p apiurl \"$PAPERCLIP_API_URL\"", "p runid \"$PAPERCLIP_RUN_ID\"", "p agentid \"$PAPERCLIP_AGENT_ID\"", "p companyid \"$PAPERCLIP_COMPANY_ID\"",
    "p wscwd \"$PAPERCLIP_WORKSPACE_CWD\"",
    "if ( : > \"$CLAUDE_CONFIG_DIR/probe-write\" ) 2>/dev/null; then p cfgwrite ok; else p cfgwrite fail; fi",
    "if [ -f \"$CLAUDE_CONFIG_DIR/settings.json\" ]; then p settings yes; else p settings no; fi",
    "if [ -r \"$CLAUDE_CONFIG_DIR/.credentials-managed\" ]; then p managedcred yes; else p managedcred no; fi",
    'prev=""; for a in "$@"; do if [ "$prev" = --append-system-prompt-file ]; then ifile="$a"; fi; prev="$a"; done',
    'p instr "$ifile"',
    'if [ -n "$ifile" ] && [ -r "$ifile" ]; then p instrread yes; else p instrread no; fi',
    'if [ -n "$ifile" ] && ( : >> "$ifile" ) 2>/dev/null; then p instrwrite yes; else p instrwrite no; fi',
  ].join("\n");
  return `${head}\n${body}${extra}\n`;
}
function installStub(world, probe) {
  const dir = path.join(world.root, "stub-bin");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "claude");
  fs.writeFileSync(file, stubSource(world, probe), { mode: 0o755 });
  return file;
}
const readDump = (world, name) => Object.fromEntries(fs.readFileSync(path.join(world.workspace, name), "utf8").split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));

/** One run of the real execute against the stub; `fn(world)` may add config. */
async function run(tree, { config = {}, env = LIVE_ENV, probe = {}, serverEnv = {}, withInstructions = true } = {}) {
  const world = makeWorld(tree);
  const command = installStub(world, probe);
  const instructions = path.join(world.root, "AGENTS.md");
  fs.writeFileSync(instructions, "# agent instructions\n");
  const r = await runAdapterProbe({
    tree, world, adapter: ADAPTERS.claude_local, env, serverEnv, probe,
    config: { ...LIVE_CONFIG, command, ...(withInstructions ? { instructionsFilePath: instructions } : {}), ...config },
  });
  r.dump = (name) => readDump(world, name);
  return r;
}
const BASE_AND_SHELL = /^(PATH|HOME|LANG|LANGUAGE|TZ|TERM|LC_[A-Z_]+|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|http_proxy|https_proxy|all_proxy|NO_PROXY|no_proxy|PWD|OLDPWD|SHLVL|_)$/;
const sorted = (a) => [...a].sort();

for (const version of versions) {
  const V = (name) => `${version}: ${name}`;
  const opts = (extra = {}) => ({ skip: noVersion || noBwrap, timeout: 180_000, ...extra });

  test(V("live shape: the full box + scrub chain gives the child its token, telemetry flag, per-agent Claude dir and box home, and no server canary"), opts(), async (t) => {
    const tree = await after(version);
    if (tree.skip) return t.skip(tree.skip);
    const r = await run(tree);
    assert.equal(r.error, null, String(r.error?.stack));
    assert.notEqual(r.result.errorCode, "claude_cli_version_incompatible", `the version probe found the stub's version: ${r.result.errorMessage}`);
    const p = r.probe;
    const runtime = runtimeDirFor(r.world, "claude");
    assert.equal(p.home, path.join(runtime, "home"), "HOME is the box home");
    assert.equal(p.cfg, path.join(runtime, "home", ".claude"), "CLAUDE_CONFIG_DIR is the per-agent dir of 0016");
    assert.equal(p.tokensha, TOKEN_SHA, "CLAUDE_CODE_OAUTH_TOKEN reaches the child unchanged");
    assert.equal(p.telemetry, "1/1", "the stored telemetry flags reach the child");
    assert.equal(p.canary, "", "no server canary value");
    for (const name of ["HARDENING_CANARY_SECRET", "DATABASE_URL"]) assert.ok(!p.env.includes(name), name);
    assert.deepEqual(p.env.filter((n) => !BASE_AND_SHELL.test(n) && !n.startsWith("PAPERCLIP_")).sort(), sorted(["CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR", ...Object.keys(TELEMETRY), ...p.env.filter((n) => ["AGENT_HOME", "IS_SANDBOX"].includes(n))]),
      "the child env is BASE + the adapter's own env, nothing else");
    // the PAPERCLIP_ run variables, among them ones the adapter adds AFTER the box is built (workspace) and the run token
    assert.equal(p.runid, r.world.runId);
    assert.equal(p.agentid, r.world.agentId);
    assert.equal(p.companyid, r.world.companyId);
    assert.equal(p.apiurl, "http://localhost:3100");
    assert.equal(p.apikeysha, RUN_TOKEN_SHA);
    assert.equal(p.wscwd, r.world.workspace, "PAPERCLIP_WORKSPACE_CWD (set after the box is built) reaches the child");
    // the box
    assert.equal(p.read[path.join(r.world.realHome, ".claude", "canary")], false, "the real home is invisible");
    assert.equal(p.cfgwrite, "ok");
    assert.equal(p.settings, "yes", "the per-agent dir is seeded");
    assert.equal(r.persisted["/etc/hardening-probe"] ?? false, false);
    // the version probe (claude-fable-5-1 needs it) ran in the box, with the same scrubbed env
    const v = r.dump("probe-version.txt");
    assert.equal(v.HOME, path.join(runtime, "home"));
    assert.equal(v.CANARY, "");
    assert.equal(v.DB, "");
    assert.equal(v.TOKEN_SHA, TOKEN_SHA);
    assert.equal(v.CFG, path.join(runtime, "home", ".claude"));
    // the instructions bundle stays in the company's server-managed prompt cache, mounted read-only (the guard of 0017 allows exactly that)
    assert.ok(p.instr.startsWith(path.join(r.world.instanceRoot, "companies", r.world.companyId, "claude-prompt-cache") + path.sep), p.instr);
    assert.equal(p.instrread, "yes");
    assert.equal(p.instrwrite, "no", "the instructions are mounted read-only");
    assert.match(fs.readFileSync(p.instr, "utf8"), /agent instructions/);
  });

  test(V("fail-before: without 0026 the scrub starves the live agent (no token, no PAPERCLIP_ vars) and the version probe runs outside the box"), opts(), async (t) => {
    const tree = await before(version);
    if (tree.skip) return t.skip(tree.skip);
    const r = await run(tree);
    assert.equal(r.error, null, String(r.error?.stack));
    const p = r.probe;
    // 0025 loaded, 0026 not: the stock sandbox object has no envPassNames -> BASE only
    assert.notEqual(p.tokensha, TOKEN_SHA, "the OAuth token no longer reaches the child");
    assert.equal(p.runid, "", "neither do the PAPERCLIP_ run variables");
    // and the version probe is not in the box: the server canary and the server's HOME are there
    const v = r.dump("probe-version.txt");
    assert.equal(v.CANARY, "set", "the version probe saw the server environment");
    assert.equal(v.HOME, r.world.realHome);
  });

  test(V("an evil PAPERCLIP_API_URL in config.env is not trusted by the proxy; the adapter's own API URL is"), opts(), async (t) => {
    const tree = await after(version);
    if (tree.skip) return t.skip(tree.skip);
    const api = net.createServer((s) => s.end());
    await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
    const port = api.address().port;
    const other = net.createServer((s) => s.end());
    await new Promise((resolve) => other.listen(0, "127.0.0.1", resolve));
    try {
      const r = await run(tree, {
        env: { ...LIVE_ENV, PAPERCLIP_API_URL: "http://evil.example:8080", PAPERCLIP_RUNTIME_API_URL: "http://evil.example:8081" },
        serverEnv: { PAPERCLIP_API_URL: `http://127.0.0.1:${port}` },
        probe: { connect: ["evil.example:8080", `127.0.0.1:${port}`, `127.0.0.1:${other.address().port}`] },
      });
      assert.equal(r.error, null, String(r.error?.stack));
      const p = r.probe;
      assert.equal(p.apiurl, `http://127.0.0.1:${port}`, "the adapter's runtime value wins over config.env");
      assert.match(p.connect["evil.example:8080"], /^HTTP\/1\.1 403 /, "the evil URL is not trusted");
      assert.match(p.connect[`127.0.0.1:${other.address().port}`], /^HTTP\/1\.1 403 /, "another loopback port is denied");
      assert.doesNotMatch(p.connect[`127.0.0.1:${port}`], /403/, "the Paperclip API URL the adapter computed is trusted");
    } finally { api.close(); other.close(); }
  });

  test(V("the managed AI connection path still works: credential home mounted, box home per agent, canary absent"), opts(), async (t) => {
    const tree = await after(version);
    if (tree.skip) return t.skip(tree.skip);
    const managedHome = fs.mkdtempSync(path.join(os.tmpdir(), "paperclip-ai-test-")); // the server makes it under os.tmpdir()
    const provider = path.join(managedHome, "provider");
    fs.mkdirSync(provider, { mode: 0o700 });
    fs.writeFileSync(path.join(provider, ".credentials-managed"), "x");
    try {
      const r = await run(tree, {
        env: { HOME: managedHome, XDG_CONFIG_HOME: path.join(managedHome, "config"), CLAUDE_CONFIG_DIR: provider, ANTHROPIC_API_KEY: "" },
        config: { managedAiConnection: { id: "grant-1" } },
      });
      assert.equal(r.error, null, String(r.error?.stack));
      const p = r.probe;
      assert.equal(p.cfg, provider, "CLAUDE_CONFIG_DIR is the server-made credential home");
      assert.equal(p.managedcred, "yes", "and it is mounted in the box");
      assert.equal(p.cfgwrite, "ok");
      assert.equal(p.home, path.join(runtimeDirFor(r.world, "claude"), "home"), "HOME is the agent's box home, not the real one");
      assert.equal(p.canary, "");
      assert.equal(p.tokensha, crypto.createHash("sha256").update("").digest("hex"), "no ambient token is invented");
      assert.equal(p.read[path.join(r.world.realHome, ".claude", "canary")], false);
      assert.equal(fs.existsSync(path.join(runtimeDirFor(r.world, "claude"), "home", ".claude")), false, "0016 does not create a per-agent dir for a managed run");
    } finally { fs.rmSync(managedHome, { recursive: true, force: true }); }
  });

  test(V("`claude login` for a boxed agent runs in the box with the scrubbed env and the per-agent dir (fail-before: unboxed with the server env)"), opts(), async (t) => {
    const result = async (tree) => {
      const world = makeWorld(tree);
      const command = installStub(world, {});
      const mod = await importFromTree(tree, "adapter-claude-local/dist/server/index.js");
      const saved = { ...process.env };
      Object.assign(process.env, { HOME: world.realHome, PAPERCLIP_HOME: world.paperclipHome, PAPERCLIP_INSTANCE_ID: "test", ...CANARY_ENV });
      try {
        const agent = { id: world.agentId, companyId: world.companyId, name: "login", adapterType: "claude_local", adapterConfig: {} };
        await mod.runClaudeLogin({ runId: "claude-login-test", agent, config: { ...LIVE_CONFIG, command, cwd: world.workspace, env: LIVE_ENV } });
      } finally {
        for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
        Object.assign(process.env, saved);
      }
      return { world, dump: readDump(world, "probe-login.txt") };
    };
    const [pre, post] = [await before(version), await after(version)];
    if (pre.skip) return t.skip(pre.skip);
    const old = await result(pre);
    assert.equal(old.dump.CANARY, "set", "fail-before: the login saw the server environment");
    assert.equal(old.dump.HOME, old.world.realHome);
    const now = await result(post);
    const runtime = runtimeDirFor(now.world, "claude");
    assert.equal(now.dump.CANARY, "");
    assert.equal(now.dump.DB, "");
    assert.equal(now.dump.HOME, path.join(runtime, "home"));
    assert.equal(now.dump.CFG, path.join(runtime, "home", ".claude"));
    assert.equal(now.dump.TOKEN_SHA, TOKEN_SHA);
    assert.ok(fs.existsSync(path.join(runtime, "home", ".claude", "settings.json")), "the login's config dir is the per-agent dir");
  });

  // ---- admission: the full chain
  test(V("0005f admits the boxed claude agent with 0016+0017+0025+0026 loaded and refuses it on the chain without 0026 (fail-before)"), { skip: noVersion, timeout: 180_000 }, async (t) => {
    const patchFiles = discoverPatchFiles(SOURCE_PATCHES_DIR);
    const hbPristine = pristineOrNull(stockTreePath(version), HB);
    if (!hbPristine) return t.skip(noPristineSkip(stockTreePath(version), [HB], version));
    const CHAIN = [["0003", "// LOCAL-PATCH 0003"], ["0003b", "// LOCAL-PATCH 0003b"], ["0005b", "// LOCAL-PATCH 0005b"], ["0005f", "// LOCAL-PATCH 0005f"], ["0006a", "// LOCAL-PATCH 0006"]];
    const built = buildFile({ rel: HB, pristine: hbPristine, steps: CHAIN.map(([id, marker]) => ({ id, marker, candidates: patchFiles.get(id) })), tmpDir: scratch });
    assert.equal(built.ok, true, built.reason);
    const content = built.content.toString("utf8");
    const lines = content.split("\n");
    const from = lines.findIndex((l) => l.startsWith("// LOCAL-PATCH 0005f: table-driven"));
    const to = lines.findIndex((l, i) => i > from && l.startsWith("function formatMissingBindingForOperator"));
    assert.ok(from > 0 && to > from);
    const instanceRoot = fs.mkdtempSync(path.join(scratch, "hb-root-"));
    const codeFile = path.join(scratch, `admission-${version}.js`);
    fs.writeFileSync(codeFile, `${extractBlock(content, "0003")}\n${lines.slice(from, to).join("\n")}`);
    // The live agents' stored shape, run through the 0003b enforcement first (what the heartbeat hands the adapter)
    const stored = { filesystemScope: "workspace", networkScope: "allowlist", networkAllowlist: ["api.anthropic.com"], engine: "cli", filesystemSandboxCommand: "/usr/bin/bwrap", env: { CLAUDE_CODE_OAUTH_TOKEN: { type: "secret_ref", secretId: "s1", version: "latest" }, ...TELEMETRY } };
    const agent = { id: "agent-1", adapterType: "claude_local", adapterConfig: stored };
    BLOCKS.admissionFull = { exports: ["refuseUnsandboxedLocalAgent", "enforceStoredSandboxConfig"] };
    const hb = evalBlock(`${fs.readFileSync(codeFile, "utf8")}`, "admissionFull", { instanceRoot });
    const enforced = await hb.enforceStoredSandboxConfig({
      agent, runId: "run-1", workspaceDirs: [], managedAi: false,
      runtimeConfig: { ...stored, env: { CLAUDE_CODE_OAUTH_TOKEN: FAKE_TOKEN, ...TELEMETRY, PAPERCLIP_API_URL: "http://evil.example:8080", PAPERCLIP_RUNTIME_TOOLS_MCP_URL: "http://evil.example:8081", HOME: "/evil/home", XDG_CONFIG_HOME: "/evil/x" } },
    });
    assert.deepEqual(Object.keys(enforced.env).sort(), sorted(["CLAUDE_CODE_OAUTH_TOKEN", ...Object.keys(TELEMETRY)]), "0003b drops the run-level API URL, tools URL and home redirects before the adapter sees them");
    assert.equal(enforced.env.CLAUDE_CODE_OAUTH_TOKEN, FAKE_TOKEN);

    // A child process per tree: the registry of 0017 is defined once per process and the adapter registers itself when it loads.
    const child = path.join(scratch, "admission-child.mjs");
    fs.writeFileSync(child, `
      import fs from "node:fs";
      import { pathToFileURL } from "node:url";
      import { BLOCKS, evalBlock } from ${JSON.stringify(pathToFileURL(path.join(import.meta.dirname, "..", "src", "patch-block.js")).href)};
      const [nm, codeFile, agentJson, instanceRoot] = process.argv.slice(2);
      await import(pathToFileURL(nm + "/@paperclipai/adapter-claude-local/dist/server/index.js").href);
      BLOCKS.admissionFull = { exports: ["refuseUnsandboxedLocalAgent"] };
      const b = evalBlock(fs.readFileSync(codeFile, "utf8"), "admissionFull", { instanceRoot });
      let message = null;
      try { b.refuseUnsandboxedLocalAgent({ agent: JSON.parse(agentJson), runId: "run-1" }); } catch (e) { message = e.message; }
      console.log("RESULT " + JSON.stringify({ message, registered: globalThis[Symbol.for("paperclip.hardening.boxedAdapters")]?.has("claude_local") === true, scrub: globalThis[Symbol.for("paperclip.hardening.envScrub")] === true }));
    `);
    const admit = async (tree) => {
      const r = spawnSync(process.execPath, [child, tree.nm, codeFile, JSON.stringify(agent), instanceRoot], { encoding: "utf8", timeout: 120_000 });
      assert.equal(r.status, 0, r.stdout + r.stderr);
      return JSON.parse(/^RESULT (.*)$/m.exec(r.stdout)[1]);
    };
    const [pre, post] = [await before(version), await after(version)];
    if (pre.skip) return t.skip(pre.skip);
    const refused = await admit(pre);
    assert.equal(refused.scrub, true, "0025 is loaded");
    assert.equal(refused.registered, false, "fail-before: claude_local does not register without 0026");
    assert.match(refused.message ?? "", /claude_local adapter is not registered as boxed/);
    const admitted = await admit(post);
    assert.deepEqual(admitted, { message: null, registered: true, scrub: true }, "the full chain admits the live-shape agent");
  });
}

test("0026 applies on both Paperclip versions right on top of 0016, and not without it; one file only", { skip: noVersion }, async (t) => {
  const patchFiles = discoverPatchFiles(SOURCE_PATCHES_DIR);
  assert.equal(patchFiles.get("0026").length, 1, "one patch file serves every version");
  assert.equal(readPatchTarget(patchFiles.get("0026")[0].file), EXECUTE);
  assert.equal(readPatchTarget(patchFiles.get("0016")[0].file), EXECUTE);
  for (const version of versions) {
    const pristine = pristineOrNull(stockTreePath(version), EXECUTE);
    if (!pristine) { t.diagnostic(noPristineSkip(stockTreePath(version), [EXECUTE], version)); continue; }
    const step = (id) => ({ id, marker: `// LOCAL-PATCH ${id}`, candidates: patchFiles.get(id) });
    const both = buildFile({ rel: EXECUTE, pristine, steps: [step("0016"), step("0026")], tmpDir: scratch });
    assert.equal(both.ok, true, `${version}: ${both.reason}`);
    const only = buildFile({ rel: EXECUTE, pristine, steps: [step("0026")], tmpDir: scratch });
    assert.equal(only.ok, false, `${version}: 0026 is stacked on 0016`);
    const text = both.content.toString("utf8");
    assert.ok(text.includes('registerBoxedAdapter("claude_local")'));
    assert.ok(!/networkTrustedUrls:\s*\[\s*env\.PAPERCLIP_API_URL/.test(text), "the proxy URL no longer comes from env after the config.env merge");
    // GNU patch -F0 dry run on the 0016 output, the way apply.sh and the engine do it
    const dir = fs.mkdtempSync(path.join(scratch, "dry-"));
    fs.mkdirSync(path.dirname(path.join(dir, EXECUTE)), { recursive: true });
    const with0016 = buildFile({ rel: EXECUTE, pristine, steps: [step("0016")], tmpDir: scratch });
    fs.writeFileSync(path.join(dir, EXECUTE), with0016.content);
    const r = spawnSync("patch", ["-p1", "-N", "-F0", "--batch", "--dry-run", "-s", "-d", dir, "-i", PATCH], { encoding: "utf8" });
    assert.equal(r.status, 0, `${version}: ${r.stdout}${r.stderr}`);
  }
});

test("0016 stays byte-stable: the file is the committed one (0026 stacks on it, never edits it)", { skip: noVersion }, () => {
  const file = path.join(SOURCE_PATCHES_DIR, "0016-per-agent-claude-config.patch");
  const r = spawnSync("git", ["diff", "--quiet", "HEAD", "--", file], { cwd: SOURCE_PATCHES_DIR, encoding: "utf8" });
  if (r.error || r.status === 128) return; // not a git checkout (a packaged copy)
  assert.equal(r.status, 0, "0016-per-agent-claude-config.patch differs from HEAD");
  assert.ok(!fs.readFileSync(file, "utf8").includes("LOCAL-PATCH 0026"));
});
