// Patch 0005f (host/patches/0005f-table-driven-admission.patch; the plan's task T6, "0005b admission"; the id has the form NNNNx the engine reads) stacks on 0005b in heartbeat.js
// and replaces its claude/hermes-only rule by a table-driven admission. A local agent runs only when
//   scoped type   filesystemScope "workspace" AND a networkScope AND (engineCli types) stored engine "cli" AND the adapter type is
//                 registered as boxed in this process AND the env scrub of patch 0025 is loaded
//   hermes_local  command AND hermesCommand are the wrapper (the adapter runs hermesCommand || command)
//   remote types  an exception for this agent id + type in the settings file, re-read with the trust checks at each run, one
//                 log line per use (cursor_cloud, openclaw_gateway, hermes_gateway, http, process)
//   anything else always refused.
// The tests build heartbeat.js from the ORIGINAL bytes (helpers/pristine.mjs; PAPERCLIP_STOCK_TREE_<vkey>) of the installed Paperclip versions with the engine's own buildFile
// (GNU patch -F0), once with the chain as v0.1.x installs run it (0003, 0003b, 0005b, 0006a) and once with 0005f, and evaluate
// the code. The upgrade test takes the v0.1.1 release's patch files from git. Skipped when no installed Paperclip with .orig
// backups (or git history for the upgrade test) is available.
//   HARDENING_TEST_SCRATCH  scratch parent dir (default: the OS temp dir)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { BLOCKS, extractBlock, evalBlock, addedText } from "./helpers/patch-block.mjs";
import { v011Package, importV011Engine, V011_DEFAULTS } from "./helpers/v011.mjs";
import { noPristineSkip, pristineOrNull, stockTreePath } from "./helpers/pristine.mjs";
import { writeHardeningConfig } from "../src/settings.js";
import { BOX_PROFILES, SCOPED_TYPES, EXCEPTIONABLE_TYPES } from "../src/profiles.js";
import { SOURCE_PATCHES_DIR, createEngine } from "../src/engine/index.js";
import { PATCHES, PROTECTIONS, comparePatchIds } from "../src/engine/registry.js";
import { discoverPatchFiles, readPatchTarget, buildFile } from "../src/engine/patches.js";

const HB = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
const WRAPPER = "/usr/local/bin/hermes-sandbox";
const BOXED_KEY = Symbol.for("paperclip.hardening.boxedAdapters");
const SCRUB_KEY = Symbol.for("paperclip.hardening.envScrub");
const stockRoot = (version) => stockTreePath(version.split(".")[1]); // PAPERCLIP_STOCK_TREE_<vkey>, else the installed version
const VERSIONS = ["2026.1005.0", "2026.1012.0"].filter((v) => pristineOrNull(stockRoot(v), HB));
const skip = VERSIONS.length ? false : noPristineSkip(stockRoot("2026.1012.0"), [HB], "1012");
const CLI_TYPES = ["claude_local", "codex_local", "gemini_local", "kimi_local"];
const OTHER_SCOPED = ["opencode_local", "cursor", "pi_local", "grok_local"];
const REMOTE = ["cursor_cloud", "openclaw_gateway", "hermes_gateway", "http", "process"];
const ALWAYS_REFUSED = ["paperclip_runner", "acpx_local", "external_plugin_adapter", "constructor", "__proto__", "toString", "", undefined, null, 7];

const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0005f-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
let n = 0;
const freshRoot = () => { const d = path.join(scratch, `root-${++n}`); fs.mkdirSync(d, { mode: 0o700, recursive: true }); return d; };

const CHAIN = [["0003", "// LOCAL-PATCH 0003"], ["0003b", "// LOCAL-PATCH 0003b"], ["0005b", "// LOCAL-PATCH 0005b"], ["0005f", "// LOCAL-PATCH 0005f"], ["0006a", "// LOCAL-PATCH 0006"]];
const pristine = (version) => pristineOrNull(stockRoot(version), HB);
/** heartbeat.js as the engine builds it from the pristine file; `with0005f:false` is the chain v0.1.x installs run plus 0003b. */
function build(version, { with0005f, order = CHAIN.map(([id]) => id) }) {
  const patchFiles = discoverPatchFiles(SOURCE_PATCHES_DIR);
  const steps = order.filter((id) => with0005f || id !== "0005f").map((id) => ({ id, marker: CHAIN.find(([x]) => x === id)[1], candidates: patchFiles.get(id) }));
  const r = buildFile({ rel: HB, pristine: pristine(version), steps, tmpDir: scratch });
  assert.equal(r.ok, true, r.reason);
  return r;
}
const built = new Map();
const chainFile = (version, with0005f) => {
  const key = `${version}/${with0005f}`;
  if (!built.has(key)) built.set(key, build(version, { with0005f }).content.toString("utf8"));
  return built.get(key);
};

// The admission code needs the 0003 block (settings reader, wrapper path) and its own: evaluate them together.
BLOCKS.admission = { exports: ["refuseUnsandboxedLocalAgent", "SANDBOX_ADMISSION_0005F", "SANDBOX_EXCEPTIONABLE_TYPES_0005F"] };
BLOCKS.admissionOld = { exports: ["refuseUnsandboxedLocalAgent"] };
function admissionCode(content) {
  const lines = content.split("\n");
  const from = lines.findIndex((l) => l.startsWith("// LOCAL-PATCH 0005f: table-driven") || l.startsWith("// LOCAL-PATCH 0005b: fail closed"));
  const to = lines.findIndex((l, i) => i > from && l.startsWith("function formatMissingBindingForOperator"));
  assert.ok(from > 0 && to > from, "admission code found");
  return `${extractBlock(content, "0003")}\n${lines.slice(from, to).join("\n")}`;
}
/** The patched admission code; instanceRoot holds the settings file (hardening/config.json). */
function admission(version, with0005f, { instanceRoot = freshRoot(), ...opts } = {}) {
  const content = chainFile(version, with0005f);
  const b = evalBlock(admissionCode(content), with0005f ? "admission" : "admissionOld", { instanceRoot, ...opts });
  b.instanceRoot = instanceRoot;
  b.file = path.join(instanceRoot, "hardening", "config.json");
  return b;
}

/** Run the admission for `agent` with the process-wide registered set and scrub flag as given; returns {error, warnings}. */
function admit(b, agent, { registered = [agent.adapterType], registry = null, scrub = true, runId = "run-1" } = {}) {
  const saved = [Object.getOwnPropertyDescriptor(globalThis, BOXED_KEY), Object.getOwnPropertyDescriptor(globalThis, SCRUB_KEY)];
  if (registry !== null) globalThis[BOXED_KEY] = registry; // any object: the admission must only trust has() === true
  else if (registered === null) delete globalThis[BOXED_KEY]; else globalThis[BOXED_KEY] = new Set(registered);
  if (scrub === null) delete globalThis[SCRUB_KEY]; else globalThis[SCRUB_KEY] = scrub;
  b.warnings.length = 0;
  let error = null;
  try {
    b.refuseUnsandboxedLocalAgent({ agent, runId });
  } catch (e) {
    error = e;
  } finally {
    for (const [key, d] of [[BOXED_KEY, saved[0]], [SCRUB_KEY, saved[1]]]) {
      if (d) Object.defineProperty(globalThis, key, d); else delete globalThis[key];
    }
  }
  return { error, message: error?.message ?? null, warnings: [...b.warnings] };
}
const BOX = { filesystemScope: "workspace", networkScope: "allowlist" };
const scoped = (type, extra = {}) => ({ id: "agent-1", adapterType: type, adapterConfig: { ...BOX, ...(CLI_TYPES.includes(type) ? { engine: "cli" } : {}), ...extra } });
const hermes = (extra = {}) => ({ id: "agent-h", adapterType: "hermes_local", adapterConfig: { command: WRAPPER, ...extra } });
const remote = (type, id = "agent-r") => ({ id, adapterType: type, adapterConfig: {} });
const exception = (agentId, type, extra = {}) => ({ agentId, type, reason: "runs on a vendor host", addedBy: "board", addedAt: "2026-10-01T10:00:00.000Z", ...extra });
const writeExceptions = (b, remoteExceptions, extra = {}) => writeHardeningConfig({ remoteExceptions, ...extra }, { file: b.file, instanceRoot: b.instanceRoot });
const refusedAction = (r) => r.warnings.filter((w) => w.obj.action === "refuse_unsandboxed");
const used = (r) => r.warnings.filter((w) => w.obj.event === "sandbox_remote_exception_used");

for (const version of VERSIONS) {
  test(`${version}: 0005f applies right after 0005b on the chain (and also after 0006a), adds its marker and changes no other file`, { skip }, () => {
    const patchFiles = discoverPatchFiles(SOURCE_PATCHES_DIR);
    assert.equal(patchFiles.get("0005f").length, 1, "one 0005f patch file serves every version");
    assert.equal(readPatchTarget(patchFiles.get("0005f")[0].file), HB);
    assert.ok(path.basename(patchFiles.get("0005b")[0].file) === "0005b-fail-closed-spawn.patch", "the v0.1 patch file keeps its name");
    const before = build(version, { with0005f: false });
    const after = build(version, { with0005f: true });
    const ids = after.used.map((u) => u.id);
    assert.deepEqual(ids, ["0003", "0003b", "0005b", "0005f", "0006a"]);
    assert.ok(!before.content.includes("// LOCAL-PATCH 0005f") && after.content.includes("// LOCAL-PATCH 0005f"));
    assert.ok(after.content.includes("// LOCAL-PATCH 0005b"), "the call site of 0005b stays");
    // Same patches in the other order (0006a first) give the same file.
    const reordered = build(version, { with0005f: true, order: ["0003", "0003b", "0005b", "0006a", "0005f"] });
    assert.ok(reordered.content.equals(after.content));
  });

  test(`${version}: the registry is read through has() === true: the frozen {has, add} object of 0017 works, anything else refuses`, { skip }, () => {
    const b = admission(version, true);
    const agent = scoped("codex_local");
    const frozen = Object.freeze({ has: (type) => type === "codex_local", add: () => {} });
    assert.equal(admit(b, agent, { registry: frozen }).error, null);
    assert.match(admit(b, scoped("pi_local"), { registry: frozen }).message ?? "", /not registered as boxed/);
    for (const registry of [{}, [], ["codex_local"], { has: () => "yes" }, { has: () => 1 }, { has: "codex_local" }, "codex_local", 7, true]) {
      assert.match(admit(b, agent, { registry }).message ?? "", /not registered as boxed/, JSON.stringify(registry));
    }
    assert.equal(admit(b, agent, { registered: [agent.adapterType] }).error, null, "a plain Set still works (the tests and older helpers)");
    assert.match(admit(b, agent, { registered: null }).message ?? "", /not registered as boxed/);
  });

  // ---------- fail-before: the chain without 0005f
  test(`${version}: fail-before - the chain without 0005f refuses every type but claude/hermes, admits a hermesCommand bypass and has no exceptions`, { skip }, () => {
    const old = admission(version, false);
    for (const type of [...CLI_TYPES.slice(1), ...OTHER_SCOPED]) {
      const r = admit(old, scoped(type));
      assert.match(r.message ?? "", /has no sandbox implementation/, `${type} boxed agent is refused by v0.1.x`);
    }
    assert.equal(admit(old, hermes({ hermesCommand: "/tmp/evil" })).error, null, "hermesCommand bypass: admitted on v0.1.x");
    writeExceptions(old, [exception("agent-r", "http")]);
    assert.match(admit(old, remote("http")).message ?? "", /has no sandbox implementation/);
    // And claude_local needs no registration, no network scope and no engine there.
    assert.equal(admit(old, { id: "c", adapterType: "claude_local", adapterConfig: { filesystemScope: "workspace" } }, { registered: null, scrub: null }).error, null);
  });

  // ---------- scoped types
  for (const type of [...CLI_TYPES, ...OTHER_SCOPED]) {
    test(`${version}: ${type} boxed with everything in place is admitted`, { skip }, () => {
      const b = admission(version, true);
      for (const networkScope of ["allowlist", "deny"]) {
        const r = admit(b, scoped(type, { networkScope }));
        assert.equal(r.error, null);
        assert.deepEqual(r.warnings, [], "nothing is logged for an admitted boxed agent");
      }
    });

    test(`${version}: ${type} is refused naming the missing piece: filesystemScope, networkScope, registration, scrub`, { skip }, () => {
      const b = admission(version, true);
      const cases = [
        [{ filesystemScope: undefined }, /no filesystemScope "workspace"/],
        [{ filesystemScope: "off" }, /no filesystemScope "workspace"/],
        [{ filesystemScope: "" }, /no filesystemScope "workspace"/],
        [{ networkScope: undefined }, /no networkScope \("deny" or "allowlist"\)/],
        [{ networkScope: "open" }, /no networkScope/],
        [{ filesystemScope: undefined, networkScope: undefined }, /filesystemScope.*networkScope/s],
      ];
      for (const [extra, pattern] of cases) {
        const agent = scoped(type, extra);
        for (const k of Object.keys(agent.adapterConfig)) if (agent.adapterConfig[k] === undefined) delete agent.adapterConfig[k];
        const r = admit(b, agent);
        assert.match(r.message ?? "", pattern, JSON.stringify(extra));
        assert.match(r.message, /^Sandbox policy: run refused, /);
        assert.equal(refusedAction(r).length, 1, "one refusal log line");
        assert.deepEqual([r.warnings[0].obj.agentId, r.warnings[0].obj.runId, r.warnings[0].obj.adapterType], ["agent-1", "run-1", type]);
      }
      // The adapter patch for the type did not register it: this server cannot box it.
      for (const registered of [null, [], ["some_other_local"], CLI_TYPES.concat(OTHER_SCOPED).filter((t) => t !== type)]) {
        const r = admit(b, scoped(type), { registered });
        assert.match(r.message ?? "", new RegExp(`the ${type} adapter is not registered as boxed`), JSON.stringify(registered));
      }
      // The env scrub (0025) is not loaded.
      for (const scrub of [null, false, "yes", 1]) {
        const r = admit(b, scoped(type), { scrub });
        assert.match(r.message ?? "", /environment scrub \(patch 0025\) is not loaded/, String(scrub));
      }
      // Several missing pieces are all named.
      const all = admit(b, { id: "a", adapterType: type, adapterConfig: {} }, { registered: null, scrub: null });
      assert.match(all.message, /filesystemScope.*networkScope.*not registered.*scrub/s);
    });
  }

  test(`${version}: engine "cli" is required exactly for the ACP-capable types (claude, codex, gemini, kimi)`, { skip }, () => {
    const b = admission(version, true);
    for (const type of CLI_TYPES) {
      for (const engine of [undefined, "acp", "auto", "ACP", "CLI", "", null, 7]) {
        const agent = scoped(type, { engine });
        if (engine === undefined) delete agent.adapterConfig.engine;
        const r = admit(b, agent);
        assert.match(r.message ?? "", /has no engine "cli" in its stored adapterConfig/, `${type} engine ${JSON.stringify(engine)}`);
      }
      assert.equal(admit(b, scoped(type, { engine: "cli" })).error, null);
    }
    // The types without an ACP lane do not need the key and are not bothered by one.
    for (const type of OTHER_SCOPED) for (const engine of [undefined, "acp", "cli"]) {
      const agent = scoped(type, { engine });
      if (engine === undefined) delete agent.adapterConfig.engine;
      assert.equal(admit(b, agent).error, null, `${type} ${engine}`);
    }
  });

  test(`${version}: stored config comes from adapterConfig only; a non-object adapterConfig is unboxed`, { skip }, () => {
    const b = admission(version, true);
    for (const adapterConfig of [null, undefined, "workspace", [BOX], 7]) {
      const r = admit(b, { id: "a", adapterType: "codex_local", adapterConfig });
      assert.match(r.message ?? "", /no filesystemScope/, JSON.stringify(adapterConfig));
    }
  });

  // ---------- hermes
  test(`${version}: hermes_local needs the wrapper in command AND hermesCommand (the adapter runs hermesCommand first)`, { skip }, () => {
    const b = admission(version, true);
    assert.equal(admit(b, hermes(), { registered: null, scrub: null }).error, null, "the wrapper needs no registration and no scrub flag");
    for (const hermesCommand of [undefined, null, "", WRAPPER]) assert.equal(admit(b, hermes({ hermesCommand })).error, null, JSON.stringify(hermesCommand));
    for (const hermesCommand of ["/tmp/evil", "hermes", "/bin/sh", ` ${WRAPPER}`, `${WRAPPER}/../x`, 7, true, {}, []]) {
      const r = admit(b, hermes({ hermesCommand }));
      assert.match(r.message ?? "", /hermesCommand is not \/usr\/local\/bin\/hermes-sandbox \(the adapter runs hermesCommand before command\)/, JSON.stringify(hermesCommand));
      assert.equal(refusedAction(r).length, 1);
    }
    for (const command of [undefined, "hermes", "/bin/sh", `${WRAPPER} `]) {
      const agent = hermes();
      if (command === undefined) delete agent.adapterConfig.command; else agent.adapterConfig.command = command;
      assert.match(admit(b, agent).message ?? "", /hermes_local agent command is not \/usr\/local\/bin\/hermes-sandbox/, String(command));
    }
    // Both wrong: both named.
    assert.match(admit(b, hermes({ command: "hermes", hermesCommand: "/tmp/evil" })).message, /command is not.*hermesCommand is not/s);
    // Another adapter type does not become boxed by carrying the wrapper path.
    assert.match(admit(b, { id: "a", adapterType: "codex_local", adapterConfig: { command: WRAPPER, engine: "cli" } }).message, /no filesystemScope/);
  });

  test(`${version}: the wrapper path of a site comes from the settings file`, { skip }, () => {
    const root = freshRoot();
    const b = admission(version, true, { instanceRoot: root });
    writeHardeningConfig({ hermesWrapperPath: "/opt/site/hermes-box" }, { file: b.file, instanceRoot: root });
    const custom = admission(version, true, { instanceRoot: root }); // read at load, like patch 0003b
    assert.equal(admit(custom, { id: "h", adapterType: "hermes_local", adapterConfig: { command: "/opt/site/hermes-box", hermesCommand: "/opt/site/hermes-box" } }).error, null);
    assert.match(admit(custom, hermes()).message ?? "", /command is not \/opt\/site\/hermes-box/);
    assert.match(admit(custom, { id: "h", adapterType: "hermes_local", adapterConfig: { command: "/opt/site/hermes-box", hermesCommand: WRAPPER } }).message ?? "", /hermesCommand is not \/opt\/site\/hermes-box/);
  });

  // ---------- remote / exceptionable types
  for (const type of REMOTE) {
    test(`${version}: ${type} is refused without an exception, admitted with one for this agent id and type, one log line per use`, { skip }, () => {
      const b = admission(version, true);
      const none = admit(b, remote(type));
      assert.match(none.message ?? "", new RegExp(`${type} agents run outside the box and this agent has no remote exception in the hardening settings file`));
      assert.match(none.message, /An administrator can exempt this agent under remote exceptions/);
      assert.equal(refusedAction(none).length, 1);
      assert.deepEqual(used(none), []);

      writeExceptions(b, [exception("agent-r", type)]);
      for (const runId of ["run-1", "run-2"]) {
        const r = admit(b, remote(type), { runId, registered: null, scrub: null });
        assert.equal(r.error, null);
        assert.deepEqual(r.warnings.map((w) => w.obj), [{ event: "sandbox_remote_exception_used", agentId: "agent-r", runId, type }], "exactly one structured line per use");
      }
      // Not for another agent, not for another type.
      assert.match(admit(b, remote(type, "agent-other")).message ?? "", /no remote exception/);
      const otherType = REMOTE.find((t) => t !== type);
      assert.match(admit(b, remote(otherType)).message ?? "", /no remote exception/);
      assert.equal(admit(b, { ...remote(type), adapterConfig: BOX }).error, null, "an exception admits the agent whatever its config says");
    });
  }

  test(`${version}: exceptions are read again at every run (edit applies without restart); removing one refuses again`, { skip }, () => {
    const b = admission(version, true); // one evaluated block = one server process
    assert.match(admit(b, remote("http")).message ?? "", /no remote exception/, "no file");
    writeExceptions(b, [exception("agent-r", "http")]);
    assert.equal(admit(b, remote("http")).error, null, "added");
    writeExceptions(b, [exception("agent-r", "http"), exception("agent-s", "process")]);
    assert.equal(admit(b, remote("process", "agent-s")).error, null, "second entry");
    writeExceptions(b, [exception("agent-s", "process")]);
    assert.match(admit(b, remote("http")).message ?? "", /no remote exception/, "removed");
    fs.rmSync(b.file);
    assert.match(admit(b, remote("process", "agent-s")).message ?? "", /no remote exception/, "file deleted");
  });

  test(`${version}: types outside the table are refused even when an exception names them`, { skip }, () => {
    const b = admission(version, true);
    // Hand-written entries the plugin would not write: the server still ignores them.
    const text = JSON.stringify({ schema: 1, remoteExceptions: ALWAYS_REFUSED.filter((t) => typeof t === "string").map((type) => exception("agent-r", type)) });
    fs.mkdirSync(path.dirname(b.file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(b.file, text, { mode: 0o600 });
    for (const type of ALWAYS_REFUSED) {
      const r = admit(b, { id: "agent-r", adapterType: type, adapterConfig: { ...BOX, engine: "cli" } }, { registered: [type].filter(Boolean) });
      assert.match(r.message ?? "", /has no sandbox implementation and cannot be excepted/, String(type));
      assert.deepEqual(used(r), []);
    }
    const inherited = admit(b, { id: "agent-r", adapterType: "hasOwnProperty", adapterConfig: BOX });
    assert.match(inherited.message ?? "", /cannot be excepted/);
  });

  test(`${version}: malformed exception entries admit nothing`, { skip }, () => {
    const b = admission(version, true);
    const cases = [
      ["agent-r"], [["agent-r", "http"]], [null], [7], [{}], [{ agentId: "agent-r" }], [{ type: "http" }], [{ agentId: 7, type: "http" }],
      [{ agentId: "agent-r", type: ["http"] }], [{ agentId: ["agent-r"], type: "http" }], [{ agentId: "AGENT-R", type: "http" }],
      { agentId: "agent-r", type: "http" }, "agent-r", 1, null, true,
    ];
    for (const remoteExceptions of cases) {
      fs.mkdirSync(path.dirname(b.file), { recursive: true, mode: 0o700 });
      fs.writeFileSync(b.file, JSON.stringify({ schema: 1, remoteExceptions }), { mode: 0o600 });
      assert.match(admit(b, remote("http")).message ?? "", /no remote exception/, JSON.stringify(remoteExceptions));
    }
    fs.writeFileSync(b.file, "{ not json", { mode: 0o600 });
    assert.match(admit(b, remote("http")).message ?? "", /no remote exception/, "unparsable file");
    fs.writeFileSync(b.file, "[]", { mode: 0o600 });
    assert.match(admit(b, remote("http")).message ?? "", /no remote exception/, "not an object");
  });

  test(`${version}: an exception file that fails the trust checks yields no exceptions (0644, symlink, other owner, writable dir, inside a workspace root)`, { skip }, () => {
    const body = JSON.stringify({ schema: 1, remoteExceptions: [exception("agent-r", "http")] });
    const refused = (b, why) => {
      const r = admit(b, remote("http"));
      assert.match(r.message ?? "", /no remote exception/, why);
      assert.deepEqual(used(r), [], why);
      assert.ok(r.warnings.some((w) => w.obj.action === "ignore_hardening_config"), `${why}: the ignored file is logged`);
    };
    {
      const b = admission(version, true);
      fs.mkdirSync(path.dirname(b.file), { mode: 0o700 });
      fs.writeFileSync(b.file, body, { mode: 0o644 });
      refused(b, "mode 0644");
      fs.chmodSync(b.file, 0o666); refused(b, "mode 0666");
      fs.chmodSync(b.file, 0o640); refused(b, "mode 0640");
      fs.chmodSync(b.file, 0o600);
      assert.equal(admit(b, remote("http")).error, null, "0600 is trusted, same file");
      fs.chmodSync(b.file, 0o644);
      refused(b, "0644 again: the change is seen at once");
    }
    {
      const b = admission(version, true);
      fs.mkdirSync(path.dirname(b.file), { mode: 0o700 });
      const real = path.join(b.instanceRoot, "real-config.json");
      fs.writeFileSync(real, body, { mode: 0o600 });
      fs.symlinkSync(real, b.file);
      refused(b, "symbolic link to a 0600 file");
    }
    {
      const b = admission(version, true);
      fs.mkdirSync(path.dirname(b.file), { mode: 0o700 });
      fs.writeFileSync(b.file, body, { mode: 0o600 });
      fs.chmodSync(path.dirname(b.file), 0o770);
      refused(b, "directory writable by group");
      fs.chmodSync(path.dirname(b.file), 0o700);
      assert.equal(admit(b, remote("http")).error, null);
    }
    {
      // The server runs as another user than the file's owner.
      const root = freshRoot();
      const b = admission(version, true, { instanceRoot: root });
      fs.mkdirSync(path.dirname(b.file), { mode: 0o700 });
      fs.writeFileSync(b.file, body, { mode: 0o600 });
      assert.equal(admit(b, remote("http")).error, null);
      const other = admission(version, true, { instanceRoot: root, uid: process.getuid() + 1 });
      refused(other, "owned by another user than the service user");
      const noUid = admission(version, true, { instanceRoot: root, uid: null });
      refused(noUid, "ownership cannot be checked");
    }
    {
      // A settings file an agent run could write: PAPERCLIP_HARDENING_CONFIG pointing into the instance's workspaces.
      const root = freshRoot();
      const inside = path.join(root, "workspaces", "w", "config.json");
      fs.mkdirSync(path.dirname(inside), { recursive: true, mode: 0o700 });
      fs.writeFileSync(inside, body, { mode: 0o600 });
      refused(admission(version, true, { instanceRoot: root, env: { PAPERCLIP_HARDENING_CONFIG: inside } }), "inside <instance>/workspaces");
      // The same file outside the workspace dirs is trusted.
      const outside = path.join(root, "elsewhere", "config.json");
      fs.mkdirSync(path.dirname(outside), { mode: 0o700 });
      fs.writeFileSync(outside, body, { mode: 0o600 });
      assert.equal(admit(admission(version, true, { instanceRoot: root, env: { PAPERCLIP_HARDENING_CONFIG: outside } }), remote("http")).error, null);
      // Inside a workspace root the settings file itself names.
      const roots = path.join(root, "elsewhere2");
      fs.mkdirSync(roots, { mode: 0o700 });
      const named = path.join(roots, "config.json");
      fs.writeFileSync(named, JSON.stringify({ schema: 1, workspaceRoots: [roots], remoteExceptions: [exception("agent-r", "http")] }), { mode: 0o600 });
      refused(admission(version, true, { instanceRoot: root, env: { PAPERCLIP_HARDENING_CONFIG: named } }), "inside a workspace root named by the file");
    }
  });

  test(`${version}: a remote exception does not weaken a scoped type, and a scoped type's boxed config does not need one`, { skip }, () => {
    const b = admission(version, true);
    writeExceptions(b, [exception("agent-1", "http")]);
    assert.match(admit(b, { id: "agent-1", adapterType: "codex_local", adapterConfig: {} }).message ?? "", /no filesystemScope/, "an exception for http does not exempt a codex agent");
    assert.equal(admit(b, scoped("codex_local")).error, null);
    assert.deepEqual(used(admit(b, scoped("codex_local"))), []);
  });
}

// ---------- the table equals the plugin's profiles and the helper patch
test("the admission table of 0005f equals BOX_PROFILES and ENGINE_CLI_TYPES of patch 0017", { skip }, () => {
  const version = VERSIONS[VERSIONS.length - 1];
  const b = admission(version, true);
  assert.deepEqual(Object.keys(b.SANDBOX_ADMISSION_0005F).sort(), [...SCOPED_TYPES].sort());
  for (const type of SCOPED_TYPES) assert.equal(b.SANDBOX_ADMISSION_0005F[type].engineCli, BOX_PROFILES[type].engineCli, type);
  assert.deepEqual([...b.SANDBOX_EXCEPTIONABLE_TYPES_0005F].sort(), [...EXCEPTIONABLE_TYPES].sort());
  assert.deepEqual([...SCOPED_TYPES].sort(), [...CLI_TYPES, ...OTHER_SCOPED].sort());
  const helper = addedText(fs.readFileSync(path.join(SOURCE_PATCHES_DIR, "0017-boxed-sandbox-helper.patch"), "utf8"));
  const engineCli = JSON.parse(/ENGINE_CLI_TYPES = Object\.freeze\((\[[^\]]*\])\)/.exec(helper)[1]);
  assert.deepEqual([...engineCli].sort(), CLI_TYPES.sort());
  assert.deepEqual(SCOPED_TYPES.filter((t) => b.SANDBOX_ADMISSION_0005F[t].engineCli).sort(), [...engineCli].sort());
  // The symbols the admission reads are the ones 0017 and 0025 write.
  assert.ok(helper.includes('Symbol.for("paperclip.hardening.boxedAdapters")'));
  assert.ok(fs.readFileSync(path.join(SOURCE_PATCHES_DIR, "0025-sandbox-env-scrub.patch"), "utf8").includes('Symbol.for("paperclip.hardening.envScrub"), { value: true, writable: false, configurable: false'));
  const types = JSON.parse(/BOXED_ADAPTER_TYPES = Object\.freeze\((\[[^\]]*\])\)/.exec(helper)[1]);
  assert.deepEqual([...types].sort(), [...SCOPED_TYPES].sort(), "the types 0017 lets register are the types this admission knows");
});

// ---------- upgrade from the v0.1.1 release
// The v0.1.1 patch files come from git; the install is made by the engine with them, then 0003b and 0005f are added (as the
// release that enables the new switches will do) and the engine rebuilds from the stored pristine file.
function releasePatches() {
  const git = (args, encoding = "utf8") => spawnSync("git", args, { cwd: SOURCE_PATCHES_DIR, encoding, maxBuffer: 64 * 1024 * 1024 });
  const listing = git(["ls-tree", "--name-only", "v0.1.1", "./"]);
  if (listing.status !== 0) return null;
  const dir = path.join(scratch, "v011-patches");
  fs.mkdirSync(dir, { recursive: true });
  for (const name of listing.stdout.split("\n").filter((x) => x.endsWith(".patch"))) {
    const blob = git(["show", `v0.1.1:./${path.basename(name)}`], "buffer");
    if (blob.status !== 0) return null;
    fs.writeFileSync(path.join(dir, path.basename(name)), blob.stdout);
  }
  return dir;
}
const releaseDir = VERSIONS.length ? releasePatches() : null;
// The v0.1.1 engine itself (its registry knows nothing of the new patches), to make the state a v0.1.1 install left.
const oldPackage = VERSIONS.length ? v011Package() : { skip: "no versions" };
test.after(() => { if (oldPackage.dir) fs.rmSync(oldPackage.dir, { recursive: true, force: true }); });
const completeInstall = (version) => releaseDir && [...new Set([...discoverPatchFiles(releaseDir).values()].flat().map((f) => readPatchTarget(f.file)))]
  .every((rel) => pristineOrNull(stockRoot(version), rel));

for (const version of VERSIONS) {
  const skipUpgrade = skip || oldPackage.skip || (!releaseDir ? "no v0.1.1 tag in git history" : !completeInstall(version) ? `NO PRISTINE: ${version} has no original for every file the v0.1.1 release patches (set PAPERCLIP_STOCK_TREE_${version.split(".")[1]} to an untouched install)` : false);
  test(`${version}: upgrade from v0.1.1 - 0003b and 0005f added to an applied v0.1.1 engine state apply cleanly and rebuild the same file`, { skip: skipUpgrade }, async () => {
    const dir = freshRoot();
    const patchFilesOld = discoverPatchFiles(releaseDir);
    // the files the v0.1.1 release patches, and the ones this package adds (box-claude needs the adapter files to be there)
    const targets = [...new Set([...patchFilesOld.values(), ...discoverPatchFiles(SOURCE_PATCHES_DIR).values()].flat().map((f) => readPatchTarget(f.file)))];
    const treeDir = path.join(dir, "tree");
    const installRoot = stockRoot(version);
    for (const rel of targets) {
      fs.mkdirSync(path.dirname(path.join(treeDir, rel)), { recursive: true });
      fs.writeFileSync(path.join(treeDir, rel), pristineOrNull(installRoot, rel));
    }
    const pj = "node_modules/@paperclipai/server/package.json";
    fs.mkdirSync(path.dirname(path.join(treeDir, pj)), { recursive: true });
    fs.copyFileSync(path.join(installRoot, pj), path.join(treeDir, pj));
    const options = (patchesDir) => ({ treeDir, dataDir: path.join(dir, "data"), patchesDir, tmpDir: scratch, systemctl: null });

    // 1. the v0.1.1 install: its registry, its patch files, every protection of that release on.
    const everyOn = [...V011_DEFAULTS];
    assert.ok(everyOn.every((id) => PROTECTIONS.some((p) => p.id === id)));
    const v011 = (await importV011Engine(oldPackage, `0005f-${version}`)).createEngine(options(releaseDir));
    const first = await v011.apply(await v011.plan(everyOn));
    assert.equal(first.ok, true, first.error);
    assert.deepEqual(first.unavailable, {});
    const installed = fs.readFileSync(path.join(treeDir, HB), "utf8");
    assert.ok(installed.includes("// LOCAL-PATCH 0005b") && !installed.includes("// LOCAL-PATCH 0005f") && !installed.includes("// LOCAL-PATCH 0003b"));

    // 2. this package (own-box carries 0003b, only-boxed 0005f, and only-boxed needs the new box-claude switch) on the same tree.
    const upgraded = createEngine(options(SOURCE_PATCHES_DIR));
    const plan = await upgraded.plan(everyOn);
    assert.deepEqual(plan.unavailable, {}, "nothing becomes unavailable");
    assert.deepEqual(plan.added.map((a) => a.id), ["box-claude"]);
    const heartbeat = plan.files.find((f) => f.rel === HB);
    assert.equal(heartbeat.change, true);
    assert.deepEqual(heartbeat.patches.map((u) => u.id).filter((id) => ["0003", "0003b", "0005b", "0005f", "0006a"].includes(id)), ["0003", "0003b", "0005b", "0005f", "0006a"]);
    const second = await upgraded.apply(plan);
    assert.equal(second.ok, true, second.error);
    const after = fs.readFileSync(path.join(treeDir, HB));
    assert.ok(after.equals(build(version, { with0005f: true }).content), "same as building from the pristine file with the new chain");
    const b = evalBlock(admissionCode(after.toString("utf8")), "admission", { instanceRoot: freshRoot() });
    assert.match(admit(b, hermes({ hermesCommand: "/tmp/evil" })).message ?? "", /hermesCommand/);
  });
}

// Without the engine's help (a hand-patched install): 0005f on top of the finished v0.1.1 heartbeat.js plus 0003b.
for (const version of VERSIONS) {
  test(`${version}: 0005f also fits on top of the finished v0.1.1 heartbeat.js with 0003b`, { skip: skip || (releaseDir ? false : "no v0.1.1 tag in git history") }, () => {
    const old = discoverPatchFiles(releaseDir);
    const steps = ["0003", "0005b", "0006a"].map((id) => ({ id, marker: CHAIN.find(([x]) => x === id)[1], candidates: old.get(id) }));
    const v011 = buildFile({ rel: HB, pristine: pristine(version), steps, tmpDir: scratch });
    assert.equal(v011.ok, true, v011.reason);
    const now = discoverPatchFiles(SOURCE_PATCHES_DIR);
    const onTop = buildFile({
      rel: HB, pristine: v011.content, tmpDir: scratch,
      steps: ["0003b", "0005f"].map((id) => ({ id, marker: CHAIN.find(([x]) => x === id)[1], candidates: now.get(id) })),
    });
    assert.equal(onTop.ok, true, onTop.reason);
    const b = evalBlock(admissionCode(onTop.content.toString("utf8")), "admission", { instanceRoot: freshRoot() });
    assert.equal(admit(b, scoped("codex_local")).error, null);
  });
}
