// Settings model and the settings-file writer (src/settings.js).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EXCEPTIONABLE_TYPES } from "../src/profiles.js";
import { DEFAULT_SETTINGS, normalizeSettings, hardeningConfigFromSettings, writeHardeningConfig, HardeningConfigRefusal, sandboxWritableRoots, CONFIG_KEYS } from "../src/settings.js";

const tmp = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "settings-test-"));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

test("defaults are empty (Paperclip's secure built-in defaults apply) with the standard restart unit", () => {
  const { settings, errors } = normalizeSettings(undefined);
  assert.deepEqual(errors, []);
  assert.deepEqual(settings, { ...DEFAULT_SETTINGS });
  assert.deepEqual(hardeningConfigFromSettings(settings), { schema: 1, writtenBy: "paperclip-security-hardening" });
});

test("normalizeSettings: lists from arrays or text, trimmed and de-duplicated; invalid entries reported and dropped", () => {
  const { settings, errors } = normalizeSettings({
    baseAllowlist: " api.anthropic.com \n127.0.0.1:8790,api.anthropic.com,,evil host,*:443,https://x.example,h:70000,***REDACTED***",
    extraReadOnlyPaths: ["/opt/vault/bin", "/opt/vault/bin/", "relative", "/a/../etc", "/a,b", 5],
    workspaceRoots: "/srv/projects",
    hermesWrapperPath: "hermes",
    alertCompanyId: "0b7c3a5e-1111-2222-3333-444455556666",
    alertProjectId: "bad id",
    unknownKey: "dropped",
  });
  assert.deepEqual(settings.baseAllowlist, ["api.anthropic.com", "127.0.0.1:8790"]);
  assert.deepEqual(settings.extraReadOnlyPaths, ["/opt/vault/bin"]);
  assert.deepEqual(settings.workspaceRoots, ["/srv/projects"]);
  assert.equal(settings.hermesWrapperPath, "");
  assert.equal(settings.alertCompanyId, "0b7c3a5e-1111-2222-3333-444455556666");
  assert.equal(settings.alertProjectId, "");
  assert.equal("unknownKey" in settings, false);
  assert.equal(errors.length, 4);
  assert.match(errors.join("\n"), /baseAllowlist: .*evil host, \*:443, https:\/\/x\.example, h:70000, \*\*\*REDACTED\*\*\*/);
  assert.match(errors.join("\n"), /extraReadOnlyPaths: .*relative, \/a\/\.\.\/etc, \/a,b, 5/);
  assert.equal(normalizeSettings({ baseAllowlist: Array.from({ length: 70 }, (_, i) => `h${i}.example`) }).settings.baseAllowlist.length, 64);
});

test("the settings file holds only the non-empty site values, in a fixed key order", () => {
  const config = hardeningConfigFromSettings({ hermesReadOnlyPaths: ["/opt/hermes"], baseAllowlist: ["a.example"], alertCompanyId: "c1", workspaceRoots: [] });
  assert.deepEqual(Object.keys(config), ["schema", "writtenBy", "baseAllowlist", "hermesReadOnlyPaths"]);
  assert.ok(Object.keys(config).slice(2).every((k) => CONFIG_KEYS.includes(k)));
});

test("writeHardeningConfig: creates the directory, writes atomically with mode 0600, rewrites only on change", () => {
  const instanceRoot = path.join(tmp, "instances", "default");
  const file = path.join(instanceRoot, "hardening", "config.json");
  const a = writeHardeningConfig({ baseAllowlist: ["api.anthropic.com"] }, { file, instanceRoot });
  assert.equal(a.changed, true);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), a.config);
  const mtime = fs.statSync(file).mtimeMs;
  assert.equal(writeHardeningConfig({ baseAllowlist: ["api.anthropic.com"] }, { file, instanceRoot }).changed, false);
  assert.equal(fs.statSync(file).mtimeMs, mtime);
  const b = writeHardeningConfig({ baseAllowlist: ["api.anthropic.com"], workspaceRoots: ["/srv"] }, { file, instanceRoot });
  assert.equal(b.changed, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")).workspaceRoots, ["/srv"]);
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ["config.json"], "no temp files left behind");
});

// ---------- where the writer will put the file (the patched server ignores it anywhere else)
const UID = process.getuid();
let seq = 0;
/** A fresh instance root with mode 0700 (nothing group- or world-writable on the way down). */
function instance() {
  const instanceRoot = path.join(tmp, `inst-${++seq}`);
  fs.mkdirSync(instanceRoot, { mode: 0o700 });
  return { instanceRoot, file: path.join(instanceRoot, "hardening", "config.json") };
}
const S = { baseAllowlist: ["api.anthropic.com"] };
const refuses = (fn, re) => assert.throws(fn, (e) => e instanceof HardeningConfigRefusal && re.test(e.message), re.toString());

test("writeHardeningConfig: creates the directory 0700 and the file 0600 whatever the umask, no temp file left", () => {
  const { instanceRoot, file } = instance();
  const old = process.umask(0);
  try { writeHardeningConfig(S, { file, instanceRoot }); } finally { process.umask(old); }
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(file).uid, UID);
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ["config.json"]);
});

test("writeHardeningConfig: refuses a file inside the workspaces, projects or companies directory, also through a link, and creates nothing", () => {
  for (const sub of ["workspaces", "projects", "companies"]) {
    const { instanceRoot } = instance();
    const file = path.join(instanceRoot, sub, "agent-1", "hardening", "config.json");
    refuses(() => writeHardeningConfig(S, { file, instanceRoot }), /lies inside .*sandboxed runs can write/);
    assert.equal(fs.existsSync(path.join(instanceRoot, sub)), false, `${sub} was created`);
  }
  // <instance root>/hardening is a link into a writable place, and so is the file itself.
  const { instanceRoot, file } = instance();
  fs.mkdirSync(path.join(instanceRoot, "workspaces", "w"), { recursive: true });
  fs.symlinkSync(path.join(instanceRoot, "workspaces", "w"), path.dirname(file));
  refuses(() => writeHardeningConfig(S, { file, instanceRoot }), /lies inside/);
  assert.deepEqual(fs.readdirSync(path.join(instanceRoot, "workspaces", "w")), []);
  // Relative segments do not hide it.
  refuses(() => writeHardeningConfig(S, { file: path.join(instanceRoot, "hardening", "..", "projects", "config.json"), instanceRoot }), /lies inside/);
});

test("writeHardeningConfig: refuses a file inside a workspace root (the settings' own, or the server's PAPERCLIP_SANDBOX_WORKSPACE_ROOT)", () => {
  const { instanceRoot } = instance();
  const shared = path.join(tmp, `shared-${seq}`);
  const file = path.join(shared, "sub", "config.json");
  refuses(() => writeHardeningConfig({ ...S, workspaceRoots: [shared] }, { file, instanceRoot }), /lies inside/);
  refuses(() => writeHardeningConfig(S, { file, instanceRoot, sandboxRootsEnv: `/srv/x${path.delimiter}${shared}` }), /lies inside/);
  assert.equal(fs.existsSync(shared), false);
  assert.equal(writeHardeningConfig({ ...S, workspaceRoots: ["/srv/other"] }, { file, instanceRoot }).changed, true, "an unrelated root is fine; the file may live outside the instance root");
  assert.deepEqual(sandboxWritableRoots({ instanceRoot: "/i", workspaceRoots: ["/a", "rel"], sandboxRootsEnv: "/b: /c ::rel" }),
    ["/i/workspaces", "/i/projects", "/i/companies", "/a", "/b", "/c"]);
});

test("writeHardeningConfig: an existing file must be a regular file owned by the service user with mode 0600; nothing is changed", () => {
  const cases = {
    "mode 0644": (f) => fs.chmodSync(f, 0o644),
    "mode 0660": (f) => fs.chmodSync(f, 0o660),
    "mode 0400": (f) => fs.chmodSync(f, 0o400),
    "a link": (f) => { fs.renameSync(f, `${f}.real`); fs.symlinkSync(`${f}.real`, f); },
    "not a file": (f) => { fs.rmSync(f); fs.mkdirSync(f); },
  };
  for (const [name, break_] of Object.entries(cases)) {
    const { instanceRoot, file } = instance();
    writeHardeningConfig(S, { file, instanceRoot });
    break_(file);
    const before = fs.readdirSync(path.dirname(file)).sort();
    refuses(() => writeHardeningConfig({ baseAllowlist: ["other.example"] }, { file, instanceRoot }), /mode|not a regular file/);
    refuses(() => writeHardeningConfig(S, { file, instanceRoot }), /mode|not a regular file/); // same content: still refused, the server would ignore it
    assert.deepEqual(fs.readdirSync(path.dirname(file)).sort(), before, name);
  }
  const { instanceRoot, file } = instance();
  writeHardeningConfig(S, { file, instanceRoot });
  refuses(() => writeHardeningConfig(S, { file, instanceRoot, uid: UID + 1 }), /not owned by the service user/);
  assert.equal(fs.readFileSync(file, "utf8").includes("other.example"), false);
});

test("writeHardeningConfig: an existing directory must be owned by the service user and not group- or world-writable", () => {
  for (const mode of [0o770, 0o707, 0o777, 0o720]) {
    const { instanceRoot, file } = instance();
    fs.mkdirSync(path.dirname(file), { mode: 0o700 });
    fs.chmodSync(path.dirname(file), mode);
    refuses(() => writeHardeningConfig(S, { file, instanceRoot }), /mode \d+; it must not be writable by group or others/);
    assert.deepEqual(fs.readdirSync(path.dirname(file)), []);
  }
  const { instanceRoot, file } = instance();
  fs.mkdirSync(path.dirname(file), { mode: 0o755 });
  assert.equal(writeHardeningConfig(S, { file, instanceRoot }).changed, true, "0755 is fine: only the owner can write");
  fs.rmSync(path.dirname(file), { recursive: true });
  fs.mkdirSync(path.dirname(file), { mode: 0o700 });
  refuses(() => writeHardeningConfig(S, { file, instanceRoot, uid: UID + 1 }), /not owned by the service user/);
  fs.rmSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(path.dirname(file), "a file where the directory should be");
  refuses(() => writeHardeningConfig(S, { file, instanceRoot }), /not a directory/);
});

test("writeHardeningConfig: needs the instance root and a way to check the owner", () => {
  const { file } = instance();
  assert.throws(() => writeHardeningConfig(S, { file }), /instance root/);
  assert.throws(() => writeHardeningConfig(S, { file, instanceRoot: "relative" }), /instance root/);
  refuses(() => writeHardeningConfig(S, { file, instanceRoot: path.dirname(file), uid: null }), /cannot be checked on this platform/);
});

// ---------- v0.2.0: per-type base allowlists and remote exceptions
const AGENT = "0b7c3a5e-1111-2222-3333-444455556666";
const EXC = { agentId: AGENT, type: "cursor_cloud", reason: "reviewed by the board", addedBy: "board-user-1", addedAt: "2026-10-20T08:00:00.000Z" };

test("a v0.1.1 settings file reads back and writes out byte for byte unchanged", () => {
  const v011 = {
    schema: 1, writtenBy: "paperclip-security-hardening",
    workspaceRoots: ["/srv/projects"], baseAllowlist: ["api.anthropic.com", "127.0.0.1:8790"], extraReadOnlyPaths: ["/opt/vault/bin"],
    hermesWrapperPath: "/usr/local/bin/hermes-sandbox", hermesAllowlist: ["openrouter.ai"], hermesReadOnlyPaths: ["/opt/hermes"],
  };
  const { settings, errors } = normalizeSettings(v011);
  assert.deepEqual(errors, []);
  assert.deepEqual(settings.baseAllowlists, {});
  assert.deepEqual(settings.remoteExceptions, []);
  assert.deepEqual(hardeningConfigFromSettings(settings), v011);
  const { instanceRoot, file } = instance();
  writeHardeningConfig(v011, { file, instanceRoot });
  assert.equal(fs.readFileSync(file, "utf8"), `${JSON.stringify(v011, null, 2)}\n`);
  assert.equal(writeHardeningConfig(JSON.parse(fs.readFileSync(file, "utf8")), { file, instanceRoot }).changed, false, "reading the file and writing it again changes nothing");
  // The older text form of the claude_local allowlist still works.
  assert.deepEqual(normalizeSettings({ baseAllowlist: "api.anthropic.com\nx.example" }).settings.baseAllowlist, ["api.anthropic.com", "x.example"]);
});

test("the new keys are settings-file keys, written after the v0.1.1 ones and only when set", () => {
  assert.deepEqual(CONFIG_KEYS.slice(-2), ["baseAllowlists", "remoteExceptions"]);
  const config = hardeningConfigFromSettings({ remoteExceptions: [EXC], baseAllowlists: { codex_local: ["api.openai.com"] }, baseAllowlist: ["a.example"] });
  assert.deepEqual(Object.keys(config), ["schema", "writtenBy", "baseAllowlist", "baseAllowlists", "remoteExceptions"]);
  assert.deepEqual(config.baseAllowlists, { codex_local: ["api.openai.com"] });
  assert.deepEqual(config.remoteExceptions, [EXC]);
  assert.deepEqual(Object.keys(hardeningConfigFromSettings({ baseAllowlists: {}, remoteExceptions: [] })), ["schema", "writtenBy"]);
});

test("baseAllowlists: lists per boxed type, validHost per entry, in profile order, empty lists dropped", () => {
  const { settings, errors } = normalizeSettings({
    baseAllowlists: { grok_local: ["api.x.ai", "api.x.ai"], codex_local: " api.openai.com \n127.0.0.1:8790", gemini_local: [], opencode_local: ["openrouter.ai", "evil host", "*:443", "https://x.example"] },
  });
  assert.deepEqual(settings.baseAllowlists, { codex_local: ["api.openai.com", "127.0.0.1:8790"], opencode_local: ["openrouter.ai"], grok_local: ["api.x.ai"] });
  assert.deepEqual(Object.keys(settings.baseAllowlists), ["codex_local", "opencode_local", "grok_local"]);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /^baseAllowlists\.opencode_local: not a host or host:port: evil host, \*:443, https:\/\/x\.example$/);
  assert.equal(normalizeSettings({ baseAllowlists: { kimi_local: Array.from({ length: 70 }, (_, i) => `h${i}.example`) } }).settings.baseAllowlists.kimi_local.length, 64);
});

test("baseAllowlists: only boxed types with their own allowlist; the rest is reported and dropped", () => {
  for (const type of ["claude_local", "hermes_local", "cursor_cloud", "process", "paperclip_runner", "__proto__", "constructor"]) {
    const { settings, errors } = normalizeSettings({ baseAllowlists: JSON.parse(`{"${type}": ["a.example"]}`) });
    assert.deepEqual(settings.baseAllowlists, {}, type);
    assert.equal(errors.length, 1, type);
    assert.match(errors[0], new RegExp(`^baseAllowlists: not a boxed adapter type .*claude_local uses baseAllowlist\\): ${type}$`));
  }
  for (const bad of ["codex_local", ["a.example"], 5]) {
    const { settings, errors } = normalizeSettings({ baseAllowlists: bad });
    assert.deepEqual(settings.baseAllowlists, {});
    assert.match(errors.join(), /baseAllowlists: must be an object/);
  }
  assert.deepEqual(normalizeSettings({ baseAllowlists: { codex_local: 7 } }).errors, ["baseAllowlists.codex_local: must be a list"]);
  assert.deepEqual(normalizeSettings({ baseAllowlists: null }).settings.baseAllowlists, {});
});

test("remoteExceptions: complete entries for the exceptionable types, in a fixed key order", () => {
  const messy = { addedAt: " 2026-10-20T08:00:00Z ", addedBy: " board-user-1 ", reason: " reviewed ", type: "http", agentId: ` ${AGENT} `, extra: "dropped" };
  const { settings, errors } = normalizeSettings({ remoteExceptions: [messy] });
  assert.deepEqual(errors, []);
  assert.deepEqual(settings.remoteExceptions, [{ agentId: AGENT, type: "http", reason: "reviewed", addedBy: "board-user-1", addedAt: "2026-10-20T08:00:00Z" }]);
  assert.deepEqual(Object.keys(settings.remoteExceptions[0]), ["agentId", "type", "reason", "addedBy", "addedAt"]);
  for (const type of EXCEPTIONABLE_TYPES) assert.deepEqual(normalizeSettings({ remoteExceptions: [{ ...EXC, type }] }).errors, [], type);
  assert.deepEqual(EXCEPTIONABLE_TYPES, ["cursor_cloud", "openclaw_gateway", "hermes_gateway", "http", "process"]);
});

test("remoteExceptions: a type that is not exceptionable is rejected, whatever the reason given", () => {
  for (const type of ["claude_local", "codex_local", "hermes_local", "paperclip_runner", "acpx_local", "some_plugin_adapter", "", "__proto__"]) {
    const { settings, errors } = normalizeSettings({ remoteExceptions: [{ ...EXC, type }] });
    assert.deepEqual(settings.remoteExceptions, [], type);
    assert.match(errors.join(), /^remoteExceptions\[0\]: type must be one of cursor_cloud, openclaw_gateway, hermes_gateway, http, process/, type);
  }
});

test("remoteExceptions: every field is required and checked; bad entries are dropped one by one", () => {
  const cases = [
    [{ ...EXC, agentId: "../x" }, /agentId is not a valid id/],
    [{ ...EXC, agentId: undefined }, /agentId is not a valid id/],
    [{ ...EXC, reason: "  " }, /reason is required/],
    [{ ...EXC, reason: "x".repeat(501) }, /reason is required/],
    [{ ...EXC, addedBy: "" }, /addedBy is required/],
    [{ ...EXC, addedAt: "yesterday" }, /addedAt must be an ISO 8601/],
    [{ ...EXC, addedAt: "2026-13-45T00:00:00Z" }, /addedAt must be an ISO 8601/],
    [AGENT, /must be an object/],
    [null, /must be an object/],
    [[EXC], /must be an object/],
  ];
  for (const [entry, re] of cases) {
    const { settings, errors } = normalizeSettings({ remoteExceptions: [entry] });
    assert.deepEqual(settings.remoteExceptions, []);
    assert.match(errors.join(), re);
  }
  const mixed = normalizeSettings({ remoteExceptions: [EXC, { ...EXC, agentId: "b2", reason: "" }, { ...EXC, agentId: "c3", type: "process" }] });
  assert.deepEqual(mixed.settings.remoteExceptions.map((e) => e.agentId), [AGENT, "c3"]);
  assert.match(mixed.errors.join(), /^remoteExceptions\[1\]: reason is required/);
  const twice = normalizeSettings({ remoteExceptions: [EXC, { ...EXC, type: "http" }] });
  assert.equal(twice.settings.remoteExceptions.length, 1);
  assert.match(twice.errors.join(), /listed twice/);
  assert.deepEqual(normalizeSettings({ remoteExceptions: "agent-1" }).errors, ["remoteExceptions: must be a list"]);
  const many = Array.from({ length: 300 }, (_, i) => ({ ...EXC, agentId: `a${i}` }));
  assert.equal(normalizeSettings({ remoteExceptions: many }).settings.remoteExceptions.length, 256);
});

test("writeHardeningConfig writes the new keys with the same 0600/0700 checks, and rewrites only on change", () => {
  const { instanceRoot, file } = instance();
  const s = { baseAllowlists: { cursor: ["api2.cursor.sh"] }, remoteExceptions: [EXC] };
  const a = writeHardeningConfig(s, { file, instanceRoot });
  assert.equal(a.changed, true);
  assert.deepEqual(a.config, { schema: 1, writtenBy: "paperclip-security-hardening", baseAllowlists: { cursor: ["api2.cursor.sh"] }, remoteExceptions: [EXC] });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  assert.equal(writeHardeningConfig(s, { file, instanceRoot }).changed, false);
  fs.chmodSync(file, 0o644);
  refuses(() => writeHardeningConfig({ ...s, remoteExceptions: [] }, { file, instanceRoot }), /mode 644; it must be 0600/);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")).remoteExceptions, [EXC], "a refused write changes nothing");
  const { instanceRoot: root2 } = instance();
  refuses(() => writeHardeningConfig(s, { file: path.join(root2, "companies", "c", "config.json"), instanceRoot: root2 }), /lies inside/);
});
