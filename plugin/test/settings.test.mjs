// Settings model and the settings-file writer (src/settings.js).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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
