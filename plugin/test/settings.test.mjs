// Settings model and the settings-file writer (src/settings.js).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DEFAULT_SETTINGS, normalizeSettings, hardeningConfigFromSettings, resolveConfigPath, writeHardeningConfig, CONFIG_KEYS } from "../src/settings.js";

const tmp = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "settings-test-"));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

test("defaults are empty (Paperclip's secure built-in defaults apply) with the standard restart unit", () => {
  const { settings, errors } = normalizeSettings(undefined);
  assert.deepEqual(errors, []);
  assert.deepEqual(settings, { ...DEFAULT_SETTINGS });
  assert.deepEqual(hardeningConfigFromSettings(settings), { schema: 1, writtenBy: "paperclip-sandbox-hardening" });
});

test("normalizeSettings: lists from arrays or text, trimmed and de-duplicated; invalid entries reported and dropped", () => {
  const { settings, errors } = normalizeSettings({
    baseAllowlist: " api.anthropic.com \n127.0.0.1:8790,api.anthropic.com,,evil host,*:443,https://x.example,h:70000,***REDACTED***",
    extraReadOnlyPaths: ["/opt/vault/bin", "/opt/vault/bin/", "relative", "/a/../etc", "/a,b", 5],
    workspaceRoots: "/srv/projects",
    hermesWrapperPath: "hermes",
    restartUnit: "paperclip;rm",
    alertCompanyId: "0b7c3a5e-1111-2222-3333-444455556666",
    alertProjectId: "bad id",
    unknownKey: "dropped",
  });
  assert.deepEqual(settings.baseAllowlist, ["api.anthropic.com", "127.0.0.1:8790"]);
  assert.deepEqual(settings.extraReadOnlyPaths, ["/opt/vault/bin"]);
  assert.deepEqual(settings.workspaceRoots, ["/srv/projects"]);
  assert.equal(settings.hermesWrapperPath, "");
  assert.equal(settings.restartUnit, "paperclipai");
  assert.equal(settings.alertCompanyId, "0b7c3a5e-1111-2222-3333-444455556666");
  assert.equal(settings.alertProjectId, "");
  assert.equal("unknownKey" in settings, false);
  assert.equal(errors.length, 5);
  assert.match(errors.join("\n"), /baseAllowlist: .*evil host, \*:443, https:\/\/x\.example, h:70000, \*\*\*REDACTED\*\*\*/);
  assert.match(errors.join("\n"), /extraReadOnlyPaths: .*relative, \/a\/\.\.\/etc, \/a,b, 5/);
  assert.equal(normalizeSettings({ baseAllowlist: Array.from({ length: 70 }, (_, i) => `h${i}.example`) }).settings.baseAllowlist.length, 64);
});

test("the settings file holds only the non-empty site values, in a fixed key order", () => {
  const config = hardeningConfigFromSettings({ hermesReadOnlyPaths: ["/opt/hermes"], baseAllowlist: ["a.example"], restartUnit: "x", alertCompanyId: "c1", workspaceRoots: [] });
  assert.deepEqual(Object.keys(config), ["schema", "writtenBy", "baseAllowlist", "hermesReadOnlyPaths"]);
  assert.ok(Object.keys(config).slice(2).every((k) => CONFIG_KEYS.includes(k)));
});

test("resolveConfigPath: $PAPERCLIP_HARDENING_CONFIG, else <PAPERCLIP_HOME>/instances/<PAPERCLIP_INSTANCE_ID>/hardening/config.json", () => {
  assert.equal(resolveConfigPath({ env: { PAPERCLIP_HARDENING_CONFIG: "/etc/pc/h.json", PAPERCLIP_HOME: "/x" }, home: "/home/u" }), "/etc/pc/h.json");
  assert.equal(resolveConfigPath({ env: {}, home: "/home/u" }), "/home/u/.paperclip/instances/default/hardening/config.json");
  assert.equal(resolveConfigPath({ env: { PAPERCLIP_HOME: "~/pc", PAPERCLIP_INSTANCE_ID: "dev" }, home: "/home/u" }), "/home/u/pc/instances/dev/hardening/config.json");
  assert.equal(resolveConfigPath({ env: { PAPERCLIP_HOME: "/srv/pc" }, home: "/home/u" }), "/srv/pc/instances/default/hardening/config.json");
  assert.throws(() => resolveConfigPath({ env: { PAPERCLIP_INSTANCE_ID: "../x" }, home: "/home/u" }), /PAPERCLIP_INSTANCE_ID/);
});

test("writeHardeningConfig: creates the directory, writes atomically with mode 0600, rewrites only on change", () => {
  const file = path.join(tmp, "instances", "default", "hardening", "config.json");
  const a = writeHardeningConfig({ baseAllowlist: ["api.anthropic.com"] }, { file });
  assert.equal(a.changed, true);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), a.config);
  const mtime = fs.statSync(file).mtimeMs;
  assert.equal(writeHardeningConfig({ baseAllowlist: ["api.anthropic.com"] }, { file }).changed, false);
  assert.equal(fs.statSync(file).mtimeMs, mtime);
  const b = writeHardeningConfig({ baseAllowlist: ["api.anthropic.com"], workspaceRoots: ["/srv"] }, { file });
  assert.equal(b.changed, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")).workspaceRoots, ["/srv"]);
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ["config.json"], "no temp files left behind");
});
