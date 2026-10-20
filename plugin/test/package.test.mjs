// Packaging and manifest: the validate-manifest script, the patch files the published plugin carries, and a render
// smoke test of the Hardening page with stubbed host modules (react and the SDK UI are host-provided at runtime).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import module from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PROTECTIONS, PATCHES } from "../src/engine/registry.js";
import { discoverPatchFiles } from "../src/engine/patches.js";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import manifest from "../src/manifest.js";

const PLUGIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(fs.readFileSync(path.join(PLUGIN, "package.json"), "utf8"));
const tmp = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "package-test-"));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

let haveShared = true;
try { await import("@paperclipai/shared"); } catch { haveShared = false; }

test("validate-manifest script accepts the manifest (host schema from @paperclipai/shared)", { skip: !haveShared && "@paperclipai/shared not installed" }, () => {
  const r = spawnSync(process.execPath, [path.join(PLUGIN, "scripts/validate-manifest.mjs")], { cwd: PLUGIN, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr || r.stdout);
  assert.match(r.stdout, /^manifest OK: paperclip-security-hardening/);
});

test("manifest: least-privilege capabilities, each one explained, and the entrypoints match package.json", () => {
  assert.deepEqual([...manifest.capabilities].sort(), ["activity.log.write", "agents.managed", "agents.pause", "agents.read", "agents.resume", "authorization.grants.read", "companies.read",
    "database.namespace.migrate", "database.namespace.read", "events.subscribe", "issue.comments.create", "issue.comments.read", "issue.documents.write", "issues.create", "issues.read", "jobs.schedule", "plugin.state.read", "plugin.state.write",
    "routines.managed", "ui.page.register", "webhooks.receive"]);
  // Writes the SDK offers but the plugin must not hold: grants, issue edits, outbound HTTP, secrets, scoped API routes.
  for (const cap of ["authorization.grants.write", "issues.update", "http.outbound", "secrets.read-ref", "agents.invoke", "agents.lifecycle.manage", "skills.managed", "projects.managed", "api.routes.register"]) assert.ok(!manifest.capabilities.includes(cap), cap);
  // The only inbound endpoint is the signed watchdog webhook; its heartbeat check is a job.
  assert.deepEqual(manifest.webhooks.map((w) => w.endpointKey), ["watchdog"]);
  assert.ok(manifest.jobs.some((j) => j.jobKey === "watchdog-heartbeat"));
  assert.ok(manifest.jobs.some((j) => j.jobKey === "alert-recheck"));
  assert.ok(manifest.jobs.some((j) => j.jobKey === "itsec-reconcile" && j.schedule === "*/15 * * * *"));
  assert.equal(manifest.instanceConfigSchema.properties.alertRecheckDays.default, 7);
  assert.ok(manifest.instanceConfigSchema.properties.alertOwnerUserIds);
  // The only core table read is heartbeat_runs; the migrations folder ships and holds no migration.
  assert.deepEqual(manifest.database.coreReadTables, ["heartbeat_runs"]);
  const migrations = path.join(PLUGIN, manifest.database.migrationsDir);
  assert.ok(fs.statSync(migrations).isDirectory() && pkg.files.some((f) => manifest.database.migrationsDir.replace(/^\.\//, "").startsWith(f)));
  assert.deepEqual(fs.readdirSync(migrations).filter((n) => n.endsWith(".sql")), []);
  assert.ok(manifest.jobs.some((j) => j.jobKey === "daily-token-caps" && j.schedule === "*/5 * * * *"));
  assert.ok(manifest.ui.slots.some((s) => s.exportName === "AgentBoxesPage"));
  const src = fs.readFileSync(path.join(PLUGIN, "src/manifest.js"), "utf8");
  for (const cap of manifest.capabilities) assert.ok(src.includes(`//   ${cap}`) || src.includes(`/${cap.split(".").pop()}`), `no reason given for ${cap}`);
  assert.equal(`./${path.normalize(pkg.paperclipPlugin.worker)}`, manifest.entrypoints.worker);
  assert.equal(`./${path.normalize(pkg.paperclipPlugin.ui)}`, manifest.entrypoints.ui);
  assert.ok(manifest.instanceConfigSchema.properties.adminUserIds);
});

test("packaging: prepack copies every patch file the engine needs into the plugin; postpack removes the copy", () => {
  assert.ok(pkg.files.includes("patches") && pkg.files.includes("src") && pkg.files.includes("bin"));
  assert.match(pkg.scripts.prepack, /copy-patches\.mjs$/);
  assert.match(pkg.scripts.postpack, /copy-patches\.mjs --clean$/);
  const dest = path.join(tmp, "patches");
  const r = spawnSync(process.execPath, [path.join(PLUGIN, "scripts/copy-patches.mjs"), dest], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const found = discoverPatchFiles(dest);
  for (const id of PROTECTIONS.flatMap((p) => p.patches)) assert.ok(found.has(id), `patch ${id} missing from the packed copy`);
  assert.deepEqual(Object.keys(PATCHES).filter((id) => !found.has(id)), []);
  assert.deepEqual(fs.readdirSync(dest).sort(), fs.readdirSync(SOURCE_PATCHES_DIR).filter((n) => n.endsWith(".patch")).sort());
});

test("npm test runs every test file", () => {
  assert.equal(pkg.scripts.test, "node --test test/*.test.js test/*.test.mjs");
  const root = JSON.parse(fs.readFileSync(path.join(PLUGIN, "../package.json"), "utf8"));
  assert.match(root.scripts.test, /\(cd plugin && npm test\)$/);
});

// ---------- render smoke test of the page
const REACT_STUB = `const React = {
  createElement: (type, props, ...children) => ({ type, props: props || {}, children: children.flat(Infinity) }),
  useState: (v) => [typeof v === "function" ? v() : v, () => {}],
  useEffect: () => {},
};
export default React;`;
const SDK_UI_STUB = `const t = () => globalThis.__hardeningUiTest;
export const usePluginData = (key, params) => t().data(key, params);
export const usePluginAction = (key) => async (params) => t().action(key, params);
export const StatusBadge = (p) => ({ type: "badge", props: {}, children: ["[" + p.status + ": " + p.label + "]"] });
export const DataTable = (p) => ({ type: "table", props: {}, children: p.rows.map((r) => r.name + " " + r.state) });`;

function renderText(node) {
  if (node === null || node === undefined || node === false || node === true) return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(renderText).join(" ");
  if (typeof node.type === "function") return renderText(node.type({ ...node.props, children: node.children }));
  const own = node.type === "input" || node.type === "textarea" ? `<${node.type}${node.props.disabled ? " disabled" : ""}${node.props.checked ? " checked" : ""}>` : "";
  return `${own} ${node.children.map(renderText).join(" ")}`;
}

test("Hardening page renders every protection row, placeholders, restart text, restore and settings", { skip: typeof module.registerHooks !== "function" && "module.registerHooks needs Node 22.15+" }, async () => {
  const stubs = { react: REACT_STUB, "@paperclipai/plugin-sdk/ui": SDK_UI_STUB };
  module.registerHooks({
    resolve(specifier, context, next) {
      if (stubs[specifier] && context.parentURL?.endsWith("/src/ui.js")) return { url: `data:text/javascript,${encodeURIComponent(stubs[specifier])}`, shortCircuit: true };
      return next(specifier, context);
    },
  });
  const rows = PROTECTIONS.map((p) => ({ id: p.id, title: p.title, description: p.description, kind: p.kind, core: p.core, placeholder: p.kind !== "patch",
    enabled: p.id === "sandbox-compat", status: p.kind !== "patch" ? "placeholder" : p.id === "sandbox-compat" ? "pending-restart" : p.id === "public-web" ? "unavailable" : "off",
    reason: p.kind !== "patch" ? "coming in a later step" : p.id === "public-web" ? "patch 0015 does not fit" : null }));
  // Self-test states and the host-installed rows.
  Object.assign(rows.find((r) => r.id === "own-box"), { enabled: true, status: "selftest-failed", reason: "a run override cannot widen the stored box (0003): LD_PRELOAD was not dropped",
    selfTest: { ok: false, mode: "functional", at: "2026-10-18T10:00:00.000Z", checks: [] } });
  Object.assign(rows.find((r) => r.id === "pipeline-board-only"), { enabled: true, status: "applied", selfTest: { ok: true, mode: "structural only", at: "2026-10-18T10:00:00.000Z", checks: [] } });
  Object.assign(rows.find((r) => r.id === "watchdog"), { placeholder: false, hostInstall: true, enabled: true, status: "silent", reason: "no heartbeat since 2026-10-18T09:00:00.000Z (more than 30 minutes)" });
  Object.assign(rows.find((r) => r.id === "hermes-boxed"), { placeholder: false, hostInstall: true, enabled: false, status: "off", reason: "/usr/local/bin/hermes-sandbox: not installed" });
  globalThis.__hardeningUiTest = {
    data: (key) => ({
      "hardening-status": { loading: false, data: { available: true, tree: "/t", paperclipVersion: "2026.1012.0", configPath: "/c/config.json", protections: rows,
        restart: { needed: true, canRestart: false, reason: "no systemd user manager here", settingsChanged: true,
          manualText: "The plugin cannot restart Paperclip itself (no systemd user manager here). Stop it and start it again", why: "Only the settings file changed, but the patched Paperclip reads it once at startup" } }, refresh() {} },
      "hardening-settings": { loading: false, data: { settings: { baseAllowlist: ["api.anthropic.com"] } }, refresh() {} },
      compliance: { loading: false, data: { total: 1, nonCompliant: 0, results: [{ id: "a", name: "Engineer", adapterType: "claude_local", compliant: true, findings: [] }] } },
    })[key],
    action: async () => ({}),
  };
  const { HardeningPage } = await import(pathToFileURL(path.join(PLUGIN, "src/ui.js")).href);
  const text = renderText({ type: HardeningPage, props: { context: { companyId: "c1", userId: "u-1" } }, children: [] }).replace(/\s+/g, " ");
  for (const p of PROTECTIONS) assert.ok(text.includes(p.title), `row for ${p.title}`);
  assert.equal(text.match(/\[info: coming in a later step\]/g).length, 1); // daily-caps is managed on the Agent boxes page
  assert.ok(text.includes("[error: self-test failed]") && text.includes("LD_PRELOAD was not dropped") && text.includes("self-test FAILED (functional, plus file check)"));
  assert.ok(text.includes("self-test passed (structural only) at 2026-10-18T10:00:00.000Z"));
  assert.ok(text.includes("[error: no heartbeat for over 30 minutes]") && text.includes("Run self-test"));
  assert.ok(text.includes("[pending: pending restart]") && text.includes("[warning: unavailable on this install]") && text.includes("patch 0015 does not fit"));
  assert.ok(text.includes("The plugin cannot restart Paperclip itself (no systemd user manager here)") && text.includes("[pending: Restart needed (settings changed)]") && text.includes("reads it once at startup"));
  assert.ok(text.includes("Restore originals") && text.includes("Site settings") && text.includes("Your user id: u-1"));
  assert.equal((text.match(/<input disabled>/g) ?? []).length >= 1, true, "placeholder switches are disabled");
  assert.ok(text.includes("Engineer ok"));
  assert.ok(text.includes("Sandbox compatibility (safety core)") && /pending restart\] <input checked> on/.test(text), "switch shows the current state");

  // The Agent boxes page loads through actions after mount (useEffect is a no-op here): it renders its frame.
  const { AgentBoxesPage } = await import(pathToFileURL(path.join(PLUGIN, "src/ui.js")).href);
  const boxes = renderText({ type: AgentBoxesPage, props: { context: { companyId: "c1", userId: "u-1" } }, children: [] }).replace(/\s+/g, " ");
  assert.ok(boxes.includes("Agent boxes") && boxes.includes("Loading...") && boxes.includes("Your user id: u-1"));
});
