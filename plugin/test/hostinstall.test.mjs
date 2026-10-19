// Host-installed parts (src/hostinstall.js): one-time enrolment codes, the one-line command, the signed watchdog
// webhook (enrol, heartbeat, alert, unenrol), heartbeat green/red and the Hermes wrapper file check. Fake plugin
// context and clock; the openssl test checks that a signature made by the host side (openssl CLI, as the installer
// and the Python watchdog do it) verifies here.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHostInstalls, hashCode, newCode, normalizeCode, readReleasePins, ENROL_KEY, WATCHDOG_KEY, SIGNED_PREFIX, SIGNATURE_HEADER,
  CODE_TTL_MS, HEARTBEAT_STALE_MS, WebhookRejected } from "../src/hostinstall.js";
import { NotAllowedError } from "../src/hardening.js";
import { register } from "../src/worker.js";

const T0 = Date.parse("2026-10-18T10:00:00.000Z");
const SHA_W = "a".repeat(64), SHA_H = "b".repeat(64), SHA_WRAP = "c".repeat(64);
const PINS = { version: "1.0.0", baseUrl: "https://github.com/example-org/paperclip-sandbox-hardening/releases/download/v1.0.0/", installWatchdogSha256: SHA_W, installHermesSha256: SHA_H, hermesWrapperSha256: SHA_WRAP };
const actor = (type, userId, companyId = "c1") => ({ actor: Object.freeze({ type, userId, agentId: type === "agent" ? "a1" : null, runId: null, companyId }), companyId });
const ADMIN = actor("user", "u-admin"), MEMBER = actor("user", "u-member"), AGENT = actor("agent", null);

function setup({ settings = { alertCompanyId: "c1", alertProjectId: "p1", paperclipUrl: "http://10.0.0.5:3100" }, pins = PINS, statFile, readFile } = {}) {
  const state = new Map();
  const logs = [], issues = [];
  const clock = { t: T0 };
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const ctx = {
    state: { get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null), set: async (key, v) => { state.set(k(key), structuredClone(v)); } },
    activity: { log: async (e) => { logs.push(e); } },
    issues: { create: async (input) => { issues.push(input); return { id: `i-${issues.length}`, identifier: `ENG-${issues.length}` }; } },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  };
  const assertAdmin = async (context) => {
    const a = context?.actor ?? {};
    if (a.type !== "user" || a.userId !== "u-admin") throw new NotAllowedError("only instance admins");
    return a;
  };
  const w = createHostInstalls({ ctx, assertAdmin, loadSettings: async () => settings, now: () => clock.t, pins, statFile, readFile, env: {} });
  return { w, ctx, state, logs, issues, clock, settings, get: (key) => state.get(k(key)) ?? null };
}

function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { privateKey, pub: publicKey.export({ format: "der", type: "spki" }).toString("base64") };
}
let nonceN = 0;
function delivery(kp, body, { clock, sigKey } = {}) {
  const raw = JSON.stringify({ ts: new Date(clock.t).toISOString(), nonce: `nonce-${String(++nonceN).padStart(12, "0")}`, ...body });
  const sig = crypto.sign(null, Buffer.from(SIGNED_PREFIX + raw), (sigKey ?? kp).privateKey).toString("base64");
  return { endpointKey: "watchdog", headers: { [SIGNATURE_HEADER]: sig }, rawBody: raw, parsedBody: JSON.parse(raw), requestId: "r" };
}
const codeFrom = (cmd) => /--enrol ([A-Z0-9-]+)$/.exec(cmd)[1];
async function enrolled(s) {
  const kp = keyPair();
  const code = codeFrom((await s.w.command({ kind: "watchdog", mode: "install" }, ADMIN)).command);
  const r = await s.w.receive(delivery(kp, { type: "enrol", installId: "inst-0001", code, publicKey: kp.pub, host: "vps1", version: "1.0.0" }, { clock: s.clock }));
  assert.equal(r.ok, true, r.reason);
  return kp;
}

// ---------------------------------------------------------------- codes and command
test("codes: 16 characters in groups of four, unambiguous alphabet, random, hashed for storage", () => {
  const codes = new Set(Array.from({ length: 200 }, () => newCode()));
  assert.equal(codes.size, 200);
  for (const c of codes) assert.match(c, /^[A-HJKMNP-TV-Z2-9]{4}(-[A-HJKMNP-TV-Z2-9]{4}){3}$/);
  const c = [...codes][0];
  assert.equal(normalizeCode(c.toLowerCase().replace(/-/g, " ")), c.replace(/-/g, ""));
  assert.equal(hashCode(c), hashCode(c.toLowerCase()));
  assert.match(hashCode(c), /^[0-9a-f]{64}$/);
  assert.notEqual(hashCode(c), crypto.createHash("sha256").update(c).digest("hex"), "domain-separated");
});

test("command: admin only; a fresh one-time code (15 minutes, only its hash stored) is the only variable secret in the line", async () => {
  const s = setup();
  await assert.rejects(s.w.command({ kind: "watchdog", mode: "install" }, AGENT), NotAllowedError);
  await assert.rejects(s.w.command({ kind: "watchdog", mode: "install" }, MEMBER), NotAllowedError);
  assert.equal(s.get(ENROL_KEY), null);
  const r = await s.w.command({ kind: "watchdog", mode: "install" }, ADMIN);
  assert.equal(r.ok, true);
  const code = codeFrom(r.command);
  assert.equal(r.command, `d=$(mktemp -d) && curl -fsSL ${PINS.baseUrl}install-watchdog.sh -o "$d/install-watchdog.sh" && echo "${SHA_W}  $d/install-watchdog.sh" | sha256sum -c - && sudo bash "$d/install-watchdog.sh" --paperclip http://10.0.0.5:3100 --enrol ${code}`);
  assert.equal(r.expiresAt, new Date(T0 + CODE_TTL_MS).toISOString());
  const stored = s.get(ENROL_KEY);
  assert.deepEqual(stored.codes.map((c) => c.hash), [hashCode(code)]);
  assert.ok(!JSON.stringify(stored).includes(code.replace(/-/g, "")) && !JSON.stringify(stored).includes(code), "the plain code is never stored");
  assert.ok(!JSON.stringify(s.logs).includes(code), "nor logged");
  // A new code replaces the previous one.
  const code2 = codeFrom((await s.w.command({ kind: "watchdog", mode: "install" }, ADMIN)).command);
  assert.notEqual(code2, code);
  assert.deepEqual(s.get(ENROL_KEY).codes.map((c) => c.hash), [hashCode(code2)]);
  // After an enrolment the state holds the public key only: still nothing secret in any later command.
  const kp = keyPair();
  assert.equal((await s.w.receive(delivery(kp, { type: "enrol", installId: "inst-0001", code: code2, publicKey: kp.pub }, { clock: s.clock }))).ok, true);
  const un = await s.w.command({ kind: "watchdog", mode: "uninstall" }, ADMIN);
  assert.match(un.command, /sudo bash "\$d\/install-watchdog\.sh" --uninstall$/);
  for (const line of [r.command, un.command]) {
    assert.ok(!line.includes(kp.pub) && !line.includes(hashCode(code2)), "no key material in the command");
    const stripped = line.replace(PINS.baseUrl, "").replace(SHA_W, "").replace(code, "");
    assert.doesNotMatch(stripped, /[A-Za-z0-9+/]{32,}|[0-9a-f]{32,}/, "no other long token-like value");
  }
});

test("command: Hermes install and removal lines; an unreleased build (no pins) shows none", async () => {
  const s = setup({ settings: { hermesWrapperPath: "/opt/bin/hermes-box" } });
  const i = await s.w.command({ kind: "hermes", mode: "install" }, ADMIN);
  assert.match(i.command, new RegExp(`echo "${SHA_H}  \\$d/install-hermes-wrapper.sh" \\| sha256sum -c - && sudo bash "\\$d/install-hermes-wrapper.sh" --path /opt/bin/hermes-box$`));
  assert.match((await s.w.command({ kind: "hermes", mode: "uninstall" }, ADMIN)).command, /--uninstall --path \/opt\/bin\/hermes-box$/);
  assert.equal(s.get(ENROL_KEY), null, "no code for the Hermes wrapper");
  const dev = setup({ pins: readReleasePins(path.join(os.tmpdir(), "no-such-pins.json")) });
  const r = await dev.w.command({ kind: "watchdog", mode: "install" }, ADMIN);
  assert.equal(r.ok, false);
  assert.match(r.error, /release pins/);
  assert.equal(dev.get(ENROL_KEY), null);
  await assert.rejects(s.w.command({ kind: "nope" }, ADMIN), /kind/);
  // The shipped development pins file is valid JSON with no pins.
  assert.deepEqual(readReleasePins(), { version: null, baseUrl: null, installWatchdogSha256: null, installHermesSha256: null, hermesWrapperSha256: null });
});

// ---------------------------------------------------------------- webhook auth
test("enrolment: a good code enrols once; bad, expired and reused codes and a wrong key are refused", async () => {
  const s = setup();
  const kp = keyPair();
  const code = codeFrom((await s.w.command({ kind: "watchdog", mode: "install" }, ADMIN)).command);
  const enrol = (over = {}, opts = {}) => s.w.receive(delivery(kp, { type: "enrol", installId: "inst-0001", code, publicKey: kp.pub, host: "vps1", ...over }, { clock: s.clock, ...opts }));

  assert.match((await enrol({ code: "AAAA-BBBB-CCCC-DDDD" })).reason, /unknown or already used/);
  assert.match((await enrol({}, { sigKey: keyPair() })).reason, /signature does not match the enrolling key/);
  assert.match((await enrol({ publicKey: "bm90LWEta2V5" })).reason, /not an Ed25519 key/);
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({ format: "der", type: "spki" }).toString("base64");
  assert.match((await enrol({ publicKey: rsa })).reason, /not an Ed25519 key/);
  assert.match((await enrol({ installId: "x" })).reason, /installId/);
  // The failed attempts did not use up the code.
  const ok = await enrol();
  assert.equal(ok.ok, true, ok.reason);
  const w = s.get(WATCHDOG_KEY);
  assert.deepEqual(Object.keys(w.installs), ["inst-0001"]);
  assert.equal(w.installs["inst-0001"].publicKey, kp.pub);
  assert.equal(w.installs["inst-0001"].lastHeartbeatAt, null);
  assert.deepEqual(s.get(ENROL_KEY).codes, [], "single use");
  assert.match(s.logs.at(-1).message, /watchdog enrolled \(vps1\)/);
  // Reused code (even by the same, legitimately enrolled key): refused.
  assert.match((await enrol()).reason, /unknown or already used/);

  // Expired: 15 minutes and one second later.
  const s2 = setup();
  const code2 = codeFrom((await s2.w.command({ kind: "watchdog", mode: "install" }, ADMIN)).command);
  s2.clock.t += CODE_TTL_MS + 1000;
  const late = await s2.w.receive(delivery(kp, { type: "enrol", installId: "inst-0002", code: code2, publicKey: kp.pub }, { clock: s2.clock }));
  assert.match(late.reason, /expired/);
  assert.equal(s2.get(WATCHDOG_KEY), null);
  assert.deepEqual(s2.get(ENROL_KEY).codes, [], "the expired code is dropped");
  // Still 14 minutes in: fine.
  const s3 = setup();
  const code3 = codeFrom((await s3.w.command({ kind: "watchdog", mode: "install" }, ADMIN)).command);
  s3.clock.t += 14 * 60 * 1000;
  assert.equal((await s3.w.receive(delivery(kp, { type: "enrol", installId: "inst-0003", code: code3, publicKey: kp.pub }, { clock: s3.clock }))).ok, true);
});

test("signed messages: a wrong key, an unknown install, a stale timestamp, a replayed nonce and a bad body are refused", async () => {
  const s = setup();
  const kp = await enrolled(s);
  const hb = (opts = {}, over = {}) => delivery(kp, { type: "heartbeat", installId: "inst-0001", ...over }, { clock: s.clock, ...opts });
  assert.match((await s.w.receive(hb({ sigKey: keyPair() }))).reason, /signature does not match the enrolled key/);
  assert.match((await s.w.receive(hb({}, { installId: "inst-9999" }))).reason, /unknown install/);
  const noSig = hb(); delete noSig.headers[SIGNATURE_HEADER];
  assert.match((await s.w.receive(noSig)).reason, /signature/);
  const tampered = hb(); tampered.rawBody = tampered.rawBody.replace('"heartbeat"', '"unenrol"');
  assert.match((await s.w.receive(tampered)).reason, /signature/);
  assert.match((await s.w.receive(hb({}, { ts: new Date(T0 - 6 * 60 * 1000).toISOString() }))).reason, /timestamp/);
  assert.match((await s.w.receive(hb({}, { nonce: "short" }))).reason, /nonce/);
  const once = hb();
  assert.equal((await s.w.receive(once)).ok, true);
  assert.match((await s.w.receive(once)).reason, /replay/);
  assert.match((await s.w.receive({ endpointKey: "watchdog", headers: {}, rawBody: "not json" })).reason, /JSON/);
  assert.match((await s.w.receive({ endpointKey: "other", headers: {}, rawBody: "{}" })).reason, /endpoint/);
  // The SDK hook throws on a refusal (host answers 502), and returns on success.
  await assert.rejects(s.w.handleWebhook(hb({ sigKey: keyPair() })), WebhookRejected);
  assert.equal((await s.w.handleWebhook(hb())).type, "heartbeat");
  // Unenrol removes the install; its key is useless afterwards.
  assert.equal((await s.w.receive(delivery(kp, { type: "unenrol", installId: "inst-0001" }, { clock: s.clock }))).ok, true);
  assert.match((await s.w.receive(hb())).reason, /unknown install/);
  assert.equal((await s.w.watchdogStatus()).status, "off");
});

test("a signature made with openssl (as the installer and the Python watchdog sign) verifies", { skip: spawnSync("openssl", ["version"]).status !== 0 && "no openssl" }, async () => {
  const dir = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "openssl-"));
  try {
    const run = (args, input) => { const r = spawnSync("openssl", args, { input }); assert.equal(r.status, 0, r.stderr?.toString()); return r.stdout; };
    run(["genpkey", "-algorithm", "ed25519", "-out", path.join(dir, "k.pem")]);
    const pub = run(["pkey", "-in", path.join(dir, "k.pem"), "-pubout", "-outform", "DER"]).toString("base64");
    const s = setup();
    const code = codeFrom((await s.w.command({ kind: "watchdog", mode: "install" }, ADMIN)).command);
    const raw = JSON.stringify({ type: "enrol", installId: "inst-ossl-1", code, publicKey: pub, ts: new Date(T0).toISOString(), nonce: "abcdefghijklmnop0001" });
    fs.writeFileSync(path.join(dir, "msg"), SIGNED_PREFIX + raw);
    const sig = run(["pkeyutl", "-sign", "-rawin", "-inkey", path.join(dir, "k.pem"), "-in", path.join(dir, "msg")]).toString("base64");
    const r = await s.w.receive({ endpointKey: "watchdog", headers: { [SIGNATURE_HEADER]: [sig] }, rawBody: raw });
    assert.equal(r.ok, true, r.reason);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------- heartbeat and alerts
test("heartbeat: waiting until the first heartbeat, green while fresh, red after 30 minutes, one alert, green again", async () => {
  const s = setup();
  assert.equal((await s.w.watchdogStatus()).status, "off");
  await s.w.command({ kind: "watchdog", mode: "install" }, ADMIN);
  assert.equal((await s.w.watchdogStatus()).status, "waiting", "code issued, nothing enrolled yet");
  const kp = await enrolled(s);
  assert.equal((await s.w.watchdogStatus()).status, "waiting", "enrolled, no heartbeat yet");
  const hb = () => s.w.receive(delivery(kp, { type: "heartbeat", installId: "inst-0001", version: "1.0.1", summary: { findings: 3, highSent: 1, deliveryFailed: 0 } }, { clock: s.clock }));
  assert.equal((await hb()).ok, true);
  let st = await s.w.watchdogStatus();
  assert.equal(st.status, "on");
  assert.equal(st.lastHeartbeatAt, new Date(T0).toISOString());
  assert.deepEqual(st.installs[0].summary, { findings: 3, highSent: 1, deliveryFailed: 0 });
  s.clock.t += HEARTBEAT_STALE_MS;
  assert.equal((await s.w.watchdogStatus()).status, "on", "exactly 30 minutes is still fine");
  assert.deepEqual(await s.w.checkHeartbeat(), { status: "on", alerted: false });
  s.clock.t += 1000;
  assert.equal((await s.w.watchdogStatus()).status, "silent");
  assert.deepEqual(await s.w.checkHeartbeat(), { status: "silent", alerted: true });
  assert.deepEqual(await s.w.checkHeartbeat(), { status: "silent", alerted: false }, "one alert per silence");
  assert.equal(s.issues.length, 1);
  assert.match(s.issues[0].title, /Watchdog stopped reporting/);
  assert.equal((await hb()).ok, true);
  assert.equal((await s.w.watchdogStatus()).status, "on");
  s.clock.t += HEARTBEAT_STALE_MS + 1000;
  assert.equal((await s.w.checkHeartbeat()).alerted, true, "a new silence alerts again");
});

test("alerts: one issue per alert key and day, created by the plugin in the alert company; refused (retried) without one", async () => {
  const s = setup();
  const kp = await enrolled(s);
  const alert = (a) => s.w.receive(delivery(kp, { type: "alert", installId: "inst-0001", alert: { key: "sudo-attempt:x", title: "[ITSec HIGH] sudo attempt", body: "evidence", priority: "high", day: "2026-10-18", ...a } }, { clock: s.clock }));
  const r = await alert();
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(r.issue, { issueId: "i-1", identifier: "ENG-1" });
  assert.equal(s.issues.length, 1);
  assert.deepEqual({ companyId: s.issues[0].companyId, projectId: s.issues[0].projectId, title: s.issues[0].title, status: s.issues[0].status, priority: s.issues[0].priority },
    { companyId: "c1", projectId: "p1", title: "[ITSec HIGH] sudo attempt", status: "todo", priority: "high" });
  assert.equal(s.issues[0].assigneeAgentId, undefined, "wakes no agent");
  assert.match(s.issues[0].description, /evidence[\s\S]*Reported by the watchdog on vps1/);
  assert.equal((await alert()).duplicate, true);
  assert.equal(s.issues.length, 1);
  assert.equal((await alert({ day: "2026-10-19" })).ok, true);
  assert.equal(s.issues.length, 2);
  assert.equal((await s.w.watchdogStatus()).recentAlerts.length, 2);
  assert.match((await alert({ title: "" })).reason, /key and title/);

  const none = setup({ settings: { alertCompanyId: "" } });
  const kp2 = await enrolled(none);
  const r2 = await none.w.receive(delivery(kp2, { type: "alert", installId: "inst-0001", alert: { key: "k", title: "t" } }, { clock: none.clock }));
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /no alert company/);
});

// ---------------------------------------------------------------- Hermes wrapper
test("Hermes wrapper: off when missing, red when not root-owned or writable, green when root-owned and matching the release", async () => {
  const content = Buffer.from("#!/usr/local/bin/node\n// wrapper\n");
  const sha = crypto.createHash("sha256").update(content).digest("hex");
  const stat = (o) => () => ({ uid: 0, mode: 0o100755, isFile: () => true, ...o });
  const mk = (statFile, pins = { ...PINS, hermesWrapperSha256: sha }) => setup({ settings: {}, statFile, readFile: () => content, pins }).w.hermesStatus();
  assert.equal((await mk(() => { throw Object.assign(new Error("x"), { code: "ENOENT" }); })).status, "off");
  assert.equal((await mk(stat({ uid: 1000 }))).status, "unsafe");
  assert.equal((await mk(stat({ mode: 0o100775 }))).status, "unsafe");
  const ok = await mk(stat({}));
  assert.equal(ok.status, "on");
  assert.equal(ok.path, "/usr/local/bin/hermes-sandbox");
  assert.equal((await mk(stat({}), { ...PINS, hermesWrapperSha256: "d".repeat(64) })).status, "differs");
  assert.match((await mk(stat({}), { ...PINS, hermesWrapperSha256: null })).reason, /not verified/);
});

test("worker: the Hardening status shows the host rows; the page actions and the webhook are wired", async () => {
  const reg = { data: {}, actions: {}, jobs: {} };
  const s = setup();
  const ctx = { ...s.ctx, config: { get: async () => ({ adminUserIds: ["u-admin"] }) }, data: { register: (k, f) => { reg.data[k] = f; } }, actions: { register: (k, f) => { reg.actions[k] = f; } }, jobs: { register: (k, f) => { reg.jobs[k] = f; } } };
  let hostFn = null;
  const fakeH = { assertAdmin: async () => ({ userId: "u-admin" }), loadSettings: async () => s.settings, setHostStatus: (fn) => { hostFn = fn; } };
  register(ctx, { hardening: fakeH, hosts: s.w });
  assert.ok(reg.actions.hostInstallCommand && reg.actions.runSelfTest && reg.jobs["watchdog-heartbeat"]);
  assert.equal((await hostFn()).watchdog.status, "off");
  const r = await reg.actions.hostInstallCommand({ kind: "watchdog", mode: "install" }, ADMIN);
  assert.equal(r.ok, true);
  const plugin = (await import("../src/worker.js")).default;
  assert.equal(typeof plugin.definition.onWebhook, "function");
});
