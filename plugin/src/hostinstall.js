// The parts installed outside Paperclip by an admin's one-line install (docs/PLUGIN-PLAN.md section 3): the watchdog
// (host/itsec) and the Hermes sandbox wrapper. No SDK imports: the plugin context is passed in, so tests use a fake one.
//
// Enrolment (watchdog). The plugin SDK delivers inbound HTTP only through POST /api/plugins/:pluginId/webhooks/:key
// (manifest `webhooks`, capability webhooks.receive). The host answers that call itself ({deliveryId, status}, or 502
// with the error message when the worker throws), so the worker can say yes or no but cannot hand anything back;
// scoped API routes with auth "webhook" are refused by the host; and every delivery's headers and body are stored in
// plugin_webhook_deliveries. A secret issued by the plugin can therefore not reach the installer, and a shared secret
// sent by the installer would sit in Paperclip's database. So the watchdog proves itself with a key pair instead:
//   1. The admin flips "Watchdog". The plugin creates a one-time code (80 random bits, valid 15 minutes, single use,
//      only its sha256 is stored; a new code replaces the previous one) and shows the one-line command.
//   2. The installer (run with sudo) generates an Ed25519 key pair; the private key stays root-only on the host
//      (/etc/itsec/watchdog-key.pem, handed to the units with LoadCredential). It posts {type: "enrol", code,
//      installId, publicKey} signed with the new key (proof of possession).
//   3. The plugin checks the code (known, unexpired, unused), deletes it and stores the public key for that install.
//   4. Heartbeats (every collector run, 15 minutes) and alerts are signed with the private key; the plugin checks the
//      signature, a 5-minute timestamp window and a single-use nonce, then records the heartbeat or creates the alert
//      issue as itself in the configured alert company/project. No Paperclip board or agent key is created, and
//      nothing in Paperclip (state, delivery log) is enough to forge a watchdog message.
// Signed message: "pcsh-v1\n" + the raw request body; header x-pcsh-signature: base64 Ed25519 signature.
//
// Hermes wrapper: no enrolment. The row is green when the wrapper file exists, is owned by root, is not writable by
// group or others and (when this plugin build carries release pins) matches the released wrapper's sha256.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { raiseAlertIssue } from "./alerts.js";
import { PLUGIN_ID } from "./manifest.js";

export const ENROL_KEY = Object.freeze({ scopeKind: "instance", stateKey: "watchdog-enrol" });
export const WATCHDOG_KEY = Object.freeze({ scopeKind: "instance", stateKey: "watchdog" });
export const ALERTS_KEY = Object.freeze({ scopeKind: "instance", stateKey: "watchdog-alerts" });
export const PLUGIN_KEY = PLUGIN_ID;
export const WEBHOOK_KEY = "watchdog";
export const CODE_TTL_MS = 15 * 60 * 1000;
export const HEARTBEAT_STALE_MS = 30 * 60 * 1000;
export const CLOCK_SKEW_MS = 5 * 60 * 1000;
export const SIGNATURE_HEADER = "x-pcsh-signature";
export const SIGNED_PREFIX = "pcsh-v1\n";
export const DEFAULT_HERMES_PATH = "/usr/local/bin/hermes-sandbox";
const MAX_BODY = 256 * 1024;
// Same pattern as install-watchdog.sh --watched-user.
const WATCHED_USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const ID_RE = /^[A-Za-z0-9-]{8,64}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"; // no 0/O, 1/I/L, U
const RECENT_ALERTS = 20;

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const RELEASE_PINS_FILE = path.join(HERE, "release-pins.json");

/** Release pins written by scripts/release.sh: {version, baseUrl, installWatchdogSha256, installHermesSha256,
 *  hermesWrapperSha256}. An unreleased build has none, and then shows no install command. */
export function readReleasePins(file = RELEASE_PINS_FILE) {
  try {
    const p = JSON.parse(fs.readFileSync(file, "utf8"));
    const sha = (v) => (typeof v === "string" && /^[0-9a-f]{64}$/.test(v) ? v : null);
    const baseUrl = typeof p.baseUrl === "string" && /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?\/[A-Za-z0-9._~\/-]*\/$/.test(p.baseUrl) ? p.baseUrl : null;
    return { version: typeof p.version === "string" ? p.version : null, baseUrl,
      installWatchdogSha256: sha(p.installWatchdogSha256), installHermesSha256: sha(p.installHermesSha256), hermesWrapperSha256: sha(p.hermesWrapperSha256) };
  } catch {
    return { version: null, baseUrl: null, installWatchdogSha256: null, installHermesSha256: null, hermesWrapperSha256: null };
  }
}

export const hashCode = (code) => crypto.createHash("sha256").update(`pcsh-enrol:${normalizeCode(code)}`).digest("hex");
export function normalizeCode(code) {
  return typeof code === "string" ? code.toUpperCase().replace(/[^A-Z0-9]/g, "") : "";
}
/** 16 characters from a 30-letter alphabet (~78 bits), shown in groups of four. */
export function newCode(random = crypto.randomBytes) {
  const out = [];
  while (out.length < 16) {
    for (const b of random(32)) { if (b < 240 && out.length < 16) out.push(CODE_ALPHABET[b % 30]); }
  }
  return out.join("").replace(/(.{4})(?=.)/g, "$1-");
}

/** Paperclip URL for the command: http(s), host and optional port, no credentials, path or query. */
export function validPaperclipUrl(v) {
  return typeof v === "string" && /^https?:\/\/[A-Za-z0-9.-]{1,253}(?::\d{1,5})?$/.test(v) && !/[@?#]/.test(v);
}

const header = (headers, name) => {
  const v = headers?.[name] ?? headers?.[name.toLowerCase()] ?? Object.entries(headers ?? {}).find(([k]) => k.toLowerCase() === name)?.[1];
  return Array.isArray(v) ? v[0] : typeof v === "string" ? v : null;
};
const plain = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
const text = (v, max) => (typeof v === "string" ? v.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "").slice(0, max) : "");

/** Ed25519 public key from base64 SPKI DER; null when it is not one. */
export function parsePublicKey(b64) {
  if (typeof b64 !== "string" || b64.length > 200 || !/^[A-Za-z0-9+/=]+$/.test(b64)) return null;
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(b64, "base64"), format: "der", type: "spki" });
    return key.asymmetricKeyType === "ed25519" ? key : null;
  } catch {
    return null;
  }
}

export function verifySignature(rawBody, signatureB64, publicKey) {
  if (typeof signatureB64 !== "string" || !/^[A-Za-z0-9+/=]{80,100}$/.test(signatureB64)) return false;
  try {
    return crypto.verify(null, Buffer.from(SIGNED_PREFIX + rawBody, "utf8"), publicKey, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

export class WebhookRejected extends Error {
  constructor(reason) { super(`watchdog webhook rejected: ${reason}`); this.name = "WebhookRejected"; this.reason = reason; }
}

/**
 * @param {object} o
 * @param {object} o.ctx            plugin context (state, activity, issues, logger)
 * @param {Function} o.assertAdmin  hardening.assertAdmin (agents and system calls always refused)
 * @param {Function} o.loadSettings hardening.loadSettings (alert company/project, Paperclip URL, Hermes path)
 * @param {Function} [o.now]
 * @param {object} [o.pins]         release pins (default: src/release-pins.json)
 * @param {Function} [o.statFile]   fs.statSync stand-in for the Hermes file check (tests)
 */
export function createHostInstalls({ ctx, assertAdmin, loadSettings, now = () => Date.now(), pins = readReleasePins(), statFile = fs.statSync, readFile = fs.readFileSync, env = process.env, serviceUser = () => os.userInfo().username } = {}) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {}, debug() {} };
  let queue = Promise.resolve();
  const exclusive = (fn) => { const run = queue.then(fn, fn); queue = run.catch(() => {}); return run; };
  const get = async (key, dflt) => plain(await ctx.state.get(key).catch(() => null) ?? dflt);

  async function activity(companyId, message, metadata) {
    if (!companyId) { log.info(message, metadata); return; }
    try { await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: PLUGIN_KEY, metadata }); }
    catch (e) { log.warn(`activity log entry not written: ${e.message}`, { message }); }
  }

  function paperclipUrl(settings) {
    if (validPaperclipUrl(settings.paperclipUrl)) return settings.paperclipUrl;
    const fromEnv = (env.PAPERCLIP_PUBLIC_URL || env.PAPERCLIP_API_URL || "").replace(/\/+$/, "").replace(/\/api$/, "");
    return validPaperclipUrl(fromEnv) ? fromEnv : "http://127.0.0.1:3100";
  }

  function oneLine(script, sha, args) {
    // A private temp dir (mode 0700): nobody else can swap the script between the fingerprint check and sudo.
    return `d=$(mktemp -d) && curl -fsSL ${pins.baseUrl}${script} -o "$d/${script}" && echo "${sha}  $d/${script}" | sha256sum -c - && sudo bash "$d/${script}" ${args}`;
  }

  // ------------------------------------------------------------------ status
  async function watchdogStatus() {
    const st = await get(WATCHDOG_KEY, {});
    const enrol = await get(ENROL_KEY, {});
    const installs = Object.entries(plain(st.installs)).map(([id, i]) => ({ id, host: i.host ?? null, version: i.version ?? null, enrolledAt: i.enrolledAt ?? null, lastHeartbeatAt: i.lastHeartbeatAt ?? null, summary: i.summary ?? null }));
    const waitingCode = (enrol.codes ?? []).some((c) => Date.parse(c.expiresAt) > now());
    const last = installs.map((i) => Date.parse(i.lastHeartbeatAt ?? "")).filter(Number.isFinite).sort((a, b) => b - a)[0] ?? null;
    let status;
    if (!installs.length) status = waitingCode ? "waiting" : "off";
    else if (last === null) status = "waiting";
    else status = now() - last <= HEARTBEAT_STALE_MS ? "on" : "silent";
    const alerts = await get(ALERTS_KEY, {});
    return { status, installs, lastHeartbeatAt: last === null ? null : new Date(last).toISOString(), waitingForEnrolment: waitingCode,
      recentAlerts: (alerts.recent ?? []).slice(0, 10) };
  }

  async function hermesStatus() {
    const settings = await loadSettings();
    const file = settings.hermesWrapperPath || DEFAULT_HERMES_PATH;
    let st;
    try { st = statFile(file); } catch { return { status: "off", path: file, reason: "not installed" }; }
    const rootOwned = st.uid === 0;
    const writable = (st.mode & 0o022) !== 0;
    if (typeof st.isFile === "function" && !st.isFile()) return { status: "unsafe", path: file, reason: "not a regular file" };
    if (!rootOwned || writable) {
      const problem = !rootOwned ? "is not owned by root, so an agent account could replace it" : "is writable by group or others";
      let found = null;
      try { found = crypto.createHash("sha256").update(readFile(file)).digest("hex"); } catch { found = null; }
      // Stays "unsafe" either way: an agent that can write this file can also change its hash, so a mismatch must not soften the result.
      const notReleased = pins.hermesWrapperSha256 && found && found !== pins.hermesWrapperSha256 ? " and it is not the released wrapper" : "";
      return { status: "unsafe", path: file, reason: `this file ${problem}${notReleased}` };
    }
    if (!pins.hermesWrapperSha256) return { status: "on", path: file, reason: "root-owned; version not verified (this plugin build has no release pins)" };
    let sha = null;
    try { sha = crypto.createHash("sha256").update(readFile(file)).digest("hex"); } catch { sha = null; }
    if (sha !== pins.hermesWrapperSha256) return { status: "differs", path: file, reason: `differs from the released wrapper ${pins.version ?? ""} (sha256 ${sha?.slice(0, 12) ?? "unreadable"})` };
    return { status: "on", path: file, reason: `root-owned, matches release ${pins.version}` };
  }

  // ------------------------------------------------------------------ admin: the one-line command
  async function command(params = {}, context) {
    const actor = await assertAdmin(context);
    const kind = params.kind === "hermes" ? "hermes" : params.kind === "watchdog" ? "watchdog" : null;
    if (!kind) throw new Error('kind must be "watchdog" or "hermes"');
    const mode = params.mode === "uninstall" ? "uninstall" : "install";
    const settings = await loadSettings();
    const script = kind === "watchdog" ? "install-watchdog.sh" : "install-hermes-wrapper.sh";
    const sha = kind === "watchdog" ? pins.installWatchdogSha256 : pins.installHermesSha256;
    if (!pins.baseUrl || !sha)
      return { ok: false, kind, mode, error: "This plugin build carries no release pins (official download URL and installer fingerprint), so it cannot show an install command. Install a released version of the plugin." };
    let args;
    let expiresAt = null;
    if (kind === "watchdog" && mode === "install") {
      // The account Paperclip runs as is the one the watchdog watches (the installer cannot know it; it runs as root).
      let user = null;
      try { user = serviceUser(); } catch { /* os.userInfo() throws when the account has no passwd entry */ }
      if (user === null)
        return { ok: false, kind, mode, error: "The account Paperclip runs as has no entry in the user database, so there is no watched user to name in the line. Install the watchdog by hand with --watched-user." };
      if (!WATCHED_USER_RE.test(user))
        return { ok: false, kind, mode, error: `Paperclip runs as the account "${user}", which the installer does not accept as a watched user (lowercase letters, digits, "_" and "-", at most 32). Install the watchdog by hand with --watched-user.` };
      const code = newCode();
      expiresAt = new Date(now() + CODE_TTL_MS).toISOString();
      await exclusive(async () => {
        // One active code: a new one replaces the previous (and every expired one).
        await ctx.state.set(ENROL_KEY, { codes: [{ hash: hashCode(code), expiresAt, createdAt: new Date(now()).toISOString(), createdBy: actor.userId }] });
      });
      args = `--paperclip ${paperclipUrl(settings)} --watched-user ${user} --enrol ${code}`;
      await activity(context?.companyId ?? actor.companyId ?? (settings.alertCompanyId || null), "Security hardening: watchdog enrolment code created (valid 15 minutes, single use)", { userId: actor.userId, expiresAt });
    } else if (kind === "watchdog") {
      args = "--uninstall";
    } else {
      const p = settings.hermesWrapperPath && settings.hermesWrapperPath !== DEFAULT_HERMES_PATH ? ` --path ${settings.hermesWrapperPath}` : "";
      args = mode === "uninstall" ? `--uninstall${p}` : p.trim();
    }
    return {
      ok: true, kind, mode, expiresAt, version: pins.version, script, sha256: sha, url: `${pins.baseUrl}${script}`,
      command: oneLine(script, sha, args).trimEnd(),
      explanation: kind === "watchdog" && mode === "install"
        ? "Paste this line into your own admin terminal (ssh as the sudo user, never Paperclip's account). It downloads the installer from the official release, checks its fingerprint, installs the watchdog under its own account and enrols it with a one-time code (valid 15 minutes, single use). Compare the URL and fingerprint with the release page."
        : mode === "uninstall" ? "Paste this line into your admin terminal to remove it (service, account and files)."
          : "Paste this line into your admin terminal. It downloads the wrapper from the official release, checks its fingerprint and installs it root-owned.",
    };
  }

  // ------------------------------------------------------------------ webhook
  /** Check one delivery; returns {ok, type, reason}. Never throws for a bad request (the wrapper turns !ok into 502). */
  async function receive(input) {
    if (input?.endpointKey !== WEBHOOK_KEY) return { ok: false, reason: "unknown endpoint" };
    const raw = typeof input.rawBody === "string" ? input.rawBody : "";
    if (!raw || raw.length > MAX_BODY) return { ok: false, reason: "empty or oversized body" };
    let body;
    try { body = JSON.parse(raw); } catch { return { ok: false, reason: "body is not JSON" }; }
    body = plain(body);
    const sig = header(input.headers, SIGNATURE_HEADER);
    const installId = typeof body.installId === "string" && ID_RE.test(body.installId) ? body.installId : null;
    if (!installId) return { ok: false, reason: "installId missing or malformed" };
    const ts = Date.parse(body.ts ?? "");
    if (!Number.isFinite(ts) || Math.abs(now() - ts) > CLOCK_SKEW_MS) return { ok: false, reason: "timestamp missing or outside the 5-minute window" };
    const nonce = typeof body.nonce === "string" && NONCE_RE.test(body.nonce) ? body.nonce : null;
    if (!nonce) return { ok: false, reason: "nonce missing or malformed" };

    return exclusive(async () => {
      const st = await get(WATCHDOG_KEY, {});
      const installs = { ...plain(st.installs) };
      const nonces = Object.fromEntries(Object.entries(plain(st.nonces)).filter(([, exp]) => exp > now()));
      if (nonces[nonce]) return { ok: false, reason: "nonce already used (replay)" };
      const save = async (patch) => ctx.state.set(WATCHDOG_KEY, { ...st, installs, nonces: { ...nonces, [nonce]: now() + 2 * CLOCK_SKEW_MS }, ...patch });

      if (body.type === "enrol") {
        const key = parsePublicKey(body.publicKey);
        if (!key) return { ok: false, reason: "publicKey is not an Ed25519 key" };
        if (!verifySignature(raw, sig, key)) return { ok: false, reason: "signature does not match the enrolling key" };
        const enrol = await get(ENROL_KEY, {});
        const codes = Array.isArray(enrol.codes) ? enrol.codes : [];
        const want = Buffer.from(hashCode(body.code), "hex");
        const match = codes.find((c) => typeof c.hash === "string" && c.hash.length === 64 && crypto.timingSafeEqual(Buffer.from(c.hash, "hex"), want));
        if (!match) return { ok: false, reason: "enrolment code unknown or already used" };
        await ctx.state.set(ENROL_KEY, { codes: codes.filter((c) => c !== match && Date.parse(c.expiresAt) > now()) }); // single use, expired dropped
        if (!(Date.parse(match.expiresAt) > now())) return { ok: false, reason: "enrolment code expired" };
        installs[installId] = { publicKey: body.publicKey, enrolledAt: new Date(now()).toISOString(), lastHeartbeatAt: null,
          host: text(body.host, 253) || null, version: text(body.version, 32) || null, enrolledBy: match.createdBy ?? null };
        await save({});
        const settings = await loadSettings();
        await activity(settings.alertCompanyId || null, `Security hardening: watchdog enrolled (${installs[installId].host ?? installId})`, { installId, host: installs[installId].host, version: installs[installId].version });
        return { ok: true, type: "enrol", installId };
      }

      const known = installs[installId];
      if (!known) return { ok: false, reason: "unknown install (not enrolled)" };
      const key = parsePublicKey(known.publicKey);
      if (!key || !verifySignature(raw, sig, key)) return { ok: false, reason: "signature does not match the enrolled key" };

      if (body.type === "heartbeat") {
        const s = plain(body.summary);
        installs[installId] = { ...known, lastHeartbeatAt: new Date(now()).toISOString(), version: text(body.version, 32) || known.version,
          summary: { findings: Number.isFinite(s.findings) ? s.findings : null, highSent: Number.isFinite(s.highSent) ? s.highSent : null, deliveryFailed: Number.isFinite(s.deliveryFailed) ? s.deliveryFailed : null } };
        await save({ silentAlerted: false });
        return { ok: true, type: "heartbeat" };
      }
      if (body.type === "unenrol") {
        delete installs[installId];
        await save({});
        const settings = await loadSettings();
        await activity(settings.alertCompanyId || null, `Security hardening: watchdog removed (${known.host ?? installId})`, { installId });
        return { ok: true, type: "unenrol" };
      }
      if (body.type === "alert") {
        const a = plain(body.alert);
        const title = text(a.title, 240);
        const alertKey = text(a.key, 200);
        if (!title || !alertKey) return { ok: false, reason: "alert needs key and title" };
        const day = /^\d{4}-\d{2}-\d{2}$/.test(a.day ?? "") ? a.day : new Date(now()).toISOString().slice(0, 10);
        const alerts = await get(ALERTS_KEY, {});
        const sent = plain(alerts.sent);
        const dedup = `${alertKey}|${day}`;
        if (sent[dedup]) { await save({}); return { ok: true, type: "alert", duplicate: true, issue: sent[dedup] }; }
        const r = await raiseIssue({ title, description: `${text(a.body, 60000)}\n\n_Reported by the watchdog on ${known.host ?? installId}; created by the Security hardening plugin._`, priority: ["critical", "high", "medium", "low"].includes(a.priority) ? a.priority : "high" });
        if (!r.ok) return { ok: false, reason: r.reason }; // not saved: the watchdog keeps the alert in its outbox and retries
        const keep = Object.fromEntries(Object.entries(sent).filter(([k]) => k.split("|").pop() >= new Date(now() - 7 * 864e5).toISOString().slice(0, 10)));
        await ctx.state.set(ALERTS_KEY, { sent: { ...keep, [dedup]: r.issue }, recent: [{ at: new Date(now()).toISOString(), title, ...r.issue }, ...(alerts.recent ?? [])].slice(0, RECENT_ALERTS) });
        await save({});
        return { ok: true, type: "alert", issue: r.issue };
      }
      return { ok: false, reason: "unknown message type" };
    });
  }

  /** Create an alert issue as the plugin in the configured alert company/project (activity log entry either way). */
  async function raiseIssue({ title, description, priority = "high" }) {
    return raiseAlertIssue({ ctx, settings: await loadSettings(), title, description, priority, metadata: { source: "watchdog" } });
  }

  /** Job: one alert when the watchdog's heartbeats stop for more than 30 minutes (again after it recovered). */
  async function checkHeartbeat() {
    const w = await watchdogStatus();
    if (w.status !== "silent") return { status: w.status, alerted: false };
    const st = await get(WATCHDOG_KEY, {});
    if (st.silentAlerted) return { status: w.status, alerted: false };
    const r = await raiseIssue({ title: "[Security hardening] Watchdog stopped reporting", priority: "high",
      description: `No heartbeat from the watchdog since ${w.lastHeartbeatAt} (more than 30 minutes). It may have been stopped, removed or cut off from Paperclip. Check \`systemctl status itsec-collect.timer\` as the admin.` });
    if (r.ok) await exclusive(async () => ctx.state.set(WATCHDOG_KEY, { ...(await get(WATCHDOG_KEY, {})), silentAlerted: true }));
    return { status: w.status, alerted: r.ok };
  }

  return {
    watchdogStatus, hermesStatus, command, receive, raiseIssue, checkHeartbeat,
    /** onWebhook: a refused delivery throws, so the host answers 502 and records it as failed. */
    async handleWebhook(input) {
      const r = await receive(input);
      if (!r.ok) { log.warn(`watchdog webhook refused: ${r.reason}`); throw new WebhookRejected(r.reason); }
      return r;
    },
  };
}
