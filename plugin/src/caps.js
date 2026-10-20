// Daily token caps (plan step 4): a plugin job every 5 minutes, ported from a standalone usage-guard script. No SDK imports: the plugin
// context (`ctx`) is passed in, so tests use a fake one.
//
// Counting, per agent per UTC day (runs that STARTED today):
//   - tokens of a run = input + cache creation + output from the run's usage (usage_json of public.heartbeat_runs,
//     read with ctx.db.query; the plugin SDK has no heartbeat-run client);
//   - a run without usage (cancelled at handoff, reassigned, still running) is parsed from its run log: the
//     per-message usage of the Claude stream events, de-duplicated by message id. The log is the local file Paperclip
//     writes under <instance root>/data/run-logs (or $RUN_LOG_BASE_PATH); finished runs are cached for the day;
//   - hermes_local runs: the log names the Hermes session ("[hermes] Session: <id>"); the run counts the growth of
//     that session's totals (input + cache write + output) in the Hermes state.db since it was last counted, because
//     resumed sessions are cumulative.
// An adapter type counts as "reporting usage" once any of its runs yielded tokens; until then its agents show "usage
// not reported" and are never paused by a cap (a cap that cannot be measured is not enforced).
//
// Enforcing, per company (modes: enforce | report | off):
//   - an agent over its cap (per-agent override, else the company default cap) or every reporting agent when the
//     company total is over the company cap is paused (ctx.agents.pause, as the plugin), with one status comment;
//   - an agent the plugin paused that someone resumed while it is still over is paused again ("re-paused");
//   - report mode only comments, once per agent per day; off measures only;
//   - at the first run of a new UTC day: the previous day's summary is posted (with that day's date), and only the
//     agents the plugin paused are resumed. Human pauses are never touched.
//   - an error on one agent (log, Hermes db, pause) or one company is recorded and the job goes on.
// Caps model: install-wide template (default cap, company cap, mode) copied into each company the first time the job
// sees it ("new companies are never uncapped"), then edited per company; per-agent overrides on top.
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { validPath } from "./settings.js";
import { listAgents, listCompanies } from "./logic.js";
import { PLUGIN_ID } from "./manifest.js";
import { resolveTarget } from "./boxes.js";

export const CAPS_INSTALL_KEY = Object.freeze({ scopeKind: "instance", stateKey: "caps-install" });
export const CAPS_STATE_KEY = Object.freeze({ scopeKind: "instance", stateKey: "caps-state" });
export const CAPS_REPORTING_KEY = Object.freeze({ scopeKind: "instance", stateKey: "caps-reporting-adapters" });
export const CAPS_KEY = (companyId) => ({ scopeKind: "company", scopeId: String(companyId), stateKey: "caps" });
export const USAGE_KEY = (companyId) => ({ scopeKind: "company", scopeId: String(companyId), stateKey: "caps-usage" });
export const MODES = Object.freeze(["enforce", "report", "off"]);
export const DEFAULT_TEMPLATE = Object.freeze({ defaultCap: 600000, companyCap: 6000000, mode: "enforce" });
export const HERMES = "hermes_local";
const MAX_CAP = 1e12;
const ID_RE = /^[A-Za-z0-9-]{1,64}$/;
const NOT_PAUSABLE = new Set(["paused", "terminated", "pending_approval"]);
const HERMES_SEEN_DAYS = 14;

const plain = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
const num = (v) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Math.floor(Number(v)) : 0);
export const utcDay = (d) => d.toISOString().slice(0, 10);
const fmt = (n) => Number(n).toLocaleString("en-US");

// ---------------------------------------------------------------------------------------------------- settings

function parseCap(v, key, errors, { optional = false } = {}) {
  if (optional && (v === null || v === undefined || v === "")) return null;
  const n = typeof v === "string" ? Number(v.replace(/[\s_,]/g, "")) : v;
  if (!Number.isInteger(n) || n < 1 || n > MAX_CAP) { errors.push(`${key}: a whole number of tokens from 1 to ${MAX_CAP}`); return undefined; }
  return n;
}

/** Install-wide caps settings: the template new companies start from, and where Hermes keeps its session totals. */
export function normalizeInstall(input = {}) {
  const src = plain(input);
  const t = plain(src.template);
  const errors = [];
  const template = {
    defaultCap: parseCap(t.defaultCap ?? DEFAULT_TEMPLATE.defaultCap, "template.defaultCap", errors) ?? DEFAULT_TEMPLATE.defaultCap,
    companyCap: parseCap(t.companyCap ?? DEFAULT_TEMPLATE.companyCap, "template.companyCap", errors) ?? DEFAULT_TEMPLATE.companyCap,
    mode: MODES.includes(t.mode ?? DEFAULT_TEMPLATE.mode) ? (t.mode ?? DEFAULT_TEMPLATE.mode) : (errors.push("template.mode: enforce, report or off"), DEFAULT_TEMPLATE.mode),
  };
  const raw = typeof src.hermesStateDbs === "string" ? src.hermesStateDbs.split(/[\n,]/) : Array.isArray(src.hermesStateDbs) ? src.hermesStateDbs : [];
  const items = raw.map((v) => (typeof v === "string" ? v.trim() : v)).filter((v) => v !== "");
  const bad = items.filter((v) => typeof v !== "string" || !validPath(v));
  if (bad.length) errors.push(`hermesStateDbs: not an absolute path: ${bad.map(String).join(", ")}`);
  return { install: { template, hermesStateDbs: [...new Set(items.filter((v) => !bad.includes(v)))].slice(0, 16) }, errors };
}

/** A company's caps. `overrides` maps agent id -> cap. */
export function normalizeCompanyCaps(input = {}, fallback = DEFAULT_TEMPLATE) {
  const src = plain(input);
  const errors = [];
  const out = {
    defaultCap: parseCap(src.defaultCap ?? fallback.defaultCap, "defaultCap", errors) ?? fallback.defaultCap,
    companyCap: parseCap(src.companyCap ?? fallback.companyCap, "companyCap", errors) ?? fallback.companyCap,
    mode: MODES.includes(src.mode ?? fallback.mode) ? (src.mode ?? fallback.mode) : (errors.push("mode: enforce, report or off"), fallback.mode),
    statusIssueId: "",
    overrides: {},
  };
  const issue = typeof src.statusIssueId === "string" ? src.statusIssueId.trim() : "";
  if (issue && !ID_RE.test(issue)) errors.push("statusIssueId: not a valid issue id"); else out.statusIssueId = issue;
  for (const [id, v] of Object.entries(plain(src.overrides))) {
    if (!ID_RE.test(id)) { errors.push(`overrides: invalid agent id ${id}`); continue; }
    const n = parseCap(v, `overrides.${id}`, errors);
    if (n !== undefined) out.overrides[id] = n;
  }
  return { caps: out, errors };
}

export const effectiveCap = (caps, agentId) => caps.overrides?.[agentId] ?? caps.defaultCap;

// ---------------------------------------------------------------------------------------------------- counting

/** input + cache creation + output from a run's usage; null when the run recorded no usage. */
export function runUsageTokens(usage) {
  let u = usage;
  if (typeof u === "string") { try { u = JSON.parse(u); } catch { return null; } }
  if (!u || typeof u !== "object" || Array.isArray(u)) return null;
  const pick = (...keys) => keys.find((k) => u[k] !== undefined && u[k] !== null);
  const inK = pick("inputTokens", "input_tokens");
  const outK = pick("outputTokens", "output_tokens");
  const ccK = pick("cacheCreationInputTokens", "cache_creation_input_tokens", "cacheWriteTokens");
  if (!inK && !outK && !ccK) return null;
  return num(u[inK]) + num(u[ccK]) + num(u[outK]);
}

/**
 * A run log (ndjson of {ts, stream, chunk}) -> {tokens, hermesSessionId}. stdout chunks are joined first (a stream
 * event can be split across chunks); assistant events count once per message id.
 */
export function parseRunLog(content) {
  let out = "";
  for (const line of String(content ?? "").split("\n")) {
    if (!line.trim()) continue;
    let rec;
    try { rec = JSON.parse(line); } catch { continue; }
    if (typeof rec?.chunk === "string" && (rec.stream === undefined || rec.stream === "stdout")) out += rec.chunk;
  }
  const perMsg = new Map();
  let hermesSessionId = null;
  for (const raw of out.split("\n")) {
    const t = raw.trim();
    const m = /^\[hermes\] Session: (\S+)/.exec(t);
    if (m) { hermesSessionId = m[1]; continue; }
    if (!t.startsWith("{")) continue;
    let ev;
    try { ev = JSON.parse(t); } catch { continue; }
    const msg = ev?.type === "assistant" ? plain(ev.message) : null;
    const u = msg ? plain(msg.usage) : null;
    if (u && msg.id && Object.keys(u).length) perMsg.set(msg.id, num(u.input_tokens) + num(u.cache_creation_input_tokens) + num(u.output_tokens));
  }
  let tokens = 0;
  for (const v of perMsg.values()) tokens += v;
  return { tokens, hermesSessionId };
}

/** Read a run's log file from the run-log directory `base` of the Paperclip instance (the target's runLogBase);
 *  "" when there is none (cancelled before output, removed, or kept off this machine). */
export async function readRunLogFile(run, { base } = {}) {
  if (!base) throw new Error("the run-log directory is not known");
  if (!run.log_ref || (run.log_store && run.log_store !== "local_file")) return "";
  const file = path.resolve(base, String(run.log_ref));
  if (!file.startsWith(path.resolve(base) + path.sep)) throw new Error("run log path escapes the run-log directory");
  let buf;
  try { buf = await fs.promises.readFile(file); } catch (e) { if (e.code === "ENOENT") return ""; throw e; }
  if (run.log_compressed) { try { buf = zlib.gunzipSync(buf); } catch { /* stored uncompressed after all */ } }
  return buf.toString("utf8");
}

let sqliteModule;
/** Hermes session totals from its state.db files (read-only); null when no file knows the session. */
export async function hermesSessionTotalFromDbs(sessionId, dbs) {
  if (sqliteModule === undefined) sqliteModule = await import("node:sqlite").catch(() => null);
  if (!sqliteModule) return null;
  for (const file of dbs) {
    let db;
    try {
      db = new sqliteModule.DatabaseSync(file, { readOnly: true });
      const row = db.prepare("select coalesce(input_tokens,0)+coalesce(cache_write_tokens,0)+coalesce(output_tokens,0) as t from sessions where id = ?").get(sessionId);
      if (row) return Number(row.t) || 0;
    } catch { /* not a Hermes db, locked or unreadable: try the next */ }
    finally { try { db?.close(); } catch { /* ignore */ } }
  }
  return null;
}

/** <home>/.hermes/state.db and <home>/.hermes/profiles/<name>/state.db that exist (home: the Paperclip server's home). */
export function discoverHermesDbs(home) {
  if (!home) return [];
  const root = path.join(home, ".hermes");
  const out = [path.join(root, "state.db")];
  try { for (const p of fs.readdirSync(path.join(root, "profiles"))) out.push(path.join(root, "profiles", p, "state.db")); } catch { /* none */ }
  return out.filter((f) => { try { return fs.statSync(f).isFile(); } catch { return false; } });
}

// ---------------------------------------------------------------------------------------------------- decisions

export function freshState(date, previous = {}) {
  const seen = {};
  const cutoff = Date.parse(date) - HERMES_SEEN_DAYS * 86400000;
  for (const [sid, v] of Object.entries(plain(previous.hermesSeen))) if (Date.parse(v?.day ?? "") >= cutoff) seen[sid] = v;
  return { date, pausedByCap: {}, reported: [], summary: {}, logUsage: {}, hermesSeen: seen };
}

function loadState(raw, today) {
  const s = plain(raw);
  if (typeof s.date !== "string") return freshState(today);
  return { date: s.date, pausedByCap: plain(s.pausedByCap), reported: Array.isArray(s.reported) ? s.reported : [], summary: plain(s.summary), logUsage: plain(s.logUsage), hermesSeen: plain(s.hermesSeen) };
}

/** What to do in one company now. `used[id]` is a number, or undefined when it could not be measured. */
export function decideCompany({ agents, used, isReporting, caps, state }) {
  const live = agents.filter((a) => a.status !== "terminated");
  const measured = (a) => isReporting(a) && Number.isFinite(used[a.id]);
  const companyUsed = live.filter(measured).reduce((s, a) => s + used[a.id], 0);
  const overCompany = companyUsed > caps.companyCap;
  const actions = [];
  for (const a of live) {
    if (!measured(a) || NOT_PAUSABLE.has(a.status)) continue;
    const cap = effectiveCap(caps, a.id);
    const overOwn = used[a.id] > cap;
    if (!overOwn && !overCompany) continue;
    const reason = overOwn ? `${fmt(used[a.id])} tokens today > cap ${fmt(cap)}` : `company ${fmt(companyUsed)} tokens today > company cap ${fmt(caps.companyCap)}`;
    if (caps.mode === "enforce") actions.push({ type: state.pausedByCap[a.id] ? "repause" : "pause", agent: a, reason });
    else if (caps.mode === "report" && !state.reported.includes(a.id)) actions.push({ type: "report", agent: a, reason });
  }
  return { companyUsed, overCompany, actions };
}

export function summaryText({ agents, used, errors = {}, isReporting, caps, state }) {
  const live = agents.filter((a) => a.status !== "terminated");
  const lines = live.map((a) => `${a.name}: ${!isReporting(a) ? "usage not reported" : errors[a.id] ? "usage unknown (error)" : `${fmt(used[a.id] ?? 0)} / cap ${fmt(effectiveCap(caps, a.id))}`}`);
  const companyUsed = live.filter((a) => isReporting(a) && Number.isFinite(used[a.id])).reduce((s, a) => s + used[a.id], 0);
  const paused = live.filter((a) => state.pausedByCap[a.id]).map((a) => a.name);
  return [...lines, `company: ${fmt(companyUsed)} / ${fmt(caps.companyCap)}`, `paused by caps: ${paused.join(", ") || "none"}`].join("\n");
}

// ---------------------------------------------------------------------------------------------------- service

/**
 * @param {object} o
 * @param {object} o.ctx           plugin context (companies, agents, db, issues, state, activity, logger)
 * @param {Function} o.assertAdmin hardening.assertAdmin
 * @param {Function} [o.now]       () => Date
 * @param {Function} [o.runLogBase]          () => the instance's run-log directory (throws while the target is unknown)
 * @param {Function} [o.userHome]            () => the Paperclip server's home directory (where ~/.hermes is looked for)
 * @param {Function} [o.readRunLog]          (run) => Promise<string>
 * @param {Function} [o.hermesSessionTotal]  (sessionId, install) => Promise<number|null>
 */
export function createCaps({ ctx, assertAdmin, now = () => new Date(), runLogBase = () => { throw new Error("the run-log directory is not known"); }, userHome = () => null,
  readRunLog = (run) => readRunLogFile(run, { base: runLogBase() }), hermesSessionTotal = null }) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {} };
  const hermesTotal = hermesSessionTotal ?? ((sid, install) => hermesSessionTotalFromDbs(sid, install.hermesStateDbs.length ? install.hermesStateDbs : discoverHermesDbs(userHome())));
  let queue = Promise.resolve();
  const exclusive = (fn) => { const run = queue.then(fn, fn); queue = run.catch(() => {}); return run; };

  const loadInstall = async () => normalizeInstall(await ctx.state.get(CAPS_INSTALL_KEY).catch(() => null) ?? {}).install;
  const loadReporting = async () => plain(await ctx.state.get(CAPS_REPORTING_KEY).catch(() => null));
  async function storedCaps(companyId) {
    const raw = await ctx.state.get(CAPS_KEY(companyId)).catch(() => null);
    return raw ? normalizeCompanyCaps(raw).caps : null;
  }
  /** The company's caps; a company seen for the first time gets a copy of the install-wide template. */
  async function ensureCaps(companyId, install) {
    const have = await storedCaps(companyId);
    if (have) return have;
    const caps = normalizeCompanyCaps({ ...install.template, createdFromTemplate: true }).caps;
    await ctx.state.set(CAPS_KEY(companyId), { ...caps, createdFromTemplateAt: now().toISOString() });
    return caps;
  }

  async function logActivity(companyId, message, metadata) {
    try { await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: PLUGIN_ID, metadata }); }
    catch (e) { log.warn(`activity log entry not written: ${e.message}`); }
  }
  /** One status comment per event, on the company's status issue; without one, an activity log entry. */
  async function announce(companyId, caps, text) {
    if (caps.statusIssueId) {
      try { await ctx.issues.createComment(caps.statusIssueId, text, companyId); return; }
      catch (e) { log.warn(`caps status comment failed for company ${companyId}: ${e.message}`); }
    }
    await logActivity(companyId, text.split("\n")[0], { text });
  }

  async function queryRuns(companyId, day) {
    const start = `${day}T00:00:00.000Z`;
    const end = new Date(Date.parse(start) + 86400000).toISOString();
    return ctx.db.query(
      "SELECT r.id, r.agent_id, r.status, r.started_at, r.finished_at, r.usage_json, r.log_store, r.log_ref, r.log_compressed FROM public.heartbeat_runs r WHERE r.company_id = $1::uuid AND r.started_at >= $2::timestamptz AND r.started_at < $3::timestamptz",
      [companyId, start, end],
    );
  }

  async function runTokens(agent, run, state, install, today) {
    const id = String(run.id);
    if (state.logUsage[id] !== undefined) return state.logUsage[id];
    const finished = Boolean(run.finished_at);
    const usage = runUsageTokens(run.usage_json);
    const hermes = agent.adapterType === HERMES;
    if (!hermes && usage !== null) return usage;
    if (!run.log_ref) return usage ?? 0;
    const parsed = parseRunLog(await readRunLog(run));
    let total = usage ?? parsed.tokens;
    if (hermes && parsed.hermesSessionId && finished) {
      const now_ = await hermesTotal(parsed.hermesSessionId, install);
      if (now_ !== null) {
        const seen = num(state.hermesSeen[parsed.hermesSessionId]?.tokens);
        total = Math.max(now_ - seen, 0);
        state.hermesSeen[parsed.hermesSessionId] = { tokens: Math.max(now_, seen), day: today };
      }
    }
    if (finished) state.logUsage[id] = total;
    return total;
  }

  let running = false;
  async function runJob() {
    if (running) return { skipped: true };
    running = true;
    try { return await exclusive(job); } finally { running = false; }
  }

  async function job() {
    const today = utcDay(now());
    const install = await loadInstall();
    const reporting = await loadReporting();
    let state = loadState(await ctx.state.get(CAPS_STATE_KEY).catch(() => null), today);
    const save = () => ctx.state.set(CAPS_STATE_KEY, state);
    const result = { date: today, companies: {}, errors: [] };

    const seen = {};
    for (const c of await listCompanies(ctx)) {
      try { seen[c.id] = { company: c, caps: await ensureCaps(c.id, install), agents: await listAgents(ctx, c.id) }; }
      catch (e) { result.errors.push({ companyId: c.id, error: e.message }); log.warn(`caps: company ${c.id} skipped: ${e.message}`); }
    }

    if (state.date !== today) {
      const ended = state.date;
      for (const [cid, text] of Object.entries(state.summary)) {
        if (seen[cid]) await announce(cid, seen[cid].caps, `Daily token caps: summary for ${ended} (UTC)\n${text}`);
      }
      for (const [aid, cid] of Object.entries(state.pausedByCap)) {
        const s = seen[cid];
        const agent = s?.agents.find((a) => a.id === aid);
        if (!agent || agent.status !== "paused" || s.caps.mode !== "enforce") continue;
        try {
          await ctx.agents.resume(aid, cid);
          await announce(cid, s.caps, `Daily token caps resumed ${agent.name} (new day ${today})`);
        } catch (e) {
          result.errors.push({ companyId: cid, agentId: aid, error: e.message });
          await announce(cid, s.caps, `Daily token caps could not resume ${agent.name} (${e.message}); left paused for a person to resume`);
        }
      }
      state = freshState(today, state);
      await save();
    }

    for (const [cid, { caps, agents }] of Object.entries(seen)) {
      try {
        const runs = await queryRuns(cid, today);
        const byAgent = {};
        for (const r of runs) (byAgent[String(r.agent_id)] ??= []).push(r);
        const used = {}, errors = {};
        for (const a of agents) {
          if (a.status === "terminated") continue;
          try {
            let total = 0;
            for (const r of byAgent[a.id] ?? []) {
              const t = await runTokens(a, r, state, install, today);
              if (t > 0) reporting[a.adapterType] = today;
              total += t;
            }
            used[a.id] = total;
          } catch (e) { errors[a.id] = e.message; log.warn(`caps: usage of agent ${a.name} not measured: ${e.message}`); }
        }
        const isReporting = (a) => Boolean(reporting[a.adapterType]);
        const d = decideCompany({ agents, used, isReporting, caps, state });
        for (const act of d.actions) {
          const a = act.agent;
          try {
            if (act.type === "report") {
              state.reported.push(a.id);
              await announce(cid, caps, `Daily token caps (report only): ${a.name} is over: ${act.reason}`);
              continue;
            }
            await ctx.agents.pause(a.id, cid);
            if (act.type === "pause") state.pausedByCap[a.id] = cid;
            a.status = "paused";
            await announce(cid, caps, `Daily token caps ${act.type === "repause" ? "re-paused (resumed while still over)" : "paused"} ${a.name}: ${act.reason}`);
          } catch (e) { errors[a.id] = errors[a.id] ?? `pause failed: ${e.message}`; log.warn(`caps: ${act.type} of ${a.name} failed: ${e.message}`); }
        }
        state.summary[cid] = summaryText({ agents, used, errors, isReporting, caps, state });
        const snapshot = {
          date: today, at: now().toISOString(), companyUsed: d.companyUsed, overCompany: d.overCompany,
          agents: Object.fromEntries(agents.filter((a) => a.status !== "terminated").map((a) => [a.id, { used: used[a.id] ?? null, reported: isReporting(a), error: errors[a.id] ?? null, pausedByCap: Boolean(state.pausedByCap[a.id]) }])),
        };
        await ctx.state.set(USAGE_KEY(cid), snapshot);
        result.companies[cid] = { companyUsed: d.companyUsed, actions: d.actions.map((x) => ({ type: x.type, agentId: x.agent.id })), errors };
      } catch (e) {
        result.errors.push({ companyId: cid, error: e.message });
        log.warn(`caps: company ${cid} not measured: ${e.message}`);
      }
      await save();
    }
    await ctx.state.set(CAPS_REPORTING_KEY, reporting);
    await save();
    return result;
  }

  /** Caps and today's usage for the Agent boxes rows (read-only; a company the job has not seen shows the template). */
  async function view(companyId, agents) {
    const install = await loadInstall();
    const stored = await storedCaps(companyId);
    const caps = stored ?? normalizeCompanyCaps(install.template).caps;
    const reporting = await loadReporting();
    const snap = plain(await ctx.state.get(USAGE_KEY(companyId)).catch(() => null));
    const fresh = snap.date === utcDay(now());
    const state = plain(await ctx.state.get(CAPS_STATE_KEY).catch(() => null));
    const paused = plain(state.pausedByCap);
    return {
      defaultCap: caps.defaultCap, companyCap: caps.companyCap, mode: caps.mode, statusIssueId: caps.statusIssueId,
      fromTemplate: !stored, template: install.template, hermesStateDbs: install.hermesStateDbs,
      date: utcDay(now()), measuredAt: fresh ? snap.at : null, companyUsed: fresh ? snap.companyUsed : null,
      agents: Object.fromEntries(agents.map((a) => {
        const s = fresh ? plain(plain(snap.agents)[a.id]) : {};
        return [a.id, { cap: effectiveCap(caps, a.id), override: caps.overrides[a.id] ?? null, reported: Boolean(reporting[a.adapterType]),
          used: fresh && Number.isFinite(s.used) ? s.used : null, error: s.error ?? null, pausedByCap: Boolean(paused[a.id]) }];
      })),
    };
  }

  return {
    runJob,
    view,
    loadInstall,

    /** Company default cap, company cap, mode and status issue (admin). */
    saveCompanyCaps(params = {}, context) {
      return exclusive(async () => {
        const { actor, companyId } = await resolveTarget(assertAdmin, params, context, { write: true });
        const install = await loadInstall();
        const current = (await storedCaps(companyId)) ?? normalizeCompanyCaps(install.template).caps;
        const { caps, errors } = normalizeCompanyCaps({ ...current, defaultCap: params.defaultCap, companyCap: params.companyCap, mode: params.mode, statusIssueId: params.statusIssueId ?? current.statusIssueId });
        if (errors.length) return { ok: false, errors };
        await ctx.state.set(CAPS_KEY(companyId), caps);
        await logActivity(companyId, `Daily token caps changed: default ${fmt(caps.defaultCap)}, company ${fmt(caps.companyCap)}, ${caps.mode}`, { userId: actor.userId, defaultCap: caps.defaultCap, companyCap: caps.companyCap, mode: caps.mode, statusIssueId: caps.statusIssueId });
        return { ok: true, caps };
      });
    },

    /** Per-agent override (admin); cap null or "" returns the agent to the company default. */
    saveAgentCap(params = {}, context) {
      return exclusive(async () => {
        const { actor, companyId } = await resolveTarget(assertAdmin, params, context, { write: true });
        const agentId = typeof params.agentId === "string" ? params.agentId : "";
        const agent = agentId ? await ctx.agents.get(agentId, companyId) : null;
        if (!agent) return { ok: false, error: "agent not found in this company" };
        const errors = [];
        const cap = parseCap(params.cap, "cap", errors, { optional: true });
        if (errors.length) return { ok: false, errors };
        const install = await loadInstall();
        const caps = (await storedCaps(companyId)) ?? normalizeCompanyCaps(install.template).caps;
        if (cap === null) delete caps.overrides[agentId]; else caps.overrides[agentId] = cap;
        await ctx.state.set(CAPS_KEY(companyId), caps);
        await logActivity(companyId, `Daily token caps: ${agent.name} ${cap === null ? "back to the company default" : `capped at ${fmt(cap)}`}`, { userId: actor.userId, agentId, cap });
        return { ok: true, cap, effective: effectiveCap(caps, agentId) };
      });
    },

    /** Install-wide template for new companies and the Hermes state.db paths (admin). */
    saveInstall(params = {}, context) {
      return exclusive(async () => {
        const { actor, companyId } = await resolveTarget(assertAdmin, params, context, { write: true });
        const { install, errors } = normalizeInstall({ template: params.template, hermesStateDbs: params.hermesStateDbs });
        if (errors.length) return { ok: false, errors };
        await ctx.state.set(CAPS_INSTALL_KEY, install);
        await logActivity(companyId, "Daily token caps: install-wide template changed", { userId: actor.userId, ...install });
        return { ok: true, install };
      });
    },
  };
}
