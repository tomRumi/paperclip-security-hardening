// Alert tamper re-check (the port of the old watchdog's verify_alerts/recheck_alerts, host/itsec/itsec/notify.py and
// collect.py, for the alert issues the plugin creates itself: watchdog alerts, a failed self-test, a silent watchdog).
// Only the alert owners (config alertOwnerUserIds, default: adminUserIds) and the host company's ITSec agent (under the
// conditions below) may close an alert. For N days after an
// alert was raised (config alertRecheckDays, default 7, 0 = off) the "alert-recheck" job re-reads it; if anyone else
// (an agent, another user, a plugin, the system) closed it (done or cancelled), or it was deleted or hidden, the job
// creates ONE new HIGH alert issue "[RE-RAISED] ..." naming who closed it (at most MAX_RERAISE times per alert chain)
// and stops checking the old one, so a later run does not repeat it.
//
// Who closed it. The plugin SDK has NO read path for the activity log: no ctx method needs `activity.read`, the
// `activity_log` table is not one of the core tables a plugin may read (PLUGIN_DATABASE_CORE_READ_TABLES), and
// ctx.authorization.audit.search is the authorization audit, which needs a company-scoped invocation (not a job). The
// Issue has no updatedBy field (only createdBy*, completedAt, cancelledAt). The actor comes from the host's
// "issue.updated" domain event instead (capability events.subscribe): its envelope carries actorType/actorId, the
// actor of the activity entry the host writes for the change (action "issue.updated"); recordEvent stores the close
// events of tracked alert issues per issue, and the job matches them to the issue's status and close time. A close
// whose event the worker missed (worker down) has no known closer: one MEDIUM alert per close, no re-raise (as the
// old watchdog's "integrity unknown"). A deletion has no event, so its actor is never known: it is always re-raised.
// The ITSec agent as closer. The ITSec agent of the CURRENT host company (itsecHostCompanyId equals the alert's company and
// the agent id is the one the plugin verified, ITSEC_REF_KEY) may close an alert, but only after its own resolution
// comment: authored by that agent, not deleted, in the format of resolutionOf() below, created strictly BEFORE the close and
// after any earlier recorded close of the same issue (so an old comment does not cover a reopened alert). The close time is
// the earlier of the event time and the issue's completedAt/cancelledAt; the comment times come from issues.listComments.
// Without such a comment the close is re-raised like any other. Accepted closes are remembered (ITSEC_CLOSED_KEY) and
// listed in the hardening-status document. Any other agent, an agent of another company or an old host agent is re-raised.
// Only a REAL agent run counts (another plugin could otherwise forge both parts: Paperclip's plugin issues.update takes
// any actorAgentId and records it as the event payload's agentId, with actorType "plugin"; the plugin createComment takes
// any authorAgentId). So (1) the close event's own actor must be actorType "agent" with actorId = the ITSec agent id
// (the payload's agentId is ignored), and (2) the resolution comment must carry createdByRunId: Paperclip sets it only
// from the authenticated agent run (route actor), a plugin-created comment never has one.
// Fail closed. If the comments cannot be read, the verification stays pending: each failed run is logged and counted
// (entry.verifyFailures, cumulative for that close: a run that could not even read the issue neither counts nor resets it);
// at MAX_VERIFY_FAILURES failed runs (about 30 minutes) or when the re-check window ends with it still pending, whichever
// comes first, the close is treated as unverified and re-raised. The pending state is cleared only when a verification
// completed (comments read and a decision made: accepted, re-raised, or the issue is no longer closed); a failed re-raise
// keeps the alert (entry.reraiseFailed, also for a close that was never pending) and is retried on every later run, also
// after the window. An unverified agent close never stands.
// The plugin re-raises by creating a new issue (issues.create) instead of reopening (that would need issues.update,
// which the plugin deliberately does not hold).
import { raiseAlertIssue, ALERT_LOG_KEY } from "./alerts.js";
import { PLUGIN_ID } from "./manifest.js";
import { ITSEC_REF_KEY, ITSEC_CLOSED_KEY } from "./itsec-declarations.js";

export const DEFAULT_RECHECK_DAYS = 7;
export const MAX_RECHECK_DAYS = 90;
export const MAX_RERAISE = 3;
export const MAX_VERIFY_FAILURES = 3;
const CLOSED = new Set(["done", "cancelled"]);
const SKEW_MS = 120_000;
const KEEP_CLOSES = 5;
const DAY_MS = 864e5;
const MIN_EVIDENCE_CHARS = 10;
const MAX_RESOLUTION_CHARS = 200;
const KEEP_ITSEC_CLOSED = 100;

/** Close events seen for one tracked alert issue: [{eventId, at, actorType, actorId, agentId, status}] (newest last). */
export const closesKey = (issueId) => ({ scopeKind: "issue", scopeId: String(issueId), stateKey: "alert-closes" });

const plainList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string" && x) : []);
const time = (v) => (v === null || v === undefined || v === "" ? NaN : new Date(v).getTime());

/** Owners and re-check days from the plugin config of the alert's company. */
export function recheckConfig(cfg = {}) {
  const d = cfg?.alertRecheckDays;
  const days = Number.isInteger(d) && d >= 0 && d <= MAX_RECHECK_DAYS ? d : DEFAULT_RECHECK_DAYS;
  const own = plainList(cfg?.alertOwnerUserIds);
  return { days, owners: own.length ? own : plainList(cfg?.adminUserIds) };
}

/** The close candidate in an "issue.updated" event, or null. The payload is the activity entry's details: the new
 *  status is details.changes.status.to or details.status (the shapes the old watchdog read from the activity log);
 *  an event without any status is kept as a candidate whose time must match the issue's close time. */
export function closeFromEvent(event) {
  const p = event?.payload && typeof event.payload === "object" ? event.payload : {};
  const raw = p.changes?.status?.to ?? p.status ?? null;
  const status = typeof raw === "string" ? raw : null;
  if (status !== null && !CLOSED.has(status)) return null;
  return { eventId: event.eventId ?? null, at: event.occurredAt ?? null, actorType: event.actorType ?? null, actorId: event.actorId ?? null,
    agentId: typeof p.agentId === "string" ? p.agentId : null, status };
}

/** The recorded close that explains the issue's current close, or null. */
export function findCloser(issue, closes) {
  const closedAt = time(issue.status === "done" ? issue.completedAt : issue.cancelledAt);
  const fits = (c) => {
    if (c.status && c.status !== issue.status) return false;
    const at = time(c.at);
    if (Number.isFinite(closedAt)) return Number.isFinite(at) && at >= closedAt - SKEW_MS && (c.status !== null || Math.abs(at - closedAt) <= SKEW_MS);
    return c.status !== null;
  };
  return (closes ?? []).filter(fits).sort((a, b) => (time(a.at) || 0) - (time(b.at) || 0)).pop() ?? null;
}

/** {kind: "agent"|"user"|"plugin"|"system"|"unknown", id} of a recorded close. Only the event's own actor decides: a
 *  plugin close that names an agent (payload agentId, which a plugin may set freely) stays a plugin close, and the claimed
 *  agent is kept in `claimedAgentId` for the alert text only. */
export function closerOf(c) {
  const who = { kind: c.actorType || "unknown", id: c.actorId ?? null };
  if (c.agentId && c.actorType !== "agent") who.claimedAgentId = c.agentId;
  return who;
}

/**
 * The resolution of a comment, or null when it is not a valid resolution comment. The format (documented in the ITSec
 * agent's instructions, src/itsec/AGENTS.md): the first non-empty line starts with "Resolution:" followed by the
 * verdict in words; a later line starts with "Evidence:" and the evidence (on that line and below it) has at least
 * 10 characters. Case-sensitive; nothing else is checked, the owner reads the text.
 * @returns {{summary: string}|null}  summary = the first line after "Resolution:" (cut at 200 characters)
 */
export function resolutionOf(body) {
  const lines = String(body ?? "").replace(/\r\n?/g, "\n").trimStart().split("\n");
  const head = /^Resolution:[ \t]*(\S.*)$/.exec(lines[0]);
  if (!head) return null;
  const at = lines.findIndex((l, i) => i > 0 && /^Evidence:/.test(l));
  if (at < 0) return null;
  const evidence = [lines[at].slice("Evidence:".length), ...lines.slice(at + 1)].join("").replace(/\s/g, "");
  if (evidence.length < MIN_EVIDENCE_CHARS) return null;
  return { summary: head[1].trim().slice(0, MAX_RESOLUTION_CHARS) };
}

export function createAlertRecheck({ ctx, now = Date.now, loadSettings = null }) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {} };

  /** events.subscribe handler for "issue.updated": remember close events of tracked alert issues. */
  async function recordEvent(event) {
    const issueId = event?.entityId;
    if (!issueId || (event.entityType && event.entityType !== "issue")) return false;
    const tracked = await ctx.state.get(ALERT_LOG_KEY).catch(() => null);
    if (!tracked?.issues?.[issueId]) return false;
    const c = closeFromEvent(event);
    if (!c) return false;
    const prev = (await ctx.state.get(closesKey(issueId)).catch(() => null)) ?? [];
    if (c.eventId && prev.some((p) => p.eventId === c.eventId)) return false;
    await ctx.state.set(closesKey(issueId), [...prev, c].slice(-KEEP_CLOSES));
    return true;
  }

  async function activity(companyId, message, metadata) {
    try { await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: PLUGIN_ID, metadata }); }
    catch (e) { log.warn(`activity log entry not written: ${e.message}`, { message }); }
  }

  /** The agent id of the ITSec agent of the current host company for this alert company, or null. */
  async function currentItsecAgent(companyId) {
    const host = (await loadSettings?.().catch(() => null))?.itsecHostCompanyId;
    if (!host || String(host) !== String(companyId)) return null;
    return (await ctx.state.get(ITSEC_REF_KEY(companyId)).catch(() => null))?.agentId ?? null;
  }

  /** The valid resolution comment ({summary, at, closedAt}) the ITSec agent wrote before this close, or null. It must come
   *  from an agent run (createdByRunId set by Paperclip; a plugin-created comment has none). Throws when the comments cannot be read. */
  async function priorResolution({ issueId, companyId, issue, closes, c, agentId }) {
    const closeAt = Math.min(...[time(c.at), time(issue.status === "done" ? issue.completedAt : issue.cancelledAt)].filter(Number.isFinite));
    if (!Number.isFinite(closeAt)) return null;
    // An earlier close of the same issue means it was reopened since: a comment from before it does not count.
    const earlier = Math.max(0, ...(closes ?? []).filter((x) => x !== c && time(x.at) < time(c.at)).map((x) => time(x.at)));
    const found = [];
    for (const m of await ctx.issues.listComments(issueId, companyId)) {
      const made = time(m?.createdAt);
      if (!m || m.deletedAt || String(m.authorAgentId ?? "") !== agentId || !(typeof m.createdByRunId === "string" && m.createdByRunId) || !(made < closeAt && made > earlier)) continue;
      const res = resolutionOf(m.body);
      if (res) found.push({ ...res, at: made, closedAt: new Date(closeAt).toISOString() });
    }
    return found.sort((a, b) => a.at - b.at).pop() ?? null;
  }

  /** Remember an accepted ITSec close once (the re-check sees the same closed alert on every run until its window ends). */
  async function noteItsecClose(companyId, entry) {
    try {
      const list = (await ctx.state.get(ITSEC_CLOSED_KEY(companyId)).catch(() => null)) ?? [];
      if (list.some((x) => x.issueId === entry.issueId && x.closedAt === entry.closedAt)) return;
      await ctx.state.set(ITSEC_CLOSED_KEY(companyId), [...list, entry].slice(-KEEP_ITSEC_CLOSED));
      await activity(companyId, `Security hardening alert closed by the ITSec agent: ${entry.title}`, { source: "alert-recheck", issueId: entry.issueId, itsecAgent: true, resolution: entry.resolution });
    } catch (e) { log.warn(`ITSec close not remembered: ${e.message}`); }
  }

  async function describeCloser(who, companyId) {
    if (!who) return "someone (Paperclip does not tell plugins who deleted or hid an issue)";
    const agentText = async (id) => {
      let name = null;
      try { name = (await ctx.agents?.get?.(id, companyId))?.name ?? null; } catch { name = null; }
      return name ? `agent ${name} (${id})` : `agent ${id}`;
    };
    if (who.kind === "agent") return agentText(who.id);
    const base = `${who.kind} ${who.id ?? "(unknown id)"}`;
    return who.claimedAgentId ? `${base}, naming ${await agentText(who.claimedAgentId)} as the actor` : base;
  }

  /** Pending markers (verifyFailures, verifySince, reraiseFailed) per alert as last decided, kept in memory in case the state write fails. */
  const pendingMemo = new Map();

  /** Job "alert-recheck". Returns [{issueId, result}] for the tests and the log. */
  async function runJob() {
    const tracked = (await ctx.state.get(ALERT_LOG_KEY).catch(() => null)) ?? {};
    const entries = Object.entries(tracked.issues ?? {});
    const results = [];
    if (!entries.length || typeof ctx.issues?.get !== "function") return results;
    const cfgs = new Map();
    const config = async (companyId) => {
      if (!cfgs.has(companyId)) cfgs.set(companyId, recheckConfig((await ctx.config.get(companyId).catch(() => null)) ?? {}));
      return cfgs.get(companyId);
    };
    const remove = new Set();
    const update = {};
    const t = now();
    // One alert; `overdue` = the window is over but an ITSec close of it is still unverified (see the header).
    // Returns true when the check completed (a decision was made), false when it must be repeated (the issue or its
    // comments could not be read, or the re-raise failed): then the pending state of the entry stays.
    const check = async (issueId, e, owners, overdue, off = false) => {
      let issue;
      try { issue = await ctx.issues.get(issueId, e.companyId); }
      catch (err) { results.push({ issueId, result: `not readable: ${err.message}` }); return false; } // trouble reading is not tampering
      let tamper = null, itsecId = null, unverified = 0;
      if (!issue || issue.hiddenAt) {
        tamper = { how: issue ? "hidden" : "deleted", who: null, at: null };
      } else if (CLOSED.has(issue.status)) {
        const closes = await ctx.state.get(closesKey(issueId)).catch(() => null);
        const closedAt = issue.status === "done" ? issue.completedAt : issue.cancelledAt;
        const key = `${issue.status}|${closedAt}`;
        // An event justifies at most one close: once the ITSec agent's close was accepted, a later close of the reopened alert
        // (a different close time) must be explained by a newer event, not by the old one (it fits within the clock skew).
        const acc = e.itsecAccepted;
        const reclosed = Boolean(acc) && Number.isFinite(time(closedAt)) && acc.key !== key;
        const c = findCloser(issue, reclosed ? (closes ?? []).filter((x) => x.eventId !== acc.eventId && !(time(x.at) <= time(acc.at))) : closes);
        if (!c) {
          if (e.unknownAlerted === key) { results.push({ issueId, result: "closer unknown (alerted)" }); return true; }
          const r = await raiseAlertIssue({ ctx, now, settings: { alertCompanyId: e.companyId, alertProjectId: e.projectId }, priority: "medium",
            metadata: { source: "alert-recheck", issueId, status: issue.status },
            title: `[Security hardening] Alert closed, closer unknown: ${e.title}`.slice(0, 240),
            description: `The alert issue ${e.identifier ?? issueId} ("${e.title}") is ${issue.status}, but the plugin did not see who closed it (its worker may have been down at the time), so it cannot tell whether an alert owner closed it. Check the issue's activity: if anyone but an alert owner closed it, treat the alert as tampered with and reopen it.` });
          update[issueId] = r.ok ? { unknownAlerted: key } : { reraiseFailed: true }; // not raised: kept and retried, also after the window
          results.push({ issueId, result: r.ok ? "closer unknown" : `closer unknown, alert failed: ${r.reason}` });
          return Boolean(r.ok);
        }
        const who = closerOf(c);
        if (who.kind === "user" && owners.includes(who.id)) { results.push({ issueId, result: "closed by owner" }); return true; }
        itsecId = who.kind === "agent" && who.id ? await currentItsecAgent(e.companyId) : null;
        if (itsecId && itsecId === who.id) {
          let res = null;
          try { res = await priorResolution({ issueId, companyId: e.companyId, issue, closes, c, agentId: itsecId }); }
          catch (err) {
            // Fail closed: keep the verification pending and retry, but an unverified agent close must not stand.
            const failures = (Number(e.verifyFailures) || 0) + 1;
            log.warn(`ITSec close of alert ${issueId} not verified, comments unreadable (run ${failures} of ${MAX_VERIFY_FAILURES}${overdue ? ", re-check window over" : ""}): ${err.message}`, { issueId, source: "alert-recheck" });
            if (!overdue && failures < MAX_VERIFY_FAILURES) {
              update[issueId] = { verifyFailures: failures, verifySince: e.verifySince ?? new Date(t).toISOString() };
              results.push({ issueId, result: `not readable: ${err.message}` });
              return false;
            }
            unverified = failures;
          }
          if (res) {
            await noteItsecClose(e.companyId, { issueId, identifier: e.identifier ?? null, title: e.title, closedAt: res.closedAt, resolution: res.summary });
            if (!acc || acc.key !== key) update[issueId] = { ...update[issueId], itsecAccepted: { eventId: c.eventId, at: c.at, key } };
            results.push({ issueId, result: "closed by ITSec agent" });
            return true;
          }
        }
        tamper = { how: issue.status === "done" ? "closed (done)" : "cancelled", who, at: c.at };
      } else {
        results.push({ issueId, result: "open" });
        return true;
      }
      const whoText = await describeCloser(tamper.who, e.companyId);
      // The current ITSec agent may close an alert only after its own resolution comment; this close had none, so the alert says so.
      const itsecCloser = Boolean(itsecId) && itsecId === tamper.who?.id && tamper.who?.kind === "agent";
      const itsecText = unverified
        ? ` That is the ITSec agent, which may close an alert only after its own comment that starts with "Resolution:" and has an "Evidence:" section, written before the close. The plugin could not read the alert's comments to check for one (${unverified} failed run${unverified === 1 ? "" : "s"}${overdue ? (off ? ", and the re-check has been switched off" : ", and the re-check window is over") : ""}), and an unverified close does not stand. Check the agent's resolution comment yourself.`
        : ` That is the ITSec agent, which may close an alert only after its own comment that starts with "Resolution:" and has an "Evidence:" section, written before the close. The plugin found no such comment. Check its run, its instructions and its sandbox (it may have read injected text).`;
      const reraised = (Number(e.reraised) || 0) + 1;
      if (reraised > MAX_RERAISE) {
        await activity(e.companyId, `Security hardening alert tampered with again (${tamper.how} by ${whoText}); re-raise limit (${MAX_RERAISE}) reached: ${e.title}`,
          { source: "alert-recheck", issueId, closer: tamper.who, how: tamper.how });
        remove.add(issueId);
        results.push({ issueId, result: "limit reached", closer: tamper.who });
        return true;
      }
      const original = String(e.title).replace(/^(\[RE-RAISED\] )+/, "");
      const r = await raiseAlertIssue({ ctx, now, recheck: { reraised }, settings: { alertCompanyId: e.companyId, alertProjectId: e.projectId }, priority: "high",
        metadata: { source: "alert-recheck", tamperedIssueId: issueId, closer: tamper.who, how: tamper.how, ...(itsecCloser ? { itsecAgent: true } : {}) },
        title: `[RE-RAISED] ${original}`.slice(0, 240),
        description: `**This Security hardening alert was ${tamper.how} by ${whoText}, who is not an alert owner.**${itsecCloser ? itsecText : ""} Only the alert owners (${owners.length ? owners.join(", ") : "none configured"})${itsecCloser ? "" : " and, with a resolution comment, the host company's ITSec agent"} may close these alerts, so the plugin raised it again.\n\n- Original issue: ${e.identifier ?? issueId}\n${tamper.at ? `- ${tamper.how} at: ${tamper.at}\n` : ""}- Re-raise ${reraised} of ${MAX_RERAISE}\n\n---\n\n${e.description ?? ""}` });
      if (r.ok) remove.add(issueId); // the new issue is tracked instead; the old one is not checked again
      else update[issueId] = { reraiseFailed: true, ...(unverified ? { verifyFailures: unverified, verifySince: e.verifySince ?? new Date(t).toISOString() } : {}) }; // not raised: kept and retried on later runs, also after the window
      results.push({ issueId, result: r.ok ? "re-raised" : `re-raise failed: ${r.reason}`, closer: tamper.who, issue: r.issue });
      return Boolean(r.ok);
    };
    for (const [issueId, base] of entries) {
      const e = { ...base, ...pendingMemo.get(issueId) }; // markers whose last write failed are still known here
      const pending = Boolean(e.verifyFailures || e.reraiseFailed);
      const { days, owners } = await config(e.companyId);
      // Switched off: an alert with a pending verification or a failed re-raise is raised once now, not kept or dropped silently.
      if (days === 0 && !pending) { results.push({ issueId, result: "off" }); continue; }
      const overdue = days === 0 || !(t - time(e.raisedAt) <= days * DAY_MS);
      if (overdue && !pending) { remove.add(issueId); results.push({ issueId, result: "window over" }); continue; }
      const done = await check(issueId, e, owners, overdue, days === 0);
      if (!done || remove.has(issueId)) continue; // not settled: the entry (and its pending state) stays for the next run
      if (overdue) remove.add(issueId); // settled after the window: stop tracking
      else if (pending) update[issueId] = { ...update[issueId], verifyFailures: undefined, verifySince: undefined, reraiseFailed: undefined }; // completed: no longer pending
    }
    for (const id of [...pendingMemo.keys()]) if (!tracked.issues?.[id] || remove.has(id)) pendingMemo.delete(id);
    for (const [id, v] of Object.entries(update)) {
      if (v.verifyFailures || v.reraiseFailed) pendingMemo.set(id, { verifyFailures: v.verifyFailures, verifySince: v.verifySince, reraiseFailed: v.reraiseFailed });
      else if ("reraiseFailed" in v || "verifyFailures" in v) pendingMemo.delete(id);
    }
    if (remove.size || Object.keys(update).length) {
      // Merge into a fresh copy: alerts raised meanwhile (also the re-raised ones) stay.
      const fresh = (await ctx.state.get(ALERT_LOG_KEY).catch(() => null)) ?? {};
      const issues = { ...(fresh.issues ?? {}) };
      for (const id of remove) delete issues[id];
      for (const [id, v] of Object.entries(update)) {
        if (!issues[id]) continue;
        const next = { ...issues[id], ...v };
        for (const key of Object.keys(next)) if (next[key] === undefined) delete next[key];
        issues[id] = next;
      }
      try {
        await ctx.state.set(ALERT_LOG_KEY, { ...fresh, issues });
        for (const id of remove) await ctx.state.delete?.(closesKey(id))?.catch?.(() => {});
      } catch (err) {
        // The next run re-reads the old state: pending markers survive in pendingMemo, so no pending alert is dropped for it.
        log.warn(`alert re-check state not saved: ${err.message}`, { source: "alert-recheck" });
        results.push({ issueId: null, result: `state not saved: ${err.message}` });
      }
    }
    return results;
  }

  return { recordEvent, runJob };
}
