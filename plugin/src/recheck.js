// Alert tamper re-check (the port of the old watchdog's verify_alerts/recheck_alerts, host/itsec/itsec/notify.py and
// collect.py, for the alert issues the plugin creates itself: watchdog alerts, a failed self-test, a silent watchdog).
// Only the alert owners (config alertOwnerUserIds, default: adminUserIds) may close an alert. For N days after an
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
// The plugin re-raises by creating a new issue (issues.create) instead of reopening (that would need issues.update,
// which the plugin deliberately does not hold).
import { raiseAlertIssue, ALERT_LOG_KEY } from "./alerts.js";

export const DEFAULT_RECHECK_DAYS = 7;
export const MAX_RECHECK_DAYS = 90;
export const MAX_RERAISE = 3;
const CLOSED = new Set(["done", "cancelled"]);
const SKEW_MS = 120_000;
const KEEP_CLOSES = 5;
const DAY_MS = 864e5;

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

/** {kind: "agent"|"user"|"plugin"|"system"|"unknown", id} of a recorded close (an agent run counts as the agent). */
export function closerOf(c) {
  if (c.actorType === "agent" || c.agentId) return { kind: "agent", id: c.agentId ?? c.actorId ?? null };
  return { kind: c.actorType || "unknown", id: c.actorId ?? null };
}

export function createAlertRecheck({ ctx, now = Date.now }) {
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
    try { await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: "paperclip-sandbox-hardening", metadata }); }
    catch (e) { log.warn(`activity log entry not written: ${e.message}`, { message }); }
  }

  async function describeCloser(who, companyId) {
    if (!who) return "someone (Paperclip does not tell plugins who deleted or hid an issue)";
    if (who.kind === "agent") {
      let name = null;
      try { name = (await ctx.agents?.get?.(who.id, companyId))?.name ?? null; } catch { name = null; }
      return name ? `agent ${name} (${who.id})` : `agent ${who.id}`;
    }
    return `${who.kind} ${who.id ?? "(unknown id)"}`;
  }

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
    for (const [issueId, e] of entries) {
      const { days, owners } = await config(e.companyId);
      if (days === 0) { results.push({ issueId, result: "off" }); continue; }
      if (!(t - time(e.raisedAt) <= days * DAY_MS)) { remove.add(issueId); results.push({ issueId, result: "window over" }); continue; }
      let issue;
      try { issue = await ctx.issues.get(issueId, e.companyId); }
      catch (err) { results.push({ issueId, result: `not readable: ${err.message}` }); continue; } // trouble reading is not tampering
      let tamper = null;
      if (!issue || issue.hiddenAt) {
        tamper = { how: issue ? "hidden" : "deleted", who: null, at: null };
      } else if (CLOSED.has(issue.status)) {
        const c = findCloser(issue, await ctx.state.get(closesKey(issueId)).catch(() => null));
        if (!c) {
          const key = `${issue.status}|${issue.status === "done" ? issue.completedAt : issue.cancelledAt}`;
          if (e.unknownAlerted === key) { results.push({ issueId, result: "closer unknown (alerted)" }); continue; }
          const r = await raiseAlertIssue({ ctx, now, settings: { alertCompanyId: e.companyId, alertProjectId: e.projectId }, priority: "medium",
            metadata: { source: "alert-recheck", issueId, status: issue.status },
            title: `[Sandbox hardening] Alert closed, closer unknown: ${e.title}`.slice(0, 240),
            description: `The alert issue ${e.identifier ?? issueId} ("${e.title}") is ${issue.status}, but the plugin did not see who closed it (its worker may have been down at the time), so it cannot tell whether an alert owner closed it. Check the issue's activity: if anyone but an alert owner closed it, treat the alert as tampered with and reopen it.` });
          if (r.ok) update[issueId] = { ...e, unknownAlerted: key };
          results.push({ issueId, result: "closer unknown" });
          continue;
        }
        const who = closerOf(c);
        if (who.kind === "user" && owners.includes(who.id)) { results.push({ issueId, result: "closed by owner" }); continue; }
        tamper = { how: issue.status === "done" ? "closed (done)" : "cancelled", who, at: c.at };
      } else {
        results.push({ issueId, result: "open" });
        continue;
      }
      const whoText = await describeCloser(tamper.who, e.companyId);
      const reraised = (Number(e.reraised) || 0) + 1;
      if (reraised > MAX_RERAISE) {
        await activity(e.companyId, `Sandbox hardening alert tampered with again (${tamper.how} by ${whoText}); re-raise limit (${MAX_RERAISE}) reached: ${e.title}`,
          { source: "alert-recheck", issueId, closer: tamper.who, how: tamper.how });
        remove.add(issueId);
        results.push({ issueId, result: "limit reached", closer: tamper.who });
        continue;
      }
      const original = String(e.title).replace(/^(\[RE-RAISED\] )+/, "");
      const r = await raiseAlertIssue({ ctx, now, recheck: { reraised }, settings: { alertCompanyId: e.companyId, alertProjectId: e.projectId }, priority: "high",
        metadata: { source: "alert-recheck", tamperedIssueId: issueId, closer: tamper.who, how: tamper.how },
        title: `[RE-RAISED] ${original}`.slice(0, 240),
        description: `**This Sandbox hardening alert was ${tamper.how} by ${whoText}, who is not an alert owner.** Only the alert owners (${owners.length ? owners.join(", ") : "none configured"}) may close these alerts, so the plugin raised it again.\n\n- Original issue: ${e.identifier ?? issueId}\n${tamper.at ? `- ${tamper.how} at: ${tamper.at}\n` : ""}- Re-raise ${reraised} of ${MAX_RERAISE}\n\n---\n\n${e.description ?? ""}` });
      if (r.ok) remove.add(issueId); // the new issue is tracked instead; the old one is not checked again
      results.push({ issueId, result: r.ok ? "re-raised" : `re-raise failed: ${r.reason}`, closer: tamper.who, issue: r.issue });
    }
    if (remove.size || Object.keys(update).length) {
      // Merge into a fresh copy: alerts raised meanwhile (also the re-raised ones) stay.
      const fresh = (await ctx.state.get(ALERT_LOG_KEY).catch(() => null)) ?? {};
      const issues = { ...(fresh.issues ?? {}) };
      for (const id of remove) delete issues[id];
      for (const [id, v] of Object.entries(update)) if (issues[id]) issues[id] = { ...issues[id], unknownAlerted: v.unknownAlerted };
      await ctx.state.set(ALERT_LOG_KEY, { ...fresh, issues });
      for (const id of remove) await ctx.state.delete?.(closesKey(id))?.catch?.(() => {});
    }
    return results;
  }

  return { recordEvent, runJob };
}
