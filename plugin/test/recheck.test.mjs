// Alert tamper re-check (src/recheck.js, src/alerts.js trackAlert, wiring in src/worker.js) with a fake plugin
// context: issues live in a Map, close events are delivered the way the host's "issue.updated" event carries them
// (envelope actorType/actorId, payload = the activity details).
import test from "node:test";
import assert from "node:assert/strict";
import { raiseAlertIssue, trackAlert, ALERT_LOG_KEY, MAX_TRACKED_ALERTS } from "../src/alerts.js";
import { createAlertRecheck, recheckConfig, closesKey, resolutionOf, MAX_RERAISE, MAX_VERIFY_FAILURES } from "../src/recheck.js";
import { ITSEC_REF_KEY, ITSEC_CLOSED_KEY } from "../src/itsec-declarations.js";
import { register } from "../src/worker.js";

const T0 = Date.parse("2026-10-18T10:00:00.000Z");
const MIN = 60_000, DAY = 864e5;

function setup({ config = { adminUserIds: ["u-owner"] }, hostCompanyId = "" } = {}) {
  const state = new Map(), issues = new Map(), comments = new Map(), created = [], logs = [], warns = [];
  const clock = { t: T0 };
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const reads = [];
  const ctx = {
    state: {
      get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null),
      set: async (key, v) => { state.set(k(key), structuredClone(v)); },
      delete: async (key) => { state.delete(k(key)); },
    },
    config: { get: async (companyId) => (companyId === "c1" ? config : {}) },
    activity: { log: async (e) => { logs.push(e); } },
    issues: {
      create: async (input) => {
        created.push(input);
        const id = `i-${created.length}`;
        issues.set(id, { id, identifier: `ENG-${created.length}`, companyId: input.companyId, title: input.title, description: input.description, status: input.status, completedAt: null, cancelledAt: null, hiddenAt: null });
        return { id, identifier: `ENG-${created.length}` };
      },
      get: async (id, companyId) => { reads.push(id); const i = issues.get(id); return i && i.companyId === companyId ? structuredClone(i) : null; },
      listComments: async (id) => structuredClone(comments.get(id) ?? []),
    },
    agents: { get: async (id) => (id === "a-rogue" ? { id, name: "Rogue Coder" } : null) },
    logger: { info() {}, warn: (m) => { warns.push(m); }, error() {}, debug() {} },
  };
  const r = createAlertRecheck({ ctx, now: () => clock.t, loadSettings: async () => ({ itsecHostCompanyId: hostCompanyId }) });
  const raise = (title = "[Security hardening] Watchdog stopped reporting") =>
    raiseAlertIssue({ ctx, now: () => clock.t, settings: { alertCompanyId: "c1", alertProjectId: "p1" }, title, description: "evidence lines", metadata: { source: "watchdog" } });
  /** Close an issue as `actor` and deliver the host's event for it. */
  let n = 0;
  async function close(issueId, { actorType, actorId, agentId, status = "done", deliver = true }) {
    const at = new Date(clock.t).toISOString();
    Object.assign(issues.get(issueId), { status, ...(status === "done" ? { completedAt: at } : { cancelledAt: at }) });
    if (deliver) return r.recordEvent({ eventId: `ev-${++n}`, eventType: "issue.updated", occurredAt: at, actorType, actorId, entityId: issueId, entityType: "issue", companyId: "c1",
      payload: { identifier: "x", status, ...(agentId ? { agentId } : {}), _previous: { status: "todo" } } });
    return null;
  }
  /** A comment on an alert issue, created at the current clock time. */
  let cn = 0;
  // createdByRunId: Paperclip sets it for a comment written by an agent run (from the run's JWT); a comment a plugin creates
  // (issues.createComment with any authorAgentId) never has one. Default: a real agent run for agent comments.
  const comment = (issueId, { agentId = null, userId = null, body, at = clock.t, deletedAt = null, runId = agentId ? "run-1" : null }) => {
    comments.set(issueId, [...(comments.get(issueId) ?? []), { id: `cm-${++cn}`, issueId, authorType: agentId ? "agent" : "user", authorAgentId: agentId, authorUserId: userId, createdByRunId: runId, body, createdAt: new Date(at).toISOString(), deletedAt }]);
  };
  const tracked = () => Object.keys(state.get(k(ALERT_LOG_KEY))?.issues ?? {});
  return { ctx, r, state, issues, comments, created, logs, warns, clock, raise, close, comment, tracked, reads };
}

test("config: owners default to adminUserIds, days default 7, 0 = off, invalid days fall back", () => {
  assert.deepEqual(recheckConfig({ adminUserIds: ["u1"] }), { days: 7, owners: ["u1"] });
  assert.deepEqual(recheckConfig({ adminUserIds: ["u1"], alertOwnerUserIds: ["u2"], alertRecheckDays: 0 }), { days: 0, owners: ["u2"] });
  assert.equal(recheckConfig({ alertRecheckDays: -1 }).days, 7);
  assert.equal(recheckConfig({ alertRecheckDays: "3" }).days, 7);
});

test("an owner's close is accepted: no new issue, the alert stays tracked", async () => {
  const s = setup();
  const a = await s.raise();
  s.clock.t += 30 * MIN;
  assert.equal(await s.close(a.issue.issueId, { actorType: "user", actorId: "u-owner" }), true);
  s.clock.t += 5 * MIN;
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result), ["closed by owner"]);
  assert.equal(s.created.length, 1);
  assert.deepEqual(s.tracked(), [a.issue.issueId]);
});

test("an explicit alertOwnerUserIds list replaces adminUserIds", async () => {
  const s = setup({ config: { adminUserIds: ["u-owner"], alertOwnerUserIds: ["u-sec"] } });
  const a = await s.raise();
  await s.close(a.issue.issueId, { actorType: "user", actorId: "u-owner" });
  assert.deepEqual((await s.r.runJob()).map((x) => x.result), ["re-raised"]);
});

test("an agent's close triggers ONE HIGH re-raise naming the agent; a repeat run does not duplicate", async () => {
  const s = setup();
  const a = await s.raise();
  s.clock.t += 2 * 60 * MIN;
  // An agent run: the activity entry's actor is the agent (agentId in the details, as the old watchdog read it).
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", agentId: "a-rogue" });
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result), ["re-raised"]);
  assert.equal(s.created.length, 2);
  const again = s.created[1];
  assert.equal(again.priority, "high");
  assert.equal(again.companyId, "c1");
  assert.equal(again.projectId, "p1");
  assert.equal(again.assigneeAgentId, undefined, "wakes no agent");
  assert.equal(again.title, "[RE-RAISED] [Security hardening] Watchdog stopped reporting");
  assert.match(again.description, /closed \(done\) by agent Rogue Coder \(a-rogue\), who is not an alert owner/);
  assert.match(again.description, /Original issue: ENG-1/);
  assert.match(again.description, /evidence lines/);
  assert.ok(s.logs.some((l) => /Security hardening alert: \[RE-RAISED\]/.test(l.message) && l.metadata.closer.kind === "agent"));
  // The old issue is no longer checked; the new one is.
  assert.deepEqual(s.tracked(), ["i-2"]);
  assert.equal(s.state.has(`issue:${a.issue.issueId}:alert-closes`), false);
  for (let i = 0; i < 3; i++) { s.clock.t += 10 * MIN; await s.r.runJob(); }
  assert.equal(s.created.length, 2, "no duplicate on later runs");
  // The re-raised alert keeps its count and is re-checked itself.
  assert.equal((await s.ctx.state.get(ALERT_LOG_KEY)).issues["i-2"].reraised, 1);
});

test("another user's cancel triggers the re-raise too; an event delivered twice is stored once", async () => {
  const s = setup();
  const a = await s.raise();
  const ev = { eventId: "dup", eventType: "issue.updated", occurredAt: new Date(T0).toISOString(), actorType: "user", actorId: "u-other", entityId: a.issue.issueId, entityType: "issue", companyId: "c1", payload: { changes: { status: { from: "todo", to: "cancelled" } } } };
  Object.assign(s.issues.get(a.issue.issueId), { status: "cancelled", cancelledAt: ev.occurredAt });
  assert.equal(await s.r.recordEvent(ev), true);
  assert.equal(await s.r.recordEvent(ev), false);
  assert.equal((await s.ctx.state.get(closesKey(a.issue.issueId))).length, 1);
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result), ["re-raised"]);
  assert.match(s.created[1].description, /cancelled by user u-other, who is not an alert owner/);
  await s.r.runJob();
  assert.equal(s.created.length, 2);
});

test("a deleted alert is re-raised once (its actor is unknown); open or reopened alerts are left alone", async () => {
  const s = setup();
  const a = await s.raise();
  const b = await s.raise("[Security hardening] Self-test failed: Own box");
  s.issues.get(b.issue.issueId).status = "in_progress"; // status changes other than a close are not tampering
  s.issues.delete(a.issue.issueId);
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result).sort(), ["open", "re-raised"]);
  assert.match(s.created[2].description, /deleted by someone/);
  await s.r.runJob();
  assert.equal(s.created.length, 3);
});

test("a close whose event was missed: one MEDIUM 'closer unknown' alert, no re-raise, not repeated", async () => {
  const s = setup();
  const a = await s.raise();
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", deliver: false });
  assert.deepEqual((await s.r.runJob()).map((x) => x.result), ["closer unknown"]);
  assert.equal(s.created.length, 2);
  assert.equal(s.created[1].priority, "medium");
  assert.match(s.created[1].title, /closer unknown/);
  assert.equal((await s.r.runJob()).find((x) => x.issueId === a.issue.issueId).result, "closer unknown (alerted)");
  assert.equal(s.created.length, 2);
});

test("an old owner close does not cover a later close whose event was missed", async () => {
  const s = setup();
  const a = await s.raise();
  await s.close(a.issue.issueId, { actorType: "user", actorId: "u-owner" });
  s.clock.t += 60 * MIN;
  s.issues.get(a.issue.issueId).status = "todo";        // reopened
  s.clock.t += 60 * MIN;
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", deliver: false });
  assert.deepEqual((await s.r.runJob()).map((x) => x.result), ["closer unknown"]);
});

test("nothing is checked after the re-check window; the alert is dropped from tracking", async () => {
  const s = setup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 2 } });
  const a = await s.raise();
  s.clock.t += 2 * DAY + MIN;
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", agentId: "a-rogue" });
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result), ["window over"]);
  assert.deepEqual(s.reads, [], "the issue is not even read");
  assert.equal(s.created.length, 1);
  assert.deepEqual(s.tracked(), []);
});

test("re-check days 0 = off: nothing read, nothing raised", async () => {
  const s = setup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 0 } });
  const a = await s.raise();
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", agentId: "a-rogue" });
  assert.deepEqual((await s.r.runJob()).map((x) => x.result), ["off"]);
  assert.deepEqual(s.reads, []);
  assert.equal(s.created.length, 1);
});

test(`re-raises stop after ${MAX_RERAISE} per alert chain (then only an activity entry)`, async () => {
  const s = setup();
  await s.raise();
  for (let i = 1; i <= MAX_RERAISE + 1; i++) {
    const id = s.tracked()[0];
    s.clock.t += MIN;
    await s.close(id, { actorType: "agent", actorId: "a-rogue", agentId: "a-rogue" });
    await s.r.runJob();
  }
  assert.equal(s.created.length, 1 + MAX_RERAISE);
  assert.equal(s.created.at(-1).title, "[RE-RAISED] [Security hardening] Watchdog stopped reporting", "the prefix is not stacked");
  assert.ok(s.logs.some((l) => /re-raise limit \(3\) reached/.test(l.message)));
  assert.deepEqual(s.tracked(), []);
});

test("events for issues that are not tracked alerts, and non-close changes, are ignored", async () => {
  const s = setup();
  const a = await s.raise();
  assert.equal(await s.r.recordEvent({ eventId: "e1", entityId: "other", entityType: "issue", actorType: "agent", actorId: "x", payload: { status: "done" } }), false);
  assert.equal(await s.r.recordEvent({ eventId: "e2", entityId: a.issue.issueId, entityType: "issue", actorType: "agent", actorId: "x", payload: { status: "in_progress" } }), false);
  assert.equal(await s.ctx.state.get(closesKey(a.issue.issueId)), null);
});

test("worker wiring: issue.updated is subscribed and the alert-recheck job re-raises", async () => {
  const s = setup();
  const reg = { jobs: {}, events: {} };
  const ctx = { ...s.ctx, data: { register() {} }, actions: { register() {} }, jobs: { register: (key, fn) => { reg.jobs[key] = fn; } },
    events: { on: (name, fn) => { reg.events[name] = fn; } } };
  register(ctx, { recheck: createAlertRecheck({ ctx, now: () => s.clock.t }) });
  assert.ok(reg.jobs["alert-recheck"] && reg.events["issue.updated"]);
  const a = await s.raise();
  Object.assign(s.issues.get(a.issue.issueId), { status: "done", completedAt: new Date(T0).toISOString() });
  await reg.events["issue.updated"]({ eventId: "w1", occurredAt: new Date(T0).toISOString(), actorType: "agent", actorId: "a-rogue", entityId: a.issue.issueId, entityType: "issue", companyId: "c1", payload: { status: "done" } });
  await reg.jobs["alert-recheck"]({ jobKey: "alert-recheck" });
  assert.equal(s.created.length, 2);
  assert.match(s.created[1].description, /agent Rogue Coder/);
});

// ------------------------------------------------------------------------------------------- the ITSec agent as a closer
const HOST = "c1";
const GOOD = "Resolution: false alarm, the watchdog restarted by itself\nEvidence:\nwatchdog log shows a heartbeat at 10:05 and the self-test passed";
async function itsecSetup(opts = {}) {
  const s = setup({ hostCompanyId: HOST, ...opts });
  await s.ctx.state.set(ITSEC_REF_KEY(HOST), { agentId: "a-itsec" });
  const a = await s.raise();
  return { ...s, id: a.issue.issueId };
}
const closeAsItsec = (s, agentId = "a-itsec") => s.close(s.id, { actorType: "agent", actorId: agentId, agentId });
const results = async (s) => (await s.r.runJob()).map((x) => x.result);

test("resolutionOf: needs a first line 'Resolution: <text>' and an 'Evidence:' section of at least 10 characters", () => {
  assert.deepEqual(resolutionOf(GOOD), { summary: "false alarm, the watchdog restarted by itself" });
  assert.deepEqual(resolutionOf("\n  \r\nResolution: ok\r\nEvidence: log line 12 shows it\n"), { summary: "ok" }, "evidence on the same line, CRLF, leading blank lines");
  assert.equal(resolutionOf("Resolution: ok\nEvidence: x"), null, "too little evidence");
  assert.equal(resolutionOf("Resolution: ok\nEvidence:\n   \n"), null, "empty evidence");
  assert.equal(resolutionOf("Resolution: ok"), null, "no evidence section");
  assert.equal(resolutionOf("Resolution:\nEvidence: lots of evidence here"), null, "empty resolution");
  assert.equal(resolutionOf("Verdict: ok\nEvidence: lots of evidence here"), null, "wrong marker");
  assert.equal(resolutionOf("Evidence: lots of evidence here\nResolution: ok"), null, "marker not first");
  assert.equal(resolutionOf("Some text first\nResolution: ok\nEvidence: lots of evidence here"), null, "marker not on the first line");
  assert.equal(resolutionOf("resolution: ok\nevidence: lots of evidence here"), null, "case-sensitive");
  assert.equal(resolutionOf(null), null);
  assert.deepEqual(resolutionOf("Resolution: ok\nEvidence: x\ny z\nw v u t s r q"), { summary: "ok" }, "evidence may continue on the lines below");
  assert.equal(resolutionOf(`Resolution: ${"x".repeat(500)}\nEvidence: lots of evidence here`).summary.length, 200);
});

test("ITSec close with its own earlier valid resolution comment: no re-raise, listed, activity entry", async () => {
  const s = await itsecSetup();
  s.clock.t += 10 * MIN;
  s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN;
  await closeAsItsec(s);
  s.clock.t += 5 * MIN;
  assert.deepEqual(await results(s), ["closed by ITSec agent"]);
  assert.equal(s.created.length, 1, "nothing re-raised");
  assert.deepEqual(s.tracked(), [s.id], "still tracked");
  const list = await s.ctx.state.get(ITSEC_CLOSED_KEY(HOST));
  assert.deepEqual(list, [{ issueId: s.id, identifier: "ENG-1", title: "[Security hardening] Watchdog stopped reporting", closedAt: new Date(T0 + 11 * MIN).toISOString(), resolution: "false alarm, the watchdog restarted by itself" }]);
  assert.equal(s.logs.filter((l) => /closed by the ITSec agent/.test(l.message)).length, 1);
  // The next runs see the same close: listed once, logged once.
  assert.deepEqual(await results(s), ["closed by ITSec agent"]);
  assert.equal((await s.ctx.state.get(ITSEC_CLOSED_KEY(HOST))).length, 1);
  assert.equal(s.logs.filter((l) => /closed by the ITSec agent/.test(l.message)).length, 1);
});

test("ITSec close by cancelling with a valid resolution comment is accepted too", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await s.close(s.id, { actorType: "agent", actorId: "a-itsec", agentId: "a-itsec", status: "cancelled" });
  assert.deepEqual(await results(s), ["closed by ITSec agent"]);
});

test("ITSec close without any comment is re-raised, and the new alert says what was missing", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; await closeAsItsec(s);
  assert.deepEqual(await results(s), ["re-raised"]);
  assert.equal(s.created.length, 2);
  assert.match(s.created[1].description, /agent ITSec|agent a-itsec/);
  assert.match(s.created[1].description, /starts with "Resolution:" and has an "Evidence:" section, written before the close/);
  assert.equal(s.logs.at(-1).metadata.itsecAgent, true);
  assert.equal(await s.ctx.state.get(ITSEC_CLOSED_KEY(HOST)), null);
});

test("ITSec close with the comment created AFTER the close is re-raised", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; await closeAsItsec(s);
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  assert.deepEqual(await results(s), ["re-raised"]);
  assert.equal(await s.ctx.state.get(ITSEC_CLOSED_KEY(HOST)), null);
});

test("ITSec close with a comment created after the close time (a comment 1 s later) is re-raised: no tolerance", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN;
  s.comment(s.id, { agentId: "a-itsec", body: GOOD, at: s.clock.t + 1000 }); // 1 s after the close: not before it
  await closeAsItsec(s);
  assert.deepEqual(await results(s), ["re-raised"]);
});

test("ITSec close with a resolution comment by ANOTHER author (agent, user) is re-raised", async () => {
  for (const author of [{ agentId: "a-rogue" }, { userId: "u-owner" }]) {
    const s = await itsecSetup();
    s.clock.t += MIN; s.comment(s.id, { ...author, body: GOOD });
    s.clock.t += MIN; await closeAsItsec(s);
    assert.deepEqual(await results(s), ["re-raised"], JSON.stringify(author));
  }
});

test("ITSec close with a malformed or deleted comment is re-raised", async () => {
  for (const c of [{ body: "Resolution: fixed" }, { body: "all good" }, { body: "Resolution: ok\nEvidence: x" }, { body: GOOD, deletedAt: new Date(T0).toISOString() }]) {
    const s = await itsecSetup();
    s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", ...c });
    s.clock.t += MIN; await closeAsItsec(s);
    assert.deepEqual(await results(s), ["re-raised"], c.body);
  }
});

test("a resolution comment from before an earlier close does not cover a later close of the reopened alert", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await closeAsItsec(s);
  assert.deepEqual(await results(s), ["closed by ITSec agent"]);
  s.clock.t += MIN; s.issues.get(s.id).status = "todo"; // an owner reopens it
  s.clock.t += MIN; await closeAsItsec(s);              // and the agent closes it again, without a new comment
  assert.deepEqual(await results(s), ["re-raised"]);
  // With a new comment between the reopening and the close it would have been fine.
  const t = await itsecSetup();
  t.clock.t += MIN; t.comment(t.id, { agentId: "a-itsec", body: GOOD });
  t.clock.t += MIN; await closeAsItsec(t);
  await results(t);
  t.clock.t += MIN; t.issues.get(t.id).status = "todo";
  t.clock.t += MIN; t.comment(t.id, { agentId: "a-itsec", body: GOOD.replace("false alarm", "still a false alarm") });
  t.clock.t += MIN; await closeAsItsec(t);
  assert.deepEqual(await results(t), ["closed by ITSec agent"]);
  assert.equal((await t.ctx.state.get(ITSEC_CLOSED_KEY(HOST))).length, 2);
});

test("another agent closing is re-raised even with a valid resolution comment on the issue; ITSec wording only for the ITSec agent", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await closeAsItsec(s, "a-rogue");
  assert.deepEqual(await results(s), ["re-raised"]);
  assert.match(s.created[1].description, /agent Rogue Coder/);
  assert.doesNotMatch(s.created[1].description, /Resolution:/);
  assert.equal(s.logs.at(-1).metadata.itsecAgent, undefined);
});

test("a non-admin user closing is re-raised even with a valid ITSec resolution comment; an owner close is unchanged", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await s.close(s.id, { actorType: "user", actorId: "u-other" });
  assert.deepEqual(await results(s), ["re-raised"]);
  const o = await itsecSetup();
  o.clock.t += MIN; await o.close(o.id, { actorType: "user", actorId: "u-owner" });
  assert.deepEqual(await results(o), ["closed by owner"]);
  assert.equal(await o.ctx.state.get(ITSEC_CLOSED_KEY(HOST)), null);
});

test("an old host agent is re-raised: the host moved to another company, or the agent id is not the verified one", async () => {
  // The alert company is no longer the host company (the mark moved); the old company still has its agent reference.
  const moved = setup({ hostCompanyId: "c2" });
  await moved.ctx.state.set(ITSEC_REF_KEY(HOST), { agentId: "a-itsec" });
  const a = await moved.raise();
  moved.clock.t += MIN; moved.comment(a.issue.issueId, { agentId: "a-itsec", body: GOOD });
  moved.clock.t += MIN; await moved.close(a.issue.issueId, { actorType: "agent", actorId: "a-itsec", agentId: "a-itsec" });
  assert.deepEqual(await results(moved), ["re-raised"]);
  // No host company at all.
  const none = setup({ hostCompanyId: "" });
  await none.ctx.state.set(ITSEC_REF_KEY(HOST), { agentId: "a-itsec" });
  const b = await none.raise();
  none.clock.t += MIN; none.comment(b.issue.issueId, { agentId: "a-itsec", body: GOOD });
  none.clock.t += MIN; await none.close(b.issue.issueId, { actorType: "agent", actorId: "a-itsec", agentId: "a-itsec" });
  assert.deepEqual(await results(none), ["re-raised"]);
  // The host company has a new agent; the previous one (same company) is not the verified one any more.
  const s = await itsecSetup();
  await s.ctx.state.set(ITSEC_REF_KEY(HOST), { agentId: "a-itsec-new" });
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await closeAsItsec(s);
  assert.deepEqual(await results(s), ["re-raised"]);
});

test("without a settings loader (no host known) the ITSec agent is treated like any other agent", async () => {
  const s = setup();
  await s.ctx.state.set(ITSEC_REF_KEY(HOST), { agentId: "a-itsec" });
  const r = createAlertRecheck({ ctx: s.ctx, now: () => s.clock.t });
  const a = await s.raise();
  s.clock.t += MIN; s.comment(a.issue.issueId, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-itsec", agentId: "a-itsec", deliver: false });
  await r.recordEvent({ eventId: "x1", occurredAt: new Date(s.clock.t).toISOString(), actorType: "agent", actorId: "a-itsec", entityId: a.issue.issueId, entityType: "issue", companyId: HOST, payload: { status: "done", agentId: "a-itsec" } });
  assert.deepEqual((await r.runJob()).map((x) => x.result), ["re-raised"]);
});

test("comments that cannot be read are not tampering: the run reports it and re-raises nothing", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await closeAsItsec(s);
  s.ctx.issues.listComments = async () => { throw new Error("host busy"); };
  assert.deepEqual(await results(s), ["not readable: host busy"]);
  assert.equal(s.created.length, 1);
  assert.deepEqual(s.tracked(), [s.id]);
});

// ------------------------------------------------------------------------------------- forgery and fail-closed verification
test("a close by a PLUGIN that names the ITSec agent (payload agentId) is re-raised, even with a valid agent resolution comment", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN;
  // Paperclip's plugin issues.update accepts any actorAgentId: the event is actorType "plugin", actorId = the plugin, payload.agentId = the claim.
  await s.close(s.id, { actorType: "plugin", actorId: "some-other-plugin", agentId: "a-itsec" });
  assert.deepEqual(await results(s), ["re-raised"]);
  assert.equal(s.created.length, 2);
  assert.match(s.created[1].description, /closed \(done\) by plugin some-other-plugin, naming agent a-itsec as the actor, who is not an alert owner/);
  assert.equal(await s.ctx.state.get(ITSEC_CLOSED_KEY(HOST)), null);
  assert.equal(s.logs.at(-1).metadata.itsecAgent, undefined);
});

test("a real ITSec agent close with a resolution comment a PLUGIN created in its name (no createdByRunId) is re-raised", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD, runId: null }); // plugin createComment with authorAgentId = ITSec
  s.clock.t += MIN; await closeAsItsec(s);
  assert.deepEqual(await results(s), ["re-raised"]);
  assert.match(s.created[1].description, /The plugin found no such comment/);
  assert.equal(await s.ctx.state.get(ITSEC_CLOSED_KEY(HOST)), null);
  // The same close with a run-authored comment is accepted.
  const ok = await itsecSetup();
  ok.clock.t += MIN; ok.comment(ok.id, { agentId: "a-itsec", body: GOOD, runId: "run-9" });
  ok.clock.t += MIN; await closeAsItsec(ok);
  assert.deepEqual(await results(ok), ["closed by ITSec agent"]);
});

test("a comment created at exactly the close time is not before it: re-raised", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN;
  s.comment(s.id, { agentId: "a-itsec", body: GOOD }); // same clock tick as the close
  await closeAsItsec(s);
  assert.deepEqual(await results(s), ["re-raised"]);
});

test("unreadable comments: each failed run is logged and counted, the third consecutive failure re-raises (fail closed)", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await closeAsItsec(s);
  s.ctx.issues.listComments = async () => { throw new Error("host busy"); };
  for (let n = 1; n < MAX_VERIFY_FAILURES; n++) {
    s.clock.t += 10 * MIN;
    assert.deepEqual(await results(s), ["not readable: host busy"]);
    assert.equal(s.warns.length, n);
    assert.equal((await s.ctx.state.get(ALERT_LOG_KEY)).issues[s.id].verifyFailures, n);
    assert.equal(s.created.length, 1);
  }
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["re-raised"]);
  assert.equal(s.warns.length, MAX_VERIFY_FAILURES);
  assert.match(s.warns.at(-1), /not verified, comments unreadable \(run 3 of 3\): host busy/);
  assert.equal(s.created.length, 2);
  assert.match(s.created[1].description, /could not read the alert's comments.*3 failed runs.*an unverified close does not stand/);
  assert.deepEqual(s.tracked(), ["i-2"]);
  assert.equal(await s.ctx.state.get(ITSEC_CLOSED_KEY(HOST)), null);
});

test("unreadable comments until the re-check window ends: the alert is re-raised, not silently dropped", async () => {
  const s = await itsecSetup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 1 } });
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await closeAsItsec(s);
  s.ctx.issues.listComments = async () => { throw new Error("host busy"); };
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["not readable: host busy"]); // 1 failure, pending
  s.clock.t += DAY;                                                    // the window is over, still unreadable
  assert.deepEqual(await results(s), ["re-raised"]);
  assert.ok(s.warns.some((w) => /re-check window over/.test(w)));
  assert.match(s.created[1].description, /re-check window is over/);
  assert.deepEqual(s.tracked(), ["i-2"]);
  // Without a pending verification the window end still just drops the alert.
  const t = await itsecSetup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 1 } });
  t.clock.t += DAY + MIN;
  assert.deepEqual(await results(t), ["window over"]);
});

test("a pending verification that can be read again is verified normally and the counter is cleared", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await closeAsItsec(s);
  const read = s.ctx.issues.listComments;
  s.ctx.issues.listComments = async () => { throw new Error("host busy"); };
  s.clock.t += 10 * MIN; await results(s);
  assert.equal((await s.ctx.state.get(ALERT_LOG_KEY)).issues[s.id].verifyFailures, 1);
  s.ctx.issues.listComments = read;
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["closed by ITSec agent"]);
  const entry = (await s.ctx.state.get(ALERT_LOG_KEY)).issues[s.id];
  assert.equal(entry.verifyFailures, undefined);
  assert.equal(entry.verifySince, undefined);
  assert.equal(s.created.length, 1);
});

// ------------------------------------------------------------- the pending state is cleared only by a completed verification
const unreadable = (s) => { s.ctx.issues.listComments = async () => { throw new Error("host busy"); }; };
const pendingOf = async (s) => (await s.ctx.state.get(ALERT_LOG_KEY)).issues[s.id];

test("pending verification: an issue that cannot be read keeps the pending state, and the window end still re-raises", async () => {
  const s = await itsecSetup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 1 } });
  s.clock.t += MIN; await closeAsItsec(s); // no comment at all
  unreadable(s);
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["not readable: host busy"]);
  assert.equal((await pendingOf(s)).verifyFailures, 1);
  const get = s.ctx.issues.get;
  s.ctx.issues.get = async () => { throw new Error("get busy"); };
  s.clock.t += DAY;                                    // the window is over, the issue cannot be read
  assert.deepEqual(await results(s), ["not readable: get busy"]);
  assert.equal((await pendingOf(s)).verifyFailures, 1, "not cleared, not counted");
  s.ctx.issues.get = get;
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["re-raised"]);  // not dropped as "window over"
  assert.equal(s.created.length, 2);
  assert.match(s.created[1].description, /re-check window is over/);
  assert.deepEqual(s.tracked(), ["i-2"]);
});

test("pending verification: a failed re-raise keeps the pending state and is retried until it works, never dropped", async () => {
  const s = await itsecSetup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 1 } });
  s.clock.t += MIN; await closeAsItsec(s);
  unreadable(s);
  const create = s.ctx.issues.create;
  for (let n = 1; n < MAX_VERIFY_FAILURES; n++) { s.clock.t += 10 * MIN; assert.deepEqual(await results(s), ["not readable: host busy"]); }
  s.ctx.issues.create = async () => { throw new Error("create busy"); };
  s.clock.t += 10 * MIN;
  assert.match((await results(s))[0], /^re-raise failed: .*create busy/);   // the MAX_VERIFY_FAILURES-th failed run
  assert.equal((await pendingOf(s)).verifyFailures, MAX_VERIFY_FAILURES);
  s.clock.t += 10 * MIN;
  assert.match((await results(s))[0], /^re-raise failed/);                  // retried
  s.clock.t += DAY;                                                          // even after the window ended
  assert.match((await results(s))[0], /^re-raise failed/);
  assert.ok((await pendingOf(s)).verifyFailures >= MAX_VERIFY_FAILURES);
  assert.deepEqual(s.tracked(), [s.id]);
  s.ctx.issues.create = create;
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["re-raised"]);
  assert.deepEqual(s.tracked(), ["i-2"]);
  assert.equal(s.created.length, 2);
});

test("pending verification: failures are counted cumulatively, alternating with a failed issue read does not reset them", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; await closeAsItsec(s);
  unreadable(s);
  const get = s.ctx.issues.get;
  const seen = [];
  for (let i = 0; i < 5 && s.created.length === 1; i++) {
    s.ctx.issues.get = i % 2 ? async () => { throw new Error("get busy"); } : get;
    s.clock.t += 10 * MIN;
    seen.push((await results(s))[0]);
  }
  assert.deepEqual(seen, ["not readable: host busy", "not readable: get busy", "not readable: host busy", "not readable: get busy", "re-raised"]);
  assert.equal(s.warns.length, MAX_VERIFY_FAILURES);
  assert.match(s.created[1].description, /3 failed runs/);
  assert.deepEqual(s.tracked(), ["i-2"]);
});

test("pending verification: a failed re-raise of a close verified as lacking a resolution comment keeps the pending state too", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; await closeAsItsec(s);
  unreadable(s);
  s.clock.t += 10 * MIN; await results(s);
  const create = s.ctx.issues.create;
  s.ctx.issues.listComments = async () => []; // readable now, no resolution comment
  s.ctx.issues.create = async () => { throw new Error("create busy"); };
  s.clock.t += 10 * MIN;
  assert.match((await results(s))[0], /^re-raise failed/);
  assert.equal((await pendingOf(s)).verifyFailures, 1, "decision not carried out: still pending");
  s.ctx.issues.create = create;
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["re-raised"]);
});

test("a failed re-raise of a tampered alert that was never pending is kept and retried after the window, never dropped", async () => {
  const s = setup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 1 } });
  const a = await s.raise();
  s.clock.t += MIN; await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", agentId: "a-rogue" });
  const create = s.ctx.issues.create;
  s.ctx.issues.create = async () => { throw new Error("create busy"); };
  s.clock.t += 10 * MIN;
  assert.match((await results(s))[0], /^re-raise failed: .*create busy/);
  s.clock.t += DAY;                                    // the window is over
  assert.match((await results(s))[0], /^re-raise failed/);
  assert.deepEqual(s.tracked(), [a.issue.issueId]);
  s.ctx.issues.create = create;
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["re-raised"]);
  assert.deepEqual(s.tracked(), ["i-2"]);
  assert.equal(s.created.length, 2);
});

// ------------------------------------------------------------------------------------ final review: pending markers never lost
test("'closer unknown' alert that could not be raised is kept and retried after the window, never dropped", async () => {
  const s = setup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 1 } });
  const a = await s.raise();
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", deliver: false });
  const create = s.ctx.issues.create;
  s.ctx.issues.create = async () => { throw new Error("create busy"); };
  s.clock.t += 10 * MIN;
  assert.match((await results(s))[0], /^closer unknown, alert failed/);
  s.clock.t += DAY;
  assert.match((await results(s))[0], /^closer unknown, alert failed/);
  assert.deepEqual(s.tracked(), [a.issue.issueId]);
  s.ctx.issues.create = create;
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["closer unknown"]);
  assert.equal(s.created.length, 2);
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["open"]);        // raised: settled, the old alert is no longer tracked (only the new one)
  assert.deepEqual(s.tracked(), ["i-2"]);
});

test("an accepted ITSec close does not justify a later re-close within the clock skew whose event was missed", async () => {
  const s = await itsecSetup();
  s.clock.t += MIN; s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await closeAsItsec(s);
  s.clock.t += MIN;
  assert.deepEqual(await results(s), ["closed by ITSec agent"]);
  assert.deepEqual(await results(s), ["closed by ITSec agent"], "same close, verified again");
  s.clock.t += MIN;                                                  // reopened and closed again 2 minutes after the accepted close
  await s.close(s.id, { actorType: "agent", actorId: "a-itsec", agentId: "a-itsec", deliver: false });
  assert.deepEqual(await results(s), ["closer unknown"]);
  assert.equal(s.created.length, 2);
  assert.equal(await s.ctx.state.get(ITSEC_CLOSED_KEY(HOST)).then((l) => l.length), 1);
  s.clock.t += 2 * MIN;                                              // a later close WITH its event is judged on its own
  s.comment(s.id, { agentId: "a-itsec", body: GOOD });
  s.clock.t += MIN; await closeAsItsec(s);
  assert.deepEqual((await s.r.runJob()).filter((x) => x.issueId === s.id).map((x) => x.result), ["closed by ITSec agent"]);
});

test("state that cannot be written: pending markers are kept in memory, the window end still re-raises, the failure is logged", async () => {
  const s = await itsecSetup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 1 } });
  s.clock.t += MIN; await closeAsItsec(s);
  unreadable(s);
  const set = s.ctx.state.set;
  s.ctx.state.set = async (key, v) => { if (key.stateKey === "alert-log") throw new Error("disk full"); return set(key, v); };
  s.clock.t += 10 * MIN;
  const first = await s.r.runJob();
  assert.deepEqual(first.map((x) => x.result), ["not readable: host busy", "state not saved: disk full"]);
  assert.ok(s.warns.some((w) => /state not saved: disk full/.test(w)));
  assert.equal((await pendingOf(s)).verifyFailures, undefined, "nothing was persisted");
  s.clock.t += DAY;
  assert.deepEqual((await s.r.runJob())[0].result, "re-raised"); // not dropped as "window over"
  assert.equal(s.created.length, 2);
});

test("re-check switched off (alertRecheckDays 0): an alert with a pending verification is re-raised once, others stay 'off'", async () => {
  const config = { adminUserIds: ["u-owner"] };
  const s = await itsecSetup({ config });
  const other = await s.raise("[Security hardening] Self-test failed: Own box");
  s.clock.t += MIN; await closeAsItsec(s);
  unreadable(s);
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["not readable: host busy", "open"]);
  config.alertRecheckDays = 0;
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["re-raised", "off"]);
  assert.match(s.created.at(-1).description, /re-check has been switched off/);
  assert.equal(s.created.length, 3);
  s.clock.t += 10 * MIN;
  assert.deepEqual(await results(s), ["off", "off"]);
  assert.equal(s.created.length, 3);
  assert.deepEqual(s.tracked().sort(), [other.issue.issueId, "i-3"].sort());
});

test(`the ${MAX_TRACKED_ALERTS}-alert cap evicts non-pending alerts first, never a pending or failed one while others exist`, async () => {
  const s = setup();
  const issues = {};
  for (let i = 0; i < MAX_TRACKED_ALERTS; i++) issues[`n${i}`] = { companyId: "c1", title: "t", raisedAt: new Date(T0 + (i + 10) * MIN).toISOString() };
  issues.pend = { companyId: "c1", title: "t", raisedAt: new Date(T0).toISOString(), verifyFailures: 1 };
  issues.fail = { companyId: "c1", title: "t", raisedAt: new Date(T0 + MIN).toISOString(), reraiseFailed: true };
  await s.ctx.state.set(ALERT_LOG_KEY, { issues });
  assert.equal(await trackAlert(s.ctx, "new", { companyId: "c1", title: "t", raisedAt: new Date(T0 + 1000 * MIN).toISOString() }), true);
  const kept = Object.keys((await s.ctx.state.get(ALERT_LOG_KEY)).issues);
  assert.equal(kept.length, MAX_TRACKED_ALERTS);
  assert.ok(kept.includes("pend") && kept.includes("fail") && kept.includes("new"));
  assert.ok(!kept.includes("n0") && !kept.includes("n1"), "the oldest non-pending alerts went");
});
