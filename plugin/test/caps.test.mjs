// Daily token caps (src/caps.js) with a fake plugin context and a fake clock: the counting rules ported from
// the standalone usage-guard script, the pause / re-pause / new-day resume state machine, "usage not reported", the new-company
// template, per-agent and per-company error isolation, and the rollover summary date.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createCaps, runUsageTokens, parseRunLog, readRunLogFile, hermesSessionTotalFromDbs, decideCompany, CAPS_KEY, CAPS_INSTALL_KEY, CAPS_STATE_KEY, USAGE_KEY } from "../src/caps.js";

const tmp = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "caps-test-"));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const actor = (type, userId, companyId = "c1") => ({ actor: Object.freeze({ type, userId, agentId: null, runId: null, companyId }), companyId });
const ADMIN = actor("user", "u-admin");

/** One stdout record of a run log, as Paperclip's run-log store writes it. */
const rec = (chunk, stream = "stdout") => JSON.stringify({ ts: "2026-10-18T10:00:00Z", stream, chunk });
const assistant = (id, u) => JSON.stringify({ type: "assistant", message: { id, usage: u } }) + "\n";

function world() {
  const state = new Map();
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const w = {
    clock: new Date("2026-10-18T10:00:00Z"),
    companies: [{ id: "c1", name: "One" }],
    agents: {},          // companyId -> agents (mutable objects; status changes stick)
    runs: {},            // companyId -> run rows
    logs: {},            // run id -> log text, or an Error to throw
    sessions: {},        // hermes session id -> cumulative tokens
    failPause: new Set(),
    failAgentsList: new Set(),
    comments: [], pauses: [], resumes: [], activity: [],
    state, k,
  };
  const findAgent = (id, cid) => (w.agents[cid] ?? []).find((a) => a.id === id) ?? null;
  w.ctx = {
    state: { get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null), set: async (key, v) => { state.set(k(key), structuredClone(v)); } },
    config: { get: async (cid) => (cid === "c1" ? { adminUserIds: ["u-admin"] } : {}) },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    activity: { log: async (e) => { w.activity.push(e); } },
    companies: { list: async ({ offset } = {}) => (offset ? [] : w.companies) },
    agents: {
      list: async ({ companyId, offset }) => { if (w.failAgentsList.has(companyId)) throw new Error("HTTP 500 listing agents"); return offset ? [] : (w.agents[companyId] ?? []).map((a) => ({ ...a })); },
      get: async (id, cid) => findAgent(id, cid),
      pause: async (id, cid) => { if (w.failPause.has(id)) throw new Error("HTTP 403"); const a = findAgent(id, cid); a.status = "paused"; w.pauses.push(id); return a; },
      resume: async (id, cid) => { const a = findAgent(id, cid); a.status = "idle"; w.resumes.push(id); return a; },
    },
    db: {
      query: async (sql, params) => {
        assert.match(sql, /FROM public\.heartbeat_runs r WHERE r\.company_id = \$1/);
        const [cid, start, end] = params;
        return (w.runs[cid] ?? []).filter((r) => r.started_at && r.started_at >= start && r.started_at < end).map((r) => ({ ...r }));
      },
    },
    issues: { createComment: async (issueId, body, cid) => { w.comments.push({ issueId, body, cid }); return { id: String(w.comments.length) }; } },
  };
  w.caps = createCaps({
    ctx: w.ctx,
    assertAdmin: async (context) => { if (context?.actor?.userId !== "u-admin") throw Object.assign(new Error("not admin"), { name: "NotAllowedError" }); return context.actor; },
    now: () => w.clock,
    readRunLog: async (run) => { const l = w.logs[run.id]; if (l instanceof Error) throw l; return l ?? ""; },
    hermesSessionTotal: async (sid) => w.sessions[sid] ?? null,
  });
  w.at = (iso) => { w.clock = new Date(iso); };
  w.run = () => w.caps.runJob();
  w.get = (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null);
  w.setCaps = (cid, caps) => state.set(k(CAPS_KEY(cid)), { defaultCap: 1000, companyCap: 100000, mode: "enforce", statusIssueId: "iss-1", overrides: {}, ...caps });
  return w;
}
const agent = (id, name, adapterType = "claude_local", status = "idle") => ({ id, name, adapterType, status, companyId: "c1" });
let runSeq = 0;
const run = (agentId, { usage = null, started = "2026-10-18T09:00:00.000Z", finished = "2026-10-18T09:05:00.000Z", logRef = `c1/${agentId}/r.ndjson`, status = "succeeded" } = {}) =>
  ({ id: `r${++runSeq}`, agent_id: agentId, status, started_at: started, finished_at: finished, usage_json: usage, log_store: "local_file", log_ref: logRef, log_compressed: false });

// ---------------------------------------------------------------------------------------------------- counting

test("run usage: input + cache creation + output; null when the run recorded none", () => {
  assert.equal(runUsageTokens({ inputTokens: 100, cachedInputTokens: 5000, outputTokens: 20 }), 120, "cache READS are not counted");
  assert.equal(runUsageTokens({ inputTokens: 100, cacheCreationInputTokens: 30, outputTokens: 20 }), 150);
  assert.equal(runUsageTokens({ input_tokens: 1, cache_creation_input_tokens: 2, output_tokens: 3 }), 6);
  assert.equal(runUsageTokens('{"inputTokens":7,"outputTokens":3}'), 10);
  assert.equal(runUsageTokens({ inputTokens: 0, outputTokens: 0 }), 0);
  assert.equal(runUsageTokens(null), null);
  assert.equal(runUsageTokens({}), null);
  assert.equal(runUsageTokens({ costUsd: 1 }), null);
});

test("run log: per-message usage counted once per message id, chunks split mid-line, Hermes session found", () => {
  const ev1 = assistant("m1", { input_tokens: 10, cache_creation_input_tokens: 100, output_tokens: 5, cache_read_input_tokens: 9999 });
  const log = [
    rec(ev1),
    rec(assistant("m1", { input_tokens: 10, cache_creation_input_tokens: 100, output_tokens: 7 })), // same message, later usage wins
    rec(ev1.slice(0, 20).replace("m1", "m2")),               // garbage start of a line...
    rec("not json\n"),
    rec(assistant("m3", { input_tokens: 1, output_tokens: 1 }).slice(0, 30)),
    rec(assistant("m3", { input_tokens: 1, output_tokens: 1 }).slice(30)),  // ...and a line split over two chunks
    rec("ignored", "stderr"),
    "not a record",
  ].join("\n");
  assert.equal(parseRunLog(log).tokens, 117 + 2);
  const hermes = [rec("[hermes] Starting\n"), rec("[hermes] Session: 20261018_abc\n")].join("\n");
  assert.deepEqual(parseRunLog(hermes), { tokens: 0, hermesSessionId: "20261018_abc" });
  assert.deepEqual(parseRunLog(""), { tokens: 0, hermesSessionId: null });
});

test("run log file: read from the run-log dir, missing is empty, no escaping the dir", async () => {
  const base = path.join(tmp, "run-logs");
  fs.mkdirSync(path.join(base, "c1", "a1"), { recursive: true });
  fs.writeFileSync(path.join(base, "c1", "a1", "r1.ndjson"), rec(assistant("m", { input_tokens: 4, output_tokens: 1 })));
  assert.equal(parseRunLog(await readRunLogFile({ log_ref: "c1/a1/r1.ndjson", log_store: "local_file" }, { base })).tokens, 5);
  assert.equal(await readRunLogFile({ log_ref: "c1/a1/gone.ndjson" }, { base }), "");
  assert.equal(await readRunLogFile({ log_ref: null }, { base }), "");
  assert.equal(await readRunLogFile({ log_ref: "x", log_store: "s3" }, { base }), "");
  await assert.rejects(readRunLogFile({ log_ref: "../../etc/passwd" }, { base }), /escapes/);
});

test("Hermes session totals: input + cache write + output from a read-only state.db", { skip: !(await import("node:sqlite").catch(() => null)) && "node:sqlite unavailable" }, async () => {
  const { DatabaseSync } = await import("node:sqlite");
  const file = path.join(tmp, "state.db");
  const db = new DatabaseSync(file);
  db.exec("create table sessions (id text primary key, input_tokens integer, cache_write_tokens integer, output_tokens integer, cache_read_tokens integer)");
  db.prepare("insert into sessions values (?, ?, ?, ?, ?)").run("s1", 100, 20, 3, 5000);
  db.prepare("insert into sessions values (?, ?, ?, ?, ?)").run("s2", 7, null, null, null);
  db.close();
  assert.equal(await hermesSessionTotalFromDbs("s1", [path.join(tmp, "missing.db"), file]), 123);
  assert.equal(await hermesSessionTotalFromDbs("s2", [file]), 7);
  assert.equal(await hermesSessionTotalFromDbs("nope", [file]), null);
});

test("job: usage, log-parse fallback for runs without usage (cancelled ones counted), Hermes session delta, cached runs not recounted", async () => {
  const w = world();
  w.agents.c1 = [agent("a1", "Engineer"), agent("h1", "Hermes", "hermes_local")];
  w.setCaps("c1", { defaultCap: 1e9, companyCap: 1e10 });
  const cancelled = run("a1", { usage: null, status: "cancelled" });
  w.runs.c1 = [
    run("a1", { usage: { inputTokens: 100, cacheCreationInputTokens: 50, outputTokens: 10 } }),
    cancelled,
    run("a1", { usage: { inputTokens: 999 }, started: "2026-10-17T23:59:00.000Z" }), // yesterday: not counted
  ];
  w.logs[cancelled.id] = rec(assistant("m1", { input_tokens: 40, cache_creation_input_tokens: 0, output_tokens: 2 }));
  const h1 = run("h1", { usage: { inputTokens: 1, outputTokens: 1 } });
  w.runs.c1.push(h1);
  w.logs[h1.id] = rec("[hermes] Session: s-1\n");
  w.sessions["s-1"] = 1000;
  await w.run();
  let snap = w.get(USAGE_KEY("c1"));
  assert.equal(snap.agents.a1.used, 160 + 42);
  assert.equal(snap.agents.h1.used, 1000, "Hermes: the session's totals, not the adapter's usage line");
  assert.equal(snap.companyUsed, 1202);
  // The same session continues in a second run: only the growth counts; the first run is not recounted.
  w.sessions["s-1"] = 1500;
  const h2 = run("h1", { usage: null, started: "2026-10-18T11:00:00.000Z", finished: "2026-10-18T11:10:00.000Z" });
  w.runs.c1.push(h2);
  w.logs[h2.id] = rec("[hermes] Session: s-1\n");
  w.at("2026-10-18T11:15:00Z");
  await w.run();
  snap = w.get(USAGE_KEY("c1"));
  assert.equal(snap.agents.h1.used, 1500);
  await w.run();
  assert.equal(w.get(USAGE_KEY("c1")).agents.h1.used, 1500, "a third job adds nothing");
  assert.equal(w.get(USAGE_KEY("c1")).agents.a1.used, 202);
});

test("state machine: pause over cap with one comment, re-pause after a human resume, resume at the next UTC day only what the caps paused", async () => {
  const w = world();
  w.agents.c1 = [agent("a1", "Busy"), agent("a2", "Quiet"), agent("a3", "Human-paused", "claude_local", "paused")];
  w.setCaps("c1", { defaultCap: 1000, overrides: { a2: 5000 } });
  w.runs.c1 = [run("a1", { usage: { inputTokens: 1500, outputTokens: 1 } }), run("a2", { usage: { inputTokens: 2000 } }), run("a3", { usage: { inputTokens: 9000 } })];
  await w.run();
  assert.deepEqual(w.pauses, ["a1"], "a2 is under its own cap; a3 was already paused by a person");
  assert.equal(w.comments.length, 1);
  assert.equal(w.comments[0].issueId, "iss-1");
  assert.match(w.comments[0].body, /^Daily token caps paused Busy: 1,501 tokens today > cap 1,000/);
  await w.run();
  assert.equal(w.pauses.length, 1, "still paused: no second pause, no second comment");
  assert.equal(w.comments.length, 1);
  // Someone resumes the agent while it is still over: paused again, said once.
  w.agents.c1[0].status = "idle";
  w.at("2026-10-18T12:00:00Z");
  await w.run();
  assert.deepEqual(w.pauses, ["a1", "a1"]);
  assert.match(w.comments.at(-1).body, /re-paused \(resumed while still over\) Busy/);
  assert.deepEqual(w.get(CAPS_STATE_KEY).pausedByCap, { a1: "c1" });
  // Next UTC day: a1 resumed (the caps paused it); a3 stays paused (a person did that).
  w.at("2026-10-19T00:04:00Z");
  await w.run();
  assert.deepEqual(w.resumes, ["a1"]);
  assert.equal(w.agents.c1[2].status, "paused");
  assert.ok(w.comments.some((c) => /resumed Busy \(new day 2026-10-19\)/.test(c.body)));
  assert.deepEqual(w.get(CAPS_STATE_KEY).pausedByCap, {});
  assert.equal(w.pauses.length, 2, "yesterday's runs do not count today");
});

test("rollover: the daily summary is posted at the first run of the new day with the date of the day that ended", async () => {
  const w = world();
  w.agents.c1 = [agent("a1", "Engineer"), agent("p1", "Script", "process")];
  w.setCaps("c1", { defaultCap: 1e6, companyCap: 5e6 });
  w.runs.c1 = [run("a1", { usage: { inputTokens: 1234 }, started: "2026-10-18T23:50:00.000Z", finished: "2026-10-18T23:55:00.000Z" })];
  w.at("2026-10-18T23:58:00Z");
  await w.run();
  assert.equal(w.comments.length, 0);
  w.at("2026-10-19T00:03:00Z");
  await w.run();
  const summary = w.comments.find((c) => /summary/.test(c.body));
  assert.ok(summary, "summary posted");
  assert.match(summary.body, /^Daily token caps: summary for 2026-10-18 \(UTC\)/);
  assert.match(summary.body, /Engineer: 1,234 \/ cap 1,000,000/);
  assert.match(summary.body, /Script: usage not reported/);
  assert.match(summary.body, /company: 1,234 \/ 5,000,000/);
  await w.run();
  assert.equal(w.comments.filter((c) => /summary/.test(c.body)).length, 1, "posted once");
  assert.equal(w.get(USAGE_KEY("c1")).agents.a1.used, 0, "the new day starts at zero");
});

test("usage not reported: an adapter type that never reported tokens is never paused, even over the company cap", async () => {
  const w = world();
  w.agents.c1 = [agent("a1", "Engineer"), agent("p1", "Script", "process")];
  w.setCaps("c1", { defaultCap: 1e6, companyCap: 100 });
  w.runs.c1 = [run("a1", { usage: { inputTokens: 150 } }), run("p1", { usage: null, logRef: null })];
  await w.run();
  assert.deepEqual(w.pauses, ["a1"], "company cap: every agent that reports usage is paused; the process agent is not");
  assert.match(w.comments[0].body, /company 150 tokens today > company cap 100/);
  const snap = w.get(USAGE_KEY("c1"));
  assert.equal(snap.agents.p1.reported, false);
  assert.equal(snap.agents.a1.reported, true);
  const view = await w.caps.view("c1", w.agents.c1);
  assert.equal(view.agents.p1.reported, false);
  assert.equal(view.agents.a1.pausedByCap, true);
  // decideCompany alone: an unreported agent over its cap gets no action.
  const d = decideCompany({ agents: [agent("x", "X", "process")], used: { x: 1e9 }, isReporting: () => false, caps: { defaultCap: 1, companyCap: 1, mode: "enforce", overrides: {} }, state: { pausedByCap: {}, reported: [] } });
  assert.deepEqual(d.actions, []);
});

test("report mode comments once per agent per day and never pauses; off only measures", async () => {
  const w = world();
  w.agents.c1 = [agent("a1", "Engineer")];
  w.setCaps("c1", { defaultCap: 10, mode: "report" });
  w.runs.c1 = [run("a1", { usage: { inputTokens: 50 } })];
  await w.run();
  await w.run();
  assert.deepEqual(w.pauses, []);
  assert.equal(w.comments.length, 1);
  assert.match(w.comments[0].body, /report only.*Engineer is over: 50 tokens today > cap 10/);
  w.setCaps("c1", { defaultCap: 10, mode: "off" });
  w.at("2026-10-19T08:00:00Z");
  w.runs.c1.push(run("a1", { usage: { inputTokens: 50 }, started: "2026-10-19T07:00:00.000Z", finished: "2026-10-19T07:01:00.000Z" }));
  await w.run();
  assert.deepEqual(w.pauses, []);
  assert.equal(w.get(USAGE_KEY("c1")).agents.a1.used, 50);
});

test("new companies start from the install-wide template; later template changes leave existing companies alone", async () => {
  const w = world();
  w.state.set(w.k(CAPS_INSTALL_KEY), { template: { defaultCap: 2000, companyCap: 9000, mode: "report" } });
  w.agents.c1 = [agent("a1", "Engineer")];
  await w.run();
  const c1 = w.get(CAPS_KEY("c1"));
  assert.equal(c1.defaultCap, 2000);
  assert.equal(c1.companyCap, 9000);
  assert.equal(c1.mode, "report");
  assert.ok(c1.createdFromTemplateAt);
  assert.equal((await w.caps.saveInstall({ template: { defaultCap: 3000, companyCap: 12000, mode: "enforce" } }, ADMIN)).ok, true);
  w.companies.push({ id: "c2", name: "Two" });
  w.agents.c2 = [{ ...agent("b1", "New"), companyId: "c2" }];
  await w.run();
  assert.equal(w.get(CAPS_KEY("c1")).defaultCap, 2000, "existing company keeps its caps");
  assert.equal(w.get(CAPS_KEY("c2")).defaultCap, 3000, "new company gets the current template");
  // The default cap covers agents added later; an override on top; clearing it returns to the default.
  assert.equal((await w.caps.saveAgentCap({ agentId: "a1", cap: "5,000" }, ADMIN)).effective, 5000);
  assert.equal((await w.caps.saveAgentCap({ agentId: "a1", cap: "" }, ADMIN)).effective, 2000);
  assert.equal((await w.caps.saveAgentCap({ agentId: "a1", cap: -3 }, ADMIN)).ok, false);
  assert.equal((await w.caps.saveCompanyCaps({ defaultCap: 0, companyCap: 10, mode: "enforce" }, ADMIN)).ok, false);
  assert.equal((await w.caps.saveCompanyCaps({ defaultCap: 500, companyCap: 10, mode: "nope" }, ADMIN)).ok, false);
  const ok = await w.caps.saveCompanyCaps({ defaultCap: "1_500", companyCap: 10000, mode: "enforce", statusIssueId: "iss-9" }, ADMIN);
  assert.deepEqual([ok.caps.defaultCap, ok.caps.statusIssueId], [1500, "iss-9"]);
});

test("an error on one agent, one pause or one company never stops the job", async () => {
  const w = world();
  w.companies = [{ id: "c0", name: "Broken" }, { id: "c1", name: "One" }];
  w.failAgentsList.add("c0");
  w.agents.c1 = [agent("a1", "Unreadable log"), agent("a2", "Pause refused"), agent("a3", "Normal")];
  w.setCaps("c1", { defaultCap: 10, companyCap: 1e9 });
  const r1 = run("a1", { usage: null });
  w.logs[r1.id] = new Error("EACCES: permission denied (HTTP 403-like)");
  w.runs.c1 = [r1, run("a2", { usage: { inputTokens: 50 } }), run("a3", { usage: { inputTokens: 50 } })];
  w.failPause.add("a2");
  const result = await w.run();
  assert.deepEqual(w.pauses, ["a3"]);
  assert.ok(result.errors.some((e) => e.companyId === "c0"));
  const snap = w.get(USAGE_KEY("c1"));
  assert.match(snap.agents.a1.error, /EACCES/);
  assert.equal(snap.agents.a1.used, null);
  assert.match(snap.agents.a2.error, /pause failed/);
  assert.deepEqual(w.get(CAPS_STATE_KEY).pausedByCap, { a3: "c1" }, "a failed pause is not recorded as paused by the caps");
  // A failing status comment does not stop it either (falls back to the activity log).
  w.ctx.issues.createComment = async () => { throw new Error("HTTP 404 issue"); };
  w.agents.c1[2].status = "idle";
  await w.run();
  assert.ok(w.activity.some((e) => /re-paused/.test(e.message)));
  // The whole company query failing is reported, nothing crashes.
  w.ctx.db.query = async () => { throw new Error("database namespace not active"); };
  const r = await w.run();
  assert.ok(r.errors.some((e) => /namespace/.test(e.error)));
});
