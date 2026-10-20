// Self-test after a restart: a short check per switched-on protection that it really works in the files Paperclip
// runs, not only that the text is there. No SDK imports, no agent run, nothing is changed:
//   - functional checks load the patched code in-process and call it with a deliberately bad request:
//       sandbox-compat  imports the built local-process-sandbox.js (it imports only Node built-ins) and builds a spawn
//                       target with network "deny" (no proxy is started): usr-merge symlinks (/bin, /lib, ...) must
//                       not be bind-mounted again (patch 0001)
//       public-web      same module: "*:443" is accepted, "*" and "*.example.com" stay refused (patch 0015)
//       own-box         evaluates the 0003 block cut out of the built heartbeat.js (stub logger, so no real
//                       enforcement log line is written): a run override that widens the network, injects LD_PRELOAD
//                       or launches outside the workspace roots is restored, dropped or refused
//       safe-defaults   evaluates the 0005a block cut out of the built services/agents.js: a new agent created
//                       unboxed with canCreateAgents/canCreateSkills comes out boxed and without them
//   - every applied protection also gets the structural check: each of its files equals the engine's recorded built
//     sha256 and contains the markers of its patches. A protection with no functional check is "structural only".
// The other protections (only-boxed, no-permission-handing, pipeline-board-only, assign-needs-grant,
// own-claude-folder) change route handlers or adapter code that cannot be called without a database, an
// authenticated agent request or a real run, so they are structural only.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PATCHES } from "./engine/registry.js";
import { sha256 } from "./engine/store.js";
import { extractBlock, evalBlock } from "./patch-block.js";

export const SANDBOX_FILE = "node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js";
export const HEARTBEAT_FILE = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
export const AGENTS_FILE = "node_modules/@paperclipai/server/dist/services/agents.js";
const USR_MERGE = ["/bin", "/sbin", "/lib", "/lib64"];

/** Import a built module by content: the same content is imported once, a changed file gets a fresh instance. */
async function importBuilt(tree, rel) {
  const file = path.join(tree, rel);
  const sha = sha256(fs.readFileSync(file));
  return import(`${pathToFileURL(file).href}?selftest=${sha}`);
}

function evalBuiltBlock(tree, rel, id, opts) {
  return evalBlock(extractBlock(fs.readFileSync(path.join(tree, rel), "utf8"), id), id, opts);
}

const expectThrow = (fn) => { try { fn(); return false; } catch { return true; } };

/** Functional checks: id -> list of {name, run(tree, env) -> detail string (throws on failure)}. */
export const FUNCTIONAL_CHECKS = {
  "sandbox-compat": [{
    name: "usr-merge directories are not mounted twice (0001)",
    async run(tree) {
      const mod = await importBuilt(tree, SANDBOX_FILE);
      if (typeof mod.buildLocalProcessSandboxSpawnTarget !== "function") throw new Error("buildLocalProcessSandboxSpawnTarget is missing");
      const ws = fs.realpathSync(os.tmpdir());
      const target = await mod.buildLocalProcessSandboxSpawnTarget({ executable: process.execPath, args: [], cwd: ws,
        options: { command: "/usr/bin/bwrap", filesystemScope: "workspace", workspaceDir: ws, networkScope: "deny" } });
      const merged = USR_MERGE.filter((p) => { try { return fs.lstatSync(p).isSymbolicLink() && fs.readlinkSync(p).replace(/^\//, "").startsWith("usr/"); } catch { return false; } });
      const twice = merged.filter((p) => target.args.some((a, i) => (a === "--ro-bind" || a === "--bind") && target.args[i + 1] === p));
      if (twice.length) throw new Error(`bind-mounted over the usr-merge symlink: ${twice.join(", ")}`);
      return merged.length ? `checked ${merged.join(", ")}` : "no usr-merge symlinks on this host (nothing to mount twice)";
    },
  }],
  "public-web": [{
    name: "\"*:443\" means public hosts only; other wildcards refused (0015)",
    async run(tree) {
      const mod = await importBuilt(tree, SANDBOX_FILE);
      const parse = mod.parseLocalProcessNetworkAllowlist;
      if (typeof parse !== "function") throw new Error("parseLocalProcessNetworkAllowlist is missing");
      let accepted;
      try { accepted = parse(["*:443"]); } catch (e) { throw new Error(`"*:443" is refused: ${e.message}`); }
      if (JSON.stringify(accepted) !== JSON.stringify(["*:443"])) throw new Error(`"*:443" parsed as ${JSON.stringify(accepted)}`);
      for (const bad of ["*", "*.example.com"]) if (!expectThrow(() => parse([bad]))) throw new Error(`"${bad}" is accepted`);
      return "accepted *:443; refused * and *.example.com";
    },
  }],
  "own-box": [{
    name: "a run override cannot widen the stored box (0003)",
    async run(tree, env) {
      const b = evalBuiltBlock(tree, HEARTBEAT_FILE, "0003", env);
      const stored = { filesystemScope: "workspace", networkScope: "allowlist", networkAllowlist: ["api.anthropic.com"], env: {} };
      const agent = { id: "selftest-agent", adapterConfig: stored };
      const out = await b.enforceStoredSandboxConfig({ agent, runId: "selftest-run", workspaceDirs: [], managedAi: false,
        runtimeConfig: { networkScope: null, networkAllowlist: ["*:443"], env: { LD_PRELOAD: "/tmp/x.so", SELFTEST_KEEP: "1" } } });
      if (out.networkScope !== "allowlist" || JSON.stringify(out.networkAllowlist) !== JSON.stringify(stored.networkAllowlist)) throw new Error("the widened network override was kept");
      if ("LD_PRELOAD" in (out.env ?? {})) throw new Error("LD_PRELOAD was not dropped");
      if (out.env?.SELFTEST_KEEP !== "1") throw new Error("a harmless env value was dropped");
      let refused = false;
      try {
        await b.enforceStoredSandboxConfig({ agent, runId: "selftest-run", workspaceDirs: [], managedAi: false, runtimeConfig: { cwd: "/etc", env: {} } });
      } catch (e) { refused = /outside the allowed workspace roots/.test(e.message); }
      if (!refused) throw new Error("a run with cwd /etc was not refused");
      return "network restored, LD_PRELOAD dropped, cwd /etc refused";
    },
  }],
  "safe-defaults": [{
    name: "a new unboxed agent starts boxed without create rights (0005a)",
    async run(tree, env) {
      const b = evalBuiltBlock(tree, AGENTS_FILE, "0005a", env);
      const r = b.applyNewAgentSafeDefaults("claude_local", { filesystemScope: null, networkScope: null, networkAllowlist: ["*:443"] },
        { canCreateAgents: true, canCreateSkills: true }, "create");
      const c = r?.adapterConfig ?? {};
      if (c.filesystemScope !== "workspace" || c.networkScope !== "allowlist") throw new Error("the new agent is not boxed");
      if ((c.networkAllowlist ?? []).includes("*:443")) throw new Error("the creator's wildcard allowlist was kept");
      if (r.permissions?.canCreateAgents !== false || r.permissions?.canCreateSkills !== false) throw new Error("create rights were kept");
      return "boxed (workspace + allowlist), canCreateAgents/canCreateSkills false";
    },
  }],
};

/** Structural check of one protection: its files equal the recorded built sha and carry the markers of its patches. */
export function structuralCheck(protection, statusFiles, tree) {
  const problems = [];
  const checked = [];
  for (const rel of protection.files ?? []) {
    const f = statusFiles.find((x) => x.rel === rel);
    if (!f) { problems.push(`${rel}: not tracked by the engine`); continue; }
    if (!f.builtSha || f.currentSha !== f.builtSha) { problems.push(`${rel}: sha256 ${f.currentSha?.slice(0, 12) ?? "missing"} is not the built ${f.builtSha?.slice(0, 12) ?? "(none)"}`); continue; }
    const mine = (f.patches ?? []).filter((id) => protection.patches.includes(id));
    let text = "";
    try { text = fs.readFileSync(path.join(tree, rel), "utf8"); } catch (e) { problems.push(`${rel}: unreadable (${e.code ?? e.message})`); continue; }
    const lost = mine.filter((id) => !text.includes(PATCHES[id].marker));
    if (lost.length) problems.push(`${rel}: marker missing for ${lost.join(", ")}`);
    checked.push(...mine);
  }
  return { name: "built files match the engine's record and carry the patch markers", kind: "structural", ok: problems.length === 0,
    detail: problems.length ? problems.join("; ") : `${checked.length} patch(es) in ${(protection.files ?? []).length} file(s)` };
}

/**
 * Run the self-test against the files of the running install.
 * @param {object} o
 * @param {object} o.engine   hardening engine (protections(), status(), tree)
 * @param {object} o.status   engine.status() result (only protections with status "applied" are tested)
 * @param {object} [o.env]    environment the patched blocks see (the variables of the target Paperclip that they read)
 * @param {string} o.instanceRoot  the target's instance root (what resolvePaperclipInstanceRoot() returns in Paperclip)
 * @param {object} [o.checks] functional checks (tests pass their own)
 * @returns {Promise<{at: string, results: object}>}  results[id] = {ok, mode, checks, filesKey}
 */
export async function runSelfTest({ engine, status, env = {}, instanceRoot, checks = FUNCTIONAL_CHECKS, now = () => new Date() }) {
  if (!instanceRoot) throw new Error("runSelfTest needs the instance root of the target Paperclip");
  const tree = status.tree ?? engine.tree;
  const blockEnv = { env, instanceRoot };
  const results = {};
  const byId = Object.fromEntries(engine.protections().map((p) => [p.id, p]));
  for (const st of status.protections) {
    const p = byId[st.id];
    if (!p || p.kind !== "patch" || st.status !== "applied") continue;
    const list = [];
    for (const c of checks[p.id] ?? []) {
      try { list.push({ name: c.name, kind: "functional", ok: true, detail: await c.run(tree, blockEnv) }); }
      catch (e) { list.push({ name: c.name, kind: "functional", ok: false, detail: e?.message ?? String(e) }); }
    }
    list.push(structuralCheck(p, status.files, tree));
    results[p.id] = {
      ok: list.every((c) => c.ok),
      mode: list.some((c) => c.kind === "functional") ? "functional" : "structural only",
      checks: list,
      filesKey: filesKey(p, status.files),
    };
  }
  return { at: now().toISOString(), results };
}

/** The current shas of a protection's files: a stored result only counts while they are unchanged. */
export function filesKey(protection, statusFiles) {
  return (protection.files ?? []).map((rel) => statusFiles.find((f) => f.rel === rel)?.currentSha ?? "-").join(",");
}
