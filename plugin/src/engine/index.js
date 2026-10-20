// The hardening engine: rebuilds Paperclip files from pristine copies plus the switched-on protections.
// Dependency-free (Node 20+ built-ins and GNU `patch`). See README.md in this directory.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PROTECTIONS, PATCHES, FOREIGN_MARKER, comparePatchIds, getProtection } from "./registry.js";
import { discoverPatchFiles, orderCandidates, readPatchTarget, buildFile } from "./patches.js";
import { Store, sha256, emptyState, tempNameFor, writeDurable, writeFileAtomic } from "./store.js";
import { detectRestart, runRestart } from "./restart.js";

export { PROTECTIONS, getProtection } from "./registry.js";
export { detectRestart, runRestart } from "./restart.js";
export { resolveTargetFromParent, verifyTarget, summarizeTarget, describeInstanceLayout, resolveInstanceInputs, systemdServiceName, TargetError, DATA_LEAF } from "./target.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// Patch files: <plugin>/patches when the plugin was packed (npm prepack copies them in, see scripts/copy-patches.mjs),
// else the source tree's <package>/host/patches (git checkout, local-path install).
const PACKED_PATCHES_DIR = path.resolve(HERE, "../../patches");
export const SOURCE_PATCHES_DIR = path.resolve(HERE, "../../../host/patches");
export const DEFAULT_PATCHES_DIR = fs.existsSync(PACKED_PATCHES_DIR) ? PACKED_PATCHES_DIR : SOURCE_PATCHES_DIR;

/** The Paperclip tree at `treeDir` (symlinks resolved). There is no default: which install to change is always the caller's decision. */
export function locateTree({ treeDir } = {}) {
  if (!treeDir) throw new Error("treeDir is required: the engine never guesses which Paperclip install to change");
  let real;
  try { real = fs.realpathSync(treeDir); } catch { throw new Error(`Paperclip tree not found at ${treeDir}`); }
  if (!fs.existsSync(path.join(real, "node_modules", "@paperclipai"))) throw new Error(`no @paperclipai packages under ${real}`);
  return real;
}

/** Version is informational only (it picks a preferred `.<vkey>` patch variant); it never blocks anything. */
export function readVersion(tree) {
  try {
    const version = JSON.parse(fs.readFileSync(path.join(tree, "node_modules/@paperclipai/server/package.json"), "utf8")).version ?? null;
    const m = /^\d+\.(\d{4})\./.exec(version ?? "");
    return { version, vkey: m ? m[1] : null };
  } catch {
    return { version: null, vkey: null };
  }
}

const readOrNull = (file) => { try { return fs.readFileSync(file); } catch (e) { if (e.code === "ENOENT") return null; throw e; } };
const modeOf = (file) => fs.statSync(file).mode & 0o7777;
const order = (ids) => PROTECTIONS.map((p) => p.id).filter((id) => ids.has(id));

/**
 * @param {object} options
 * @param {string} options.treeDir   the Paperclip install to change (required)
 * @param {string} options.dataDir   pristine copies, state and events of that install (required)
 * @param {string} [options.patchesDir]
 * @param {{unit: string, cgroup: string, pid: number}|{unit: null, reason: string}} [options.restart]  how Paperclip is restarted,
 *        as verified by the target (src/engine/target.js); a unit only counts when it runs that server process
 * @param {string} [options.unitName]  alternative to `restart` for an operator-chosen unit (CLI --unit); unverified
 * @param {string|null} [options.systemctl]  path to systemctl, or null to disable restart detection
 * @param {boolean} [options.refuseTreeChange]  refuse apply/restore when the data dir belongs to another install tree
 */
export function createEngine(options = {}) {
  if (!options.dataDir) throw new Error("dataDir is required: the engine never guesses where its state lives");
  const tree = locateTree(options);
  const patchesDir = path.resolve(options.patchesDir ?? DEFAULT_PATCHES_DIR);
  const store = new Store(path.resolve(options.dataDir));
  const io = { writeFile: writeDurable, rename: fs.renameSync, ...(options.io ?? {}) };
  const systemctl = options.systemctl === undefined ? "systemctl" : options.systemctl;
  const restartInfo = () => {
    const r = options.restart;
    if (r) return r.unit ? detectRestart({ unitName: r.unit, expectCgroup: r.cgroup, parentPid: r.pid, systemctl })
      : { canRestart: false, command: null, commandText: null, unit: null, startedAt: null, reason: r.reason };
    return detectRestart({ unitName: options.unitName, systemctl });
  };
  const { version, vkey } = readVersion(tree);
  const plans = new WeakMap();
  const buildCache = new Map();

  // ---- patch catalog: id -> {id, protection, marker, rel, candidates, optional, missing}
  const found = discoverPatchFiles(patchesDir);
  const catalog = {};
  for (const p of PROTECTIONS) {
    for (const id of p.patches) {
      const meta = PATCHES[id];
      if (!meta) throw new Error(`registry: no patch table entry for ${id}`);
      const candidates = orderCandidates(found.get(id) ?? [], vkey);
      const optional = Boolean(vkey && meta.notNeededOn?.includes(vkey));
      const rels = new Set(candidates.map((c) => readPatchTarget(c.file)));
      if (rels.size > 1) throw new Error(`patch ${id}: its variants change different files`);
      catalog[id] = { id, protection: p.id, marker: meta.marker, rel: [...rels][0] ?? null, candidates, optional, missing: candidates.length === 0 && !optional };
    }
  }
  const targets = [...new Set(Object.values(catalog).map((c) => c.rel).filter(Boolean))].sort();
  const protectionFiles = (p) => [...new Set(p.patches.map((id) => catalog[id].rel).filter(Boolean))];

  // ---- dependencies
  // soft: also follow `softRequires` (switched on together by default). Only the hard ones make a protection unavailable.
  const withRequirements = (ids, { soft = true } = {}) => {
    const out = new Set();
    const visit = (id) => {
      if (out.has(id)) return;
      const p = getProtection(id);
      if (!p) throw new Error(`unknown protection "${id}" (known: ${PROTECTIONS.map((x) => x.id).join(", ")})`);
      out.add(id);
      p.requires.forEach(visit);
      if (soft) (p.softRequires ?? []).forEach(visit);
    };
    ids.forEach(visit);
    return out;
  };
  const dependsOn = (a, b) => a !== b && withRequirements([a]).has(b);
  const hardDependsOn = (a, b) => a !== b && withRequirements([a], { soft: false }).has(b);

  function build(rel, pristine, ids) {
    const key = `${rel}\0${sha256(pristine)}\0${ids.join(",")}`;
    if (!buildCache.has(key)) {
      if (buildCache.size > 256) buildCache.clear();
      const steps = ids.map((id) => ({ id, marker: catalog[id].marker, candidates: catalog[id].candidates }));
      buildCache.set(key, ids.length ? buildFile({ rel, pristine, steps, tmpDir: options.tmpDir }) : { ok: true, content: pristine, used: [] });
    }
    return buildCache.get(key);
  }

  /** What the file's original is right now: the stored pristine, or (first run / after an outside change) the file. */
  function resolvePristine(rel, state, { repair = false, adoptOrig = false } = {}) {
    const abs = path.join(tree, rel);
    const current = readOrNull(abs);
    if (!current) return { rel, abs, missing: true };
    const base = { rel, abs, current, currentSha: sha256(current) };
    const stored = store.readPristine(rel);
    if (stored) {
      const storedSha = sha256(stored);
      if (base.currentSha === storedSha || state.files[rel]?.builtSha === base.currentSha)
        return { ...base, pristine: stored, pristineSha: storedSha, source: "stored", drift: false };
      if (current.includes(FOREIGN_MARKER)) {
        // A built file edited by hand (or tampered with). repair: rebuild it from the stored pristine copy.
        if (repair) return { ...base, pristine: stored, pristineSha: storedSha, source: "stored", drift: true };
        return { ...base, drift: true, blocked: `${rel} was changed outside the engine and still contains local patches; plan with repair to rebuild it from the stored original, or reinstall Paperclip` };
      }
      return { ...base, pristine: current, pristineSha: base.currentSha, source: "refreshed", drift: true, previousPristineSha: storedSha };
    }
    if (!current.includes(FOREIGN_MARKER)) return { ...base, pristine: current, pristineSha: base.currentSha, source: "current", drift: false };
    // Patched before the engine took over (apply.sh): accept <file>.orig if rebuilding it with the same patches reproduces
    // the file exactly, or, with adoptOrig (migration from apply.sh with different patch files), any marker-free .orig.
    const orig = readOrNull(`${abs}.orig`);
    if (!orig || orig.includes(FOREIGN_MARKER))
      return { ...base, blocked: `${rel} already contains local patches made outside the engine and has no clean ${rel}.orig next to it` };
    const ids = Object.values(catalog).filter((c) => c.rel === rel && current.includes(c.marker)).map((c) => c.id).sort(comparePatchIds);
    const b = build(rel, orig, ids);
    if (b.ok && b.content.equals(current)) return { ...base, pristine: orig, pristineSha: sha256(orig), source: "orig", drift: false };
    if (adoptOrig) return { ...base, pristine: orig, pristineSha: sha256(orig), source: "orig-unverified", drift: false };
    return { ...base, blocked: `${rel} already contains local patches that differ from this package's; adopt ${rel}.orig as the original (adoptOrig) to take over` };
  }

  /** opts.repair: rebuild built files that were edited outside the engine from their stored originals.
   *  opts.adoptOrig: take over files patched by apply.sh with other patch files, using their `.orig` as the original. */
  async function plan(enabledInput = [], opts = {}) {
    const state = store.readState();
    const desired = [...new Set(enabledInput)];
    const closure = withRequirements(desired);
    const added = order(closure).filter((id) => !desired.includes(id)).map((id) => ({ id, neededBy: desired.filter((d) => dependsOn(d, id)) }));
    const neededOff = state.enabled.filter((id) => !desired.includes(id) && closure.has(id))
      .map((id) => ({ id, neededBy: desired.filter((d) => dependsOn(d, id)) }));

    const files = Object.fromEntries(targets.map((rel) => [rel, resolvePristine(rel, state, opts)]));
    const unavailable = {};
    const markUnavailable = (id, reason) => {
      if (unavailable[id]) return;
      unavailable[id] = reason;
      for (const other of closure) if (hardDependsOn(other, id)) markUnavailable(other, `needs "${getProtection(id).title}", which is unavailable on this install`);
    };
    for (const id of order(closure)) {
      for (const pid of getProtection(id).patches) {
        const c = catalog[pid];
        if (c.missing) markUnavailable(id, `patch ${pid} has no patch file in ${patchesDir}`);
        else if (c.rel && files[c.rel].missing) markUnavailable(id, `${c.rel} does not exist on this install`);
        else if (c.rel && files[c.rel].blocked) markUnavailable(id, files[c.rel].blocked);
      }
    }
    const skipped = new Set();
    const upstream = new Set(); // patches whose change Paperclip's own code now contains (skipped too)
    let built;
    for (let round = 0; ; round++) {
      if (round > 100) throw new Error("plan did not converge");
      built = {};
      let retry = false;
      for (const rel of targets) {
        const f = files[rel];
        if (f.missing || f.blocked) continue;
        const ids = Object.values(catalog)
          .filter((c) => c.rel === rel && closure.has(c.protection) && !unavailable[c.protection] && !skipped.has(c.id))
          .map((c) => c.id).sort(comparePatchIds);
        const b = build(rel, f.pristine, ids);
        if (!b.ok) {
          if (catalog[b.failedId].optional) skipped.add(b.failedId);
          else if (b.upstream) { skipped.add(b.failedId); upstream.add(b.failedId); }
          else markUnavailable(catalog[b.failedId].protection, b.reason);
          retry = true;
          break;
        }
        built[rel] = b;
      }
      if (!retry) break;
    }

    const fileEntries = targets.map((rel) => {
      const f = files[rel];
      const b = built[rel];
      const builtSha = b ? sha256(b.content) : null;
      return {
        rel, missing: Boolean(f.missing), blocked: f.blocked ?? null, drift: Boolean(f.drift), pristineSource: f.source ?? null,
        pristineSha: f.pristineSha ?? null, currentSha: f.currentSha ?? null, builtSha,
        change: Boolean(b) && builtSha !== f.currentSha, patches: b ? b.used : [],
      };
    });
    // A protection counts as unchanged only when the file is what the engine built last time AND the patches of this protection
    // in the planned build are the ones recorded then (same list, same patch file bytes). The file hash alone is not enough: if
    // the list of patches of a protection grows (a new release adds a patch to it), the file on disk still equals the old build.
    // A state written before patch hashes were recorded has no hash to compare: then any planned change of the file counts.
    const patchesCurrent = (p, rel) => {
      const recorded = state.files[rel];
      const planned = (built[rel]?.used ?? []).filter((u) => p.patches.includes(u.id));
      const was = (recorded.patches ?? []).filter((id) => p.patches.includes(id));
      if (planned.length !== was.length || planned.some((u) => !was.includes(u.id))) return false;
      if (recorded.patchShas) return planned.every((u) => recorded.patchShas[u.id] === u.sha);
      return !fileEntries.find((f) => f.rel === rel).change;
    };
    const effective = (p) => state.applied.includes(p.id)
      && protectionFiles(p).every((rel) => state.files[rel]?.builtSha && state.files[rel].builtSha === files[rel].currentSha && patchesCurrent(p, rel));
    // Is the protection in the files right now (the file is what the engine built last time, with this protection's patches in it)?
    // Rebuilding without it then removes it from a running tree; on files an update already made stock there is nothing to remove.
    const inEffect = (p) => state.applied.includes(p.id) && protectionFiles(p).some((rel) => {
      const rec = state.files[rel];
      return rec?.builtSha && rec.builtSha === files[rel].currentSha && (rec.patches ?? []).some((id) => p.patches.includes(id));
    });
    const protections = PROTECTIONS.map((p) => {
      const on = closure.has(p.id);
      let action;
      if (p.kind !== "patch") action = on === state.enabled.includes(p.id) ? "unchanged" : on ? "will-apply" : "will-remove";
      else if (on && unavailable[p.id]) action = "unavailable";
      else if (on) action = effective(p) ? "unchanged" : "will-apply";
      else action = state.applied.includes(p.id) ? "will-remove" : "unchanged";
      return { id: p.id, title: p.title, kind: p.kind, core: p.core, enabled: on, action, reason: unavailable[p.id] ?? null,
        inEffect: action === "unavailable" && inEffect(p),
        upstreamPatches: p.patches.filter((id) => upstream.has(id)),
        skippedPatches: p.patches.filter((id) => skipped.has(id) || (catalog[id].optional && catalog[id].candidates.length === 0)) };
    });
    const result = {
      createdAt: new Date().toISOString(), tree, paperclipVersion: version, vkey, patchesDir,
      requested: desired, enabled: order(closure), added, neededOff, unavailable,
      // A core protection leaves the files in two ways: switched off (will-remove), or switched on but no longer fitting this Paperclip while
      // it is IN the files now (new patch files that do not fit the tree the engine built): rebuilding then would silently drop it, which
      // counts as switching it off. Either way the owner confirms; `unavailable` tells the two apart (and `reason` says why it no longer fits).
      // A protection that no longer fits files an update already made stock is not in the files: nothing is dropped, it is just skipped
      // (see `unfitting`), and everything that still fits is applied.
      confirmationNeeded: protections.filter((p) => p.core && (p.action === "will-remove" || p.inEffect))
        .map((p) => ({ id: p.id, title: p.title, risk: getProtection(p.id).risk ?? null, unavailable: p.action === "unavailable", reason: p.action === "unavailable" ? p.reason : null })),
      // Switched-on protections (available ones) whose change is now part of Paperclip itself: no longer needed, informational only.
      nowUpstream: protections.filter((p) => p.enabled && p.action !== "unavailable" && p.upstreamPatches.length)
        .map((p) => ({ id: p.id, title: p.title, patches: p.upstreamPatches })),
      // Switched-on core protections that do not fit this Paperclip (skipped, still enabled), with what the owner should be told.
      unfitting: protections.filter((p) => p.core && p.action === "unavailable").map((p) => ({ id: p.id, title: p.title, risk: getProtection(p.id).risk ?? null, reason: p.reason, held: p.inEffect })),
      protections, files: fileEntries, changes: fileEntries.filter((f) => f.change).length,
    };
    result.restartNeededAfterApply = result.changes > 0;
    plans.set(result, { files, built, unavailable, state });
    return result;
  }

  /** The data dir may only be used for the tree it was made for. An update inside the same folder (installs/npm/<version>)
   *  or a tree that is gone is fine; two live installs sharing one data dir are not. */
  function treeMismatch(state) {
    if (!options.refuseTreeChange || !state.tree || state.tree === tree) return null;
    if (path.dirname(state.tree) === path.dirname(tree) || !fs.existsSync(state.tree)) return null;
    return `the data dir ${store.dir} belongs to the Paperclip install at ${state.tree}, not ${tree}; nothing was changed`;
  }

  function commitFiles(changes) {
    const staged = [];
    try {
      for (const c of changes) { const tmp = tempNameFor(c.abs); staged.push({ c, tmp }); io.writeFile(tmp, c.content, c.mode); }
    } catch (e) {
      for (const s of staged) fs.rmSync(s.tmp, { force: true });
      throw e;
    }
    const done = [];
    try {
      for (const s of staged) { io.rename(s.tmp, s.c.abs); done.push(s); }
    } catch (e) {
      for (const s of staged) if (!done.includes(s)) fs.rmSync(s.tmp, { force: true });
      const failed = [];
      for (const s of done.reverse()) { try { writeFileAtomic(s.c.abs, s.c.old, s.c.mode); } catch (re) { failed.push(`${s.c.rel}: ${re.message}`); } }
      if (failed.length) e.message += `; ROLLBACK FAILED for ${failed.join(", ")}`;
      throw e;
    }
  }

  async function apply(planned, { confirmCoreOff = false } = {}) {
    const internal = plans.get(planned);
    if (!internal) throw new Error("apply() needs a plan returned by plan() of this engine");
    const fail = (error) => ({ ok: false, error, changed: [], applied: [], unavailable: planned.unavailable });
    if (planned.confirmationNeeded.length && !confirmCoreOff) {
      const quoted = (list) => list.map((p) => `"${p.title}"`).join(", ");
      const dropped = planned.confirmationNeeded.filter((p) => p.unavailable);
      const off = planned.confirmationNeeded.filter((p) => !p.unavailable);
      return fail([off.length ? `switching off ${quoted(off)} needs confirmation` : null,
        dropped.length ? `${quoted(dropped)} no longer fit${dropped.length === 1 ? "s" : ""} this Paperclip; rebuilding the files would remove ${dropped.length === 1 ? "it" : "them"}, which needs confirmation` : null].filter(Boolean).join("; "));
    }
    for (const rel of targets) {
      const cur = readOrNull(path.join(tree, rel));
      if ((cur ? sha256(cur) : null) !== (internal.files[rel].currentSha ?? null)) return fail(`${rel} changed after the plan was made; plan again (nothing was changed)`);
    }
    const state = store.readState();
    const mismatch = treeMismatch(state);
    if (mismatch) return fail(mismatch);
    store.ensure();
    if (state.tree && state.tree !== tree) store.event("tree-changed", { from: state.tree, to: tree, paperclipVersion: version });
    for (const rel of targets) {
      const f = internal.files[rel];
      if (f.missing || f.blocked || f.source === "stored") continue;
      store.writePristine(rel, f.pristine);
      store.event(f.source === "refreshed" ? "pristine-refreshed" : "pristine-stored", { rel, sha256: f.pristineSha, from: f.source, previousSha256: f.previousPristineSha ?? null });
    }
    const changes = planned.files.filter((f) => f.change)
      .map((f) => ({ rel: f.rel, abs: path.join(tree, f.rel), content: internal.built[f.rel].content, old: internal.files[f.rel].current, mode: modeOf(path.join(tree, f.rel)) }));
    try {
      commitFiles(changes);
    } catch (e) {
      store.event("apply-failed", { error: e.message });
      return fail(`could not write the rebuilt files (${e.message}); nothing was changed`);
    }
    const now = new Date().toISOString();
    const applied = planned.protections.filter((p) => p.enabled && p.action !== "unavailable").map((p) => p.id);
    const changedIds = planned.protections.filter((p) => p.action === "will-apply" || p.action === "will-remove").map((p) => p.id);
    const files = { ...state.files };
    for (const f of planned.files) {
      if (f.missing || f.blocked) continue;
      files[f.rel] = { pristineSha: f.pristineSha, builtSha: f.builtSha, patches: f.patches.map((u) => u.id),
        patchShas: Object.fromEntries(f.patches.map((u) => [u.id, u.sha])) };
    }
    const changedAt = { ...(state.changedAt ?? {}) };
    if (changes.length) for (const id of changedIds) changedAt[id] = now;
    const next = {
      ...emptyState(), tree, paperclipVersion: version, enabled: planned.enabled, applied, unavailable: planned.unavailable, files, changedAt,
      appliedAt: changes.length ? now : state.appliedAt,
      restartPending: state.restartPending || changes.length > 0,
      pending: changes.length ? [...new Set([...(state.pending ?? []), ...changedIds])] : (state.pending ?? []),
    };
    store.writeState(next);
    store.event("applied", { enabled: next.enabled, applied, unavailable: Object.keys(planned.unavailable), changed: changes.map((c) => c.rel) });
    return { ok: true, changed: changes.map((c) => c.rel), applied, unavailable: planned.unavailable, restartNeeded: changes.length > 0 || next.restartPending };
  }

  async function status({ serverStartedAt } = {}) {
    const state = store.readState();
    const started = serverStartedAt !== undefined ? serverStartedAt : restartInfo().startedAt;
    const restartNeeded = started && state.appliedAt ? Date.parse(state.appliedAt) > Date.parse(started) : Boolean(state.restartPending);
    const files = targets.map((rel) => {
      const cur = readOrNull(path.join(tree, rel));
      const pristine = store.readPristine(rel);
      const pristineSha = pristine ? sha256(pristine) : null;
      const builtSha = state.files[rel]?.builtSha ?? null;
      const expected = builtSha ?? pristineSha;
      const currentSha = cur ? sha256(cur) : null;
      let s;
      if (!cur) s = "missing";
      else if (!expected) s = cur.includes(FOREIGN_MARKER) ? "foreign-patched" : "unmanaged";
      else if (currentSha === expected) s = builtSha && builtSha !== pristineSha ? "built" : "pristine";
      else s = "drifted";
      return { rel, state: s, currentSha, builtSha, pristineSha, patches: state.files[rel]?.patches ?? [] };
    });
    const byRel = Object.fromEntries(files.map((f) => [f.rel, f]));
    const protections = PROTECTIONS.map((p) => {
      const on = state.enabled.includes(p.id);
      const pendingRestart = restartNeeded && (started && state.changedAt?.[p.id] ? Date.parse(state.changedAt[p.id]) > Date.parse(started) : (state.pending ?? []).includes(p.id));
      let s;
      if (!on) s = "off";
      else if (p.kind !== "patch") s = "on";
      else if (state.unavailable[p.id]) s = "unavailable";
      else if (protectionFiles(p).some((rel) => ["drifted", "missing"].includes(byRel[rel].state))) s = "drifted";
      else s = pendingRestart ? "pending-restart" : "applied";
      return { id: p.id, title: p.title, kind: p.kind, core: p.core, status: s, pendingRestart, reason: state.unavailable[p.id] ?? null };
    });
    return { tree, paperclipVersion: version, enabled: state.enabled, appliedAt: state.appliedAt, serverStartedAt: started ?? null, restartNeeded, protections, files };
  }

  async function restoreAll({ force = false } = {}) {
    const state = store.readState();
    const mismatch = treeMismatch(state);
    if (mismatch) return { ok: false, error: mismatch, restored: [], skipped: [] };
    const changes = [];
    const skipped = [];
    for (const rel of store.listPristine()) {
      const abs = path.join(tree, rel);
      const pristine = store.readPristine(rel);
      const cur = readOrNull(abs);
      if (!cur) { skipped.push({ rel, reason: "file is missing" }); continue; }
      if (cur.equals(pristine)) continue;
      if (force || sha256(cur) === state.files[rel]?.builtSha) changes.push({ rel, abs, content: pristine, old: cur, mode: modeOf(abs) });
      else skipped.push({ rel, reason: "changed outside the engine (for example by a Paperclip update); left as it is" });
    }
    try {
      commitFiles(changes);
    } catch (e) {
      store.event("restore-failed", { error: e.message });
      return { ok: false, error: `could not restore (${e.message}); nothing was changed`, restored: [], skipped };
    }
    // Clear everything, except the originals of files left alone, so `force` can still put those back later.
    const kept = skipped.filter((s) => store.readPristine(s.rel)).map((s) => s.rel);
    if (kept.length) { for (const rel of store.listPristine()) if (!kept.includes(rel)) store.removePristine(rel); }
    else store.clear();
    const now = new Date().toISOString();
    store.writeState({ ...emptyState(), files: Object.fromEntries(kept.filter((rel) => state.files[rel]).map((rel) => [rel, state.files[rel]])),
      restartPending: state.restartPending || changes.length > 0, appliedAt: changes.length ? now : state.appliedAt });
    store.event("restored", { restored: changes.map((c) => c.rel), skipped });
    return { ok: true, restored: changes.map((c) => c.rel), skipped, restartNeeded: changes.length > 0 };
  }

  async function markRestarted() {
    const state = store.readState();
    store.writeState({ ...state, restartPending: false, pending: [] });
  }

  return {
    tree, patchesDir, dataDir: store.dir, paperclipVersion: version, vkey, targets,
    protections: () => PROTECTIONS.map((p) => ({ ...p, files: protectionFiles(p) })),
    plan,
    /** Rebuild the switched-on set against the current files (after a Paperclip update or on start). */
    replan: (opts) => plan(store.readState().enabled, opts),
    apply,
    status,
    restoreAll,
    markRestarted,
    restartInfo,
    /** noBlock: only queue the restart (needed when the caller runs inside Paperclip and is stopped by it). */
    restart: async ({ noBlock = false } = {}) => { const r = runRestart(restartInfo(), { noBlock }); if (r.ok) await markRestarted(); return r; },
    events: () => store.readEvents(),
  };
}
