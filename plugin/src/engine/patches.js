// Patch files and trial builds. A build always starts from pristine bytes in a private temp dir and applies patches
// with GNU `patch` exactly like apply.sh (-p1 -N -F0): first --dry-run, then for real, then the marker check.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { comparePatchIds } from "./registry.js";

const NAME_RE = /^(\d{4}[a-z]?)-[A-Za-z0-9._-]+?(?:\.(\d{4}))?\.patch$/;
const TARGET_PREFIX = "node_modules/@paperclipai/";

/** Scan a patch dir: Map id -> [{file, vkey|null}] (vkey = the `.<MMDD>` per-version variant suffix, if any). */
export function discoverPatchFiles(patchesDir) {
  const out = new Map();
  for (const name of fs.readdirSync(patchesDir).sort()) {
    const m = NAME_RE.exec(name);
    if (!m) continue;
    const list = out.get(m[1]) ?? [];
    list.push({ file: path.join(patchesDir, name), vkey: m[2] ?? null });
    out.set(m[1], list);
  }
  return out;
}

/** Candidates in order of preference: the variant for this install's vkey, the plain patch, then every other variant
 *  (newest first). Whichever FITS the file is used; the version string never excludes anything. */
export function orderCandidates(files, vkey) {
  const exact = files.filter((f) => vkey && f.vkey === vkey);
  const plain = files.filter((f) => f.vkey === null);
  const others = files.filter((f) => f.vkey !== null && f.vkey !== vkey).sort((a, b) => comparePatchIds(b.vkey, a.vkey));
  return [...exact, ...plain, ...others];
}

/** The single file a patch changes, relative to the tree (from its `+++ b/...` header). */
export function readPatchTarget(file) {
  const targets = new Set();
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.startsWith("+++ ")) continue;
    const raw = line.slice(4).split("\t")[0].trim();
    const rel = raw.split("/").slice(1).join("/"); // -p1
    targets.add(rel);
  }
  if (targets.size !== 1) throw new Error(`${path.basename(file)}: a patch must change exactly one file (found ${targets.size})`);
  const [rel] = targets;
  if (!rel.startsWith(TARGET_PREFIX) || rel.split("/").includes("..") || path.isAbsolute(rel))
    throw new Error(`${path.basename(file)}: target ${rel} is outside ${TARGET_PREFIX}`);
  return rel;
}

function runPatch(dir, file, dryRun, reverse = false) {
  const args = ["-p1", reverse ? "-R" : "-N", "-F0", "--batch", "-s", "--no-backup-if-mismatch", "-r", "-", "-d", dir, "-i", file];
  if (dryRun) args.push("--dry-run");
  const r = spawnSync("patch", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60_000, env: { ...process.env, LC_ALL: "C" } });
  if (r.error?.code === "ENOENT") throw new Error("the `patch` program is required (GNU patch) but was not found on PATH");
  if (r.error) throw r.error;
  return { ok: r.status === 0, output: `${r.stdout ?? ""}${r.stderr ?? ""}`.trim() };
}

/** The patch text without what only we write: comment-only added lines and the trailing `// LOCAL-PATCH ...` comments, hunk counts fixed.
 *  What is left is the code the patch adds; null when none is left (nothing to look for). */
export function withoutOurComments(text) {
  const lines = text.split("\n");
  const isBody = (l) => /^[ +\-\\]/.test(l) && !/^(---|\+\+\+) /.test(l);
  const res = [];
  let added = 0;
  let delta = 0;
  for (let i = 0; i < lines.length;) {
    const h = /^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@(.*)$/.exec(lines[i]);
    if (!h) { if (i < lines.length - 1 || lines[i] !== "") res.push(lines[i]); i++; continue; }
    const body = [];
    for (i++; i < lines.length && isBody(lines[i]); i++) {
      const l = lines[i];
      if (l.startsWith("+") && /^\+\s*\/\//.test(l)) continue;
      body.push(l.startsWith("+") ? l.replace(/\s*\/\/ LOCAL-PATCH\b.*$/, "") : l);
    }
    const oc = body.filter((l) => l[0] === " " || l[0] === "-").length;
    const nc = body.filter((l) => l[0] === " " || l[0] === "+").length;
    added += body.filter((l) => l[0] === "+" && l.slice(1).trim() !== "").length;
    res.push(`@@ -${h[1]},${oc} +${Number(h[1]) + delta},${nc} @@${h[2]}`, ...body);
    delta += nc - oc;
  }
  return added ? `${res.join("\n")}\n` : null;
}

/** Does Paperclip's own code already contain the change this patch makes? True when the patch, without our comments, reverse-applies
 *  cleanly to `content` (dry run). Only used after the patch failed to apply forward. */
function alreadyPresent(root, rel, candidates) {
  for (const cand of candidates) {
    const stripped = withoutOurComments(fs.readFileSync(cand.file, "utf8"));
    if (!stripped) continue;
    const tmp = path.join(root, ".upstream-check.patch");
    fs.writeFileSync(tmp, stripped);
    try { if (runPatch(root, tmp, true, true).ok) return true; } finally { fs.rmSync(tmp, { force: true }); }
  }
  return false;
}

/**
 * Build one target file: pristine bytes + steps in order. steps: [{id, candidates:[{file,vkey}], marker}].
 * Returns {ok:true, content, used:[{id, file, sha}]} or {ok:false, failedId, reason, used, upstream} (upstream: Paperclip's code already
 * contains the change, so the patch is not needed; false: it simply no longer fits).
 */
export function buildFile({ rel, pristine, steps, tmpDir }) {
  const root = fs.mkdtempSync(path.join(tmpDir ?? os.tmpdir(), "hardening-build-"));
  try {
    const target = path.join(root, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, pristine);
    const used = [];
    for (const step of steps) {
      const before = fs.readFileSync(target);
      let chosen = null;
      const tried = [];
      for (const cand of step.candidates) {
        const dry = runPatch(root, cand.file, true);
        if (!dry.ok) { tried.push(`${path.basename(cand.file)}: ${dry.output.split("\n")[0] || "does not fit"}`); continue; }
        const real = runPatch(root, cand.file, false);
        if (real.ok && fs.readFileSync(target, "utf8").includes(step.marker)) { chosen = cand; break; }
        fs.writeFileSync(target, before);
        tried.push(`${path.basename(cand.file)}: applied without its marker`);
      }
      if (!chosen) {
        return { ok: false, failedId: step.id, used, upstream: alreadyPresent(root, rel, step.candidates),
          reason: `patch ${step.id} does not fit ${rel}: the code it changes is missing or has changed shape (${tried.join("; ") || "no patch file"})` };
      }
      // sha: of the patch file's bytes, so a changed patch (same id, same name) is noticed later by the engine's plan
      used.push({ id: step.id, file: path.basename(chosen.file), sha: crypto.createHash("sha256").update(fs.readFileSync(chosen.file)).digest("hex") });
    }
    return { ok: true, content: fs.readFileSync(target), used };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
