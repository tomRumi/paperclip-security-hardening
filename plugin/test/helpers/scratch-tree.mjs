// A scratch Paperclip tree holding ONLY the files the patches target, copied from the live tree's pristine `.orig`
// backups (the live tree is only read), plus a copy of the package's patch files. Same approach as engine.test.mjs.
//   PAPERCLIP_TREE / HARDENING_TEST_SCRATCH as there.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { locateTree, SOURCE_PATCHES_DIR } from "../../src/engine/index.js";

/** The live install this machine runs (read only; the tests copy from it). PAPERCLIP_TREE overrides the managed default. */
export function liveTreeOrNull(env = process.env) {
  try { return locateTree({ treeDir: env.PAPERCLIP_TREE || path.join(os.homedir(), ".paperclip", "cli", "current") }); } catch { return null; }
}

/** A target as src/engine/target.js derives it, for tests that do not run a server process (no fingerprint, no unit). */
export function fakeTarget(over = {}) {
  const instanceRoot = over.instanceRoot ?? "/nonexistent/instances/test";
  return {
    source: "test", pid: null, tree: "/nonexistent/tree", userHome: "/nonexistent/home", home: "/nonexistent", instanceId: "test", instanceRoot,
    dataDir: "/nonexistent/data", configPath: path.join(instanceRoot, "hardening", "config.json"), runLogBase: path.join(instanceRoot, "data", "run-logs"),
    startedAt: undefined, restart: { unit: null, reason: "test target" }, fingerprint: null, ...over,
  };
}
/** createHardening options that serve this target. */
export const hardeningFor = (target, engineOptions = {}) => ({ resolveTargetFn: () => ({ ok: true, target }), engineOptions });
import { readPatchTarget } from "../../src/engine/patches.js";

export function makeScratchBase(prefix) {
  const live = liveTreeOrNull();
  const targets = [...new Set(fs.readdirSync(SOURCE_PATCHES_DIR).filter((n) => n.endsWith(".patch")).map((n) => readPatchTarget(path.join(SOURCE_PATCHES_DIR, n))))].sort();
  const ok = Boolean(live) && targets.every((rel) => fs.existsSync(path.join(live, `${rel}.orig`)));
  if (!ok) return { skip: "no live Paperclip tree with .orig backups" };
  const root = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), prefix));
  const base = path.join(root, "base");
  for (const rel of targets) {
    fs.mkdirSync(path.dirname(path.join(base, "tree", rel)), { recursive: true });
    fs.copyFileSync(path.join(live, `${rel}.orig`), path.join(base, "tree", rel));
  }
  const pj = "node_modules/@paperclipai/server/package.json";
  fs.mkdirSync(path.dirname(path.join(base, "tree", pj)), { recursive: true });
  fs.copyFileSync(path.join(live, pj), path.join(base, "tree", pj));
  fs.cpSync(SOURCE_PATCHES_DIR, path.join(base, "patches"), { recursive: true, filter: (s) => s === SOURCE_PATCHES_DIR || s.endsWith(".patch") });
  let n = 0;
  return {
    skip: false, root, live, targets,
    baseFile: (rel) => fs.readFileSync(path.join(base, "tree", rel)),
    /** A fresh copy of the base tree with its own data dir; engineOptions for createEngine / createHardening. */
    fresh() {
      const dir = path.join(root, `case-${++n}`);
      fs.cpSync(path.join(base, "tree"), path.join(dir, "tree"), { recursive: true });
      const engineOptions = { treeDir: path.join(dir, "tree"), dataDir: path.join(dir, "data"), patchesDir: path.join(base, "patches"), tmpDir: root, systemctl: null };
      const instanceRoot = path.join(dir, "instance");
      const target = fakeTarget({ tree: engineOptions.treeDir, dataDir: engineOptions.dataDir, instanceRoot });
      // engineOptions (tree, data dir, patches, tmp) are for createEngine; hardening is what createHardening takes.
      return { dir, tree: engineOptions.treeDir, engineOptions, target, hardening: hardeningFor(target, { patchesDir: engineOptions.patchesDir, tmpDir: root, systemctl: null }),
        configPath: target.configPath, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
    },
    cleanup: () => fs.rmSync(root, { recursive: true, force: true }),
  };
}
