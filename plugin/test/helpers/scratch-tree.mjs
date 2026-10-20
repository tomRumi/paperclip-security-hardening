// A scratch Paperclip tree holding ONLY the files the patches target, copied from the ORIGINAL bytes of a stock install
// (helpers/pristine.mjs: .orig backup, the unpatched file, or the engine store; the install is only read), plus a copy of the
// package's patch files. Same approach as engine.test.mjs.
//   PAPERCLIP_STOCK_TREE_1012 / HARDENING_TEST_SCRATCH as there. A file with no original makes the tests skip, loudly.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SOURCE_PATCHES_DIR } from "../../src/engine/index.js";
import { noPristineSkip, pristineOrNull, stockTreeOrNull } from "./pristine.mjs";

/** The stock install the tests read (read only; see pristine.mjs): $PAPERCLIP_STOCK_TREE_1012, else ~/.paperclip/cli/installs/npm/2026.1012.0. */
export const stockTreeForTests = (vkey = "1012") => stockTreeOrNull(vkey);

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

export function makeScratchBase(prefix, vkey = "1012") {
  const stock = stockTreeForTests(vkey);
  const targets = [...new Set(fs.readdirSync(SOURCE_PATCHES_DIR).filter((n) => n.endsWith(".patch")).map((n) => readPatchTarget(path.join(SOURCE_PATCHES_DIR, n))))].sort();
  if (!stock) return { skip: `NO STOCK TREE: no Paperclip 2026.${vkey}.0 install found; set PAPERCLIP_STOCK_TREE_${vkey} to an untouched install` };
  const noOrig = noPristineSkip(stock, targets, vkey);
  if (noOrig) return { skip: noOrig };
  const root = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), prefix));
  const base = path.join(root, "base");
  for (const rel of targets) {
    fs.mkdirSync(path.dirname(path.join(base, "tree", rel)), { recursive: true });
    fs.writeFileSync(path.join(base, "tree", rel), pristineOrNull(stock, rel));
  }
  const pj = "node_modules/@paperclipai/server/package.json";
  fs.mkdirSync(path.dirname(path.join(base, "tree", pj)), { recursive: true });
  fs.copyFileSync(path.join(stock, pj), path.join(base, "tree", pj));
  fs.cpSync(SOURCE_PATCHES_DIR, path.join(base, "patches"), { recursive: true, filter: (s) => s === SOURCE_PATCHES_DIR || s.endsWith(".patch") });
  let n = 0;
  return {
    skip: false, root, stock, targets,
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
