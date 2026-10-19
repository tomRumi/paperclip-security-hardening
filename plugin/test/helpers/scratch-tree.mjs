// A scratch Paperclip tree holding ONLY the files the patches target, copied from the live tree's pristine `.orig`
// backups (the live tree is only read), plus a copy of the package's patch files. Same approach as engine.test.mjs.
//   PAPERCLIP_TREE / HARDENING_TEST_SCRATCH as there.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { locateTree, SOURCE_PATCHES_DIR } from "../../src/engine/index.js";
import { readPatchTarget } from "../../src/engine/patches.js";

export function makeScratchBase(prefix) {
  let live = null;
  try { live = locateTree(); } catch { live = null; }
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
      return { dir, tree: engineOptions.treeDir, engineOptions, configPath: path.join(dir, "instance", "hardening", "config.json"), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
    },
    cleanup: () => fs.rmSync(root, { recursive: true, force: true }),
  };
}
