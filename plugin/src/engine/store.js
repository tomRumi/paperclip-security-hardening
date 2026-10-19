// Data dir: pristine copies, state and the event log. Layout:
//   <dataDir>/state.json          enabled / applied / unavailable sets, per-file pristine + built sha256, restart flag
//   <dataDir>/pristine/<rel>      byte-exact original of each Paperclip file the engine manages (rel = path in the tree)
//   <dataDir>/events.jsonl        one JSON object per line: pristine stored/refreshed, applied, apply-failed, restored
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

export function emptyState() {
  return { schema: 1, tree: null, paperclipVersion: null, enabled: [], applied: [], unavailable: {}, files: {}, appliedAt: null, restartPending: false };
}

/** Write a file durably next to its final place, then rename over it (atomic on one filesystem). */
export function writeFileAtomic(target, content, mode) {
  const tmp = tempNameFor(target);
  writeDurable(tmp, content, mode);
  try { fs.renameSync(tmp, target); } catch (e) { fs.rmSync(tmp, { force: true }); throw e; }
}

export function tempNameFor(target) {
  return path.join(path.dirname(target), `.${path.basename(target)}.hardening-${process.pid}-${crypto.randomBytes(4).toString("hex")}`);
}

export function writeDurable(file, content, mode = 0o644) {
  const fd = fs.openSync(file, "wx", mode);
  try {
    fs.writeSync(fd, content);
    fs.fchmodSync(fd, mode);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export class Store {
  constructor(dataDir) {
    this.dir = dataDir;
    this.stateFile = path.join(dataDir, "state.json");
    this.eventsFile = path.join(dataDir, "events.jsonl");
    this.pristineDir = path.join(dataDir, "pristine");
  }

  ensure() { fs.mkdirSync(this.pristineDir, { recursive: true, mode: 0o700 }); }

  readState() {
    try { return { ...emptyState(), ...JSON.parse(fs.readFileSync(this.stateFile, "utf8")) }; }
    catch (e) { if (e.code === "ENOENT") return emptyState(); throw new Error(`cannot read ${this.stateFile}: ${e.message}`); }
  }

  writeState(state) { fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 }); writeFileAtomic(this.stateFile, `${JSON.stringify(state, null, 2)}\n`, 0o600); }

  pristinePath(rel) { return path.join(this.pristineDir, rel); }

  readPristine(rel) {
    try { return fs.readFileSync(this.pristinePath(rel)); } catch (e) { if (e.code === "ENOENT") return null; throw e; }
  }

  writePristine(rel, content) {
    const p = this.pristinePath(rel);
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
    writeFileAtomic(p, content, 0o600);
  }

  removePristine(rel) { fs.rmSync(this.pristinePath(rel), { force: true }); }

  listPristine() {
    const out = [];
    const walk = (dir) => {
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { if (e.code === "ENOENT") return; throw e; }
      for (const e of entries) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.isFile() && !e.name.includes(".hardening-")) out.push(path.relative(this.pristineDir, p).split(path.sep).join("/"));
      }
    };
    walk(this.pristineDir);
    return out.sort();
  }

  clear() {
    fs.rmSync(this.pristineDir, { recursive: true, force: true });
    fs.rmSync(this.stateFile, { force: true });
  }

  event(type, data = {}) {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    fs.appendFileSync(this.eventsFile, `${JSON.stringify({ at: new Date().toISOString(), type, ...data })}\n`, { mode: 0o600 });
  }

  readEvents() {
    try { return fs.readFileSync(this.eventsFile, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); }
    catch (e) { if (e.code === "ENOENT") return []; throw e; }
  }
}
