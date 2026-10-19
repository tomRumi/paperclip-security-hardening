# Hardening engine

Rebuilds Paperclip's own files from pristine copies plus the protections that are switched on. Plain ES modules,
Node 20+ built-ins only (`fs`, `path`, `crypto`, `child_process`), plus GNU `patch` on PATH. No npm dependencies.

| File | Role |
|---|---|
| `registry.js` | The protections (id, owner-facing title/description, patch ids, `requires`, `core` + `risk`, `kind`) and the patch table (marker, `notNeededOn`) |
| `patches.js` | Finds patch files, orders variants, trial-builds one file with `patch -p1 -N -F0` (dry run, then real, then marker check) in a temp dir |
| `store.js` | Data dir: pristine copies, `state.json`, `events.jsonl`; atomic writes |
| `restart.js` | Restart hook (systemd user unit detection; restart only on request) |
| `index.js` | `createEngine()` |

## API

```js
import { createEngine } from "./src/engine/index.js";
const engine = createEngine({
  treeDir,     // default: $PAPERCLIP_TREE, else realpath(~/.paperclip/cli/current) (same rule as apply.sh)
  patchesDir,  // default: <plugin>/patches when packed (npm prepack copies host/patches there), else <package>/host/patches
  dataDir,     // default: $PAPERCLIP_HARDENING_DATA, else ~/.paperclip/sandbox-hardening
  unitName,    // systemd user unit, default "paperclipai"
  systemctl,   // path to systemctl, or null to disable restart detection
  tmpDir,      // where trial builds go (default: OS temp dir)
});
const plan = await engine.plan(["public-web"], { repair, adoptOrig }); // dry run; changes nothing anywhere
const result = await engine.apply(plan, { confirmCoreOff });           // all-or-nothing write
await engine.status({ serverStartedAt });                               // per protection and per file
await engine.restoreAll({ force });                                     // put every original back
```

- **`plan(enabled)`** adds what the switched-on protections `require` (`added`, with `neededBy`). It lists a protection
  you switched off that others still need in `neededOff`; that one stays on until its dependents are off too. Then
  every target file is trial-built: pristine, then the patches of every switched-on protection that touches the file,
  in global patch-id order. Each protection gets an `action`: `will-apply`, `will-remove`, `unchanged`, or
  `unavailable` (with `reason`). Each file gets `pristineSource`, `builtSha`, `currentSha` and `change`.
  `confirmationNeeded` lists the core protections being switched off, with their `risk`.
  - `repair`: a built file edited outside the engine is rebuilt from its stored original. Without it, that file is
    left alone and its protections are unavailable.
  - `adoptOrig`: takes over files patched by `apply.sh` with different patch files, using the `.orig` next to each one.
    Without it, a `.orig` is only accepted when rebuilding it reproduces the current file exactly.
- **`apply(plan)`** first refuses if any target file changed since the plan, or if core switch-offs are unconfirmed.
  It then stores pristine copies, writes every rebuilt file to a temp file next to it (fsync) and renames them all into
  place. If any write or rename fails, renamed files are put back and nothing changes. An unavailable protection is
  left out together with everything that depends on it; the rest still apply. `replan()` rebuilds the stored enabled
  set, for use on start and after a Paperclip update.
- **`status()`** per protection: `off`, `on` (plugin-job / host-install kinds), `applied`, `pending-restart`,
  `unavailable` or `drifted` (one of its files changed outside the engine). Per file: `pristine`, `built`, `drifted`,
  `missing`, `unmanaged` or `foreign-patched`. `restartNeeded` compares the last change with the server's start time:
  either `serverStartedAt`, or the systemd unit's start time, or the stored flag cleared by `markRestarted()`.
- **`restoreAll()`** writes back every stored original byte for byte, all-or-nothing, and clears the state. A file that
  changed outside the engine (for example a Paperclip update) is left as it is and its original is kept, unless you
  pass `force`.
- **`restartInfo()`** returns `{canRestart, command, commandText, startedAt}`. `restart({noBlock})` runs that command
  (`noBlock` only queues it, for callers that Paperclip's restart stops, such as the plugin worker). `systemctl --user`
  gets the standard `XDG_RUNTIME_DIR` when the caller's environment lacks it (plugin workers do). The engine never
  restarts Paperclip by itself.

## Pristine copies and drift

The first `apply` stores the current version of every target file as its original. If a target file already contains
`LOCAL-PATCH` markers, its `.orig` is used instead (see above). Later, if a file matches neither its stored original nor
the last built result, it was changed outside the engine:

- **No markers in it** (a Paperclip update replaced it): the next plan treats it as the new original, `apply` stores
  it, and a `pristine-refreshed` event is logged.
- **Markers in it** (hand edit or tampering): status shows `drifted`, and only `repair` rebuilds it.

## No version lock

The Paperclip version is never a reason to refuse. A patch is usable wherever it fits the file (`patch --dry-run`
with exact context). Variants named `X.<vkey>.patch` (vkey = the second field of the version, e.g. `1012`) are tried
in this order: the one for this install's vkey, then the plain `X.patch`, then the other variants, newest first.
`notNeededOn` in the patch table only allows skipping a patch on versions where the code it changes does not exist; it
never blocks anything. When no candidate fits, the protection is `unavailable on this install`.

## Data dir

```
<dataDir>/state.json      {enabled, applied, unavailable, files: {rel: {pristineSha, builtSha, patches}}, appliedAt,
                           changedAt, pending, restartPending, tree, paperclipVersion}
<dataDir>/pristine/<rel>  byte-exact originals (rel = path inside the Paperclip tree), mode 0600
<dataDir>/events.jsonl    pristine-stored / pristine-refreshed / tree-changed / applied / apply-failed / restored
```

## CLI (fallback when the plugin cannot run)

```
node plugin/bin/hardening-engine.mjs status
node plugin/bin/hardening-engine.mjs plan    --enable public-web,own-claude-folder
node plugin/bin/hardening-engine.mjs apply   --enable defaults [--confirm-core-off] [--repair] [--adopt-orig]
node plugin/bin/hardening-engine.mjs restore [--force]
```

`--enable` takes protection ids, `defaults`, `all` or `none`. Every command also takes `--tree`, `--patches`, `--data`,
`--unit`, `--no-systemd` and `--json`. Exit codes: 0 ok, 1 error or nothing changed, 2 usage. The CLI never restarts
Paperclip; it prints the restart command when one is needed.

Tests: `node --test plugin/test/` (the engine tests copy only the target files into a scratch dir; see the header of
`test/engine.test.mjs`).
