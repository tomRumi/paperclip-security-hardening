# Hardening engine

Rebuilds Paperclip's own files from pristine copies plus the protections that are switched on. Plain ES modules,
Node 20+ built-ins only (`fs`, `path`, `crypto`, `child_process`), plus GNU `patch` on PATH. No npm dependencies.

| File | Role |
|---|---|
| `registry.js` | The protections (id, owner-facing title/description, patch ids, `requires` (hard: the protection is unavailable too when one does not fit) and `softRequires` (switched on together, but not needed), `core` + `risk`, `kind`) and the patch table (marker, `notNeededOn`) |
| `patches.js` | Finds patch files, orders variants, trial-builds one file with `patch -p1 -N -F0` (dry run, then real, then marker check) in a temp dir |
| `store.js` | Data dir: pristine copies, `state.json`, `events.jsonl`; atomic writes |
| `target.js` | Which Paperclip install the engine works on: derived from the running server process (`/proc/<pid>`), strict, see "Which Paperclip" below |
| `restart.js` | Restart hook (systemd user unit detection; restart only on request) |
| `index.js` | `createEngine()` |

## API

```js
import { createEngine } from "./src/engine/index.js";
const engine = createEngine({
  treeDir,     // REQUIRED: the Paperclip install to change. There is no default and no environment fallback.
  dataDir,     // REQUIRED: pristine copies, state and events of that install
  patchesDir,  // default: <plugin>/patches when packed (npm prepack copies host/patches there), else <package>/host/patches
  restart,     // {unit, cgroup, pid} (a unit verified to run the server, from target.js) or {unit: null, reason}
  unitName,    // alternative to `restart`: a unit the caller chose (the CLI's --unit); not verified. Neither: no restart offered
  systemctl,   // path to systemctl, or null to disable restart detection
  refuseTreeChange, // apply/restore refuse when the data dir was made for another live install tree (the plugin always sets it)
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
  An applied protection is `unchanged` only when its files equal the last build AND its patches in the planned build are the
  recorded ones (same list, same patch file bytes: `files[rel].patches` and `patchShas`). A release that adds a patch to a
  protection, or reworks a patch file, therefore shows `will-apply` for that protection only, and only it is marked as
  waiting for the restart. A state written before `patchShas` existed has no hash to compare: any planned change of the file
  counts for the protections on it.
  `confirmationNeeded` lists the core protections being switched off, with their `risk`, and the core protections that are IN the files now (`inEffect`) but no longer fit (`unavailable: true`, with the `reason`): rebuilding would drop them, which counts as switching them off. A core protection that does not fit files that are stock again (a Paperclip update) drops nothing: it is listed in `unfitting` (skipped, still enabled) and everything else is applied. `nowUpstream` lists protections with a patch that does not apply forward but whose change, without our comments, reverse-applies cleanly to the file: Paperclip contains it itself, the patch is skipped and the protection counts as satisfied.
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

## Which Paperclip

The engine changes only what its caller names. The plugin worker is a plain fork of the Paperclip server and gets no
`PAPERCLIP_HOME`, instance id or home directory of that instance, so its own environment (or `os.homedir()`) would
always point at the default install, even when it serves another instance of the same user. `target.js` therefore
derives the target from the server process that started the worker (`/proc/<ppid>`):

1. The process must be a node process of the same user, started as `node [options] <tree>/node_modules/paperclipai/dist/index.js run [flags]`
   (the managed `paperclipai` install, which is also how `paperclipai service install` starts it). The tree is the real
   path of that script's `<tree>`, and it must hold `@paperclipai/server`. Any other launcher (Docker with another layout,
   pm2, a `tsx` dev run, another subcommand) is refused.
2. Instance id and home follow Paperclip's own rule: the `--instance/-i` and `--data-dir/-d` flags of that command line win
   over the server's start-up environment (`PAPERCLIP_INSTANCE_ID`, `PAPERCLIP_HOME`), then the defaults (`default`,
   `<HOME of the server>/.paperclip`). Instance root = `<home>/instances/<id>`. The server's config file (`-c`,
   `PAPERCLIP_CONFIG`, a `.paperclip/config.json` above its working directory) must be that instance's `config.json`;
   otherwise the layout is unusual and the target is refused. `paperclipai run` also loads `.env` files without
   overriding anything already set (a variable that is set, even empty, is never overridden): first the one beside the config
   resolved from the start-up environment alone (the default instance's when only `--instance` is given), then the one beside
   the config it then runs with, and finally the `.env` in the server's working directory (loaded by the server module itself;
   skipped when `PAPERCLIP_DISABLE_CWD_ENV_FILE` is exactly `true` or it is the same file as the previous one). The first source
   that has a key wins. Files are parsed with dotenv's own rules (same pattern as the installed dotenv: `KEY=value`, `KEY: value`,
   `export`, quotes, `# comments`, multiline values), and only these variables are read from them: `PAPERCLIP_HOME`,
   `PAPERCLIP_INSTANCE_ID`, `PAPERCLIP_CONFIG`, `PAPERCLIP_HARDENING_CONFIG`, `PAPERCLIP_SANDBOX_WORKSPACE_ROOT`,
   `PAPERCLIP_DISABLE_CWD_ENV_FILE` and `RUN_LOG_BASE_PATH`. A `PAPERCLIP_HOME`, `PAPERCLIP_INSTANCE_ID` or `PAPERCLIP_CONFIG` that
   only such a `.env` supplies and that Paperclip then uses (no flag, not in the environment, not empty) is a `CONFIG_LAYOUT`
   refusal. Refusal messages and evidence name variables, files and flags, never a value.
3. Data dir = `<home>/sandbox-hardening`. Settings file read by the patched Paperclip = the server's absolute
   `PAPERCLIP_HARDENING_CONFIG` (environment, else the first of those `.env` files that has it), else
   `<instance root>/hardening/config.json`. Run logs = the server's `RUN_LOG_BASE_PATH` (environment, else the first `.env` that has it; used untrimmed and resolved against the server's working directory, as its run-log store does), else `<instance root>/data/run-logs`.
   The patched server resolves the same file without parsing anything itself: `process.env.PAPERCLIP_HARDENING_CONFIG` (set by the
   start-up environment or the `.env` that `paperclipai run` loaded before it imports the server) and `resolvePaperclipInstanceRoot()`
   (reads the `PAPERCLIP_HOME` and `PAPERCLIP_INSTANCE_ID` that `--data-dir` and `--instance` set), so both sides land on one file.
   The server uses the file only if it is trusted (see "The settings file" below); the writer applies the same rules first.
4. Restart: only a systemd user unit that really runs this server. `/proc/<pid>/cgroup` must name a `.service` below this
   user's `user@<uid>.service`, the unit must be Paperclip's own name for the instance (`paperclipai.service` for
   `default`, else `paperclipai-<id>.service`), and `systemctl --user show` must report that exact control group with
   the server as its main process (or a member of the group). Anything else (a terminal session, Docker, cgroup v1, a
   differently named unit) gives no restart button; the page says why.
5. Guards: if a symlink on the way to the script (for example `cli/current`) was changed after the server started, the
   files on disk are not what runs and the target is refused until Paperclip restarts. The server process is identified
   by pid, start time and command line, and checked again before every write. Only the variables named above are read
   from `/proc/<pid>/environ`; every other value is dropped unread and nothing from it is logged.

Refusal codes: `NO_PARENT`, `FOREIGN_UID`, `PROC_UNREADABLE` (gone, or `/proc` mounted with `hidepid`), `UNKNOWN_LAUNCHER`,
`NO_TREE`, `STALE_LAUNCH`, `BAD_INSTANCE`, `CONFIG_LAYOUT`, `BAD_CONFIG_PATH`, `INSTANCE_MISMATCH`, `TARGET_CHANGED`. With no target the
Hardening page shows the reason, every action that would change something refuses (after the admin check), no settings file
is written, and nothing is re-applied on start (one alert issue per failure code). There is deliberately no setting that
points the plugin at another tree or unit: an admin-editable path would let a plugin-settings edit steer file writes and
restarts. Unsupported layouts use the command-line tool below.

`refuseTreeChange` (set by the plugin and by the CLI's derived targets) protects a data dir that belongs to another install:
`apply` and `restoreAll` refuse when the stored tree differs from the current one, unless both live in the same folder (a
managed `installs/npm/<version>` update) or the old tree is gone.

## The settings file

The patched server (0003, 0005a) takes allowlists, read-only paths and workspace roots from this file, so it must be a file
no agent run can write. The server reads it once at startup, and ignores it (secure built-in defaults stay; one warning,
`event: "sandbox_enforcement"`, `action: "ignore_hardening_config"`, with the reason) unless all of these hold:

* its path is absolute, and its real path (links resolved) is not inside `<instance root>/workspaces`, `/projects` or
  `/companies`, nor inside a workspace root. These are the directories a sandboxed run mounts read-write: the run's workspace
  (`workspaceDir` in `adapter-utils/dist/local-process-sandbox.js`, `mount(workspaceDir, "rw")`), the managed paths of the
  adapters (`adapter-claude-local/dist/server/execute.js`: the per-agent `claude-runtime` under `<instance root>/companies/<company>/agents/<agent>`;
  the Codex home under `companies/<company>/codex-home`) and writable extra paths, which the sandbox only allows inside the
  workspace or for git common dirs that patch 0006a requires to lie inside the workspace roots. The workspace roots are not a
  fixed list: they are the ones patch 0003 enforces for every run (`workspaceRoots` of the file itself, and
  `PAPERCLIP_SANDBOX_WORKSPACE_ROOT`), so the check uses the same data (`sandboxWritableRoots` in `src/settings.js` on the
  writer side, the same expression in both patches on the reader side). `<instance root>/hardening/` is fine;
* the file is a regular file owned by the service user with mode 0600, and its directory is owned by the service user and
  not group- or world-writable.

The writer (`writeHardeningConfig`) checks the same before it writes, refuses with the reason when an existing file or
directory fails (it changes neither), creates a missing directory with mode 0700, and writes the file with mode 0600 through a
temporary file and a rename. A refused save stores nothing and the Hardening page shows the reason. The target reports the
server's `PAPERCLIP_SANDBOX_WORKSPACE_ROOT` (`sandboxRootsEnv`) so the writer can keep clear of it.

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
<dataDir>/state.json      {enabled, applied, unavailable, files: {rel: {pristineSha, builtSha, patches, patchShas}}, appliedAt,
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

`--enable` takes protection ids, `defaults`, `all` or `none`. Exit codes: 0 ok, 1 error or nothing changed, 2 usage. The CLI
never restarts Paperclip; it prints the restart command when one is needed.

Which Paperclip it works on is printed first (`target (...)`: tree, data dir, settings file, restart unit; `--json` has the
same under `target`):

| Flags | Target |
|---|---|
| `--pid N` | The running server process N, derived exactly as the plugin does (read only; refuses what the plugin refuses) |
| `--instance ID [--home DIR]` | The managed install of that instance: tree `<home>/cli/current`, data `<home>/sandbox-hardening`, unit `paperclipai.service` / `paperclipai-<id>.service` (assumed, not verified). Home: `--home`, else `$PAPERCLIP_HOME`, else `~/.paperclip` |
| none of these | The default instance, as `apply.sh`: tree `$PAPERCLIP_TREE` or `~/.paperclip/cli/current`, data `$PAPERCLIP_HARDENING_DATA` or `~/.paperclip/sandbox-hardening` |
| `--tree DIR`, `--data DIR`, `--unit NAME`, `--no-systemd` | Explicit values; they win over everything above. `--patches DIR` and `--json` are unrelated options |

The CLI is run by an operator who chooses the target, so it keeps the default-instance rule; the plugin never uses it.

Tests: `node --test plugin/test/` (the engine tests copy only the target files into a scratch dir; see the header of
`test/engine.test.mjs`).
