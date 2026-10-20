# Paperclip plugin: Security hardening

One switch per sandbox protection, Agent boxes with daily token caps, a self-test after every restart, and one-line installs for the
watchdog and the Hermes wrapper. What it protects, the assumptions, the switch table, the install lines and the known limits are in the
[root README](../README.md); the design is in [docs/PLUGIN-PLAN.md](../docs/PLUGIN-PLAN.md).

* **Hardening page** (admin only): switches with dependencies, Save shows the plan, the affected Paperclip files are rebuilt from their
  originals plus the switched-on protections (`src/engine`, all-or-nothing), then one restart. "Restore originals" puts every original
  back. On every worker start the switched-on set is rebuilt against the current files (no version lock; a protection whose target
  code changed shows "unavailable on this install"). A self-test checks each applied protection after the restart.
* **Agent boxes page:** one row per existing agent with its box and daily cap (default, per-agent override, company cap, new-company
  template). The SDK cannot update agents, so a box change is shown as a `PATCH` for an admin to apply. `claude_local` and
  `opencode_local` are boxable. Each row also shows what this version does with its adapter type (boxed, Hermes wrapper, needs a
  remote exception, excepted, planned for a later version, not supported), its findings (for example engine not `cli` on
  `claude_local`, or stored `env` names such as `HOME`, `XDG_*_HOME` or `CLAUDE_CONFIG_DIR` that the server drops) and, when keys
  are missing, the exact `PATCH /api/agents/:id` body that fixes them. Nothing is written automatically; env names to remove are listed, not rebuilt.
* **ITSec agent** (`src/itsec.js`, declarations in `src/itsec-declarations.js`, instructions in `src/itsec/`): a plugin-managed, sandboxed security agent that triages alerts and closes one only after its own resolution comment with evidence (otherwise it escalates to the owner; the alert re-check enforces it) with two routines (alert triage, started by alerts above low priority at most every 30 minutes and by a safety-net check only when an alert has no verdict; daily review at 07:00 UTC), created only in the company the operator marks as the host company, verified before its first run and paused on drift. The ITSec card is on the Hardening page; see the root README, "The ITSec agent" and its known limits.
* **Who can change things:** plugin actions are callable by company members and agents, and the plugin is told who calls but not
  whether they are an instance admin. Write actions refuse agents and accept a user only when an instance admin listed their user id
  in the setting "Users who may change protections" (the page shows your id). See `src/hardening.js`.
* **Which Paperclip:** the worker gets no Paperclip home or instance id, so the engine's tree, data folder, settings file and restart unit are derived from the Paperclip server process that started it (`src/engine/target.js`, documented in `src/engine/README.md`). If that fails the page says why and every write refuses; nothing falls back to the default install.
* **Site values** (base allowlist, base allowlist for new OpenCode agents, read-only paths, workspace roots, Hermes wrapper, remote
  exceptions, alert target) are set on the Hardening page. Remote exceptions (`agentId type reason` per line, types `cursor_cloud`,
  `openclaw_gateway`, `hermes_gateway`, `http`, `process`) are saved by admins only like the rest; the worker sets who added one and when, and each
  addition or removal is written to the activity log. An empty OpenCode allowlist uses the common LLM API hosts (no single provider). The plugin writes the part Paperclip needs to the running Paperclip's `$PAPERCLIP_HARDENING_CONFIG`, else `<its instance root>/hardening/config.json`;
  patches 0003 and 0005a read it at startup and fall back to secure generic defaults. They ignore it unless it is outside every
  directory agent runs can write, owned by the service user, mode 0600 in a directory not writable by group or others; the writer
  applies the same rules and refuses otherwise (see "The settings file" in `src/engine/README.md` and `src/settings.js`).
* **Install:** from a clone of the release tag by path (`npm install --omit=dev --ignore-scripts` in this directory, then
  `paperclipai plugin install <absolute path to this directory>` after `paperclipai auth login --instance-admin`; see the root README for the requirements and the per-company admin list). Not published to npm.
* **Packaging:** the patch files stay in the package's `host/patches` (one copy, shared with `apply.sh`). `npm pack` / `npm publish` copy
  them into `plugin/patches` (prepack) and remove the copy afterwards (postpack); the engine uses `plugin/patches` when present, else
  `../host/patches` (git checkout or local-path install).
* **Check:** `npm run validate-manifest` (needs `@paperclipai/shared` installed) and `npm test`. Tests that need Paperclip's files copy
  only the patch targets, in their ORIGINAL bytes, from a stock install into a scratch dir (`test/helpers/pristine.mjs`: the `.orig`
  backup, else the file itself when it carries no `LOCAL-PATCH` marker, else the engine store's copy under
  `~/.paperclip/sandbox-hardening/pristine`, `$PAPERCLIP_HARDENING_ENGINE_DATA` first). The install is `$PAPERCLIP_STOCK_TREE_<vkey>`
  (`PAPERCLIP_STOCK_TREE_1012`, `PAPERCLIP_STOCK_TREE_1005`), else `~/.paperclip/cli/installs/npm/2026.<vkey>.0`; point it at an
  untouched install. Tests only read it. A test that cannot find an original skips with a `NO PRISTINE: ...` message that names the
  file. `HARDENING_LIVE_PATCHES` names the patch dir a hand-patched install was patched from (two comparison tests skip without it);
  `HARDENING_TEST_SCRATCH` sets the scratch parent.
* **Fallback without the plugin:** `node bin/hardening-engine.mjs status|plan|apply|restore` (see `src/engine/README.md`).
