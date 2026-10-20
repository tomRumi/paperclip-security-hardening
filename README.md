# paperclip-security-hardening

Security hardening for [Paperclip](https://github.com/paperclipai/paperclip) agent runs, installed as a Paperclip plugin.
Every protection has its own switch. Parts that must live outside Paperclip (a watchdog, the Hermes sandbox wrapper) install with one pasted line.

Paperclip agents run real coding tools. This package keeps a misbehaving or prompt-injected agent inside a box it cannot open, stops it
from giving itself more power, and tells you when someone tampers with the protections.

## What it protects

In plain words:

* **The host and its secrets.** An agent's tools see only their workspace, and reach only the network hosts you allow. Claude and OpenCode agents also run with a cleared environment: the server's own variables (database URL, API keys, tokens) never reach them, only the credentials bound to the agent itself.
* **The box itself.** An agent cannot change its own sandbox, network list, commands, instructions or skills. The stored box is forced again at every run, and a hidden `***REDACTED***` value can never overwrite real settings.
* **Unboxed runs.** An agent without a box is refused instead of running unprotected.
* **New agents.** Every new agent (hire, import, join) starts boxed, with no permissions and unable to create agents or skills. Agent types that have an ACP engine (Claude, Codex, Gemini, Kimi) always start on the CLI engine, whatever the creator sent: Paperclip's default engine (ACP) refuses to run inside a box, and a stored ACP value would be trusted for every later run. Names that would move an agent's home or state directory, or change how the box starts, are removed from a new agent's environment.
* **Power and structure.** Agents cannot hand out permissions, cannot change a pipeline's stages, and can assign work to others only with an explicit grant.
* **Privacy between agents.** Each agent's Claude settings and conversations are its own.
* **Cost.** Daily token caps per agent and per company pause runaway agents and say why.
* **Your visibility.** A separate watchdog notices logins, sudo, changed system files and tampering with these protections, and raises alerts as issues.
* **A security agent that reads the alerts.** Once you mark a host company, the plugin keeps a sandboxed ITSec agent there (re-created at every 15-minute check if it is deleted); only clearing the mark removes it. It comments on alerts and is started by alerts and a daily review (see "The ITSec agent").

Not covered: a kernel or sandbox escape (bwrap is a namespace sandbox, not a VM), misuse of a credential an agent is allowed to hold, secrets you keep outside the sandbox, and an attacker who has root or the admin account.

## Paperclip's built-in sandbox and why this plugin exists

Paperclip already has a sandbox mode for local agents. It is set per agent in the adapter settings:

* `filesystemScope: "workspace"` runs the agent's process in bubblewrap (`bwrap`), so it sees its workspace and the system files it needs, and not the rest of the host.
* `networkScope: "deny"` blocks all network access. `networkScope: "allowlist"` allows only the hosts in `networkAllowlist` (exact host names, `host:port` entries or origin URLs, no wildcards), through a filtering proxy.
* `filesystemExtraPaths` adds host paths to the box, and `filesystemSandboxCommand` names the `bwrap` binary.

Both scopes are off by default. They need `bwrap` and, for the types that have an ACP engine, `engine: "cli"` (the ACP engine is rejected).

Paperclip 2026.1012.0 (and the upstream source at commit `cde944e`, 19 October 2026) implements this mode only in the `claude_local` and `codex_local` adapters, and even there the boxed process inherits the server's environment. `opencode_local`, `pi_local`, `gemini_local`, `grok_local`, `kimi_local`, `cursor_local`, the Hermes adapters and the others have no such settings.

This plugin uses that sandbox and does not replace it. It extends it to `opencode_local`, gives the boxed `claude_local` and `opencode_local` agents a cleared environment, and closes these gaps:

| Gap in Paperclip's own behaviour | Closed by |
|---|---|
| An agent may edit its own adapter settings. Paperclip stops agents from changing the command keys (`command`, `args`, `env`, `cwd`, `filesystemSandboxCommand`) but not the sandbox keys, so a prompt-injected agent could widen or remove its own box. | "Agents can't change their own box" |
| Nothing requires a sandbox: an agent with no scope set runs with the full access of the account that runs Paperclip. | "Only boxed agents run" |
| A boxed child process inherits the server's environment: database URL, API keys, secrets master key, `NODE_OPTIONS`. | "Box Claude agents" and "Box OpenCode agents" |
| `opencode_local` has no sandbox settings at all. | "Box OpenCode agents" |
| The board's "Test environment" button starts the adapter's probes on the server, outside any box, from the settings in the request, and any agent that may create agents can press it. | "Only boxed agents run" (board users only) and the box patches (the probes ignore files an agent wrote) |
| An agent that has to read arbitrary websites cannot use `networkAllowlist`, which takes exact host names only. It runs without a network scope, on the host network, where the embedded database (127.0.0.1, default port 54329) is reachable. | "Public-web box" (any public website, nothing local) |
| With the sandbox on, `claude_local` mounts one Claude config folder read-write into every agent's box, so all agents share the same settings, login and conversation history. | "Own Claude folder per agent" |
| Any active agent can assign work to any other agent of its company unless the company has a restrictive assignment policy. | "Assigning work needs a grant" |
| New agents get no sandbox settings and a broad set of default permissions (for example configuring agents, creating skills, assigning work; an agent created directly may also create agents). | "Safe defaults for new agents" and "Agents can't hand out permissions" |

## What runs where

"Only boxed agents run" decides, when a run starts, from the agent's stored settings. This is what it does for each adapter type in this release:

| Adapter type | What happens | What you do |
|---|---|---|
| `claude_local` | Runs in the box (bubblewrap, allowlisted network, own folders) with a cleared environment. | New agents start this way. Bind a Claude credential as an agent secret (see "Credentials"). |
| `opencode_local` | The same: runs in the box with its own home and state folders, a cleared environment, and the common LLM provider hosts on its allowlist. | New agents start this way. Install the `opencode` CLI and bind a provider key (see "Setting up an OpenCode agent"). |
| `hermes_local` | Runs through the root-owned Hermes sandbox wrapper (one-line install below). The command and the working directory are checked at every start. | Install the wrapper. The agent's working directory must lie below a workspace root (see "Known limits"). |
| `cursor_cloud`, `openclaw_gateway`, `hermes_gateway`, `http`, `process` | These run on someone else's machine or outside any box, so there is nothing to put in a box. Refused unless an administrator lists the agent as a remote exception. | Add the agent under "Remote exceptions" (below), if you accept that it runs unprotected. |
| `codex_local`, `gemini_local`, `cursor`, `pi_local`, `kimi_local`, `grok_local` | Refused for now: the run does not start and fails with a message naming what is missing. Boxing for these is planned for later versions. (An agent that has no credentials bound yet fails first with the adapter's own "no credentials" error, for example Codex's `configuration_incomplete`; the refusal naming the unboxed adapter appears once a credential is bound.) | Nothing yet. Switching "Only boxed agents run" off lets them run with whatever settings they have, unprotected by this plugin. |
| Anything else (`paperclip_runner`, `acpx_local`, adapter plugins, unknown types) | Always refused, and an exception is not possible. | - |

Runs placed on a remote execution target (SSH or a sandbox provider) are not checked.

### Cleared environment

A process that Paperclip starts for a Claude or OpenCode agent is normally given the server's whole environment. With "Box Claude agents" (and "Box OpenCode agents" for OpenCode) on, it gets only a short fixed list of harmless variables (`PATH`, `LANG`, `TERM` and the like, and a `HOME` inside the agent's own folder) plus what belongs to that agent: the secrets bound to it and the `PAPERCLIP_*` variables of the current run (run id, API URL, the run's token). Variables that change how a program loads code or starts (`NODE_OPTIONS`, `NODE_PATH`, `LD_*`, `BASH_ENV`) are never passed, and neither are `PAPERCLIP_*` variables that look like secrets. So `DATABASE_URL`, the secrets master key or an `ANTHROPIC_API_KEY` that happens to be set for the server do not reach the agent.

At every start the server also drops run-level values (from an issue, project, routine or environment) that would move an agent's home, config or state folder (`HOME`, `XDG_*`, `OPENCODE_*`, `CLAUDE_CONFIG_DIR` and the like), change the Paperclip API address the box trusts, or switch the engine to ACP. The agent's own stored values stay; run-level ones that differ are removed or reset, and each action is logged (`event=sandbox_enforcement`).

### Credentials

An agent gets its model credentials only from secrets bound to the agent, never from the server's environment. In Paperclip, create the secret, then bind it to the agent as an environment variable with the **exact name** below (the board's UI may suggest a different default name; correct it). Through the API the binding is a `PATCH /api/agents/<id>` with:

```
{"adapterConfig":{"env":{"CLAUDE_CODE_OAUTH_TOKEN":{"type":"secret_ref","secretId":"<secret id>","version":"latest"}}}}
```

* **`claude_local`:** `CLAUDE_CODE_OAUTH_TOKEN` (a Claude subscription token) or `ANTHROPIC_API_KEY`.
* **`opencode_local`:** any of `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` (also `GOOGLE_API_KEY`), whichever provider the agent's model uses.
* Never put a key in the server's environment expecting agents to pick it up: they will not, and keys there are what this protection keeps away from them.

### Setting up an OpenCode agent

1. Install the `opencode` CLI as the account that runs Paperclip, and check that `opencode --version` works for that account. If npm's global prefix is not writable for that account (for example `/usr/local`, where a plain `npm install -g opencode-ai` stops with `EACCES`), install into a prefix of your own: `npm install -g --prefix ~/.npm-global opencode-ai`, then put `~/.npm-global/bin` on the `PATH` of the Paperclip server process itself (the server looks `opencode` up in ITS PATH, not in your shell's; its service definition or the environment you start `paperclipai run` from), or link it into a directory that is already there (`ln -s ~/.npm-global/bin/opencode ~/.local/bin/opencode`). The install method on opencode's own site works as well.
2. Create a secret holding your provider key and bind it to the agent as `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` or `GEMINI_API_KEY`.
3. Create the agent with adapter type `opencode_local` and a model of that provider (for example `openrouter/<model>`). With "Safe defaults for new agents" on, it starts boxed: own folders under its runtime directory, no permissions, and a network allowlist of the common provider hosts (`openrouter.ai`, `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`). To list only the hosts you use, set "Base allowlist for new OpenCode agents" in the Hardening page settings; for an existing agent, change `networkAllowlist` through the board.
4. Press "Test environment" on the agent: the probes run inside the same box and start the server's own `opencode` (`PAPERCLIP_OPENCODE_COMMAND`, else `opencode` on the server's PATH), never a command written in the request. Run an issue to confirm.

OpenCode agents run only while **"Box OpenCode agents"** is on (it needs "Box Claude agents"). With it off, an OpenCode agent is refused with "the opencode_local adapter is not registered as boxed in this server", and Claude agents are unaffected.

A connection the agent's tools try to open to a host that is not on the allowlist is refused and logged once as `sandbox_network_denied` (agent id, run id, host, port; at most 20 lines per run), so a missing host shows up in the server log.

### Remote exceptions

To let a remote or gateway agent run anyway, an instance admin lists it on the Hardening page, **Settings, Remote exceptions**: one line per agent, `<agent id> <type> <reason>`. The type must be one of `cursor_cloud`, `openclaw_gateway`, `hermes_gateway`, `http`, `process`, and the reason is required. The plugin records who added the line and when. The server re-reads the settings file at every start of such a run, so an exception applies without a restart (the file has to pass the trust checks described under "Site values"; if it does not, there are no exceptions). Every run admitted this way is logged as `sandbox_remote_exception_used`. An exception exempts that one agent from the box; nothing else about it changes. The Agent boxes page shows such an agent as excepted, and every change to the list is logged. Removing the line stops the agent at its next run.

## Assumptions

* Paperclip runs as a **normal user without sudo** (never root), and a **separate admin account with sudo** exists. The admin account is only used for the one-line installs below.
* Linux, `bwrap` (bubblewrap) and Node as shipped with Paperclip. GNU `patch` on the PATH. `systemd` is optional (it gives the plugin a restart button).
* Paperclip started the way `paperclipai service install` or `paperclipai run` starts it: `node <install>/node_modules/paperclipai/dist/index.js run`. The plugin works out which install, instance and settings file it serves from that running server process (see "Which Paperclip" below); any other layout (a Docker image, pm2, a `tsx` dev run) is refused, and the command-line tool covers it.
* Paperclip in authenticated mode on a private network, sign-up disabled, board approval for new agents. In `local_trusted` mode every caller without a token is the board, including a boxed agent that reaches the server's API: the plugin raises a HIGH alert on start and the Hardening page says so, and the protections that rest on "who is calling" cannot hold.
* Agents use `claude_local` or `opencode_local`, and optionally `hermes_local` through the wrapper. Remote and gateway types need an admin exception, and the other local adapters are refused by "Only boxed agents run" (see "What runs where").

## Requirements

* **Linux** with `bwrap` (bubblewrap) and GNU `patch` on the PATH. Node.js **24.11 or newer** (Paperclip's own requirement), plus `npm` and `git` for the steps below.
* **Paperclip 2026.1005.0 or newer**, installed and running (the plugin manifest sets 2026.1005.0 as the minimum; tested on 2026.1012.0). Paperclip is not installed by this package: follow Paperclip's own install instructions ([docs.paperclip.ing](https://docs.paperclip.ing), [github.com/paperclipai/paperclip](https://github.com/paperclipai/paperclip)) and check that `paperclipai` is on the PATH of the account that runs Paperclip (the installer puts it in `~/.local/bin`).
* A Paperclip **instance admin** login, and at least one company (the plugin's settings are stored per company).
* For the optional watchdog: on the host, `setfacl` (package `acl`), `python3` (3.8 or newer), `openssl` (1.1.1 or newer), `curl`, `tar` and `sha256sum`. The installer stops with a message when one is missing.

## Install the plugin

1. Sign the command-line tool in as an instance admin. Installing a plugin is instance-admin only, and without this step `paperclipai plugin install` fails with `API error 403: Board access required`:
   ```
   paperclipai auth login --instance-admin
   ```
   It prints an approval URL (and tries to open a browser; add `--no-browser` on a server without one). Open the URL while signed in to Paperclip as an instance admin and approve. `paperclipai auth whoami` then shows your user id, which step 4 needs.
2. Get the plugin from a clone of the release tag and install it by path. The plugin is plain ES modules with no build step; it only needs its two
   `@paperclipai` dependencies, which `npm install` fetches. Run this as the account that runs Paperclip (no sudo):
   ```
   git clone --branch v0.2.0 https://github.com/tomRumi/paperclip-security-hardening
   (cd paperclip-security-hardening/plugin && npm install --omit=dev --ignore-scripts)
   paperclipai plugin install "$PWD/paperclip-security-hardening/plugin"
   ```
   Keep the clone where it is: Paperclip loads the plugin from that path, and the protection files are read from `host/patches` in the same clone.
   The plugin is not published to npm. To update, check out a newer tag in the clone, run `npm install --omit=dev --ignore-scripts` in `plugin/` again and run `paperclipai plugin upgrade paperclip-security-hardening`. (`paperclipai plugin install` on a plugin that is already installed fails with "Plugin already installed"; the upgrade keeps the settings, the admin list and the state, and `paperclipai plugin list` then shows the new version.)
   The command ends with "Keep pnpm dev running ... Paperclip watches rebuilt dist output". That hint is printed for every local plugin; ignore it, this plugin has no build step.
3. Check that it is running: `paperclipai plugin list` shows `paperclip-security-hardening` as `ready`. Installing from the command line already enables it, so there is nothing to enable (if the status is `disabled` or `error`, run `paperclipai plugin enable paperclip-security-hardening`). The command line shows no permissions card; the capabilities the plugin asks for are explained in `plugin/src/manifest.js`.
4. Put **your own user id** in "Users who may change protections". This list is stored **per company**: set it in every company whose members will open the pages (a new instance has no company until you create one). Take your id from `paperclipai auth whoami` (the Hardening page also shows it, read only). Either use the plugin's settings form in Paperclip's plugin manager, with the company selected, or the command line (find company ids with `paperclipai company list`):
   ```
   paperclipai plugin config:set paperclip-security-hardening --company-id <company id> --payload-json '{"configJson":{"adminUserIds":["<your user id>"]}}'
   ```
   Only instance admins can save plugin settings. The command replaces all plugin settings for that company; after the first setup, change settings in the plugin's settings form.
5. Open the **Hardening** page, fill in the site values (below), switch on what you want, and press Save.

The plugin does not touch anything until you save. When you save, it keeps a pristine copy of every Paperclip file it will change,
rebuilds those files from the pristine copy plus the switched-on protections, and asks for **one restart**. When Paperclip runs as a systemd user unit that the plugin can verify, the page has a restart button. Otherwise the page says so and you restart it yourself (below).
The rebuild is all-or-nothing: if anything does not fit, nothing changes and the row turns red.

**Restarting by hand.** The plugin can only restart a Paperclip that runs as its own systemd user service (`paperclipai service install`). If you started Paperclip another way, stop it and start it again the way you started it: press Ctrl-C in the terminal that runs `paperclipai run` and run the same command (same options) again; if you use Paperclip's own service, `paperclipai service restart`. The patched Paperclip loads its files and the settings file only at startup, so a restart is needed after a settings-only save too. The page names the reason.

### Which Paperclip

A plugin worker gets no Paperclip home or instance id from Paperclip, so it cannot read them from its own environment. The plugin therefore asks the Paperclip server process that started it (`/proc/<parent>`): which install tree it runs from, its instance id and home (the `--instance` and `--data-dir` flags of its command line win over its environment, as in Paperclip itself), the settings file it reads, and the systemd user unit it runs in.
The Hardening page shows the result (install, instance, data folder, restart unit). Two Paperclip instances of one user, each with the plugin, therefore each change only their own install.
If the plugin cannot tell (unsupported launcher, `/proc` hidden by `hidepid`, files replaced since Paperclip started), the page says why, every action that would change something refuses, and nothing is re-applied on start; use the command-line tool (see "Fallback without the plugin"). A restart button appears only when the unit systemd reports for Paperclip's control group is Paperclip's own unit for that instance (`paperclipai.service`, or `paperclipai-<id>.service`).

### Site values

On the Hardening page, "Settings" holds values that belong to your install (base network allowlist, base allowlist for new OpenCode agents, extra read-only paths, workspace roots, Hermes wrapper path and allowlist, remote exceptions, alert company and project, Paperclip URL for the install lines).
The plugin writes the part Paperclip itself needs to a settings file: the running Paperclip's `$PAPERCLIP_HARDENING_CONFIG`, else `<its instance root>/hardening/config.json`
(for the default instance `~/.paperclip/instances/default/hardening/config.json`). The patched Paperclip reads it once at startup, so saving settings needs a restart too. Without it, secure generic defaults apply.
Because it is trusted for allowlists and read-only paths, the patched Paperclip uses it only if no agent run can write it: the file must not be inside the instance's `workspaces`, `projects` or `companies` directory or a workspace root (after resolving links),
must be owned by the user Paperclip runs as with mode 0600, and its directory must be owned by that user and not writable by group or others. Otherwise it is ignored (secure defaults stay, and a `sandbox_enforcement` warning names the reason).
The plugin creates the directory with mode 0700 and the file with mode 0600, and refuses to write when an existing file or directory fails these checks. If you set `PAPERCLIP_HARDENING_CONFIG` yourself, point it at such a place.

## Upgrading from v0.1.x

Update as in step 2 of "Install the plugin": in the clone, `git fetch --tags && git checkout v0.2.0`, run `npm install --omit=dev --ignore-scripts` in `plugin/`, and run `paperclipai plugin upgrade paperclip-security-hardening` (not `plugin install`, which refuses an installed plugin; the upgrade keeps your settings, the admin list and the state, and `paperclipai plugin list` then shows 0.2.0). On start the plugin re-plans the switched-on protections against the new patch files: "Box Claude agents" is added (switched on together with "Only boxed agents run"), the page shows "restart needed", and one restart applies everything. If the new row shows as pending instead, press Save. **Switch "Box OpenCode agents" on** if you use OpenCode agents: an upgrade does not turn it on by itself (v0.1.1 had no OpenCode support), and without it OpenCode agents are refused. Saving that switch asks for **a second restart** (every settings save does), so restart again after the first restart of the upgrade.

**After a Paperclip update, everything that still fits is applied.** On start the plugin rebuilds each protection whose patches fit the new Paperclip files, one protection never holds back another. A protection that no longer fits (a patch's context changed) is skipped but **stays switched on**; it comes back by itself on the first start with a plugin release whose patches fit. Until then it is not in the files. **Only safety-core protections raise an alert:** one HIGH alert, and their row shows **"update needs admin decision"**. Any other protection (for example "Box OpenCode agents", "Public-web box") only shows **"unavailable on this install"** on the Hardening page: no alert, no issue, so look at the page after a Paperclip update. "Only boxed agents run" applies even when "Box Claude agents" is the one that does not fit: Claude agents are then refused (they are not registered as boxed), nothing runs unboxed. If "Only boxed agents run" itself does not fit there is the alert and nothing else (the plugin does not pause agents). If the change of a patch is now **part of Paperclip itself**, the plugin sees that (the patch undone cleanly on the new file, ignoring its comments) and shows the heads-up **"now part of Paperclip, no longer needed"**: no alert, the protection counts as satisfied. The one exception is a protection that is in the files right now and that new patch files would remove (the engine built the tree, a plugin update brings patches that do not fit it): nothing is rebuilt then, a HIGH alert is raised, and Save asks you to confirm dropping it. Then **paste the watchdog install line from the Hardening page again**: the patched Paperclip files changed, so the watchdog's manifest must be refreshed or it may report them as changed.

What changes for an operator:

* **A Claude agent no longer inherits the server's environment.** One that relied on an `ANTHROPIC_API_KEY` (or any other variable) set for the server loses it. Bind a secret to the agent (see "Credentials"). This includes the ITSec agent, which is a `claude_local` agent.
* **Run-level overrides are dropped for all boxed agents,** also for Claude agents, which v0.1.1 let through: `HOME`, `XDG_*`, `OPENCODE_*` and the other state and config directories, `PAPERCLIP_API_URL` and `PAPERCLIP_RUNTIME_TOOLS_*`, and `engine`. If a project really needs a different `PAPERCLIP_API_URL` (a container that reaches the API on another address), set it on the agent through the board instead.
* **Hermes agents are now checked at every start,** like the others: the working directory must lie below a workspace root, the command (and `hermesCommand`) must be the wrapper, and a run cannot change the `HERMES_SANDBOX_*` variables. The wrapper itself changed in v0.2.0: it finds Paperclip's sandbox code and its allowed roots under the account's passwd home (not `$HOME`, which a Hermes agent sets to its own folder), and it no longer reads a `PAPERCLIP_ADAPTER_UTILS` override (that variable could make it load a module of the agent's choosing outside the box). `NODE_*` names and `PAPERCLIP_ADAPTER_UTILS` in an agent's env are removed from new agents, dropped from runs, and an agent that stores one is refused at start with the variable named. **Install the new wrapper** (the Hardening page shows the line) or the old one stays in place. A Hermes agent whose working directory is outside Paperclip's own `workspaces` and `projects` folders (for example under `~/projects`) needs that directory in **Workspace roots** on the Hardening page, or its runs are refused with "is outside the allowed workspace roots". If you change the Hermes wrapper path later, existing Hermes agents keep the old command and are refused until you `PATCH` their `command` to the new path; new agents get the new path.
* **Extra read-only paths are checked against a deny list.** The board sets them (an agent cannot change them), so a read-only path may be anywhere, for example `~/setup/agent-mcp.json`, `~/browser` or a skills folder. It is refused when it lies in a credential or state location of the account Paperclip runs as (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.docker`, `~/.npmrc`, `~/.netrc`, `~/.config/gcloud`, `~/.config/paperclip-*`, `~/.local/state`, `~/.claude`, `~/.claude.json`), when it is the home directory or a parent of it (or of `~/.config`, `~/.local`), or when it lies in the Paperclip instance directory outside `workspaces`, `projects`, `skills`, the agent's own folder and its company's `claude-prompt-cache` (so never `db`, `secrets`, the master key, another company or another agent). Links are resolved first. **Read-write** mounts keep the strict rule: inside the home or the instance only the agent's own folders and the workspace roots.
* **New agents:** the engine is always `cli` for Claude, Codex, Gemini and Kimi agents (v0.1.1 kept an explicit choice), and when an **agent** creates a new agent, names that move its home or state directory or change how the box starts (`HOME`, `HERMES_HOME`, `HERMES_SANDBOX_*`, `XDG_*` and the like) are removed from the environment it supplies. Credentials under other names stay. A **board user** creating an agent keeps those values: a Hermes agent is set up with its own `HOME`, `HERMES_SANDBOX_HOME`, `HERMES_SANDBOX_RO` and `HERMES_SANDBOX_ALLOW`. An agent can never change any of them afterwards, on itself or on another agent (the server answers 403).
* **Existing agents are not rewritten.** An existing `opencode_local` agent (refused until now) needs the box settings before it runs: `filesystemScope: "workspace"`, `networkScope: "allowlist"` and a `networkAllowlist`. The Agent boxes page shows the exact `PATCH`. The compliance check on the Hardening page also lists agents whose stored environment holds the names that are now dropped, or whose engine is not `cli`; remove them with a `PATCH`.
* **The "Test environment" button is for board users only.** An agent (for example a CEO-role agent that may create agents) can no longer start it: the server answers 403. The probe also ignores files an agent can write: the workspace's project settings and a `CLAUDE_CONFIG_DIR` from the request (see "Known limits").
* **Remote and gateway agents** (`cursor_cloud`, `openclaw_gateway`, `hermes_gateway`, `http`, `process`) were refused before and still are, until an admin lists them as remote exceptions.

## The Hardening page

Admin only. One row per protection, each with an on/off switch (the safety core too; switching a core protection off asks for confirmation and names the risk).

| Switch | What it does | Default |
|---|---|---|
| Sandbox compatibility | makes the built-in sandbox work reliably (modern Linux layouts, git worktrees, proxy crashes, apps inside a run reachable on localhost, interaction wake-ups) | on (required by most others) |
| Agents can't change their own box | sandbox, network, commands, instructions and skills are board-only for agents; the stored box is forced again at every run; a hidden `***REDACTED***` value can never overwrite real settings | on |
| Box Claude agents | Claude agents run in the sandbox with their own folders and a cleared environment (the server's secrets do not reach them); sets up the shared sandbox helper OpenCode uses; denied connections are logged | on |
| Box OpenCode agents | OpenCode agents get a sandbox at all (own folders, cleared environment). Needs "Box Claude agents". While it is off, OpenCode agents are refused; switching it off needs no confirmation because it fails closed | on |
| Only boxed agents run | an agent without a sandbox is refused instead of running unboxed (it is switched on together with "Box Claude agents" but does not depend on it: if that one does not fit a new Paperclip, Claude agents are refused instead of run); remote types need an admin exception, other local types are refused for now; an agent cannot press "Test environment" | on |
| Safe defaults for new agents | every new agent (hire, import, join) starts boxed (CLI engine where the type has an ACP engine), with no permissions, unable to create agents or skills | on |
| Agents can't hand out permissions | granting permissions, including "may edit pipelines", is board-only | on |
| Pipeline structure is board-only | agents can move work along a pipeline but not change its stages | on |
| Assigning work needs a grant | an agent may assign work to others only with an explicit grant | on |
| Public-web box | web-reading agents get the private network with "any public website, nothing local" instead of the host network | on |
| Own Claude folder per agent | each agent's Claude settings and conversations are private to it | on |
| Daily token caps | pauses an agent or company that exceeds its daily token budget; posts the reason; resumes at the next day. Caps are edited per agent on the Agent boxes page (any agent type) | on |
| Watchdog | separate service under its own account: logins, sudo, changed system files, tampering with these protections, alerts as issues | off until installed (one-line install, below) |
| Hermes agents boxed | installs the root-owned Hermes sandbox wrapper | off; one-line install, only if Hermes is used |

Rules the page enforces:

* **Dependencies.** Switching a protection on also switches on what it needs (for example the public-web box needs "Sandbox compatibility" and "Agents can't change their own box"). Switching one off that others need asks first and lists the dependents.
* **One restart per save.** Changes are collected and applied with a single restart. The page says "restart needed" and offers the button.
* **Status column.** applied, pending restart, unavailable on this install, update needs admin decision, self-test failed, or drifted (files changed outside the plugin). "Drifted" is shown on the page only. The plugin raises no alert for it and the self-test skips such a row (it cannot say what the file does); noticing a changed protected file and alerting is the watchdog's job (see "Known limits").
* **Alerts.** Recent watchdog alerts and caps events, with links to the issues.

### No version lock

There is no list of supported Paperclip versions. A protection is offered wherever the code it changes still exists in that shape. If that code is missing or changed,
the row shows **"unavailable on this install"** and stays off; nothing is half-applied, and the other protections still apply (dependencies permitting). Only a safety-core protection that was already in the files and stops fitting after an update raises an alert (see "Upgrading").
After a Paperclip update, the plugin rebuilds the switched-on set against the new files on start (applying everything that still fits, see "Upgrading") and asks for one restart. Docker images re-create the files on every container start; the plugin does not support a container layout yet (it refuses, see "Which Paperclip"), so apply the protections to the image with the command-line tool.

## The Agent boxes page

One row per agent that exists in the company, read fresh from Paperclip at every refresh (there is no list of models or adapters). A company picker switches companies. Each row shows the agent's type, its box (allowlist or public web), extra hosts, read-only paths, permissions and **daily token cap**.

* **Default cap** (one field per company): applies to every agent without its own cap, including agents added later. A new agent appears at the next refresh and is capped from its first run.
* **Per-agent override:** optional, on the agent's row. Clearing it returns the agent to the default.
* **Company cap:** the total for all agents per day.
* **New-company template:** an install-wide default cap and company cap (and mode: enforce, report or off) copied into each company the first time the plugin sees it, so a new company is never uncapped. Edit it per company afterwards.
* An agent whose type reports no token usage shows "usage not reported" instead of a cap that cannot be enforced.
* Conflicts are flagged: public web together with "may assign work" is refused.

Protection switches apply to the whole install; boxes and caps are per company.
Caps count tokens per UTC day. An agent over its cap is paused with a comment explaining why; at the next UTC day only the agents the plugin paused are resumed (a person's pause is never undone).

## The ITSec agent

The plugin creates and manages one security agent, **ITSec**, in the company you mark as the **host company**. No other company ever gets one, and until you mark a company nothing is created. It reads the alert issues this plugin raises and the plugin's own status, for each alert either resolves and closes it with a resolution comment that names its evidence, or escalates it to you, and reviews the host's safety automation once a day. It changes nothing on the host: a real fix is proposed to you, never applied.

What the plugin sets up, all in the host company:

* **The agent** ("ITSec", `claude_local`, model `claude-sonnet-5-5`) with generic security-stance instructions shipped in this package. It is created **paused**, runs in the sandbox (CLI engine, `bwrap` workspace scope, your base allowlist and read-only paths as on every new agent (so the model API only and no host paths, if you set none), `dangerouslySkipPermissions` left unset so that the adapter's default applies: skip permissions, inside that box), cannot create agents or skills, holds no grants, and has a cap of 30 runs a day on top of the daily token caps. Like every boxed Claude agent it gets no credential from the server's environment: bind a Claude credential to it as an agent secret (`CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`, see "Credentials") before its first run.
* **Two routines.** *ITSec: alert triage* has no schedule of its own: the plugin starts it when an alert of medium priority or higher is raised in the host company, at most once every 30 minutes, and a 15-minute check starts it only when an open alert still has no comment from the agent (otherwise no agent run happens). *ITSec: daily review* is declared to run at 07:00 UTC (the page shows the declared schedule; the live one is on the Routines page of Paperclip).
* **A status issue** (not an alert, assigned to nobody) holding two documents the plugin keeps current: `hardening-status` (protections, last self-test, watchdog, sandbox compliance of the company's agents, the alerts the ITSec agent closed) and `itsec-context` (your notes about this host). The agent reads its facts from these. Paperclip only updates a document when the caller names the revision it is replacing, and the plugin SDK has no way to do that, so the plugin replaces a changed document (deletes it and creates it again). The documents therefore keep no revision history; do not edit them by hand, the next change overwrites your edit.
* **Triage, resolve and close, or escalate.** The agent may close an alert of this plugin (set it to done) only after its own resolution comment on that alert, posted as a separate comment before the close, in this format: the first line starts with `Resolution:` and says why the alert is resolved, and a later line starts with `Evidence:` followed by at least 10 characters of what it checked (on that line or below). The plugin's alert re-check (see Known limits) verifies that such a comment exists, was written by the host company's current ITSec agent (in a real agent run, not created by a plugin in its name) and was created before the close, and that the close itself was made by that agent's own run (not by a plugin that names the agent); otherwise it raises the alert again, naming the ITSec agent. An alert whose cause needs a change on the host or in Paperclip is not closed by the agent: it stays open, with a verdict comment and a separate "ITSec proposal" issue that starts with "For the owner:" and names the recommended fix and who applies it. Every alert the agent closed is listed, with time and the first line of its resolution, under "Alerts closed by the ITSec agent" in the `hardening-status` document (and in the activity log), and the daily review copies that list into its comment. Closes by any other agent, by agents of other companies, by users who are not alert owners, or by an old host agent are re-raised as before.
* **Verify before it runs.** After creating the agent the plugin reads it back and checks the whole sandbox (the same box checks the plugin runs on every agent: workspace scope, `bwrap`, allowlist without wildcards, no `canCreate*`, and skip-permissions only on a boxed agent; plus for ITSec: CLI engine, no host path beyond your configured read-only paths, no grant except `tools:use`). Only if that passes does it resume the agent (and only an agent still paused with the reason Paperclip wrote when it was created, never one a person or a token cap paused) and switch the routines on. If the agent later drifts, for example somebody adds `*:443` to its allowlist or it gets a `tasks:assign` grant, the plugin pauses the agent and its routines and raises a HIGH alert (one alert per distinct set of findings).
* **What resumes by itself, and what needs the board.** The plugin resumes the agent and switches both routines on again, after a check (the 15-minute check, or "Check now") found the agent compliant, **only when the plugin paused it itself**. The plugin remembers its own pauses (Paperclip writes the reason "manual" for every pause, so the reason cannot tell them apart). That covers: the first activation; a pause for drift, once the board has fixed the agent in Paperclip or you pressed "Reset to the plugin's declaration"; and the pause when you cleared the host mark or moved it, once you mark the company again. It does **not** resume an agent that a board user or a token cap paused, nor one the plugin could not verify, nor one that still drifts. Those need the board: resume the agent in Paperclip (agent page, Resume), then press "Check now" so the plugin verifies it and switches the routines on. The card says which case it is.

How to mark the host company:

1. In **Settings > Plugins > Security hardening**, save the plugin settings for the host company (add your user id to "Users who may change protections"). Paperclip lets a plugin act for a company only once the plugin has saved settings for it.
2. Set the **alert company** on the Hardening page (Site settings) to the host company; the agent can only see issues of its own company.
3. Open the **Hardening page inside the host company**, find the **ITSec agent** card and press "Mark this company as the host company and create the agent". Optionally write notes about this host (what it is called, which knowledge-base project to search, your rules). The notes land in the `itsec-context` document, so write no secrets.
4. Press "Check now" (or wait for the next 15-minute check) if the card does not show a verified agent. The plugin verifies the agent and resumes it. **A company that requires board approval for new agents needs one extra board step**, see "Companies that require board approval" below.

**Companies that require board approval for new agents.** On Paperclip 2026.1012.0 (and current Paperclip source) a plugin cannot create a managed agent in such a company: Paperclip creates it as `pending_approval`, then fails to write its instructions (it refuses to change a pending agent) before it makes the hire approval. So the ITSec agent exists but is empty and pending, and there is **no approval to decide**. The plugin detects this, reports it on the card ("A board member must approve the agent itself in Paperclip (agent page, Approve; or `POST /api/agents/<id>/approve`)") and creates no routines. The step is: a board member approves **the agent** on its agent page in Paperclip (the "Approve" button of a pending agent; Paperclip activates a pending agent that has no open approval). The next check (15 minutes, or "Check now") then writes the agent's declared instructions, creates the routines, verifies and switches everything on. If a Paperclip version does create the hire approval, the card says so and you approve that instead. Switching the company's "Require board approval for new agents" setting off for the marking is not needed.

The agent is always created with the model declared in the package (`claude-sonnet-5-5`); Paperclip's plugin SDK cannot change it afterwards. The model you may pick on the card is only compared with the live one, and the card shows the difference as a `PATCH` for the board to apply in Paperclip.

Marking a different company pauses the old agent and its routines within seconds of the save (a background step that runs once the save request has ended; Paperclip refuses calls for another company while a request runs). If that step fails, the 15-minute check retries it, and the card lists the company under "Still to pause". The plugin never deletes the old agent, the board may. Clearing the marking pauses the current one (at once, when done from the host company's own page); marking the company again resumes it, see above. The marking is an instance-wide setting, so an admin listed in any company can move or clear it, not only one listed in the host company.

The optional memory plugin is not required. If you run it, give the ITSec agent its read-only Memory tool profile by hand (the plugin cannot grant tool access); that is the one grant (`tools:use`) the check allows. Two more steps are the board's, in Paperclip: use a **read-only host token** for the memory service (the plugin cannot verify that the token is read-only, so check it yourself), and add the memory service's host to the ITSec agent's network allowlist with a `PATCH` (the plugin accepts any allowlist entry except wildcards, so this does not count as drift).

## Install the watchdog and the Hermes wrapper (one line, run by the admin)

The admin password must never pass through Paperclip, which runs under the same account as the agents' tools. So these two parts install with a line you paste into your own admin terminal (ssh as the sudo user).

1. On the Hardening page, flip **Watchdog** (or **Hermes agents boxed**). A box shows one line and "waiting for the watchdog to report in".
2. Paste the line into your admin terminal. It looks like this:
   ```
   d=$(mktemp -d) && curl -fsSL https://github.com/tomRumi/paperclip-security-hardening/releases/download/v<version>/install-watchdog.sh -o "$d/install-watchdog.sh" && echo "<sha256>  $d/install-watchdog.sh" | sha256sum -c - && sudo bash "$d/install-watchdog.sh" --paperclip http://<host>:3100 --watched-user <account> --enrol <one-time code>
   ```
   The plugin fills in `--watched-user` with the account Paperclip runs as. The installer also takes `--admin-user <name>`, the admin account whose logins the watchdog reports as maintenance (default: the account that ran `sudo`; if it cannot tell, the example value `admin` stays and the installer says so, then edit `/etc/itsec/config.json`). Both are written into a new config only; an existing config is kept.
3. The watchdog reports in and the switch turns green by itself.

**Check the line before you run it.** Compare the **URL** (it must be the official release of this project) and the **sha256 fingerprint** with the values on the release page for that version (each release page lists the fingerprint of both installers in its notes; the release assets are `install-watchdog.sh`, `install-hermes-wrapper.sh`, `paperclip-watchdog-<version>.tar.gz`, `hermes-sandbox` and `SHA256SUMS`). If they differ, do not run it.
The installer itself downloads the watchdog bundle from the same release and checks it against fingerprints pinned inside the script. It never uses local files that Paperclip's account could have changed.
This is the standard download, verify, then sudo model: if someone controlled Paperclip's account they could show you a forged line, which is why you compare it with the release page.

* **The one-time code** is created by the plugin, valid 15 minutes, single use, stored only as a hash. The installer makes the watchdog's own signing key pair, keeps the private key root-only on the host, and enrols by sending the code plus its public key, signed. Every heartbeat and alert is signed (5-minute window, one-use nonce) and the plugin creates the alert issues itself. No Paperclip key exists on the host.
* **Hermes wrapper:** the same pattern with `install-hermes-wrapper.sh` and its own fingerprint (also in the release notes), without `--paperclip` and `--enrol`:
  ```
  d=$(mktemp -d) && curl -fsSL https://github.com/tomRumi/paperclip-security-hardening/releases/download/v<version>/install-hermes-wrapper.sh -o "$d/install-hermes-wrapper.sh" && echo "<sha256>  $d/install-hermes-wrapper.sh" | sha256sum -c - && sudo bash "$d/install-hermes-wrapper.sh"
  ```
  No enrolment: the row turns green when the wrapper file is root-owned, not writable by others, and matches the released fingerprint. If the file at the configured path is not root-owned or is writable by others, the row says "unsafe", and adds "and it is not the released wrapper" when its fingerprint differs from the release. The check looks at the path in the setting "Hermes wrapper path" (default `/usr/local/bin/hermes-sandbox`), once for the whole host, not per Paperclip instance. A wrapper that is wrongly owned or writable always shows "unsafe", whatever its content.
* **Removal:** the switch shows the same kind of line with `--uninstall`. It removes the service, its account and its key; the plugin forgets the public key.
* A development checkout (not a release build) has no pinned release, so the rows show no install line. Release files are built by `scripts/release.sh` (see its header; it publishes nothing by itself).

What the watchdog watches and its rule table: [host/itsec/README.md](host/itsec/README.md). What the installer put on the host, what is optional (fail2ban, a vault, the Claude narrative) and day-to-day operation: [host/itsec/INSTALL.md](host/itsec/INSTALL.md). The optional fail2ban template ignores only localhost; add your own private or tailnet range or a fixed admin IP to `ignoreip` if you need it.
The same line also gives the watchdog's account read access (`setfacl`) to the files it watches in the watched user's home (never keys, credentials or conversations, though a world-readable file in the home becomes reachable through the traversal entry on the home; see [host/itsec/INSTALL.md](host/itsec/INSTALL.md), section 3), never following a symlink, and writes the patch manifest (the hashes of the patched Paperclip files). `--uninstall` removes exactly those access entries again (any it could not remove are printed and listed in `/root/itsec-acl-paths.left`). **After a Paperclip update, paste the install line from the Hardening page again**: it refreshes the access and the manifest. If the protections were not yet applied when you installed (the manifest needs the patched files), the installer says so; apply them, restart Paperclip and paste the line again.

## Self-test

After each restart, a short self-test checks that every switched-on protection really works in the files Paperclip runs, not only that the text is there.
Six protections are tested functionally:

* the sandbox builds a spawn target without re-mounting usr-merge symlinks;
* the public-web box accepts `*:443` and still refuses `*`;
* a run override that widens the network, escapes the workspace or switches the engine is undone;
* a new agent created unboxed comes out boxed;
* the box around Claude and OpenCode agents works in a real bubblewrap sandbox: a process in it cannot read or write outside its workspace and runtime folder, a host that is not on the allowlist gets a refusal and one `sandbox_network_denied` log line, and the server's own environment does not reach the child while the agent's own variables do (no model call, no credential; where bubblewrap is unusable the page says "not run");
* the admission rule refuses an unboxed agent, one whose adapter is not set up for the box, one on the ACP engine and an unknown type, naming the missing piece, and admits a boxed Claude and a boxed OpenCode agent.

The rest get a structural check (each file equals the build the plugin recorded and carries its markers). The page says which kind each row got. A failed self-test turns the row red, logs once and raises an alert issue.
"Run self-test" repeats it on demand.

## Fallback without the plugin

If the plugin cannot run, the same engine runs from the command line (nothing restarts Paperclip; it prints the restart command):

```
node plugin/bin/hardening-engine.mjs status
node plugin/bin/hardening-engine.mjs plan  --enable defaults
node plugin/bin/hardening-engine.mjs apply --enable defaults
node plugin/bin/hardening-engine.mjs restore
```

Every command prints the install it works on first. By default that is the default instance (`$PAPERCLIP_TREE` or `~/.paperclip/cli/current`, data in `~/.paperclip/sandbox-hardening`); `--instance ID [--home DIR]` picks another instance's managed install, `--pid N` takes a running Paperclip server process as the plugin would, and `--tree`, `--data`, `--unit`, `--no-systemd` set the values explicitly.

Details: [plugin/src/engine/README.md](plugin/src/engine/README.md). `host/patches/apply.sh [--check]` applies the whole patch set in one go (idempotent, all-or-nothing) and `host/sandbox` holds optional systemd units that re-apply it after a Paperclip update.
Use one route or the other for a given install, not both.

## Uninstall

Do the steps in this order.

1. On the Hardening page press **Restore originals** (it asks for confirmation). Every file Paperclip had is written back byte for byte, all-or-nothing. Restart Paperclip (see "Restarting by hand").
2. Remove the watchdog and the Hermes wrapper with the `--uninstall` lines from their rows (run by the admin). The watchdog's line also takes away the read access it granted.
3. If you marked a host company, remove the ITSec agent first. Open the Hardening page inside the host company and press **Clear the host company** on the ITSec card: it pauses the agent and both routines, and the plugin stops re-creating them. Then, in Paperclip, by hand and in this order (Paperclip 2026.1012.0 has no delete for these):
   1. **Archive** the routines **ITSec: alert triage** and **ITSec: daily review** (Paperclip cannot delete a routine; an archived one stays in the database).
   2. **Terminate** the agent **ITSec** (agent page, Terminate; `POST /api/agents/<id>/terminate`). It cannot be deleted while any routine, even an archived one, still points at it (`DELETE /api/agents/<id>` fails with HTTP 500). A terminated agent is hidden from the default lists.
   3. Delete the issue **ITSec: plugin status (read-only snapshot)**; its two documents go with it.

   What stays after that, and how to remove it if you want: the **alert issues** the plugin created (titles start with `[Security hardening]`, including `[RE-RAISED]` ones) and the **"ITSec: alert triage" run issues** the routine made are ordinary issues of the host company, delete them in Paperclip if you do not want them; the terminated agent and the archived routines cannot be removed through Paperclip; the agent's **instruction folder** stays on disk under `<instance root>/companies/<company id>/agents/<agent id>/` (delete that folder by hand once the agent is terminated). Paperclip's plugin uninstall, even with `--force`, deliberately leaves managed agents and routines in place, so they stay (paused, but present) until you do the above.
4. Remove the plugin and everything Paperclip stores for it:
   ```
   paperclipai plugin uninstall paperclip-security-hardening --force
   ```
   `--force` also deletes the plugin's state and its per-company settings (admin lists, caps, the watchdog's public key). Without `--force` they stay in Paperclip's database and come back if you install the plugin again.
5. Delete the files the plugin left on disk, now that the originals are back: the data folder `<Paperclip home>/sandbox-hardening` (`~/.paperclip/sandbox-hardening` for a default home; it holds the event log, state and the pristine copies) and the settings file `<instance root>/hardening/config.json` (`~/.paperclip/instances/default/hardening/config.json` for the default instance). Then delete the clone.

If Paperclip was updated meanwhile, a file that changed outside the plugin is left as it is and its stored original is kept (the CLI's `restore --force` overrides that).

## Known limits

* **Only Claude, OpenCode and (through the wrapper) Hermes agents can run boxed.** "Only boxed agents run" checks the agent's stored settings when a local run starts. A `claude_local` or `opencode_local` agent needs `filesystemScope` and `networkScope` set (and, for Claude, `engine: "cli"`), a `hermes_local` agent needs the sandbox wrapper as its command, remote and gateway types need an admin exception, and every other adapter type is refused: the run does not start and fails with a message that names what is missing, with a warning in the server log. **`codex_local`, `gemini_local`, `cursor`, `pi_local`, `kimi_local` and `grok_local` are refused for now, even though Paperclip's own sandbox covers some of them**: this plugin does not yet give them the cleared environment and the folder checks, and boxing them is planned for later versions. Runs placed on a remote execution target (SSH or a sandbox provider) are not checked. To run such an agent today you have to switch the protection off on the Hardening page (the page asks for confirmation); the agent then runs with whatever sandbox settings it has, and this plugin does not guarantee them.
* **The board's "Test environment" button for a Claude agent ignores the project's Claude settings and the agent's own Claude folder.** An agent writes its workspace and its Claude folder, and `claude --print` would run the hooks it finds in `.claude/settings.json` or in the `settings.json` of `CLAUDE_CONFIG_DIR` as the Paperclip user, outside the box. The probe of a local target therefore always loads the user-level settings only (`--setting-sources user`), runs in an empty temporary folder, and uses a `CLAUDE_CONFIG_DIR` from the request only when it is the credential home the server made for a managed AI connection of that company (the home folder must belong to the server's user and have mode 0700, and the probe gets the real path, not the text of the request); otherwise it uses the server user's own Claude folder. It can pass or fail differently from a real run. The probe for an OpenCode agent runs inside the box and starts the server's own `opencode`, not a `command` from the request (a request without sandbox settings runs it unboxed with the server's environment, as the stock test does, but in an empty temporary folder, never in the workspace; such an agent would be refused at run time).
* **A Claude or OpenCode agent gets no credential from the server's environment.** Credentials come only from secrets bound to the agent, and a run-level `HOME`, `XDG_*`, `OPENCODE_*` or `PAPERCLIP_API_URL` is dropped. See "Upgrading from v0.1.x" for the details. A tool that needs a variable the box does not pass (for example a `GITHUB_TOKEN`) needs it bound to the agent as a secret.
* **The OpenCode allowlist is a list of provider hosts, not a single one.** The default is the four common LLM API hosts; each is a place a prompt-injected agent could send data to if it holds a key for that provider. Keep only the hosts you use ("Base allowlist for new OpenCode agents"; existing agents keep what they have).
* **The server's temp directory must lie outside the home directory.** The boxed OpenCode "Test environment" makes a temporary directory and refuses to mount one that is inside the home of the user running Paperclip. With `TMPDIR` set to a folder inside that home, the probe fails with `opencode_sandbox_unavailable ... it is inside the home directory of the user running Paperclip`. Leave `TMPDIR` unset (`/tmp`) or point it outside the home for the Paperclip server. Agent runs themselves are not affected: their per-run files live in the agent's own runtime folder.
* **Provider hosts beyond the first run.** A CLI may contact a host the default list does not cover (a login, update or telemetry host). Such a connection is refused and logged as `sandbox_network_denied`; add the host to the agent's `networkAllowlist` if the run needs it.
* **The Agent boxes page does not write an agent's sandbox settings.** Paperclip's plugin SDK has no way to change an agent's configuration, and the plugin holds no admin credential. The page therefore keeps the plugin-side values and shows the exact change (a `PATCH /api/agents/<id>` body) for an instance admin to apply by hand; the row shows "not applied" until the agent matches. Writing them automatically would need either a narrow extra protection that grants this ability or a stored admin key; neither is built, so the change is always applied by hand.
* **Plugin actions are callable by company members.** Paperclip lets any company member and the company's agents call a plugin's actions, and tells the plugin who is calling but not whether they are an instance admin. The plugin therefore refuses agents and accepts a user only when an instance admin listed their user id in the plugin's own admin list ("Users who may change protections"). That list gates every write on both pages.
* **Alert re-checks happen in the plugin, and see closes only while it runs.** The watchdog's signed channel deliberately has no read access to Paperclip's issues, so the plugin re-checks the alert issues it creates (watchdog alerts, a failed self-test, a silent watchdog). For `alertRecheckDays` (default 7, 0 = off) after an alert, the "Alert tamper re-check" job re-reads it every 10 minutes; only the users in `alertOwnerUserIds` (default: the admin list) and, with a valid prior resolution comment, the host company's ITSec agent (see "The ITSec agent") may close it. If anyone else (another agent, another user, or the ITSec agent without such a comment) closes, cancels, deletes or hides it, the plugin opens one new HIGH "[RE-RAISED]" alert naming who did it (at most 3 per alert; it creates a new issue rather than reopening, so it needs no issue-edit right). The plugin SDK cannot read the activity log, so the closer comes from Paperclip's `issue.updated` event: a close made while the plugin worker was down gets one MEDIUM "closer unknown" alert instead, and a deletion's actor is never known. Edits to an alert's text are not checked.
* **The ITSec agent's configuration is fixed when Paperclip creates it.** Paperclip's plugin SDK can create the agent but not change it afterwards, and "reset" would overwrite the board's edits. So the **model setting is advisory**: the page shows the live model and, if it differs, the `PATCH /api/agents/<id>` body for the board to apply. A new plugin version's instructions or sandbox declaration reach an existing agent only through the admin "Reset to the plugin's declaration" button, which also wipes board edits (the page says so).
* **ITSec routine schedules are edited in Paperclip, not in the plugin.** The daily review's 07:00 UTC schedule is created once; change it in the Routines page of Paperclip. The plugin can only switch the routines on or off. The triage routine has no schedule.
* **Facts about your host reach the agent through a notes field.** Instruction text cannot be filled in from plugin settings, so the generic instructions point to the `itsec-context` document that the plugin writes from the "Notes about this host" field. Any agent that can read issues of the host company can read it: keep secrets out.
* **The host company needs saved plugin settings.** Paperclip admits a plugin's calls for a company only inside that company's own page or after the plugin settings were saved for it. Without them the ITSec card says "save the plugin settings for this company" and nothing is created. Marking has to be done from inside the host company for the same reason.
* **The ITSec agent's close rule is checked after the fact.** Paperclip lets a standard agent edit any issue it can see, and the plugin has no way to block a close. The re-check runs about every 10 minutes and only inside the re-check window, so a prompt-injected ITSec agent can close an alert, and the close stands, for up to 10 minutes before the re-raise. A valid resolution comment only proves that the agent wrote text in the right format before the close; the plugin does not judge whether the evidence is true or the verdict right, the owner reads the list. The comment must be strictly earlier than the close (a comment posted in the same request as the close is not accepted), and a comment older than an earlier close of the same alert does not count. The close must be made by the agent itself: Paperclip lets any plugin with issue-edit rights name any agent as the actor of its edit, so the plugin accepts only a close whose event actor is the agent, and only a resolution comment that Paperclip tied to an agent run (a comment a plugin creates in an agent's name has no run). If Paperclip refuses the read of an alert's comments, the check is retried every run and logged; after 3 failed runs for that close (counted in total, not only in a row; about 30 minutes), or when the re-check window ends with it still pending, whichever comes first, the close counts as unverified and the alert is raised again (a failed raise is retried on the next run, also after the window; switching the re-check off with 0 days raises a still-pending alert once; an unverified agent close never stands). A server patch that refuses agent edits of this plugin's issues is possible but not built.
* **ITSec depends on its sandbox settings staying as declared, and on a patched Paperclip for grants.** On a Paperclip without the "no default grants" protection, new agents receive default grants (such as assigning work); the plugin cannot remove them, so it pauses the ITSec agent and says why. ITSec runs with skip-permissions (the adapter's default for an unset `dangerouslySkipPermissions`, which a headless Claude run needs to use its shell and MCP tools at all); the box is its boundary. Setting it to `false` makes those tools refuse, so ITSec could no longer read alerts or comment.
* **Skip-permissions is accepted only inside the box.** The adapter treats an unset `dangerouslySkipPermissions` as `true` (every tool runs without approval). The compliance report accepts that, or an explicit `true`, for a `claude_local` agent that is boxed (workspace scope, sandbox command, network allowlist) and flags it on an agent that is not.
* **ITSec costs tokens.** One run a day, plus a triage run at most every 30 minutes while an alert is waiting, limited by the agent's 30 runs a day and the daily token caps.
* **A changed protected file is shown on the page, and alerted only by the watchdog.** If someone edits a patched Paperclip file after the plugin applied it, that row turns "drifted" on the Hardening page; the plugin raises no alert for it (it also cannot tell a deliberate edit from a Paperclip update that replaced the file, and it re-applies its protections itself when it starts). The alert for a tampered or changed file comes from the watchdog, so without the watchdog installed such a change is visible only to someone who looks at the page. Alerts the plugin does raise itself: a failed self-test, an install it cannot identify, a safety-core protection that no longer fits after a Paperclip update ("update needs admin decision"), a Paperclip running in `local_trusted` mode, a silent watchdog, the watchdog's own alerts, an ITSec agent that drifted, and a tampered alert issue.
* **Jobs that visit every company can run on a remembered list.** Paperclip refuses a plugin's request for all companies for 15 minutes after it delivered any company event to the plugin (the alert re-check receives every `issue.updated`), and logs an error for each refused request. The compliance and token-cap jobs therefore use the companies the plugin saw at its last successful listing and in events since, instead of asking Paperclip, during those 15 minutes (and whenever Paperclip refuses anyway). A company created in that window is picked up at the next real listing.
* **Same trust zone.** The plugin runs inside Paperclip's process account. A compromised Paperclip can lie to the plugin; the watchdog, which runs outside it, is what notices a deliberate switch-off or changed files. Plugin runtime APIs are alpha, and a Paperclip version that moved plugin workers into a restricted loader would stop the plugin from applying protections (it would show red; the fallback CLI still works).
* **Only the standard launch is recognised.** The plugin identifies its Paperclip from `node <install>/node_modules/paperclipai/dist/index.js run ...` (what `paperclipai service install` and `paperclipai run` start). Docker images with another layout, pm2 wrappers and dev runs are refused rather than guessed, with the reason on the Hardening page; the command-line tool covers them. Two instances that share one install tree patch the same files, and the second instance's data folder then sees the first one's patches as outside changes.
* **The sandbox is only as strong as bwrap and your allowlist.** An allowlisted host can be abused for exfiltration; the public-web box allows any public website on purpose.
* The watchdog's alert path runs through the Paperclip instance the agent account hosts. An agent that escapes can silence it; use an independent second channel for high-value setups.
* Log-based watchdog rules depend on Paperclip's log line formats; check them after updates. Linux only.
* **The watchdog assumes the standard Paperclip layout.** Its watch list and read access name `~/.paperclip/cli/current` and the instance `default` in the watched user's home. Another layout needs the `watch` list in `/etc/itsec/config.json` edited, and the read access added by hand. Files created later in a watched folder (a new agent's settings, a new skill) are covered after the install line is pasted again.
* **The Hermes wrapper is fixed to two defaults.** Its first line is `#!/usr/local/bin/node`, so Node must be there (the installer stops with a message if it is not), and it only runs agents whose working directory is under `~/projects` or the `default` instance's `workspaces` and `projects` folders of the account that runs it (the server now also refuses a Hermes run whose working directory is outside the workspace roots; list a directory under "Workspace roots" for the server, and the wrapper's own limit stays); it finds Paperclip's sandbox code under that account's `~/.paperclip/cli/current`. Another Node path or instance needs an edited wrapper (its fingerprint then differs from the release, and the plugin shows that).
* **The watchdog installs no `lynis`.** Without it (`apt-get install lynis`) the weekly audit timer stays off and a run reports an INFO finding; see [host/itsec/INSTALL.md](host/itsec/INSTALL.md), section 2.

## Upstreaming

Each protection is also meant to be offered to the Paperclip project as a pull request. Notes per patch (problem, repro, fix, tests) are in [host/patches/UPSTREAM.md](host/patches/UPSTREAM.md). Accepted ones drop out of the plugin in later versions.

## Layout

| Path | What it is |
|---|---|
| `plugin/` | the Paperclip plugin (switches, Agent boxes, caps, self-test, engine, fallback CLI, the ITSec agent: `src/itsec.js`, its instructions in `src/itsec/`) |
| `host/patches/` | the patch set (0001 to 0026), `apply.sh`, `cleanup-agent-grants.js` |
| `host/install/` | the one-line installers (`install-watchdog.sh`, `install-hermes-wrapper.sh`) |
| `host/itsec/` | the watchdog (Python 3 standard library only), systemd units, fail2ban templates |
| `host/sandbox/` | the `hermes-sandbox` wrapper and optional re-apply units |
| `scripts/release.sh` | builds the release files (bundle, installers with pinned fingerprints, `SHA256SUMS`) |
| `docs/` | `PLUGIN-PLAN.md` (the design), `sandbox-verification.md` (manual checks) |

`SHA256SUMS` in the package root lists every file (`sha256sum -c SHA256SUMS`). Check its own hash against a value you got somewhere other than the package itself.

## Tests

Prerequisites on a Linux host: **Node.js 24.11 or newer** with `npm` (as for Paperclip), **Python 3.8 or newer**, GNU `patch`, `bash`, `openssl`, `curl`, `tar`, `gzip` and `sha256sum`. Nothing needs root, and no test installs anything on the host (the installer tests run in a scratch directory). The plugin tests import `@paperclipai/plugin-sdk`, so install the plugin's dependencies once first:

```
(cd plugin && npm install --omit=dev --ignore-scripts)
npm test
```

`npm test` at the package root runs the watchdog, installer and plugin tests. Some plugin tests compare the package patches with a hand-patched live Paperclip install; they run only when `HARDENING_LIVE_PATCHES` names the patch directory that install was patched from, and skip with a message otherwise. The other tests read the original bytes of Paperclip's files from `$PAPERCLIP_STOCK_TREE_<vkey>` (for example `PAPERCLIP_STOCK_TREE_1012`; default `~/.paperclip/cli/installs/npm/2026.<vkey>.0`) and skip with a `NO PRISTINE` message when they cannot find them.
Patch fit on a given tree: `host/patches/apply.sh --check` (changes nothing).

License: MIT, see [LICENSE](LICENSE).
