# paperclip-sandbox-hardening

Sandbox hardening for [Paperclip](https://github.com/paperclipai/paperclip) agent runs, installed as a Paperclip plugin.
Every protection has its own switch. Parts that must live outside Paperclip (a watchdog, the Hermes sandbox wrapper) install with one pasted line.

Paperclip agents run real coding tools. This package keeps a misbehaving or prompt-injected agent inside a box it cannot open, stops it
from giving itself more power, and tells you when someone tampers with the protections.

## What it protects

In plain words:

* **The host and its secrets.** An agent's tools see only their workspace, and reach only the network hosts you allow.
* **The box itself.** An agent cannot change its own sandbox, network list, commands, instructions or skills. The stored box is forced again at every run, and a hidden `***REDACTED***` value can never overwrite real settings.
* **Unboxed runs.** An agent without a box is refused instead of running unprotected.
* **New agents.** Every new agent (hire, import, join) starts boxed, with no permissions and unable to create agents or skills.
* **Power and structure.** Agents cannot hand out permissions, cannot change a pipeline's stages, and can assign work to others only with an explicit grant.
* **Privacy between agents.** Each agent's Claude settings and conversations are its own.
* **Cost.** Daily token caps per agent and per company pause runaway agents and say why.
* **Your visibility.** A separate watchdog notices logins, sudo, changed system files and tampering with these protections, and raises alerts as issues.

Not covered: a kernel or sandbox escape (bwrap is a namespace sandbox, not a VM), misuse of a credential an agent is allowed to hold, secrets you keep outside the sandbox, and an attacker who has root or the admin account.

## Assumptions

* Paperclip runs as a **normal user without sudo** (never root), and a **separate admin account with sudo** exists. The admin account is only used for the one-line installs below.
* Linux, `bwrap` (bubblewrap) and Node as shipped with Paperclip. GNU `patch` on the PATH. `systemd` is optional (it gives the plugin a restart button).
* Paperclip in authenticated mode on a private network, sign-up disabled, board approval for new agents.
* Agents use `claude_local`, and optionally `hermes_local` through the wrapper. Other local adapters have no sandbox support, so "Only boxed agents run" refuses them.

## Install the plugin

1. Install it through Paperclip's plugin installer: Settings, Plugins, install by package name `paperclip-sandbox-hardening`, or on the command line
   `paperclipai plugin install paperclip-sandbox-hardening` (a local checkout also works: `paperclipai plugin install <path to plugin/>`).
2. Enable it and review the permissions card (every capability is explained in `plugin/src/manifest.js`).
3. In the plugin's settings, put **your own user id** in "Users who may change protections" (the Hardening page shows your id). Only instance admins can save plugin settings.
4. Open the **Hardening** page, fill in the site values (below), switch on what you want, and press Save.

The plugin does not touch anything until you save. When you save, it keeps a pristine copy of every Paperclip file it will change,
rebuilds those files from the pristine copy plus the switched-on protections, and asks for **one restart** (a button when Paperclip runs as a systemd user unit, otherwise "restart Paperclip now").
The rebuild is all-or-nothing: if anything does not fit, nothing changes and the row turns red.

### Site values

On the Hardening page, "Settings" holds values that belong to your install (base network allowlist, extra read-only paths, workspace roots, Hermes wrapper path and allowlist, restart unit, alert company and project, Paperclip URL for the install lines).
The plugin writes the part Paperclip itself needs to a settings file: `$PAPERCLIP_HARDENING_CONFIG`, else `<instance root>/hardening/config.json`
(by default `~/.paperclip/instances/default/hardening/config.json`). The patched Paperclip reads it once at startup; it is not agent-writable. Without it, secure generic defaults apply.

## The Hardening page

Admin only. One row per protection, each with an on/off switch (the safety core too; switching a core protection off asks for confirmation and names the risk).

| Switch | What it does | Default |
|---|---|---|
| Sandbox compatibility | makes the built-in sandbox work reliably (modern Linux layouts, git worktrees, proxy crashes, apps inside a run reachable on localhost, interaction wake-ups) | on (required by most others) |
| Agents can't change their own box | sandbox, network, commands, instructions and skills are board-only for agents; the stored box is forced again at every run; a hidden `***REDACTED***` value can never overwrite real settings | on |
| Only boxed agents run | an agent without a sandbox is refused instead of running unboxed | on |
| Safe defaults for new agents | every new agent (hire, import, join) starts boxed, with no permissions, unable to create agents or skills | on |
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
* **Status column.** applied, pending restart, unavailable on this install, self-test failed, or drifted (files changed outside the plugin).
* **Alerts.** Recent watchdog alerts and caps events, with links to the issues.

### No version lock

There is no list of supported Paperclip versions. A protection is offered wherever the code it changes still exists in that shape. If that code is missing or changed,
the row shows **"unavailable on this install"** and stays off; nothing is half-applied, an alert is raised, and the other protections still apply (dependencies permitting).
After a Paperclip update, the plugin rebuilds the switched-on set against the new files on start and asks for one restart. Docker installs re-create files with the image, so the plugin re-applies them on every start.

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

## Install the watchdog and the Hermes wrapper (one line, run by the admin)

The admin password must never pass through Paperclip, which runs under the same account as the agents' tools. So these two parts install with a line you paste into your own admin terminal (ssh as the sudo user).

1. On the Hardening page, flip **Watchdog** (or **Hermes agents boxed**). A box shows one line and "waiting for the watchdog to report in".
2. Paste the line into your admin terminal. It looks like this:
   ```
   d=$(mktemp -d) && curl -fsSL https://github.com/<org>/paperclip-sandbox-hardening/releases/download/v<version>/install-watchdog.sh -o "$d/install-watchdog.sh" && echo "<sha256>  $d/install-watchdog.sh" | sha256sum -c - && sudo bash "$d/install-watchdog.sh" --paperclip http://<host>:3100 --enrol <one-time code>
   ```
3. The watchdog reports in and the switch turns green by itself.

**Check the line before you run it.** Compare the **URL** (it must be the official release of this project) and the **sha256 fingerprint** with the values on the release page for that version (the fingerprint is printed in the release notes). If they differ, do not run it.
The installer itself downloads the watchdog bundle from the same release and checks it against fingerprints pinned inside the script. It never uses local files that Paperclip's account could have changed.
This is the standard download, verify, then sudo model: if someone controlled Paperclip's account they could show you a forged line, which is why you compare it with the release page.

* **The one-time code** is created by the plugin, valid 15 minutes, single use, stored only as a hash. The installer makes the watchdog's own signing key pair, keeps the private key root-only on the host, and enrols by sending the code plus its public key, signed. Every heartbeat and alert is signed (5-minute window, one-use nonce) and the plugin creates the alert issues itself. No Paperclip key exists on the host.
* **Hermes wrapper:** the same pattern with `install-hermes-wrapper.sh`. No enrolment: the row turns green when the wrapper file is root-owned, not writable by others, and matches the released fingerprint.
* **Removal:** the switch shows the same kind of line with `--uninstall`. It removes the service, its account and its key; the plugin forgets the public key.
* A development checkout (not a release build) has no pinned release, so the rows show no install line. Release files are built by `scripts/release.sh` (see its header; it publishes nothing by itself).

What the watchdog watches and its rule table: [host/itsec/README.md](host/itsec/README.md). Manual install steps it automates: [host/itsec/INSTALL.md](host/itsec/INSTALL.md).
The read ACLs on the watched user's files and the patch manifest are the two things the installer prints for you to do afterwards.

## Self-test

After each restart, a short self-test checks that every switched-on protection really works in the files Paperclip runs, not only that the text is there.
Four protections are tested functionally (the sandbox builds a spawn target without re-mounting usr-merge symlinks, the public-web box accepts `*:443` and still refuses `*`, a run override that widens the network or escapes the workspace is undone, a new agent created unboxed comes out boxed);
the rest get a structural check (each file equals the build the plugin recorded and carries its markers). The page says which kind each row got. A failed self-test turns the row red, logs once and raises an alert issue.
"Run self-test" repeats it on demand.

## Fallback without the plugin

If the plugin cannot run, the same engine runs from the command line (nothing restarts Paperclip; it prints the restart command):

```
node plugin/bin/hardening-engine.mjs status
node plugin/bin/hardening-engine.mjs plan  --enable defaults
node plugin/bin/hardening-engine.mjs apply --enable defaults
node plugin/bin/hardening-engine.mjs restore
```

Details: [plugin/src/engine/README.md](plugin/src/engine/README.md). `host/patches/apply.sh [--check]` applies the whole patch set in one go (idempotent, all-or-nothing) and `host/sandbox` holds optional systemd units that re-apply it after a Paperclip update.
Use one route or the other for a given install, not both.

## Uninstall

1. On the Hardening page press **Restore originals** (it asks for confirmation). Every file Paperclip had is written back byte for byte, all-or-nothing. Restart Paperclip.
2. Remove the watchdog and the Hermes wrapper with the `--uninstall` lines from their rows (run by the admin).
3. Disable and remove the plugin in Paperclip's plugin manager.

If Paperclip was updated meanwhile, a file that changed outside the plugin is left as it is and its stored original is kept (the CLI's `restore --force` overrides that).
The plugin's own data lives in `~/.paperclip/sandbox-hardening` (`$PAPERCLIP_HARDENING_DATA`) and the settings file above; remove them after the restore.

## Known limits

* **The SDK cannot update agent boxes.** Paperclip's plugin SDK has no way to change an agent's configuration. The Agent boxes page therefore keeps the plugin-side values and shows the exact change (a `PATCH /api/agents/<id>` body) for an admin to apply by hand; the row shows "not applied" until the agent matches.
* **Plugin actions are callable by company members.** Paperclip lets any company member and the company's agents call a plugin's actions, and tells the plugin who is calling but not whether they are an instance admin. The plugin therefore refuses agents and accepts a user only when an instance admin listed their user id in the plugin's own admin list ("Users who may change protections"). That list gates every write on both pages.
* **Alert re-checks happen in the plugin, and see closes only while it runs.** The watchdog's signed channel deliberately has no read access to Paperclip's issues, so the plugin re-checks the alert issues it creates (watchdog alerts, a failed self-test, a silent watchdog). For `alertRecheckDays` (default 7, 0 = off) after an alert, the "Alert tamper re-check" job re-reads it every 10 minutes; only the users in `alertOwnerUserIds` (default: the admin list) may close it. If anyone else (an agent, another user) closes, cancels, deletes or hides it, the plugin opens one new HIGH "[RE-RAISED]" alert naming who did it (at most 3 per alert; it creates a new issue rather than reopening, so it needs no issue-edit right). The plugin SDK cannot read the activity log, so the closer comes from Paperclip's `issue.updated` event: a close made while the plugin worker was down gets one MEDIUM "closer unknown" alert instead, and a deletion's actor is never known. Edits to an alert's text are not checked.
* **Same trust zone.** The plugin runs inside Paperclip's process account. A compromised Paperclip can lie to the plugin; the watchdog, which runs outside it, is what notices a deliberate switch-off or changed files. Plugin runtime APIs are alpha, and a Paperclip version that moved plugin workers into a restricted loader would stop the plugin from applying protections (it would show red; the fallback CLI still works).
* **The sandbox is only as strong as bwrap and your allowlist.** An allowlisted host can be abused for exfiltration; the public-web box allows any public website on purpose.
* The watchdog's alert path runs through the Paperclip instance the agent account hosts. An agent that escapes can silence it; use an independent second channel for high-value setups.
* Log-based watchdog rules depend on Paperclip's log line formats; check them after updates. Linux only.

## Upstreaming

Each protection is also meant to be offered to the Paperclip project as a pull request. Notes per patch (problem, repro, fix, tests) are in [host/patches/UPSTREAM.md](host/patches/UPSTREAM.md). Accepted ones drop out of the plugin in later versions.

## Layout

| Path | What it is |
|---|---|
| `plugin/` | the Paperclip plugin (switches, Agent boxes, caps, self-test, engine, fallback CLI) |
| `host/patches/` | the 0001-0016 patch set, `apply.sh`, `cleanup-agent-grants.js` |
| `host/install/` | the one-line installers (`install-watchdog.sh`, `install-hermes-wrapper.sh`) |
| `host/itsec/` | the watchdog (Python 3 standard library only), systemd units, fail2ban templates |
| `host/sandbox/` | the `hermes-sandbox` wrapper and optional re-apply units |
| `scripts/release.sh` | builds the release files (bundle, installers with pinned fingerprints, `SHA256SUMS`) |
| `docs/` | `PLUGIN-PLAN.md` (the design), `sandbox-verification.md` (manual checks) |

`SHA256SUMS` in the package root lists every file (`sha256sum -c SHA256SUMS`). Check its own hash against a value you got somewhere other than the package itself.

## Tests

`npm test` at the package root runs the watchdog, installer and plugin tests. Some plugin tests compare the package patches with a live, hand-patched Paperclip install and skip themselves when there is none (`HARDENING_LIVE_PATCHES`, `PAPERCLIP_TREE`).
Patch fit on a given tree: `host/patches/apply.sh --check` (changes nothing).

License: MIT, see [LICENSE](LICENSE).
