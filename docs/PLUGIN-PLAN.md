# Design: the Security Hardening plugin

Goal: one Paperclip plugin that anyone can install on any Paperclip instance. Each protection gets its own switch. Parts that must run outside Paperclip (the watchdog) are installed with one pasted line.

Assumptions, as before: Paperclip runs as a normal user without sudo, and a separate admin account (with sudo) exists for the one-line installs.

## 1. What the owner sees

**Hardening page** (admin only), one row per protection:

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
| Watchdog | separate service under its own account: logins, sudo, changed system files, tampering with these protections, alerts as issues | off until installed (one-line install, section 3) |
| Hermes agents boxed | installs the root-owned Hermes sandbox wrapper | off; one-line install, only if Hermes is used |

Rules the page enforces:
- **Dependencies:** switching a protection on also switches on what it needs (for example the public-web box needs "Sandbox compatibility" and "Agents can't change their own box"). Switching one off that others need asks first and lists the dependents.
- **One restart per save:** changes are collected and applied with a single Paperclip restart. The page says "restart needed" and offers the button.
- **No version lock:** a protection is offered on every Paperclip version where the code it changes is still there. Only when that code is missing or has changed shape does the row show "unavailable on this install" and stay off; nothing is half-applied. After each restart a short self-test checks that every switched-on protection really works (for example, an agent trying to change its own box gets refused). A failed self-test turns the row red and raises an alert.
- **Status column:** applied / pending restart / unavailable on this install / self-test failed / drifted (files changed outside the plugin).
- **Every row has an on/off switch**, the safety core included. Switching off a core protection asks for confirmation and names the risk.

**Agent boxes page:** one row per agent that actually exists in the company, read fresh from Paperclip at every refresh (no list of possible models or adapters). Each row shows the agent's type, its box (allowlist or public web), extra hosts, permissions and **daily token cap**.
- **Default cap** (one field per company): applies to every agent without its own cap, including agents added later. A new agent appears at the next refresh and is capped from its first run.
- **Per-agent cap:** an optional override on the agent's row. Clearing it returns the agent to the default.
- **Company cap:** the total for all agents per day.
- An agent whose type reports no token usage shows "usage not reported" instead of a cap that can't be enforced. It flags conflicts: public web together with "may assign work" is refused.

**Alerts:** recent watchdog alerts and caps events, with links to the issues.

**ITSec agent card** (on the Hardening page, host company only): the plugin creates and manages one security agent in the company the operator marks as the host company (setting `itsecHostCompanyId`, set from inside that company by a plugin admin; nothing exists until then, and no other company ever gets one).
- **The agent:** `claude_local`, CLI engine, `bwrap` workspace scope, the base allowlist and the configured read-only paths, `dangerouslySkipPermissions` left unset (the adapter then skips permissions, which a headless run needs; accepted only because the agent is boxed), no `canCreate*`, no grants beyond `tools:use`, 30 runs a day, created paused. Generic security-stance instructions (`AGENTS.md`, `TRIAGE.md`, `DAILY-REVIEW.md`) ship in `plugin/src/itsec/`; host facts go in the plugin-written `itsec-context` document.
- **Routines:** *alert triage* has no schedule: an alert above low priority in the host company starts it (`routines.managed.run`), debounced to once per 30 minutes; a 15-minute job starts it only if an open alert still has no comment from the agent, so there is no agent run when there is nothing to triage. *Daily review* at 07:00 UTC.
- **Verify before it runs:** after reconcile the plugin reads the agent and its grants; only a compliant agent is resumed, then the routines go active. It resumes only a pause that is its own: the provisioning pause, or one it recorded itself (`pausedByPlugin` in the company state: drift, or the company un-marked), because Paperclip writes the reason "manual" for every pause. A pause by a person or a token cap stays. Drift later: agent and routines paused, HIGH alert (one per distinct findings); once a check finds the agent compliant again (board fix, or Reset) the plugin resumes it and switches the routines on.
- **Board approval companies:** Paperclip 2026.1012.0 and master fail to create a managed agent where `requireBoardApprovalForNewAgents` is on (pending agent, instructions write refused, no hire approval). The plugin adopts the half-created agent, says on the card that the board approves the agent itself (`POST /api/agents/<id>/approve`, no approval record needed), and after that writes the instructions (managed reset), creates the routines and verifies.
- **Status documents:** replaced by delete + create, because the SDK's `issues.documents.upsert` cannot pass the `baseRevisionId` Paperclip requires for an update.
- **Moving the mark:** the old company's agent is paused by a loop started in the worker's `setup()` (outside any request, since a request is scoped to one company and the scope travels with the work it starts), right after the save; the 15-minute job is the retry.
- **Allowed closer, with evidence:** the host company's current ITSec agent may close the plugin's alert issues, but only after its own comment (separate, before the close) whose first line starts with `Resolution:` and that has an `Evidence:` line with at least 10 characters of evidence. The alert re-check lists the comments (`issue.comments.read`), takes the close time as the earlier of the `issue.updated` event time and the issue's `completedAt`/`cancelledAt`, and accepts the close only if the `issue.updated` event's own actor is `actorType: "agent"` with `actorId` = the verified ITSec agent (the payload's `agentId` is ignored: a plugin's `issues.update` accepts any `actorAgentId` and records it there with `actorType: "plugin"`) and only for a non-deleted comment by that agent that has a `createdByRunId` (set by Paperclip from the authenticated agent run; a plugin-created comment never has one) created strictly before the close and after any earlier recorded close of the same issue. If the comments cannot be read the verification stays pending (retried and logged each run); after 3 failed runs for that close (counted in total) or at the end of the re-check window, whichever comes first, the close is treated as unverified and re-raised (a failed re-raise is retried on the next run; the pending state is cleared only when a verification completed). Anything else is re-raised as today (other agents, other companies' agents, non-admin users, an old host agent, no or malformed comment). Accepted closes are stored per company and written to the `hardening-status` document and the activity log. Real host fixes are escalated to the owner as an issue ("ITSec proposal", starting "For the owner:"); the agent has no host write. Preventive blocking would need a server patch (not built).
- **Model:** advisory setting, shown against the live model with the `PATCH` for the board. Schedule edits happen in Paperclip's Routines page.

## 1b. Multiple companies

- **Protection switches are install-wide:** they change how Paperclip itself works, so they apply to every company at once (no per-company exceptions).
- **Agent boxes and caps are per company:** the page has a company picker; each company has its own default cap, company cap and per-agent overrides. New companies appear automatically.
- **New companies are never uncapped:** they start from an install-wide cap template (default cap and company cap), editable per company afterwards.
- **Watchdog:** one service for the install; its alerts go to one chosen company and project.
- **Status:** shown per company (all agents boxed, caps active), plus the install-wide protection status.

## 2. How the switches work

- **Applying:** the plugin keeps a pristine copy of each Paperclip file it changes. On save it rebuilds each affected file from the pristine copy plus the switched-on protections, in a fixed order. This is all-or-nothing: if anything doesn't fit, nothing changes and the row turns red. Then one restart.
- **Off means original:** switching everything off restores the pristine files exactly.
- **After a Paperclip update:** on start the plugin rebuilds the switched-on set against the new files and asks for one restart. If the code a protection changes is no longer there, that protection is shown "unavailable on this install" and an alert is raised; the others still apply (dependencies permitting). The self-test then confirms they work.
- **Who can switch:** only users on the plugin's own admin list ("Users who may change protections", stored per company; only an instance admin can save plugin settings). Paperclip lets any company member and the company's agents call a plugin's actions and does not tell the plugin whether the caller is an instance admin, so the plugin refuses agents outright and accepts a user only when that list names them. The list gates every write on both pages.
- **Restart:** where Paperclip runs as a systemd user service, the plugin restarts it itself, but only after verifying that the unit's control group is the one the Paperclip server process runs in and that the unit is Paperclip's own name for the instance (`paperclipai.service`, `paperclipai-<id>.service`); elsewhere (Docker, pm2, manual) it says so and shows how to restart by hand (Ctrl-C and re-run `paperclipai run`, or `paperclipai service restart`). The unit is detected, not configured.
- **Which Paperclip:** the plugin worker gets no Paperclip home or instance id, so the install tree, instance, data folder and settings file are derived from the Paperclip server process that started it (`/proc/<parent>`: command line flags over start-up environment, as Paperclip resolves them). If that is not possible (unknown launcher, hidden `/proc`, files replaced since start) the plugin changes nothing and says why; the command-line tool is the fallback. No setting can point the plugin at another tree or unit.
- **Tamper visibility:** the watchdog, outside Paperclip, notices any change to the protected files, including a deliberate switch-off, and raises an alert. A hostile or accidental switch-off is therefore never silent. The plugin itself only shows a changed file as "drifted" on the page (no alert; it cannot tell tampering from a Paperclip update that replaced the file), so without the watchdog installed the change is visible only on the page.

## 3. The one-line install (watchdog, Hermes wrapper)

Why one line and not a password modal: the admin password must never pass through Paperclip, which runs under the same account as the agents' tools.

**Flow:**
1. The owner flips "Watchdog". The modal shows one line, a short explanation and "waiting for the watchdog to report in".
2. The owner pastes the line into their own admin terminal (`ssh` as the sudo user).
3. The line downloads the watchdog bundle **from the official release**, never from local files that Paperclip's account could have changed. It checks the bundle's fingerprint, installs it under its own account, and enrols it with Paperclip.
4. The watchdog reports in and the switch turns green by itself.

**The line**, for example:
```
d=$(mktemp -d) && curl -fsSL https://github.com/tomRumi/paperclip-security-hardening/releases/download/v<version>/install-watchdog.sh -o "$d/install-watchdog.sh" && echo "<sha256>  $d/install-watchdog.sh" | sha256sum -c - && sudo bash "$d/install-watchdog.sh" --paperclip http://<host>:3100 --watched-user <account> --enrol <one-time code>
```
- `<account>` is the account Paperclip runs as (the plugin fills it in). `<sha256>` is also printed on the release page, so the owner can compare it there if they want. The script itself checks the bundle it downloads against fingerprints pinned inside the script.
- `<one-time code>`: created by the plugin, valid 15 minutes, single use, stored only as a hash. The installer creates the watchdog's own signing key pair, keeps the private key root-only on the host, and enrols by sending the code plus its public key, signed. Every heartbeat and alert is signed (5-minute window, one-use nonce) and the plugin creates the alert issues itself. **No Paperclip key exists on the host**, and no shared secret ever passes through Paperclip (whose webhook log the agents' account can read).
- **Removal:** the toggle shows the same kind of line with `--uninstall`. It removes the service, its account and its key pair; the plugin forgets the public key.
- **Hermes wrapper:** the same pattern with `install-hermes-wrapper.sh`.

Residual: someone who controls Paperclip's account could show a forged line in the modal. Mitigations: the line is short and readable (official GitHub URL plus fingerprint), and the README tells admins to check the URL and fingerprint against the release page. This is the standard `curl | verify | sudo` trust model; the plugin cannot do better without a channel the agent account can't touch.

## 4. Packaging

- Repository `tomRumi/paperclip-security-hardening`. The plugin is installed from a clone at the release tag, by path, through Paperclip's plugin installer; it is not published to npm. (The package keeps `prepack`/`postpack` scripts so a pack would carry the protection files.)
- GitHub releases carry the root-side scripts (`install-watchdog.sh`, `install-hermes-wrapper.sh`), with fingerprints in the release notes.
- MIT licence, copyright holder and GitHub account tomRumi.
- Tests: per protection, a test that it does its job and a test that switching it off restores the original. Run them against the current and newest Paperclip releases to catch shape changes early (there is no CI job in this repository yet); there is no version pin.
- Upstream: each protection is also offered to the Paperclip project as a pull request. Accepted ones drop out of the plugin for later versions.

## 5. Risks to accept

- **Platform:** plugin background workers are normal programs today. A Paperclip version that moves workers into the (existing but unused) restricted plugin loader would stop the plugin from applying protections. It would then show red, and the fallback is the command-line engine, which runs the same apply step.
- **Maintenance:** when a Paperclip release changes the code a protection targets, that protection shows "unavailable" until it is refreshed; the others keep working.
- **A protection that applies but no longer works** on a much newer version: caught by the self-test after restart, not silently trusted.
- **Docker installs:** the image's files are rebuilt on container re-creation; the plugin re-applies them on every start, which costs one restart.
- **Managed agent configuration is fixed at creation (ITSec):** Paperclip's SDK offers create/relink/reset for a managed agent but no update; `reset` re-applies the declaration and wipes board edits. So adapter settings, permissions and instructions are changed by the board, and the plugin only verifies them. Routine schedules are created once the same way, and the model setting is advisory.
- **The ITSec agent can read issues and write comments, so a prompt-injected ITSec agent could close an alert:** only detective controls exist (alert re-check naming the agent, pause on sandbox drift). A host company without saved plugin settings cannot get the agent (Paperclip admits plugin calls per company); on a Paperclip without the no-default-grants protection the agent is paused instead of stripped of its default grants.
- **Skip-permissions only inside the box:** `dangerouslySkipPermissions` unset (the adapter's default is `true`) or `true` is accepted for a boxed `claude_local` agent and flagged on an unboxed one; the ITSec agent leaves it unset because `claude -p` with `false` refuses Bash and MCP tools. The Routines page of Paperclip holds the live schedule (the plugin shows the declared one: `routines.managed.get` returns no triggers).

## 6. Build order

1. The engine: pristine copies, rebuild, all-or-nothing, restart, version table, using today's protections and tests.
2. Hardening page with switches, dependencies and status.
3. Agent boxes page (per-agent boxes and caps).
4. Daily token caps moved into the plugin as a scheduled job.
5. The one-line installers, enrolment codes and the watchdog heartbeat.
6. Release packaging, README, then a fresh test install on a clean Paperclip.

## Decisions

1. MIT licence. Copyright holder and GitHub account: tomRumi.
2. Caps: a default cap per company that covers every agent, including new ones, plus an optional per-agent override; only agents that actually exist are listed (fresh at every refresh); no model-based presets.
3. Every protection, the safety core included, has an on/off switch (core switch-off asks for confirmation).
4. No version lock: a protection is available wherever the code it changes exists; a self-test after restart confirms it works.

## Candidate protections (not built)

- **Agents cannot change status or assignee of the plugin's own issues:** a server rule on issues whose origin kind starts with `plugin:paperclip-security-hardening`. It would make the ITSec agent's close rule (resolution comment first) preventive instead of detective. Not built (owner decision pending).
- **Goals are board-only:** today any agent can create, edit or delete Goals (milestones); the server only checks company access.
- **Own worktree entry only:** in a run, only the agent's own `.git/worktrees/<name>` is writable; sibling entries are read-only. This stops an agent's `git worktree prune` from dropping other tasks' worktree registrations (observed in testing; the impact was availability, not access).

## Appendix for builders: switch → today's local patches

Sandbox compatibility 0001, 0004, 0006a/b, 0012, 0014 · own box 0002, 0003, 0008 · only boxed 0005b · safe defaults 0005a, 0005c, 0005d, 0005e, 0010 · no permission handing 0009, 0011a/b · pipeline 0007 · assign grant 0013a/b · public web 0015 · own Claude folder 0016 · caps: plugin/src/caps.js · watchdog: host/itsec · Hermes: host/sandbox/hermes-sandbox.
