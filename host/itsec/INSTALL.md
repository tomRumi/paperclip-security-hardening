# The watchdog after the one-line install

The watchdog is installed by `install-watchdog.sh`, the line the plugin's Hardening page shows (top-level README, "Install the
watchdog and the Hermes wrapper"). This file is the reference for what that line put on the host, the few steps that remain,
and day-to-day operation. A copy is kept at `/opt/itsec/INSTALL.md`.

Everything below runs as the admin account (the account with sudo, not the account Paperclip runs as). The old step-by-step manual
install is gone: its root steps are done by the installer, and none of them needs to be repeated by hand.

## 1. What the installer did

| Step | Result |
|---|---|
| User and groups | system user `itsec` (no shell, no sudo) in the groups `adm`, `systemd-journal` and `vaultaudit` (the last one is only used with a vault, section 9) |
| Code | `/opt/itsec`, root-owned, so `itsec` cannot rewrite its own detector |
| Config | `/etc/itsec/config.json` (no secrets in it); an existing config is kept on re-runs |
| Key | `/etc/itsec/watchdog-key.pem` (root, 0600), handed to the units with `LoadCredential`; its public half is enrolled with the plugin. No Paperclip board or agent key exists on the host |
| Units | `itsec-collect` (every 15 minutes), `itsec-report` (daily), `itsec-lynis` (weekly) in `/etc/systemd/system` |
| Read access | `setfacl` entries for `itsec`: read on the watched files in the watched user's home, traversal on the directories above them (section 3); the paths are listed in `/etc/itsec/acl-paths` before they are granted |
| Patch manifest | `/etc/itsec/patch-manifest.json` (section 4) |
| Baseline | one collector run (learns SSH addresses, file hashes, ports, users) before the timers start |

The first collector run is the baseline: every SSH source address seen in the last 3 days of the journal becomes "known", and later
logins from other addresses are HIGH. Install while the host is in a known-good state. Only entries from the real sshd unit with uid 0
are used, so a forged `logger -t sshd` line cannot poison the baseline.

## 2. What the installer needs and does not install

* `setfacl` (package `acl`), `python3`, `openssl` (Ed25519 support, 1.1.1 or newer), `curl`, `tar`, `sha256sum`. The installer stops with a message when one is missing.
* **Persistent journal.** Otherwise a reboot loses the evidence. `ls /var/log/journal` must exist; if not:
  `sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal && sudo systemctl restart systemd-journald`.
* `lynis` for the weekly audit: `sudo apt-get install lynis`. The installer enables `itsec-lynis.timer` only when `lynis` is installed; otherwise it prints the command to enable it later (`sudo systemctl enable --now itsec-lynis.timer`), and a weekly run without `lynis` reports an INFO finding `lynis-missing` instead of an alarm. `fail2ban` (section 6) is optional.
* Host check before relying on the sudo rules: `sudo -l -U <Paperclip's account>` must say that it may not run sudo. Any successful sudo by that account raises HIGH `sudo-success`; `su` use raises HIGH `su-attempt`. Content changes in `/etc/sudoers` and `/etc/sudoers.d` are HIGH through the watch list.

The config is written once, from `config.example.json`: `watched_user` and the home in the watch list come from `--watched-user` (the plugin's line passes the account Paperclip runs as), `admin_user` from `--admin-user` or else the account that ran `sudo`. If neither is known the example value `admin` stays and the installer says so; edit `/etc/itsec/config.json` then. Other keys worth a look: `known_restart_windows`, `disk_paths`, the `watch` list.

## 3. Read access to the watched files

The watched user's home is 0750. The installer gives `itsec` traversal (`x`) on the home and on the directories between it and each watched path, and read (`r`)
on the paths themselves, as ACL entries (`setfacl`). It applies them through `/opt/itsec/bin/itsec-acl`, because the home belongs to the
account the agents run as, which could swap a directory for a symlink while the installer runs (and `setfacl -P` only refuses a symlink in the last path component).
The helper walks each path from `/` one component at a time without following any symlink, checks through the open descriptor that every component belongs to the
watched account or root, and applies the entry to that descriptor, so a swap after the check cannot redirect it. A path that fails the check is refused and
reported (a path the helper cannot even look at, for example a mount the account made that root may not enter, is refused the same way, and the installer goes on with the next path);
in a recursive tree, symlinks, files owned by anyone else, objects on another file system (a mount inside the tree) and objects that cannot be looked at are left out and counted,
and a tree with more than 20000 entries is refused as a whole before anything is changed (exit 2, like an unsafe path). The same bound applies to the agents' settings files: more than 500 are refused together, and so is a search that has to look at more than 20000 directory entries, whether or not any of them matches.
An unexpected failure of `setfacl` stops the installer (running it again is safe). The paths are written to `/etc/itsec/acl-paths` before the first entry is applied.
Precisely, what `itsec` can read afterwards: the listed files, and any other file in the home or in those directories whose own mode already lets everybody read it
(traversal makes such a file reachable; a 0600 or 0640 file stays closed). `ls -l` shows a `+` on the touched paths and the group bits show the ACL mask.

What is granted:

* files: `.claude/settings.json`, `.claude/settings.local.json`, `.claude/CLAUDE.md`, `.bashrc`, `.profile`, `.bash_logout`, `.ssh/authorized_keys`, `.ssh/authorized_keys2`, `.ssh/rc`, `.ssh/config`, each agent's `.claude/settings*.json` under `~/.paperclip/instances/default/companies/*/agents/*/`;
* trees (read-only, recursive): `.config/systemd/user`, `.config/environment.d`, `.local/bin`, `.claude/skills`, `.claude/plugins`, `.claude/agents`, `.claude/commands`, `.claude/hooks`;
* the patched Paperclip files under `~/.paperclip/cli/current` (the files the manifest records, up to ten).

Not granted: private SSH keys, `.claude/.credentials.json`, Paperclip secrets, agent conversations. Files the account cannot read (`/etc/sudoers`,
crontabs, `/root/.ssh`) are still watched through their stat signature (mode, owner, size, mtime, ctime). A path that is a symlink, or sits behind
one, is skipped with a message: the home belongs to the account the agents run as. The collector hashes the watched files that account
controls (under its home, or owned by it) through the same safe walk; one that has become a FIFO, a device, a file over 64 MiB, or sits behind a swapped symlink
is not read and is reported as `watch-unsafe` (the watch entry's severity, HIGH for the home); other files (root's) are opened the same way, capped at 1 GiB.
The watch is bounded so that a tree the account fills cannot run the collector past its 600 s timeout: a watched directory is read up to `watch_max_objects` (3000)
entries, files, directories and links together, and more is HIGH `watch-truncated` (new entries past the cut are not discovered; every path already recorded is still checked by its own path each run, so its change or removal is reported, and a file named without a wildcard is never cut; a wildcard pattern has ONE budget of that many objects for all its hits and their walks, and reads at most ten times that many directory entries, matching or not; the state never holds more recorded paths per tree or pattern than that); a symlink to a directory is recorded
as a link and never followed, a directory `itsec` cannot list by its stat signature, so a change to either is a finding; at most `hash_budget_bytes` (1 GiB) are hashed
per run, and a file whose device, inode, size, mtime and ctime are unchanged reuses the hash cached in the state (`hash_cache`); beyond the budget the remaining new or changed
files are compared by stat signature and reported once as MEDIUM `hash-budget-exceeded` (a file that is hashed later is not reported changed while its stat signature is the recorded one; a file with an old hash that the budget did not reach is a change only where the cache proves it, otherwise it keeps its old signature until a run can hash it). All three are config keys. The vault audit files get the same treatment (MEDIUM `vault-log-unsafe`). A watched path `itsec` cannot reach is reported as MEDIUM
`watch-unreadable` instead of vanishing; this lists them:

```
sudo -u itsec env ITSEC_CONFIG=/etc/itsec/config.json /opt/itsec/bin/itsec-collect --dry-run
```

**After a Paperclip update, or when new files appear in a watched tree** (a new agent, a new skill), paste the install line from the Hardening page again
(a fresh line has a fresh code): it refreshes the access and the manifest and keeps the key, the install id and the config. Only paths under the default
Paperclip instance (`~/.paperclip/instances/default`) and the standard install layout (`~/.paperclip/cli/current`) are covered, because the watch list in the config names them; edit the list for another layout.

Optional, not done by the installer: content hashes of sudoers (without them it is watched by stat signature only):
`sudo setfacl -m u:itsec:x /etc/sudoers.d; sudo sh -c 'setfacl -m u:itsec:r /etc/sudoers /etc/sudoers.d/*'` (`/etc/sudoers.d` is 0750 root; repeat when a file is added;
`--uninstall` does not undo this one).

## 4. Patch manifest

`itsec` never runs `apply.sh` or anything under `/home`. It hashes the patched Paperclip files and looks for the `LOCAL-PATCH` markers, comparing
against `/etc/itsec/patch-manifest.json`, which the installer writes (root, 0644) with `/opt/itsec/bin/itsec-make-manifest --tree ~/.paperclip/cli/current`.
The generator reads the files only and refuses to record a file that lacks its marker, so the manifest is written once the protections are applied.
It reads them through the same symlink-safe walk (`--uid` names the watched account), because the account can turn a file into a FIFO or a link to `/dev/zero`: only a regular
file of at most 64 MiB is read; anything else (or a path it may not look at) is refused with a message, no manifest is written, an older one stays, and the installer goes on.
If they were not yet (the usual order is: plugin, protections, restart, then watchdog), the installer says "the patch manifest was NOT written"
and continues; turn the protections on, restart Paperclip, then paste the install line again.

The collector reads those files the same way (`itsec/acl.py`, run as `itsec`): `.../cli/current` is resolved once, then each component is opened
without following a symlink, must belong to the watched account (`watched_uid`) or root, and the last one must be a regular file of at most 64 MiB. A FIFO
(which would stall the run until its timeout), a device such as `/dev/zero`, a bigger file or a swapped symlink is never opened for a blocking read: it is HIGH
`patch-file-unsafe`, and a file that is only permission-denied or missing stays MEDIUM `watch-degraded`.
A missing or unreadable manifest or file is MEDIUM `watch-degraded` (never a false HIGH). A hash mismatch, a lost marker, or a manifest that is not root-owned or is
group/world-writable is HIGH. A Paperclip update therefore raises HIGH until the manifest is regenerated (section 3, last paragraph): that is intended.
`sudo cat /etc/itsec/patch-manifest.json` has one entry per patched file (9 or 10, depending on the Paperclip version): its sha256 and its markers.

## 5. Secrets

With the one-line install the watchdog holds only its own signing key. It needs no board token, no agent key and no shared secret, and the plugin creates the alert
issues itself. Nothing else has to be stored in `/etc/itsec`.

Optional: the daily report can add a narrative written by Claude. For that, install the `claude` binary yourself from the official source with checksum
verification into `/usr/local/bin/claude` (root:root 0755; do not copy it from the Paperclip user's `~/.local/share/claude`, which that account can modify), put the
output of `claude setup-token` into `/etc/itsec/claude-token` (root, 0600) and paste the install line again so the unit receives it as a credential. Without it the report is
produced from the deterministic findings alone. `/usr/local/bin/node` and `/usr/local/lib/node_modules` should be root-owned as well (the watchdog watches `/usr/local/bin`).

## 6. fail2ban (optional)

```
sudo apt-get install -y fail2ban
sudo cp /opt/itsec/fail2ban/jail.local /etc/fail2ban/jail.local   # review ignoreip first so your own address cannot be banned
sudo cp /opt/itsec/fail2ban/fail2ban.local /etc/fail2ban/fail2ban.local   # logs to the journal, else "[sshd] Ban" never reaches the watchdog
sudo journalctl -u ssh.service -n 3       # confirm the unit name is ssh.service (else edit journalmatch)
sudo fail2ban-regex "systemd-journal[journalmatch='_SYSTEMD_UNIT=ssh.service']" sshd     # must show matched lines
sudo systemctl enable --now fail2ban && sudo fail2ban-client status sshd
```
The template's `ignoreip` covers only localhost (`127.0.0.1/8 ::1`); add your own private or tailnet range or a fixed admin IP if you need it.
The installer put the templates under `/opt/itsec/fail2ban` (root-owned). If the regex shows 0 matches (an older filter without
sshd-session support), install `sshd.local.optional` as `/etc/fail2ban/filter.d/sshd.local` and repeat.

## 7. Operations

* Planned Paperclip restarts: put the maintenance window into `known_restart_windows` in the config
  (`[["2026-10-14T20:00:00Z","2026-10-14T21:00:00Z"]]`); a restart outside any window is MEDIUM `paperclip-restart`.
  After a Paperclip update: let the plugin re-apply the protections, restart, then paste the install line again (section 3).
* Re-baseline after a deliberate change (a new service port, a new user): `sudo -u itsec env ITSEC_CONFIG=/etc/itsec/config.json /opt/itsec/bin/itsec-collect --rebaseline` (one quiet run).
* Test delivery without waiting: `sudo systemctl start itsec-report.service` (creates a real issue).
* Findings: `/var/lib/itsec/findings/YYYY-MM-DD.jsonl`; undelivered HIGH alerts: `state.json` key `outbox`. Logs: `journalctl -u itsec-collect.service`.
* Update the code: paste the install line again.
* Uninstall: `install-watchdog.sh --uninstall` (the line with `--uninstall` on the Hardening page). It stops the timers, removes the units, the read access it granted
  (the entries listed in `/etc/itsec/acl-paths`, through the same symlink-safe helper; a listed path that was never granted or no longer exists is skipped. When no
  other user or group entry is left on a path, the ACL mask goes too, so the path is back to plain mode bits without a `+`; other entries and their mask stay. An entry that could not be removed
  is printed, and the list of such entries is kept in `/root/itsec-acl-paths.left` (root only, outside `/etc/itsec`, which is deleted: check a path with `getfacl -p PATH`), the user `itsec`, the group `vaultaudit` if it created it, and `/opt/itsec`, `/etc/itsec`, `/var/lib/itsec`.

## 8. Alerts: where they go

The installer sets `"notifier": "plugin"`: HIGH alerts, the daily report and the heartbeat are signed messages to the Security hardening plugin's webhook,
and the plugin creates the issues in the alert company and project chosen in its settings (the Hardening page). The plugin also re-checks those issues
for tampering (README, Known limits). Idempotency keys, deduplication and the outbox work as described in `README.md` of this directory.

The alert path runs through the Paperclip instance the agent account hosts. For high-value setups add an independent second channel (`BotNotifier` is a stub).

## 9. Only with a vault

Only for hosts that also run the separate vault package (a `vaultd` service with an audit log in `/var/log/vault`). Without it, skip this section: the installer
writes `"vault_audit_log": ""` into the config when `/var/log/vault` does not exist, which switches the vault checks off (no finding about a missing log).

* After the vault is installed, set `vault_audit_log` back to `/var/log/vault/audit.jsonl` in `/etc/itsec/config.json` (and `vault_uid` to the vault service user's uid, to require it for `vaultd` log lines).
* Read access to the audit log through the group `vaultaudit` (an ACL, so rotation keeps working):
  ```
  sudo setfacl -m  g:vaultaudit:rx /var/log/vault
  sudo setfacl -d -m g:vaultaudit:r /var/log/vault          # files created later (rotation) inherit it
  sudo setfacl -m  g:vaultaudit:r /var/log/vault/audit*.jsonl
  sudo -u itsec head -c 100 /var/log/vault/audit.jsonl >/dev/null && echo readable
  ```
  `audit.jsonl` is `chattr +a` (append-only), which blocks every ACL change: set the ACL before the flag, or stop `vaultd`, `chattr -a`, `setfacl`, `chattr +a`, start `vaultd`.

## 10. Optional additions

* **auditd** (`log_group = adm`): `-w <credential path> -p r -k itsec-cred` for `~/.claude/.credentials.json` and `~/.paperclip/instances/default/secrets`,
  `-w <watched path> -p wa -k itsec-persist` for the patched files and persistence paths; then add `/var/log/audit/audit.log` (`key="itsec-*"`) as a source.
  This is what closes the revert-restart-restore race and credential reads, which the 15-minute snapshots cannot see.
* **AppArmor / seccomp** profiles for the agents' bwrap sandbox; today only `apparmor="DENIED"` kernel lines are reported (MEDIUM).
* Paperclip activity polling (new agents, adapter-config approvals) and an egress diff (`ss -tn`).

## 11. Tests (any user, no root)

```
cd host/itsec && python3 -I -B -m unittest discover -s tests
```
