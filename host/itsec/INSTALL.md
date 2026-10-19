# Installing the watchdog (root steps for the admin account)

Everything below is executed by the admin account with sudo, from a root-owned staged copy of this package (see the top-level README, install step 1).
Code goes to `/opt/itsec` (root-owned, so the `itsec` user cannot rewrite its own detector).

## 1. Packages
```
sudo apt-get update && sudo apt-get install -y fail2ban lynis acl
```
Check the journal is persistent (otherwise a reboot loses the evidence): `ls /var/log/journal` must exist;
if not, `sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal && sudo systemctl restart systemd-journald`.

## 2. User and groups (no sudo, no login shell)
```
sudo groupadd --system vaultaudit
sudo useradd --system --home-dir /var/lib/itsec --no-create-home --shell /usr/sbin/nologin itsec
sudo usermod -aG adm,systemd-journal,vaultaudit itsec
id itsec        # expect adm, systemd-journal, vaultaudit; NOT sudo
```

## 3. Read access to the vault audit log (group `vaultaudit`, via ACL so rotation keeps working)
```
sudo setfacl -m  g:vaultaudit:rx /var/log/vault
sudo setfacl -d -m g:vaultaudit:r /var/log/vault          # files created later (rotation) inherit it
sudo setfacl -m  g:vaultaudit:r /var/log/vault/audit*.jsonl
# NOTE: audit.jsonl is chattr +a (append-only), which blocks every ACL change. Set the ACL BEFORE the flag
# (vault/INSTALL.md step 2 does), or: stop vaultd, chattr -a, setfacl, chattr +a, start vaultd.
sudo -u itsec head -c 100 /var/log/vault/audit.jsonl >/dev/null && echo readable
```
(`/var/log/vault` is created by the vaultd install; do this step after it.)

## 4. Read access to the watched files that live in `paperclip`'s home
`/home/paperclip` is 0750. Grant traversal only, then read on exactly the watched paths (do NOT grant the whole home).
Every `setfacl` below is guarded so a missing path cannot abort the chain:
```
H=/home/paperclip
sudo setfacl -P -m u:itsec:x $H $H/.config $H/.paperclip $H/.paperclip/instances $H/.paperclip/instances/default $H/.paperclip/cli \
     $H/.paperclip/cli/installs $H/.paperclip/cli/installs/npm     # installs/ and installs/npm are 0700 too; instances/ and instances/default need x as well
# paperclip controls these paths: -P (never follow symlinks), refuse symlink arguments, keep the resolved path under /home/paperclip.
# Every test runs through sudo (admin cannot traverse the 0750 home, so a plain [ -e ] would report everything absent).
okp() { local r; r=$(sudo readlink -f "$1"); case "$r" in /home/paperclip/*) return 0;; esac; echo "STOP outside home: $1 -> $r"; return 1; }
acl()  { for p in "$@"; do if sudo test -L "$p"; then echo "STOP symlink: $p"; elif sudo test -e "$p"; then okp "$p" && sudo setfacl -P -R -m u:itsec:rX "$p"; else echo "skip (absent): $p"; fi; done; }
aclf() { for p in "$@"; do if sudo test -L "$p"; then echo "STOP symlink: $p"; elif sudo test -e "$p"; then okp "$p" && sudo setfacl -P -m u:itsec:r "$p"; fi; done; }
acl $H/.config/systemd/user $H/.ssh $H/.local/bin $H/.config/environment.d
sudo setfacl -P -m u:itsec:rx $H/.claude
acl $H/.claude/skills $H/.claude/plugins $H/.claude/agents $H/.claude/commands $H/.claude/hooks
aclf $H/.claude/settings.json $H/.claude/settings.local.json $H/.claude/CLAUDE.md
aclf $H/.bashrc $H/.profile $H/.bash_logout
# the agents' per-agent config (real layout: ~/.paperclip/instances/default/companies/<id>/agents/<id>/.claude/): only if the dirs exist
acl $H/.paperclip/instances/default/companies
# Paperclip tree (resolve the symlink, pin the prefix): the three patched files are hashed against the manifest (step 5b)
TREE=$(sudo readlink -f $H/.paperclip/cli/current)
case "$TREE" in /home/paperclip/.paperclip/cli/installs/npm/*) sudo setfacl -P -R -m u:itsec:rX "$TREE";; *) echo "STOP: tree is $TREE";; esac
```
**Re-run the `TREE` lines after every Paperclip update** (a new version directory has no ACL), then regenerate the manifest (step 5b).
The patch scripts under `$PKG/host/patches` need NO ACL: itsec never executes or reads them.
Do NOT grant access to `.paperclip` secrets, `.claude/.credentials.json` or keys. Files the user cannot read
(`/etc/sudoers`, crontabs, `/root/.ssh`) are still watched through their stat signature (mode, owner, size, mtime, ctime).
For content hashes of sudoers: `sudo setfacl -m u:itsec:rx /etc/sudoers.d; sudo sh -c 'setfacl -m u:itsec:r /etc/sudoers /etc/sudoers.d/*'` (`/etc/sudoers.d` is 0750 root, so itsec needs `x` on it and the glob must expand as root; re-apply when a file is added).
A watched path itsec cannot even reach (EACCES on a parent) is reported as MEDIUM `watch-unreadable` instead of vanishing;
`sudo -u itsec /opt/itsec/bin/itsec-collect --dry-run` lists them.

## 5. Install the code and config
```
sudo install -d -m 0755 -o root -g root /opt/itsec /etc/itsec
sudo cp -r $PKG/host/itsec/bin $PKG/host/itsec/itsec /opt/itsec/
sudo chown -R root:root /opt/itsec && sudo chmod -R go-w /opt/itsec
sudo install -m 0644 $PKG/host/itsec/config.example.json /etc/itsec/config.json
sudoedit /etc/itsec/config.json        # paperclip.company_id, paperclip.assignee_user_id, paperclip.hmac_key_file (keep the default),
                                       # vault_uid once vaultd's user exists, claude.command, watch list
```
Secrets (root-only; systemd hands them to the units with `LoadCredential`, so `itsec` never reads `/etc/itsec`):
```
sudo install -m 0600 -o root -g root /dev/null /etc/itsec/paperclip-token   # then write the BOARD-scoped token into it, without echo:
#   sudo -v; systemd-ask-password -n "board token:" | sudo sh -c 'umask 077; cat > /etc/itsec/paperclip-token'
sudo install -m 0600 -o root -g root /dev/null /etc/itsec/claude-token      # output of `claude setup-token` run by the owner
sudo sh -c 'umask 077; head -c 48 /dev/urandom | base64 -w0 > /etc/itsec/idempotency-secret'   # HMAC secret for the issue keys
sudo chown root:root /etc/itsec/idempotency-secret
```
The idempotency secret is what stops an agent from guessing an alert's key and pre-empting it. Only the itsec units get it
(`LoadCredential=`); it is never in `config.json`, never printed, and agents cannot read `/etc/itsec`.
Later these can move to the vault / `systemd-creds encrypt` (swap `LoadCredential=` for `LoadCredentialEncrypted=`; the
config paths use `${CREDENTIALS_DIRECTORY}` so nothing else changes). The token must be able to create issues in the
company and nothing more. Never put either token in `config.json`.

The `claude` binary must be root-owned and outside `/home/paperclip`: do NOT copy it from `~/.local/share/claude/versions/`
(paperclip-writable, could be trojaned). As admin, install it from the official source with checksum verification into
`/usr/local/bin/claude` (root:root 0755). The report unit sets `DISABLE_AUTOUPDATER=1`. If absent, the daily report is still
produced without the narrative.
Also: `/usr/local/bin/node` and `/usr/local/lib/node_modules/{npm,corepack,pnpm}` (and the parents `/usr/local/lib` and `/usr/local/lib/node_modules`) must be owned by root (a non-root owner, e.g. an orphaned uid, lets that user replace what the watchdog trusts); if not, fix with
`sudo chown -R root:root` on the three packages and `sudo chown root:root /usr/local/lib /usr/local/lib/node_modules` (itsec watches `/usr/local/bin`).

## 5b. Patch manifest (ADMIN step, repeat after every deliberate Paperclip update)
itsec never runs `apply.sh` or anything under `/home`. It hashes the patched Paperclip files and looks for the `LOCAL-PATCH`
markers, comparing against a root-owned manifest that the admin writes after a verified patch run:
```
sudo -u <agent user> $PKG/host/patches/apply.sh --check   # run as the AGENT USER (it owns the install), never as admin and never by itsec; exit 0 = all applied
# run the generator as itsec (it needs no root), then install the result root-owned:
T=$(sudo mktemp -d /run/itsec-mf.XXXXXX); sudo chown itsec:itsec "$T"
sudo -u itsec /opt/itsec/bin/itsec-make-manifest --tree /home/paperclip/.paperclip/cli/current --out "$T/m.json"
sudo install -m 0644 -o root -g root "$T/m.json" /etc/itsec/patch-manifest.json; sudo rm -rf "$T"    # /etc/itsec/patch-manifest.json (0644 root)
sudo cat /etc/itsec/patch-manifest.json                          # one entry per patched file (8 on 2026.1005.0, 9 on 2026.1012.0 where 0005e applies): sha256 and the markers each
```
The generator reads the files only and refuses to record a file that lacks its marker. A missing/unreadable manifest or file is a
MEDIUM `watch-degraded` finding (never a false HIGH); a hash mismatch, a lost marker, or a manifest that is not root-owned or is
group/world-writable is HIGH. A Paperclip update therefore raises HIGH until step 5b is repeated: that is intended.

## 6. fail2ban (config only)
```
sudo cp $PKG/host/itsec/fail2ban/jail.local /etc/fail2ban/jail.local
sudo cp $PKG/host/itsec/fail2ban/fail2ban.local /etc/fail2ban/fail2ban.local   # log to the journal, else "[sshd] Ban" never reaches itsec
sudo journalctl -u ssh.service -n 3       # confirm the unit name is ssh.service (else edit journalmatch); needs sudo
sudo fail2ban-regex "systemd-journal[journalmatch='_SYSTEMD_UNIT=ssh.service']" sshd     # must show matched lines
```
If it shows 0 matches (older filter without sshd-session support), install
`$PKG/host/itsec/fail2ban/sshd.local.optional` as `/etc/fail2ban/filter.d/sshd.local` and repeat.
```
sudo systemctl enable --now fail2ban && sudo fail2ban-client status sshd
```
Review `ignoreip` first so the owner's own address cannot be banned.

## 7. Baseline first, then enable the timers
```
sudo cp $PKG/host/itsec/systemd/itsec-collect.* $PKG/host/itsec/systemd/itsec-report.* $PKG/host/itsec/systemd/itsec-lynis.* /etc/systemd/system/
# optional, sudo cp .../systemd/itsec-lynis-root.service /etc/systemd/system/ and set "lynis_consume_root_report": true in config.json
sudo systemd-analyze verify /etc/systemd/system/itsec-*.service /etc/systemd/system/itsec-*.timer
sudo ls -ld /var/lib/itsec     # after the first start: drwx------ itsec (StateDirectoryMode=0700)
sudo systemctl daemon-reload
sudo systemctl start itsec-collect.service         # first run = baseline mode: learns IPs, hashes, ports, users; raises nothing
journalctl -u itsec-collect.service -n 20
sudo systemctl enable --now itsec-collect.timer itsec-report.timer itsec-lynis.timer
```
Do the first run when the system is in a known-good state. Every SSH source IP seen in the last 3 days of the
journal becomes "known"; later logins from other IPs are HIGH. (Only entries from the real sshd unit with uid 0 are used;
a forged `logger -t sshd` line cannot poison the baseline.)
Host check before relying on the sudo rules, as admin: `sudo -l -U paperclip` must say that paperclip may not run sudo. Any
successful sudo by paperclip afterwards raises HIGH `sudo-success`; `su` use raises HIGH `su-attempt`. Content changes in
`/etc/sudoers` and `/etc/sudoers.d` are HIGH through the watch list (tested).

## 8. Operations
- Planned Paperclip restarts: put the maintenance window into config `known_restart_windows`
  (`[["2026-10-14T20:00:00Z","2026-10-14T21:00:00Z"]]`); a restart outside any window is MEDIUM `paperclip-restart`
  (journal start/stop message plus a changed process start time). After a Paperclip update: ACL (step 4), `apply.sh`, step 5b.
- Re-baseline after a deliberate change (new service port, Paperclip update + `apply.sh`, new user):
  `sudo -u itsec env ITSEC_CONFIG=/etc/itsec/config.json /opt/itsec/bin/itsec-collect --rebaseline` (one quiet run).
- Test delivery without waiting: `sudo systemctl start itsec-report.service` (creates a real issue).
- Look at findings: `/var/lib/itsec/findings/YYYY-MM-DD.jsonl`; undelivered HIGH alerts: `state.json` key `outbox`.
- Update the code: repeat the `cp -r` in step 5.
- Uninstall: disable the three timers, remove units, `userdel itsec`, `groupdel vaultaudit`, remove `/opt/itsec /etc/itsec /var/lib/itsec`.

## 9. Where the alert issues live (recommended: a separate alerts company)
By default the code posts alerts into a Paperclip company that agents can read, and `paperclip` owns Paperclip itself. The code
already has the hardening that needs no decision: an HMAC idempotency key (secret in a credential file only itsec reads),
a check that the returned issue is ours, and a per-run re-check that alert issues of the last N days still exist, are open
and unedited (otherwise HIGH `alert-tampered` plus a re-raised alert under a new key).
**Recommended option (not set up, NOT assumed to exist):** create a Paperclip company "ITSec" with NO agents, a dedicated
low-privilege user that is a member of that company only, and a board key for that user with an `expiresAt` (rotate yearly).
Then set in `/etc/itsec/config.json`: `paperclip.alert_company_id` (the ITSec company), `paperclip.alert_token_file`
(path of that user's token credential, add a `LoadCredential=` line for it), `paperclip.assignee_user_id` and
`paperclip.board_user_id` (the board owner, whose closes are not treated as tampering). Until configured, the existing
`company_id` / `token_file` pair is used. Assumption to verify against the live API before relying on it: issue JSON carries
`updatedByUserId` / `updatedByAgentId`; without them every close by anyone counts as tampering (safe, but noisy).
The second, non-paperclip-hosted channel is still the `BotNotifier` stub (README).

## 10. Optional additions (not part of the first install)
- **auditd** (`log_group = adm`): `-w <cred path> -p r -k itsec-cred` for `~/.claude/.credentials.json` and
  `~/.paperclip/instances/default/secrets`, `-w <watched path> -p wa -k itsec-persist` for the patched files and persistence paths;
  then add `/var/log/audit/audit.log` (`key="itsec-*"`) as a source. This is what closes the revert-restart-restore race and
  credential reads, which the 15-minute snapshots cannot see.
- **AppArmor / seccomp** profiles for the agents' bwrap sandbox; today only `apparmor="DENIED"` kernel lines are reported (MEDIUM).
- Paperclip activity polling (`agent_api_key.created`, new agents, adapter-config approvals) and an egress diff (`ss -tn`).

## 11. Tests (any user, no root)
```
cd $PKG/host/itsec && python3 -I -m unittest discover -s tests
```
