# GDDC Blue Team Kit

A two-week training camp and competition toolkit for the **Great Dane Defense Competition**
(Red vs. Blue, UAlbany Cyber Defense Organization). Built from the Spring '26 Blue Team packet:
a 7-system network on Proxmox — pfSense, two Rocky 9 boxes, two Ubuntu 24.04 boxes, two Server 2016
DCs — scored on service uptime (35%), injects (35%), CTF (20%), and a Gold Team interview (10%).

Everything here is **defensive**: triage, hardening, monitoring, and a safe practice lab that
plants *inert decoys* of last year's mess so you can rehearse the cleanup against a clock.

> **Rules check (from the packet).** Scripting is allowed as long as every tool is coded on the
> spot or publicly available; AI *agents* (Claude Code, OpenClaw, Aider, etc.) are banned during
> play, and paid AI "agents such as Claude" are allowed only in non-autonomous use. These scripts
> are plain Bash/PowerShell/Python you run yourself — no agent, no network calls to an LLM — so they
> sit on the right side of that line. Host them wherever you like (a repo of yours is fine; it only
> has to be publicly reachable). Read [`docs/RULES.md`](docs/RULES.md) before you lean on any of it.

## What's in the box

```
linux/      Bash: triage, harden, monitor, backup, app + agent audits (Rocky 9 / Ubuntu 24.04)
windows/    PowerShell: triage, harden, AD + ADCS audit, persistence cleanup, monitor (Server 2016)
pfsense/    Read-only audit for the firewall (DNS + ICMP are scored on it)
lab/        Practice harness: chaos planters (INERT), a grader, and scorebot (a DSSS-style scoreboard)
docs/       The training camp: 14-day plan, playbooks, inject drills, Gold Team prep, scoring math
```

## Fast start (practice lab)

On your Proxmox lab, not the real competition network:

```bash
# 1. On a throwaway practice VM (Rocky or Ubuntu):
sudo touch /etc/dog-lab                      # opt-in marker
# 2. Snapshot the VM in Proxmox (your lab = snapshots allowed).
# 3. Plant last year's mess (inert decoys + real misconfigs):
sudo ./lab/chaos-linux.sh plant --i-know-this-is-a-lab --service sshd --n 12
# 4. In another terminal on your workstation, watch the board:
python3 lab/scorebot.py --config services.yml --interval 30   # edit services.yml for your IPs
# 5. Clean the box with the real tools, racing the clock:
sudo ./linux/hunt.sh                         # see what's wrong
sudo ./linux/harden.sh web                   # fix it (role: gitlab|comms|web|file|generic)
sudo ./linux/agent-hunt.sh                   # neutralise the AI-agent adversary
sudo ./linux/watch.sh                        # leave running; alerts on re-compromise
# 6. Grade yourself, then reset the snapshot and go again, faster:
sudo ./lab/chaos-linux.sh grade --hints
```

Windows is the same shape: `New-Item C:\dog-lab -ItemType File`, snapshot, then
`lab\Chaos-Windows.ps1 -Mode plant -IKnowThisIsALab`, clean with `windows\Hunt.ps1` /
`windows\Harden.ps1 -Role DC1`, grade with `-Mode grade`.

## Competition day (real network — the first 60 minutes)

Order matters. Full detail in [`docs/PLAYBOOK.md`](docs/PLAYBOOK.md).

1. **Don't harden blind.** Open the scoreboard first. You're racing to keep green, not to lock down.
2. **Change the packet passwords** on every box you own (`dog`, `root`, `admin`, DB root, GitLab root,
   Mattermost admin, pfSense admin). Red team has the same packet.
3. **Kick out who's already in** — `hunt.sh` / `Hunt.ps1` show sessions, backdoor users, keys, cron,
   services, and the AI agent. Remove persistence *before* the symptom or it comes back.
4. **Harden to the scored services, not past them.** Each script only opens the ports the packet
   scores and warns before it could take a service down.
5. **Back up** (`backup.sh` / the backup step) — no VM snapshots are allowed, so this is your rollback.
6. **Leave the monitor running** (`watch.sh` / `Watch.ps1`) and work the injects.

## The golden rule of this competition

**Uptime + injects are 70% of the score; the CTF is 20%.** A locked-down box that fails its scoring
check is worth less than a slightly-messy box that stays green. Every script here is built around
that: it tells you which listener is a scored service before you firewall it off, and it keeps the
ZeroClaw and DNS checks answering while it strips the attacker's access. Read
[`docs/SCORING-STRATEGY.md`](docs/SCORING-STRATEGY.md) for the point math and where last year's 5th
place actually leaked points.

## Update the lists for the new packet

If you get a Spring-27 packet, the scored users, services, and IPs may change. Update:
- `linux/common.sh` → `SCORED_USERS`, `ROLE_PORTS`, `ROLE_SERVICES`
- `windows/common.ps1` → `$ScoredUsers`, `$KeepUsers`, `$PrivAllow`
- `lab/scorebot.py` → `services.yml` (IPs + checks)

Send me the new packet and I'll retune all of it.

## Safety

The lab planters install **inert decoys** — no reverse shells, no real ransomware (files are backed
up then reversibly renamed), no working webshells or auth bypasses. They refuse to run without a
`dog-lab` marker file, and each has a `restore` mode. Run them only on throwaway lab VMs you own.
See [`docs/RULES.md`](docs/RULES.md).
