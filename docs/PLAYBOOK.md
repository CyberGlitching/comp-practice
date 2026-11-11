# GDDC Playbook — the first hour, then the rest of the day

This is the run-of-show for competition day. It assumes the Spring '26 network: pfSense router,
GitLab (Rocky 9), Comms/Mattermost (Rocky 9), Web (Ubuntu 24.04), File/FTP/ZeroClaw (Ubuntu 24.04),
two Windows Server 2016 DCs (DC1 = LDAP/WinRM/RDP, DC2 = IIS/CA/RDP). You are 4–6 people, randomly
assigned, with a captain who talks to the directors.

## Minute 0–5: set up, don't touch anything yet

- Open **three things** on your screen and keep them open all day: the **scoreboard**
  (`https://scoring.uacyber.org`), your **team Discord channel** (injects + the SSO password land
  here), and a notes doc (every action with a timestamp — this is your inject + Gold Team evidence).
- Captain: confirm which boxes count, grab the SSO password, and **split the team by box, not by task**
  (see delegation below). Idle teammates are lost points — that was the #1 lesson from last year.
- Everyone: log into your assigned box(es) via the Kali jumpboxes / Proxmox console. Confirm you can
  get in as `dog` before you change a single password.

## Minute 5–20: lock the doors (per box, in parallel)

Do these in order on each box. The scripts do exactly this and ask before anything risky.

**Linux (GitLab / Comms / Web / File):**
```bash
sudo -i
# get the kit onto the box (host it publicly; pull with curl/git). Example:
#   git clone https://github.com/<you>/<repo> /root/kit && cd /root/kit/linux
./hunt.sh                 # READ-ONLY: who's logged in, backdoor users, keys, cron, services, agent
./harden.sh <role>        # role = gitlab | comms | web | file  — backups, passwords, keys, sshd, firewall
./backup.sh <role>        # app data + /etc — your only rollback (no snapshots allowed)
./agent-hunt.sh           # the AI-agent adversary (see its own section below)
./watch.sh &              # leave running in tmux; alerts on re-compromise
```

**Windows (DC1 / DC2):**
```powershell
powershell -ep bypass
cd C:\kit\windows
.\Hunt.ps1                # triage + persistence + agent hunt
.\Audit-AD.ps1            # DC1: users, privileged groups, DCSync, AdminSDHolder, GPOs, ADCS (ESC1/ESC8)
.\Harden.ps1 -Role DC1    # or -Role DC2 — backups, groups, Defender, firewall, creds, logging
.\Rotate-Passwords.ps1    # random passwords for unlisted accounts
.\Watch.ps1               # leave running in its own window
```

**The password change is the single highest-value action.** Red team has the same packet with the
same default creds (`pfsense/pfsense`, `dog/bb123#123#123`, MySQL `root/bb123#123`, GitLab `Root/bb123#123`,
Mattermost `admin/bb123#123`). Change all of them in the first ten minutes. For app accounts (GitLab
root, Mattermost admin, MySQL), change the password **in the app and in whatever config the service
reads**, together, or you'll take the service down yourself.

## Minute 20–45: evict and verify

- Work the `[!]` findings from `hunt.sh` / `Hunt.ps1`. **Remove persistence before the symptom**: a
  cron job or scheduled task that re-adds a firewall-DROP or a backdoor user will keep winning until
  you kill the job. `watch.sh --FIX` / `Watch.ps1 -AutoFix` buys you time by reverting automatically
  while you find the loop.
- Keep one eye on the scoreboard. If a service you just hardened goes red, you did it — check the
  change you just made (firewall port, service account password, config file). Hardening that breaks
  a scored service is a self-inflicted outage and the single most common way teams bleed points.
- `backup.sh` again after the box is clean, so your rollback point is a *good* state.

## Minute 45+: steady state

- **Injects** (35% of score) start flowing in Discord. Rotate who writes them so defense never stops.
  See [`INJECTS.md`](INJECTS.md) for templates and the drill.
- **CTF** (20%) opens at 9:00. Park one person on it when defense is quiet; don't let it pull two
  people off boxes during an active intrusion.
- **Gold Team interview** (10%): the captain and one other prep talking points from the notes doc.
  See [`GOLD-TEAM.md`](GOLD-TEAM.md).
- Keep `watch` running everywhere. Re-run `hunt`/`Hunt` every 30–45 min — new persistence appears.

---

## Per-service notes (what's scored, what breaks it)

| Box | Scored | Keep it green by… | Classic own-goal |
|-----|--------|-------------------|------------------|
| pfSense | ICMP, DNS | Don't firewall off ICMP echo; keep Unbound running and resolving | Blocking ping on the router; breaking the resolver while "hardening" |
| GitLab (Rocky) | ICMP, SSH, GitLab | Keep `sshd` + `gitlab-runsvdir` up; change GitLab root in-app | Changing GitLab root via DB and breaking login; firewalling 80/443 |
| Comms (Rocky) | ICMP, SSH, Mattermost | Keep `mattermost` + its DB (port 8065) up | Stopping the DB while changing the admin password |
| Web (Ubuntu) | ICMP, SSH, HTTP, MySQL | Keep Apache/Nginx + MySQL (3306) reachable | Changing MySQL `root` when the app logs in as root → HTTP dies |
| File (Ubuntu) | ICMP, SSH, FTP, **ZeroClaw** | Allow FTP passive range; keep ZeroClaw `/health` answering | Firewalling FTP's passive ports; killing ZeroClaw outright (it's scored) |
| DC1 (2016) | ICMP, LDAP, WinRM, RDP | Use built-in firewall rule groups so AD still replicates | LDAP-signing lockdown that breaks the plain-LDAP check; disabling WinRM |
| DC2 (2016) | ICMP, IIS, RDP, CA | Keep W3SVC + CertSvc running | Over-locking /certsrv and killing the CA check |

Details and the exact commands are embedded as `[*]` info lines in each script.

---

## The AI-agent adversary (ZeroClaw + any planted agent)

Last year an OpenClaw/Claude-Code-style agent was used as an internal adversary. This year the packet
makes **ZeroClaw a scored service on the File Server** — so you can't just kill it. Two jobs:

**1. Neuter the scored agent (ZeroClaw) without dropping its score.** `agent-hunt.sh` keeps
`/health` answering (that's what the scoreboard checks) while it:
- revokes paired tokens and sets `require_pairing = true` (so no one on the network can drive it),
- comments out every remote chat channel (Discord/Telegram/Slack/Mattermost) in its config,
- sets autonomy to read-only / `allowed_commands = []` (takes away its shell),
- sinkholes the LLM API hosts in `/etc/hosts` (cuts its "brain" — `/health` doesn't need it),
- and auto-restores the config if `/health` stops answering.

**2. Kill every agent that isn't scored.** OpenClaw, Claude Code, Aider, Codex, Gemini CLI, Goose,
Ollama, etc. — processes, services, scheduled tasks, install dirs, API keys, and the instruction
files (`AGENTS.md`, `CLAUDE.md`, `.mcp.json`, `SKILL.md`) they use to persist. A poisoned instruction
file re-tasks an agent after you think you've cleaned it, so treat those files as persistence.

Run `agent-hunt.sh --audit` first to see everything, then without `--audit` to act with prompts.
On Windows the agent sweep is built into `Hunt.ps1` and cleanup into `Clean-Persistence.ps1`.

**Why this is in-bounds:** you're hardening and monitoring a service on a box you own, and removing
unauthorized software — standard blue-team work. You are *not* running an autonomous agent yourself.

---

## Delegation (the thing that actually wins)

Last year's takeaway: nobody idle, ever. A 5-person split that works:

- **Captain / Windows AD** — DC1 + DC2, runs the Gold Team interview, owns the notes doc.
- **Linux A** — GitLab + Comms. **Linux B** — Web + File (incl. ZeroClaw/agent-hunt).
- **Network / IR** — pfSense, watches the scoreboard, calls out red services, runs `watch` triage,
  first responder when a box gets re-popped.
- **Injects / CTF floater** — owns inject writing, dips into CTF when defense is calm, backs up whoever
  is drowning.

Rotate the floater so defense never pauses. The captain's job is to keep everyone pointed at the
highest-value thing on the board right now.
