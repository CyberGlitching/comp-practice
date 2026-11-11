# 14-Day Training Camp

Two weeks, ~1.5–2.5 hrs/day. The spine is a **daily lab rep**: snapshot a practice VM, plant the
chaos, race the clock to clean it, grade, reset, repeat — shaving minutes off each time. Everything
else (service-specific drills, injects, Gold Team) hangs off that.

You already have Proxmox and built a 7-VM VirtualBox lab before; rebuild the competition shape on
Proxmox so the muscle memory matches the real environment (same hypervisor, same consoles).

**Scoring you're training against:** uptime 35% · injects 35% · CTF 20% · Gold Team 10%. Notice that
**defense + communication is 80%**. Train like it.

---

## Week 1 — build the lab, learn each box cold

### Day 1 — Stand up the range
- Rebuild the topology on Proxmox: pfSense + 2× Rocky 9 + 2× Ubuntu 24.04 + 2× Server 2016, one flat
  `172.16.20+X.0/24` segment behind the pfSense LAN, plus a Kali box to play attacker.
- Install the scored services so your lab matches the packet: GitLab, Mattermost (+DB), Apache/Nginx
  +MySQL, vsftpd, ZeroClaw, and promote the two Windows boxes to a domain with DC2 as a CA.
- Drop the kit on each box. **Snapshot every VM clean** — label it `clean`.
- Win condition for the day: `scorebot.py` shows every service green. Fix `services.yml` IPs until it does.

### Day 2 — Linux triage + hardening, slow and correct
- On one Rocky box: `hunt.sh`, read every `[!]`, understand *why* each is flagged.
- `harden.sh gitlab` with prompts on — answer each one deliberately. Watch the scoreboard the whole
  time; if GitLab/SSH/ICMP goes red, figure out which step did it and undo precisely.
- Repeat on an Ubuntu box with `harden.sh web`. Learn the MySQL own-goal: `mysql-audit.sh`, find which
  account the web app uses, change the *right* password.
- Rep goal: clean one Linux box end-to-end without dropping a scored service.

### Day 3 — Windows + AD triage
- `Hunt.ps1` then `Audit-AD.ps1` on DC1. Learn to read: backdoor users, extra Domain Admins, AS-REP /
  kerberoast flags, DCSync rights, AdminSDHolder, GPO persistence, and the ADCS ESC1/ESC8 findings.
- `Harden.ps1 -Role DC1` with prompts. Then DC2 (`-Role DC2`) — IIS + CA. Learn which firewall rule
  groups must stay on for AD replication.
- Rep goal: know every section of the AD audit output by name.

### Day 4 — Persistence & re-compromise
- `chaos-linux.sh plant --n 8` on a Rocky box, then clean it using only the tools. The planted timer
  + cron will try to re-add a backdoor and a firewall DROP — practice **killing the loop before the
  symptom**. Use `watch.sh --FIX` and learn to find the parent process/unit.
- Windows: `Chaos-Windows.ps1 -Mode plant`, then `Clean-Persistence.ps1`. Learn WMI subscriptions,
  IFEO, Run keys, scheduled tasks, services.
- Rep goal: nothing you removed comes back after 5 minutes of `watch`.

### Day 5 — The AI-agent adversary
- On the File box, let the lab plant the rogue agent (`chaos-linux.sh plant` includes it) and ZeroClaw.
- `agent-hunt.sh --audit`, read it. Then `agent-hunt.sh`: neuter ZeroClaw while keeping `/health` green
  (watch it on scorebot), and kill the planted OpenClaw. Inspect the poisoned `AGENTS.md`.
- Windows: find the agent footprints via `Hunt.ps1`'s agent section.
- Rep goal: ZeroClaw stays green on the board the entire time you're neutralizing it.

### Day 6 — First full-network timed run
- Reset all VMs to `clean`. Have a teammate (or `chaos-*` on every box with random `--n`) plant chaos
  across the whole range. Start `scorebot` and a 90-minute timer.
- Clean the entire network: passwords, evict, harden, back up, monitor. Keep the board green.
- Grade with `chaos-* grade --hints`. Write down every point you leaked and why.

### Day 7 — Review + fix your weak box
- Re-run Day 6's weakest box solo until it's smooth. Rebuild any snapshot you dirtied.
- Read [`SCORING-STRATEGY.md`](SCORING-STRATEGY.md) and decide your team's priority order.

---

## Week 2 — speed, team coordination, communication

### Day 8 — Injects
- Work through [`INJECTS.md`](INJECTS.md): write responses to all 10 practice injects on a timer
  (15 min each). Have someone grade them on timeliness + technical depth + professionalism.
- Rep goal: a clean, named, stakeholder-addressed inject response in under 12 minutes.

### Day 9 — Gold Team interview
- Run a mock interview from [`GOLD-TEAM.md`](GOLD-TEAM.md). Record it. Practice explaining a technical
  incident to "the CEO" in business terms, and the scope-before-obligations framing you nailed last year.

### Day 10 — Team roles under fire
- Full-team timed run with your Day-7 role split. Red (a teammate on Kali, or the chaos planters on a
  cron) keeps re-popping boxes. Defense + injects run simultaneously. Captain drives priorities.
- Rep goal: nobody idle for more than a minute; injects answered while boxes are being cleaned.

### Day 11 — CTF + opportunistic points
- Practice CTFd-style challenges (crypto, web, forensics, recon on your own network). Decide who pivots
  to CTF and when. Build a flag-submission rhythm so it doesn't pull defenders at the wrong moment.

### Day 12 — Second full timed run, shorter clock
- 60-minute clean-and-hold on the full network with chaos on every box. Compare your leaked-points list
  to Day 6 — it should be shorter. Drill whatever still bleeds.

### Day 13 — Dress rehearsal
- Full 2–3 hour simulation: opening, continuous defense, injects every ~20 min, a mid-run re-compromise,
  CTF running, and a Gold Team interview at the end. As close to game day as you can make it.

### Day 14 — Rest + checklist
- Light touch only. Finalize the one-page competition-day checklist (print it). Confirm the kit is
  hosted somewhere you can pull it from fast. Sleep.

---

## Standing drills (fit them in anywhere)

- **The 10-minute lockdown:** from a cold box, how fast can you change all passwords + evict + firewall
  without dropping a scored service? Time it. Beat it.
- **Find-the-loop:** have someone plant one persistence mechanism; you find and kill it from `watch`
  alerts only, under 5 minutes.
- **Green-the-board:** someone takes a service down (stop/mask/firewall); you diagnose from the
  scoreboard + `hunt` and restore it under 3 minutes.
