# Rules & safety — read before using any of this

## What the packet allows (Spring '26, Competition Conduct)

- **Scripting / automation is allowed**, as long as every tool is either written on the spot or
  **freely/publicly available**. Hosting it in a repo of yours is fine — it only has to be publicly
  reachable; there's no requirement to hand anyone a master list. This whole kit is plain
  Bash/PowerShell/Python you run yourself.
- **Paid AI "agents such as Claude" are allowed** — but see the autonomy ban below.
- **No attacking.** This is blue-team only. Some injects may have you run offensive *tools* (e.g.
  Nmap) **on your own network only**. Anything that looks like recon/attack against another team, the
  university, or outside hosts = immediate DQ. Nothing in this kit touches another team or scans
  outside your box; keep it that way.
- **No autonomous AI agents during play** — explicitly Claude Code, OpenClaw, OpenCode, Aider, and the
  like. **These scripts are not agents:** they don't call an LLM, make no outbound AI requests, and do
  only what you tell them, step by step, with prompts. That's the distinction that keeps them legal.
  Don't wire any of them up to an agent runtime during the competition.
- **No snapshots/reverts of competition VMs**, no touching other teams' infrastructure, no changing
  the IP/VLAN scheme unless an inject tells you to. The kit never does any of these; it hardens in
  place and backs up to files (your only allowed rollback).
- **No outside assistance** from non-team members during play. Building and reading this kit *before*
  the competition is fine; during play, only your team touches it.

Re-read the actual packet you're given — rules change year to year. If anything here conflicts with
your packet or a White Team ruling, the packet/ruling wins. Update the scored users/services/IPs in
`linux/common.sh`, `windows/common.ps1`, and `services.yml` to match.

## Lab safety (the chaos planters)

The practice planters (`lab/chaos-linux.sh`, `lab/Chaos-Windows.ps1`) exist to make a VM *look*
compromised so you can practice the cleanup. They are deliberately **inert**:

- **No reverse shells or C2.** The "suspicious service" runs a harmless sleep/ping loop wearing a
  fake kernel-thread name — it connects nowhere.
- **No real ransomware.** Files are backed up first, then **reversibly renamed** to `*.dog` (contents
  untouched — no encryption). A `restore` mode and your snapshot both bring them back.
- **No working webshell / auth bypass / SUID shell.** Those decoys are marker files that match a
  scanner's *signature* but execute nothing (e.g. a SUID copy of `/bin/true`, a webshell file that's
  all comment, an IFEO debugger pointed at a harmless marker rather than a replaced `sethc.exe`).
- **They refuse to run** without a `dog-lab` marker file you create by hand, and they demand an
  explicit `--i-know-this-is-a-lab` / `-IKnowThisIsALab` flag.

Still: **only run them on throwaway lab VMs you own, snapshotted first.** Never on the competition
network, never on anything you care about. They need root/admin and they change system state; that's
the point, and it's why they're gated.

## The real tools (hunt/harden/watch/agent-hunt)

These make real changes to a real box (passwords, firewall, services, accounts). On competition day
that's exactly what you want, but:

- Run `hunt`/`Hunt` (read-only) **first** and read it before you change anything.
- Keep prompts **on** (don't set `AUTO_YES`/`-IKnowThisIsALab`... wait, that's the lab) — don't set
  `AUTO_YES=1` until you've drilled a script enough to trust it blind.
- Watch the scoreboard after every hardening step. If a scored service drops, undo the last change.
- Everything is logged to `/root/.blue/actions.log` (Linux) and `C:\ProgramData\blue\actions.log`
  (Windows) — that log is also your inject/Gold-Team evidence.
