# Scoring strategy — how 5th becomes 1st

## The math

| Category | Weight | What it rewards | How you max it |
|---|---|---|---|
| Infrastructure / Services | **35%** | Uptime, checked every ~30–60s | Never let a scored service go red; harden *to* the service, not past it |
| Injects | **35%** | 10 business deliverables, timeliness + quality | Own the format, assign an owner, answer all 10 |
| Capture the Flag | **20%** | CTFd challenges, scaled by difficulty | Floater picks low-hanging flags when defense is calm |
| Gold Team | **10%** | One exec interview | Impact-first narration from your notes doc |

**Defense + communication is 80% of the score.** CTF is the smallest lever. This changes how you
spend people: your best defenders stay on boxes; the CTF is where the *spare* capacity goes, not your
starters.

## Where last year's points actually leaked (5th of 11)

You placed 5th and took MVP, so the raw skill was there. At that rank the gap to the podium is almost
never "we couldn't hack the CTF" — it's **uptime minutes lost** and **injects left on the table**.
The three biggest leaks for a strong-but-mid team:

1. **Self-inflicted downtime.** Hardening that takes a scored service offline — firewalling a port the
   scoreboard checks, changing a DB/app password without updating the config, over-locking sshd/WinRM.
   Every one of these scripts warns before it can do this, and `scorebot` in the lab trains you to
   *see* it the instant it happens. This is the #1 recoverable loss.
2. **Injects answered slowly or thinly.** 35% of the score, and the most coachable. A dedicated owner
   using the template (see [`INJECTS.md`](INJECTS.md)) turns "we got to 6 of 10" into "all 10, solid."
3. **Re-compromise you didn't notice.** Red team re-pops a box, a service drops, and nobody sees it
   for ten minutes because everyone's heads-down. `watch` + one person owning the scoreboard fixes it.

## The priority order (when two things are on fire)

1. **A scored service is red →** fix it now. Uptime is continuous; every minute red is gone forever.
2. **Active intrusion on a box →** evict + kill persistence (it'll take a service down if you don't).
3. **An inject is due →** the owner writes it; defenders feed findings. Don't stop defense for it.
4. **Hardening not yet done →** continue the first-hour checklist.
5. **CTF →** only with genuinely spare hands.

When in doubt, ask: *is this protecting or earning the 70% (uptime + injects), or the 20% (CTF)?*

## Concrete targets to beat last year

- **Uptime:** aim for >95% green across all scored services. Translate: across a ~7-hour window, keep
  total red time per service under ~20 minutes. The lab + scorebot is exactly this drill.
- **Injects:** all 10 submitted, average ≥4/5 on quality. This alone can move you several places.
- **Gold Team:** impact-first, scope-before-obligations. You already do this well — don't regress.
- **CTF:** a steady trickle of the easy/medium flags from the floater. Don't chase one hard flag for
  an hour with a defender.

## The one-sentence strategy

Keep every scored service green, answer all ten injects well, neutralize (don't blindly delete) the
things you're scored on — and let the 20% CTF be where your *spare* time goes, never your defenders.
