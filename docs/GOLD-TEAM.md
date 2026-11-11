# Gold Team interview — 10%, and a tiebreaker

The Gold Team is industry professionals playing DOG's C-suite. One interview, during the day, about
recent downtime and attacks. They're grading **professionalism, knowledge, and communication with
upper management** — can you explain a technical incident in business terms and make decisions under
pressure. Ten percent is small, but it's pure communication, it's easy to prep, and it breaks ties.

You did well here last year with scope-before-obligations. Lean into that.

## What they're actually testing

- Can you translate "we found a cron job re-adding an iptables DROP on ICMP" into "an attacker had
  planted a mechanism that was knocking our router offline every minute; we removed it and the service
  recovered" — **impact first, mechanism second**.
- Do you know your own environment (what's up, what was hit, what you did).
- Do you stay calm, honest about what you don't know yet, and decisive about next steps.

## Prep (assign the captain + one other)

Keep the **notes doc** current all day — it's the raw material. For each significant event: time,
what happened (business impact), what you did, current status. The interview is just you narrating
that doc in exec language.

## The framing that works

- **Impact → cause → action → risk.** "Our developer portal was unreachable for about six minutes
  around 9:40 (impact). An attacker had changed a firewall rule (cause). We removed it and restored
  access, and added monitoring so it can't recur silently (action). Residual risk is low; we're
  watching for repeat attempts (risk)."
- **Scope before obligations** (the regulatory question): don't name a law or a reporting deadline
  before you've established *what* data, *whose*, and whether it actually left the environment. "First
  we'd determine what was accessed and whether any of it is regulated or left our network; that scopes
  which obligations apply. Reporting prematurely or to the wrong body is its own risk." This read as
  mature last year — keep it.
- **Honest about unknowns.** "We don't yet have confirmation that data was exfiltrated; here's how
  we're checking." Beats bluffing.
- **Decision under pressure:** when they push ("would you take the server offline?"), weigh it out
  loud — uptime is scored/business-critical vs. containment — and commit to a defensible call.

## Likely questions

1. Walk us through the most serious incident today.
2. Are our systems safe right now? How do you know?
3. We heard a server went down — what did that cost us and why did it happen?
4. If you had more time/budget, what's the first thing you'd fix?
5. (Curveball) We think a competitor may have our data — what do we do?  → scope first.
6. How is your team coordinating?  → your role split and how you prioritize the board.

## Do / don't

- **Do** use the requesters' and systems' real names, give numbers (minutes of downtime, accounts
  removed), and end with a recommendation.
- **Don't** drown them in jargon, blame teammates, guess at facts, or claim everything is "100%
  secure." Confident + honest + specific wins.

## Drill

Week 2, Day 9: full mock interview, recorded, with someone playing a slightly impatient CEO. Review
the recording for filler words, jargon, and whether you led with impact. Run it twice.
