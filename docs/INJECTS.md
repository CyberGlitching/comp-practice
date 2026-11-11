# Injects — 35% of your score, and the most coachable

Injects are business tasks from White Team, delivered in Discord as a note from a supervisor, a work
order, or a break/fix ticket. You get **10 over the day**. Each is graded on **timeliness** and
**quality of the deliverable**. The prompt names a requester (and title) — address them. Be concise,
professional, personable, and technical to a depth that matches the ask.

This is the most *coachable* 35% on the board: unlike a live intrusion, you can rehearse the format
until it's automatic. A team that answers 10 solid injects beats a team that answers 6 great ones.

## The response template (use it every time)

```
To:      <requester name + title from the prompt>
From:    <your name>, <role>, Team <X>
Date/Time: <when you completed it>
Re:      <inject subject / ticket #>

Summary:  <1–2 sentences: what was asked and what you did.>

Actions taken / Findings:
  - <concrete step or finding, with the specific host/user/service>
  - <...>

Result / Recommendation:
  <outcome, residual risk, and what you recommend next.>

Evidence: <command output, config snippet, or screenshot reference — trimmed to what proves it>
```

Keep it to a screen. A director skims it. Lead with the answer, then back it up.

### Why this wins points
- **Timeliness:** the template means you're never staring at a blank page. Assign an inject owner so
  defense never stops to write.
- **Quality:** named requester + concrete hosts/users + evidence + a recommendation hits every rubric
  line White Team is grading. Vague "we secured the server" answers lose the quality points.

## Practice injects (realistic for this network)

Run these on a 15-minute timer during Week 2. Have a teammate grade each on
timeliness / technical depth / professionalism, 1–5 each.

1. **Password policy (break/fix).** *"— from J. Marino, IT Director. Corporate audit flagged weak
   local passwords. Document the password policy you've enforced on the Linux servers and the domain,
   and how you verified it."* → Deliverable: the policy values you set (length, complexity, lockout),
   where (sshd/PAM, GPO/`Get-ADDefaultDomainPasswordPolicy`), and proof.

2. **Account audit.** *"Provide a list of all privileged accounts across the domain and the Linux
   servers, note any you removed, and justify the ones that remain."* → Pull from `Audit-AD.ps1` and
   `hunt.sh`; show before/after.

3. **Firewall change request.** *"The web team needs a new internal service on TCP 8443 on the Web
   server. Make the change, keep everything else locked, and document it."* → Show the exact rule and
   that scored services still pass.

4. **Incident report.** *"We saw downtime on the GitLab server at ~9:40. What happened and what did you
   do?"* → From your notes doc + `watch.log`: timeline, root cause, remediation, prevention.

5. **DNS / service verification.** *"Confirm DNS resolution is healthy on the router and list the
   records you're authoritative for."* → pfSense Unbound status + a resolution test.

6. **Backup & recovery plan.** *"Describe your backup strategy for the database servers and show you
   can restore."* → `backup.sh`/`gitlab-backup` output + a restore you actually tested in the lab.

7. **Malware / unauthorized software.** *"Security flagged suspicious software on the File server.
   Investigate and report."* → The ZeroClaw/agent findings from `agent-hunt.sh`, what you removed vs.
   hardened, and why ZeroClaw (scored) was kept but neutered.

8. **Certificate services review.** *"Review the certificate authority for misconfigurations."* → The
   ESC1/ESC8 findings from `Audit-AD.ps1`, what you fixed, residual risk.

9. **Compliance / regulatory.** *"We may have had a data exposure. What are our reporting
   obligations?"* → **Scope first, then obligations** — exactly the framing that scored well for you
   last year. Don't name a regulation before you've established what data, whose, and whether it left.

10. **Executive summary.** *"One-page summary of the day's security posture for leadership."* → No
    jargon; what was attacked, what held, current risk, top recommendation.

## Drill

- Week 2, Day 8: answer all 10 on the clock. Target under 12 minutes each, all scoring ≥4/5.
- Assign a permanent inject owner for game day, with the floater as backup. The owner never touches a
  box mid-inject; defenders feed them findings in Discord, the owner writes.
