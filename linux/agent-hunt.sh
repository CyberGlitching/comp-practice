#!/usr/bin/env bash
# agent-hunt.sh - find and neutralise AI agents (ZeroClaw, OpenClaw, Claude Code, Aider, Codex, ...)
# used as an "internal adversary". Run on EVERY Linux box, not just the File Server.
#
# Usage: sudo ./agent-hunt.sh            audit, then asks before each action
#        sudo ./agent-hunt.sh --audit    audit only
#
# Strategy:
#   * ZeroClaw is a SCORED service on the File Server. Don't delete it - neuter it:
#     keep the gateway answering /health, but take away its hands (shell/tools), its ears
#     (chat channels + paired tokens) and its brain (LLM API egress).
#   * Any other agent is not scored: kill it, disable its persistence, quarantine its files.
#   * An agent's prompt/skill/memory files ARE persistence. A poisoned AGENTS.md or skill
#     re-tasks the agent after you "fixed" everything else.

DIR="$(cd "$(dirname "$0")" && pwd)"; source "$DIR/common.sh"
need_root
AUDIT_ONLY=0; [[ "${1:-}" == "--audit" ]] && AUDIT_ONLY=1
OUT="$BLUE_DIR/agent-hunt-$TS.txt"
Q="$BLUE_DIR/quarantine/agents-$TS"
act() { [[ $AUDIT_ONLY == 1 ]] && return 1; ask "$1"; }

# name regex for processes/units/cron
AGENT_RE='zeroclaw|openclaw|clawdbot|moltbot|nanobot|picoclaw|claude|aider|opencode|codex|gemini-cli|@google/gemini|goose|crush|cursor-agent|open-interpreter|autogpt|agent-zero|ollama|llama-server|vllm|n8n'
AGENT_DIRS=".zeroclaw .openclaw .clawdbot .moltbot .nanobot .picoclaw .claude .claude.json .aider .aider.conf.yml .config/opencode .local/share/opencode .codex .gemini .config/goose .cursor .continue .ollama .open-interpreter"
LLM_HOSTS="api.anthropic.com api.openai.com openrouter.ai api.openrouter.ai generativelanguage.googleapis.com api.groq.com api.mistral.ai api.deepseek.com api.x.ai api.together.xyz api.fireworks.ai api.cohere.ai api.cohere.com api.perplexity.ai api.moonshot.ai api.venice.ai"
CHAT_HOSTS="discord.com gateway.discord.gg api.telegram.org slack.com wss-primary.slack.com api.slack.com"

{
hdr "1. AGENT PROCESSES"
ps -eo pid,user,etimes,cmd --no-headers | grep -Ei "$AGENT_RE" | grep -vE "grep|agent-hunt" | while read -r pid user et cmd; do
  warn "pid=$pid user=$user up=${et}s  $cmd"
  [[ "$user" == root ]] && warn "   ^ running as ROOT: every tool call it makes is root"
done

hdr "2. LISTENERS ON KNOWN AGENT PORTS (zeroclaw 42617/8585/3000, openclaw 18789, ollama 11434)"
ss -tlnpH 2>/dev/null | grep -E ':(42617|8585|3000|18789|18790|11434|8080) |zeroclaw|openclaw|node|ollama' | while read -r l; do warn "$l"; done

hdr "3. INSTALL FOOTPRINTS"
for h in /root /home/* /opt /srv /var/lib/*; do
  for d in $AGENT_DIRS; do [[ -e "$h/$d" ]] && warn "$h/$d  ($(du -sh "$h/$d" 2>/dev/null | cut -f1))"; done
done
for d in /etc/zeroclaw /opt/zeroclaw /opt/openclaw /usr/lib/node_modules/@anthropic-ai /usr/lib/node_modules/openclaw /usr/lib/node_modules/@openai/codex /usr/lib/node_modules/@google/gemini-cli /usr/lib/node_modules/opencode-ai /usr/local/lib/node_modules; do
  [[ -e "$d" ]] && ls -d "$d"/* 2>/dev/null | grep -Ei "$AGENT_RE|anthropic" | while read -r x; do warn "$x"; done
  [[ -e "$d" && "$d" != /usr/local/lib/node_modules ]] && warn "$d"
done
for b in zeroclaw openclaw claude aider opencode codex gemini goose crush ollama interpreter; do
  p=$(command -v "$b" 2>/dev/null) && warn "binary in PATH: $p"
  for h in /root /home/*; do [[ -x "$h/.local/bin/$b" ]] && warn "$h/.local/bin/$b"; [[ -x "$h/.npm-global/bin/$b" ]] && warn "$h/.npm-global/bin/$b"; done
done
pip list 2>/dev/null | grep -Ei 'aider|open-interpreter|crewai|autogen|langchain|smolagents' | while read -r l; do warn "pip: $l"; done

hdr "4. PERSISTENCE THAT LAUNCHES AGENTS (units / cron / shell init)"
grep -rlEi "$AGENT_RE" /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /root/.config/systemd /home/*/.config/systemd 2>/dev/null | while read -r f; do warn "unit: $f -> $(grep -hE '^(ExecStart|User)=' "$f" | tr '\n' ' ')"; done
grep -HnEi "$AGENT_RE" /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null | while read -r l; do warn "cron: $l"; done
grep -HnEi "$AGENT_RE" /etc/profile /etc/profile.d/* /etc/bash.bashrc /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null | while read -r l; do warn "shell init: $l"; done
for h in /root /home/*; do
  s="$h/.claude/settings.json"; [[ -f $s ]] && grep -q '"hooks"' "$s" && warn "Claude Code HOOKS in $s (runs commands on agent events):" && grep -A3 '"command"' "$s" | head -12
done

hdr "5. API KEYS / TOKENS ON DISK (the agent's fuel)"
grep -rIlE 'sk-ant-[A-Za-z0-9_-]{10,}|sk-proj-[A-Za-z0-9_-]{10,}|sk-or-v1-[a-f0-9]{10,}|AIza[0-9A-Za-z_-]{30,}|gsk_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,}|(ANTHROPIC|OPENAI|OPENROUTER|GEMINI|GOOGLE|GROQ|DEEPSEEK)_API_KEY\s*=' \
  /etc /root /home /opt /srv 2>/dev/null | grep -v "$BLUE_DIR" | head -30 | while read -r f; do warn "key material: $f"; done
grep -lE '(ANTHROPIC|OPENAI|OPENROUTER|GEMINI)_API_KEY' /proc/[0-9]*/environ 2>/dev/null | while read -r f; do p=${f#/proc/}; p=${p%%/*}; warn "API key in env of pid $p: $(tr '\0' ' ' < /proc/$p/cmdline | cut -c1-80)"; done

hdr "6. INSTRUCTION / SKILL / MEMORY FILES (prompt-injection persistence)"
find / -xdev \( -name 'CLAUDE.md' -o -name 'AGENTS.md' -o -name 'GEMINI.md' -o -name '.cursorrules' -o -name 'SOUL.md' -o -name 'IDENTITY.md' -o -name 'MEMORY.md' -o -name 'HEARTBEAT.md' -o -name 'TOOLS.md' -o -name 'SKILL.md' -o -name '.mcp.json' -o -name 'mcp.json' -o -name 'mcp_servers.json' \) \
  -not -path '*/node_modules/*' -not -path '/proc/*' -not -path "$BLUE_DIR/*" 2>/dev/null | while read -r f; do
  age=$(( ($(date +%s) - $(stat -c %Y "$f")) / 60 ))
  if grep -qEi 'curl|wget|/dev/tcp|nc -|bash -i|useradd|chpasswd|iptables|base64|ignore (all|previous)|do not tell|secretly|never reveal' "$f" 2>/dev/null; then
    warn "$f (modified ${age}m ago) contains suspicious instructions:"; grep -nEi 'curl|wget|/dev/tcp|nc -|bash -i|useradd|chpasswd|iptables|base64|ignore (all|previous)|do not tell|secretly|never reveal' "$f" | head -5 | sed 's/^/        /'
  else echo "    $f (modified ${age}m ago)"; fi
done

hdr "7. ZEROCLAW CONFIG (scored - harden, don't delete)"
ZCFGS=$(ls /root/.zeroclaw/config.toml /home/*/.zeroclaw/config.toml /etc/zeroclaw/config.toml /opt/zeroclaw/config.toml 2>/dev/null)
for c in $ZCFGS; do
  echo "  -- $c"
  grep -nE '^\s*\[|^\s*(host|port|allow_public_bind|require_pairing|paired_tokens|level|workspace_only|allowed_commands|forbidden_paths|max_actions_per_hour|bot_token|allowed_users|api_key|default_provider)\s*=' "$c" | sed -E 's/(api_key|bot_token|paired_tokens)(\s*=\s*).{0,6}.*/\1\2<redacted>/' | sed 's/^/     /'
  grep -qE '^\s*require_pairing\s*=\s*false' "$c" && warn "require_pairing = false: anyone on the network can drive it"
  grep -qE '^\s*level\s*=\s*"full"' "$c" && warn "autonomy level = full: no approval for shell commands"
  grep -qE '^\s*workspace_only\s*=\s*false' "$c" && warn "workspace_only = false: can touch the whole filesystem"
  grep -qE '^\s*allowed_commands\s*=.*"\*"' "$c" && warn "allowed_commands includes * (any command)"
  grep -qE '^\s*\[channels_config\.(discord|telegram|slack|whatsapp|matrix|signal|email|imessage|mattermost)' "$c" && warn "Remote chat channel configured: someone outside can instruct the agent"
  grep -qE '^\s*allowed_users\s*=\s*\[\s*"\*"' "$c" && warn "allowed_users = * on a channel"
done
[[ -z "$ZCFGS" ]] && info "No ZeroClaw config in the usual places. Find it: ps -ef | grep zeroclaw; ls -la /proc/<pid>/cwd; cat /proc/<pid>/environ | tr '\\0' '\\n' | grep ZEROCLAW"
} 2>&1 | tee "$OUT"

[[ $AUDIT_ONLY == 1 ]] && { ok "Audit saved: $OUT"; exit 0; }

# =================================================================== ACTIONS
hdr "ACTIONS: non-scored agents"
mkdir -p "$Q"
ps -eo pid,cmd --no-headers | grep -Ei "openclaw|clawdbot|moltbot|nanobot|picoclaw|claude|aider|opencode|codex|gemini-cli|goose|crush|cursor-agent|open-interpreter|autogpt|agent-zero" | grep -vE 'grep|agent-hunt' | while read -r pid cmd; do
  act "Kill pid $pid ($cmd)?" && kill -9 "$pid" && log_action "agent-hunt: killed $pid $cmd"
done
for u in $(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei 'openclaw|clawdbot|moltbot|claude|aider|opencode|codex|gemini|goose|ollama|n8n'); do
  act "Disable + stop + mask unit $u?" && systemctl disable --now "$u" && systemctl mask "$u" && log_action "agent-hunt: masked $u"
done
for h in /root /home/*; do
  for d in .openclaw .clawdbot .moltbot .nanobot .picoclaw .claude .claude.json .aider.conf.yml .config/opencode .codex .gemini .config/goose .open-interpreter; do
    [[ -e "$h/$d" ]] || continue
    act "Quarantine $h/$d (tar to $Q, then remove)?" && tar czf "$Q/$(echo "$h/$d" | tr / _).tgz" "$h/$d" 2>/dev/null && rm -rf "${h:?}/$d" && log_action "agent-hunt: quarantined $h/$d"
  done
done
for pkg in @anthropic-ai/claude-code openclaw @openai/codex @google/gemini-cli opencode-ai; do
  npm ls -g "$pkg" >/dev/null 2>&1 && act "npm uninstall -g $pkg?" && npm uninstall -g "$pkg" && log_action "agent-hunt: npm removed $pkg"
done

hdr "ACTIONS: ZeroClaw (keep /health up)"
for c in $ZCFGS; do
  ZUSER=$(stat -c %U "$c"); ZHOME=$(dirname "$c")
  ZPORT=$(grep -E '^\s*port\s*=' "$c" | head -1 | grep -oE '[0-9]+'); ZPORT=${ZPORT:-42617}
  health() { curl -s -m 4 "http://127.0.0.1:${ZPORT}/health" | head -c 200; }
  info "Before: /health -> $(health)"
  act "Harden $c? (backup kept, auto-restore if /health dies)" || continue
  backup_file "$c"; cp -a "$c" "$c.blue-$TS"
  python3 - "$c" <<'PY'
import re,sys
p=sys.argv[1]; lines=open(p).read().split("\n"); out=[]; sec=""
# Only change keys that already exist - unknown keys can stop ZeroClaw from starting.
want={("gateway","require_pairing"):"true",
      ("gateway","paired_tokens"):"[]",
      ("autonomy","level"):'"readonly"',
      ("autonomy","workspace_only"):"true",
      ("autonomy","allowed_commands"):"[]",
      ("autonomy","max_actions_per_hour"):"0"}
done=set(); in_chan=False; skip_array=False
for l in lines:
    if skip_array:
        if "]" in l: skip_array=False
        continue
    m=re.match(r'^\s*\[+\s*([^\]]+?)\s*\]+\s*$',l)
    if m:
        sec=m.group(1); in_chan=sec.startswith("channels_config.") and sec!="channels_config.cli"
        out.append(("# blue-disabled: "+l) if in_chan else l); continue
    if in_chan:
        out.append(("# blue-disabled: "+l) if l.strip() else l); continue
    k=re.match(r'^(\s*)([A-Za-z0-9_]+)(\s*=\s*)(.*)$',l)
    if k and (sec,k.group(2)) in want:
        out.append(f"{k.group(1)}{k.group(2)}{k.group(3)}{want[(sec,k.group(2))]}"); done.add((sec,k.group(2)))
        v=k.group(4).split("#")[0].strip()
        if v.startswith("[") and "]" not in v: skip_array=True   # drop the rest of a multi-line array
        continue
    out.append(l)
open(p,"w").write("\n".join(out))
print("  changed:", sorted(f"{a}.{b}" for a,b in done) or "nothing (keys not present)")
missing=[f"{a}.{b}" for a,b in want if (a,b) not in done]
if missing: print("  not present (set by hand after checking the docs for this version):", missing)
PY
  log_action "agent-hunt: zeroclaw config hardened $c"
  UNIT=$(systemctl list-units --all --no-legend 2>/dev/null | awk '{print $1}' | grep -i zeroclaw | head -1)
  if [[ -n "$UNIT" ]]; then systemctl restart "$UNIT"
  else
    warn "No systemd unit - restarting by hand. Check how it was started first: ps -ef | grep zeroclaw"
    pkill -f 'zeroclaw (daemon|gateway)'; sleep 1
    su -s /bin/bash "$ZUSER" -c "cd $(dirname "$ZHOME"); nohup zeroclaw daemon >/tmp/zeroclaw.log 2>&1 &" 2>/dev/null
  fi
  sleep 5; H=$(health)
  if [[ -z "$H" ]]; then
    warn "/health not answering - RESTORING config"; cp -a "$c.blue-$TS" "$c"
    [[ -n "$UNIT" ]] && systemctl restart "$UNIT"; sleep 5; info "After restore: $(health)"
    log_action "agent-hunt: zeroclaw restore after failed harden"
  else ok "/health -> $H"; fi
  [[ "$ZUSER" == root ]] && warn "ZeroClaw config is owned by root and probably runs as root. Moving it to a dedicated user is the real fix: useradd -r -m zeroclaw; move ~/.zeroclaw; set User=zeroclaw in the unit."
  info "Review the workspace files it reads at startup (section 6 above) and delete instructions you didn't write."
done

hdr "ACTIONS: cut the agent's brain (LLM API) and remote control (chat) via /etc/hosts"
info "ZeroClaw's /health doesn't need the LLM. If the scoring check only hits /health, this costs nothing."
info "If the score for ZeroClaw goes red after this, undo with: sed -i '/# blue-sinkhole/d' /etc/hosts"
if act "Sinkhole LLM API hosts on this box?"; then
  backup_file /etc/hosts
  for h in $LLM_HOSTS; do grep -q " $h # blue-sinkhole" /etc/hosts || echo "0.0.0.0 $h # blue-sinkhole" >> /etc/hosts; done
  log_action "agent-hunt: sinkholed LLM APIs"; ok "done"
fi
if act "Sinkhole Discord/Telegram/Slack on this box too? (only affects THIS server, not your Kali)"; then
  for h in $CHAT_HOSTS; do grep -q " $h # blue-sinkhole" /etc/hosts || echo "0.0.0.0 $h # blue-sinkhole" >> /etc/hosts; done
  log_action "agent-hunt: sinkholed chat platforms"; ok "done"
fi
info "Sinkholes stop hostname lookups only. For a stronger block, do the same with DNS host overrides on pfSense, or block egress 443 from this host."
ok "Saved: $OUT  | quarantine: $Q"
