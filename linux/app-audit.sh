#!/usr/bin/env bash
# app-audit.sh - application-layer backdoors that OS hardening never sees.
# Usage: sudo ./app-audit.sh gitlab        (audit; then asks about fixes)
#        sudo ./app-audit.sh mattermost
# Red team loves: extra admin users, personal access tokens, SSH/deploy keys, webhooks,
# CI runners, slash commands - all survive a password change.

DIR="$(cd "$(dirname "$0")" && pwd)"; source "$DIR/common.sh"
need_root
APP="${1:-}"

gitlab_audit() {
  command -v gitlab-rails >/dev/null || { warn "gitlab-rails not found"; exit 1; }
  hdr "GitLab audit (gitlab-rails runner is slow, ~30-60s)"
  gitlab-rails runner '
    s = Gitlab::CurrentSettings.current_application_settings
    puts "== Settings: signup_enabled=#{s.signup_enabled} require_admin_approval=#{s.require_admin_approval_after_user_signup rescue "?"} default_branch_protection=#{s.default_branch_protection rescue "?"}"
    puts "== ADMINS"
    User.admins.each { |u| puts "  #{u.username} <#{u.email}> state=#{u.state} created=#{u.created_at} last_sign_in=#{u.last_sign_in_at}" }
    puts "== ALL USERS (created in last 2 days marked !)"
    (User.respond_to?(:humans) ? User.humans : User.all).each { |u| puts "  #{u.created_at > 2.days.ago ? "[!]" : "   "} #{u.username} admin=#{u.admin} state=#{u.state}" }
    puts "== ACTIVE PERSONAL/IMPERSONATION ACCESS TOKENS"
    PersonalAccessToken.active.each { |t| puts "  id=#{t.id} user=#{t.user&.username} name=#{t.name} scopes=#{t.scopes.join(",")} impersonation=#{t.impersonation} created=#{t.created_at}" }
    puts "== SSH KEYS (user + deploy)"
    Key.all.each { |k| puts "  id=#{k.id} type=#{k.type || "user"} owner=#{k.user&.username} title=#{k.title} created=#{k.created_at}" }
    puts "== SYSTEM HOOKS"; SystemHook.all.each { |h| puts "  [!] id=#{h.id} #{h.url}" }
    puts "== PROJECT/GROUP HOOKS"; (ProjectHook.all + GroupHook.all rescue ProjectHook.all).each { |h| puts "  id=#{h.id} #{h.url}" }
    puts "== CI RUNNERS (a rogue runner = code exec on every pipeline)"; Ci::Runner.all.each { |r| puts "  id=#{r.id} #{r.description} type=#{r.runner_type} contacted=#{r.contacted_at}" }
    puts "== CI/CD VARIABLES (instance)"; Ci::InstanceVariable.all.each { |v| puts "  #{v.key}" } rescue nil
  ' 2>&1 | tee "$BLUE_DIR/gitlab-audit-$TS.txt"

  hdr "GitLab fixes"
  if ask "Reset GitLab root password now (interactive rake task)?"; then gitlab-rake "gitlab:password:reset[root]" </dev/tty && log_action "gitlab root pw reset"; fi
  local RB=""
  ask "Disable public sign-ups?" && RB+='Gitlab::CurrentSettings.current_application_settings.update!(signup_enabled: false); puts "signups off";'
  if ask "Revoke ALL personal access tokens except scoring_user's?"; then
    RB+='PersonalAccessToken.active.each { |t| next if t.user&.username == "scoring_user"; t.revoke!; puts "revoked #{t.id} #{t.user&.username} #{t.name}" };'
  fi
  if ask "Delete ALL system hooks?"; then RB+='SystemHook.destroy_all; puts "system hooks gone";'; fi
  read -r -p "${Y}[?]${N} Usernames to BLOCK (space separated, blank = none; never root/scoring_user): " BL </dev/tty
  for u in $BL; do [[ $u == root || $u == scoring_user ]] && continue; RB+="u=User.find_by_username('$u'); if u; u.update!(admin: false); u.block!; puts 'blocked $u'; end;"; done
  read -r -p "${Y}[?]${N} Key ids to DELETE (space separated, blank = none): " KD </dev/tty
  for k in $KD; do RB+="Key.find_by(id: $k)&.destroy; puts 'key $k deleted';"; done
  read -r -p "${Y}[?]${N} Runner ids to DELETE: " RD </dev/tty
  for r in $RD; do RB+="Ci::Runner.find_by(id: $r)&.destroy; puts 'runner $r deleted';"; done
  if [[ -n "$RB" ]]; then gitlab-rails runner "$RB" && log_action "gitlab fixes: $RB"; fi
  info "Then: check the scoreboard. gitlab-ctl status should show every service 'run:'."
}

mm_audit() {
  local MM=/opt/mattermost CFG=/opt/mattermost/config/config.json
  [[ -f $CFG ]] || { warn "No $CFG"; exit 1; }
  local MMCTL="$MM/bin/mmctl"; [[ -x $MMCTL ]] || MMCTL=$(command -v mmctl)
  local DSN; DSN=$(python3 -c "import json;print(json.load(open('$CFG'))['SqlSettings']['DataSource'])" 2>/dev/null)
  hdr "Mattermost config red flags"
  python3 - "$CFG" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
def g(*p):
    x=c
    for k in p: x=x.get(k,{}) if isinstance(x,dict) else {}
    return x
checks=[
 (("TeamSettings","EnableOpenServer"),True,"Open server: anyone can sign up"),
 (("TeamSettings","EnableUserCreation"),True,"User creation enabled"),
 (("ServiceSettings","EnableUserAccessTokens"),True,"Personal access tokens enabled"),
 (("ServiceSettings","EnableOutgoingWebhooks"),True,"Outgoing webhooks enabled (data exfil)"),
 (("ServiceSettings","EnableCommands"),True,"Custom slash commands enabled"),
 (("PluginSettings","EnableUploads"),True,"Plugin uploads enabled (plugin = server-side code exec)"),
 (("ServiceSettings","EnableInsecureOutgoingConnections"),True,"Insecure outgoing connections"),
]
for path,bad,msg in checks:
    v=g(*path)
    print(("[!] " if v==bad else "    ")+".".join(path)+"="+str(v)+("  <- "+msg if v==bad else ""))
print("    Plugins enabled:", [k for k,v in g("PluginSettings","PluginStates").items() if isinstance(v,dict) and v.get("Enable")])
PY
  if [[ "$DSN" == postgres* ]]; then
    hdr "Mattermost DB audit"
    P() { psql "$DSN" -At -c "$1" 2>/dev/null; }
    echo "== SYSTEM ADMINS"; P "SELECT username||'  '||email||'  created='||to_timestamp(createat/1000)||'  deleted='||(deleteat>0) FROM users WHERE roles LIKE '%system_admin%'" | sed 's/^/  [!] /'
    echo "== USERS CREATED LAST 2 DAYS"; P "SELECT username||'  roles='||roles FROM users WHERE createat > (extract(epoch from now())-172800)*1000" | sed 's/^/  [!] /'
    echo "== ACCESS TOKENS"; P "SELECT t.id||'  user='||u.username||'  '||t.description||'  active='||t.isactive FROM useraccesstokens t JOIN users u ON u.id=t.userid" | sed 's/^/  /'
    echo "== BOTS"; P "SELECT username FROM users WHERE isbot" | sed 's/^/  /'
    echo "== OUTGOING WEBHOOKS"; P "SELECT id||'  '||callbackurls FROM outgoingwebhooks WHERE deleteat=0" | sed 's/^/  [!] /'
    echo "== INCOMING WEBHOOKS"; P "SELECT id||'  channel='||channelid FROM incomingwebhooks WHERE deleteat=0" | sed 's/^/  /'
    echo "== SLASH COMMANDS"; P "SELECT id||'  /'||trigger||' -> '||url FROM commands WHERE deleteat=0" | sed 's/^/  [!] /'
  else
    warn "DataSource isn't postgres or not readable - use mmctl / System Console"
  fi | tee "$BLUE_DIR/mm-audit-$TS.txt"

  hdr "Mattermost fixes (via mmctl --local)"
  if ! "$MMCTL" --local system version >/dev/null 2>&1; then
    warn "mmctl local mode off."
    if ask "Enable ServiceSettings.EnableLocalMode (root-only unix socket) and restart mattermost?"; then
      backup_file "$CFG"
      python3 -c "import json;p='$CFG';c=json.load(open(p));c['ServiceSettings']['EnableLocalMode']=True;json.dump(c,open(p,'w'),indent=2)"
      systemctl restart mattermost; sleep 8
    else return; fi
  fi
  M() { "$MMCTL" --local "$@"; }
  ask "Change the 'admin' user's password?" && { read -r -s -p "New password: " NP </dev/tty; echo; M user change-password admin --password "$NP" && log_action "mm admin pw changed"; }
  ask "Turn off open sign-up, user tokens, outgoing webhooks, plugin uploads?" && {
    M config set TeamSettings.EnableOpenServer false; M config set TeamSettings.EnableUserCreation false
    M config set ServiceSettings.EnableUserAccessTokens false; M config set ServiceSettings.EnableOutgoingWebhooks false
    M config set PluginSettings.EnableUploads false; log_action "mm settings locked"; }
  read -r -p "${Y}[?]${N} Usernames to DEMOTE from system admin (blank = none, never 'admin'): " D </dev/tty
  for u in $D; do M roles member "$u" && log_action "mm demoted $u"; done
  read -r -p "${Y}[?]${N} Usernames to DEACTIVATE: " X </dev/tty
  for u in $X; do is_scored "$u" && { warn "skip scored $u"; continue; }; M user deactivate "$u" && log_action "mm deactivated $u"; done
  read -r -p "${Y}[?]${N} Token ids to REVOKE: " T </dev/tty
  for t in $T; do M token revoke "$t" && log_action "mm token revoked $t"; done
  read -r -p "${Y}[?]${N} Webhook ids to DELETE: " W </dev/tty
  for w in $W; do M webhook delete "$w" && log_action "mm webhook deleted $w"; done
  read -r -p "${Y}[?]${N} Slash command ids to DELETE: " C </dev/tty
  for c in $C; do M command delete "$c" && log_action "mm command deleted $c"; done
}

case "$APP" in
  gitlab) gitlab_audit ;;
  mattermost|mm) mm_audit ;;
  *) echo "Usage: $0 gitlab|mattermost"; exit 1 ;;
esac
