#!/bin/bash
# =============================================================================
#  blue.sh — GDDC Team 7 Linux hardening + incident response
#
#  Roles:  web (172.16.7.10) | file (172.16.7.20) | msgboard (172.16.7.30)
#  Phases: creds persistence shells integrity services firewall av watch
#
#  Default is --audit (read-only).  Changes only with --apply --phase <list>.
#  Every destructive action asks y/N unless --yes (and --yes only auto-applies
#  high-confidence findings; low-confidence ones still need an interactive y).
#
#  Usage:
#    SCORING_USER=<name> ./blue.sh --role file                        # audit all
#    SCORING_USER=<name> ./blue.sh --role file --apply --phase creds,services
#    SCORING_USER=<name> ./blue.sh --role web  --apply --phase firewall
#    SCORING_USER=<name> ./blue.sh --role web  --phase watch [--heal] [--bg]
#    systemctl stop blue-watch                                        # stop --bg
# =============================================================================

# ---------------------------- EDIT / OVERRIDE --------------------------------
SCORING_USER="${SCORING_USER:-}"          # REQUIRED for --apply/--heal. Never removed/locked/rotated.
TEAM=7
SCORED_USERS=(amarino mdesocio lsmith acapece johnlinux linuswindows alvin simon theodore abauer)
SCORED_PW='bb123#123'                      # scored users must KEEP this (rule 8)
KEEP_USERS=(rum usario)                    # extra accounts never removed (app user, packet admin)
IOC_USERS=(systemd-sync)                   # red-team accounts to always list for removal
ROOT_LOGIN_MODE="prohibit-password"        # sshd PermitRootLogin (asked before applying)
MSG_CONTENT_PATH="/"                       # msgboard HTTP Content path the scorer GETs
MSG_CONTENT_STRING=""                      # optional string that must appear in that page
RUM_MP4_PATH="/watch/cdo/cdo_documentary_2026.mp4"
SSH_RESTRICT=0                             # 1 = SSH only from team /24 + SCORER_NETS (SSH is scored: leave 0 unless you know the scorer IP)
SCORER_NETS=(172.16.0.2)                   # the unknown-origin ufw allow; kept as an allow, flagged
ALLOW_APT_EGRESS=0                         # 1 = allow outbound tcp 80/443 (apt, github). Run integrity/av BEFORE firewall or set this.
EXTRA_EGRESS=()                            # e.g. ("tcp:172.16.7.40:389" "udp:172.16.7.40:88")
FTP_PASV_MIN=50000
FTP_PASV_MAX=50100
FW_ROLLBACK_SECS=60                        # firewall auto-rollback window (scorer polls every 90s; 200 lets you see one tick)
WATCH_INTERVAL=30
# -----------------------------------------------------------------------------

# Re-exec in a clean environment: red team aliases, BASH_ENV, exported
# functions, LD_PRELOAD and PATH hijacks in our login shell can't follow us.
if [[ -z "${BLUE_CLEAN:-}" ]]; then
  exec /usr/bin/env -i BLUE_CLEAN=1 HOME=/root TERM="${TERM:-xterm}" LANG=C.UTF-8 \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    SCORING_USER="$SCORING_USER" SSH_CONNECTION="${SSH_CONNECTION:-}" BLUE_IN_BG="${BLUE_IN_BG:-}" \
    /bin/bash --noprofile --norc "$(readlink -f "$0")" "$@"
fi
umask 077
SELF=$(readlink -f "$0")

# ------------------------------- args ----------------------------------------
ROLE=""; MODE=audit; PHASES=(); YES=0; HEAL=0; BG=0; REBASE=0; ROTATE=0
usage(){ sed -n '2,20p' "$SELF"; }
while (($#)); do
  case "$1" in
    --role) ROLE="$2"; shift 2;;
    --audit) MODE=audit; shift;;
    --apply) MODE=apply; shift;;
    --phase) IFS=, read -r -a PHASES <<<"$2"; shift 2;;
    --yes|-y) YES=1; shift;;
    --heal) HEAL=1; shift;;
    --bg) BG=1; shift;;
    --rebaseline) REBASE=1; shift;;
    --rotate) ROTATE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown argument: $1"; usage; exit 2;;
  esac
done

# ------------------------------- output --------------------------------------
R=$'\e[1;31m'; Y=$'\e[1;33m'; G=$'\e[1;32m'; C=$'\e[1;36m'; B=$'\e[1m'; N=$'\e[0m'
FINDINGS=0
section(){ printf '\n%s==== %s ====%s\n' "$B" "$*" "$N"; }
info(){ printf '  %s\n' "$*"; }
ok(){ printf '  %s[OK]%s %s\n' "$G" "$N" "$*"; }
warn(){ printf '  %s[WARN]%s %s\n' "$Y" "$N" "$*"; }
alert(){ printf '  %s[ALERT]%s %s\n' "$R" "$N" "$*"; FINDINGS=$((FINDINGS+1)); }
plan(){ printf '  %s[WOULD]%s %s\n' "$C" "$N" "$*"; }
did(){ printf '  %s[DONE]%s %s\n' "$G" "$N" "$*"; }
die(){ printf '%s[FATAL]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
indent(){ sed 's/^/        /'; }

# ------------------------------- guards --------------------------------------
[[ $EUID -eq 0 ]] || die "run as root"
case "$ROLE" in
  web)      MYIP=172.16.$TEAM.10;;
  file)     MYIP=172.16.$TEAM.20;;
  msgboard) MYIP=172.16.$TEAM.30;;
  *) usage; die "--role web|file|msgboard is required";;
esac
TEAM_NET=172.16.$TEAM.0/24
ROUTER=172.16.$TEAM.1
FILE_IP=172.16.$TEAM.20
DC=172.16.$TEAM.40
if ! ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$MYIP"; then
  die "WRONG BOX: role '$ROLE' expects $MYIP but this host ($(hostname)) has: $(ip -4 -o addr show | awk '{print $4}' | tr '\n' ' ')"
fi
APPLY=0; [[ $MODE == apply ]] && APPLY=1
(( HEAL )) && APPLY_HEAL=1 || APPLY_HEAL=0
if (( APPLY || APPLY_HEAL )) && [[ -z $SCORING_USER ]]; then
  die "SCORING_USER is not set. Refusing to --apply/--heal. Run: SCORING_USER=<name> $0 ..."
fi
if (( APPLY )) && (( ${#PHASES[@]} == 0 )); then die "--apply needs --phase (creds|persistence|shells|integrity|services|firewall|av|watch)"; fi
if (( ${#PHASES[@]} == 0 )); then PHASES=(creds persistence shells integrity services firewall); fi
for p in "${PHASES[@]}"; do
  case "$p" in creds|persistence|shells|integrity|services|firewall|av|watch) ;; *) die "unknown phase $p";; esac
done

TS=$(date +%Y%m%d-%H%M%S)
HOST=$(hostname -s 2>/dev/null || hostname)
STATE=/root/blue-state
QDIR=/root/blue-quarantine/$TS
BAKDIR=/root/blue-backups/$TS
LOG=/root/blue-$HOST-$TS.log
mkdir -p "$STATE" /root/blue-quarantine /root/blue-backups
if [[ -n ${BLUE_IN_BG:-} ]]; then exec >>"$LOG" 2>&1; else exec > >(tee -a "$LOG") 2>&1; fi

printf '%sblue.sh role=%s host=%s ip=%s mode=%s phases=%s yes=%s heal=%s%s\n' "$B" "$ROLE" "$HOST" "$MYIP" "$MODE" "${PHASES[*]}" "$YES" "$HEAL" "$N"
info "log: $LOG"
[[ -n $SSH_CONNECTION ]] && info "your SSH session comes from: ${SSH_CONNECTION%% *}"
[[ -n $SCORING_USER ]] && info "SCORING_USER=$SCORING_USER (protected)"

# ------------------------------- helpers -------------------------------------
confirm(){ (( YES )) && return 0; local a; read -r -p "  ${Y}?${N} $* [y/N] " a </dev/tty || return 1; [[ $a == [yY]* ]]; }
# want DESC  -> 0 if we should do it (apply + confirmed). Audit mode prints WOULD.
want(){ if (( ! APPLY )); then plan "$*"; return 1; fi; if confirm "$*"; then return 0; fi; info "skipped: $*"; return 1; }
# gate SCORE DESC -> like want, but under --yes only auto-apply when SCORE>=3 (high confidence)
gate(){ local s=$1; shift
  if (( ! APPLY )); then plan "$*"; return 1; fi
  if (( YES && s < 3 )); then info "needs an interactive y (low confidence, score $s): $*"; return 1; fi
  want "$*"; }

is_scored(){ local x; for x in "${SCORED_USERS[@]}"; do [[ $x == "$1" ]] && return 0; done; return 1; }
is_keep(){ local x; for x in "${KEEP_USERS[@]}"; do [[ $x == "$1" ]] && return 0; done; return 1; }
is_protected(){ [[ $1 == root ]] && return 0; [[ -n $SCORING_USER && $1 == "$SCORING_USER" ]] && return 0; is_scored "$1" || is_keep "$1"; }

unattr(){ local f; for f in "$@"; do [[ -e $f && ! -L $f ]] || continue
  if lsattr -d -- "$f" 2>/dev/null | awk '{print $1}' | grep -q '[ia]'; then chattr -i -a -- "$f" 2>/dev/null && warn "removed immutable/append-only attribute on $f"; fi; done; }
# bak FILE... : timestamped copy beside the file + copy under BAKDIR. Only used before EDITS.
bak(){ local f; for f in "$@"; do [[ -e $f ]] || continue
  mkdir -p "$BAKDIR$(dirname -- "$f")"; cp -a -- "$f" "$BAKDIR$f" 2>/dev/null
  [[ -f $f ]] && cp -a -- "$f" "$f.bak.$TS" 2>/dev/null
  unattr "$f"; done; }
# quarantine PATH... : move out of the tree (evidence kept, reversible). Used for REMOVALS.
quarantine(){ local p dest; for p in "$@"; do [[ -e $p || -L $p ]] || continue
  dest="$QDIR$p"; mkdir -p "$(dirname -- "$dest")"
  unattr "$p"; [[ -d $p && ! -L $p ]] && chattr -R -i -a -- "$p" 2>/dev/null
  if mv -f -- "$p" "$dest" 2>/dev/null; then
    find "$dest" -type f -exec chmod 0400 {} + 2>/dev/null
    did "quarantined $p -> $dest"
  else alert "could not move $p"; fi; done; }

etc_tarball(){ local last; last=$(find /root -maxdepth 1 -name "blue-etc-$HOST-*.tgz" -mmin -15 2>/dev/null | head -1)
  if [[ -n $last ]]; then info "recent /etc tarball exists: $last"; return; fi
  tar czf "/root/blue-etc-$HOST-$TS.tgz" -C / etc 2>/dev/null && info "/etc backed up to /root/blue-etc-$HOST-$TS.tgz"; }

pcmd(){ tr '\0' ' ' <"/proc/$1/cmdline" 2>/dev/null; }
declare -A PROTECT_PID=()
init_protect(){ local p=$$ n=0; PROTECT_PID[1]=1
  while [[ -n $p && $p != 0 && $n -lt 64 ]]; do PROTECT_PID[$p]=1; p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' '); n=$((n+1)); done; }
init_protect
# kill_pid PID EXPECTED_CMDLINE : verify cmdline unchanged, keep exe as evidence, SIGKILL. Never by user.
kill_pid(){ local pid=$1 expect=$2 cur
  [[ -d /proc/$pid ]] || return 0
  [[ -n ${PROTECT_PID[$pid]:-} ]] && { warn "refusing to kill protected pid $pid (init / this session)"; return 1; }
  cur=$(pcmd "$pid")
  if [[ -n $expect && $cur != "$expect" ]]; then warn "pid $pid cmdline changed ('$cur'), not killing"; return 1; fi
  mkdir -p "$QDIR/proc"; cp -- "/proc/$pid/exe" "$QDIR/proc/$pid.exe" 2>/dev/null; printf '%s\n' "$cur" >"$QDIR/proc/$pid.cmdline"
  kill -9 "$pid" 2>/dev/null && did "killed pid $pid ($cur)"; }
psline(){ ps -o pid=,ppid=,user=,lstart=,args= -p "$1" 2>/dev/null; }

# dpkg ownership database (handles usrmerge /lib vs /usr/lib)
declare -A OWNED=(); OWNED_LOADED=0
load_owned(){ (( OWNED_LOADED )) && return; info "loading dpkg file database..."
  local f
  while IFS= read -r f; do [[ -n $f ]] && OWNED[$f]=1; done < <(cat /var/lib/dpkg/info/*.list 2>/dev/null)
  while IFS= read -r f; do [[ -n $f ]] && OWNED[$f]=1; done < <(dpkg-divert --list 2>/dev/null | awk '{print $3; print $5}')
  OWNED_LOADED=1; }
owned(){ local p=$1 r
  [[ -n ${OWNED[$p]:-} ]] && return 0
  [[ $p == /usr/* && -n ${OWNED[${p#/usr}]:-} ]] && return 0
  [[ -n ${OWNED[/usr$p]:-} ]] && return 0
  r=$(readlink -f -- "$p" 2>/dev/null) || return 1
  if [[ $r != "$p" ]]; then [[ -n ${OWNED[$r]:-} || -n ${OWNED[${r#/usr}]:-} || -n ${OWNED[/usr$r]:-} ]] && return 0; fi
  return 1; }

# ------------------------------- IOCs ----------------------------------------
IOC_UNITS=(syssam snap-snapd-21445 snap-snapd-21446 apt-serviced console-keep heretohelp
           dbus-org.freedesktop.session1 dbus-session-helper snap-cache apt-cache-refresh systemd-sync)
IOC_PATHS=(/.bin /etc/.inittd)
IOC_FIND=( -iname '*cerberus*' -o -iname '*watershell*' -o -regex '.*/\.init[0-9]*\.py' -o -iname '*rickroll*' )
SUS_RE='/dev/(tcp|udp)/|(^|[ /;|&])(nc|ncat|netcat)( [^|;]*)? -[ecl]|bash -i|sh -i|socket\.socket|pty\.spawn|base64 +(-d|--decode)|\| *(ba|da|z)?sh( |$)|mkfifo|socat|python[0-9.]* +-c|perl +-e|php +-r|cerberus|watershell|\.inittd|/\.bin/|\.init[0-9]*\.py|while +(true|:)|rick|cowsay|PROMPT_COMMAND|(^|[ ;])trap |LD_PRELOAD|/tmp/|/dev/shm/|curl [^|]*\| *(ba)?sh|wget [^|]*\| *(ba)?sh'
ALIAS_RE='^[[:space:]]*alias[[:space:]]+(sudo|su|ls|cd|cat|ps|ss|netstat|systemctl|kill|pkill|passwd|vi|vim|nano|top|htop|id|whoami|exit|clear|grep|find|rm|mv|cp|ip|iptables|nft|ufw|crontab|history|bash|sh|ssh|apt|apt-get|dpkg|chattr|lsattr|which|type|unalias|unset|less|more|tail|head|echo|w|who|last|lsof|chmod|chown|mount|reboot)='
FUNC_RE='^[[:space:]]*(function[[:space:]]+)?(sudo|su|ls|cd|cat|ps|ss|kill|passwd|systemctl|exit|clear|ip|unalias|unset|command|builtin)[[:space:]]*\(\)'
RC_RE="$SUS_RE|$ALIAS_RE|$FUNC_RE"
PROC_RE='/dev/(tcp|udp)/|(^|[ /])(nc|ncat|netcat)( [^|;]*)? -[ecl]|bash -i|sh -i|socket\.socket|pty\.spawn|base64 +(-d|--decode)|\| *(ba|da|z)?sh( |$)|mkfifo|socat .*(exec|system)|python[0-9.]* +-c|perl +-e|php +-r|cerberus|watershell|\.inittd|/\.bin/|\.init[0-9]*\.py|while +(true|:)'
INTERP_RE='^(bash|sh|dash|zsh|ksh|fish|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|lua[0-9.]*|nc|ncat|netcat|socat|telnet|awk|gawk|mawk|openssl|tclsh[0-9.]*)$'
LEGIT_SVC_RE='^(rum[^/]*|blue-[^/]*|apache2|httpd|nginx|lighttpd|php[0-9.]*-fpm|mariadb|mysql|postgresql[^/]*|smbd|nmbd|samba[^/]*|vsftpd|ssh|sshd|cloudflared[^/]*)\.service$'

is_ioc_unit(){ local stem=${1%.*} x; for x in "${IOC_UNITS[@]}"; do [[ $stem == "$x" ]] && return 0; done; return 1; }
unit_whitelisted(){ [[ $1 =~ ^(rum|blue-) ]]; }

ROLE_UNITS_CACHE=""
role_units(){ [[ -n $ROLE_UNITS_CACHE ]] && { printf '%s\n' "$ROLE_UNITS_CACHE"; return; }; _role_units; }
_role_units(){ # scored units for this role (printed one per line)
  echo "$(ssh_unit)"
  case $ROLE in
    web) local u; u=$(rum_unit); [[ -n $u ]] && echo "$u";;
    file) echo smbd.service; echo vsftpd.service;;
    msgboard) msg_units;;
  esac; }
ssh_unit(){ if systemctl cat ssh.service >/dev/null 2>&1; then echo ssh.service; else echo sshd.service; fi; }
rum_unit(){ local u
  u=$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^rum' | grep -v retry | head -1)
  if [[ -z $u ]]; then u=$(grep -lsE '/opt/rum' /etc/systemd/system/*.service /usr/lib/systemd/system/*.service /lib/systemd/system/*.service 2>/dev/null | grep -v -e retry -e blue- | head -1); [[ -n $u ]] && u=$(basename "$u"); fi
  echo "$u"; }
msg_units(){ local web="" pid u
  pid=$(ss -tlnpH 'sport = :80' 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
  if [[ -n $pid ]]; then web=$(grep -oE '[^/]+\.service' "/proc/$pid/cgroup" 2>/dev/null | tail -1); fi
  if [[ -z $web ]]; then for u in apache2 nginx lighttpd httpd; do systemctl cat "$u.service" >/dev/null 2>&1 && { web=$u.service; break; }; done; fi
  [[ -n $web ]] && echo "$web"
  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^(php[0-9.]*-fpm|mariadb|mysql|postgresql)\.service$'; }

# expected listening ports (tcp) for this role
role_tcp_ports(){ case $ROLE in web) echo "22 80 8000";; file) echo "22 21 139 445";; msgboard) echo "22 80 443";; esac; }

# ------------------------------- scored-user helpers -------------------------
shadow_field(){ awk -F: -v u="$1" -v n="$2" '$1==u{print $n}' /etc/shadow; }
pw_ok(){ local u=$1 p=${2:-$SCORED_PW} h; h=$(shadow_field "$u" 2); h=${h#!}; [[ $h == \$* ]] || return 1
  perl -e 'exit(crypt($ARGV[0],$ARGV[1]) eq $ARGV[1] ? 0 : 1)' -- "$p" "$h"; }
set_pw(){ local u=$1 p=$2 h=""
  command -v openssl >/dev/null && h=$(printf '%s' "$p" | openssl passwd -6 -stdin 2>/dev/null)
  unattr /etc/shadow /etc/passwd
  if [[ $h == \$6\$* ]]; then usermod -p "$h" "$u"; else printf '%s:%s\n' "$u" "$p" | chpasswd; fi; }
scored_status(){ # prints space-separated problems, empty = healthy
  local u=$1 ent uid home sh h today f3 f5 f8 iss=()
  ent=$(getent passwd "$u") || { echo "MISSING"; return; }
  IFS=: read -r _ _ uid _ _ home sh <<<"$ent"
  [[ $uid == 0 ]] && iss+=(uid0)
  [[ $sh == /bin/bash || $sh == /usr/bin/bash ]] || iss+=("shell=$sh")
  h=$(shadow_field "$u" 2); [[ $h == \!* || $h == \** ]] && iss+=(locked)
  pw_ok "$u" || iss+=(password)
  today=$(( $(date +%s) / 86400 )); f3=$(shadow_field "$u" 3); f5=$(shadow_field "$u" 5); f8=$(shadow_field "$u" 8)
  [[ $f3 == 0 ]] && iss+=(must-change-pw)
  [[ -n $f8 && $f8 -le $today ]] && iss+=(account-expired)
  [[ -n $f5 && -n $f3 && $f5 != 99999 && $f3 != 0 ]] && (( f3 + f5 < today )) && iss+=(pw-expired)
  [[ -d $home ]] || iss+=(no-home)
  grep -qxE "[[:space:]]*${u}[[:space:]]*" /etc/ftpusers 2>/dev/null && [[ $ROLE == file ]] && iss+=(in-ftpusers)
  if [[ $ROLE == file ]] && command -v pdbedit >/dev/null; then
    pdbedit -L 2>/dev/null | cut -d: -f1 | grep -qx "$u" || iss+=(no-samba)
    pdbedit -v -u "$u" 2>/dev/null | grep -i 'account flags' | grep -q '[DL]' && iss+=(samba-disabled)
  fi
  echo "${iss[*]}"; }
smb_restore_user(){ local u=$1
  printf '%s\n%s\n' "$SCORED_PW" "$SCORED_PW" | smbpasswd -s -a "$u" >/dev/null 2>&1 || { alert "smbpasswd -a $u failed"; return 1; }
  smbpasswd -e "$u" >/dev/null 2>&1; pdbedit -r -c '[UX]' -u "$u" >/dev/null 2>&1; pdbedit -z -u "$u" >/dev/null 2>&1
  did "samba passdb ok: $u"; }
restore_scored_user(){ local u=$1 h home
  unattr /etc/passwd /etc/shadow /etc/group /etc/gshadow
  if ! getent passwd "$u" >/dev/null; then useradd -m -s /bin/bash "$u" && did "created $u"; fi
  if [[ $(id -u "$u") == 0 ]]; then alert "$u has uid 0 — fix by hand (vipw), not auto-changing"; fi
  [[ $(getent passwd "$u" | cut -d: -f7) == /bin/bash ]] || { usermod -s /bin/bash "$u" && did "$u shell -> /bin/bash"; }
  h=$(shadow_field "$u" 2); [[ $h == \!* ]] && usermod -U "$u" >/dev/null 2>&1
  pw_ok "$u" || { set_pw "$u" "$SCORED_PW" && did "$u password -> default"; }
  [[ $(shadow_field "$u" 3) == 0 ]] && chage -d "$(date +%F)" "$u"
  chage -E -1 -M 99999 -I -1 "$u" 2>/dev/null
  home=$(getent passwd "$u" | cut -d: -f6)
  if [[ ! -d $home ]]; then mkdir -p "$home" && cp -rT /etc/skel "$home" && chown -R "$u:" "$home" && chmod 750 "$home" && did "$u home recreated"; fi
  command -v faillock >/dev/null && faillock --user "$u" --reset >/dev/null 2>&1
  if [[ $ROLE == file ]]; then
    if grep -qxE "[[:space:]]*${u}[[:space:]]*" /etc/ftpusers 2>/dev/null; then bak /etc/ftpusers; sed -i -E "/^[[:space:]]*${u}[[:space:]]*$/d" /etc/ftpusers; did "$u removed from /etc/ftpusers"; fi
    command -v smbpasswd >/dev/null && smb_restore_user "$u"
  fi; }

# =============================================================================
# PHASE: creds
# =============================================================================
declare -A STD_UID=([daemon]=1 [bin]=2 [sys]=3 [sync]=4 [games]=5 [man]=6 [lp]=7 [mail]=8 [news]=9 [uucp]=10 [proxy]=13 [www-data]=33 [backup]=34 [list]=38 [irc]=39 [nobody]=65534)
pick_uid(){ local u=$1 c
  if [[ -n ${STD_UID[$u]:-} ]] && ! getent passwd "${STD_UID[$u]}" >/dev/null; then echo "${STD_UID[$u]}"; return; fi
  c=$(getent group "$u" | cut -d: -f3)
  if [[ -n $c && $c != 0 ]] && ! getent passwd "$c" >/dev/null; then echo "$c"; return; fi
  for ((c=999; c>=100; c--)); do getent passwd "$c" >/dev/null || { echo "$c"; return; }; done; }
fix_uid0(){ local u=$1 nu=$2 ng
  ng=$(getent group "$u" | cut -d: -f3); [[ -z $ng || $ng == 0 ]] && ng=65534
  bak /etc/passwd /etc/shadow
  awk -F: -v OFS=: -v u="$u" -v nu="$nu" -v ng="$ng" '$1==u{$3=nu;$4=ng;$7="/usr/sbin/nologin"}1' /etc/passwd >/etc/passwd.blue.tmp \
    && cat /etc/passwd.blue.tmp >/etc/passwd && rm -f /etc/passwd.blue.tmp
  passwd -l "$u" >/dev/null 2>&1; usermod -e 1 "$u" >/dev/null 2>&1
  command -v nscd >/dev/null && nscd -i passwd 2>/dev/null
  did "$u: uid 0 -> $nu, gid $ng, shell nologin, locked (processes NOT killed — they are real root processes)"; }
remove_user(){ local u=$1 uid pid
  uid=$(id -u "$u" 2>/dev/null) || return
  [[ $uid == 0 ]] && { alert "$u is uid 0 – fix uid first"; return 1; }
  bak /etc/passwd /etc/shadow /etc/group /etc/gshadow
  usermod -L -e 1 -s /usr/sbin/nologin "$u" >/dev/null 2>&1
  for pid in $(ps -eo pid=,ruid= | awk -v x="$uid" '$2==x{print $1}'); do info "$(psline "$pid")"; kill_pid "$pid" "$(pcmd "$pid")"; done
  quarantine "/var/spool/cron/crontabs/$u" "/var/lib/systemd/linger/$u"
  command -v pdbedit >/dev/null && pdbedit -L 2>/dev/null | cut -d: -f1 | grep -qx "$u" && pdbedit -x -u "$u" >/dev/null 2>&1
  userdel "$u" >/dev/null 2>&1 || userdel -f "$u" >/dev/null 2>&1
  getent passwd "$u" >/dev/null && alert "userdel $u failed" || did "removed account $u (home dir left in place as evidence)"; }
rotate_pw(){ local u=$1 p1 p2
  read -r -s -p "  New password for $u: " p1 </dev/tty; echo; read -r -s -p "  Again: " p2 </dev/tty; echo
  [[ -n $p1 && $p1 == "$p2" ]] || { warn "empty or mismatch — $u NOT rotated"; return 1; }
  [[ $p1 == "$SCORED_PW" ]] && { warn "that is the public default — $u NOT rotated"; return 1; }
  set_pw "$u" "$p1" && { did "$u password rotated (hash set directly, PAM bypassed)"; date >"$STATE/rotated-$u"; }
  unset p1 p2; }
SUDOERS_DEFAULT='Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults	use_pty
root	ALL=(ALL:ALL) ALL
%admin	ALL=(ALL) ALL
%sudo	ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d'

phase_creds(){
  load_owned
  local u uid gid home sh line f s cands=() x

  section "CREDS: uid-0 accounts"
  while IFS=: read -r u _ uid _ _ home sh; do
    [[ $uid == 0 && $u != root ]] || continue
    if [[ $u == "$SCORING_USER" ]]; then alert "SCORING_USER $u is uid 0 — NOT touching it. Tell White Team."; continue; fi
    alert "uid-0 backdoor account: $u (home $home, shell $sh)"
    local nu; nu=$(pick_uid "$u")
    gate 3 "Set $u uid 0 -> $nu, shell nologin, lock (edit /etc/passwd)" && fix_uid0 "$u" "$nu"
  done </etc/passwd
  awk -F: '$4==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do warn "non-root account with primary gid 0: $u"; done

  section "CREDS: system accounts with login shells"
  while IFS=: read -r u _ uid _ _ home _; do
    (( uid > 0 && uid < 1000 )) || continue
    is_protected "$u" && continue
    sh=$(getent passwd "$u" | cut -d: -f7)
    case "$sh" in */nologin|*/false|/bin/sync|"") continue;; esac
    alert "system account $u (uid $uid) has shell $sh"
    gate 3 "Set $u shell -> /usr/sbin/nologin and lock" && { bak /etc/passwd /etc/shadow; usermod -s /usr/sbin/nologin "$u" && passwd -l "$u" >/dev/null 2>&1 && did "$u neutralized"; }
  done </etc/passwd
  while read -r u; do
    is_scored "$u" && continue
    alert "account with EMPTY password: $u"
    is_protected "$u" || { gate 3 "Lock $u" && passwd -l "$u" >/dev/null && did "locked $u"; }
  done < <(awk -F: '$2==""{print $1}' /etc/shadow)

  section "CREDS: scored users"
  local bad=0
  for u in "${SCORED_USERS[@]}"; do
    s=$(scored_status "$u")
    if [[ -z $s ]]; then ok "$u"; else alert "$u: $s"; bad=1; fi
  done
  if (( bad )) && want "Restore scored users (create/unlock/bash/default pw/no expiry$([[ $ROLE == file ]] && echo '/samba passdb/ftpusers'))"; then
    for u in "${SCORED_USERS[@]}"; do [[ -n $(scored_status "$u") ]] && restore_scored_user "$u"; done
  fi
  if [[ $ROLE == file ]] && command -v pdbedit >/dev/null; then
    local v; v=$(pdbedit -P "bad lockout attempt" 2>/dev/null | grep -oE '[0-9-]+$')
    if [[ -n $v && $v != 0 ]]; then alert "Samba 'bad lockout attempt' = $v (lockout trap)"; want "Set Samba lockout=0 and max password age=never" && { pdbedit -P "bad lockout attempt" -C 0 >/dev/null; pdbedit -P "maximum password age" -C -1 >/dev/null; did "samba policy reset"; }; fi
  fi

  section "CREDS: /etc/shells, /etc/nologin, ftpusers"
  for x in /bin/bash /usr/bin/bash; do
    if ! grep -qx "$x" /etc/shells 2>/dev/null; then alert "$x missing from /etc/shells (breaks FTP/chsh)"; want "Add $x to /etc/shells" && { bak /etc/shells; echo "$x" >>/etc/shells; did "added $x"; }; fi
  done
  for f in /etc/nologin /run/nologin; do [[ -e $f ]] && { alert "$f exists — blocks all non-root logins"; gate 3 "Quarantine $f" && quarantine "$f"; }; done
  if [[ -f /etc/ftpusers ]]; then
    for u in "${SCORED_USERS[@]}" "$SCORING_USER"; do [[ -n $u ]] && grep -qxE "[[:space:]]*${u}[[:space:]]*" /etc/ftpusers && alert "$u is DENIED in /etc/ftpusers"; done
    grep -qx root /etc/ftpusers || warn "root not in /etc/ftpusers (root FTP allowed)"
    if [[ $ROLE == file ]]; then
      for u in "${SCORED_USERS[@]}"; do if grep -qxE "[[:space:]]*${u}[[:space:]]*" /etc/ftpusers && want "Remove $u from /etc/ftpusers"; then bak /etc/ftpusers; sed -i -E "/^[[:space:]]*${u}[[:space:]]*$/d" /etc/ftpusers; did "removed $u"; fi; done
      grep -qx root /etc/ftpusers || { want "Add root to /etc/ftpusers" && { bak /etc/ftpusers; echo root >>/etc/ftpusers; }; }
    fi
  fi

  section "CREDS: non-scored, non-system human accounts (dry-run list)"
  while IFS=: read -r u _ uid _ _ home sh; do
    is_protected "$u" && continue
    (( uid > 0 && uid < 60000 )) || continue
    case "$sh" in */nologin|*/false|"") (( uid >= 1000 )) && info "no-login account (not removed): $u uid $uid"; continue;; esac
    if (( uid >= 1000 )) || [[ $home == /home/* ]]; then cands+=("$u"); fi
  done </etc/passwd
  for x in "${IOC_USERS[@]}"; do getent passwd "$x" >/dev/null && ! printf '%s\n' "${cands[@]}" | grep -qx "$x" && cands+=("$x"); done
  if (( ${#cands[@]} == 0 )); then ok "none"; else
    for u in "${cands[@]}"; do alert "candidate for removal: $(getent passwd "$u")"; done
    for u in "${cands[@]}"; do gate 2 "Remove account $u (lock, kill its PIDs, drop crontab/linger/samba, userdel)" && remove_user "$u"; done
  fi

  if command -v pdbedit >/dev/null; then
    section "CREDS: Samba passdb"
    while IFS=: read -r u uid _; do
      [[ -z $u ]] && continue
      if is_scored "$u" || [[ $u == "$SCORING_USER" ]] || is_keep "$u"; then continue; fi
      alert "unexpected Samba passdb entry: $u (uid $uid)"
      gate 3 "pdbedit -x -u $u" && pdbedit -x -u "$u" >/dev/null 2>&1 && did "removed $u from passdb"
    done < <(pdbedit -L 2>/dev/null)
  fi

  section "CREDS: privileged groups"
  for g in sudo admin wheel root shadow disk docker lxd adm; do
    local mem; mem=$(getent group "$g" | cut -d: -f4)
    [[ -z $mem ]] && continue
    for u in ${mem//,/ }; do
      [[ $u == root ]] && continue
      if [[ $u == "$SCORING_USER" ]]; then info "group $g: $u (SCORING_USER, left alone)"; continue; fi
      if is_scored "$u"; then alert "scored user $u is in '$g' (its password is public!)"; [[ $g != adm ]] && gate 3 "gpasswd -d $u $g" && { bak /etc/group /etc/gshadow; gpasswd -d "$u" "$g" >/dev/null && did "removed $u from $g"; }
      else warn "group $g: $u"; fi
    done
  done

  section "CREDS: sudoers"
  visudo -c >/dev/null 2>&1 && ok "visudo -c passes" || alert "visudo -c FAILS"
  grep -HnvE '^[[:space:]]*($|#($|[^i@]))' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | while IFS= read -r line; do
    if [[ $line =~ NOPASSWD|\!authenticate|LD_PRELOAD|\!env_reset ]] || ! [[ ${line#*:*:} =~ ^[[:space:]]*(Defaults|root[[:space:]]|%sudo[[:space:]]|%admin[[:space:]]|[@#]include) ]]; then alert "$line"; else info "$line"; fi
  done
  for f in /etc/sudoers.d/*; do
    [[ -f $f ]] || continue; owned "$f" && continue
    if [[ -n $SCORING_USER ]] && grep -qw -- "$SCORING_USER" "$f"; then warn "$f mentions SCORING_USER — leaving it"; continue; fi
    alert "unowned sudoers drop-in: $f"; gate 3 "Quarantine $f" && quarantine "$f"
  done
  local extra; extra=$(grep -vE '^[[:space:]]*($|#($|[^i@]))' /etc/sudoers | sed 's/[[:space:]]\+/ /g' | grep -vxF -f <(printf '%s\n' "$SUDOERS_DEFAULT" '#includedir /etc/sudoers.d' | sed 's/[[:space:]]\+/ /g') | grep -vE '^Defaults' ; grep -E '^[[:space:]]*Defaults.*(!authenticate|LD_PRELOAD|LD_LIBRARY|!env_reset|BASH_ENV)' /etc/sudoers)
  if [[ -n $extra ]]; then
    alert "/etc/sudoers has non-default lines:"; printf '%s\n' "$extra" | indent
    if gate 2 "Reset /etc/sudoers to distro default (lines naming SCORING_USER are kept)"; then
      local t; t=$(mktemp); { printf '%s\n' "$SUDOERS_DEFAULT"; [[ -n $SCORING_USER ]] && grep -w -- "$SCORING_USER" /etc/sudoers; } >"$t"
      if visudo -c -f "$t" >/dev/null 2>&1; then bak /etc/sudoers; cat "$t" >/etc/sudoers; chmod 0440 /etc/sudoers; did "/etc/sudoers reset"; else alert "new sudoers failed visudo; not installed"; fi; rm -f "$t"
    fi
  else ok "/etc/sudoers matches default"; fi

  section "CREDS: SSH authorized_keys (every user)"
  local akf akc; akf=$(sshd -T 2>/dev/null | awk '$1=="authorizedkeysfile"{$1=""; print}')
  akc=$(sshd -T 2>/dev/null | awk '$1=="authorizedkeyscommand"{print $2}')
  [[ -n $akc && $akc != none ]] && alert "sshd AuthorizedKeysCommand=$akc (services phase rewrites sshd_config)"
  [[ -z $akf ]] && akf=".ssh/authorized_keys .ssh/authorized_keys2"
  declare -A seenk=()
  while IFS=: read -r u _ _ _ _ home _; do
    for t in $akf .ssh/authorized_keys .ssh/authorized_keys2; do
      t=${t//%h/$home}; t=${t//%u/$u}; t=${t//%%/%}; [[ $t == /* ]] || t="$home/$t"
      [[ -s $t && -z ${seenk[$t]:-} ]] || continue; seenk[$t]=1
      alert "$t ($u): $(grep -cvE '^[[:space:]]*(#|$)' "$t") key(s)"
      ssh-keygen -lf "$t" 2>/dev/null | indent
      grep -nE '(command|environment|from|permitopen)=' "$t" | indent
      if [[ $u == "$SCORING_USER" ]]; then warn "SCORING_USER keys — left alone"; continue; fi
      gate 2 "Quarantine $t" && quarantine "$t"
    done
  done </etc/passwd

  section "CREDS: PAM"
  grep -HnE '^[^#]*(pam_exec|pam_listfile|pam_succeed_if|pam_permit|pam_rootok)' /etc/pam.d/* 2>/dev/null | while IFS= read -r line; do
    case "$line" in
      */common-session*:*'[default=1]'*pam_permit*|*/etc/pam.d/ch[fs][nh]:*pam_rootok*|*/etc/pam.d/runuser:*pam_rootok*) info "$line";;
      *pam_exec*) alert "$line";;
      *sufficient*pam_permit*|*success=done*pam_permit*|*'[default=ok]'*pam_permit*) alert "$line";;
      */etc/pam.d/su:*pam_rootok*|*/etc/pam.d/vsftpd:*pam_listfile*sense=deny*ftpusers*) info "$line";;
      *pam_permit*) [[ $line == */common-*:*required*pam_permit* ]] && info "$line" || warn "$line";;
      *) warn "$line";;
    esac
  done
  # comment out pam_exec and "sufficient pam_permit" lines
  while IFS=: read -r f n _; do
    gate 3 "Comment out $f line $n: $(sed -n "${n}p" "$f")" && { bak "$f"; sed -i "${n}s/^/#BLUE# /" "$f"; did "commented $f:$n"; }
  done < <(grep -HnE '^[^#]*(pam_exec|sufficient[[:space:]]+pam_permit)' /etc/pam.d/* 2>/dev/null)
  local m mb
  for m in /lib/*/security/*.so /usr/lib/*/security/*.so /lib/security/*.so /usr/lib/security/*.so; do
    [[ -f $m ]] || continue; owned "$m" && continue
    mb=$(basename "$m"); alert "PAM module NOT owned by any package: $m"
    grep -lsw -- "$mb" /etc/pam.d/* | indent
    if gate 3 "Comment out pam.d lines using $mb, then quarantine $m"; then
      for f in $(grep -lsw -- "$mb" /etc/pam.d/*); do bak "$f"; sed -i -E "/^[^#].*$mb/s/^/#BLUE# /" "$f"; done
      quarantine "$m"
    fi
  done
  for f in /usr/share/pam-configs/*; do [[ -f $f ]] && ! owned "$f" && alert "unowned pam-auth-update profile: $f"; done
  for f in /etc/security/access.conf /etc/security/limits.conf /etc/security/limits.d/* /etc/security/time.conf /etc/security/group.conf /etc/security/pam_env.conf; do
    [[ -f $f ]] || continue
    local act; act=$(grep -nvE '^[[:space:]]*(#|$)' "$f")
    [[ -z $act ]] && continue
    warn "$f has active lines:"; printf '%s\n' "$act" | indent
    if [[ $f == */access.conf ]] || grep -qE 'maxlogins|maxsyslogins|LD_PRELOAD' <<<"$act"; then
      gate 3 "Comment out active lines in $f" && { bak "$f"; sed -i -E 's/^([[:space:]]*[^#[:space:]])/#BLUE# \1/' "$f"; did "commented $f"; }
    fi
  done
  warn "after PAM edits: open a SECOND ssh session and test login before closing this one"

  section "CREDS: rotate root"
  if (( APPLY )); then
    if [[ -f $STATE/rotated-root && $ROTATE == 0 ]]; then info "root already rotated $(cat "$STATE/rotated-root") (use --rotate to do it again)"
    elif (( YES )) || confirm "Rotate root password now?"; then rotate_pw root; fi
    if [[ $ROLE == msgboard ]] && getent passwd usario >/dev/null; then
      if [[ -f $STATE/rotated-usario && $ROTATE == 0 ]]; then info "usario already rotated"
      elif confirm "Rotate usario (packet admin, default password) too?"; then rotate_pw usario; fi
    fi
  else plan "prompt for and rotate root password$([[ $ROLE == msgboard ]] && echo ' (+ usario)')"; fi
}

# =============================================================================
# PHASE: persistence
# =============================================================================
unit_pids(){ local name=$1 d; while IFS= read -r d; do find "$d" -name cgroup.procs -exec cat {} + 2>/dev/null; done < <(find /sys/fs/cgroup -type d -name "$name" 2>/dev/null) | sort -un; }
unit_payloads(){ # absolute unowned files referenced by Exec*= lines of a unit file
  local p; grep -E '^[[:space:]]*Exec[A-Za-z]*=' "$1" 2>/dev/null | cut -d= -f2- | grep -oE '/[^[:space:]"'"'"';|&)]+' | sort -u | while read -r p; do
    [[ -f $p ]] && ! owned "$p" && echo "$p"; done; }
procs_referencing(){ local path=$1 p c e w
  for p in /proc/[0-9]*; do c=$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null); e=$(readlink "$p/exe" 2>/dev/null); w=$(readlink "$p/cwd" 2>/dev/null)
    if [[ $c == *"$path"* || $e == "$path"* || $w == "$path"* ]]; then echo "${p#/proc/}"; fi; done; }
neutralize_path(){ local path=$1 pid
  for pid in $(procs_referencing "$path"); do [[ -n ${PROTECT_PID[$pid]:-} ]] && continue; info "$(psline "$pid")"; kill_pid "$pid" "$(pcmd "$pid")"; done
  quarantine "$path"; }
RELOAD=0
neutralize_unit(){ # rule 2: disable -> (move file) -> mask -> daemon-reload -> stop/kill -> payloads
  local f=$1 src=$2 name scope=system u="" pids=() cmds=() p i payloads=()
  name=$(basename "$f")
  case "$f" in */.config/systemd/user/*|*/.local/share/systemd/user/*) scope=user; u=$(stat -c %U "$f");;
               /etc/systemd/user/*|/usr/lib/systemd/user/*|/usr/local/lib/systemd/user/*) scope=global;; esac
  mapfile -t payloads < <(unit_payloads "$src")
  mapfile -t pids < <(unit_pids "$name"); for p in "${pids[@]}"; do cmds+=("$(pcmd "$p")"); done
  case $scope in system) systemctl disable "$name" >/dev/null 2>&1;; global) systemctl --global disable "$name" >/dev/null 2>&1;; esac
  while IFS= read -r -d '' p; do [[ $p == "$f" ]] && continue; quarantine "$p"; done < <(find /etc/systemd /run/systemd/system /usr/local/lib/systemd /home /root/.config/systemd -type l \( -name "$name" -o -lname "*/$name" \) -print0 2>/dev/null)
  quarantine "$f" "$f.d"
  [[ $src != "$f" && -e $src ]] && ! owned "$src" && quarantine "$src"
  [[ $scope == system ]] && systemctl mask "$name" >/dev/null 2>&1 && did "masked $name"
  systemctl daemon-reload
  [[ $scope == user && -n $u ]] && systemctl --user -M "$u@" daemon-reload >/dev/null 2>&1
  case $scope in system) systemctl stop "$name" >/dev/null 2>&1;; user) systemctl --user -M "$u@" stop "$name" >/dev/null 2>&1;; esac
  for i in "${!pids[@]}"; do kill_pid "${pids[$i]}" "${cmds[$i]}"; done
  for p in "${payloads[@]}"; do
    [[ -e $p ]] || continue
    alert "payload referenced by $name: $p"; gate 3 "Kill processes using and quarantine $p" && neutralize_path "$p"
  done; }

check_unit_file(){ local f=$1 name src t score=0 why=() desc exec pl
  name=$(basename "$f")
  if [[ -L $f ]]; then t=$(readlink -f "$f")
    if [[ $t == /dev/null ]]; then role_units | grep -qx "$name" && alert "scored unit $name is MASKED ($f) — services phase unmasks"; return; fi
    [[ -f $t ]] || return
    if owned "$t" && ! is_ioc_unit "$name"; then return; fi
    src=$t
  else src=$f; owned "$f" && return; fi
  unit_whitelisted "$name" && { info "unowned but whitelisted: $f"; return; }
  if [[ $name == snap-*.mount ]] && grep -q '^What=/var/lib/snapd/snaps/' "$src"; then return; fi
  if [[ $name == snap.* ]] && grep -q 'ExecStart=/usr/bin/snap run' "$src"; then return; fi
  desc=$(grep -m1 -E '^Description=' "$src" | cut -d= -f2-)
  exec=$(grep -E '^[[:space:]]*Exec[A-Za-z]*=' "$src" | cut -d= -f2-)
  is_ioc_unit "$name" && { score=$((score+3)); why+=(ioc-name); }
  [[ $desc == *"Initiation Services"* ]] && { score=$((score+3)); why+=(ioc-desc); }
  grep -qE "$SUS_RE" <<<"$exec" && { score=$((score+2)); why+=(sus-exec); }
  grep -qE '/\.[^/]|/tmp/|/dev/shm/|/var/tmp/' <<<"$exec" && { score=$((score+2)); why+=(hidden/tmp-path); }
  grep -qE '^Restart=always' "$src" && grep -qE '(ba)?sh -c|python|perl' <<<"$exec" && { score=$((score+1)); why+=(respawning-interp); }
  if (( score >= 2 )); then alert "SUSPICIOUS unit $f [${why[*]}] score=$score desc='$desc'"; else warn "unowned unit (review) $f desc='$desc'"; fi
  printf '%s\n' "$exec" | indent
  pl=$(unit_pids "$name" | tr '\n' ' '); [[ -n $pl ]] && info "      running pids: $pl"
  if (( score >= 3 )); then gate 3 "Neutralize $name (disable→mask→delete→reload→kill→payloads)" && neutralize_unit "$f" "$src"
  else gate "$score" "Neutralize $name (disable→mask→delete→reload→kill→payloads)" && neutralize_unit "$f" "$src"; fi; }

check_dropin(){ local f=$1 body s=1 parent
  owned "$f" && return; [[ $(basename "$f") == zz-blue-* ]] && return
  parent=$(basename "$(dirname "$f")"); parent=${parent%.d}
  body=$(grep -vE '^[[:space:]]*(#|$)' "$f")
  grep -qE '^(Exec[A-Za-z]*|Environment|EnvironmentFile|User|Group)=' <<<"$body" && s=2
  grep -qE "$SUS_RE|LD_PRELOAD|/bin/false|/bin/true|^ExecStart(Pre)?=-?/usr/bin/(false|true)" <<<"$body" && s=3
  role_units | grep -qx "$parent" && [[ $s -ge 2 ]] && s=3
  if (( s >= 2 )); then alert "unowned drop-in for $parent: $f (score $s)"; else warn "unowned drop-in for $parent: $f"; fi
  printf '%s\n' "$body" | indent
  gate "$s" "Quarantine drop-in $f" && { quarantine "$f"; RELOAD=1; }; }

scan_unowned_dir(){ # scan_unowned_dir LABEL DIR... : unowned files in hook dirs
  local label=$1 f s; shift
  while IFS= read -r -d '' f; do
    owned "$f" && continue
    [[ $(basename "$f") == zz-blue* || $f == *.bak.* ]] && continue
    s=2; grep -qsE "$SUS_RE|Invoke|RUN\+=|install .*/" "$f" && s=3
    alert "$label: unowned $f (score $s)"; grep -nE "$SUS_RE|Invoke|RUN\+=|^install" "$f" 2>/dev/null | head -5 | indent
    gate "$s" "Quarantine $f" && quarantine "$f"
  done < <(find "$@" -xdev \( -type f -o -type l \) -print0 2>/dev/null); }

sys_rc_default(){ case "$1" in
/etc/bash.bashrc) cat <<'EOF'
# System-wide .bashrc file for interactive bash(1) shells. (restored by blue.sh)
[ -z "${PS1-}" ] && return
shopt -s checkwinsize
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
EOF
;;
/etc/profile) cat <<'EOF'
# /etc/profile: system-wide .profile file for the Bourne shell (restored by blue.sh)
if [ "${PS1-}" ]; then
  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then
    if [ -f /etc/bash.bashrc ]; then
      . /etc/bash.bashrc
    fi
  else
    if [ "$(id -u)" -eq 0 ]; then PS1='# '; else PS1='$ '; fi
  fi
fi
if [ -d /etc/profile.d ]; then
  for i in /etc/profile.d/*.sh; do
    if [ -r $i ]; then . $i; fi
  done
  unset i
fi
EOF
;;
/etc/environment) echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"';;
/etc/skel/.bash_logout) printf '%s\n' '# ~/.bash_logout (restored by blue.sh)' 'if [ "$SHLVL" = 1 ]; then [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q; fi';;
/etc/skel/.profile) cat <<'EOF'
# ~/.profile (restored by blue.sh)
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then . "$HOME/.bashrc"; fi
fi
if [ -d "$HOME/bin" ] ; then PATH="$HOME/bin:$PATH"; fi
if [ -d "$HOME/.local/bin" ] ; then PATH="$HOME/.local/bin:$PATH"; fi
EOF
;;
/etc/skel/.bashrc) cat <<'EOF'
# ~/.bashrc (minimal clean version restored by blue.sh)
case $- in *i*) ;; *) return;; esac
HISTCONTROL=ignoreboth
shopt -s histappend checkwinsize
HISTSIZE=1000
HISTFILESIZE=2000
PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
alias ls='ls --color=auto'
alias grep='grep --color=auto'
alias ll='ls -alF'
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then . /etc/bash_completion; fi
fi
EOF
;;
*) return 1;; esac; }

phase_persistence(){
  load_owned
  local d f rd u uid home x
  section "PERSISTENCE: systemd units / timers / drop-ins (system + user)"
  local dirs=(/etc/systemd/system /run/systemd/system /run/systemd/transient /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/systemd/user /usr/lib/systemd/user /usr/local/lib/systemd/user)
  while IFS=: read -r _ _ _ _ _ home _; do [[ -d $home && $home != / ]] && dirs+=("$home/.config/systemd/user" "$home/.local/share/systemd/user"); done </etc/passwd
  declare -A seen=()
  for d in "${dirs[@]}"; do
    [[ -d $d ]] || continue; rd=$(readlink -f "$d"); [[ -n ${seen[$rd]:-} ]] && continue; seen[$rd]=1
    while IFS= read -r -d '' f; do check_unit_file "$f"; done < <(find "$d" -maxdepth 1 \( -type f -o -type l \) \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.mount' -o -name '*.target' \) -print0 2>/dev/null)
    while IFS= read -r -d '' f; do check_dropin "$f"; done < <(find "$d" -mindepth 2 -maxdepth 2 -path '*.d/*' -name '*.conf' -type f -print0 2>/dev/null)
  done
  (( RELOAD )) && systemctl daemon-reload
  for x in "${IOC_UNITS[@]}"; do
    systemctl list-units --all --no-legend "$x*" 2>/dev/null | grep -q . && alert "IOC unit still loaded: $(systemctl list-units --all --no-legend "$x*" | head -1)"
  done
  scan_unowned_dir "systemd generator" /etc/systemd/system-generators /usr/local/lib/systemd/system-generators /etc/systemd/user-generators /usr/local/lib/systemd/user-generators
  grep -HnsE 'DefaultEnvironment|ManagerEnvironment' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/* /etc/systemd/user.conf.d/* | grep -v ':#' | while read -r x; do alert "systemd manager env: $x"; done
  for f in /var/lib/systemd/linger/*; do [[ -e $f ]] || continue; u=$(basename "$f")
    [[ $u == "$SCORING_USER" ]] && { info "linger: $u (SCORING_USER)"; continue; }
    warn "user lingering (user systemd survives logout): $u"; gate 2 "Remove linger for $u" && quarantine "$f"; done

  section "PERSISTENCE: cron / at / anacron"
  for f in /etc/crontab /etc/anacrontab; do [[ -f $f ]] || continue
    grep -nE "$SUS_RE" "$f" | while read -r x; do alert "$f: $x"; done; done
  dpkg --verify cron 2>/dev/null | grep -q crontab && alert "/etc/crontab modified vs package (integrity phase restores)"
  scan_unowned_dir "cron" /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly
  for f in /var/spool/cron/crontabs/* /var/spool/cron/[!ac]*; do
    [[ -f $f ]] || continue
    local s=2; grep -qE "$SUS_RE" "$f" && s=3
    alert "user crontab $f (score $s):"; grep -vE '^[[:space:]]*(#|$)' "$f" | indent
    if [[ $(basename "$f") == "$SCORING_USER" ]]; then warn "SCORING_USER crontab — left alone"; continue; fi
    gate "$s" "Quarantine crontab $f" && quarantine "$f"
  done
  if command -v atq >/dev/null; then
    while read -r x _; do [[ -z $x ]] && continue; alert "at job $x:"; at -c "$x" 2>/dev/null | tail -5 | indent; gate 3 "atrm $x" && atrm "$x" && did "removed at job $x"; done < <(atq 2>/dev/null)
  fi
  for f in /var/spool/cron/atjobs/*; do [[ -f $f ]] && alert "at spool file: $f"; done

  section "PERSISTENCE: rc.local / init.d"
  if [[ -e /etc/rc.local ]]; then alert "/etc/rc.local exists:"; grep -vE '^[[:space:]]*(#|$)' /etc/rc.local | indent; gate 3 "Quarantine /etc/rc.local" && quarantine /etc/rc.local; fi
  scan_unowned_dir "init.d" /etc/init.d

  section "PERSISTENCE: login shell hooks (profile.d, bash.bashrc, skel, fish, zsh)"
  for f in /etc/profile.d/* /etc/fish/conf.d/* /etc/fish/functions/* /etc/zsh/zshrc.d/*; do
    [[ -f $f ]] || continue; owned "$f" && { grep -qE "$RC_RE" "$f" && alert "package file $f contains hook patterns (modified?)"; continue; }
    local s=2; grep -qE "$RC_RE" "$f" && s=3
    alert "unowned shell hook $f (score $s)"; grep -nE "$RC_RE" "$f" | head -5 | indent
    gate "$s" "Quarantine $f" && quarantine "$f"
  done
  for f in /etc/bash.bashrc /etc/profile /etc/environment /etc/bash.bash_logout /etc/zsh/zshrc /etc/zsh/zshenv /etc/zsh/zprofile /etc/fish/config.fish /etc/inputrc /etc/skel/.bashrc /etc/skel/.profile /etc/skel/.bash_logout; do
    [[ -f $f ]] || continue
    local hits; hits=$(grep -nE "$RC_RE" "$f" | grep -v -- '--color=auto')
    [[ -n $hits ]] || continue
    alert "$f contains hook patterns:"; printf '%s\n' "$hits" | head -8 | indent
    if sys_rc_default "$f" >/dev/null; then gate 3 "Replace $f with clean default" && { bak "$f"; sys_rc_default "$f" >"$f"; chmod 644 "$f"; did "$f restored"; }
    else gate 3 "Comment out matching lines in $f" && { bak "$f"; while IFS=: read -r n _; do sed -i "${n}s/^/#BLUE# /" "$f"; done <<<"$hits"; did "$f lines commented"; }; fi
  done

  section "PERSISTENCE: every user's shell rc files"
  declare -A seenh=()
  while IFS=: read -r u _ uid _ _ home _; do
    [[ -d $home && $home != / && -z ${seenh[$home]:-} ]] || continue; seenh[$home]=1
    for f in "$home"/.bashrc "$home"/.bash_profile "$home"/.bash_login "$home"/.bash_logout "$home"/.profile "$home"/.bash_aliases \
             "$home"/.zshrc "$home"/.zprofile "$home"/.zshenv "$home"/.zlogin "$home"/.config/fish/config.fish \
             "$home"/.config/fish/conf.d/*.fish "$home"/.config/fish/functions/*.fish "$home"/.ssh/rc "$home"/.inputrc "$home"/.vimrc; do
      [[ -f $f ]] || continue
      local hits; hits=$(grep -nE "$RC_RE" "$f" | grep -v -- '--color=auto')
      [[ $f == */.ssh/rc ]] && hits=${hits:-"(file exists — runs on every ssh login)"}
      [[ -n $hits ]] || continue
      alert "$f ($u):"; printf '%s\n' "$hits" | head -8 | indent
      local b; b=$(basename "$f")
      if [[ $b == .bashrc || $b == .profile || $b == .bash_logout ]] && [[ -f /etc/skel/$b ]]; then
        gate 3 "Replace $f with /etc/skel/$b" && { bak "$f"; cp -f "/etc/skel/$b" "$f"; chown "$u:" "$f" 2>/dev/null; did "$f reset"; }
      else gate 3 "Quarantine $f" && quarantine "$f"; fi
    done
  done </etc/passwd
  [[ -f /etc/ssh/sshrc ]] && { alert "/etc/ssh/sshrc exists (runs on every ssh login)"; gate 3 "Quarantine /etc/ssh/sshrc" && quarantine /etc/ssh/sshrc; }

  section "PERSISTENCE: motd / udev / apt hooks / misc hook dirs"
  scan_unowned_dir "update-motd" /etc/update-motd.d
  scan_unowned_dir "udev" /etc/udev/rules.d /usr/local/lib/udev/rules.d
  scan_unowned_dir "apt hook" /etc/apt/apt.conf.d
  scan_unowned_dir "dispatcher/ifup" /etc/NetworkManager/dispatcher.d /etc/network/if-up.d /etc/network/if-pre-up.d /etc/dhcp/dhclient-exit-hooks.d /etc/ppp/ip-up.d /etc/networkd-dispatcher
  scan_unowned_dir "logrotate" /etc/logrotate.d
  scan_unowned_dir "sleep hook" /etc/systemd/system-sleep /usr/lib/systemd/system-sleep
  scan_unowned_dir "autostart" /etc/xdg/autostart
  scan_unowned_dir "polkit" /etc/polkit-1/rules.d /etc/PackageKit
  scan_unowned_dir "ld.so.conf.d" /etc/ld.so.conf.d
  scan_unowned_dir "modules" /etc/modules-load.d /etc/modprobe.d
  [[ -s /etc/motd ]] && { info "/etc/motd:"; head -5 /etc/motd | indent; }
  for f in /usr/local/bin/* /usr/local/sbin/*; do
    [[ -f $f ]] || continue; owned "$f" && continue
    if [[ -e /usr/bin/$(basename "$f") || -e /usr/sbin/$(basename "$f") || -e /bin/$(basename "$f") ]]; then
      alert "$f SHADOWS a system binary of the same name"; gate 3 "Quarantine $f" && neutralize_path "$f"
    else warn "unowned in /usr/local: $f"; fi
  done

  section "PERSISTENCE: ld.so.preload / LD_PRELOAD"
  if [[ -s /etc/ld.so.preload ]]; then
    alert "/etc/ld.so.preload:"; indent </etc/ld.so.preload
    if gate 3 "Quarantine /etc/ld.so.preload and the libraries it lists"; then
      local libs; libs=$(grep -vE '^[[:space:]]*(#|$)' /etc/ld.so.preload)
      quarantine /etc/ld.so.preload
      for x in $libs; do [[ -f $x ]] && ! owned "$x" && quarantine "$x"; done; ldconfig
    fi
  else ok "no /etc/ld.so.preload"; fi
  grep -lsE 'LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT' /etc/environment /etc/environment.d/* /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/security/pam_env.conf /etc/default/* /etc/systemd/system/*.d/* 2>/dev/null | while read -r f; do alert "LD_* variable set in $f"; done
  for f in /proc/[0-9]*/environ; do grep -qasE 'LD_PRELOAD=|LD_AUDIT=' "$f" 2>/dev/null && { x=${f#/proc/}; x=${x%/environ}; alert "process $x has LD_PRELOAD/LD_AUDIT: $(pcmd "$x")"; }; done

  section "PERSISTENCE: IOC paths, implant names, hidden dirs"
  for x in "${IOC_PATHS[@]}"; do [[ -e $x ]] && { alert "IOC path present: $x"; ls -la "$x" 2>/dev/null | head -10 | indent; gate 3 "Kill users of and quarantine $x" && neutralize_path "$x"; }; done
  while IFS= read -r -d '' f; do
    [[ $f == /root/blue-* ]] && continue
    alert "implant-named file: $f"; gate 3 "Kill users of and quarantine $f" && neutralize_path "$f"
  done < <(find / -xdev \( "${IOC_FIND[@]}" \) -not -path '/proc/*' -not -path '/root/blue-*' -print0 2>/dev/null)
  while IFS= read -r -d '' f; do
    [[ -e $f ]] || continue
    case "$f" in /etc/.pwd.lock|/etc/skel/*|/etc/.git|/etc/.etckeeper|/etc/.gitignore|/etc/.updated|/var/.updated|/tmp/.X11-unix|/tmp/.ICE-unix|/tmp/.font-unix|/tmp/.XIM-unix|/tmp/.Test-unix|/root/blue-*) continue;; esac
    owned "$f" && continue
    local base; base=$(basename "$f"); local s=1
    [[ $base =~ ^[.[:space:]]+$ ]] && s=3                                   # "...", ". ", etc.
    [[ -d $f ]] && find "$f" -maxdepth 3 -type f \( -perm /111 -o -name '*.py' -o -name '*.sh' -o -name '*.pl' \) 2>/dev/null | grep -q . && s=3
    [[ -f $f && -x $f ]] && s=3
    if (( s >= 3 )); then alert "hidden: $f"; ls -la "$f" 2>/dev/null | head -8 | indent; gate 3 "Kill users of and quarantine $f" && neutralize_path "$f"
    else info "hidden (low): $f"; fi
  done < <({ find / -xdev -mindepth 1 -maxdepth 1 -name '.*' -print0; find /etc /usr /var -xdev -mindepth 1 -maxdepth 4 -name '.*' -print0; find /tmp /var/tmp /dev/shm -mindepth 1 -maxdepth 3 -name '.*' -print0; } 2>/dev/null)

  section "PERSISTENCE: setuid/setgid + file capabilities not from packages"
  while IFS= read -r -d '' f; do
    owned "$f" && continue; [[ $f == /root/blue-* ]] && continue
    alert "unowned setuid/setgid: $(ls -l "$f")"; gate 3 "chmod u-s,g-s $f" && { chmod u-s,g-s "$f"; did "stripped suid/sgid $f"; }
  done < <(find / -xdev -type f -perm /6000 -print0 2>/dev/null)
  if command -v getcap >/dev/null; then
    getcap -r /usr /bin /sbin /opt /home /tmp /var /root /srv /etc 2>/dev/null | while read -r f x; do
      owned "$f" && continue; alert "unowned file with capabilities: $f $x"
      gate 3 "setcap -r $f" && setcap -r "$f" && did "caps removed $f"
    done
  fi

  section "PERSISTENCE: kernel modules"
  local tainted m fn; tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null)
  [[ $tainted != 0 ]] && warn "kernel taint flags = $tainted"
  while read -r m _; do
    fn=$(modinfo -n "$m" 2>/dev/null)
    [[ -z $fn || $fn == "(builtin)" ]] && continue
    owned "$fn" || alert "module $m loaded from unowned file $fn (manual: rmmod $m)"
    x=$(cat "/sys/module/$m/taint" 2>/dev/null); [[ $x == *O* || $x == *E* ]] && warn "module $m taint '$x' (out-of-tree/unsigned)"
  done </proc/modules
  for d in /sys/module/*; do m=$(basename "$d"); [[ -f $d/initstate ]] || continue
    grep -q "^$m " /proc/modules || alert "module $m in /sys/module but hidden from /proc/modules (rootkit?)"; done
  grep -HnsE '^[[:space:]]*install[[:space:]]' /etc/modprobe.d/* | grep -vE '/bin/(true|false)' | while read -r x; do alert "modprobe install hook: $x"; done
}

# =============================================================================
# PHASE: shells
# =============================================================================
phase_shells(){
  load_owned
  local ports p line proto la port proc
  ports=" $(role_tcp_ports) "
  section "SHELLS: listening sockets"
  while read -r proto _ _ _ la _ proc; do
    port=${la##*:}
    case "$la" in 127.*|\[::1\]*|*%lo:*) info "local-only $proto $la $proc"; continue;; esac
    if [[ $proto == tcp && $ports == *" $port "* ]]; then ok "$proto $la $proc"
    elif [[ $ROLE == file && $proto == udp && $port =~ ^(137|138)$ ]]; then ok "$proto $la $proc"
    elif [[ $proto == udp && $port =~ ^(68|546|5353|323)$ ]]; then info "$proto $la $proc"
    else alert "unexpected listener: $proto $la $proc"; fi
  done < <(ss -tulnpH 2>/dev/null)

  section "SHELLS: established connections"
  local lport peer pport
  while read -r proto st _ _ la peer proc; do
    [[ $st == ESTAB ]] || continue
    lport=${la##*:}; pport=${peer##*:}; peer=${peer%:*}; peer=${peer#[}; peer=${peer%]}
    if [[ $ports == *" $lport "* || ($ROLE == file && $lport -ge $FTP_PASV_MIN && $lport -le $FTP_PASV_MAX) ]]; then info "inbound  $proto $la <- $peer:$pport $proc"; continue; fi
    case "$peer" in 127.*|::1) continue;; esac
    if [[ $ROLE == web && $peer == "$FILE_IP" && $pport =~ ^(445|139)$ ]]; then ok "outbound CIFS to file server $peer:$pport"; continue; fi
    if [[ $pport == 53 && ( $peer == "$ROUTER" || $peer == "$DC" ) ]]; then info "outbound DNS $peer"; continue; fi
    local comm=""; [[ $proc =~ \(\(\"([^\"]+)\" ]] && comm=${BASH_REMATCH[1]}
    if [[ $comm =~ $INTERP_RE ]]; then alert "OUTBOUND from interpreter: $proto $la -> $peer:$pport $proc"
    else warn "outbound $proto $la -> $peer:$pport $proc"; fi
  done < <(ss -tunapH 2>/dev/null)
  pgrep -a cloudflared >/dev/null 2>&1 && warn "cloudflared is running here — egress firewall will allow 443/7844 for it"

  section "SHELLS: suspicious processes"
  declare -A INET=()
  local ino; while read -r ino; do [[ $ino != 0 ]] && INET[$ino]=1; done < <(awk 'FNR>1{print $10}' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null)
  local SP=() SC=() SU=() pid cmd comm exe unit reasons fd lnk ufile
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}; [[ -n ${PROTECT_PID[$pid]:-} || $pid == "$BASHPID" ]] && continue
    cmd=$(pcmd "$pid"); [[ -z $cmd ]] && continue
    comm=$(awk '/^Name:/{print $2; exit}' "$p/status" 2>/dev/null)
    exe=$(readlink "$p/exe" 2>/dev/null)
    unit=$(grep -oE '[^/]+\.(service|scope)$' "$p/cgroup" 2>/dev/null | tail -1)
    reasons=()
    [[ $exe == *" (deleted)" ]] && reasons+=(deleted-exe)
    [[ $exe =~ ^(/tmp/|/dev/shm/|/var/tmp/|/run/user/)|/\.[^/]+/ ]] && reasons+=(exe-in-tmp/hidden)
    [[ $cmd =~ $PROC_RE ]] && reasons+=(cmdline)
    if [[ $comm =~ $INTERP_RE ]]; then
      for fd in "$p"/fd/*; do lnk=$(readlink "$fd" 2>/dev/null); [[ $lnk =~ ^socket:\[([0-9]+)\]$ && -n ${INET[${BASH_REMATCH[1]}]:-} ]] && { [[ $unit =~ $LEGIT_SVC_RE ]] || reasons+=(interpreter-with-inet-socket); break; }; done
    fi
    if [[ $unit == *.service ]]; then
      is_ioc_unit "$unit" && reasons+=("ioc-unit:$unit")
      ufile=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)
      [[ -n $ufile && -f $ufile ]] && ! owned "$ufile" && ! unit_whitelisted "$unit" && ! [[ $unit =~ $LEGIT_SVC_RE ]] && reasons+=("unowned-unit:$unit")
    fi
    grep -qasE 'LD_PRELOAD=|LD_AUDIT=' "$p/environ" 2>/dev/null && reasons+=(ld_preload)
    (( ${#reasons[@]} )) || continue
    alert "pid $pid [${reasons[*]}] unit=${unit:-?}"; psline "$pid" | indent
    SP+=("$pid"); SC+=("$cmd"); SU+=("$unit")
  done
  (( ${#SP[@]} )) || ok "nothing suspicious"
  local i
  for i in "${!SP[@]}"; do
    pid=${SP[$i]}; unit=${SU[$i]}
    if [[ $unit == *.service ]] && ! [[ $unit =~ $LEGIT_SVC_RE ]]; then
      ufile=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)
      if [[ -n $ufile && -f $ufile ]] && ! owned "$ufile"; then
        warn "pid $pid belongs to unowned unit $unit — neutralizing the unit first (rule 2)"
        gate 3 "Neutralize $unit ($ufile) then kill" && neutralize_unit "$ufile" "$(readlink -f "$ufile")"
      fi
    fi
    [[ -d /proc/$pid ]] || continue
    if gate 3 "Kill pid $pid: ${SC[$i]}"; then
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null); exe=${exe% (deleted)}
      kill_pid "$pid" "${SC[$i]}"
      [[ -n $exe && -f $exe ]] && ! owned "$exe" && { gate 3 "Quarantine executable $exe" && quarantine "$exe"; }
    fi
  done
}

# =============================================================================
# PHASE: integrity
# =============================================================================
APT_OK=""
apt_ok(){ if [[ -z $APT_OK ]]; then
    local out; out=$(timeout 120 apt-get update 2>&1); local rc=$?
    if (( rc == 0 )) && ! grep -qiE 'Failed to fetch|Could not resolve|Temporary failure|Unable to connect' <<<"$out"; then APT_OK=0; else APT_OK=1; warn "apt is offline/failing"; fi
  fi; return "$APT_OK"; }
cached_deb(){ local p=${1%%:*} v; v=$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null); v=${v//:/%3a}; ls /var/cache/apt/archives/"${p}_${v}"_*.deb 2>/dev/null | head -1; }
reinstall_pkgs(){ local p deb
  if apt_ok && DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y -o Dpkg::Options::=--force-confold "$@"; then did "reinstalled: $*"; return 0; fi
  warn "apt reinstall failed; trying cached .debs"
  for p in "$@"; do deb=$(cached_deb "$p"); if [[ -n $deb ]]; then dpkg -i --force-confold "$deb" >/dev/null && did "reinstalled $p from cache"; else warn "no cached .deb for $p"; fi; done; }
restore_conffile(){ local f=$1 pkg tmp deb
  pkg=$(dpkg -S "$f" 2>/dev/null | head -1 | sed 's/: .*//; s/, .*//')
  bak "$f"; tmp="$BAKDIR$f.moved"; mkdir -p "$(dirname "$tmp")"; mv -f "$f" "$tmp"
  if [[ -n $pkg ]]; then
    if apt_ok; then DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y -o Dpkg::Options::=--force-confmiss -o Dpkg::Options::=--force-confold "$pkg" >/dev/null 2>&1
    else deb=$(cached_deb "$pkg"); [[ -n $deb ]] && dpkg -i --force-confmiss --force-confold "$deb" >/dev/null 2>&1; fi
  fi
  if [[ -e $f ]]; then did "restored $f from package $pkg"; return 0; fi
  if sys_rc_default "$f" >"$f" 2>/dev/null; then chmod 644 "$f"; did "wrote clean default $f (package reinstall unavailable)"; return 0; fi
  rm -f "$f"; mv -f "$tmp" "$f"; alert "could not restore $f — original put back"; }

CRIT_PKGS=(bash coreutils openssh-server openssh-client openssh-sftp-server samba samba-common-bin vsftpd libpam-modules libpam-modules-bin libpam-runtime libpam0g sudo procps iproute2 systemd passwd login util-linux findutils grep sed cifs-utils curl net-tools)
phase_integrity(){
  local line attrs typ path pkg modbin=() modconf=() pkgs=() x
  section "INTEGRITY: dpkg --verify (this takes a minute)"
  while read -r line; do
    attrs=$(awk '{print $1}' <<<"$line"); path=$(awk '{print $NF}' <<<"$line"); typ=$(awk 'NF==3{print $2}' <<<"$line")
    [[ $attrs == missing || ${attrs:2:1} == 5 ]] || continue
    if [[ $typ == c ]]; then modconf+=("$path"); else modbin+=("$path"); fi
  done < <(dpkg --verify 2>/dev/null)
  for path in "${modbin[@]}"; do
    pkg=$(dpkg -S "$path" 2>/dev/null | head -1 | sed 's/: .*//; s/, .*//')
    alert "modified/missing package file: $path ($pkg)"; [[ -n $pkg ]] && pkgs+=("$pkg")
  done
  for path in "${modconf[@]}"; do warn "modified conffile: $path"; done
  (( ${#modbin[@]} )) || ok "no modified non-config package files"
  if command -v debsums >/dev/null; then info "debsums -c second opinion:"; debsums -c 2>/dev/null | head -40 | indent; fi
  mapfile -t pkgs < <(printf '%s\n' "${pkgs[@]}" | sort -u | grep .)
  if (( ${#pkgs[@]} )); then gate 3 "Reinstall packages with modified files: ${pkgs[*]}" && reinstall_pkgs "${pkgs[@]}"; fi
  local inst=(); for x in "${CRIT_PKGS[@]}"; do dpkg-query -W -f='${Status}' "$x" 2>/dev/null | grep -q 'ok installed' && inst+=("$x"); done
  info "a rootkit can also edit /var/lib/dpkg md5sums — reinstalling critical packages anyway is cheap insurance"
  gate 2 "Reinstall critical packages regardless (${inst[*]})" && reinstall_pkgs "${inst[@]}"

  section "INTEGRITY: shell rc + PAM + sudoers conffiles"
  for path in "${modconf[@]}"; do
    case "$path" in
      /etc/bash.bashrc|/etc/profile|/etc/skel/*|/etc/pam.d/*|/etc/sudoers|/etc/security/*|/etc/crontab|/etc/environment|/etc/login.defs|/etc/bash.bash_logout|/etc/inputrc)
        gate 3 "Restore $path from its package" && restore_conffile "$path";;
    esac
  done
  for x in /etc/bash.bashrc /etc/profile; do
    if grep -qE "$RC_RE" "$x" 2>/dev/null; then alert "$x still has hook patterns"; gate 3 "Write clean default $x" && { bak "$x"; sys_rc_default "$x" >"$x"; chmod 644 "$x"; did "$x clean"; }; fi
  done
  load_owned
  local unowned_pc=0; for x in /usr/share/pam-configs/*; do [[ -f $x ]] && ! owned "$x" && { alert "unowned pam-config $x"; unowned_pc=1; }; done
  if (( unowned_pc == 0 )); then gate 2 "Regenerate /etc/pam.d/common-* with pam-auth-update --force" && { bak /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; DEBIAN_FRONTEND=noninteractive pam-auth-update --force --package >/dev/null 2>&1 && did "pam common-* regenerated"; }
  else warn "fix unowned pam-configs before pam-auth-update (creds phase)"; fi

  section "INTEGRITY: root dotfiles"
  for x in .bashrc .profile; do
    [[ -f /etc/skel/$x ]] || continue
    if ! cmp -s "/etc/skel/$x" "/root/$x"; then warn "/root/$x differs from /etc/skel/$x"; fi
  done
  gate 3 "Reset /root/.bashrc and /root/.profile from /etc/skel" && for x in .bashrc .profile; do [[ -f /etc/skel/$x ]] && { bak "/root/$x"; cp -f "/etc/skel/$x" "/root/$x"; did "/root/$x reset"; }; done
  for x in /root/.bash_profile /root/.bash_login /root/.bash_aliases /root/.zshrc /root/.config/fish /root/.ssh/rc /root/.inputrc; do
    [[ -e $x ]] && { warn "$x exists"; gate 2 "Quarantine $x" && quarantine "$x"; }
  done
  if [[ $(grep -cvE '^[[:space:]]*(#|$)' /etc/environment 2>/dev/null) -gt 1 ]] || grep -qE 'LD_|PROMPT|BASH_ENV' /etc/environment 2>/dev/null; then
    alert "/etc/environment has extra content:"; indent </etc/environment
    gate 3 "Reset /etc/environment to default PATH" && { bak /etc/environment; sys_rc_default /etc/environment >/etc/environment; did "/etc/environment reset"; }
  fi
  gate 2 "Reset scored users' .bashrc/.profile/.bash_logout from /etc/skel" && for x in "${SCORED_USERS[@]}"; do
    local h; h=$(getent passwd "$x" | cut -d: -f6); [[ -d $h ]] || continue
    for f in .bashrc .profile .bash_logout; do [[ -f /etc/skel/$f ]] && { bak "$h/$f"; cp -f "/etc/skel/$f" "$h/$f"; chown "$x:" "$h/$f"; }; done; did "$x dotfiles reset"
  done
}

# =============================================================================
# PHASE: services
# =============================================================================
fix_icmp(){ local v6 v files
  v=$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null); v6=$(sysctl -n net.ipv6.icmp.echo_ignore_all 2>/dev/null)
  files=$(grep -lsrE '^[[:space:]]*net[./]ipv(4[./]icmp_echo_ignore_all|6[./]icmp[./]echo_ignore_all)[[:space:]]*=[[:space:]]*1' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d 2>/dev/null)
  if [[ $v == 0 && ${v6:-0} == 0 && -z $files ]]; then ok "ICMP echo not ignored by sysctl"; return; fi
  alert "ICMP echo ignored: ipv4=$v ipv6=${v6:-?} files: ${files//$'\n'/ }"
  if want "Set icmp_echo_ignore_all=0 now and persistently (comment out the red-team sysctl lines)"; then
    local f; for f in $files; do bak "$f"; sed -i -E 's/^([[:space:]]*net[./]ipv(4[./]icmp_echo_ignore_all|6[./]icmp[./]echo_ignore_all))/#BLUE# \1/' "$f"; done
    sysctl -qw net.ipv4.icmp_echo_ignore_all=0; sysctl -qw net.ipv6.icmp.echo_ignore_all=0 2>/dev/null
    printf 'net.ipv4.icmp_echo_ignore_all = 0\nnet.ipv6.icmp.echo_ignore_all = 0\n' >/etc/sysctl.d/zz-blue.conf
    did "ICMP echo re-enabled"
  fi; }

cfgsum(){ cat "$@" 2>/dev/null | md5sum | cut -d" " -f1; }
ensure_unit_up(){ # ensure_unit_up UNIT [restart]
  local u=$1 force=${2:-} d f
  [[ -z $u ]] && return
  systemctl cat "$u" >/dev/null 2>&1 || { alert "$u: unit not found"; return 1; }
  if [[ $(systemctl is-enabled "$u" 2>/dev/null) == masked ]]; then alert "$u is MASKED"; want "Unmask $u" && systemctl unmask "$u" >/dev/null 2>&1; fi
  for d in /etc/systemd/system/"$u".d /run/systemd/system/"$u".d /usr/local/lib/systemd/system/"$u".d; do
    for f in "$d"/*.conf; do [[ -f $f ]] || continue; [[ $(basename "$f") == zz-blue-* ]] && continue; owned "$f" && continue
      warn "foreign drop-in on scored unit $u: $f"; indent <"$f"; gate 3 "Quarantine $f" && quarantine "$f"; done
  done
  if [[ ! -f /etc/systemd/system/$u.d/zz-blue-restart.conf ]]; then
    want "Add Restart=always/RestartSec=3 drop-in to $u" && { mkdir -p "/etc/systemd/system/$u.d"; printf '[Unit]\nStartLimitIntervalSec=0\n\n[Service]\nRestart=always\nRestartSec=3\n' >"/etc/systemd/system/$u.d/zz-blue-restart.conf"; }
  fi
  (( APPLY )) && systemctl daemon-reload
  [[ $(systemctl is-enabled "$u" 2>/dev/null) == enabled ]] || { warn "$u not enabled"; want "Enable $u" && systemctl enable "$u" >/dev/null 2>&1; }
  if [[ -n $force ]]; then want "Restart $u" && { systemctl restart "$u" && did "$u restarted" || alert "$u failed to restart: $(systemctl status "$u" --no-pager -n 5 2>&1 | tail -5)"; }
  elif ! systemctl is-active --quiet "$u"; then alert "$u is not running"; want "Start $u" && { systemctl restart "$u" && did "$u started" || alert "$u failed: $(journalctl -u "$u" -n 5 --no-pager 2>&1 | tail -5)"; }
  else ok "$u active"; fi; }

svc_sshd(){
  section "SERVICES: sshd"
  local cfg=/etc/ssh/sshd_config new rl="$ROOT_LOGIN_MODE" su before
  before=$(cfgsum "$cfg")
  grep -HnsiE '^[[:space:]]*(AllowUsers|DenyUsers|AllowGroups|DenyGroups|Match|ForceCommand|AuthorizedKeysCommand|PermitEmptyPasswords|ListenAddress|Port|UsePAM|PasswordAuthentication|ChrootDirectory|PermitUserEnvironment|AuthorizedKeysFile|Banner|MaxAuthTries|MaxSessions|MaxStartups)' "$cfg" /etc/ssh/sshd_config.d/*.conf | indent
  ssh-keygen -A >/dev/null 2>&1
  if (( APPLY )) && [[ ${SSH_CONNECTION:-} != "" && $rl == prohibit-password ]]; then
    warn "PermitRootLogin prohibit-password blocks NEW root password logins over SSH (this session survives; console/Proxmox still work)."
    confirm "Use prohibit-password? (n = keep 'yes')" || rl=yes
  fi
  new=$(mktemp)
  cat >"$new" <<EOF
# Written by blue.sh $TS — no Include on purpose (sshd_config.d is ignored)
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin $rl
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
PrintMotd no
MaxAuthTries 6
MaxStartups 30:30:100
LoginGraceTime 30
ClientAliveInterval 300
AcceptEnv LANG LC_*
Subsystem sftp $( [[ -x /usr/lib/openssh/sftp-server ]] && echo /usr/lib/openssh/sftp-server || echo internal-sftp )
EOF
  if ! sshd -t -f "$new" 2>/dev/null; then sed -i '/^HostKey .*ecdsa/d' "$new"; fi
  if cmp -s "$new" "$cfg"; then ok "sshd_config already blue's version"
  elif ! sshd -t -f "$new"; then alert "generated sshd_config fails sshd -t — not installing"
  elif want "Install known-good /etc/ssh/sshd_config (PasswordAuthentication yes, no Allow/Deny/Match traps, PermitRootLogin $rl)"; then
    bak "$cfg"; cat "$new" >"$cfg"; chmod 644 "$cfg"; did "sshd_config written"
  fi
  rm -f "$new"
  su=$(ssh_unit)
  if systemctl is-enabled ssh.socket >/dev/null 2>&1 && [[ $(systemctl is-enabled ssh.socket 2>/dev/null) == enabled ]]; then
    warn "ssh uses socket activation (ssh.socket)"
    want "Switch to classic ssh.service (more robust with Restart=always)" && { systemctl disable --now ssh.socket >/dev/null 2>&1; systemctl enable ssh.service >/dev/null 2>&1; }
  fi
  local rs=""; [[ $(cfgsum "$cfg") != "$before" ]] && rs=restart
  sshd -t && ensure_unit_up "$su" $rs; }

svc_web(){
  section "SERVICES: rum web app"
  local cfg=/opt/rum/config.toml u mp line before
  before=$(cfgsum "$cfg" /etc/fstab)
  u=$(rum_unit)
  [[ -z $u ]] && alert "no rum systemd unit found (grep /opt/rum in units). Check how rum is started: ps -ef | grep rum"
  [[ -n $u ]] && { info "rum unit: $u"; systemctl cat "$u" 2>/dev/null | grep -E '^(User|Group|ExecStart|WorkingDirectory|Environment)' | indent; }
  if [[ -f $cfg ]]; then
    grep -nE '^[[:space:]]*(host|port|media_path)[[:space:]]*=' "$cfg" | indent
    grep -qE '^[[:space:]]*host[[:space:]]*=[[:space:]]*"0\.0\.0\.0"' "$cfg" || { alert "rum host != 0.0.0.0"; want "Set host = \"0.0.0.0\"" && { bak "$cfg"; sed -i -E 's|^([[:space:]]*)host[[:space:]]*=.*|\1host = "0.0.0.0"|' "$cfg"; }; }
    grep -qE '^[[:space:]]*port[[:space:]]*=[[:space:]]*"?8000"?[[:space:]]*$' "$cfg" || { alert "rum port != 8000"; want "Set port = 8000" && { bak "$cfg"; sed -i -E 's|^([[:space:]]*)port[[:space:]]*=.*|\1port = 8000|' "$cfg"; }; }
    mp=$(grep -m1 -E '^[[:space:]]*media_path[[:space:]]*=' "$cfg" | cut -d= -f2- | tr -d ' "'\''')
    [[ -n $mp && $mp != /* ]] && mp="/opt/rum/$mp"
    if [[ -z $mp || ! -d $mp ]]; then
      alert "media_path '${mp:-<missing>}' does not exist (this crash-loops rum)"
      if want "Set media_path = \"/opt/rum/media\""; then bak "$cfg"
        if grep -qE '^[[:space:]]*media_path[[:space:]]*=' "$cfg"; then sed -i -E 's|^([[:space:]]*)media_path[[:space:]]*=.*|\1media_path = "/opt/rum/media"|' "$cfg"
        else sed -i -E '0,/^[[:space:]]*port[[:space:]]*=/s||media_path = "/opt/rum/media"\n&|' "$cfg"; fi; did "media_path set"; fi
    else ok "media_path $mp exists"; fi
    stat -c '%U:%G %a %n' "$cfg" /opt/rum 2>/dev/null | indent
  else alert "$cfg missing"; fi

  section "SERVICES: CIFS media mount (web -> file SMB)"
  line=$(grep -E '^[^#]*[[:space:]]/opt/rum/media[[:space:]]' /etc/fstab)
  if [[ -z $line ]]; then
    alert "no fstab entry for /opt/rum/media"
    want "Add fstab: //$FILE_IP/ftp/upload /opt/rum/media cifs ro,guest,vers=3.0,_netdev,nofail" && { bak /etc/fstab; echo "//$FILE_IP/ftp/upload /opt/rum/media cifs ro,guest,vers=3.0,_netdev,nofail 0 0" >>/etc/fstab; systemctl daemon-reload; }
  else
    info "fstab: $line"
    [[ $line == *"//$FILE_IP/ftp/upload"* && $line == *guest* && $line == *cifs* ]] || alert "fstab line looks tampered (expected //$FILE_IP/ftp/upload cifs ro,guest,vers=3.0)"
  fi
  command -v mount.cifs >/dev/null || { alert "mount.cifs missing (cifs-utils)"; want "apt-get install -y cifs-utils" && apt_ok && apt-get install -y cifs-utils; }
  mkdir -p /opt/rum/media 2>/dev/null
  if mountpoint -q /opt/rum/media; then ok "/opt/rum/media mounted"; else alert "/opt/rum/media NOT mounted"; want "mount /opt/rum/media" && { mount /opt/rum/media && did "mounted" || alert "mount failed — check file server SMB (guest ok, signing auto) and egress 445"; }; fi
  local t; for t in $(systemctl list-unit-files --no-legend 'rum-media-retry*' 2>/dev/null | awk '{print $1}'); do
    [[ $t == *.timer ]] && { systemctl is-active --quiet "$t" && ok "$t active" || { warn "$t inactive"; want "enable --now $t" && systemctl enable --now "$t" >/dev/null 2>&1; }; }; done
  find /opt/rum/media -maxdepth 4 -name "$(basename "$RUM_MP4_PATH")" 2>/dev/null | head -1 | sed 's/^/  media file: /'

  section "SERVICES: port-80 -> 8000 redirect"
  local pre out
  pre=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -E -- '--dport 80 .*REDIRECT --to-ports 8000')
  out=$(iptables -t nat -S OUTPUT 2>/dev/null | grep -E -- '-o lo .*--dport 80 .*REDIRECT --to-ports 8000')
  iptables -t nat -S 2>/dev/null | grep -E -- '^-A' | grep -vE -- '--dport 80 .*REDIRECT --to-ports 8000' | while read -r x; do warn "other nat rule: $x"; done
  [[ -n $pre ]] && ok "PREROUTING redirect present" || alert "PREROUTING 80->8000 redirect MISSING"
  [[ -n $out ]] && ok "OUTPUT(lo) redirect present" || alert "OUTPUT lo 80->8000 redirect MISSING"
  if [[ -z $pre || -z $out ]] && want "Re-add the 80->8000 redirect rules"; then
    iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8000 2>/dev/null || iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8000
    iptables -t nat -C OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-ports 8000 2>/dev/null || iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-ports 8000
    did "redirect rules added"
  fi
  if [[ ! -f /etc/systemd/system/blue-rum-redirect.service ]] && want "Install blue-rum-redirect.service (re-adds the redirect at boot)"; then
    cat >/etc/systemd/system/blue-rum-redirect.service <<'EOF'
[Unit]
Description=BLUE: ensure port 80 -> 8000 redirect for rum
After=network-pre.target nftables.service ufw.service netfilter-persistent.service
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8000 2>/dev/null || iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8000'
ExecStart=/bin/sh -c 'iptables -t nat -C OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-ports 8000 2>/dev/null || iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-ports 8000'
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable blue-rum-redirect.service >/dev/null 2>&1; did "blue-rum-redirect.service enabled"
  fi
  [[ -n $u ]] && ensure_unit_up "$u" "$([[ $(cfgsum "$cfg" /etc/fstab) != "$before" ]] && echo restart)"
  local mf; mf=$(find /opt/rum -xdev -newer /etc/hostname -type f -mmin -720 2>/dev/null | grep -v '/media/' | head -20)
  [[ -n $mf ]] && { warn "files under /opt/rum modified in the last 12h:"; printf '%s\n' "$mf" | indent; }
}

kv_set(){ local f=$1 k=$2 v=$3
  if [[ $(grep -cE "^[[:space:]]*${k}[[:space:]]*=" "$f") == 1 ]] && grep -qxE "[[:space:]]*${k}[[:space:]]*=[[:space:]]*${v}[[:space:]]*" "$f"; then return; fi
  sed -i -E "/^[[:space:]]*${k}[[:space:]]*=/d" "$f"; echo "$k=$v" >>"$f"; }
kv_del(){ local f=$1 k=$2; sed -i -E "s/^([[:space:]]*${k}[[:space:]]*=)/#BLUE# \1/" "$f"; }
kv_get(){ grep -E "^[[:space:]]*$2[[:space:]]*=" "$1" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d ' '; }
VSFTPD_PAM_DEFAULT='# Standard behaviour for ftpd(8).
auth	required	pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed
# Note: vsftpd handles anonymous logins on its own. Do not enable pam_ftp.so.
# Standard pam includes
@include common-account
@include common-session
@include common-auth
auth	required	pam_shells.so'

svc_file(){
  section "SERVICES: Samba"
  local cfg=/etc/samba/smb.conf new wg ro u before vbefore
  before=$(cfgsum "$cfg"); vbefore=$(cfgsum /etc/vsftpd.conf /etc/pam.d/vsftpd)
  if [[ -f $cfg ]]; then
    testparm -s "$cfg" 2>/dev/null | grep -iE 'signing|encrypt|map to guest|guest|valid users|invalid users|hosts (allow|deny)|exec|include|interfaces|smb ports|passdb|ntlm auth|restrict anonymous|path|read only|username map|script' | indent
  else alert "$cfg missing"; fi
  wg=$(awk -F= 'tolower($0)~/^[[:space:]]*\[global\]/{g=1;next} /^[[:space:]]*\[/{g=0} g && tolower($1)~/^[[:space:]]*workgroup[[:space:]]*$/{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2);print $2;exit}' "$cfg" 2>/dev/null)
  ro=$(awk -F= 'tolower($0)~/^[[:space:]]*\[ftp\]/{s=1;next} /^[[:space:]]*\[/{s=0} s && tolower($1)~/^[[:space:]]*read only[[:space:]]*$/{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2);print $2}' "$cfg" 2>/dev/null | tail -1)
  new=$(mktemp)
  {
    cat <<EOF
# Written by blue.sh $TS (old file: $BAKDIR$cfg)
[global]
   workgroup = ${wg:-WORKGROUP}
   server string = %h server (Samba)
   server role = standalone server
   security = user
   passdb backend = tdbsam
   map to guest = Bad User
   guest account = nobody
   server signing = auto
   server smb encrypt = if_required
   ntlm auth = ntlmv2-only
   server min protocol = SMB2_02
   smb ports = 445 139
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes
   unix password sync = no
   usershare allow guests = no

[ftp]
EOF
    awk 'BEGIN{s=0} /^[[:space:]]*\[/{n=tolower($0); gsub(/\[|\]|[[:space:]]/,"",n); s=(n=="ftp"); next}
      s { l=tolower($0)
          if (l ~ /^[[:space:]]*#[[:space:]]*blue-removed/) next
          if (l ~ /^[[:space:]]*(guest ok|public|path|available|browseable|browsable)[[:space:]]*=/) next
          if (l ~ /^[[:space:]]*(valid users|invalid users|hosts allow|hosts deny|allow hosts|deny hosts|guest only|smb encrypt|server smb encrypt|include|magic script|magic output|(root )?(pre|post)?exec|(root )?preexec close|vfs objects|force user|admin users)[[:space:]]*=/) {print "   # BLUE-REMOVED: " $0; next}
          if ($0 ~ /^[[:space:]]*$/) next; print }' "$cfg" 2>/dev/null
    printf '   path = /srv/ftp\n   browseable = yes\n   guest ok = yes\n   available = yes\n'
    [[ -z $ro ]] && printf '   read only = yes\n'
    echo
    awk 'BEGIN{skip=1} /^[[:space:]]*\[/{n=tolower($0); gsub(/\[|\]|[[:space:]]/,"",n); skip=(n=="global"||n=="ftp"); if(!skip) print ""}
      skip {next}
      { l=tolower($0); if (l ~ /^[[:space:]]*#[[:space:]]*blue-removed/) {print; next}; if (l ~ /^[[:space:]]*((root )?(pre|post)?exec|(root )?preexec close|magic script|magic output|include)[[:space:]]*=/) {print "   # BLUE-REMOVED: " $0; next} print }' "$cfg" 2>/dev/null
  } >"$new"
  if ! testparm -s "$new" >/dev/null 2>&1; then alert "generated smb.conf fails testparm — not installing ($new)"
  elif cmp -s <(grep -v '^# Written by' "$new") <(grep -v '^# Written by' "$cfg"); then ok "smb.conf already blue's version"
  else
    info "diff (old -> new):"; diff <(testparm -s "$cfg" 2>/dev/null) <(testparm -s "$new" 2>/dev/null) | head -40 | indent
    want "Install known-good smb.conf (signing auto, map to guest = Bad User, [ftp] guest ok = yes, exec/include/hosts traps stripped)" && { bak "$cfg"; cat "$new" >"$cfg"; chmod 644 "$cfg"; did "smb.conf written"; }
  fi
  rm -f "$new"
  for u in /srv /srv/ftp /srv/ftp/upload; do
    [[ -d $u ]] || { alert "$u missing"; want "mkdir -p $u (755)" && mkdir -p "$u" && chmod 755 "$u"; continue; }
    [[ $(stat -c %A "$u") =~ ^d......r.x ]] || { alert "$u not world-readable/traversable (guest = nobody): $(stat -c '%A %U:%G' "$u")"; want "chmod o+rx $u" && chmod o+rx "$u"; }
  done
  local nr; nr=$(find /srv/ftp/upload -type f ! -perm -o=r 2>/dev/null | head -20)
  [[ -n $nr ]] && { alert "files in /srv/ftp/upload not readable by guest:"; printf '%s\n' "$nr" | indent; want "chmod o+r on them" && find /srv/ftp/upload -type f ! -perm -o=r -exec chmod o+r {} +; }
  if command -v pdbedit >/dev/null; then
    local missing=(); for u in "${SCORED_USERS[@]}"; do pdbedit -L 2>/dev/null | cut -d: -f1 | grep -qx "$u" || missing+=("$u"); done
    if (( ${#missing[@]} )); then alert "not in Samba passdb: ${missing[*]}"; want "Add scored users to Samba passdb with the default password" && for u in "${missing[@]}"; do smb_restore_user "$u"; done; else ok "all scored users in passdb"; fi
    want "Re-set Samba password to default for ALL scored users (idempotent; fixes 'authenticated as guest')" && for u in "${SCORED_USERS[@]}"; do getent passwd "$u" >/dev/null && smb_restore_user "$u"; done
  fi
  ensure_unit_up smbd.service "$([[ $(cfgsum "$cfg") != "$before" ]] && echo restart)"
  systemctl cat nmbd.service >/dev/null 2>&1 && { systemctl is-active --quiet nmbd || warn "nmbd not running (not needed for SMB over 445)"; }

  section "SERVICES: vsftpd"
  local vc=/etc/vsftpd.conf ex
  ex=$(systemctl cat vsftpd.service 2>/dev/null | grep -E '^ExecStart=' | tail -1)
  info "$ex"; [[ $ex == *vsftpd* && $ex != *"/etc/vsftpd.conf"* && $ex =~ \.conf ]] && alert "vsftpd started with a non-default config: $ex"
  if [[ -f $vc ]]; then
    grep -vE '^[[:space:]]*(#|$)' "$vc" | indent
    if want "Enforce vsftpd settings (local_enable, listen, pasv $FTP_PASV_MIN-$FTP_PASV_MAX, no userlist/cmds/max_* traps, writable-chroot fix)"; then
      bak "$vc"
      kv_set "$vc" listen YES; kv_set "$vc" listen_ipv6 NO; kv_set "$vc" local_enable YES; kv_set "$vc" anonymous_enable NO
      kv_set "$vc" pam_service_name vsftpd; kv_set "$vc" pasv_enable YES; kv_set "$vc" pasv_min_port "$FTP_PASV_MIN"; kv_set "$vc" pasv_max_port "$FTP_PASV_MAX"
      kv_set "$vc" port_enable YES; kv_set "$vc" connect_from_port_20 YES; kv_set "$vc" userlist_enable NO; kv_set "$vc" tcp_wrappers NO
      for x in listen_address listen_address6 listen_port cmds_allowed cmds_denied max_clients max_per_ip user_config_dir guest_enable deny_file hide_file local_root banned_email_file deny_email_enable; do kv_del "$vc" "$x"; done
      [[ $(kv_get "$vc" chroot_local_user) == YES ]] && kv_set "$vc" allow_writeable_chroot YES
      if [[ $(kv_get "$vc" ssl_enable) == YES ]]; then kv_set "$vc" force_local_logins_ssl NO; kv_set "$vc" force_local_data_ssl NO; fi
      local scd; scd=$(kv_get "$vc" secure_chroot_dir); mkdir -p "${scd:-/var/run/vsftpd/empty}"
      did "vsftpd.conf enforced"
    fi
  else alert "$vc missing"; fi
  if [[ -f /etc/pam.d/vsftpd ]] && ! diff -qBw <(grep -vE '^[[:space:]]*(#|$)' /etc/pam.d/vsftpd) <(grep -vE '^[[:space:]]*(#|$)' <<<"$VSFTPD_PAM_DEFAULT") >/dev/null; then
    alert "/etc/pam.d/vsftpd differs from default:"; diff <(grep -vE '^[[:space:]]*(#|$)' <<<"$VSFTPD_PAM_DEFAULT") <(grep -vE '^[[:space:]]*(#|$)' /etc/pam.d/vsftpd) | indent
    want "Restore default /etc/pam.d/vsftpd" && { bak /etc/pam.d/vsftpd; printf '%s\n' "$VSFTPD_PAM_DEFAULT" >/etc/pam.d/vsftpd; did "pam.d/vsftpd restored"; }
  elif [[ ! -f /etc/pam.d/vsftpd ]]; then alert "/etc/pam.d/vsftpd missing"; want "Write default /etc/pam.d/vsftpd" && printf '%s\n' "$VSFTPD_PAM_DEFAULT" >/etc/pam.d/vsftpd; fi
  ensure_unit_up vsftpd.service "$([[ $(cfgsum /etc/vsftpd.conf /etc/pam.d/vsftpd) != "$vbefore" ]] && echo restart)"
}

msg_docroot(){ local d
  d=$(grep -rhsE '^[[:space:]]*DocumentRoot[[:space:]]' /etc/apache2/sites-enabled/ | awk '{print $2}' | tr -d '"' | head -1)
  [[ -z $d ]] && d=$(grep -rhsE '^[[:space:]]*root[[:space:]]' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ | awk '{print $2}' | tr -d ';' | head -1)
  echo "${d:-/var/www/html}"; }
svc_msgboard(){
  section "SERVICES: message board"
  local u dr
  for u in $(msg_units); do info "unit: $u"; done
  command -v apache2ctl >/dev/null && { apache2ctl -t 2>&1 | indent; apache2ctl -S 2>/dev/null | head -10 | indent; }
  command -v nginx >/dev/null && nginx -t 2>&1 | indent
  for u in $(msg_units); do ensure_unit_up "$u"; done
  dr=$(msg_docroot); info "document root: $dr"
  if [[ -d $dr && ! -f $STATE/msgboard-webroot.tgz ]]; then tar czf "$STATE/msgboard-webroot.tgz" -C / "${dr#/}" 2>/dev/null && info "webroot snapshot saved to $STATE/msgboard-webroot.tgz (restore: tar xzf ... -C /)"; fi
  if [[ ! -f $STATE/msgboard-content.sha ]]; then curl -s --max-time 10 "http://127.0.0.1$MSG_CONTENT_PATH" | sha256sum >"$STATE/msgboard-content.sha"; fi
  local ws; ws=$(find "$dr" -xdev -type f \( -name '*.php*' -o -name '*.phtml' -o -name '.htaccess' \) -mmin -1440 2>/dev/null | xargs -r grep -lE 'eval\(|base64_decode\(|system\(|shell_exec\(|passthru\(|assert\(|proc_open\(|popen\(|AddType|SetHandler' 2>/dev/null | head -20)
  [[ -n $ws ]] && { alert "recently modified web files with exec/eval patterns (review, not auto-deleted):"; printf '%s\n' "$ws" | indent; }
  find "$dr" -xdev -type f -name '*.php' -path '*upload*' 2>/dev/null | head -10 | while read -r x; do alert "PHP file in an upload dir: $x"; done
}

# ---------------------------- verification -----------------------------------
VFAIL=()
verify_scored(){ local quiet=${1:-} u s code
  VFAIL=()
  [[ -z $quiet ]] && section "VERIFY: scored checks (local view)"
  if [[ $(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null) == 0 ]]; then [[ -z $quiet ]] && ok "ICMP sysctl ok"; else alert "ICMP: icmp_echo_ignore_all=1"; VFAIL+=(icmp); fi
  iptables-save 2>/dev/null | grep -E -- '-p icmp.*-j (DROP|REJECT)' | while read -r x; do alert "iptables ICMP drop: $x"; done
  if timeout 6 ssh-keyscan -T 4 "$MYIP" 2>/dev/null | grep -q .; then [[ -z $quiet ]] && ok "SSH answers on $MYIP:22"; else alert "SSH not answering on $MYIP:22"; VFAIL+=("svc:$(ssh_unit)"); fi
  for u in "${SCORED_USERS[@]}"; do s=$(scored_status "$u"); if [[ -n $s ]]; then alert "scored user $u: $s"; VFAIL+=("user:$u"); fi; done
  if command -v sshpass >/dev/null; then
    if SSHPASS=$SCORED_PW timeout 15 sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -o LogLevel=ERROR "${SCORED_USERS[0]}@$MYIP" true 2>/dev/null; then [[ -z $quiet ]] && ok "real SSH password login as ${SCORED_USERS[0]} works"; else alert "SSH password login as ${SCORED_USERS[0]} FAILED"; VFAIL+=(sshlogin); fi
  fi
  case $ROLE in
    web)
      code=$(curl -s -o /dev/null --max-time 20 -w '%{http_code}' "http://$MYIP$RUM_MP4_PATH" 2>/dev/null)
      [[ $code == 200 ]] && { [[ -z $quiet ]] && ok "HTTP Content $RUM_MP4_PATH -> 200"; } || { alert "HTTP Content $RUM_MP4_PATH -> ${code:-none}"; VFAIL+=(http); }
      code=$(curl -s -o /dev/null --max-time 8 -w '%{http_code}' "http://127.0.0.1:8000/" 2>/dev/null); [[ -z $quiet ]] && info "rum direct :8000 / -> $code"
      mountpoint -q /opt/rum/media || { alert "/opt/rum/media not mounted"; VFAIL+=(mount); }
      iptables -t nat -S PREROUTING 2>/dev/null | grep -qE -- '--dport 80 .*REDIRECT --to-ports 8000' || { alert "80->8000 redirect missing"; VFAIL+=(redirect); }
      ;;
    file)
      if smbclient "//$MYIP/ftp" -U "${SCORED_USERS[0]}%$SCORED_PW" -m SMB3 -c 'ls' >/dev/null 2>&1; then [[ -z $quiet ]] && ok "SMB login as ${SCORED_USERS[0]} works"; else alert "SMB login as ${SCORED_USERS[0]} FAILED: $(smbclient "//$MYIP/ftp" -U "${SCORED_USERS[0]}%$SCORED_PW" -m SMB3 -c ls 2>&1 | tail -1)"; VFAIL+=(smb); fi
      if smbclient "//$MYIP/ftp" -N -m SMB3 -c 'ls upload/*' >/dev/null 2>&1; then [[ -z $quiet ]] && ok "SMB guest read of ftp/upload works (web's mount)"; else alert "SMB guest access FAILED (web mount will break)"; VFAIL+=(smbguest); fi
      if curl -s --max-time 10 -u "${SCORED_USERS[0]}:$SCORED_PW" "ftp://$MYIP/" -o /dev/null; then [[ -z $quiet ]] && ok "FTP login+LIST as ${SCORED_USERS[0]} works"; else alert "FTP login as ${SCORED_USERS[0]} FAILED"; VFAIL+=(ftp); fi
      ;;
    msgboard)
      local body; body=$(curl -s --max-time 10 -w '\n%{http_code}' "http://$MYIP$MSG_CONTENT_PATH" 2>/dev/null); code=${body##*$'\n'}; body=${body%$'\n'*}
      [[ $code == 200 ]] && { [[ -z $quiet ]] && ok "HTTP $MSG_CONTENT_PATH -> 200"; } || { alert "HTTP $MSG_CONTENT_PATH -> ${code:-none}"; VFAIL+=(http); }
      [[ -n $MSG_CONTENT_STRING && $body != *"$MSG_CONTENT_STRING"* ]] && { alert "content string '$MSG_CONTENT_STRING' missing"; VFAIL+=(content); }
      if [[ -f $STATE/msgboard-content.sha ]] && [[ $(printf '%s' "$body" | sha256sum) != "$(cat "$STATE/msgboard-content.sha")" ]]; then warn "page differs from first-seen baseline (dynamic page, or defacement?)"; fi
      ;;
  esac
  local x; while read -r x; do [[ -n $x ]] && { systemctl is-active --quiet "$x" || { alert "$x not active"; VFAIL+=("svc:$x"); }; }; done < <(role_units)
  if (( ${#VFAIL[@]} == 0 )); then [[ -z $quiet ]] && ok "ALL LOCAL SCORED CHECKS PASS"; else alert "failing: ${VFAIL[*]}"; fi; }

phase_services(){
  load_owned
  section "SERVICES: ICMP"; fix_icmp
  svc_sshd
  case $ROLE in web) svc_web;; file) svc_file;; msgboard) svc_msgboard;; esac
  verify_scored
}

# =============================================================================
# PHASE: firewall  (separate nft table "inet bluefw"; nat table / redirect untouched)
# =============================================================================
FWSNAP=$STATE/fw-$TS
dns_servers(){ { grep -hE '^nameserver' /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null | awk '{print $2}'; resolvectl dns 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'; echo "$ROUTER"; echo "$DC"; } | grep -vE '^127\.' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u | paste -sd, -; }
gen_nft(){ local f=$1 tcp dns x proto ip port s
  tcp=$(role_tcp_ports | tr ' ' ','); dns=$(dns_servers)
  {
    echo "# generated by blue.sh $TS role=$ROLE"
    echo "table inet bluefw"
    echo "delete table inet bluefw"
    echo "table inet bluefw {"
    [[ $ROLE == file ]] && echo '  ct helper ftp-std { type "ftp" protocol tcp; }'
    echo "  chain pre { type filter hook prerouting priority filter; policy accept;"
    [[ $ROLE == file ]] && echo '    tcp dport 21 ct helper set "ftp-std"'
    echo "  }"
    echo "  chain input { type filter hook input priority filter; policy drop;"
    echo "    iif lo accept"
    echo "    ct state invalid drop"
    echo "    ct state established,related accept"
    echo "    meta l4proto icmp accept"
    echo "    meta l4proto ipv6-icmp accept"
    if (( SSH_RESTRICT )); then echo "    ip saddr { $TEAM_NET$(printf ', %s' "${SCORER_NETS[@]}") } tcp dport 22 accept"; fi
    echo "    tcp dport { $tcp } accept"
    [[ $ROLE == file ]] && echo "    tcp dport $FTP_PASV_MIN-$FTP_PASV_MAX accept"
    for s in "${SCORER_NETS[@]}"; do echo "    ip saddr $s accept    # unknown-origin ufw allow (scorer?) — kept"; done
    echo '    limit rate 10/second log prefix "BLUE-IN-DROP " level info'
    echo "  }"
    echo "  chain output { type filter hook output priority filter; policy drop;"
    echo "    oif lo accept"
    echo "    ct state invalid drop"
    echo "    ct state established,related accept"
    echo "    meta l4proto icmp accept"
    echo "    meta l4proto ipv6-icmp accept"
    echo "    ip daddr { $dns } udp dport 53 accept"
    echo "    ip daddr { $dns } tcp dport 53 accept"
    echo "    ip daddr { $ROUTER, $DC } udp dport 123 accept"
    [[ $ROLE == web ]] && echo "    ip daddr $FILE_IP tcp dport { 445, 139 } accept    # CIFS media mount"
    [[ $ROLE == file ]] && echo "    tcp sport 20 accept    # active-mode FTP data"
    (( ALLOW_APT_EGRESS )) && echo "    tcp dport { 80, 443 } accept    # ALLOW_APT_EGRESS=1"
    pgrep -x cloudflared >/dev/null 2>&1 && echo "    tcp dport { 443, 7844 } accept    # cloudflared detected" && echo "    udp dport 7844 accept"
    for x in "${EXTRA_EGRESS[@]}"; do IFS=: read -r proto ip port <<<"$x"; echo "    ip daddr $ip $proto dport $port accept    # EXTRA_EGRESS"; done
    echo '    limit rate 10/second log prefix "BLUE-OUT-DROP " level info'
    echo "  }"
    echo "}"
  } >"$f"; }

phase_firewall(){
  section "FIREWALL: current state"
  local x t fam name
  fix_icmp
  if command -v ufw >/dev/null; then
    ufw status verbose 2>/dev/null | indent
    ufw status 2>/dev/null | grep -q '172.16.0.2' && warn "ufw has 'ALLOW from 172.16.0.2' (unknown origin; may be the scorer) — NOT deleting; carried into bluefw as an allow"
  fi
  info "nft tables:"; nft list tables 2>/dev/null | indent
  local foreign_ipt foreign_ipt6
  foreign_ipt=$(iptables-save -t filter 2>/dev/null | grep -E '^-A' | grep -vE -- '-A ufw|-j ufw|ufw-' | grep -E -- '-j (DROP|REJECT)')
  foreign_ipt6=$(ip6tables-save -t filter 2>/dev/null | grep -E '^-A' | grep -vE -- '-A ufw|-j ufw|ufw6?-' | grep -E -- '-j (DROP|REJECT)')
  [[ -n $foreign_ipt ]] && { alert "non-ufw iptables DROP/REJECT rules:"; printf '%s\n' "$foreign_ipt" | indent; }
  [[ -n $foreign_ipt6 ]] && { alert "non-ufw ip6tables DROP/REJECT rules:"; printf '%s\n' "$foreign_ipt6" | indent; }
  command -v iptables-legacy-save >/dev/null && iptables-legacy-save 2>/dev/null | grep -E '^-A.*-j (DROP|REJECT)' | while read -r x; do alert "iptables-LEGACY rule: $x"; done
  local foreign_tables=()
  while read -r _ fam name; do
    [[ "$fam $name" == "inet bluefw" ]] && continue
    case "$fam $name" in "ip filter"|"ip nat"|"ip mangle"|"ip raw"|"ip security"|"ip6 filter"|"ip6 nat"|"ip6 mangle"|"ip6 raw"|"ip6 security"|"bridge filter"|"arp filter") continue;; esac
    if nft list table "$fam" "$name" 2>/dev/null | grep -qE '\b(drop|reject)\b'; then alert "foreign nft table '$fam $name' contains drop/reject:"; nft list table "$fam" "$name" | grep -nE 'drop|reject|policy' | indent; foreign_tables+=("$fam $name"); else info "foreign nft table '$fam $name' (no drops)"; fi
  done < <(nft list tables 2>/dev/null)
  systemctl is-enabled nftables.service 2>/dev/null | grep -q enabled && grep -q 'flush ruleset' /etc/nftables.conf 2>/dev/null && warn "nftables.service is enabled and /etc/nftables.conf does 'flush ruleset' — a restart wipes the rum redirect (web) and bluefw"
  (( APPLY )) || { local tmp; tmp=$(mktemp); gen_nft "$tmp"; info "ruleset that --apply would load:"; indent <"$tmp"; rm -f "$tmp"; plan "load inet bluefw with ${FW_ROLLBACK_SECS}s auto-rollback"; return; }

  want "Apply firewall (inbound default-deny + egress filtering) with ${FW_ROLLBACK_SECS}s auto-rollback" || return
  mkdir -p "$FWSNAP"
  nft list ruleset >"$FWSNAP/nft-ruleset-before.nft" 2>/dev/null
  iptables-save >"$FWSNAP/iptables-before.rules" 2>/dev/null; ip6tables-save >"$FWSNAP/ip6tables-before.rules" 2>/dev/null
  local RB=$FWSNAP/rollback.sh
  printf '#!/bin/sh\n# blue.sh firewall rollback %s\nnft delete table inet bluefw 2>/dev/null\n' "$TS" >"$RB"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    if confirm "Disable ufw (its rules are saved; rollback re-enables it)? n = keep ufw and add allow rules to it"; then
      ufw --force disable >/dev/null && did "ufw disabled"; echo 'ufw --force enable' >>"$RB"
    else
      for x in $(role_tcp_ports); do ufw allow "$x/tcp" >/dev/null; done
      [[ $ROLE == file ]] && ufw allow "$FTP_PASV_MIN:$FTP_PASV_MAX/tcp" >/dev/null
      did "ufw allow rules added for scored ports"
    fi
  fi
  if [[ -n $foreign_ipt ]] && gate 3 "Delete the non-ufw iptables DROP/REJECT rules listed above"; then
    iptables-save -t filter >"$FWSNAP/iptables-filter.rules"
    { echo '*filter'; printf '%s\n' "$foreign_ipt" | sed 's/^-A /-D /'; echo COMMIT; } | iptables-restore --noflush && did "iptables drop rules removed"
    echo "iptables-restore < '$FWSNAP/iptables-filter.rules'" >>"$RB"
  fi
  if [[ -n $foreign_ipt6 ]] && gate 3 "Delete the non-ufw ip6tables DROP/REJECT rules"; then
    ip6tables-save -t filter >"$FWSNAP/ip6tables-filter.rules"
    { echo '*filter'; printf '%s\n' "$foreign_ipt6" | sed 's/^-A /-D /'; echo COMMIT; } | ip6tables-restore --noflush && did "ip6tables drop rules removed"
    echo "ip6tables-restore < '$FWSNAP/ip6tables-filter.rules'" >>"$RB"
  fi
  for x in INPUT OUTPUT; do
    if [[ $(iptables -S "$x" 2>/dev/null | head -1) == "-P $x DROP" ]] && ! { command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; }; then
      alert "iptables $x policy DROP without ufw"; gate 3 "iptables -P $x ACCEPT" && { iptables -P "$x" ACCEPT; echo "iptables -P $x DROP" >>"$RB"; }
    fi
  done
  for t in "${foreign_tables[@]}"; do
    read -r fam name <<<"$t"
    if gate 3 "Delete foreign nft table '$t' (saved for rollback)"; then
      nft list table "$fam" "$name" >"$FWSNAP/nft-foreign-$fam-$name.nft"; nft delete table "$fam" "$name" && did "deleted table $t"
      echo "nft -f '$FWSNAP/nft-foreign-$fam-$name.nft'" >>"$RB"
    fi
  done
  echo 'logger -t blue "firewall rollback executed"; echo "BLUE FIREWALL ROLLED BACK" | wall 2>/dev/null' >>"$RB"; chmod 700 "$RB"
  [[ $ROLE == file ]] && modprobe nf_conntrack_ftp 2>/dev/null
  mkdir -p /etc/blue; local nf=/etc/blue/bluefw.nft.new
  gen_nft "$nf"
  if ! nft -c -f "$nf"; then alert "nft syntax check failed — nothing loaded"; sh "$RB"; return 1; fi
  # schedule rollback BEFORE loading so a dropped session still gets rolled back
  systemctl stop blue-fw-rollback.timer blue-fw-rollback.service >/dev/null 2>&1; systemctl reset-failed blue-fw-rollback.service >/dev/null 2>&1
  local rbmode=nohup rbpid=""
  if systemd-run --unit=blue-fw-rollback --on-active="${FW_ROLLBACK_SECS}" --timer-property=AccuracySec=1s /bin/sh "$RB" >/dev/null 2>&1; then rbmode=systemd
  else nohup setsid sh -c "sleep $FW_ROLLBACK_SECS; sh '$RB'" >/dev/null 2>&1 & rbpid=$!; fi
  nft -f "$nf" && did "inet bluefw loaded (rollback armed: $rbmode, ${FW_ROLLBACK_SECS}s)"
  nft list table inet bluefw | indent
  verify_scored
  info "Test from Kali NOW (ping, ssh, ports) — pfsense/pf-check.sh --probe"
  local ans=""; read -r -t "$(( FW_ROLLBACK_SECS > 10 ? FW_ROLLBACK_SECS - 5 : 5 ))" -p "  ${Y}Type CONFIRM to keep the firewall (anything else / timeout = rollback): ${N}" ans </dev/tty; echo
  if [[ $ans == CONFIRM ]]; then
    if [[ $rbmode == systemd ]]; then systemctl stop blue-fw-rollback.timer >/dev/null 2>&1; else kill "$rbpid" 2>/dev/null; fi
    mv -f "$nf" /etc/blue/bluefw.nft
    cat >/etc/systemd/system/blue-fw.service <<EOF
[Unit]
Description=BLUE team nftables table inet bluefw
After=network-pre.target nftables.service ufw.service blue-rum-redirect.service
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/sbin/modprobe nf_conntrack_ftp
ExecStart=/usr/sbin/nft -f /etc/blue/bluefw.nft
ExecStop=/usr/sbin/nft delete table inet bluefw
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable blue-fw.service >/dev/null 2>&1
    did "firewall KEPT and persisted (blue-fw.service). Rollback any time: sh $RB"
    info "watch drops: journalctl -k -f | grep BLUE-"
  else
    if [[ $rbmode == systemd ]]; then systemctl stop blue-fw-rollback.timer >/dev/null 2>&1; else kill "$rbpid" 2>/dev/null; fi
    sh "$RB"; warn "rolled back"
  fi; }

# =============================================================================
# PHASE: av
# =============================================================================
phase_av(){
  local out=/root/blue-av-$HOST-$TS.txt need=() x
  section "AV: tools"
  for x in clamscan:clamav freshclam:clamav-freshclam rkhunter:rkhunter chkrootkit:chkrootkit; do command -v "${x%%:*}" >/dev/null || need+=("${x#*:}"); done
  if (( ${#need[@]} )); then
    warn "missing: ${need[*]}"
    if want "apt-get install ${need[*]}"; then if apt_ok; then DEBIAN_FRONTEND=noninteractive apt-get install -y "${need[@]}" >/dev/null 2>&1 && did "installed"; else warn "apt offline — scanning with whatever is installed"; fi; fi
  fi
  (( APPLY )) || { plan "run freshclam, clamscan (targeted), rkhunter --check, chkrootkit; write $out"; return; }
  : >"$out"
  if command -v clamscan >/dev/null; then
    section "AV: ClamAV"
    systemctl stop clamav-freshclam >/dev/null 2>&1
    timeout 180 freshclam --quiet >/dev/null 2>&1 && did "signatures updated" || warn "freshclam failed (offline?)"
    if ls /var/lib/clamav/*.c[lv]d >/dev/null 2>&1; then
      local targets=(/tmp /var/tmp /dev/shm /etc /root /home /opt /srv /usr/local /var/www /var/spool/cron /.bin /usr/lib/systemd /lib/systemd)
      info "scanning (nice'd, up to 20 min)..."
      timeout 1200 nice -n 19 ionice -c3 clamscan -r -i --no-summary --max-filesize=50M --exclude-dir='^/opt/rum/media' --exclude-dir='^/root/blue-' "${targets[@]}" 2>/dev/null | tee -a "$out" | grep FOUND | while read -r x; do alert "ClamAV: $x"; done
    else alert "no ClamAV signature database (freshclam offline) — clamscan skipped"; fi
  fi
  if command -v rkhunter >/dev/null; then
    section "AV: rkhunter (no --propupd: would baseline trojaned binaries)"
    timeout 120 rkhunter --update >/dev/null 2>&1
    timeout 900 rkhunter --check --sk --rwo --nocolors 2>&1 | tee -a "$out" | grep -iE 'warning|found|infected' | head -40 | while read -r x; do alert "rkhunter: $x"; done
  fi
  if command -v chkrootkit >/dev/null; then
    section "AV: chkrootkit"
    timeout 600 chkrootkit -q 2>&1 | tee -a "$out" | grep -viE '^$|not tested' | head -40 | while read -r x; do warn "chkrootkit: $x"; done
  fi
  info "full AV output: $out (nothing auto-deleted)"; }

# =============================================================================
# PHASE: watch
# =============================================================================
snap_state(){ local d=$1 f u
  mkdir -p "$d"
  awk -F: '$3==0{print $1}' /etc/passwd >"$d/uid0"
  awk -F: '{print $1":"$3":"$7}' /etc/passwd >"$d/users"
  for u in "${SCORED_USERS[@]}"; do printf '%s %s\n' "$u" "$(scored_status "$u")"; done >"$d/scored"
  systemctl list-unit-files --no-legend --no-pager 2>/dev/null | awk '{print $1, $2}' >"$d/unit-files"
  systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' >"$d/running"
  systemctl list-units --type=timer --all --no-legend --no-pager 2>/dev/null | awk '{print $1, $3}' >"$d/timers"
  find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron -type f -exec sha256sum {} + 2>/dev/null | sort -k2 >"$d/cron"
  ss -tulnpH 2>/dev/null | awk '{print $1, $5, $7}' | sed -E 's/,fd=[0-9]+//g' | sort -u >"$d/listen"
  local ports=" $(role_tcp_ports) "
  ss -tunapH 2>/dev/null | awk '$2=="ESTAB"{print $1, $5, $6, $7}' | while read -r p la pa proc; do lp=${la##*:}; [[ $ports == *" $lp "* ]] && continue; case "$pa" in 127.*|"[::1]"*) continue;; esac; echo "$p $pa ${proc%%,pid*}"; done | sort -u >"$d/outbound"
  command -v pdbedit >/dev/null && pdbedit -L 2>/dev/null | cut -d: -f1 | sort >"$d/samba"
  { for f in /etc/ld.so.preload /etc/sudoers /etc/sudoers.d/* /etc/pam.d/* /etc/ssh/sshd_config /etc/samba/smb.conf /etc/vsftpd.conf /opt/rum/config.toml /etc/profile /etc/bash.bashrc /etc/profile.d/* /etc/fstab /root/.bashrc; do [[ -f $f ]] && sha256sum "$f"; done
    awk -F: '{print $6}' /etc/passwd | sort -u | while read -r h; do for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do [[ -f $f ]] && sha256sum "$f"; done; done; } >"$d/files" 2>/dev/null
  iptables -t nat -S 2>/dev/null >"$d/nat"
  sysctl -n net.ipv4.icmp_echo_ignore_all >"$d/icmp" 2>/dev/null; }

wall_alert(){ (( BG )) && printf 'BLUE WATCH %s: %s\n' "$HOST" "$*" | wall 2>/dev/null; }
declare -A LAST_RESTART=()
phase_watch(){
  if (( BG )) && [[ -z ${BLUE_IN_BG:-} ]]; then
    systemctl stop blue-watch >/dev/null 2>&1; systemctl reset-failed blue-watch >/dev/null 2>&1
    systemd-run --unit=blue-watch --setenv=BLUE_IN_BG=1 --setenv=SCORING_USER="$SCORING_USER" /bin/bash "$SELF" --role "$ROLE" --phase watch --bg $( (( HEAL )) && echo --heal ) >/dev/null \
      && { did "watch running as transient unit blue-watch (alerts via wall + $STATE/watch.log)"; info "stop: systemctl stop blue-watch   follow: tail -f /root/blue-$HOST-*.log"; } || alert "systemd-run failed"
    exit 0
  fi
  local base=$STATE/watch/baseline prev=$STATE/watch/prev cur=$STATE/watch/cur f d x u
  if (( REBASE )) || [[ ! -d $base ]]; then rm -rf "$base"; snap_state "$base"; did "baseline saved to $base"; fi
  rm -rf "$prev"; cp -a "$base" "$prev"
  section "WATCH every ${WATCH_INTERVAL}s (Ctrl-C to stop) heal=$HEAL"
  while true; do
    rm -rf "$cur"; snap_state "$cur"
    for f in "$cur"/*; do
      x=$(basename "$f")
      d=$(diff "$prev/$x" "$f" 2>/dev/null | grep -E '^[<>]')
      [[ -n $d ]] || continue
      while read -r line; do printf '%s %s[ALERT %s]%s %s\n' "$(date +%T)" "$R" "$x" "$N" "${line/#>/NEW:}"; done <<<"${d//</GONE:}"
      wall_alert "$x changed: $(head -c 300 <<<"$d")"
    done
    verify_scored quiet
    if (( ${#VFAIL[@]} )); then
      wall_alert "scored checks failing: ${VFAIL[*]}"
      if (( HEAL )); then
        for x in "${VFAIL[@]}"; do
          case $x in
            user:*) u=${x#user:}; ( YES=1; APPLY=1; restore_scored_user "$u" ) ;;
            svc:*)  u=${x#svc:}; systemctl unmask "$u" >/dev/null 2>&1; systemctl restart "$u" && did "healed: restarted $u" ;;
            http|mount|smb|smbguest|ftp|content|sshlogin)
              local now; now=$(date +%s)
              for u in $(role_units); do
                if (( now - ${LAST_RESTART[$u]:-0} > 120 )); then LAST_RESTART[$u]=$now; systemctl restart "$u" && did "healed: restarted $u (check $x failing)"; fi
              done
              [[ $x == mount ]] && mount /opt/rum/media 2>/dev/null && did "healed: remounted /opt/rum/media";;
            *) warn "not auto-healed (by design): $x";;
          esac
        done
      fi
    else printf '%s %s[ok]%s scored checks pass\n' "$(date +%T)" "$G" "$N"; fi
    rm -rf "$prev"; mv "$cur" "$prev"
    sleep "$WATCH_INTERVAL"
  done; }

# =============================================================================
# main
# =============================================================================
ROLE_UNITS_CACHE=$(_role_units)
if (( APPLY )); then etc_tarball; mkdir -p "$QDIR" "$BAKDIR"; info "quarantine: $QDIR   backups: $BAKDIR"; fi
for p in "${PHASES[@]}"; do
  case "$p" in
    creds) phase_creds;; persistence) phase_persistence;; shells) phase_shells;;
    integrity) phase_integrity;; services) phase_services;; firewall) phase_firewall;;
    av) phase_av;; watch) phase_watch;;
  esac
done
section "DONE"
info "findings flagged: $FINDINGS   log: $LOG"
(( APPLY )) && info "quarantined items: $QDIR   backups: $BAKDIR   /etc tarball: /root/blue-etc-$HOST-*.tgz"
