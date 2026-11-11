#!/usr/bin/env bash
# Shared helpers for the Linux scripts. Sourced, not run.
# Edit SCORED_USERS / ROLE_PORTS here if the new packet changes them.

# ---- From the Spring '26 packet (update from the new packet!) ----
SCORED_USERS="amarino mdesocio lsmith acapece johnlinux linuswindows alvin simon theodore abauer"
# Accounts we own and keep: dog = the team login. root stays but gets a new password.
KEEP_USERS="dog root"

# Scored TCP ports per role. ICMP is always allowed.
# FTP passive range is read from vsftpd.conf at runtime. ZeroClaw port auto-detected.
declare -A ROLE_PORTS=(
  [gitlab]="22 80 443"
  [comms]="22 80 443 8065"
  [web]="22 80 443 3306"
  [file]="22 21"
  [generic]="22"
)
declare -A ROLE_SERVICES=(
  [gitlab]="sshd gitlab-runsvdir"
  [comms]="sshd mattermost"
  [web]="ssh apache2 nginx mysql mariadb"
  [file]="ssh vsftpd proftpd pure-ftpd zeroclaw"
  [generic]="ssh sshd"
)

BLUE_DIR="${BLUE_DIR:-/root/.blue}"
TS="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BLUE_DIR" 2>/dev/null && chmod 700 "$BLUE_DIR" 2>/dev/null

if [[ -t 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[36m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; N=""
fi

hdr()  { printf '\n%s==== %s ====%s\n' "$B" "$*" "$N"; }
ok()   { printf '%s[+]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$R" "$N" "$*"; }
info() { printf '%s[*]%s %s\n' "$Y" "$N" "$*"; }

# Append an action to the action log. This is your inject / Gold Team evidence.
ACTION_LOG="$BLUE_DIR/actions.log"
log_action() { printf '%s %s %s\n' "$(date '+%F %T')" "$(hostname)" "$*" >> "$ACTION_LOG"; }

need_root() { [[ $EUID -eq 0 ]] || { echo "Run as root (sudo -i first)."; exit 1; }; }

# ask "question" -> returns 0 for yes. AUTO_YES=1 answers yes to everything.
ask() {
  [[ "${AUTO_YES:-0}" == 1 ]] && return 0
  local a; read -r -p "${Y}[?]${N} $1 [y/N] " a </dev/tty
  [[ "$a" =~ ^[Yy] ]]
}

is_scored() { local u=$1; for s in $SCORED_USERS; do [[ "$u" == "$s" ]] && return 0; done; return 1; }
is_kept()   { local u=$1; for s in $KEEP_USERS;   do [[ "$u" == "$s" ]] && return 0; done; return 1; }

os_family() {
  . /etc/os-release 2>/dev/null
  case "${ID:-} ${ID_LIKE:-}" in
    *rhel*|*rocky*|*fedora*|*centos*) echo rhel ;;
    *debian*|*ubuntu*) echo debian ;;
    *) echo unknown ;;
  esac
}

# Login-capable shells
is_login_shell() { [[ "$1" =~ (sh|bash|zsh|ksh|fish|dash)$ ]] && [[ ! "$1" =~ (nologin|false)$ ]]; }

backup_file() {
  local f=$1; [[ -e "$f" ]] || return 0
  local dst="$BLUE_DIR/filebak/$TS$(dirname "$f")"
  mkdir -p "$dst" && cp -a "$f" "$dst/"
}

# Strong random password (no chars that break shells/SQL quoting)
gen_pw() { tr -dc 'A-HJ-NP-Za-km-z2-9' </dev/urandom | head -c 16; printf '!%s' "$((RANDOM % 90 + 10))"; }
