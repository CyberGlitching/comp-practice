#!/usr/bin/env bash
# watch.sh - leave running in its own terminal/tmux pane after hardening.
# Takes a baseline, then every N seconds diffs the things red team touches to get back in.
# Usage: sudo ./watch.sh [interval_seconds=20]
#        sudo FIX=1 ./watch.sh     auto-revert: kills new uid0 users' sessions, re-locks them,
#                                  removes new authorized_keys, re-enables the firewall
# Alerts go to the screen and /root/.blue/watch.log (timestamped = your incident timeline for injects).

DIR="$(cd "$(dirname "$0")" && pwd)"; source "$DIR/common.sh"
need_root
INT="${1:-20}"; FIX="${FIX:-0}"
BASE="$BLUE_DIR/baseline"; mkdir -p "$BASE"
WLOG="$BLUE_DIR/watch.log"
SEEN="$BLUE_DIR/watch.seen"; : > "$SEEN"
FAM=$(os_family)

snap() {  # $1 = output dir
  local o=$1; mkdir -p "$o"
  cut -d: -f1,3,4,7 /etc/passwd > "$o/passwd"
  awk -F: '{print $1":"substr($2,1,12)}' /etc/shadow > "$o/shadow"   # hash prefix only: detects pw changes
  getent group | grep -E '^(sudo|wheel|admin|root|docker|lxd|disk|adm|shadow):' > "$o/groups"
  { cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null; } | grep -v '^\s*#' | sort > "$o/sudoers"
  for f in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys*; do [[ -f $f ]] && echo "$f $(sha1sum < "$f" | cut -c1-12)"; done > "$o/keys" 2>/dev/null
  { cat /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null; ls -1 /etc/cron.hourly /etc/cron.daily 2>/dev/null; } | grep -v '^\s*#' | sort > "$o/cron"
  systemctl list-unit-files --type=service,timer --no-legend --no-pager 2>/dev/null | awk '{print $1,$2}' | sort > "$o/units"
  ss -tulnH 2>/dev/null | awk '{print $1,$5}' | sort -u > "$o/listen"
  sha1sum /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/pam.d/* /etc/ld.so.preload /etc/profile.d/* 2>/dev/null | sort > "$o/configs"
  if [[ $FAM == rhel ]]; then
    { systemctl is-active firewalld; firewall-cmd --list-all 2>/dev/null; firewall-cmd --direct --get-all-rules 2>/dev/null; } > "$o/fw"
  else
    { ufw status 2>/dev/null; } > "$o/fw"
  fi
  iptables -S 2>/dev/null | grep -E 'DROP|REJECT' | grep -vE 'ufw|f2b|FINAL|REJECT --reject-with icmp-host-prohibited$' > "$o/iptdrop"
}

alert() { local m="$(date '+%T') [$(hostname)] $*"; printf '%s%s%s\n' "$R" "$m" "$N"; echo "$m" >> "$WLOG"; printf '\a'; }

if [[ ! -f "$BASE/passwd" ]] || ask "Re-take baseline now? (do this right after hardening)"; then
  rm -rf "$BASE"; snap "$BASE"; ok "Baseline saved in $BASE"
fi
info "Watching every ${INT}s. FIX=$FIX. Ctrl-C to stop."

while true; do
  NOW=$(mktemp -d); snap "$NOW"
  for k in passwd shadow groups sudoers keys cron units listen configs fw iptdrop; do
    d=$(diff "$BASE/$k" "$NOW/$k" 2>/dev/null | grep -E '^[<>]')
    # Back to baseline -> forget it, so a re-plant of the same thing alerts again
    if [[ -z "$d" ]]; then sed -i "/^$k:/d" "$SEEN"; continue; fi
    h="$k:$(echo "$d" | sha1sum | cut -c1-16)"
    # Alert once per distinct change
    grep -qx "$h" "$SEEN" 2>/dev/null && continue
    echo "$h" >> "$SEEN"
    alert "CHANGE in $k:"; echo "$d" | sed 's/^/      /' | tee -a "$WLOG"
    if [[ $FIX == 1 ]]; then
      case $k in
        passwd)
          echo "$d" | grep '^>' | sed 's/^> //' | while IFS=: read -r u uid _ _; do
            if [[ "$uid" == 0 && "$u" != root ]] || ! grep -q "^$u:" "$BASE/passwd"; then
              pkill -KILL -u "$u" 2>/dev/null; usermod -L -e 1 -s /usr/sbin/nologin "$u" 2>/dev/null && alert "FIX: locked new user $u"
            fi
          done ;;
        keys)
          echo "$d" | grep '^>' | awk '{print $2}' | while read -r f; do
            grep -q "^$f " "$BASE/keys" && continue
            chattr -i "$f" 2>/dev/null; mv "$f" "$BLUE_DIR/quarantine-$(date +%s)-$(echo "$f" | tr / _)" 2>/dev/null && alert "FIX: quarantined new key file $f"
          done ;;
        fw)
          if [[ $FAM == rhel ]]; then systemctl start firewalld; firewall-cmd --reload >/dev/null; else ufw --force enable >/dev/null; fi
          alert "FIX: firewall re-applied (check what changed it - a cron/timer/loop is doing this)" ;;
        iptdrop)
          echo "$d" | grep '^>' | sed 's/^> -A/-D/' | while read -r rule; do iptables $rule 2>/dev/null && alert "FIX: removed iptables $rule"; done ;;
      esac
    fi
  done
  # Always-on checks
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    [[ "$exe" =~ ^/(tmp|dev/shm|var/tmp)/ || "$exe" == *"(deleted)"* ]] && alert "PROC ${p#/proc/} from $exe: $(tr '\0' ' ' < "$p/cmdline" | cut -c1-120)"
  done
  who | awk '{print $1,$2,$5}' | while read -r u t from; do
    [[ "$u" == dog || "$u" == root ]] && continue; alert "SESSION: $u on $t $from"; done
  rm -rf "$NOW"
  sleep "$INT"
done
