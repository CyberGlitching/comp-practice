#!/usr/bin/env bash
# harden.sh - first-15-minutes hardening for a Linux box. Asks before every step.
# Usage: sudo ./harden.sh <role>     role = gitlab | comms | web | file | generic
#        AUTO_YES=1 sudo ./harden.sh web   (no prompts - only once you've drilled it in the lab)
#        EXTRA_PORTS="8080 9000" sudo ./harden.sh web
#
# Order matters: backup -> creds -> keys -> users -> sshd -> firewall -> service check.
# It never touches scored users' accounts except to report them. Ask Black/White Team
# at kickoff whether you may change scored users' passwords (and how to report them).

DIR="$(cd "$(dirname "$0")" && pwd)"; source "$DIR/common.sh"
need_root
ROLE="${1:-}"; [[ -n "${ROLE_PORTS[$ROLE]:-}" ]] || { echo "Usage: $0 <gitlab|comms|web|file|generic>"; exit 1; }
FAM=$(os_family)
log_action "harden.sh start role=$ROLE"

# --------------------------------------------------------------- 1 backup
hdr "1. BACKUP /etc (no snapshots allowed - this is your undo button)"
tar czf "$BLUE_DIR/etc-$TS.tgz" /etc 2>/dev/null && ok "Saved $BLUE_DIR/etc-$TS.tgz"
info "Run ./backup.sh $ROLE next for app data (DB dumps, web root, gitlab secrets)."

# --------------------------------------------------------------- 2 passwords
hdr "2. PASSWORDS (root + dog + every unlisted login account)"
PWFILE="$BLUE_DIR/passwords-$TS.txt"; umask 077
if ask "Set a new password for root and dog? (you type it)"; then
  for u in root dog; do
    id "$u" >/dev/null 2>&1 || continue
    passwd "$u" </dev/tty && log_action "password changed: $u"
  done
fi
mapfile -t OTHERS < <(awk -F: '{print $1":"$3":"$7}' /etc/passwd | while IFS=: read -r u uid sh; do
  is_scored "$u" || is_kept "$u" && continue
  { [[ "$uid" -ge 1000 ]] || [[ "$uid" == 0 ]]; } && is_login_shell "$sh" && echo "$u"; done)
if ((${#OTHERS[@]})); then
  info "Unlisted login accounts: ${OTHERS[*]}"
  if ask "Give each a random password (saved to $PWFILE)?"; then
    for u in "${OTHERS[@]}"; do p=$(gen_pw); echo "$u:$p" | chpasswd && echo "$u $p" >> "$PWFILE" && log_action "random password: $u"; done
    ok "Saved to $PWFILE"
  fi
fi
EMPTY=$(awk -F: '$2==""{print $1}' /etc/shadow)
[[ -n "$EMPTY" ]] && warn "Empty passwords: $EMPTY" && ask "Lock them?" && for u in $EMPTY; do passwd -l "$u"; log_action "locked empty-pw $u"; done

# --------------------------------------------------------------- 3 keys
hdr "3. SSH AUTHORIZED KEYS (moved to backup, not deleted)"
KEYS=$(ls /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys* 2>/dev/null)
if [[ -n "$KEYS" ]]; then
  echo "$KEYS"
  if ask "Remove ALL authorized_keys files? (you log in with passwords)"; then
    for f in $KEYS; do chattr -i "$f" 2>/dev/null; backup_file "$f"; rm -f "$f"; log_action "removed $f"; done
    ok "Keys moved to $BLUE_DIR/filebak/$TS"
  fi
else ok "None found"; fi

# --------------------------------------------------------------- 4 users
hdr "4. UNAUTHORIZED / BACKDOOR USERS"
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do
  warn "UID 0 backdoor: $u"
  if ask "Lock $u and set its shell to nologin?"; then usermod -L -e 1 -s /usr/sbin/nologin "$u"; log_action "locked uid0 $u"; fi
done
for u in "${OTHERS[@]}"; do
  [[ "$(id -u "$u" 2>/dev/null)" == 0 ]] && continue
  if ask "Lock unlisted user '$u' (usermod -L, expire, nologin)? Locking > deleting: reversible if it turns out scored"; then
    usermod -L -e 1 -s /usr/sbin/nologin "$u" && pkill -KILL -u "$u" 2>/dev/null; log_action "locked user $u"
  fi
done
for g in sudo wheel admin docker lxd disk; do
  getent group "$g" >/dev/null || continue
  for m in $(getent group "$g" | cut -d: -f4 | tr ',' ' '); do
    is_kept "$m" && continue
    if ask "Remove '$m' from group $g?"; then gpasswd -d "$m" "$g" && log_action "removed $m from $g"; fi
  done
done
if ls /etc/sudoers.d/* >/dev/null 2>&1; then
  echo "sudoers.d contents:"; grep -Hv '^\s*#' /etc/sudoers.d/* 2>/dev/null
  if ask "Move every sudoers.d file out (backup kept)? Check none of them are needed by a service first"; then
    for f in /etc/sudoers.d/*; do [[ "$(basename "$f")" == README ]] && grep -q '^#' "$f" && ! grep -qv '^\s*#\|^\s*$' "$f" && continue; chattr -i "$f" 2>/dev/null; backup_file "$f"; rm -f "$f"; log_action "removed $f"; done
  fi
fi
grep -n NOPASSWD /etc/sudoers && warn "NOPASSWD in /etc/sudoers itself - fix with visudo"
visudo -c >/dev/null && ok "sudoers syntax OK" || warn "sudoers broken - fix NOW with visudo or pkexec"

# --------------------------------------------------------------- 5 sshd
hdr "5. SSHD (stays up - it's scored - but closes the obvious doors)"
if ask "Apply sshd hardening drop-in (no root login, no empty pw, no user env, MaxAuthTries 4)?"; then
  backup_file /etc/ssh/sshd_config; cp -a /etc/ssh/sshd_config.d "$BLUE_DIR/filebak/$TS-sshd_config.d" 2>/dev/null
  # Drop-ins are read first-match-wins on modern OpenSSH, so prefix 00- and also fix the main file.
  mkdir -p /etc/ssh/sshd_config.d
  grep -qE '^\s*Include\s+/etc/ssh/sshd_config.d' /etc/ssh/sshd_config || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  cat > /etc/ssh/sshd_config.d/00-blue.conf <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AuthorizedKeysCommand none
MaxAuthTries 4
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
EOF
  # neutralise any other drop-in that re-enables root/empty pw
  for f in /etc/ssh/sshd_config.d/*.conf; do [[ "$f" == */00-blue.conf ]] && continue; sed -i -E 's/^\s*(PermitRootLogin|PermitEmptyPasswords|AuthorizedKeysCommand|AuthorizedKeysFile)\b/# blue: &/I' "$f"; done
  sed -i -E 's/^\s*(PermitRootLogin|PermitEmptyPasswords|AuthorizedKeysCommand)\b/# blue: &/I' /etc/ssh/sshd_config
  if sshd -t; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || systemctl restart ssh
    ok "sshd reloaded. Keep this session open and test a NEW login before closing it."; log_action "sshd hardened"
  else
    warn "sshd -t failed - restoring"; rm -f /etc/ssh/sshd_config.d/00-blue.conf; cp -a "$BLUE_DIR/filebak/$TS/etc/ssh/sshd_config" /etc/ssh/sshd_config
  fi
fi
info "If a scoring check logs in as root over SSH, re-allow it. Watch the scoreboard after this step."

# --------------------------------------------------------------- 6 pam
hdr "6. PAM BACKDOORS"
grep -lE '^\s*auth\s+sufficient\s+pam_permit\.so' /etc/pam.d/* 2>/dev/null | while read -r f; do
  warn "$f lets ANY password in"; grep -nE 'pam_permit|pam_exec' "$f"
  if ask "Comment out pam_permit/pam_exec auth lines in $f?"; then backup_file "$f"; sed -i -E 's/^(\s*auth\s+\S+\s+(pam_permit|pam_exec)\.so.*)/# blue: \1/' "$f"; log_action "fixed pam $f"; fi
done
[[ -s /etc/ld.so.preload ]] && { warn "ld.so.preload: $(cat /etc/ld.so.preload)"; ask "Empty /etc/ld.so.preload?" && { backup_file /etc/ld.so.preload; chattr -i /etc/ld.so.preload 2>/dev/null; : > /etc/ld.so.preload; log_action "emptied ld.so.preload"; }; }

# --------------------------------------------------------------- 7 perms
hdr "7. FILE PERMISSIONS"
chmod 644 /etc/passwd /etc/group; chown root:root /etc/passwd /etc/group
if [[ $FAM == debian ]]; then chown root:shadow /etc/shadow /etc/gshadow; chmod 640 /etc/shadow /etc/gshadow
else chown root:root /etc/shadow /etc/gshadow; chmod 000 /etc/shadow /etc/gshadow; fi
chmod 440 /etc/sudoers; ok "passwd/shadow/sudoers perms reset"; log_action "perms reset"

# --------------------------------------------------------------- 8 firewall
hdr "8. HOST FIREWALL"
PORTS="${ROLE_PORTS[$ROLE]} ${EXTRA_PORTS:-}"
if [[ $ROLE == file ]]; then
  VC=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
  if [[ -n "$VC" ]]; then
    PMIN=$(awk -F= '/^pasv_min_port/{print $2}' "$VC"); PMAX=$(awk -F= '/^pasv_max_port/{print $2}' "$VC")
    if [[ -n "$PMIN" && -n "$PMAX" ]]; then PORTS="$PORTS $PMIN-$PMAX"
    else warn "vsftpd has no pasv_min_port/pasv_max_port - passive FTP will break behind a firewall. Add pasv_min_port=40000 pasv_max_port=40100 and restart vsftpd"; fi
  fi
  ZP=$(ss -tlnpH 2>/dev/null | awk '/zeroclaw/{split($4,a,":"); print a[length(a)]}' | sort -u | tr '\n' ' ')
  [[ -n "$ZP" ]] && { info "ZeroClaw listening on: $ZP"; PORTS="$PORTS $ZP"; } || warn "ZeroClaw not listening - is it running? Add its port with EXTRA_PORTS"
fi
info "Listening right now:"; ss -tlnpH | awk '{printf "    %-25s %s\n",$4,$6}'
info "Will allow inbound TCP: $PORTS (+ ICMP, + established). Everything else inbound dropped."
warn "Any listener above that's a scored service but NOT in that list will go down. Ctrl-C and use EXTRA_PORTS if so."
if ask "Apply firewall now?"; then
  iptables-save > "$BLUE_DIR/iptables-before-$TS.rules" 2>/dev/null
  if [[ $FAM == rhel ]]; then
    # One tool only. Last year: firewalld kept re-applying red team rules over manual iptables flushes.
    systemctl unmask firewalld 2>/dev/null; systemctl enable --now firewalld
    Z=public
    firewall-cmd --permanent --zone=$Z --set-target=default >/dev/null
    for s in $(firewall-cmd --permanent --zone=$Z --list-services); do firewall-cmd --permanent --zone=$Z --remove-service="$s" >/dev/null; done
    for p in $(firewall-cmd --permanent --zone=$Z --list-ports); do firewall-cmd --permanent --zone=$Z --remove-port="$p" >/dev/null; done
    for r in $(firewall-cmd --permanent --direct --get-all-rules 2>/dev/null | tr ' ' '|'); do warn "direct rule removed: ${r//|/ }"; firewall-cmd --permanent --direct --remove-rule ${r//|/ } >/dev/null; done
    firewall-cmd --permanent --zone=$Z --list-rich-rules | while read -r rr; do [[ -n "$rr" ]] && firewall-cmd --permanent --zone=$Z --remove-rich-rule="$rr" >/dev/null && warn "rich rule removed: $rr"; done
    for b in $(firewall-cmd --permanent --zone=$Z --list-icmp-blocks); do firewall-cmd --permanent --zone=$Z --remove-icmp-block="$b" >/dev/null; done
    firewall-cmd --permanent --zone=$Z --remove-icmp-block-inversion >/dev/null 2>&1
    for p in $PORTS; do firewall-cmd --permanent --zone=$Z --add-port="${p}/tcp" >/dev/null; done
    firewall-cmd --reload >/dev/null && ok "firewalld: $(firewall-cmd --zone=$Z --list-ports)"
  else
    command -v ufw >/dev/null || apt-get install -y ufw >/dev/null
    systemctl disable --now firewalld 2>/dev/null
    ufw --force reset >/dev/null
    ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
    for p in $PORTS; do ufw allow "${p/-/:}/tcp" >/dev/null; done
    # ufw allows ICMP echo by default via before.rules; make sure nobody removed that
    grep -q 'icmp-type echo-request -j ACCEPT' /etc/ufw/before.rules || warn "ICMP echo rule missing from /etc/ufw/before.rules - ping check will fail"
    ufw --force enable >/dev/null && ok "ufw: $(ufw status | grep -c ALLOW) allow rules"
  fi
  log_action "firewall applied ports=$PORTS"
fi

# --------------------------------------------------------------- 9 services
hdr "9. SCORED SERVICES"
for s in ${ROLE_SERVICES[$ROLE]}; do
  systemctl list-unit-files "$s.service" >/dev/null 2>&1 || continue
  st=$(systemctl is-active "$s" 2>/dev/null); en=$(systemctl is-enabled "$s" 2>/dev/null)
  if [[ "$en" == masked ]]; then warn "$s is MASKED"; ask "Unmask $s?" && systemctl unmask "$s"; fi
  if [[ "$st" != active ]]; then warn "$s is $st"; ask "Enable + start $s?" && { systemctl enable --now "$s"; log_action "started $s"; }
  else ok "$s active ($en)"; fi
done
[[ $ROLE == gitlab ]] && command -v gitlab-ctl >/dev/null && gitlab-ctl status | grep -v '^run' | sed 's/^/[!] /'

hdr "DONE"
ok "Actions logged to $ACTION_LOG. Next: ./backup.sh $ROLE, then ./watch.sh in a second terminal."
