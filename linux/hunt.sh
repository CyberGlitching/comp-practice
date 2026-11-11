#!/usr/bin/env bash
# hunt.sh - READ-ONLY triage + persistence hunt. Changes nothing.
# Usage: sudo ./hunt.sh            (prints and saves report to /root/.blue/hunt-<ts>.txt)
#        sudo ./hunt.sh --quick    (skip the slow filesystem sweeps)
# Lines marked [!] deserve a look. Not everything flagged is evil; everything evil should be flagged.

DIR="$(cd "$(dirname "$0")" && pwd)"; source "$DIR/common.sh"
need_root
QUICK=0; [[ "${1:-}" == "--quick" ]] && QUICK=1
OUT="$BLUE_DIR/hunt-$TS.txt"
exec > >(tee "$OUT") 2>&1

hdr "HOST"
echo "$(hostname) | $(. /etc/os-release; echo "$PRETTY_NAME") | kernel $(uname -r) | $(date)"
ip -br a 2>/dev/null

# ---------------------------------------------------------------- sessions
hdr "WHO IS ON THE BOX (kill what isn't you: pkill -KILL -t <tty>)"
w 2>/dev/null
info "Note: ttyS0/tty1 can be your own Proxmox console. pts/* from an IP you don't own is not."

# ---------------------------------------------------------------- users
hdr "USERS"
while IFS=: read -r u _ uid gid _ home shell; do
  tag=""
  is_scored "$u" && tag="(scored)"
  is_kept "$u" && tag="(ours)"
  if [[ "$uid" == 0 && "$u" != root ]]; then warn "UID 0 account: $u  shell=$shell  <-- backdoor root"; continue; fi
  if is_login_shell "$shell"; then
    if [[ -z "$tag" && ( "$uid" -ge 1000 || "$uid" == 0 ) ]]; then
      warn "Unlisted login user: $u uid=$uid home=$home shell=$shell"
    elif [[ -z "$tag" && "$uid" -lt 1000 && "$u" != root ]]; then
      warn "System account with a login shell: $u uid=$uid shell=$shell"
    else
      echo "    $u uid=$uid shell=$shell $tag"
    fi
  fi
done < /etc/passwd

hdr "PASSWORD STATE (empty / no-password accounts)"
awk -F: '($2=="" ){print "[!] EMPTY password: "$1}' /etc/shadow
awk -F: '($2!~/^[!*]/ && $2!=""){print "    has password: "$1}' /etc/shadow

hdr "PRIVILEGED GROUPS"
for g in sudo wheel admin root adm docker lxd disk shadow; do
  m=$(getent group "$g" | cut -d: -f4); [[ -n "$m" ]] && echo "    $g: $m"
done
for g in docker lxd disk; do
  m=$(getent group "$g" | cut -d: -f4); [[ -n "$m" ]] && warn "Members of $g can get root: $m"
done

hdr "SUDOERS (NOPASSWD and anything in sudoers.d)"
grep -HnEv '^\s*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | while read -r l; do
  if [[ "$l" =~ NOPASSWD|ALL=\(ALL ]]; then warn "$l"; else echo "    $l"; fi
done

# ---------------------------------------------------------------- ssh
hdr "AUTHORIZED KEYS (every key here is a way back in)"
for f in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys* /etc/ssh/authorized_keys* ; do
  [[ -s "$f" ]] || continue
  warn "$f ($(grep -cv '^\s*#' "$f") keys)"
  awk '{print "        " $NF}' "$f" | head -20
done
grep -rhiE '^\s*AuthorizedKeys(File|Command)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | while read -r l; do warn "sshd: $l"; done

hdr "SSHD EFFECTIVE CONFIG (key lines)"
sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|authorizedkeysfile|usepam|port|listenaddress|allowusers|maxauthtries|x11forwarding|permituserenvironment) ' | while read -r k v; do
  case "$k $v" in
    "permitrootlogin yes"|"permitemptypasswords yes"|"permituserenvironment yes") warn "$k $v";;
    *) echo "    $k $v";;
  esac
done
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null

hdr "PAM (pam_permit / pam_exec in auth = backdoor)"
grep -HnE 'pam_permit|pam_exec|pam_script|pam_succeed_if.*uid.*0' /etc/pam.d/* 2>/dev/null | grep -v '^\s*#' | while read -r l; do
  if [[ "$l" =~ auth.*(sufficient|required).*pam_permit ]] || [[ "$l" =~ pam_exec ]]; then warn "$l"; else echo "    $l"; fi
done
find /lib*/security /usr/lib*/security /lib/*/security -name '*.so' -newer /etc/hostname 2>/dev/null | while read -r f; do warn "PAM module newer than install: $f"; done

# ---------------------------------------------------------------- scheduled
hdr "CRON (all of it)"
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* /etc/anacrontab; do
  [[ -f "$f" ]] || continue
  lines=$(grep -Ev '^\s*(#|$|SHELL|PATH|MAILTO|HOME|LOGNAME)' "$f")
  [[ -z "$lines" ]] && continue
  echo "  -- $f"
  echo "$lines" | while read -r l; do
    if [[ "$l" =~ (curl|wget|nc |ncat|/dev/tcp|bash\ -i|base64|python|perl|iptables|nft|useradd|chpasswd|/tmp/|/dev/shm|/var/tmp) ]]; then warn "   $l"; else echo "     $l"; fi
  done
done
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  find "$d" -type f -newer /etc/hostname 2>/dev/null | while read -r f; do warn "Recently added: $f"; done
done
atq 2>/dev/null | while read -r l; do warn "at job: $l"; done

hdr "SYSTEMD TIMERS"
systemctl list-timers --all --no-pager 2>/dev/null | head -30

hdr "SYSTEMD UNITS NOT FROM A PACKAGE (custom/dropped units)"
for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system ~root/.config/systemd/user /home/*/.config/systemd/user; do
  [[ -d "$d" ]] || continue
  find "$d" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) 2>/dev/null
done | while read -r f; do
  owned=1
  if command -v dpkg >/dev/null; then dpkg -S "$f" >/dev/null 2>&1 || owned=0
  elif command -v rpm >/dev/null; then rpm -qf "$f" >/dev/null 2>&1 || owned=0; fi
  if [[ $owned == 0 ]]; then
    ex=$(grep -hE '^\s*Exec(Start|StartPre|StartPost|Stop)=' "$f" | head -2 | tr '\n' ' ')
    warn "Unpackaged unit: $f  ->  $ex"
  fi
done
info "Unpackaged units also include legit app units (gitlab-runsvdir, mattermost, zeroclaw). Read the Exec line."

hdr "RUNNING SERVICES"
systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print "    "$1}'

# ---------------------------------------------------------------- shell init
hdr "SHELL INIT FILES (aliases / PROMPT_COMMAND / launchers)"
for f in /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc /etc/environment /root/.bashrc /root/.profile /root/.bash_profile /root/.bash_logout /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.bash_logout; do
  [[ -f "$f" ]] || continue
  grep -HnE 'alias (sudo|su|ls|ps|ss|netstat|cat|passwd|ssh)=|PROMPT_COMMAND|/dev/tcp|nc |ncat|curl |wget |base64|nohup|setsid|LD_PRELOAD|\(\) *\{' "$f" 2>/dev/null | while read -r l; do warn "$l"; done
done
[[ -s /etc/ld.so.preload ]] && { warn "/etc/ld.so.preload is NOT empty (userland rootkit):"; cat /etc/ld.so.preload; }
grep -l LD_PRELOAD /proc/[0-9]*/environ 2>/dev/null | head -5 | while read -r f; do warn "Process with LD_PRELOAD: $f"; done
[[ -f /etc/rc.local ]] && { echo "  -- /etc/rc.local"; grep -Ev '^\s*(#|$)' /etc/rc.local; }

# ---------------------------------------------------------------- network
hdr "LISTENING PORTS"
ss -tulpnH 2>/dev/null | awk '{printf "    %-5s %-28s %s\n",$1,$5,$7}'

hdr "ESTABLISHED CONNECTIONS (outbound to strangers = C2)"
ss -tnpH state established 2>/dev/null | awk '{printf "    %-28s -> %-28s %s\n",$3,$4,$5}'

hdr "FIREWALL STATE (one tool only! firewalld vs ufw vs raw iptables fight each other)"
systemctl is-active firewalld >/dev/null 2>&1 && echo "    firewalld: ACTIVE" || echo "    firewalld: inactive"
command -v ufw >/dev/null && ufw status 2>/dev/null | head -3 | sed 's/^/    /'
command -v iptables >/dev/null && iptables -S 2>/dev/null | grep -E 'DROP|REJECT' | while read -r l; do warn "iptables: $l"; done
command -v nft >/dev/null && nft list ruleset 2>/dev/null | grep -nE 'drop|reject' | head -20 | while read -r l; do echo "    nft: $l"; done

# ---------------------------------------------------------------- processes
hdr "SUSPICIOUS PROCESSES"
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-150)
  if [[ "$exe" == *"(deleted)"* ]]; then warn "pid $pid runs a DELETED binary: $exe | $cmd"; fi
  if [[ "$exe" =~ ^/(tmp|dev/shm|var/tmp|run/user)/ || "$exe" =~ /\.[^/]+/ ]]; then warn "pid $pid runs from odd path: $exe | $cmd"; fi
  if [[ "$cmd" =~ (/dev/tcp|nc\ -e|ncat.*-e|bash\ -i|sh\ -i|socat|python.*pty|perl\ -e|base64\ -d|sleep\ [0-9]+.*;|while\ true) ]]; then warn "pid $pid looks like a shell/loop: $cmd"; fi
  # kernel-thread impostors: name in [brackets] but has an exe
  if [[ "$cmd" =~ ^\[.*\] ]]; then warn "pid $pid fake kernel thread name: $cmd exe=$exe"; fi
done
info "Loops: find the parent with: ps -o ppid= -p <pid>; then pstree -ps <pid>"

# ---------------------------------------------------------------- files
hdr "SUID/SGID OUTSIDE NORMAL SET"
if [[ $QUICK == 0 ]]; then
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while read -r f; do
    case "$f" in
      /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/libexec/*|/bin/*|/sbin/*|/snap/*)
        case "$(basename "$f")" in
          bash|sh|dash|zsh|python*|perl|vim*|find|cp|nmap|less|more|env|tee|awk|nano) warn "SUID shell/tool: $f";;
        esac;;
      *) warn "SUID/SGID in odd place: $f";;
    esac
  done
fi

hdr "SENSITIVE FILE PERMISSIONS"
stat -c '    %A %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null
[[ $(stat -c %a /etc/shadow) =~ [1-7]$ ]] && warn "/etc/shadow is world-readable"
[[ $(stat -c %a /etc/passwd) =~ [2367].$|[2367]$ ]] && warn "/etc/passwd is writable by non-root"

hdr "IMMUTABLE FILES (chattr +i: red team uses it to stop you deleting their stuff)"
lsattr -R /etc /root /home /var/spool/cron /usr/local/bin /opt 2>/dev/null | grep -E '^[^ ]*i[^ ]* ' | while read -r l; do warn "$l"; done

hdr "HIDING SPOTS (/tmp /dev/shm /var/tmp, dot-dirs)"
find /tmp /var/tmp /dev/shm /run/shm -mindepth 1 -maxdepth 3 \( -type f -o -type d -name '.*' \) 2>/dev/null | grep -vE 'systemd-private|\.X11-unix|\.ICE-unix|\.XIM-unix|\.font-unix|\.Test-unix|snap\.' | head -40 | while read -r f; do warn "$f"; done

if [[ $QUICK == 0 ]]; then
  hdr "FILES CHANGED IN LAST 60 MIN (outside /proc /sys /run, data dirs)"
  find /etc /root /home /usr/local /opt /var/www /srv /var/spool -xdev -type f -mmin -60 2>/dev/null | grep -vE '/\.blue/|\.cache/|/var/opt/gitlab/(postgresql|redis|gitlab-rails/shared|prometheus)' | head -60

  hdr "RANSOMWARE SIGNS"
  find /var/www /srv /home /opt /var/ftp /root -xdev -type f \( -iname '*.enc' -o -iname '*.locked' -o -iname '*.crypt*' -o -iname '*.dog' -o -iname '*.pwned' -o -iname '*.encrypted' \) 2>/dev/null | head -20 | while read -r f; do warn "Encrypted-looking: $f"; done
  grep -rliE 'bitcoin|decrypt your|your files (have been|are) encrypted|ransom' /var/www /srv /home /root /opt /tmp 2>/dev/null | head -10 | while read -r f; do warn "Ransom note / encryptor?: $f"; done
  info "Red team encryptors often leave the key in the script that did it. grep for 'openssl enc', 'gpg --batch', 'key=' in the paths above."

  hdr "WEBSHELLS"
  for d in /var/www /usr/share/nginx /srv; do
    [[ -d $d ]] || continue
    grep -rlE --include='*.php' --include='*.phtml' --include='*.jsp' --include='*.py' 'system\s*\(|shell_exec|passthru|eval\s*\(\s*\$_|base64_decode\s*\(\s*\$_|assert\s*\(\s*\$_|popen\s*\(' "$d" 2>/dev/null | head -20 | while read -r f; do warn "Possible webshell: $f"; done
  done
fi

# ---------------------------------------------------------------- apps
hdr "APP-SPECIFIC"
if [[ -f /etc/vsftpd.conf || -f /etc/vsftpd/vsftpd.conf ]]; then
  f=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | head -1)
  echo "  vsftpd ($f):"; grep -E '^(anonymous_enable|anon_upload_enable|anon_mkdir_write_enable|write_enable|chroot_local_user|local_enable|pasv_min_port|pasv_max_port|userlist_enable|userlist_deny)' "$f" | sed 's/^/    /'
  grep -qE '^anonymous_enable=YES' "$f" && warn "Anonymous FTP is ON"
  grep -qE '^anon_upload_enable=YES' "$f" && warn "Anonymous FTP upload is ON"
fi
for zc in /root/.zeroclaw /home/*/.zeroclaw /etc/zeroclaw /opt/zeroclaw; do
  [[ -d "$zc" ]] || continue
  echo "  ZeroClaw dir: $zc"
  grep -HnE '^\s*(host|port|allow_public_bind|require_pairing|paired_tokens|level|workspace_only|allowed_commands|forbidden_paths)\s*=' "$zc"/config.toml "$zc"/*.toml 2>/dev/null | sed 's/^/    /'
  grep -qE 'require_pairing\s*=\s*false' "$zc"/config.toml 2>/dev/null && warn "ZeroClaw pairing DISABLED - anyone can drive the agent"
  find "$zc" -type f -mmin -120 2>/dev/null | head -20 | while read -r f; do warn "Recently changed ZeroClaw file (prompt/skill/memory persistence?): $f"; done
done
command -v mysql >/dev/null && info "MySQL present: run ./mysql-audit.sh"
[[ -x /opt/gitlab/bin/gitlab-rails ]] && info "GitLab present: run ./app-audit.sh gitlab"
[[ -d /opt/mattermost ]] && info "Mattermost present: run ./app-audit.sh mattermost"

hdr "DONE"
ok "Report saved: $OUT"
grep -c '\[!\]' "$OUT" | xargs -I{} echo "{} findings flagged [!]"
