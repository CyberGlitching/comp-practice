#!/bin/sh
# pf-audit.sh - READ-ONLY audit of a pfSense box. Run from console option 8 (Shell):
#   fetch -o /tmp/pf-audit.sh https://raw.githubusercontent.com/<you>/<repo>/main/pfsense/pf-audit.sh && sh /tmp/pf-audit.sh
# Fixes are done in the web GUI (safer: pfSense rewrites config.xml). See the doc's pfSense checklist.
C=/conf/config.xml
h() { printf '\n==== %s ====\n' "$1"; }
w() { printf '[!] %s\n' "$1"; }

h "VERSION"; cat /etc/version 2>/dev/null; uname -r

h "GUI USERS (should be: admin only, unless the packet says otherwise)"
xmllint --xpath '//system/user/name/text()' $C 2>/dev/null | tr ' ' '\n' || grep -A1 '<user>' $C | grep '<name>'
grep -c '<authorizedkeys>' $C | xargs -I{} echo "authorizedkeys entries in config: {}"
grep -q '<authorizedkeys>.\+</authorizedkeys>' $C && w "SSH authorized keys stored for a GUI user (System > User Manager)"
grep -o '<priv>[^<]*</priv>' $C | sort | uniq -c

h "PERSISTENCE IN CONFIG.XML (shellcmd / earlyshellcmd / cron)"
grep -nE '<(shellcmd|earlyshellcmd)>' $C && w "shellcmd runs a command at EVERY boot (Services > Shellcmd, or config.xml)"
sed -n '/<cron>/,/<\/cron>/p' $C | grep '<command>' | sed 's/^/    /'
crontab -l 2>/dev/null | grep -v '^#' | sed 's/^/    root crontab: /'
ls -la /root/.ssh/ 2>/dev/null

h "SERVICES"
grep -q '<enablesshd>' $C && w "SSH is enabled on the firewall - disable unless you need it (System > Advanced > Admin Access)"
grep -o '<protocol>[a-z]*</protocol>' $C | head -1 | sed 's/^/    webgui /'
sockstat -4l 2>/dev/null | awk 'NR>1{print "    "$2" "$6}' | sort -u

h "NAT PORT FORWARDS (a forward to an internal box = a door in)"
sed -n '/<nat>/,/<\/nat>/p' $C | grep -E '<(descr|target|local-port|interface)>' | sed 's/^/    /'

h "FIREWALL RULES (look for pass any->any, rules with odd descriptions, disabled block rules)"
sed -n '/<filter>/,/<\/filter>/p' $C | grep -E '<(type|interface|descr|any|disabled)' | paste - - - - 2>/dev/null | head -60 | sed 's/^/    /'

h "DNS RESOLVER (DNS is scored on this box)"
grep -q '<unbound>' $C && echo "    unbound configured" || w "Unbound not configured?"
sed -n '/<unbound>/,/<\/unbound>/p' $C | grep -E '<(enable|custom_options|forwarding|host>|domain>|ip>)' | sed 's/^/    /'
grep -q '<custom_options>' $C && w "Unbound custom options present - read them (can forward/poison DNS)"
pgrep -l unbound >/dev/null && echo "    unbound running" || w "unbound NOT running (Services > DNS Resolver > Save/Apply, or Status > Services)"

h "PACKAGES"
pkg info 2>/dev/null | grep -i pfSense-pkg | sed 's/^/    /'

h "PROCESSES (anything that isn't pfSense)"
ps auxww | grep -vE '\[|php-fpm|nginx|unbound|dpinger|syslogd|filterlog|dhcp|ntpd|cron|getty|sshd|check_reload|minicron|sh -c|ps aux|grep|login|tcsh|devd|rtsold|radvd|openvpn|lighttpd|pf-audit|awk|sort|zsh' | sed 's/^/    /'

h "FILES CHANGED IN GUI / BOOT PATHS (last 2 days; webshells live in /usr/local/www)"
find /usr/local/www /etc/inc /usr/local/etc/rc.d /etc/rc.conf.local /root -type f -mtime -2 2>/dev/null | sed 's/^/[!] /'
echo
echo "Done. Fix in GUI: System > User Manager (passwords/users/keys), Firewall > NAT, Firewall > Rules,"
echo "Services > DNS Resolver, Diagnostics > Backup & Restore (download config.xml FIRST)."
