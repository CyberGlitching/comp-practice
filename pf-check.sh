#!/bin/bash
# =============================================================================
#  pf-check.sh — read-only pfSense audit for GDDC Team 7. Run from a Kali box.
#  Never changes pfSense. Uses sshpass; drives the console menu (option 8) if a
#  direct command doesn't work.
#
#  Usage:
#    PFPASS='<admin pw>' ./pf-check.sh                 # dump + diff + highlights
#    PFPASS='<admin pw>' ./pf-check.sh --baseline      # save current pfctl -sr/-sn as known-good
#    ./pf-check.sh --probe                             # from Kali: ping + port-check every scored service
#    ./pf-check.sh --egress-howto                      # print the WebUI egress steps
# =============================================================================
TEAM=7
PF=172.16.$TEAM.1
PFUSER=${PFUSER:-admin}
DIR=$(cd "$(dirname "$0")" && pwd)
KNOWN_RULES=$DIR/known-good-rules.txt     # fill in / --baseline: one normalized `pfctl -sr` line per row
KNOWN_NAT=$DIR/known-good-nat.txt
OUT=$DIR/pf-dump-$(date +%Y%m%d-%H%M%S)
SCORED_PORTS='22|21|53|80|88|135|139|389|443|445|464|636|3268|3269|5985|5986|8000'
R=$'\e[1;31m'; Y=$'\e[1;33m'; G=$'\e[1;32m'; B=$'\e[1m'; N=$'\e[0m'
sec(){ printf '\n%s==== %s ====%s\n' "$B" "$*" "$N"; }

probe(){
  sec "PROBE from $(hostname) (own team network only)"
  local h p
  for h in 1 10 20 30 40; do
    if ping -c1 -W2 "172.16.$TEAM.$h" >/dev/null 2>&1; then printf '  %sICMP ok%s   172.16.%s.%s\n' "$G" "$N" "$TEAM" "$h"; else printf '  %sICMP FAIL%s 172.16.%s.%s\n' "$R" "$N" "$TEAM" "$h"; fi
  done
  check(){ if timeout 4 bash -c "</dev/tcp/$1/$2" 2>/dev/null; then printf '  %sopen%s   %s:%s %s\n' "$G" "$N" "$1" "$2" "$3"; else printf '  %sCLOSED%s %s:%s %s\n' "$R" "$N" "$1" "$2" "$3"; fi; }
  check "$PF" 443 "pfSense WebUI(https)"; check "$PF" 80 "pfSense WebUI(http)"
  for p in 22 80; do check "172.16.$TEAM.10" $p web; done
  for p in 22 21 445; do check "172.16.$TEAM.20" $p file; done
  for p in 22 80; do check "172.16.$TEAM.30" $p msgboard; done
  for p in 22 389 5985 53 88; do check "172.16.$TEAM.40" $p DC; done
  local code; code=$(curl -s -o /dev/null --max-time 20 -w '%{http_code}' "http://172.16.$TEAM.10/watch/cdo/cdo_documentary_2026.mp4")
  [[ $code == 200 ]] && echo "  ${G}HTTP Content web 200${N}" || echo "  ${R}HTTP Content web -> $code${N}"
  code=$(curl -s -o /dev/null --max-time 10 -w '%{http_code}' "http://172.16.$TEAM.30/"); echo "  msgboard / -> $code"
  if command -v smbclient >/dev/null; then smbclient "//172.16.$TEAM.20/ftp" -U 'amarino%bb123#123' -m SMB3 -c ls >/dev/null 2>&1 && echo "  ${G}SMB amarino ok${N}" || echo "  ${R}SMB amarino FAIL${N}"; fi
  curl -s --max-time 10 -u 'amarino:bb123#123' "ftp://172.16.$TEAM.20/" -o /dev/null && echo "  ${G}FTP amarino ok${N}" || echo "  ${R}FTP amarino FAIL${N}"
}

egress_howto(){ sed -n '/^## pfSense egress policy/,/^## /p' "$DIR/../README.md" 2>/dev/null | sed '$d' || echo "see README.md"; }

case "${1:-}" in --probe) probe; exit;; --egress-howto) egress_howto; exit;; esac
command -v sshpass >/dev/null || { echo "apt install sshpass"; exit 1; }
[[ -n ${PFPASS:-} ]] || { read -r -s -p "pfSense $PFUSER password: " PFPASS; echo; }
export SSHPASS=$PFPASS
SSHO=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=8)
mkdir -p "$OUT"

# ----- the read-only script run on pfSense (FreeBSD /bin/sh). Keep lines short (tty limits). -----
REMOTE=$(cat <<'EOS'
C=/cf/conf/config.xml
s(){ printf '\100\100SEC %s\n' "$1"; }
s RULES; pfctl -sr 2>&1
s NAT; pfctl -sn 2>&1
s TABLES; for t in $(pfctl -sT 2>/dev/null); do echo "-- $t"; pfctl -t "$t" -T show 2>/dev/null | head -30; done
s IFACES; ifconfig -a | grep -E '^[a-z]|inet '
s XMLFILTER; sed -n '/<filter>/,/<\/filter>/p' $C
s XMLNAT; sed -n '/<nat>/,/<\/nat>/p' $C
s XMLALIASES; sed -n '/<aliases>/,/<\/aliases>/p' $C
s XMLIF; sed -n '/<interfaces>/,/<\/interfaces>/p' $C
s USERS; sed -n '/<system>/,/<\/system>/p' $C | grep -E '<user>|</user>|<name>|<scope>|<priv>|<disabled|<groupname>|<member>|<authorizedkeys>|<expires>|<uid>'
s WEBGUI; sed -n '/<webgui>/,/<\/webgui>/p' $C; grep -E 'noantilockout|nohttpreferercheck|disablehttpredirect|enablesshd|sshdkeyonly|sshport' $C
s SHELLCMD; grep -E '<shellcmd>|<earlyshellcmd>|<afterfilterchangeshellcmd>' $C
s CRONXML; sed -n '/<cron>/,/<\/cron>/p' $C | grep -E '<command>|<who>|<minute>|<hour>'
s CRONFS; cat /etc/crontab; ls -la /var/cron/tabs 2>/dev/null; cat /var/cron/tabs/* 2>/dev/null
s PKGS; pkg query -e '%a = 0' '%n-%v' 2>/dev/null
s KEYS; for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] && { echo "-- $f"; cat "$f"; }; done
s LISTEN; sockstat -4 -l 2>/dev/null | grep -vE '^USER'
s CONNS; sockstat -4 -c 2>/dev/null | grep -vE '^USER' | head -60
s PROCS; ps auxww | grep -vE '\[|ps auxww' | grep -E 'nc |ncat|socat|python|perl|/tmp/|bash -i|sh -i|php -r|curl|fetch '
s RCD; ls -la /usr/local/etc/rc.d/ 2>/dev/null; ls -la /etc/rc.conf.local /usr/local/etc/rc.d/*.sh 2>/dev/null
s END
EOS
)

run_direct(){ # only feed the script if a plain command really runs (never feed lines into the console menu)
  timeout 20 sshpass -e ssh "${SSHO[@]}" "$PFUSER@$PF" 'echo PFDIRECT_OK' </dev/null 2>&1 | grep -q '^PFDIRECT_OK' || return 1
  printf '%s\n' "$REMOTE" | timeout 120 sshpass -e ssh "${SSHO[@]}" "$PFUSER@$PF" 'sh -s' 2>&1; }
run_menu(){ # console menu: 8 = shell. Feed commands through the PTY.
  { sleep 3; printf '8\n'; sleep 2; printf 'sh\n'; sleep 1
    printf '%s\n' "$REMOTE" | while IFS= read -r l; do printf '%s\n' "$l"; sleep 0.05; done
    sleep 4; printf 'exit\nexit\n'; sleep 1; printf '0\n'; } | timeout 180 sshpass -e ssh -tt "${SSHO[@]}" "$PFUSER@$PF" 2>&1 | tr -d '\r'; }

echo "connecting to $PFUSER@$PF ..."
RAW=$(run_direct || true)
if ! grep -q '^@@SEC END' <<<"$RAW"; then echo "direct exec didn't work (console menu?) — driving option 8"; RAW=$(run_menu); fi
grep -q '^@@SEC END' <<<"$RAW" || { echo "${R}could not collect data. Raw output in $OUT/raw.txt${N}"; printf '%s\n' "$RAW" >"$OUT/raw.txt"; exit 1; }
printf '%s\n' "$RAW" >"$OUT/raw.txt"
awk -v d="$OUT" '/^@@SEC /{f=d"/"$2".txt"; next} f{print > f}' "$OUT/raw.txt"
echo "dump: $OUT"

norm(){ sed -E 's/ (ridentifier|label) "?[^ ]+"?//g; s/[[:space:]]+/ /g; s/ $//' | grep -vE '^\s*$|^@@|^\$ |^# ' | sort -u; }

sec "RULES diff vs $KNOWN_RULES"
if [[ "${1:-}" == --baseline ]]; then norm <"$OUT/RULES.txt" >"$KNOWN_RULES"; norm <"$OUT/NAT.txt" >"$KNOWN_NAT"; echo "baseline written — REVIEW it, it is now your known-good"; fi
if [[ -s $KNOWN_RULES ]]; then
  diff <(norm <"$KNOWN_RULES") <(norm <"$OUT/RULES.txt") | grep -E '^[<>]' | sed -e "s/^>/  ${R}NEW    ${N}/" -e "s/^</  ${Y}MISSING${N}/" || echo "  ${G}rules match known-good${N}"
else echo "  ${Y}no known-good file yet: run with --baseline after reviewing the rules below${N}"; fi
if [[ -s $KNOWN_NAT ]]; then
  sec "NAT diff vs $KNOWN_NAT"
  diff <(norm <"$KNOWN_NAT") <(norm <"$OUT/NAT.txt") | grep -E '^[<>]' | sed -e "s/^>/  ${R}NEW    ${N}/" -e "s/^</  ${Y}MISSING${N}/" || echo "  ${G}NAT matches known-good${N}"
fi

sec "HIGHLIGHT: block/reject touching team net, scored ports, or ICMP"
grep -E '^(block|reject)|return-rst|return-icmp' "$OUT/RULES.txt" | grep -E "172\.16\.$TEAM\.|port = ($SCORED_PORTS)\b|port ($SCORED_PORTS)\b|icmp|\{[^}]*($SCORED_PORTS)" | sed "s/^/  ${R}!${N} /"
grep -cE '^(block|reject)' "$OUT/RULES.txt" | sed 's/^/  total block\/reject lines: /'
sec "HIGHLIGHT: NAT / port forwards (rdr) and outbound NAT"
grep -E '^rdr' "$OUT/NAT.txt" | grep -vE 'anti-lockout|pfSense' | sed "s/^/  ${Y}rdr${N} /"
grep -E '^(nat|binat)' "$OUT/NAT.txt" | head -20 | sed 's/^/  /'
grep -q 'anti-lockout' "$OUT/RULES.txt" && echo "  anti-lockout rule present" || echo "  ${Y}anti-lockout rule NOT present (noantilockout set?)${N}"
sec "pass rules from anywhere to the firewall's admin ports (exposure)"
grep -E '^pass in' "$OUT/RULES.txt" | grep -E 'port = (22|80|443)\b' | sed 's/^/  /'
sec "WebUI / SSH settings"
sed 's/^/  /' "$OUT/WEBGUI.txt"
sec "users / privileges / keys"
sed 's/^/  /' "$OUT/USERS.txt"
grep -oE '<authorizedkeys>[^<]+' "$OUT/USERS.txt" | sed 's/<authorizedkeys>//' | while read -r k; do echo "  ${R}user SSH key:${N} $(echo "$k" | base64 -d 2>/dev/null | cut -c1-60)..."; done
[[ -s $OUT/KEYS.txt ]] && { echo "  ${R}authorized_keys on disk:${N}"; sed 's/^/    /' "$OUT/KEYS.txt"; }
sec "shellcmd / earlyshellcmd (boot persistence)"
[[ -s $OUT/SHELLCMD.txt ]] && sed "s/^/  ${R}!${N} /" "$OUT/SHELLCMD.txt" || echo "  none"
sec "cron"
sed 's/^/  /' "$OUT/CRONXML.txt"; grep -vE '^#|^$' "$OUT/CRONFS.txt" | sed 's/^/  /'
sec "packages (non-automatic)"
sed 's/^/  /' "$OUT/PKGS.txt"
sec "listening sockets / outbound connections / odd processes"
sed 's/^/  /' "$OUT/LISTEN.txt"; echo "  -- connections:"; sed 's/^/  /' "$OUT/CONNS.txt"; echo "  -- processes:"; sed "s/^/  ${Y}?${N} /" "$OUT/PROCS.txt"
echo; echo "Nothing was changed on pfSense. Fixes are manual in the WebUI (see README: pfSense egress policy)."
