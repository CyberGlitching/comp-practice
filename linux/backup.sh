#!/usr/bin/env bash
# backup.sh - back up the things that make a scored service work. Run right after harden.sh
# and again after any big fix. Snapshots are banned at GDDC, so this IS your rollback.
# Usage: sudo ./backup.sh <gitlab|comms|web|file|generic> [user@other-box:/path]   (optional off-box copy)
# Restore hints are printed at the end.

DIR="$(cd "$(dirname "$0")" && pwd)"; source "$DIR/common.sh"
need_root
ROLE="${1:-generic}"; DEST="${2:-}"
BK="$BLUE_DIR/bk/$TS"; mkdir -p "$BK"; chmod 700 "$BLUE_DIR/bk"

hdr "Backing up for role: $ROLE -> $BK"
tar czf "$BK/etc.tgz" /etc 2>/dev/null && ok "etc"

case "$ROLE" in
  web)
    for d in /var/www /usr/share/nginx/html /srv/www; do [[ -d $d ]] && tar czf "$BK/$(echo "$d" | tr / _).tgz" "$d" && ok "$d"; done
    if command -v mysqldump >/dev/null; then
      read -r -s -p "MySQL root password (blank = try socket auth): " MP </dev/tty; echo
      if [[ -n "$MP" ]]; then MYSQL_PWD="$MP" mysqldump -uroot --all-databases --routines --events --triggers > "$BK/mysql-all.sql"
      else mysqldump --all-databases --routines --events --triggers > "$BK/mysql-all.sql"; fi
      [[ -s "$BK/mysql-all.sql" ]] && ok "mysqldump ($(du -h "$BK/mysql-all.sql" | cut -f1))" || warn "mysqldump failed"
    fi ;;
  gitlab)
    # gitlab-secrets.json is the thing people forget: without it a restore can't decrypt CI vars/2FA.
    tar czf "$BK/etc-gitlab.tgz" /etc/gitlab && ok "/etc/gitlab (incl. gitlab-secrets.json + gitlab.rb)"
    if ask "Run gitlab-backup create? (can take minutes and load the box)"; then
      gitlab-backup create SKIP=artifacts,registry,builds STRATEGY=copy 2>&1 | tail -3
      ls -t /var/opt/gitlab/backups/*.tar 2>/dev/null | head -1 | xargs -r -I{} cp {} "$BK/" && ok "gitlab data backup copied"
    fi ;;
  comms)
    MM=/opt/mattermost
    [[ -d $MM/config ]] && tar czf "$BK/mm-config.tgz" $MM/config && ok "mattermost config"
    [[ -d $MM/data ]] && ask "Back up mattermost data dir ($(du -sh $MM/data 2>/dev/null | cut -f1))?" && tar czf "$BK/mm-data.tgz" $MM/data && ok "mattermost data"
    DSN=$(grep -oE '"DataSource":\s*"[^"]+"' $MM/config/config.json 2>/dev/null | cut -d'"' -f4)
    if [[ "$DSN" == postgres* ]]; then
      sudo -u postgres pg_dumpall > "$BK/postgres-all.sql" 2>/dev/null && ok "pg_dumpall" || warn "pg_dumpall failed (try: sudo -u postgres pg_dump mattermost)"
    elif [[ "$DSN" == *tcp* || "$DSN" == mysql* ]]; then
      warn "Mattermost uses MySQL: dump it with mysqldump"
    fi ;;
  file)
    for d in /srv/ftp /var/ftp /home /srv; do [[ -d $d ]] && tar czf "$BK/$(echo "$d" | tr / _).tgz" --exclude='*/.cache' "$d" 2>/dev/null && ok "$d"; done
    for z in /root/.zeroclaw /home/*/.zeroclaw /etc/zeroclaw; do [[ -d $z ]] && tar czf "$BK/zeroclaw$(echo "$z" | tr / _).tgz" "$z" && ok "$z"; done ;;
esac

# Unit files for scored services
for s in ${ROLE_SERVICES[$ROLE]}; do
  f=$(systemctl show -p FragmentPath --value "$s" 2>/dev/null); [[ -f "$f" ]] && cp -a "$f" "$BK/" 2>/dev/null
done

( cd "$BK" && sha256sum ./* > SHA256SUMS ) && ok "Checksums written"
log_action "backup role=$ROLE -> $BK"

if [[ -n "$DEST" ]]; then
  scp -r "$BK" "$DEST" && ok "Copied off-box to $DEST" || warn "Off-box copy failed"
else
  info "Tip: copy off-box too, red team can delete /root: scp -r $BK dog@<other-box>:/tmp/.x/"
fi

cat <<EOF

Restore cheatsheet:
  one file from /etc:   tar xzf $BK/etc.tgz -C / etc/path/to/file
  web root:             tar xzf $BK/_var_www.tgz -C /
  MySQL:                mysql -uroot -p < $BK/mysql-all.sql
  GitLab config:        tar xzf $BK/etc-gitlab.tgz -C / && gitlab-ctl reconfigure
  Postgres (MM):        sudo -u postgres psql -f $BK/postgres-all.sql
EOF
