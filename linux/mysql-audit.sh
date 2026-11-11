#!/usr/bin/env bash
# mysql-audit.sh - audit + fix MySQL/MariaDB on the Web Server. Asks before each change.
# Usage: sudo ./mysql-audit.sh
# FIRST find which account the web app uses. If the app uses root and you change root's
# password without updating the app config, HTTP goes down. That's the classic own-goal.

DIR="$(cd "$(dirname "$0")" && pwd)"; source "$DIR/common.sh"
need_root

hdr "Which DB creds does the web app use?"
grep -rnoE --include='*.php' --include='.env' --include='*.ini' --include='*.conf' --include='*.py' --include='*.js' --include='*.json' --include='*.yml' \
  "(DB_(USER|USERNAME|PASSWORD|PASS|HOST|NAME)|db_user|db_pass|'user(name)?'|'password'|mysqli?_connect|new PDO)[^;]{0,120}" /var/www /srv 2>/dev/null | head -20
info "Note the user + config file path. Change that user's password in BOTH MySQL and the config file, together."

read -r -s -p "MySQL root password (blank = socket auth / the packet default): " MP </dev/tty; echo
q() { if [[ -n "$MP" ]]; then MYSQL_PWD="$MP" mysql -uroot -N -B -e "$1"; else mysql -N -B -e "$1"; fi; }
q 'SELECT 1' >/dev/null 2>&1 || { MP='bb123#123'; q 'SELECT 1' >/dev/null 2>&1 || { warn "Can't log in as root"; exit 1; }; warn "root still uses the PACKET password"; }

hdr "Server settings"
q "SELECT @@version, @@bind_address, @@local_infile, @@secure_file_priv, @@skip_name_resolve" | sed 's/^/    /'
[[ "$(q 'SELECT @@local_infile')" == 1 ]] && warn "local_infile=ON (file read via LOAD DATA)"
[[ -z "$(q 'SELECT @@secure_file_priv')" ]] && warn "secure_file_priv empty -> INTO OUTFILE can write anywhere mysqld can (webshell drop)"

hdr "Accounts"
q "SELECT CONCAT(user,'@',host,'  plugin=',plugin,'  locked=',IFNULL(account_locked,'?')) FROM mysql.user" 2>/dev/null \
  || q "SELECT CONCAT(user,'@',host) FROM mysql.user"
q "SELECT CONCAT('[!] anonymous: ''',user,'''@',host) FROM mysql.user WHERE user=''"
q "SELECT CONCAT('[!] no password: ',user,'@',host) FROM mysql.user WHERE (authentication_string='' OR authentication_string IS NULL) AND plugin NOT IN ('auth_socket','unix_socket')" 2>/dev/null
q "SELECT CONCAT('[!] remote root: ',user,'@',host) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')"

hdr "Dangerous privileges (SUPER / FILE / GRANT / ALL on *.*)"
for ua in $(q "SELECT CONCAT(QUOTE(user),'@',QUOTE(host)) FROM mysql.user WHERE user<>''" | tr '\n' ' '); do
  g=$(q "SHOW GRANTS FOR $ua" 2>/dev/null)
  if echo "$g" | grep -qE 'ALL PRIVILEGES ON \*\.\*|SUPER|FILE|WITH GRANT OPTION'; then warn "$ua"; echo "$g" | sed 's/^/        /'; fi
done

hdr "Databases"
q "SHOW DATABASES" | sed 's/^/    /'

hdr "FIXES"
if [[ -n "$(q "SELECT 1 FROM mysql.user WHERE user='' LIMIT 1")" ]] && ask "Drop anonymous users?"; then
  for h in $(q "SELECT host FROM mysql.user WHERE user=''"); do q "DROP USER ''@'$h'"; done; log_action "mysql: dropped anonymous"; fi
[[ -n "$(q "SHOW DATABASES LIKE 'test'")" ]] && ask "Drop 'test' database?" && q "DROP DATABASE test" && log_action "mysql: dropped test db"
if ask "Change root@localhost password? (only if the app does NOT use root)"; then
  read -r -s -p "New root password: " NP </dev/tty; echo
  q "ALTER USER 'root'@'localhost' IDENTIFIED BY '${NP//\'/\'\'}'" && { MP="$NP"; ok "root changed"; log_action "mysql: root pw changed"; }
fi
for ua in $(q "SELECT CONCAT(QUOTE(user),'@',QUOTE(host)) FROM mysql.user WHERE user NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema','debian-sys-maint','mariadb.sys','') " | tr '\n' ' '); do
  echo; info "Account $ua"
  ask "  LOCK $ua? (No if the web app or scoring uses it)" && q "ALTER USER $ua ACCOUNT LOCK" && log_action "mysql: locked $ua"
done
q "FLUSH PRIVILEGES"
info "Persist settings: add to [mysqld] in /etc/mysql/mysql.conf.d/mysqld.cnf: local_infile=0  secure_file_priv=/var/lib/mysql-files  then restart."
info "MySQL port 3306 is scored - keep bind-address reachable (0.0.0.0) unless told otherwise."
