# 1) the preload (the thing that broke file-server SSH/FTP)
lsattr /etc/ld.so.preload 2>/dev/null; cat /etc/ld.so.preload 2>/dev/null
chattr -i /etc/ld.so.preload 2>/dev/null; rm -f /etc/ld.so.preload
ls /etc/ld.so.preload 2>&1          # want: No such file or directory

# 2) shadow perms + unix_chkpwd setgid
ls -la /etc/shadow /usr/sbin/unix_chkpwd
chown root:shadow /etc/shadow /etc/gshadow; chmod 640 /etc/shadow /etc/gshadow
chown root:shadow /usr/sbin/unix_chkpwd; chmod 2755 /usr/sbin/unix_chkpwd

# 3) make sure the scored users exist + have the right password
for u in amarino mdesocio lsmith acapece johnlinux linuswindows alvin simon theodore abauer; do
  id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
  usermod -U -s /bin/bash "$u" 2>/dev/null
  H=$(getent shadow "$u" | cut -d: -f2)
  perl -e 'exit((crypt($ARGV[0],$ARGV[1]) eq $ARGV[1])?0:1)' 'bb123#123' "$H" 2>/dev/null \
    && echo "$u ok" || { echo "$u:bb123#123" | chpasswd; echo "$u reset"; }
  chage -E -1 -M 99999 -I -1 "$u"
done

# 4) prove it
pamtester sshd alvin authenticate     # bb123#123 -> "successfully authenticated"
