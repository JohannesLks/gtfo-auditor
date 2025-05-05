#!/bin/sh
# gtfo-auditor.sh – POSIX-kompatibel für Nessus
# Prüft Sudo-/NOEXEC-Policies. Exit: 0 = OK, 1 = Fehler, 2 = Systemfehler


# Cleanup bei STRG+C
cleanup() {
  echo "❌ Audit abgebrochen. Breche Prozesse ab ..."
  for pid in $(jobs -p); do
    kill "$pid" 2>/dev/null
  done
  exit 130
}
trap cleanup INT TERM HUP

# Root-Check
if [ "$(id -u)" != "0" ]; then
  echo "ERROR: Script must run as root."
  id
  whoami
  exit 2
fi

# Befehle, die per sudo GAR NICHT ausgeführt werden dürfen
ALWAYS_BLOCK="/bin/ash /usr/bin/awk /bin/bash /usr/bin/capsh /usr/lib/nagios/plugins/check_by_ssh /usr/bin/crash /bin/csh /bin/dash /usr/bin/elvish /usr/bin/emacs /usr/bin/env /usr/bin/expect /usr/bin/fish /usr/bin/ftp /usr/bin/gawk /usr/bin/gdb /usr/bin/ginsh /usr/bin/irb /bin/ksh /usr/bin/ksshell /usr/bin/less /usr/bin/lftp /usr/bin/lua /usr/bin/lualatex /usr/bin/luatex /usr/bin/man /usr/bin/mawk /bin/more /bin/nano /usr/bin/nawk /usr/bin/ncftp /usr/bin/nmap /usr/bin/node /usr/sbin/openvpn /usr/bin/openvt /usr/bin/perl /usr/bin/perlbug /usr/bin/php /usr/bin/pico /bin/posh /usr/bin/psftp /usr/bin/psql /usr/bin/pwsh /usr/bin/python /usr/bin/ruby /usr/bin/rview /usr/bin/rvim /usr/bin/sash /usr/bin/scp /usr/bin/screen /usr/bin/sftp /usr/bin/sh /usr/bin/shuf /usr/bin/slsh /usr/bin/sqlmap /usr/bin/ssh-agent /usr/bin/ssh-keygen /usr/bin/ssh-keyscan /usr/bin/ssh /usr/bin/sshpass /usr/bin/tasksh /usr/bin/tclsh /usr/bin/tftp /usr/bin/tmux /usr/bin/unshare /usr/sbin/unsquashfs /usr/sbin/varnishncsa /usr/bin/view /usr/bin/vim /usr/bin/vimdiff /usr/bin/virsh /usr/bin/wireshark /usr/bin/wish /usr/bin/xmore /usr/bin/yash /bin/zsh /usr/bin/zsh"
# Befehle, die (falls erlaubt) nur mit NOEXEC laufen dürfen
ALLOW_NOEXEC="/usr/bin/7z /usr/bin/aa-exec /usr/bin/ab /usr/bin/alpine /usr/bin/ansible-playbook /usr/bin/ansible-test /usr/bin/aoss /usr/sbin/apache2ctl /usr/bin/apt-get /usr/bin/apt /usr/bin/ar /usr/bin/aria2c /usr/bin/arj /usr/sbin/arp /usr/bin/as /usr/bin/ascii-xfr /usr/bin/ascii85 /usr/bin/aspell /usr/bin/at /usr/bin/atobm /usr/bin/aws /usr/bin/base32 /usr/bin/base58 /usr/bin/base64 /usr/bin/basenc /usr/bin/basez /usr/bin/batcat /usr/bin/bc /usr/sbin/bconsole /usr/bin/bpftrace /usr/sbin/bridge /usr/bin/bundle /usr/bin/bundler /usr/bin/busctl /bin/busybox /usr/bin/byebug /bin/bzip2 /usr/bin/c89 /usr/bin/c99 /usr/bin/cabal /bin/cat /usr/bin/cdist /usr/bin/certbot /usr/lib/nagios/plugins/check_cups /usr/lib/nagios/plugins/check_log /usr/lib/nagios/plugins/check_memory /usr/lib/nagios/plugins/check_raid /usr/lib/nagios/plugins/check_ssl_cert /usr/lib/nagios/plugins/check_statusfile /bin/chmod /usr/bin/choom /bin/chown /usr/sbin/chroot /usr/bin/clamscan /usr/bin/cmp /usr/bin/cobc /usr/bin/column /usr/bin/comm /usr/bin/composer /usr/games/cowsay /usr/games/cowthink /bin/cp /usr/bin/cpan /bin/cpio /usr/bin/cpulimit /usr/bin/crontab /usr/bin/csplit /usr/bin/csvtool /usr/lib/cups/filter/cupsfilter /usr/bin/curl /usr/bin/cut /bin/date /usr/bin/dc /bin/dd /sbin/debugfs /usr/bin/dialog /usr/bin/diff /usr/bin/dig /usr/bin/distcc /bin/dmesg /usr/sbin/dmidecode /sbin/dmsetup /usr/bin/dnf /usr/bin/docker /usr/bin/dosbox /usr/bin/dotnet /usr/bin/dpkg /usr/bin/dstat /usr/bin/dvips /usr/bin/easy_install /usr/bin/eb /bin/ed /usr/bin/efax /usr/bin/enscript /usr/bin/eqn /usr/bin/espeak /bin/ex /usr/bin/exiftool /usr/bin/expand /usr/bin/facter /usr/bin/file /usr/bin/find /usr/bin/flock /usr/bin/fmt /usr/bin/fold /usr/bin/fping /usr/bin/gcc /usr/bin/gcloud /usr/bin/gcore /usr/bin/gem /usr/bin/genie /usr/bin/genisoimage /usr/bin/ghc /usr/bin/ghci /usr/bin/gimp /usr/bin/git /usr/bin/grc /bin/grep /usr/lib/glib2.0/gtester /bin/gzip /usr/bin/hd /usr/bin/head /usr/bin/hexdump /usr/bin/highlight /usr/sbin/hping3 /usr/bin/iconv /usr/sbin/iftop /usr/bin/install /usr/bin/ionice /bin/ip /usr/bin/ispell /usr/bin/jjs /usr/bin/joe /usr/bin/join /bin/journalctl /usr/bin/jq /usr/bin/jrunscript /usr/bin/jtag /usr/bin/julia /usr/bin/knife /usr/bin/ksu /usr/bin/kubectl /usr/bin/latex /usr/bin/latexmk /lib/ld.so /sbin/ldconfig /usr/bin/links /bin/ln /bin/loginctl /usr/bin/logsave /usr/bin/look /usr/bin/ltrace /usr/bin/lwp-download /usr/bin/lwp-request /usr/bin/mail /usr/bin/make /usr/bin/minicom /usr/sbin/mosquitto /bin/mount /usr/bin/msfconsole /usr/bin/msgattrib /usr/bin/msgcat /usr/bin/msgconv /usr/bin/msgfilter /usr/bin/msgmerge /usr/bin/msguniq /usr/bin/mtr /usr/bin/multitime /bin/mv /usr/bin/mysql /usr/bin/nasm /bin/nc /usr/bin/ncdu /usr/bin/neofetch /usr/sbin/nft /usr/bin/nice /usr/bin/nl /usr/bin/nm /usr/bin/nohup /usr/bin/npm /usr/bin/nroff /usr/bin/nsenter /usr/sbin/ntpdate /usr/bin/octave /usr/bin/od /usr/bin/openssl /usr/bin/opkg /usr/bin/pandoc /usr/bin/paste /usr/bin/pdb /usr/bin/pdflatex /usr/bin/pdftex /usr/bin/perf /usr/bin/pexec /usr/bin/pg /usr/bin/pic /usr/bin/pidstat /usr/bin/pip /usr/bin/pkexec /usr/bin/pkg /usr/bin/pr /usr/bin/pry /usr/bin/ptx /usr/bin/puppet /usr/bin/rake /bin/rc /usr/bin/readelf /usr/bin/red /usr/bin/redcarpet /usr/bin/restic /usr/bin/rev /usr/bin/rlwrap /usr/bin/rpm /usr/bin/rpmdb /usr/bin/rpmquery /usr/bin/rpmverify /usr/bin/rsync /usr/bin/run-mailcap /usr/bin/run-parts /usr/bin/runscript /usr/bin/scanmem /usr/bin/script /usr/bin/scrot /bin/sed /usr/sbin/service /usr/bin/setarch /usr/bin/setfacl /usr/bin/setlock /usr/bin/sg /usr/bin/smbclient /usr/bin/snap /usr/bin/socat /usr/bin/soelim /usr/bin/softlimit /usr/bin/sort /usr/bin/split /usr/bin/sqlite3 /bin/ss /sbin/start-stop-daemon /usr/bin/stdbuf /usr/bin/strace /usr/bin/strings /bin/su /usr/bin/sudo /sbin/sysctl /bin/systemctl /usr/bin/systemd-resolve /usr/bin/tac /usr/bin/tail /bin/tar /usr/bin/task /usr/bin/taskset /usr/bin/tbl /usr/sbin/tcpdump /usr/bin/tdbtool /usr/bin/tee /usr/bin/telnet /usr/bin/terraform /usr/bin/tex /usr/bin/tic /usr/bin/time /usr/bin/timedatectl /usr/bin/timeout /usr/bin/tmate /usr/bin/top /usr/bin/torify /usr/bin/torsocks /usr/bin/troff /usr/bin/ul /usr/bin/unexpand /usr/bin/uniq /usr/bin/unzip /usr/sbin/update-alternatives /usr/bin/uudecode /usr/bin/uuencode /usr/bin/vagrant /usr/bin/valgrind /usr/bin/vi /usr/sbin/vigr /usr/sbin/vipw /usr/bin/w3m /usr/bin/wall /usr/bin/watch /usr/bin/wc /usr/bin/wget /usr/bin/whiptail /usr/bin/xargs /usr/bin/xdg-user-dir /usr/bin/xdotool /usr/bin/xelatex /usr/bin/xetex /usr/bin/xmodmap /usr/bin/xpad /usr/bin/xxd /usr/bin/xz /usr/bin/yarn /usr/bin/yum /usr/bin/zathura /usr/bin/zip /usr/bin/zsoelim /usr/bin/zypper"

# Admin-User ermitteln
ADMIN_USERS=""
for g in sudo wheel admin; do
  entry=$(getent group "$g")
  [ -n "$entry" ] && users=$(echo "$entry" | awk -F: '{print $4}' | tr ',' ' ') && ADMIN_USERS="$ADMIN_USERS $users"
done
[ -z "$ADMIN_USERS" ] && ADMIN_USERS=$(awk -F: '$3>=1000{print $1}' /etc/passwd)
[ -z "$ADMIN_USERS" ] && { echo "Keine Audit-User gefunden."; exit 2; }

# Tabellenrahmen
CMD_W=30; STATE_W=16; EXPECT_W=10; COMP_W=10
i=1; LINE=""
while [ $i -le $CMD_W ]; do LINE="${LINE}-"; i=$((i+1)); done
TOP="+$LINE+----------------+----------+----------+"
MID="$TOP"; BOT="$TOP"

print_header() {
  echo "$TOP"
  printf "| %-*s| %-*s| %-*s| %-*s|\n" "$((CMD_W-1))" "COMMAND" "$((STATE_W-1))" "STATE" "$((EXPECT_W-1))" "EXPECT" "$((COMP_W-1))" "COMPLIANT"
  echo "$MID"
}

output_row() {
  printf "| %-*.*s| %-*s| %-*s| %-*s|\n" \
         "$((CMD_W-1))" "$((CMD_W-1))" "$1" \
         "$((STATE_W-1))" "$2" \
         "$((EXPECT_W-1))" "$3" \
         "$((COMP_W-1))" "$4"
}

# Prüflogik
check_base_state() {
  user="$1"; bin="$2"
  [ ! -x "$bin" ] && echo NOT_INSTALLED && return

  timeout 1s sudo -n -l -U "$user" "$bin" >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    timeout 1s sudo -n -u "$user" "$bin" -c true >/dev/null 2>&1 && echo NOPASSWD || echo PASSWD
  else
    echo BLOCKED
  fi
}

viol=0
for user in $ADMIN_USERS; do
  echo
  echo "Auditing user: $user"
  print_header

  for cmd in $ALWAYS_BLOCK; do
    state=$(check_base_state "$user" "$cmd")
    case "$state" in
      BLOCKED|NOT_INSTALLED) compliant="YES" ;;
      *) compliant="NO"; viol=1 ;;
    esac
    output_row "$cmd" "$state" "BLOCKED" "$compliant"
  done

  for cmd in $ALLOW_NOEXEC; do
    state=$(check_base_state "$user" "$cmd")
    if [ "$state" = "BLOCKED" ] || [ "$state" = "NOT_INSTALLED" ]; then
      compliant="YES"
    elif [ "$state" = "NOPASSWD" ]; then
      compliant="NO"  # NOEXEC kann nicht geprüft werden ohne runuser
    else
      compliant="NO"
    fi
    [ "$compliant" = "NO" ] && viol=1
    output_row "$cmd" "$state" "NOEXEC" "$compliant"
  done

  echo "$BOT"
done

# Abschlussmeldung
echo "==============================================================="
[ "$viol" -eq 0 ] && echo "✅ POLICY OK" || { echo "❌ VIOLATIONS DETECTED"; exit 1; }
