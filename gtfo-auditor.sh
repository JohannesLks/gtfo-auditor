#!/bin/bash
# gtfo-auditor.sh
# Audits sudo policies for forbidden shell escapes, NOEXEC bypasses, and misconfigurations.
# Exit codes: 0 = Policy OK, 1 = Violations found, 2 = Invocation/System error

###############################################################################
# Banner
###############################################################################
cat <<'BANNER'
   _____ _______ ______ ____                      _ _ _             
  / ____|__   __|  ____/ __ \      /\            | (_) |            
 | |  __   | |  | |__ | |  | |    /  \  _   _  __| |_| |_ ___  _ __ 
 | | |_ |  | |  |  __|| |  | |   / /\ \| | | |/ _` | | __/ _ \| '__|
 | |__| |  | |  | |   | |__| |  / ____ \ |_| | (_| | | || (_) | |   
  \_____|  |_|  |_|    \____/  /_/    \_\__,_|\__,_|_|\__\___/|_|   
                                                                    
                                                                    
(c) 2026  JohannesLks

BANNER

###############################################################################
# Usage / Help
###############################################################################
usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  -f, --file FILE         Read additional binaries to audit from FILE (one per line)"
  echo "                          These binaries will be added to the ALWAYS_BLOCK list"
  echo "  -b, --block-file FILE   Read binaries that should ALWAYS be blocked from FILE"
  echo "  -n, --noexec-file FILE  Read binaries that require NOEXEC from FILE"
  echo "  -h, --help              Show this help message"
  echo ""
  echo "File format: One binary path per line (e.g., /usr/bin/vim)"
  echo "Lines starting with # are treated as comments and ignored."
  echo "Empty lines are ignored."
  echo ""
  echo "Example:"
  echo "  $0 -f /path/to/custom_binaries.txt"
  echo "  $0 -b /path/to/block_list.txt -n /path/to/noexec_list.txt"
  exit 0
}

###############################################################################
# Parse command line arguments
###############################################################################
EXTRA_BLOCK_FILE=""
EXTRA_NOEXEC_FILE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -f|--file|-b|--block-file)
      EXTRA_BLOCK_FILE="$2"
      shift 2
      ;;
    -n|--noexec-file)
      EXTRA_NOEXEC_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

###############################################################################
# 1) Lists - modify/extend as needed
###############################################################################

# Commands that should NEVER be executed via sudo (always blocked)
ALWAYS_BLOCK=(/bin/ash /usr/bin/awk /bin/bash /usr/bin/capsh /usr/lib/nagios/plugins/check_by_ssh /usr/bin/crash /bin/csh /bin/dash /usr/bin/elvish /usr/bin/emacs /usr/bin/env /usr/bin/expect /usr/bin/fish /usr/bin/ftp /usr/bin/gawk /usr/bin/gdb /usr/bin/ginsh /usr/bin/irb /bin/ksh /usr/bin/ksshell /usr/bin/less /usr/bin/lftp /usr/bin/lua /usr/bin/lualatex /usr/bin/luatex /usr/bin/man /usr/bin/mawk /bin/more /bin/nano /usr/bin/nawk /usr/bin/ncftp /usr/bin/nmap /usr/bin/node /usr/sbin/openvpn /usr/bin/openvt /usr/bin/perl /usr/bin/perlbug /usr/bin/php /usr/bin/pico /bin/posh /usr/bin/psftp /usr/bin/psql /usr/bin/pwsh /usr/bin/python /usr/bin/ruby /usr/bin/rview /usr/bin/rvim /usr/bin/sash /usr/bin/scp /usr/bin/screen /usr/bin/sftp /usr/bin/sh /usr/bin/shuf /usr/bin/slsh /usr/bin/sqlmap /usr/bin/ssh-agent /usr/bin/ssh-keygen /usr/bin/ssh-keyscan /usr/bin/ssh /usr/bin/sshpass /usr/bin/tasksh /usr/bin/tclsh /usr/bin/tftp /usr/bin/tmux /usr/bin/unshare /usr/sbin/unsquashfs /usr/sbin/varnishncsa /usr/bin/view /usr/bin/vim /usr/bin/vimdiff /usr/bin/virsh /usr/bin/wireshark /usr/bin/wish /usr/bin/xmore /usr/bin/yash /bin/zsh /usr/bin/zsh)

# Commands that (if allowed) must only run with NOEXEC flag
ALLOW_NOEXEC=(/usr/bin/7z /usr/bin/aa-exec /usr/bin/ab /usr/bin/alpine /usr/bin/ansible-playbook /usr/bin/ansible-test /usr/bin/aoss /usr/sbin/apache2ctl /usr/bin/apt-get /usr/bin/apt /usr/bin/ar /usr/bin/aria2c /usr/bin/arj /usr/sbin/arp /usr/bin/as /usr/bin/ascii-xfr /usr/bin/ascii85 /usr/bin/aspell /usr/bin/at /usr/bin/atobm /usr/bin/aws /usr/bin/base32 /usr/bin/base58 /usr/bin/base64 /usr/bin/basenc /usr/bin/basez /usr/bin/batcat /usr/bin/bc /usr/sbin/bconsole /usr/bin/bpftrace /usr/sbin/bridge /usr/bin/bundle /usr/bin/bundler /usr/bin/busctl /bin/busybox /usr/bin/byebug /bin/bzip2 /usr/bin/c89 /usr/bin/c99 /usr/bin/cabal /bin/cat /usr/bin/cdist /usr/bin/certbot /usr/lib/nagios/plugins/check_cups /usr/lib/nagios/plugins/check_log /usr/lib/nagios/plugins/check_memory /usr/lib/nagios/plugins/check_raid /usr/lib/nagios/plugins/check_ssl_cert /usr/lib/nagios/plugins/check_statusfile /bin/chmod /usr/bin/choom /bin/chown /usr/sbin/chroot /usr/bin/clamscan /usr/bin/cmp /usr/bin/cobc /usr/bin/column /usr/bin/comm /usr/bin/composer /usr/games/cowsay /usr/games/cowthink /bin/cp /usr/bin/cpan /bin/cpio /usr/bin/cpulimit /usr/bin/crontab /usr/bin/csplit /usr/bin/csvtool /usr/lib/cups/filter/cupsfilter /usr/bin/curl /usr/bin/cut /bin/date /usr/bin/dc /bin/dd /sbin/debugfs /usr/bin/dialog /usr/bin/diff /usr/bin/dig /usr/bin/distcc /bin/dmesg /usr/sbin/dmidecode /sbin/dmsetup /usr/bin/dnf /usr/bin/docker /usr/bin/dosbox /usr/bin/dotnet /usr/bin/dpkg /usr/bin/dstat /usr/bin/dvips /usr/bin/easy_install /usr/bin/eb /bin/ed /usr/bin/efax /usr/bin/enscript /usr/bin/eqn /usr/bin/espeak /bin/ex /usr/bin/exiftool /usr/bin/expand /usr/bin/facter /usr/bin/file /usr/bin/find /usr/bin/flock /usr/bin/fmt /usr/bin/fold /usr/bin/fping /usr/bin/gcc /usr/bin/gcloud /usr/bin/gcore /usr/bin/gem /usr/bin/genie /usr/bin/genisoimage /usr/bin/ghc /usr/bin/ghci /usr/bin/gimp /usr/bin/git /usr/bin/grc /bin/grep /usr/lib/glib2.0/gtester /bin/gzip /usr/bin/hd /usr/bin/head /usr/bin/hexdump /usr/bin/highlight /usr/sbin/hping3 /usr/bin/iconv /usr/sbin/iftop /usr/bin/install /usr/bin/ionice /bin/ip /usr/bin/ispell /usr/bin/jjs /usr/bin/joe /usr/bin/join /bin/journalctl /usr/bin/jq /usr/bin/jrunscript /usr/bin/jtag /usr/bin/julia /usr/bin/knife /usr/bin/ksu /usr/bin/kubectl /usr/bin/latex /usr/bin/latexmk /lib/ld.so /sbin/ldconfig /usr/bin/links /bin/ln /bin/loginctl /usr/bin/logsave /usr/bin/look /usr/bin/ltrace /usr/bin/lwp-download /usr/bin/lwp-request /usr/bin/mail /usr/bin/make /usr/bin/minicom /usr/sbin/mosquitto /bin/mount /usr/bin/msfconsole /usr/bin/msgattrib /usr/bin/msgcat /usr/bin/msgconv /usr/bin/msgfilter /usr/bin/msgmerge /usr/bin/msguniq /usr/bin/mtr /usr/bin/multitime /bin/mv /usr/bin/mysql /usr/bin/nasm /bin/nc /usr/bin/ncdu /usr/bin/neofetch /usr/sbin/nft /usr/bin/nice /usr/bin/nl /usr/bin/nm /usr/bin/nohup /usr/bin/npm /usr/bin/nroff /usr/bin/nsenter /usr/sbin/ntpdate /usr/bin/octave /usr/bin/od /usr/bin/openssl /usr/bin/opkg /usr/bin/pandoc /usr/bin/paste /usr/bin/pdb /usr/bin/pdflatex /usr/bin/pdftex /usr/bin/perf /usr/bin/pexec /usr/bin/pg /usr/bin/pic /usr/bin/pidstat /usr/bin/pip /usr/bin/pkexec /usr/bin/pkg /usr/bin/pr /usr/bin/pry /usr/bin/ptx /usr/bin/puppet /usr/bin/rake /bin/rc /usr/bin/readelf /usr/bin/red /usr/bin/redcarpet /usr/bin/restic /usr/bin/rev /usr/bin/rlwrap /usr/bin/rpm /usr/bin/rpmdb /usr/bin/rpmquery /usr/bin/rpmverify /usr/bin/rsync /usr/bin/run-mailcap /usr/bin/run-parts /usr/bin/runscript /usr/bin/scanmem /usr/bin/script /usr/bin/scrot /bin/sed /usr/sbin/service /usr/bin/setarch /usr/bin/setfacl /usr/bin/setlock /usr/bin/sg /usr/bin/smbclient /usr/bin/snap /usr/bin/socat /usr/bin/soelim /usr/bin/softlimit /usr/bin/sort /usr/bin/split /usr/bin/sqlite3 /bin/ss /sbin/start-stop-daemon /usr/bin/stdbuf /usr/bin/strace /usr/bin/strings /bin/su /usr/bin/sudo /sbin/sysctl /bin/systemctl /usr/bin/systemd-resolve /usr/bin/tac /usr/bin/tail /bin/tar /usr/bin/task /usr/bin/taskset /usr/bin/tbl /usr/sbin/tcpdump /usr/bin/tdbtool /usr/bin/tee /usr/bin/telnet /usr/bin/terraform /usr/bin/tex /usr/bin/tic /usr/bin/time /usr/bin/timedatectl /usr/bin/timeout /usr/bin/tmate /usr/bin/top /usr/bin/torify /usr/bin/torsocks /usr/bin/troff /usr/bin/ul /usr/bin/unexpand /usr/bin/uniq /usr/bin/unzip /usr/sbin/update-alternatives /usr/bin/uudecode /usr/bin/uuencode /usr/bin/vagrant /usr/bin/valgrind /usr/bin/vi /usr/sbin/vigr /usr/sbin/vipw /usr/bin/w3m /usr/bin/wall /usr/bin/watch /usr/bin/wc /usr/bin/wget /usr/bin/whiptail /usr/bin/xargs /usr/bin/xdg-user-dir /usr/bin/xdotool /usr/bin/xelatex /usr/bin/xetex /usr/bin/xmodmap /usr/bin/xpad /usr/bin/xxd /usr/bin/xz /usr/bin/yarn /usr/bin/yum /usr/bin/zathura /usr/bin/zip /usr/bin/zsoelim /usr/bin/zypper)

###############################################################################
# 1.1) Load additional binaries from file (if provided)
###############################################################################

# Function to read binaries from a file
read_binaries_from_file() {
  local file="$1"
  local -n arr="$2"  # nameref to the target array
  
  if [[ ! -f "$file" ]]; then
    echo -e "${RED}  Error: File not found: $file${NC}"
    exit 2
  fi
  
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    # Trim whitespace
    line=$(echo "$line" | xargs)
    # Add to array if not empty
    [[ -n "$line" ]] && arr+=("$line")
  done < "$file"
}

# Load additional block list from file
if [[ -n "$EXTRA_BLOCK_FILE" ]]; then
  echo "📂  Loading additional blocked binaries from: $EXTRA_BLOCK_FILE"
  read_binaries_from_file "$EXTRA_BLOCK_FILE" ALWAYS_BLOCK
  echo "    Added $(wc -l < "$EXTRA_BLOCK_FILE" | xargs) entries"
fi

# Load additional noexec list from file
if [[ -n "$EXTRA_NOEXEC_FILE" ]]; then
  echo "📂  Loading additional NOEXEC binaries from: $EXTRA_NOEXEC_FILE"
  read_binaries_from_file "$EXTRA_NOEXEC_FILE" ALLOW_NOEXEC
  echo "    Added $(wc -l < "$EXTRA_NOEXEC_FILE" | xargs) entries"
fi

###############################################################################
# 2) Colors
###############################################################################
RED=$'\e[0;31m'; GREEN=$'\e[0;32m'; YELLOW=$'\e[0;33m'; NC=$'\e[0m'

###############################################################################
# 3) Root Check
###############################################################################
if [[ $(id -u) -ne 0 ]]; then
    echo -e "${RED}  Root required (id -u check).${NC}"
    id
    whoami
    exit 2
fi

###############################################################################
# 4) Helper Functions
###############################################################################

# Check base state: NOT_INSTALLED / BLOCKED / PASSWD / NOPASSWD
check_base_state() {
  local user="$1" bin="$2"
  [[ ! -e $bin ]] && { echo NOT_INSTALLED; return; }

  if sudo -n -l -U "$user" "$bin" &>/dev/null; then
      runuser -u "$user" -- sudo -n "$bin" -c true &>/dev/null && echo NOPASSWD || echo PASSWD
  else
      echo BLOCKED
  fi
}

# Check if NOEXEC flag is set
check_noexec_flag() { 
  sudo -n -l -U "$1" "$2" 2>/dev/null | grep -q NOEXEC && echo SET || echo UNSET
}

# Check if NOEXEC is enforced: ENFORCED / BYPASSED / UNKNOWN
check_noexec_enforced() {
  local u="$1" b="$2" o
  case "$b" in
    */vim|*/vi|*/view)   o=$(runuser -u "$u" -- sudo -n "$b" -c ':!whoami' 2>/dev/null);;
    */less)              o=$(echo '!whoami' | runuser -u "$u" -- sudo -n "$b" 2>/dev/null);;
    */python*|*/python3) o=$(runuser -u "$u" -- sudo -n "$b" -c 'import os,sys;os.system("whoami")' 2>/dev/null);;
    */perl)              o=$(runuser -u "$u" -- sudo -n "$b" -e 'system("whoami")' 2>/dev/null);;
    */awk)               o=$(runuser -u "$u" -- sudo -n "$b" 'BEGIN{system("whoami")}' 2>/dev/null);;
    *) echo UNKNOWN; return;;
  esac
  [[ $o == root ]] && echo BYPASSED || echo ENFORCED
}

###############################################################################
# 5) Admin Users - find users with sudo privileges
###############################################################################
ADMIN_USERS=()
for g in sudo wheel admin; do
  [[ $(getent group "$g") ]] && IFS=, read -ra m <<<"$(getent group "$g"|cut -d: -f4)" && ADMIN_USERS+=("${m[@]}")
done
[[ ${#ADMIN_USERS[@]} -eq 0 ]] && mapfile -t ADMIN_USERS < <(awk -F: '$3>=1000{print $1}' /etc/passwd)
[[ ${#ADMIN_USERS[@]} -eq 0 ]] && { echo "No audit users found."; exit 2; }

###############################################################################
# 6) Table Width & Borders
###############################################################################
all_cmds=$(printf "%s\n" "${ALWAYS_BLOCK[@]}" "${ALLOW_NOEXEC[@]}")
max_cmd_len=$(echo "$all_cmds" | awk '{print length}' | sort -nr | head -1)
[ "$max_cmd_len" -lt 25 ] && max_cmd_len=25
CMD_W=$(( max_cmd_len + 2 ))

# Longest state string => "NOEXEC_MISSING" (14) - +2 padding
STATE_W=16
EXPECT_W=10
COMP_W=10

line(){ printf '─%.0s' $(seq 1 "$1"); }
TOP="┌$(line $CMD_W)┬$(line $STATE_W)┬$(line $EXPECT_W)┬$(line $COMP_W)┐"
MID="├$(line $CMD_W)┼$(line $STATE_W)┼$(line $EXPECT_W)┼$(line $COMP_W)┤"
BOT="└$(line $CMD_W)┴$(line $STATE_W)┴$(line $EXPECT_W)┴$(line $COMP_W)┘"

print_header() {
  echo -e "$TOP"
  printf "│ %-*s│ %-*s│ %-*s│ %-*s│\n" \
         $((CMD_W-1)) COMMAND  $((STATE_W-1)) STATE  \
         $((EXPECT_W-1)) EXPECT  $((COMP_W-1)) COMPLIANT
  echo -e "$MID"
}

###############################################################################
# 7) Audit Loop - with aligned, color-safe output
###############################################################################
viol=0
for user in "${ADMIN_USERS[@]}"; do
  echo -e "\n🔍  Auditing ${YELLOW}$user${NC}"
  print_header

  # Output a row: $1=cmd $2=state $3=expect $4=yes/no
  output_row() {
    local col=$([[ $4 == YES ]] && echo "$GREEN" || echo "$RED")
    printf "│ %-*.*s│ %-*s│ %-*s│ %s%-*s%s│\n" \
           $((CMD_W-1)) $((CMD_W-1)) "$1" \
           $((STATE_W-1)) "$2" \
           $((EXPECT_W-1)) "$3" \
           "$col" $((COMP_W-1)) "$4" "$NC"
  }

  # -------- Check ALWAYS_BLOCK list
  for cmd in "${ALWAYS_BLOCK[@]}"; do
    st=$(check_base_state "$user" "$cmd")
    ok=$([[ $st =~ ^(BLOCKED|NOT_INSTALLED)$ ]] && echo YES || echo NO)
    [[ $ok == NO ]] && viol=1
    output_row "$cmd" "$st" BLOCKED "$ok"
  done

  # -------- Check ALLOW_NOEXEC list
  for cmd in "${ALLOW_NOEXEC[@]}"; do
    base=$(check_base_state "$user" "$cmd")
    case "$base" in
      BLOCKED|NOT_INSTALLED) st=$base ;;
      NOPASSWD|PASSWD)
        [[ $(check_noexec_flag "$user" "$cmd") == UNSET ]] && st=NOEXEC_MISSING || {
          [[ $base == NOPASSWD ]] && st=$(check_noexec_enforced "$user" "$cmd") || st=NOEXEC_SET
        }
        ;;
    esac
    ok=$([[ $st =~ ^(ENFORCED|NOEXEC_SET|BLOCKED|NOT_INSTALLED)$ ]] && echo YES || echo NO)
    [[ $ok == NO ]] && viol=1
    output_row "$cmd" "$st" NOEXEC "$ok"
  done

  echo -e "$BOT"
done

###############################################################################
# 8) Final Result
###############################################################################
echo "==============================================================="
(( viol )) && { echo -e "${RED}VIOLATIONS DETECTED${NC}"; exit 1; }
echo -e "${GREEN}POLICY OK${NC}"
