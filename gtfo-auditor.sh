#!/usr/bin/env bash
# gtfo‑auditor.sh
# Prüft Sudo‑Policies auf verbotene Shell‑Escapes, NOEXEC‑Bypässe und Fehlkonfigurationen.
# Exit‑Codes: 0 = Policy OK, 1 = Verstöße, 2 = Aufruf‑/Systemfehler

###############################################################################
# 1) Listen – bei Bedarf anpassen/erweitern
###############################################################################

# Befehle, die per sudo GAR NICHT ausgeführt werden dürfen
ALWAYS_BLOCK=(
  /bin/bash /usr/bin/zsh /bin/sh /usr/bin/fish /usr/bin/dash /bin/ksh
  # … (Original‑Liste beliebig ergänzen)
)

# Befehle, die (falls erlaubt) nur mit NOEXEC laufen dürfen
ALLOW_NOEXEC=(
  /usr/bin/vim /usr/bin/less
  /usr/bin/python3 /usr/bin/perl /usr/bin/php /usr/bin/lua
  /usr/bin/node /usr/bin/ruby /usr/bin/awk
  # … (vollständige Original‑Liste beliebig ergänzen)
)

###############################################################################
# 2) Farb‑Konstanten
###############################################################################
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
NC="\033[0m"           # reset / no colour

###############################################################################
# 3) Root‑Check
###############################################################################
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}❌ Dieses Skript MUSS als root laufen.${NC}"
  exit 2
fi

###############################################################################
# 4) Hilfsfunktionen
###############################################################################

# --- Prüft, ob user «sudo BIN -c true» ohne PW (‑n) ausführen darf ------------
check_base_state() {
  local user="$1" bin="$2"

  if [[ ! -x "$bin" ]]; then
    echo "NOT_INSTALLED"; return
  fi

  # Erst ohne Passwortversuch
  if runuser -u "$user" -- sudo -n "$bin" -c 'true' &>/dev/null; then
    echo "NOPASSWD"; return
  fi

  local out
  out=$(runuser -u "$user" -- sudo -n "$bin" -c 'true' 2>&1)

  if echo "$out" | grep -qi "password.*required"; then
    echo "PASSWD"
  elif echo "$out" | grep -qi "command not found"; then
    # sudo erlaubt, Binary existiert aber nicht
    echo "NOT_INSTALLED"
  else
    echo "BLOCKED"
  fi
}

# --- NOEXEC‑Test: versucht per GTFOBins‑Typ aus «bin» root‑whoami -------------
check_noexec_enforced() {
  local user="$1" bin="$2" out result

  case "$bin" in
    */vim|*/view|*/vi)
      out=$(runuser -u "$user" -- sudo -n "$bin" -c ':!whoami' 2>/dev/null)
      ;;
    */less)
      out=$(echo '!whoami' | runuser -u "$user" -- sudo -n "$bin" 2>/dev/null)
      ;;
    */python*|*/python3)
      out=$(runuser -u "$user" -- sudo -n "$bin" -c 'import os,sys; os.system("whoami")' 2>/dev/null)
      ;;
    */perl)
      out=$(runuser -u "$user" -- sudo -n "$bin" -e 'system("whoami")' 2>/dev/null)
      ;;
    */php)
      out=$(runuser -u "$user" -- sudo -n "$bin" -r 'echo shell_exec("whoami");' 2>/dev/null)
      ;;
    */lua)
      out=$(runuser -u "$user" -- sudo -n "$bin" -e 'os.execute("whoami")' 2>/dev/null)
      ;;
    */node)
      out=$(runuser -u "$user" -- sudo -n "$bin" -e \
            'require("child_process").exec("whoami",(e,o)=>console.log(o.trim()))' 2>/dev/null)
      ;;
    */ruby)
      out=$(runuser -u "$user" -- sudo -n "$bin" -e 'puts `whoami`' 2>/dev/null)
      ;;
    */awk)
      out=$(runuser -u "$user" -- sudo -n "$bin" 'BEGIN{system("whoami")}' 2>/dev/null)
      ;;
    *)  # Kein Test definiert
      echo "UNKNOWN"; return
      ;;
  esac

  [[ "$out" == "root" ]] && echo "BYPASSED" || echo "ENFORCED"
}

###############################################################################
# 5) Sudo‑/Admin‑User automatisch ermitteln
###############################################################################
ADMIN_GROUPS=(sudo wheel admin)
ADMIN_USERS=()

for g in "${ADMIN_GROUPS[@]}"; do
  if getent group "$g" >/dev/null; then
    IFS=',' read -ra members <<<"$(getent group "$g" | cut -d: -f4)"
    for u in "${members[@]}"; do
      [[ -n "$u" ]] && ADMIN_USERS+=("$u")
    done
  fi
done

# Fallback: alle logins mit UID ≥1000
if [[ ${#ADMIN_USERS[@]} -eq 0 ]]; then
  mapfile -t ADMIN_USERS < <(awk -F: '$3>=1000{print $1}' /etc/passwd)
fi

[[ ${#ADMIN_USERS[@]} -eq 0 ]] && { echo "Keine Audit‑User gefunden."; exit 2; }

###############################################################################
# 6) Audit‑Loop
###############################################################################
viol=0

for user in "${ADMIN_USERS[@]}"; do
  echo
  echo "🔍 Auditing sudo rights for user: ${YELLOW}$user${NC}"
  printf "%-25s %-10s %-10s %-10s\n" "COMMAND" "STATE" "EXPECT" "COMPLIANT"
  printf "%-25s %-10s %-10s %-10s\n" "-------" "-----" "------" "---------"

  # === ALWAYS_BLOCK ===
  for cmd in "${ALWAYS_BLOCK[@]}"; do
    state=$(check_base_state "$user" "$cmd")
    expect="BLOCKED"

    if [[ $state =~ ^(BLOCKED|NOT_INSTALLED)$ ]]; then
      comp="YES" ; col=$GREEN
    else
      comp="NO"  ; col=$RED ; viol=1
    fi

    printf "${col}%-25s %-10s %-10s %-10s${NC}\n" "$cmd" "$state" "$expect" "$comp"
  done

  # === ALLOW_NOEXEC ===
  for cmd in "${ALLOW_NOEXEC[@]}"; do
    base=$(check_base_state "$user" "$cmd")

    if [[ $base == "NOPASSWD" ]]; then
      # Programm ist (gefährlich) erlaubt ⇒ NOEXEC‑Test
      nx=$(check_noexec_enforced "$user" "$cmd")
      state=$nx
    else
      # NOT_INSTALLED / PASSWD / BLOCKED
      state=$base
    fi

    expect="NOEXEC"

    if [[ $state =~ ^(ENFORCED|BLOCKED|NOT_INSTALLED)$ ]]; then
      comp="YES" ; col=$GREEN
    else
      comp="NO"  ; col=$RED ; viol=1
    fi

    printf "${col}%-25s %-10s %-10s %-10s${NC}\n" "$cmd" "$state" "$expect" "$comp"
  done
done

###############################################################################
# 7) Ergebnis
###############################################################################
echo "==============================================================="
if (( viol )); then
  echo -e "${RED}❌ VIOLATIONS DETECTED${NC}"
  exit 1
else
  echo -e "${GREEN}✅ POLICY OK${NC}"
  exit 0
fi
