#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "Usage:"
  echo "  sudo -E bash scripts/run_baseline_experiment.sh RUN_NAME IFACE DURATION_SECONDS"
  exit 1
fi

RUN_NAME="$1"
IFACE="$2"
DURATION_SECONDS="$3"

PCAP="data/pcaps/${RUN_NAME}.pcap"
CSV="data/logs/${RUN_NAME}_frames.csv"
ALERTS="data/logs/${RUN_NAME}_alerts.jsonl"
STDOUT_LOG="data/logs/${RUN_NAME}_stdout.log"
NOTE="data/notes/${RUN_NAME}.md"

WIDS_PGID=""

mkdir -p data/pcaps data/logs data/notes

log_event() {
  local label="$1"
  local iso
  local epoch

  iso="$(date --iso-8601=ns)"
  epoch="$(date +%s.%N)"

  echo "${label}_ISO=${iso}" | tee -a "$NOTE"
  echo "${label}_EPOCH=${epoch}" | tee -a "$NOTE"
  echo "" | tee -a "$NOTE"
}

cleanup_wids() {
  if [ -n "${WIDS_PGID}" ]; then
    echo "[+] Stopping WIDS process group: ${WIDS_PGID}"

    kill -INT "-${WIDS_PGID}" 2>/dev/null || true
    sleep 3

    if ps -p "${WIDS_PGID}" >/dev/null 2>&1; then
      echo "[!] WIDS still running, sending TERM..."
      kill -TERM "-${WIDS_PGID}" 2>/dev/null || true
      sleep 2
    fi

    if ps -p "${WIDS_PGID}" >/dev/null 2>&1; then
      echo "[!] WIDS still running, sending KILL..."
      kill -KILL "-${WIDS_PGID}" 2>/dev/null || true
      sleep 1
    fi
  fi
}

trap cleanup_wids EXIT INT TERM

{
  echo "# ${RUN_NAME}"
  echo ""
  echo "RUN_NAME=${RUN_NAME}"
  echo "IFACE=${IFACE}"
  echo "DURATION_SECONDS=${DURATION_SECONDS}"
  echo "SCENARIO=baseline"
  echo ""
  echo "PCAP=${PCAP}"
  echo "CSV=${CSV}"
  echo "ALERTS=${ALERTS}"
  echo "STDOUT_LOG=${STDOUT_LOG}"
  echo ""
} > "$NOTE"

echo "[+] Starting baseline ${RUN_NAME}"
log_event "WIDS_START"

setsid bash -c "
  python main.py -i '$IFACE' --detect --summary --quiet \
    --csv '$CSV' \
    --alerts-json '$ALERTS' \
    --pcap-output '$PCAP'
" > "$STDOUT_LOG" 2>&1 &

WIDS_PGID="$!"

echo "WIDS_PGID=${WIDS_PGID}" | tee -a "$NOTE"
echo "" | tee -a "$NOTE"

sleep "$DURATION_SECONDS"

echo "[+] Stopping baseline ${RUN_NAME}"
log_event "WIDS_STOP_REQUEST"

cleanup_wids

log_event "WIDS_STOPPED"

WIDS_PGID=""

echo "[+] Baseline finished: ${RUN_NAME}"
echo "[+] Files:"
echo "    PCAP:   ${PCAP}"
echo "    CSV:    ${CSV}"
echo "    ALERTS: ${ALERTS}"
echo "    NOTE:   ${NOTE}"
echo "    LOG:    ${STDOUT_LOG}"
