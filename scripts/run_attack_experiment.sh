#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 6 ]; then
  echo "Usage:"
  echo "  sudo bash scripts/run_attack_experiment.sh RUN_NAME IFACE PRE_SECONDS ATTACK_SECONDS POST_SECONDS ATTACK_COMMAND"
  exit 1
fi

RUN_NAME="$1"
IFACE="$2"
PRE_SECONDS="$3"
ATTACK_SECONDS="$4"
POST_SECONDS="$5"
shift 5

ATTACK_COMMAND="$*"

PCAP="data/pcaps/${RUN_NAME}.pcap"
CSV="data/logs/${RUN_NAME}_frames.csv"
ALERTS="data/logs/${RUN_NAME}_alerts.jsonl"
STDOUT_LOG="data/logs/${RUN_NAME}_stdout.log"
NOTE="data/notes/${RUN_NAME}.md"

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

{
  echo "# ${RUN_NAME}"
  echo ""
  echo "RUN_NAME=${RUN_NAME}"
  echo "IFACE=${IFACE}"
  echo "PRE_SECONDS=${PRE_SECONDS}"
  echo "ATTACK_SECONDS=${ATTACK_SECONDS}"
  echo "POST_SECONDS=${POST_SECONDS}"
  echo ""
  echo "PCAP=${PCAP}"
  echo "CSV=${CSV}"
  echo "ALERTS=${ALERTS}"
  echo "STDOUT_LOG=${STDOUT_LOG}"
  echo ""
  echo "ATTACK_COMMAND=${ATTACK_COMMAND}"
  echo ""
} > "$NOTE"

echo "[+] Starting WIDS for ${RUN_NAME}"
log_event "WIDS_START"

python main.py -i "$IFACE" --detect --summary --quiet \
  --csv "$CSV" \
  --alerts-json "$ALERTS" \
  --pcap-output "$PCAP" \
  > "$STDOUT_LOG" 2>&1 &

WIDS_PID="$!"

echo "WIDS_PID=${WIDS_PID}" | tee -a "$NOTE"
echo "" | tee -a "$NOTE"

sleep "$PRE_SECONDS"

echo "[+] Starting attack for ${RUN_NAME}"
log_event "ATTACK_START"

set +e
timeout --foreground --signal=INT "${ATTACK_SECONDS}s" bash -lc "$ATTACK_COMMAND" | tee -a "$STDOUT_LOG"
ATTACK_EXIT_CODE="${PIPESTATUS[0]}"
set -e

echo "ATTACK_EXIT_CODE=${ATTACK_EXIT_CODE}" | tee -a "$NOTE"
echo "" | tee -a "$NOTE"

log_event "ATTACK_END"

sleep "$POST_SECONDS"

echo "[+] Stopping WIDS for ${RUN_NAME}"
log_event "WIDS_STOP_REQUEST"

kill -INT "$WIDS_PID" 2>/dev/null || true
wait "$WIDS_PID" 2>/dev/null || true

log_event "WIDS_STOPPED"

echo "[+] Experiment finished: ${RUN_NAME}"
echo "[+] Files:"
echo "    PCAP:   ${PCAP}"
echo "    CSV:    ${CSV}"
echo "    ALERTS: ${ALERTS}"
echo "    NOTE:   ${NOTE}"
echo "    LOG:    ${STDOUT_LOG}"
