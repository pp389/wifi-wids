#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "Usage:"
  echo "  sudo bash scripts/run_baseline_experiment.sh RUN_NAME IFACE DURATION_SECONDS"
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

set +e
timeout --foreground --signal=INT "${DURATION_SECONDS}s" \
  python main.py -i "$IFACE" --detect --summary --quiet \
    --csv "$CSV" \
    --alerts-json "$ALERTS" \
    --pcap-output "$PCAP" \
    > "$STDOUT_LOG" 2>&1
EXIT_CODE="$?"
set -e

echo "EXIT_CODE=${EXIT_CODE}" | tee -a "$NOTE"
echo "" | tee -a "$NOTE"

log_event "WIDS_STOPPED"

echo "[+] Baseline finished: ${RUN_NAME}"
