#!/usr/bin/env bash
set -euo pipefail

mkdir -p data/threshold_sweeps/beacon
mkdir -p data/threshold_sweeps/rts_cts
mkdir -p data/threshold_sweeps/deauth
mkdir -p data/threshold_sweeps/disassoc
mkdir -p data/threshold_sweeps/logs

run_analysis() {
  local pcap="$1"
  local output="$2"
  shift 2

  echo "[+] Analyzing $pcap -> $output"

  python main.py --pcap "$pcap" --detect --summary --quiet \
    --alerts-json "$output" \
    "$@" \
    > "${output%.jsonl}.stdout.log" 2>&1
}

# ============================================================
# BEACON FLOOD THRESHOLD SWEEP
# ============================================================

BEACON_PCAPS=(
  "data/pcaps/baseline_01.pcap"
  "data/pcaps/baseline_03.pcap"
  "data/pcaps/beacon_flood_01.pcap"
  "data/pcaps/beacon_flood_02.pcap"
  "data/pcaps/beacon_flood_03.pcap"
)

for pcap in "${BEACON_PCAPS[@]}"; do
  name="$(basename "$pcap" .pcap)"

  run_analysis "$pcap" "data/threshold_sweeps/beacon/${name}_sensitive_alerts.jsonl" \
    --beacon-count-threshold 100 \
    --beacon-unique-bssid-threshold 30 \
    --beacon-unique-ssid-threshold 20

  run_analysis "$pcap" "data/threshold_sweeps/beacon/${name}_medium_alerts.jsonl" \
    --beacon-count-threshold 150 \
    --beacon-unique-bssid-threshold 40 \
    --beacon-unique-ssid-threshold 30

  run_analysis "$pcap" "data/threshold_sweeps/beacon/${name}_strict_alerts.jsonl" \
    --beacon-count-threshold 200 \
    --beacon-unique-bssid-threshold 60 \
    --beacon-unique-ssid-threshold 40
done


# ============================================================
# RTS/CTS FLOOD THRESHOLD SWEEP
# ============================================================

RTS_CTS_PCAPS=(
  "data/pcaps/baseline_02.pcap"
  "data/pcaps/rts_cts_01.pcap"
  "data/pcaps/rts_cts_02.pcap"
  "data/pcaps/rts_cts_03.pcap"
)

for pcap in "${RTS_CTS_PCAPS[@]}"; do
  name="$(basename "$pcap" .pcap)"

  run_analysis "$pcap" "data/threshold_sweeps/rts_cts/${name}_sensitive_alerts.jsonl" \
    --rts-cts-window 5 \
    --rts-count-threshold 100 \
    --cts-count-threshold 100 \
    --rts-cts-combined-threshold 150 \
    --rts-per-source-threshold 50

  run_analysis "$pcap" "data/threshold_sweeps/rts_cts/${name}_medium_alerts.jsonl" \
    --rts-cts-window 5 \
    --rts-count-threshold 200 \
    --cts-count-threshold 200 \
    --rts-cts-combined-threshold 300 \
    --rts-per-source-threshold 100

  run_analysis "$pcap" "data/threshold_sweeps/rts_cts/${name}_strict_alerts.jsonl" \
    --rts-cts-window 5 \
    --rts-count-threshold 300 \
    --cts-count-threshold 300 \
    --rts-cts-combined-threshold 500 \
    --rts-per-source-threshold 150
done


# ============================================================
# DEAUTH FLOOD THRESHOLD SWEEP
# ============================================================

DEAUTH_PCAPS=(
  "data/pcaps/baseline_01.pcap"
  "data/pcaps/deauth_01.pcap"
  "data/pcaps/deauth_02.pcap"
  "data/pcaps/deauth_03.pcap"
)

for pcap in "${DEAUTH_PCAPS[@]}"; do
  name="$(basename "$pcap" .pcap)"

  run_analysis "$pcap" "data/threshold_sweeps/deauth/${name}_t10_alerts.jsonl" \
    --detection-window 5 \
    --deauth-threshold 10

  run_analysis "$pcap" "data/threshold_sweeps/deauth/${name}_t25_alerts.jsonl" \
    --detection-window 5 \
    --deauth-threshold 25

  run_analysis "$pcap" "data/threshold_sweeps/deauth/${name}_t50_alerts.jsonl" \
    --detection-window 5 \
    --deauth-threshold 50

  run_analysis "$pcap" "data/threshold_sweeps/deauth/${name}_t100_alerts.jsonl" \
    --detection-window 5 \
    --deauth-threshold 100
done


# ============================================================
# DISASSOC FLOOD THRESHOLD SWEEP
# ============================================================

DISASSOC_PCAPS=(
  "data/pcaps/baseline_01.pcap"
  "data/pcaps/disassoc_01.pcap"
  "data/pcaps/disassoc_02.pcap"
  "data/pcaps/disassoc_03.pcap"
)

for pcap in "${DISASSOC_PCAPS[@]}"; do
  name="$(basename "$pcap" .pcap)"

  run_analysis "$pcap" "data/threshold_sweeps/disassoc/${name}_t10_alerts.jsonl" \
    --detection-window 5 \
    --disassoc-threshold 10

  run_analysis "$pcap" "data/threshold_sweeps/disassoc/${name}_t20_alerts.jsonl" \
    --detection-window 5 \
    --disassoc-threshold 20

  run_analysis "$pcap" "data/threshold_sweeps/disassoc/${name}_t40_alerts.jsonl" \
    --detection-window 5 \
    --disassoc-threshold 40

  run_analysis "$pcap" "data/threshold_sweeps/disassoc/${name}_t80_alerts.jsonl" \
    --detection-window 5 \
    --disassoc-threshold 80
done

echo "[+] Threshold sweep finished."
echo "[+] Results saved in data/threshold_sweeps/"
