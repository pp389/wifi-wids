#!/usr/bin/env bash
set -euo pipefail

mkdir -p data/threshold_sweeps/probe

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

PROBE_PCAPS=(
  "data/pcaps/baseline_01.pcap"
  "data/pcaps/baseline_02.pcap"
  "data/pcaps/baseline_03.pcap"
  "data/pcaps/probe_flood_01.pcap"
  "data/pcaps/probe_flood_02.pcap"
  "data/pcaps/probe_flood_03.pcap"
  "data/pcaps/probe_flood_random_01.pcap"
)

for pcap in "${PROBE_PCAPS[@]}"; do
  if [ ! -f "$pcap" ]; then
    echo "[!] Missing PCAP, skipping: $pcap"
    continue
  fi

  name="$(basename "$pcap" .pcap)"

  # Czuła konfiguracja — powinna wykrywać szybko, ale może zwiększać FP.
  run_analysis "$pcap" "data/threshold_sweeps/probe/${name}_sensitive_alerts.jsonl" \
    --probe-window 10 \
    --probe-count-threshold 50 \
    --probe-per-source-threshold 20 \
    --probe-unique-ssid-per-source-threshold 8

  # Konfiguracja domyślna/bazowa.
  run_analysis "$pcap" "data/threshold_sweeps/probe/${name}_default_alerts.jsonl" \
    --probe-window 10 \
    --probe-count-threshold 100 \
    --probe-per-source-threshold 50 \
    --probe-unique-ssid-per-source-threshold 20

  # Konfiguracja ostrzejsza — mniejsze ryzyko FP, potencjalnie większe opóźnienie.
  run_analysis "$pcap" "data/threshold_sweeps/probe/${name}_strict_alerts.jsonl" \
    --probe-window 10 \
    --probe-count-threshold 200 \
    --probe-per-source-threshold 100 \
    --probe-unique-ssid-per-source-threshold 40

  # Bardzo ostra konfiguracja — sprawdzenie granicy detekcji.
  run_analysis "$pcap" "data/threshold_sweeps/probe/${name}_very_strict_alerts.jsonl" \
    --probe-window 10 \
    --probe-count-threshold 500 \
    --probe-per-source-threshold 250 \
    --probe-unique-ssid-per-source-threshold 80
done

echo "[+] Probe threshold sweep finished."
echo "[+] Results saved in data/threshold_sweeps/probe/"
