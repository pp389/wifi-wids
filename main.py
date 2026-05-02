import argparse

from src.capture.live_capture import LiveCapture
from src.parser.frame_parser import FrameParser
from src.detectors.deauth_detector import DeauthDetector


def main():
    args = parse_args()

    parser = FrameParser()

    detectors = [
        DeauthDetector(window_seconds=5, threshold=25),
    ]

    def handle_packet(packet):
        event = parser.parse(packet)

        if event is None:
            return

        for detector in detectors:
            alerts = detector.process(event)

            for alert in alerts:
                print_alert(alert)

    capture = LiveCapture(interface=args.interface)
    capture.start(handle_packet)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Prosty system detekcji ataków WiFi 802.11"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Interfejs WiFi w trybie monitor, np. wlan0mon",
    )

    return parser.parse_args()


def print_alert(alert):
    print()
    print("=" * 80)
    print(f"[ALERT] {alert.attack_type}")
    print(f"Severity: {alert.severity}")
    print(f"Time: {alert.timestamp}")
    print(f"Message: {alert.message}")
    print(f"Evidence: {alert.evidence}")
    print("=" * 80)
    print()


if __name__ == "__main__":
    main()
