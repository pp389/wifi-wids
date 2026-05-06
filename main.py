import argparse

from src.capture.live_capture import LiveCapture
from src.parser.frame_parser import FrameParser
from src.output.console_printer import ConsolePrinter


def main():
    args = parse_args()

    frame_parser = FrameParser()
    printer = ConsolePrinter()

    def handle_packet(packet):
        event = frame_parser.parse(packet)

        if event is None:
            return

        printer.print_event(event)

    capture = LiveCapture(interface=args.interface)
    capture.start(handle_packet)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Klasyfikator ramek WiFi 802.11"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Interfejs WiFi w trybie monitor, np. wlan0mon",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
