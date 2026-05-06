import argparse
import sys

from src.capture.live_capture import LiveCapture
from src.parser.frame_parser import FrameParser
from src.output.console_printer import ConsolePrinter
from src.output.csv_writer import CsvWriter
from src.filters.frame_filter import FrameFilter
from src.stats.frame_stats import FrameStats


def main():
    args = parse_args()

    frame_parser = FrameParser()
    printer = ConsolePrinter()

    frame_filter = FrameFilter(
        frame_type=args.type,
        frame_subtype=args.subtype,
        ssid=args.ssid,
        bssid=args.bssid,
    )

    stats = FrameStats(interval_seconds=args.stats_interval)

    csv_writer = CsvWriter(args.csv) if args.csv else None

    def handle_packet(packet):
        event = frame_parser.parse(packet)

        if event is None:
            return

        stats.update(event)

        if csv_writer:
            csv_writer.write(event)

        if frame_filter.matches(event) and not args.summary:
            printer.print_event(event)

        if args.summary and stats.should_report():
            print(stats.report())

    capture = LiveCapture(interface=args.interface)

    try:
        capture.start(handle_packet)
    except KeyboardInterrupt:
        print("\nStopping capture...")

        if args.summary:
            print(stats.report())

        if csv_writer:
            csv_writer.close()

        sys.exit(0)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Klasyfikator i obserwator ramek WiFi 802.11"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Interfejs WiFi w trybie monitor, np. wlan0mon",
    )

    parser.add_argument(
        "--type",
        choices=["management", "control", "data", "extension"],
        help="Pokazuj tylko wybrany typ ramek",
    )

    parser.add_argument(
        "--subtype",
        help="Pokazuj tylko wybrany podtyp ramek, np. beacon, deauthentication, qos_data",
    )

    parser.add_argument(
        "--ssid",
        help="Pokazuj tylko ramki dotyczące danego SSID",
    )

    parser.add_argument(
        "--bssid",
        help="Pokazuj tylko ramki dotyczące danego BSSID",
    )

    parser.add_argument(
        "--summary",
        action="store_true",
        help="Nie wypisuj każdej ramki, pokazuj tylko statystyki okresowe",
    )

    parser.add_argument(
        "--stats-interval",
        type=int,
        default=10,
        help="Interwał wypisywania statystyk w sekundach",
    )

    parser.add_argument(
        "--csv",
        help="Ścieżka do pliku CSV, np. data/logs/capture.csv",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
