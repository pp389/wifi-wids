import argparse
import sys

from src.capture.live_capture import LiveCapture
from src.capture.pcap_reader import PcapFileReader
from src.detectors.deauth_detector import DeauthDetector
from src.detectors.detection_engine import DetectionEngine
from src.detectors.disassoc_detector import DisassocDetector
from src.filters.frame_filter import FrameFilter
from src.output.alert_printer import AlertPrinter
from src.output.console_printer import ConsolePrinter
from src.output.csv_writer import CsvWriter
from src.parser.frame_parser import FrameParser
from src.stats.frame_stats import FrameStats


def main():
    args = parse_args()

    frame_parser = FrameParser()
    printer = ConsolePrinter()
    alert_printer = AlertPrinter()

    frame_filter = FrameFilter(
        frame_type=args.type,
        frame_subtype=args.subtype,
        ssid=args.ssid,
        bssid=args.bssid,
    )

    stats = FrameStats(interval_seconds=args.stats_interval)
    csv_writer = CsvWriter(args.csv) if args.csv else None

    detection_engine = build_detection_engine(args) if args.detect else None

    def handle_packet(packet):
        event = frame_parser.parse(packet)

        if event is None:
            return

        stats.update(event)

        if csv_writer:
            csv_writer.write(event)

        if frame_filter.matches(event) and not args.summary:
            printer.print_event(event)

        if detection_engine:
            alerts = detection_engine.process(event)

            for alert in alerts:
                alert_printer.print_alert(alert)

        if args.summary and stats.should_report():
            print(stats.report())

    source = build_capture_source(args)

    try:
        source.start(handle_packet)
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        if args.summary:
            print(stats.report())

        if csv_writer:
            csv_writer.close()

        sys.exit(0)


def build_capture_source(args):
    if args.pcap:
        return PcapFileReader(args.pcap)

    return LiveCapture(interface=args.interface)


def build_detection_engine(args):
    detectors = [
        DeauthDetector(
            window_seconds=args.detection_window,
            threshold=args.deauth_threshold,
        ),
        DisassocDetector(
            window_seconds=args.detection_window,
            threshold=args.disassoc_threshold,
        ),
    ]

    return DetectionEngine(detectors)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Klasyfikator, obserwator i detektor ramek WiFi 802.11"
    )

    source_group = parser.add_mutually_exclusive_group(required=True)

    source_group.add_argument(
        "-i",
        "--interface",
        help="Interfejs WiFi w trybie monitor, np. wlan0mon",
    )

    source_group.add_argument(
        "--pcap",
        help="Ścieżka do pliku PCAP/PCAPNG do analizy offline",
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

    parser.add_argument(
        "--detect",
        action="store_true",
        help="Włącz moduły detekcji heurystycznej",
    )

    parser.add_argument(
        "--detection-window",
        type=int,
        default=5,
        help="Okno czasowe detekcji w sekundach",
    )

    parser.add_argument(
        "--deauth-threshold",
        type=int,
        default=25,
        help="Próg liczby ramek deauthentication w oknie czasowym",
    )

    parser.add_argument(
        "--disassoc-threshold",
        type=int,
        default=20,
        help="Próg liczby ramek disassociation w oknie czasowym",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
