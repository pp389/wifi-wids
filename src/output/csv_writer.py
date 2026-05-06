import csv
from pathlib import Path
from src.models.frame_event import FrameEvent


class CsvWriter:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        self.file = open(self.file_path, mode="w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(
            self.file,
            fieldnames=[
                "timestamp",
                "frame_type",
                "frame_subtype",
                "source_mac",
                "destination_mac",
                "receiver_mac",
                "transmitter_mac",
                "bssid",
                "ssid",
                "rssi",
                "channel",
                "frequency",
                "is_protected",
                "retry",
            ],
        )

        self.writer.writeheader()

    def write(self, event: FrameEvent) -> None:
        self.writer.writerow(
            {
                "timestamp": event.timestamp,
                "frame_type": event.frame_type,
                "frame_subtype": event.frame_subtype,
                "source_mac": event.source_mac,
                "destination_mac": event.destination_mac,
                "receiver_mac": event.receiver_mac,
                "transmitter_mac": event.transmitter_mac,
                "bssid": event.bssid,
                "ssid": event.ssid,
                "rssi": event.rssi,
                "channel": event.channel,
                "frequency": event.frequency,
                "is_protected": event.is_protected,
                "retry": event.retry,
            }
        )
        self.file.flush()

    def close(self) -> None:
        self.file.close()
