import time
from collections import Counter
from src.models.frame_event import FrameEvent


class FrameStats:
    def __init__(self, interval_seconds: int = 10):
        self.interval_seconds = interval_seconds
        self.start_time = time.time()
        self.last_report_time = time.time()

        self.total_counter = 0
        self.type_counter = Counter()
        self.subtype_counter = Counter()

        self.unique_ssids = set()
        self.unique_bssids = set()

    def update(self, event: FrameEvent) -> None:
        self.total_counter += 1
        self.type_counter[event.frame_type] += 1
        self.subtype_counter[event.frame_subtype] += 1

        if event.ssid and event.ssid != "<hidden>":
            self.unique_ssids.add(event.ssid)

        if event.bssid:
            self.unique_bssids.add(event.bssid)

    def should_report(self) -> bool:
        return time.time() - self.last_report_time >= self.interval_seconds

    def report(self) -> str:
        now = time.time()
        elapsed = now - self.start_time

        lines = []
        lines.append("")
        lines.append("=" * 80)
        lines.append(f"STATISTICS after {elapsed:.1f}s")
        lines.append("-" * 80)
        lines.append(f"total frames: {self.total_counter}")
        lines.append("")

        lines.append("by frame type:")
        for frame_type, count in self.type_counter.most_common():
            lines.append(f"  {frame_type}: {count}")

        lines.append("")
        lines.append("by frame subtype:")
        for subtype, count in self.subtype_counter.most_common():
            lines.append(f"  {subtype}: {count}")

        lines.append("")
        lines.append(f"unique SSIDs: {len(self.unique_ssids)}")
        lines.append(f"unique BSSIDs: {len(self.unique_bssids)}")
        lines.append("=" * 80)

        self.last_report_time = now

        return "\n".join(lines)
