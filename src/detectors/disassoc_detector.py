from collections import defaultdict, deque

from src.detectors.base import BaseDetector
from src.models.alert import Alert
from src.models.frame_event import FrameEvent


class DisassocDetector(BaseDetector):
    def __init__(self, window_seconds: int = 5, threshold: int = 20):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.events_by_source = defaultdict(deque)
        self.last_alert_time_by_source = {}
        self.alert_cooldown_seconds = window_seconds

    def process(self, event: FrameEvent) -> list[Alert]:
        if event.frame_subtype != "disassociation":
            return []

        source = event.source_mac or "unknown"
        now = event.timestamp

        window = self.events_by_source[source]
        window.append(now)

        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if len(window) < self.threshold:
            return []

        last_alert = self.last_alert_time_by_source.get(source)

        if last_alert is not None and now - last_alert < self.alert_cooldown_seconds:
            return []

        self.last_alert_time_by_source[source] = now

        return [
            Alert(
                timestamp=now,
                attack_type="DISASSOC_FLOOD",
                severity=self._severity(len(window)),
                message=(
                    f"Wykryto możliwy atak Disassociation Flood: "
                    f"{len(window)} ramek disassociation z adresu {source} "
                    f"w oknie {self.window_seconds}s."
                ),
                evidence={
                    "source_mac": source,
                    "destination_mac": event.destination_mac,
                    "bssid": event.bssid,
                    "count": len(window),
                    "threshold": self.threshold,
                    "window_seconds": self.window_seconds,
                },
            )
        ]

    def _severity(self, count: int) -> str:
        if count >= self.threshold * 3:
            return "CRITICAL"

        if count >= self.threshold * 2:
            return "HIGH"

        return "MEDIUM"
