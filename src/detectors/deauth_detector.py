from collections import defaultdict, deque
from src.detectors.base import BaseDetector
from src.models.frame_event import FrameEvent
from src.models.alert import Alert


class DeauthDetector(BaseDetector):
    def __init__(self, window_seconds: int = 5, threshold: int = 25):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.events_by_source = defaultdict(deque)

    def process(self, event: FrameEvent) -> list[Alert]:
        if event.frame_subtype != "deauthentication":
            return []

        now = event.timestamp
        source = event.source_mac or "unknown"

        window = self.events_by_source[source]
        window.append(now)

        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if len(window) >= self.threshold:
            return [
                Alert(
                    timestamp=now,
                    attack_type="DEAUTH_FLOOD",
                    severity="HIGH",
                    message=(
                        f"Wykryto możliwy atak Deauthentication Flood: "
                        f"{len(window)} ramek deauth z {source} "
                        f"w czasie {self.window_seconds}s."
                    ),
                    evidence={
                        "source_mac": source,
                        "destination_mac": event.destination_mac,
                        "count": len(window),
                        "window_seconds": self.window_seconds,
                    },
                )
            ]

        return []
