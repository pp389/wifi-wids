from collections import deque

from src.detectors.base import BaseDetector
from src.models.alert import Alert
from src.models.frame_event import FrameEvent


class BeaconFloodDetector(BaseDetector):
    def __init__(
        self,
        window_seconds: int = 10,
        beacon_count_threshold: int = 100,
        unique_bssid_threshold: int = 30,
        unique_ssid_threshold: int = 20,
    ):
        self.window_seconds = window_seconds
        self.beacon_count_threshold = beacon_count_threshold
        self.unique_bssid_threshold = unique_bssid_threshold
        self.unique_ssid_threshold = unique_ssid_threshold

        self.window = deque()
        self.last_alert_time = None
        self.alert_cooldown_seconds = window_seconds

    def process(self, event: FrameEvent) -> list[Alert]:
        if event.frame_subtype != "beacon":
            return []

        now = event.timestamp

        self.window.append(
            {
                "timestamp": now,
                "bssid": event.bssid,
                "ssid": event.ssid,
                "source_mac": event.source_mac,
                "channel": event.channel,
                "rssi": event.rssi,
            }
        )

        while self.window and now - self.window[0]["timestamp"] > self.window_seconds:
            self.window.popleft()

        beacon_count = len(self.window)
        unique_bssids = {
            item["bssid"]
            for item in self.window
            if item["bssid"]
        }
        unique_ssids = {
            item["ssid"]
            for item in self.window
            if item["ssid"] and item["ssid"] != "<hidden>"
        }

        triggered_reasons = []

        if beacon_count >= self.beacon_count_threshold:
            triggered_reasons.append("high_beacon_rate")

        if len(unique_bssids) >= self.unique_bssid_threshold:
            triggered_reasons.append("many_unique_bssids")

        if len(unique_ssids) >= self.unique_ssid_threshold:
            triggered_reasons.append("many_unique_ssids")

        if not triggered_reasons:
            return []

        if (
            self.last_alert_time is not None
            and now - self.last_alert_time < self.alert_cooldown_seconds
        ):
            return []

        self.last_alert_time = now

        return [
            Alert(
                timestamp=now,
                attack_type="BEACON_FLOOD",
                severity=self._severity(
                    beacon_count=beacon_count,
                    unique_bssid_count=len(unique_bssids),
                    unique_ssid_count=len(unique_ssids),
                ),
                message=(
                    f"Wykryto możliwy atak Beacon Flood: "
                    f"{beacon_count} ramek beacon, "
                    f"{len(unique_bssids)} unikalnych BSSID, "
                    f"{len(unique_ssids)} unikalnych SSID "
                    f"w oknie {self.window_seconds}s."
                ),
                evidence={
                    "beacon_count": beacon_count,
                    "unique_bssid_count": len(unique_bssids),
                    "unique_ssid_count": len(unique_ssids),
                    "window_seconds": self.window_seconds,
                    "beacon_count_threshold": self.beacon_count_threshold,
                    "unique_bssid_threshold": self.unique_bssid_threshold,
                    "unique_ssid_threshold": self.unique_ssid_threshold,
                    "triggered_reasons": triggered_reasons,
                    "sample_ssids": list(unique_ssids)[:10],
                    "sample_bssids": list(unique_bssids)[:10],
                },
            )
        ]

    def _severity(
        self,
        beacon_count: int,
        unique_bssid_count: int,
        unique_ssid_count: int,
    ) -> str:
        if (
            beacon_count >= self.beacon_count_threshold * 3
            or unique_bssid_count >= self.unique_bssid_threshold * 3
            or unique_ssid_count >= self.unique_ssid_threshold * 3
        ):
            return "CRITICAL"

        if (
            beacon_count >= self.beacon_count_threshold * 2
            or unique_bssid_count >= self.unique_bssid_threshold * 2
            or unique_ssid_count >= self.unique_ssid_threshold * 2
        ):
            return "HIGH"

        return "MEDIUM"
