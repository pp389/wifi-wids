from collections import defaultdict, deque

from src.detectors.base import BaseDetector
from src.models.alert import Alert
from src.models.frame_event import FrameEvent


class ProbeFloodDetector(BaseDetector):
    def __init__(
        self,
        window_seconds: int = 10,
        probe_count_threshold: int = 100,
        per_source_threshold: int = 50,
        unique_ssid_per_source_threshold: int = 20,
    ):
        self.window_seconds = window_seconds
        self.probe_count_threshold = probe_count_threshold
        self.per_source_threshold = per_source_threshold
        self.unique_ssid_per_source_threshold = unique_ssid_per_source_threshold

        self.global_window = deque()
        self.events_by_source = defaultdict(deque)

        self.last_global_alert_time = None
        self.last_alert_time_by_source = {}

        self.alert_cooldown_seconds = window_seconds

    def process(self, event: FrameEvent) -> list[Alert]:
        if event.frame_subtype != "probe_request":
            return []

        now = event.timestamp
        source = event.source_mac or "unknown"
        ssid = event.ssid

        self.global_window.append(
            {
                "timestamp": now,
                "source_mac": source,
                "ssid": ssid,
            }
        )

        source_window = self.events_by_source[source]
        source_window.append(
            {
                "timestamp": now,
                "ssid": ssid,
            }
        )

        self._cleanup_global_window(now)
        self._cleanup_source_window(source, now)

        alerts = []

        global_alert = self._check_global_probe_flood(now)
        if global_alert:
            alerts.append(global_alert)

        source_alert = self._check_source_probe_flood(source, now)
        if source_alert:
            alerts.append(source_alert)

        return alerts

    def _cleanup_global_window(self, now: float) -> None:
        while (
            self.global_window
            and now - self.global_window[0]["timestamp"] > self.window_seconds
        ):
            self.global_window.popleft()

    def _cleanup_source_window(self, source: str, now: float) -> None:
        source_window = self.events_by_source[source]

        while (
            source_window
            and now - source_window[0]["timestamp"] > self.window_seconds
        ):
            source_window.popleft()

    def _check_global_probe_flood(self, now: float) -> Alert | None:
        probe_count = len(self.global_window)

        if probe_count < self.probe_count_threshold:
            return None

        if (
            self.last_global_alert_time is not None
            and now - self.last_global_alert_time < self.alert_cooldown_seconds
        ):
            return None

        self.last_global_alert_time = now

        unique_sources = {
            item["source_mac"]
            for item in self.global_window
            if item["source_mac"]
        }

        unique_ssids = {
            item["ssid"]
            for item in self.global_window
            if item["ssid"] and item["ssid"] != "<hidden>"
        }

        return Alert(
            timestamp=now,
            attack_type="PROBE_FLOOD_GLOBAL",
            severity=self._severity(
                value=probe_count,
                threshold=self.probe_count_threshold,
            ),
            message=(
                f"Wykryto możliwy globalny Probe Flood: "
                f"{probe_count} ramek probe request "
                f"w oknie {self.window_seconds}s."
            ),
            evidence={
                "probe_count": probe_count,
                "unique_source_count": len(unique_sources),
                "unique_ssid_count": len(unique_ssids),
                "threshold": self.probe_count_threshold,
                "window_seconds": self.window_seconds,
                "sample_sources": list(unique_sources)[:10],
                "sample_ssids": list(unique_ssids)[:10],
            },
        )

    def _check_source_probe_flood(self, source: str, now: float) -> Alert | None:
        source_window = self.events_by_source[source]
        probe_count = len(source_window)

        unique_ssids = {
            item["ssid"]
            for item in source_window
            if item["ssid"] and item["ssid"] != "<hidden>"
        }

        triggered_reasons = []

        if probe_count >= self.per_source_threshold:
            triggered_reasons.append("high_probe_rate_from_single_source")

        if len(unique_ssids) >= self.unique_ssid_per_source_threshold:
            triggered_reasons.append("many_unique_ssids_from_single_source")

        if not triggered_reasons:
            return None

        last_alert = self.last_alert_time_by_source.get(source)

        if (
            last_alert is not None
            and now - last_alert < self.alert_cooldown_seconds
        ):
            return None

        self.last_alert_time_by_source[source] = now

        return Alert(
            timestamp=now,
            attack_type="PROBE_FLOOD_SOURCE",
            severity=self._severity(
                value=max(probe_count, len(unique_ssids)),
                threshold=min(
                    self.per_source_threshold,
                    self.unique_ssid_per_source_threshold,
                ),
            ),
            message=(
                f"Wykryto możliwy Probe Flood z pojedynczego źródła: "
                f"{probe_count} ramek probe request z adresu {source}, "
                f"{len(unique_ssids)} unikalnych SSID "
                f"w oknie {self.window_seconds}s."
            ),
            evidence={
                "source_mac": source,
                "probe_count": probe_count,
                "unique_ssid_count": len(unique_ssids),
                "per_source_threshold": self.per_source_threshold,
                "unique_ssid_per_source_threshold": self.unique_ssid_per_source_threshold,
                "window_seconds": self.window_seconds,
                "triggered_reasons": triggered_reasons,
                "sample_ssids": list(unique_ssids)[:10],
            },
        )

    def _severity(self, value: int, threshold: int) -> str:
        if value >= threshold * 3:
            return "CRITICAL"

        if value >= threshold * 2:
            return "HIGH"

        return "MEDIUM"
