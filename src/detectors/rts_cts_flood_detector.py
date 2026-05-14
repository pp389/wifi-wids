from collections import defaultdict, deque

from src.detectors.base import BaseDetector
from src.models.alert import Alert
from src.models.frame_event import FrameEvent


class RtsCtsFloodDetector(BaseDetector):
    def __init__(
        self,
        window_seconds: int = 5,
        rts_count_threshold: int = 100,
        cts_count_threshold: int = 100,
        combined_count_threshold: int = 150,
        rts_per_source_threshold: int = 50,
    ):
        self.window_seconds = window_seconds
        self.rts_count_threshold = rts_count_threshold
        self.cts_count_threshold = cts_count_threshold
        self.combined_count_threshold = combined_count_threshold
        self.rts_per_source_threshold = rts_per_source_threshold

        self.global_window = deque()
        self.rts_by_source = defaultdict(deque)

        self.last_global_alert_time = None
        self.last_alert_time_by_source = {}

        self.alert_cooldown_seconds = window_seconds

    def process(self, event: FrameEvent) -> list[Alert]:
        if event.frame_subtype not in {"rts", "cts"}:
            return []

        now = event.timestamp
        subtype = event.frame_subtype
        source = event.source_mac or "unknown"

        self.global_window.append(
            {
                "timestamp": now,
                "subtype": subtype,
                "source_mac": source,
                "destination_mac": event.destination_mac,
                "bssid": event.bssid,
            }
        )

        if subtype == "rts":
            source_window = self.rts_by_source[source]
            source_window.append(
                {
                    "timestamp": now,
                    "destination_mac": event.destination_mac,
                }
            )

        self._cleanup_global_window(now)

        if subtype == "rts":
            self._cleanup_source_window(source, now)

        alerts = []

        global_alert = self._check_global_flood(now)
        if global_alert:
            alerts.append(global_alert)

        if subtype == "rts":
            source_alert = self._check_rts_source_flood(source, now)
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
        source_window = self.rts_by_source[source]

        while (
            source_window
            and now - source_window[0]["timestamp"] > self.window_seconds
        ):
            source_window.popleft()

    def _check_global_flood(self, now: float) -> Alert | None:
        rts_count = sum(
            1 for item in self.global_window
            if item["subtype"] == "rts"
        )

        cts_count = sum(
            1 for item in self.global_window
            if item["subtype"] == "cts"
        )

        combined_count = rts_count + cts_count

        triggered_reasons = []

        if rts_count >= self.rts_count_threshold:
            triggered_reasons.append("high_rts_rate")

        if cts_count >= self.cts_count_threshold:
            triggered_reasons.append("high_cts_rate")

        if combined_count >= self.combined_count_threshold:
            triggered_reasons.append("high_combined_rts_cts_rate")

        if not triggered_reasons:
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
            if item["source_mac"] and item["source_mac"] != "unknown"
        }

        unique_destinations = {
            item["destination_mac"]
            for item in self.global_window
            if item["destination_mac"]
        }

        return Alert(
            timestamp=now,
            attack_type="RTS_CTS_FLOOD_GLOBAL",
            severity=self._severity(
                value=max(rts_count, cts_count, combined_count),
                threshold=min(
                    self.rts_count_threshold,
                    self.cts_count_threshold,
                    self.combined_count_threshold,
                ),
            ),
            message=(
                f"Wykryto możliwy RTS/CTS Flood: "
                f"{rts_count} ramek RTS oraz {cts_count} ramek CTS "
                f"w oknie {self.window_seconds}s."
            ),
            evidence={
                "rts_count": rts_count,
                "cts_count": cts_count,
                "combined_count": combined_count,
                "window_seconds": self.window_seconds,
                "rts_count_threshold": self.rts_count_threshold,
                "cts_count_threshold": self.cts_count_threshold,
                "combined_count_threshold": self.combined_count_threshold,
                "triggered_reasons": triggered_reasons,
                "unique_source_count": len(unique_sources),
                "unique_destination_count": len(unique_destinations),
                "sample_sources": list(unique_sources)[:10],
                "sample_destinations": list(unique_destinations)[:10],
            },
        )

    def _check_rts_source_flood(self, source: str, now: float) -> Alert | None:
        source_window = self.rts_by_source[source]
        rts_count = len(source_window)

        if rts_count < self.rts_per_source_threshold:
            return None

        last_alert = self.last_alert_time_by_source.get(source)

        if (
            last_alert is not None
            and now - last_alert < self.alert_cooldown_seconds
        ):
            return None

        self.last_alert_time_by_source[source] = now

        unique_destinations = {
            item["destination_mac"]
            for item in source_window
            if item["destination_mac"]
        }

        return Alert(
            timestamp=now,
            attack_type="RTS_FLOOD_SOURCE",
            severity=self._severity(
                value=rts_count,
                threshold=self.rts_per_source_threshold,
            ),
            message=(
                f"Wykryto możliwy RTS Flood z pojedynczego źródła: "
                f"{rts_count} ramek RTS z adresu {source} "
                f"w oknie {self.window_seconds}s."
            ),
            evidence={
                "source_mac": source,
                "rts_count": rts_count,
                "unique_destination_count": len(unique_destinations),
                "rts_per_source_threshold": self.rts_per_source_threshold,
                "window_seconds": self.window_seconds,
                "sample_destinations": list(unique_destinations)[:10],
            },
        )

    def _severity(self, value: int, threshold: int) -> str:
        if value >= threshold * 3:
            return "CRITICAL"

        if value >= threshold * 2:
            return "HIGH"

        return "MEDIUM"
