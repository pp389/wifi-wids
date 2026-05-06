from collections import defaultdict

from src.detectors.base import BaseDetector
from src.models.alert import Alert
from src.models.frame_event import FrameEvent


class EvilTwinDetector(BaseDetector):
    def __init__(
        self,
        min_bssid_per_ssid: int = 2,
        rssi_delta_threshold: int = 25,
        channel_change_enabled: bool = True,
        alert_cooldown_seconds: int = 30,
    ):
        self.min_bssid_per_ssid = min_bssid_per_ssid
        self.rssi_delta_threshold = rssi_delta_threshold
        self.channel_change_enabled = channel_change_enabled
        self.alert_cooldown_seconds = alert_cooldown_seconds

        self.networks_by_ssid = defaultdict(dict)
        self.last_alert_time_by_ssid = {}

    def process(self, event: FrameEvent) -> list[Alert]:
        if event.frame_subtype not in {"beacon", "probe_response"}:
            return []

        if not event.ssid or event.ssid == "<hidden>":
            return []

        if not event.bssid:
            return []

        ssid = event.ssid
        bssid = event.bssid
        now = event.timestamp

        self._update_network_observation(ssid, bssid, event)

        bssids_for_ssid = self.networks_by_ssid[ssid]

        if len(bssids_for_ssid) < self.min_bssid_per_ssid:
            return []

        triggered_reasons = self._evaluate_suspicious_conditions(ssid)

        if not triggered_reasons:
            return []

        last_alert = self.last_alert_time_by_ssid.get(ssid)

        if (
            last_alert is not None
            and now - last_alert < self.alert_cooldown_seconds
        ):
            return []

        self.last_alert_time_by_ssid[ssid] = now

        return [
            Alert(
                timestamp=now,
                attack_type="POTENTIAL_EVIL_TWIN",
                severity=self._severity(triggered_reasons),
                message=(
                    f"Wykryto potencjalny Evil Twin / Rogue AP dla SSID '{ssid}'. "
                    f"Zaobserwowano {len(bssids_for_ssid)} różnych BSSID "
                    f"oraz podejrzane różnice parametrów sieci."
                ),
                evidence={
                    "ssid": ssid,
                    "bssid_count": len(bssids_for_ssid),
                    "bssids": list(bssids_for_ssid.keys()),
                    "triggered_reasons": triggered_reasons,
                    "observations": self._build_observation_snapshot(ssid),
                },
            )
        ]

    def _update_network_observation(
        self,
        ssid: str,
        bssid: str,
        event: FrameEvent,
    ) -> None:
        networks = self.networks_by_ssid[ssid]

        if bssid not in networks:
            networks[bssid] = {
                "first_seen": event.timestamp,
                "last_seen": event.timestamp,
                "seen_count": 0,
                "channels": set(),
                "rssi_values": [],
            }

        observation = networks[bssid]
        observation["last_seen"] = event.timestamp
        observation["seen_count"] += 1

        if event.channel is not None:
            observation["channels"].add(event.channel)

        if event.rssi is not None:
            observation["rssi_values"].append(event.rssi)

            if len(observation["rssi_values"]) > 20:
                observation["rssi_values"] = observation["rssi_values"][-20:]

    def _evaluate_suspicious_conditions(self, ssid: str) -> list[str]:
        observations = self.networks_by_ssid[ssid]
        reasons = []

        if len(observations) >= self.min_bssid_per_ssid:
            reasons.append("same_ssid_multiple_bssid")

        channels = set()

        for data in observations.values():
            channels.update(data["channels"])

        if self.channel_change_enabled and len(channels) > 1:
            reasons.append("same_ssid_multiple_channels")

        avg_rssi_values = []

        for bssid, data in observations.items():
            if data["rssi_values"]:
                avg_rssi = sum(data["rssi_values"]) / len(data["rssi_values"])
                avg_rssi_values.append((bssid, avg_rssi))

        if len(avg_rssi_values) >= 2:
            rssi_values = [value for _, value in avg_rssi_values]
            rssi_delta = max(rssi_values) - min(rssi_values)

            if abs(rssi_delta) >= self.rssi_delta_threshold:
                reasons.append("large_rssi_delta_between_bssids")

        return reasons

    def _build_observation_snapshot(self, ssid: str) -> dict:
        snapshot = {}

        for bssid, data in self.networks_by_ssid[ssid].items():
            avg_rssi = None

            if data["rssi_values"]:
                avg_rssi = sum(data["rssi_values"]) / len(data["rssi_values"])

            snapshot[bssid] = {
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "seen_count": data["seen_count"],
                "channels": list(data["channels"]),
                "avg_rssi": avg_rssi,
            }

        return snapshot

    def _severity(self, triggered_reasons: list[str]) -> str:
        if len(triggered_reasons) >= 3:
            return "HIGH"

        if len(triggered_reasons) == 2:
            return "MEDIUM"

        return "LOW"
