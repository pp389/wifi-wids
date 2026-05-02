from dataclasses import dataclass


@dataclass
class FrameEvent:
    timestamp: float
    frame_type: str
    frame_subtype: str
    source_mac: str | None
    destination_mac: str | None
    bssid: str | None
    ssid: str | None = None
    rssi: int | None = None
    channel: int | None = None
