from dataclasses import dataclass


@dataclass
class FrameEvent:
    timestamp: float

    frame_type: str
    frame_subtype: str

    source_mac: str | None
    destination_mac: str | None
    bssid: str | None

    receiver_mac: str | None = None
    transmitter_mac: str | None = None

    ssid: str | None = None

    rssi: int | None = None
    channel: int | None = None
    frequency: int | None = None

    is_protected: bool | None = None
    retry: bool | None = None

    raw_summary: str | None = None
