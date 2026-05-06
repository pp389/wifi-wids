from src.models.frame_event import FrameEvent


class FrameFilter:
    def __init__(
        self,
        frame_type: str | None = None,
        frame_subtype: str | None = None,
        ssid: str | None = None,
        bssid: str | None = None,
    ):
        self.frame_type = frame_type
        self.frame_subtype = frame_subtype
        self.ssid = ssid
        self.bssid = bssid.lower() if bssid else None

    def matches(self, event: FrameEvent) -> bool:
        if self.frame_type and event.frame_type != self.frame_type:
            return False

        if self.frame_subtype and event.frame_subtype != self.frame_subtype:
            return False

        if self.ssid and event.ssid != self.ssid:
            return False

        if self.bssid:
            if not event.bssid:
                return False

            if event.bssid.lower() != self.bssid:
                return False

        return True
