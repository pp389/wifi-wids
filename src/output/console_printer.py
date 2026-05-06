from src.models.frame_event import FrameEvent


class ConsolePrinter:
    def print_event(self, event: FrameEvent) -> None:
        prefix = self._get_prefix(event)

        parts = [
            f"{prefix}",
            f"type={event.frame_type}",
            f"subtype={event.frame_subtype}",
        ]

        if event.source_mac:
            parts.append(f"src={event.source_mac}")

        if event.destination_mac:
            parts.append(f"dst={event.destination_mac}")

        if event.bssid:
            parts.append(f"bssid={event.bssid}")

        if event.ssid:
            parts.append(f"ssid={event.ssid}")

        if event.channel:
            parts.append(f"ch={event.channel}")

        if event.rssi:
            parts.append(f"rssi={event.rssi}dBm")

        if event.is_protected is not None:
            parts.append(f"protected={event.is_protected}")

        if event.retry is not None:
            parts.append(f"retry={event.retry}")

        print(" | ".join(parts))

    def _get_prefix(self, event: FrameEvent) -> str:
        if event.frame_type == "management":
            return "[MGMT]"

        if event.frame_type == "control":
            return "[CTRL]"

        if event.frame_type == "data":
            return "[DATA]"

        if event.frame_type == "extension":
            return "[EXT]"

        return "[UNKNOWN]"

