from scapy.all import Dot11, Dot11Deauth, RadioTap
from src.models.frame_event import FrameEvent


class FrameParser:
    def parse(self, packet) -> FrameEvent | None:
        if not packet.haslayer(Dot11):
            return None

        dot11 = packet[Dot11]

        frame_type = self._get_frame_type(dot11.type)
        frame_subtype = self._get_frame_subtype(dot11.type, dot11.subtype)

        rssi = None
        if packet.haslayer(RadioTap):
            rssi = getattr(packet[RadioTap], "dBm_AntSignal", None)

        return FrameEvent(
            timestamp=float(packet.time),
            frame_type=frame_type,
            frame_subtype=frame_subtype,
            source_mac=dot11.addr2,
            destination_mac=dot11.addr1,
            bssid=dot11.addr3,
            rssi=rssi,
        )

    def _get_frame_type(self, type_id: int) -> str:
        mapping = {
            0: "management",
            1: "control",
            2: "data",
        }
        return mapping.get(type_id, "unknown")

    def _get_frame_subtype(self, type_id: int, subtype_id: int) -> str:
        if type_id == 0:
            management_subtypes = {
                0: "association_request",
                1: "association_response",
                2: "reassociation_request",
                3: "reassociation_response",
                4: "probe_request",
                5: "probe_response",
                8: "beacon",
                10: "disassociation",
                11: "authentication",
                12: "deauthentication",
                13: "action",
            }
            return management_subtypes.get(subtype_id, "unknown_management")

        if type_id == 1:
            control_subtypes = {
                11: "rts",
                12: "cts",
                13: "ack",
            }
            return control_subtypes.get(subtype_id, "unknown_control")

        if type_id == 2:
            return "data"

        return "unknown"
