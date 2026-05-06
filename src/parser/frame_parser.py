from scapy.all import Dot11, Dot11Elt, RadioTap

from src.models.frame_event import FrameEvent


class FrameParser:
    def parse(self, packet) -> FrameEvent | None:
        if not packet.haslayer(Dot11):
            return None

        dot11 = packet[Dot11]

        frame_type = self._get_frame_type(dot11.type)
        frame_subtype = self._get_frame_subtype(dot11.type, dot11.subtype)

        ssid = self._extract_ssid(packet)
        rssi = self._extract_rssi(packet)
        frequency, channel = self._extract_channel(packet)

        return FrameEvent(
            timestamp=float(packet.time),

            frame_type=frame_type,
            frame_subtype=frame_subtype,

            source_mac=dot11.addr2,
            destination_mac=dot11.addr1,
            bssid=dot11.addr3,

            receiver_mac=dot11.addr1,
            transmitter_mac=dot11.addr2,

            ssid=ssid,
            rssi=rssi,
            channel=channel,
            frequency=frequency,

            is_protected=self._is_protected(dot11),
            retry=self._is_retry(dot11),

            raw_summary=packet.summary(),
        )

    def _get_frame_type(self, type_id: int) -> str:
        mapping = {
            0: "management",
            1: "control",
            2: "data",
            3: "extension",
        }
        return mapping.get(type_id, "unknown")

    def _get_frame_subtype(self, type_id: int, subtype_id: int) -> str:
        if type_id == 0:
            return self._get_management_subtype(subtype_id)

        if type_id == 1:
            return self._get_control_subtype(subtype_id)

        if type_id == 2:
            return self._get_data_subtype(subtype_id)

        if type_id == 3:
            return self._get_extension_subtype(subtype_id)

        return "unknown"

    def _get_management_subtype(self, subtype_id: int) -> str:
        mapping = {
            0: "association_request",
            1: "association_response",
            2: "reassociation_request",
            3: "reassociation_response",
            4: "probe_request",
            5: "probe_response",
            6: "timing_advertisement",
            7: "reserved",
            8: "beacon",
            9: "atim",
            10: "disassociation",
            11: "authentication",
            12: "deauthentication",
            13: "action",
            14: "action_no_ack",
        }
        return mapping.get(subtype_id, "unknown_management")

    def _get_control_subtype(self, subtype_id: int) -> str:
        mapping = {
            7: "control_wrapper",
            8: "block_ack_request",
            9: "block_ack",
            10: "ps_poll",
            11: "rts",
            12: "cts",
            13: "ack",
            14: "cf_end",
            15: "cf_end_cf_ack",
        }
        return mapping.get(subtype_id, "unknown_control")

    def _get_data_subtype(self, subtype_id: int) -> str:
        mapping = {
            0: "data",
            1: "data_cf_ack",
            2: "data_cf_poll",
            3: "data_cf_ack_cf_poll",
            4: "null_data",
            5: "cf_ack",
            6: "cf_poll",
            7: "cf_ack_cf_poll",
            8: "qos_data",
            9: "qos_data_cf_ack",
            10: "qos_data_cf_poll",
            11: "qos_data_cf_ack_cf_poll",
            12: "qos_null",
            13: "reserved",
            14: "qos_cf_poll",
            15: "qos_cf_ack_cf_poll",
        }
        return mapping.get(subtype_id, "unknown_data")

    def _get_extension_subtype(self, subtype_id: int) -> str:
        mapping = {
            0: "dmG_beacon",
            1: "s1g_beacon",
        }
        return mapping.get(subtype_id, "unknown_extension")

    def _extract_ssid(self, packet) -> str | None:
        if not packet.haslayer(Dot11Elt):
            return None

        elt = packet[Dot11Elt]

        while isinstance(elt, Dot11Elt):
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode("utf-8", errors="ignore")
                    return ssid if ssid else "<hidden>"
                except Exception:
                    return "<decode_error>"

            elt = elt.payload

        return None

    def _extract_rssi(self, packet) -> int | None:
        if not packet.haslayer(RadioTap):
            return None

        return getattr(packet[RadioTap], "dBm_AntSignal", None)

    def _extract_channel(self, packet) -> tuple[int | None, int | None]:
        if not packet.haslayer(RadioTap):
            return None, None

        radiotap = packet[RadioTap]
        frequency = getattr(radiotap, "ChannelFrequency", None)

        if frequency is None:
            return None, None

        channel = self._frequency_to_channel(frequency)

        return frequency, channel

    def _frequency_to_channel(self, frequency: int) -> int | None:
        if frequency == 2484:
            return 14

        if 2412 <= frequency <= 2472:
            return int((frequency - 2407) / 5)

        if 5000 <= frequency <= 5900:
            return int((frequency - 5000) / 5)

        return None

    def _is_protected(self, dot11: Dot11) -> bool:
        return bool(dot11.FCfield & 0x40)

    def _is_retry(self, dot11: Dot11) -> bool:
        return bool(dot11.FCfield & 0x08)

