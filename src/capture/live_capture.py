from scapy.all import sniff


class LiveCapture:
    def __init__(self, interface: str):
        self.interface = interface

    def start(self, packet_handler):
        sniff(
            iface=self.interface,
            prn=packet_handler,
            store=False,
        )
