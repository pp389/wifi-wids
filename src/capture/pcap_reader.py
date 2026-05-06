from scapy.all import PcapReader


class PcapFileReader:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def start(self, packet_handler):
        with PcapReader(self.file_path) as packets:
            for packet in packets:
                packet_handler(packet)
