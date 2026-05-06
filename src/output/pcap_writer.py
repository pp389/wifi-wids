from pathlib import Path
from scapy.all import PcapWriter


class PcapFileWriter:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        self.writer = PcapWriter(
            str(self.file_path),
            append=False,
            sync=True,
        )

    def write(self, packet) -> None:
        self.writer.write(packet)

    def close(self) -> None:
        self.writer.close()
