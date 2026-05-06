import json
from datetime import datetime
from pathlib import Path

from src.models.alert import Alert


class AlertJsonWriter:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        self.file = open(self.file_path, mode="w", encoding="utf-8")

    def write(self, alert: Alert) -> None:
        record = {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp,
            "timestamp_iso": datetime.fromtimestamp(alert.timestamp).isoformat(),
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "message": alert.message,
            "evidence": alert.evidence,
        }

        self.file.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.file.flush()

    def close(self) -> None:
        self.file.close()
