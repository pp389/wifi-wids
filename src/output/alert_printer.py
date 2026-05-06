from datetime import datetime

from src.models.alert import Alert


class AlertPrinter:
    def print_alert(self, alert: Alert) -> None:
        readable_time = datetime.fromtimestamp(alert.timestamp).isoformat()

        print()
        print("!" * 80)
        print(f"[ALERT] {alert.alert_id or 'UNKNOWN'} | {alert.attack_type}")
        print(f"severity: {alert.severity}")
        print(f"time: {readable_time}")
        print(f"message: {alert.message}")
        print(f"evidence: {alert.evidence}")
        print("!" * 80)
        print()
