from collections import Counter

from src.models.alert import Alert


class AlertStats:
    def __init__(self):
        self.total_alerts = 0
        self.attack_counter = Counter()
        self.severity_counter = Counter()

    def update(self, alert: Alert) -> None:
        self.total_alerts += 1
        self.attack_counter[alert.attack_type] += 1
        self.severity_counter[alert.severity] += 1

    def report(self) -> str:
        lines = []

        lines.append("")
        lines.append("=" * 80)
        lines.append("DETECTION SUMMARY")
        lines.append("-" * 80)
        lines.append(f"total alerts: {self.total_alerts}")
        lines.append("")

        lines.append("by attack type:")
        if self.attack_counter:
            for attack_type, count in self.attack_counter.most_common():
                lines.append(f"  {attack_type}: {count}")
        else:
            lines.append("  none")

        lines.append("")
        lines.append("by severity:")
        if self.severity_counter:
            for severity, count in self.severity_counter.most_common():
                lines.append(f"  {severity}: {count}")
        else:
            lines.append("  none")

        lines.append("=" * 80)

        return "\n".join(lines)
