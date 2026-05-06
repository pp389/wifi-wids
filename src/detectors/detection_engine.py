from src.models.alert import Alert
from src.models.frame_event import FrameEvent


class DetectionEngine:
    def __init__(self, detectors):
        self.detectors = detectors
        self.alert_counter = 0

    def process(self, event: FrameEvent) -> list[Alert]:
        alerts = []

        for detector in self.detectors:
            detector_alerts = detector.process(event)

            for alert in detector_alerts:
                self.alert_counter += 1
                alert.alert_id = f"ALERT-{self.alert_counter:06d}"
                alerts.append(alert)

        return alerts
