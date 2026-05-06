from src.models.alert import Alert
from src.models.frame_event import FrameEvent


class DetectionEngine:
    def __init__(self, detectors):
        self.detectors = detectors

    def process(self, event: FrameEvent) -> list[Alert]:
        alerts = []

        for detector in self.detectors:
            alerts.extend(detector.process(event))

        return alerts
