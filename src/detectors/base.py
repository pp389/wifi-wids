from abc import ABC, abstractmethod

from src.models.alert import Alert
from src.models.frame_event import FrameEvent


class BaseDetector(ABC):
    @abstractmethod
    def process(self, event: FrameEvent) -> list[Alert]:
        pass
