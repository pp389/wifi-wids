from abc import ABC, abstractmethod
from src.models.frame_event import FrameEvent
from src.models.alert import Alert


class BaseDetector(ABC):
    @abstractmethod
    def process(self, event: FrameEvent) -> list[Alert]:
        pass
