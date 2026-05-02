from dataclasses import dataclass


@dataclass
class Alert:
    timestamp: float
    attack_type: str
    severity: str
    message: str
    evidence: dict
