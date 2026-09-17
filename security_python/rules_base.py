"""
Base architecture and abstract class for rule-based detection engine.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from models import SecurityEvent, DetectionAlert


class BaseRule(ABC):
    """
    Abstract Base Class for all detection rules in the Mini-SIEM detection engine.
    Every security rule inherits from this class and encapsulates its own detection logic,
    identifier, severity, risk score, and evidence structure.
    """

    rule_id: str = "RULE_BASE_000"
    name: str = "Base Security Rule"
    description: str = "Abstract base rule description"
    attack_type: str = "GENERIC_ATTACK"
    severity: str = "MEDIUM"
    risk_score: int = 50
    enabled: bool = True

    def __init__(self, enabled: bool = True, **kwargs):
        self.enabled = enabled
        for key, value in kwargs.items():
            setattr(self, key, value)

    @abstractmethod
    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionAlert]:
        """
        Analyzes a stream/batch of normalized SecurityEvents and generates
        DetectionAlert instances when detection conditions are satisfied.
        """
        raise NotImplementedError("Subclasses must implement the evaluate method.")

    def create_alert(
        self,
        source: str,
        message: str,
        evidence: Dict[str, Any],
        severity: Optional[str] = None,
        risk_score: Optional[int] = None,
        attack_type: Optional[str] = None,
    ) -> DetectionAlert:
        """
        Helper method to construct a standard DetectionAlert for this rule.
        """
        return DetectionAlert(
            rule_id=self.rule_id,
            attack_type=attack_type or self.attack_type,
            severity=severity or self.severity,
            risk_score=risk_score if risk_score is not None else self.risk_score,
            source=source,
            message=message,
            evidence=evidence,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Returns rule metadata dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "enabled": self.enabled,
        }
