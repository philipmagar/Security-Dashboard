"""
Base architecture and abstract class for rule-based detection engine.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set, Union
from models import SecurityEvent, DetectionAlert
from alert_generator import AlertGenerator


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
        event_count: int = 1,
        time_window_minutes: float = 5.0,
        target_accounts: Optional[Union[List[str], Set[str]]] = None,
        target_endpoints: Optional[Union[List[str], Set[str]]] = None,
        severity: Optional[str] = None,
        risk_score: Optional[int] = None,
        attack_type: Optional[str] = None,
        recommended_response: Optional[str] = None,
        additional_risk_boost: int = 0,
    ) -> DetectionAlert:
        """
        Constructs a standard DetectionAlert for this rule, applying multi-factor
        risk scoring and response playbook generation.
        """
        if risk_score is not None:
            # Explicit static override if provided
            return DetectionAlert(
                rule_id=self.rule_id,
                attack_type=attack_type or self.attack_type,
                severity=severity or self.severity,
                risk_score=risk_score,
                source=source,
                message=message,
                evidence=evidence,
                recommended_response=recommended_response or "",
            )

        return AlertGenerator.generate_alert(
            rule_id=self.rule_id,
            attack_type=attack_type or self.attack_type,
            base_severity=severity or self.severity,
            source=source,
            message=message,
            evidence=evidence,
            event_count=event_count,
            time_window_minutes=time_window_minutes,
            target_accounts=target_accounts,
            target_endpoints=target_endpoints,
            custom_response=recommended_response,
            additional_risk_boost=additional_risk_boost,
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
