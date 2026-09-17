"""
Alert Generation Layer for Mini-SIEM.

Combines detection matches, multi-factor risk assessment, evidence compilation,
and actionable recommended responses into structured DetectionAlert instances.
"""
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Union

from models import DetectionAlert
from risk_scorer import RiskScorer


class AlertGenerator:
    """
    Standardizes the construction of security alerts enriched with
    dynamic risk scores, evidence dictionaries, and recommended response playbooks.
    """

    @classmethod
    def generate_alert(
        cls,
        rule_id: str,
        attack_type: str,
        base_severity: str,
        source: str,
        message: str,
        evidence: Dict[str, Any],
        event_count: int = 1,
        time_window_minutes: float = 5.0,
        target_accounts: Optional[Union[List[str], Set[str]]] = None,
        target_endpoints: Optional[Union[List[str], Set[str]]] = None,
        custom_response: Optional[str] = None,
        additional_risk_boost: int = 0,
    ) -> DetectionAlert:
        """
        Creates a structured DetectionAlert with dynamic risk score and response playbook.
        """
        # Calculate dynamic risk score based on volume, frequency, base severity & target sensitivity
        dynamic_risk_score = RiskScorer.calculate_risk_score(
            base_severity=base_severity,
            event_count=event_count,
            time_window_minutes=time_window_minutes,
            target_accounts=target_accounts,
            target_endpoints=target_endpoints,
            additional_boost=additional_risk_boost,
        )

        # Dynamic severity alignment based on calculated risk score
        evaluated_severity = RiskScorer.get_risk_level(dynamic_risk_score)

        # Determine target account & endpoint for response customization
        first_account = None
        if target_accounts:
            first_account = next(iter(target_accounts), None)
        elif "username" in evidence:
            first_account = evidence["username"]
        elif "target_account" in evidence:
            first_account = evidence["target_account"]

        first_endpoint = None
        if target_endpoints:
            first_endpoint = next(iter(target_endpoints), None)
        elif "endpoint" in evidence:
            first_endpoint = evidence["endpoint"]

        # Generate recommended mitigation steps
        recommended_response = custom_response or RiskScorer.generate_recommended_response(
            attack_type=attack_type,
            risk_score=dynamic_risk_score,
            source=source,
            target_account=first_account,
            target_endpoint=first_endpoint,
        )

        # Attach computed risk metrics to evidence for transparency
        enriched_evidence = dict(evidence)
        enriched_evidence["calculated_risk_score"] = dynamic_risk_score
        enriched_evidence["risk_level"] = evaluated_severity
        enriched_evidence["evaluation_timestamp"] = datetime.now(timezone.utc).isoformat()

        return DetectionAlert(
            rule_id=rule_id,
            attack_type=attack_type,
            severity=evaluated_severity,
            risk_score=dynamic_risk_score,
            source=source,
            message=message,
            evidence=enriched_evidence,
            recommended_response=recommended_response,
            timestamp=datetime.now(timezone.utc),
        )
