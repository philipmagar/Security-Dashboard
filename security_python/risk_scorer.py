"""
Dynamic Multi-Factor Risk-Scoring Engine and Actionable Response Playbooks.

Calculates contextual risk scores (0-100) based on:
1. Base Severity Weight
2. Event Volume / Count
3. Frequency / Velocity (Events per minute)
4. Target Account Criticality (e.g., admin, root, executive)
5. Target Endpoint / Resource Criticality (e.g., /api/admin/*)
"""
from typing import List, Dict, Any, Optional, Set, Union


class RiskScorer:
    """
    Evaluates context, frequency, volume, and target sensitivity
    to produce a standardized dynamic risk score (0-100) and actionable mitigation steps.
    """

    # Base severity score weights
    SEVERITY_WEIGHTS = {
        "CRITICAL": 50,
        "HIGH": 35,
        "MEDIUM": 20,
        "LOW": 10,
        "INFO": 5,
    }

    # Sensitive account keywords
    SENSITIVE_ACCOUNTS = {"admin", "root", "administrator", "exec", "ceo", "cfo", "manager", "security"}

    # Sensitive endpoint prefixes
    SENSITIVE_ENDPOINTS = ("/api/admin", "/api/security", "/api/auth", "/admin")

    @classmethod
    def calculate_risk_score(
        cls,
        base_severity: str = "MEDIUM",
        event_count: int = 1,
        time_window_minutes: float = 5.0,
        target_accounts: Optional[Union[List[str], Set[str]]] = None,
        target_endpoints: Optional[Union[List[str], Set[str]]] = None,
        additional_boost: int = 0,
    ) -> int:
        """
        Calculates a dynamic risk score between 1 and 100.
        """
        # 1. Base Severity Weight (up to 50 pts)
        sev_key = str(base_severity).upper().strip()
        base_score = cls.SEVERITY_WEIGHTS.get(sev_key, 20)

        # 2. Volume Factor (up to 20 pts)
        volume_score = min(20, int(event_count * 2.0))

        # 3. Frequency / Velocity Factor (up to 15 pts)
        window = max(0.5, float(time_window_minutes))
        frequency = event_count / window  # events per minute
        if frequency >= 5.0:
            freq_score = 15
        elif frequency >= 2.0:
            freq_score = 10
        elif frequency >= 1.0:
            freq_score = 5
        else:
            freq_score = 2

        # 4. Account Criticality Factor (up to 15 pts)
        account_score = 0
        if target_accounts:
            for acc in target_accounts:
                acc_lower = str(acc).lower()
                if any(kw in acc_lower for kw in cls.SENSITIVE_ACCOUNTS):
                    account_score = 15
                    break

        # 5. Endpoint Criticality Factor (up to 10 pts)
        endpoint_score = 0
        if target_endpoints:
            for ep in target_endpoints:
                ep_lower = str(ep).lower()
                if any(ep_lower.startswith(prefix) for prefix in cls.SENSITIVE_ENDPOINTS):
                    endpoint_score = 10
                    break

        # Compute total raw score and clamp to [1, 100]
        raw_score = base_score + volume_score + freq_score + account_score + endpoint_score + additional_boost
        final_score = max(1, min(100, raw_score))
        return final_score

    @staticmethod
    def get_risk_level(risk_score: int) -> str:
        """Categorizes numeric risk score into standard risk tier."""
        if risk_score >= 90:
            return "CRITICAL"
        elif risk_score >= 70:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        return "LOW"

    @classmethod
    def generate_recommended_response(
        cls,
        attack_type: str,
        risk_score: int,
        source: str = "unknown",
        target_account: Optional[str] = None,
        target_endpoint: Optional[str] = None,
    ) -> str:
        """
        Generates structured, actionable mitigation playbooks based on attack type and risk score.
        """
        atk = str(attack_type).upper().strip()
        account_str = f" for account '{target_account}'" if target_account and target_account != "unknown" else ""
        source_str = f" from IP {source}" if source and source != "unknown" and source != "MULTIPLE_IPS" else ""

        if "BRUTE_FORCE" in atk:
            if risk_score >= 80:
                return (
                    f"1. Immediately apply temporary firewall/WAF IP block{source_str} for 60 minutes.\n"
                    f"2. Trigger account lockout and force password reset{account_str}.\n"
                    f"3. Enforce Multi-Factor Authentication (MFA) and verify whether any credential attempts succeeded."
                )
            return (
                f"1. Rate-limit authentication requests{source_str}.\n"
                f"2. Enable CAPTCHA challenge on the login endpoint.\n"
                f"3. Monitor targeted account{account_str} for consecutive failures."
            )

        if "PRIVILEGE_ESCALATION" in atk:
            return (
                f"1. CRITICAL: Immediately revoke and invalidate all active session tokens for the actor{source_str}.\n"
                f"2. Lock user account{account_str} and audit recent administrative role modifications.\n"
                f"3. Inspect server access logs for unauthorized configuration changes or sensitive data access."
            )

        if "PASSWORD_SPRAY" in atk:
            return (
                f"1. Block identified distributed proxy/VPN source IP addresses on perimeter firewall.\n"
                f"2. Force global password reset{account_str} and require MFA verification.\n"
                f"3. Check for successful logins originating from unusual geolocations around the same timeframe."
            )

        if "API_ABUSE" in atk or "RATE_LIMIT" in atk:
            return (
                f"1. Enforce automated WAF IP throttling{source_str} on endpoint '{target_endpoint or '/api'}'.\n"
                f"2. Inspect incoming User-Agent and payload signatures for automated scraping or fuzzing bots.\n"
                f"3. If abuse persists, ban the offending subnet for 24 hours."
            )

        if "INVALID_TOKEN" in atk:
            return (
                f"1. Reject and blacklist unauthorized session tokens{source_str}.\n"
                f"2. Inspect token payload for cryptographic tampering or forged claim attempts.\n"
                f"3. If token forgery pattern is verified, consider immediate JWT secret/key rotation."
            )

        if "RAPID_REGISTRATION" in atk:
            return (
                f"1. Enable Cloudflare/reCAPTCHA on the registration endpoint.\n"
                f"2. Limit max account creations to 2 per IP per hour.\n"
                f"3. Place newly registered accounts in quarantine pending email verification."
            )

        # Default generic response
        return (
            f"1. Review and monitor activity{source_str}.\n"
            f"2. Verify security logs and apply rate limiting if anomalous traffic continues."
        )
