"""
Modular Rule-Based Detection Engine and Rule Implementations for Mini-SIEM.

Each rule encapsulates its own detection logic, identifier, severity, risk score,
and structured evidence generator.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Union

from models import SecurityEvent, DetectionAlert
from rules_base import BaseRule
from event_processor import EventProcessor


# ─────────────────────────────────────────────────────────────────────────────
# 1. BRUTE_FORCE_001: Credential Brute Force Detection
# ─────────────────────────────────────────────────────────────────────────────
class BruteForceRule(BaseRule):
    rule_id = "BRUTE_FORCE_001"
    name = "Credential Brute Force Detection"
    description = "Detects multiple failed login attempts from the same source IP within a sliding time window."
    attack_type = "BRUTE_FORCE"
    severity = "HIGH"
    risk_score = 75

    def __init__(self, time_window_minutes: int = 5, max_attempts: int = 5, **kwargs):
        super().__init__(**kwargs)
        self.time_window_minutes = time_window_minutes
        self.max_attempts = max_attempts

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionAlert]:
        alerts = []
        ip_attempts = defaultdict(list)
        ip_users = defaultdict(set)

        for event in events:
            if event.event_type != "LOGIN" or not event.is_failure:
                continue

            ip = event.source_ip
            if not ip or ip == "unknown":
                continue

            timestamp = event.timestamp
            ip_attempts[ip].append((timestamp, event))
            if event.username and event.username != "unknown":
                ip_users[ip].add(event.username)

            window_start = timestamp - timedelta(minutes=self.time_window_minutes)
            ip_attempts[ip] = [entry for entry in ip_attempts[ip] if entry[0] >= window_start]

            if len(ip_attempts[ip]) >= self.max_attempts:
                matched_entries = list(ip_attempts[ip])
                evidence = {
                    "ip": ip,
                    "attempts_count": len(matched_entries),
                    "threshold": self.max_attempts,
                    "time_window_minutes": self.time_window_minutes,
                    "targeted_accounts": list(ip_users[ip]),
                    "first_attempt": matched_entries[0][0].isoformat(),
                    "last_attempt": matched_entries[-1][0].isoformat(),
                    "endpoint": event.endpoint,
                }

                alert = self.create_alert(
                    source=ip,
                    message=f"Brute force attack detected from IP {ip}. {len(matched_entries)} failed login attempts within {self.time_window_minutes} minutes.",
                    evidence=evidence,
                    event_count=len(matched_entries),
                    time_window_minutes=self.time_window_minutes,
                    target_accounts=ip_users[ip],
                    target_endpoints=[event.endpoint],
                )
                alerts.append(alert)
                # Clear to prevent duplicate consecutive triggers in the same burst
                ip_attempts[ip] = []
                ip_users[ip].clear()

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# 2. API_ABUSE_001: API Rate Limit & Flood Abuse
# ─────────────────────────────────────────────────────────────────────────────
class ApiAbuseRule(BaseRule):
    rule_id = "API_ABUSE_001"
    name = "API Rate Limit & Endpoint Abuse"
    description = "Detects rapid request flooding or repeated rate limit violations from a source IP."
    attack_type = "API_ABUSE"
    severity = "MEDIUM"
    risk_score = 60

    def __init__(self, time_window_minutes: int = 5, max_violations: int = 2, **kwargs):
        super().__init__(**kwargs)
        self.time_window_minutes = time_window_minutes
        self.max_violations = max_violations

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionAlert]:
        alerts = []
        ip_violations = defaultdict(list)
        ip_endpoints = defaultdict(set)

        for event in events:
            is_rate_limit = event.event_type in ("RATE_LIMIT_EXCEEDED", "LOGIN_RATE_LIMIT") or (
                event.is_blocked and "rate" in str(event.details).lower()
            )
            if not is_rate_limit:
                continue

            ip = event.source_ip
            if not ip or ip == "unknown":
                continue

            timestamp = event.timestamp
            ip_violations[ip].append((timestamp, event))
            ip_endpoints[ip].add(event.endpoint)

            window_start = timestamp - timedelta(minutes=self.time_window_minutes)
            ip_violations[ip] = [entry for entry in ip_violations[ip] if entry[0] >= window_start]

            if len(ip_violations[ip]) >= self.max_violations:
                matched_entries = list(ip_violations[ip])
                evidence = {
                    "ip": ip,
                    "violations_count": len(matched_entries),
                    "threshold": self.max_violations,
                    "time_window_minutes": self.time_window_minutes,
                    "targeted_endpoints": list(ip_endpoints[ip]),
                    "first_violation": matched_entries[0][0].isoformat(),
                    "last_violation": matched_entries[-1][0].isoformat(),
                }

                alert = self.create_alert(
                    source=ip,
                    message=f"API abuse / rate limit flooding detected from IP {ip}. {len(matched_entries)} violations within {self.time_window_minutes} minutes.",
                    evidence=evidence,
                    event_count=len(matched_entries),
                    time_window_minutes=self.time_window_minutes,
                    target_endpoints=ip_endpoints[ip],
                )
                alerts.append(alert)
                ip_violations[ip] = []
                ip_endpoints[ip].clear()

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# 3. INVALID_TOKEN_001: Invalid / Forged JWT Token Burst
# ─────────────────────────────────────────────────────────────────────────────
class InvalidTokenRule(BaseRule):
    rule_id = "INVALID_TOKEN_001"
    name = "Invalid / Forged JWT Token Spike"
    description = "Detects anomalous bursts of invalid, expired, or forged authentication tokens from a source IP."
    attack_type = "INVALID_TOKEN"
    severity = "HIGH"
    risk_score = 70

    def __init__(self, time_window_minutes: int = 5, max_attempts: int = 3, **kwargs):
        super().__init__(**kwargs)
        self.time_window_minutes = time_window_minutes
        self.max_attempts = max_attempts

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionAlert]:
        alerts = []
        ip_attempts = defaultdict(list)
        ip_endpoints = defaultdict(set)

        for event in events:
            if event.event_type != "TOKEN_INVALID":
                continue

            ip = event.source_ip
            if not ip or ip == "unknown":
                continue

            timestamp = event.timestamp
            ip_attempts[ip].append((timestamp, event))
            ip_endpoints[ip].add(event.endpoint)

            window_start = timestamp - timedelta(minutes=self.time_window_minutes)
            ip_attempts[ip] = [entry for entry in ip_attempts[ip] if entry[0] >= window_start]

            if len(ip_attempts[ip]) >= self.max_attempts:
                matched_entries = list(ip_attempts[ip])
                evidence = {
                    "ip": ip,
                    "invalid_token_attempts": len(matched_entries),
                    "threshold": self.max_attempts,
                    "time_window_minutes": self.time_window_minutes,
                    "targeted_endpoints": list(ip_endpoints[ip]),
                    "first_attempt": matched_entries[0][0].isoformat(),
                    "last_attempt": matched_entries[-1][0].isoformat(),
                }

                alert = self.create_alert(
                    source=ip,
                    message=f"Invalid authentication token spike detected from IP {ip}. {len(matched_entries)} invalid token attempts within {self.time_window_minutes} minutes.",
                    evidence=evidence,
                    event_count=len(matched_entries),
                    time_window_minutes=self.time_window_minutes,
                    target_endpoints=ip_endpoints[ip],
                )
                alerts.append(alert)
                ip_attempts[ip] = []
                ip_endpoints[ip].clear()

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# 4. PRIVILEGE_ESCALATION_001: Unauthorized Privilege / Role Escalation
# ─────────────────────────────────────────────────────────────────────────────
class PrivilegeEscalationRule(BaseRule):
    rule_id = "PRIVILEGE_ESCALATION_001"
    name = "Unauthorized Privilege Escalation Attempt"
    description = "Detects attempts to perform unauthorized role escalation or repeated access to restricted administrative endpoints."
    attack_type = "PRIVILEGE_ESCALATION"
    severity = "CRITICAL"
    risk_score = 95

    def __init__(self, time_window_minutes: int = 5, max_denials: int = 3, **kwargs):
        super().__init__(**kwargs)
        self.time_window_minutes = time_window_minutes
        self.max_denials = max_denials

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionAlert]:
        alerts = []
        ip_denials = defaultdict(list)

        for event in events:
            # Immediate critical alert for explicit role escalation attempt
            if event.event_type == "ROLE_ESCALATION_ATTEMPT":
                evidence = {
                    "ip": event.source_ip,
                    "username": event.username,
                    "endpoint": event.endpoint,
                    "timestamp": event.timestamp.isoformat(),
                    "details": event.details,
                }
                alerts.append(
                    self.create_alert(
                        source=event.source_ip if event.source_ip != "unknown" else event.username,
                        message=f"Critical role escalation attempt detected for account '{event.username}' from IP {event.source_ip}.",
                        evidence=evidence,
                        event_count=1,
                        time_window_minutes=1.0,
                        target_accounts=[event.username],
                        target_endpoints=[event.endpoint],
                        severity="CRITICAL",
                        additional_risk_boost=20,
                    )
                )
                continue

            # Check unauthorized access bursts (e.g. 403 denials)
            if event.event_type == "UNAUTHORIZED_ACCESS":
                ip = event.source_ip
                if not ip or ip == "unknown":
                    continue

                timestamp = event.timestamp
                ip_denials[ip].append((timestamp, event))

                window_start = timestamp - timedelta(minutes=self.time_window_minutes)
                ip_denials[ip] = [entry for entry in ip_denials[ip] if entry[0] >= window_start]

                if len(ip_denials[ip]) >= self.max_denials:
                    matched_entries = list(ip_denials[ip])
                    target_endpoints = list({e[1].endpoint for e in matched_entries})
                    target_accounts = list({e[1].username for e in matched_entries if e[1].username != "unknown"})
                    evidence = {
                        "ip": ip,
                        "unauthorized_access_count": len(matched_entries),
                        "threshold": self.max_denials,
                        "time_window_minutes": self.time_window_minutes,
                        "targeted_endpoints": target_endpoints,
                        "targeted_accounts": target_accounts,
                    }

                    alerts.append(
                        self.create_alert(
                            source=ip,
                            message=f"Privilege violation / access denied spike detected from IP {ip}. {len(matched_entries)} unauthorized requests within {self.time_window_minutes} minutes.",
                            evidence=evidence,
                            event_count=len(matched_entries),
                            time_window_minutes=self.time_window_minutes,
                            target_accounts=target_accounts,
                            target_endpoints=target_endpoints,
                            severity="HIGH",
                        )
                    )
                    ip_denials[ip] = []

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# 5. PASSWORD_SPRAY_001: Distributed Password Spraying
# ─────────────────────────────────────────────────────────────────────────────
class PasswordSprayingRule(BaseRule):
    rule_id = "PASSWORD_SPRAY_001"
    name = "Distributed Password Spraying Detection"
    description = "Detects coordinated distributed brute force attacks where multiple IPs fail logins against the same target account."
    attack_type = "PASSWORD_SPRAY"
    severity = "CRITICAL"
    risk_score = 90

    def __init__(self, time_window_minutes: int = 30, max_ips: int = 3, **kwargs):
        super().__init__(**kwargs)
        self.time_window_minutes = time_window_minutes
        self.max_ips = max_ips

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionAlert]:
        alerts = []
        account_attempts = defaultdict(lambda: defaultdict(list))

        for event in events:
            if event.event_type != "LOGIN" or not event.is_failure:
                continue

            username = event.username
            ip = event.source_ip
            if not username or username == "unknown" or not ip or ip == "unknown":
                continue

            timestamp = event.timestamp
            account_attempts[username][ip].append(timestamp)
            window_start = timestamp - timedelta(minutes=self.time_window_minutes)

            # Prune old timestamps
            for k_ip in list(account_attempts[username].keys()):
                account_attempts[username][k_ip] = [t for t in account_attempts[username][k_ip] if t >= window_start]
                if not account_attempts[username][k_ip]:
                    del account_attempts[username][k_ip]

            unique_ips = list(account_attempts[username].keys())
            if len(unique_ips) >= self.max_ips:
                evidence = {
                    "username": username,
                    "target_account": username,
                    "unique_ips_count": len(unique_ips),
                    "threshold_ips": self.max_ips,
                    "ips": unique_ips,
                    "time_window_minutes": self.time_window_minutes,
                }

                alert = self.create_alert(
                    source="MULTIPLE_IPS",
                    message=f"Distributed password spraying detected targeting account '{username}'. {len(unique_ips)} different IPs attempted access within {self.time_window_minutes} minutes.",
                    evidence=evidence,
                    event_count=len(unique_ips),
                    time_window_minutes=self.time_window_minutes,
                    target_accounts=[username],
                    severity="CRITICAL",
                )
                alerts.append(alert)
                account_attempts[username].clear()

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# 6. RAPID_REG_001: Rapid Account Registration Spike
# ─────────────────────────────────────────────────────────────────────────────
class RapidRegistrationRule(BaseRule):
    rule_id = "RAPID_REG_001"
    name = "Rapid Account Registration Spike"
    description = "Detects automated account creation bursts from a single source IP address."
    attack_type = "RAPID_REGISTRATION"
    severity = "MEDIUM"
    risk_score = 50

    def __init__(self, time_window_minutes: int = 10, max_registrations: int = 3, **kwargs):
        super().__init__(**kwargs)
        self.time_window_minutes = time_window_minutes
        self.max_registrations = max_registrations

    def evaluate(self, events: List[SecurityEvent]) -> List[DetectionAlert]:
        alerts = []
        ip_registrations = defaultdict(list)
        ip_usernames = defaultdict(list)

        for event in events:
            if event.event_type != "REGISTER":
                continue

            ip = event.source_ip
            if not ip or ip == "unknown":
                continue

            timestamp = event.timestamp
            ip_registrations[ip].append(timestamp)
            if event.username and event.username != "unknown":
                ip_usernames[ip].append(event.username)

            window_start = timestamp - timedelta(minutes=self.time_window_minutes)
            ip_registrations[ip] = [t for t in ip_registrations[ip] if t >= window_start]

            if len(ip_registrations[ip]) >= self.max_registrations:
                evidence = {
                    "ip": ip,
                    "registrations_count": len(ip_registrations[ip]),
                    "threshold": self.max_registrations,
                    "time_window_minutes": self.time_window_minutes,
                    "registered_accounts": list(ip_usernames[ip]),
                }

                alert = self.create_alert(
                    source=ip,
                    message=f"Rapid account registrations detected from IP {ip}. {len(ip_registrations[ip])} accounts created within {self.time_window_minutes} minutes.",
                    evidence=evidence,
                    event_count=len(ip_registrations[ip]),
                    time_window_minutes=self.time_window_minutes,
                    target_accounts=ip_usernames[ip],
                    severity="MEDIUM",
                )
                alerts.append(alert)
                ip_registrations[ip] = []
                ip_usernames[ip].clear()

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# 7. Rule Engine Registry & Coordinator
# ─────────────────────────────────────────────────────────────────────────────
class RuleEngine:
    """
    Central Coordinator for discovering, configuring, and executing detection rules.
    """

    def __init__(self, auto_register: bool = True):
        self.rules: Dict[str, BaseRule] = {}
        if auto_register:
            self.register_default_rules()

    def register_default_rules(self):
        """Registers all standard built-in rules."""
        self.register_rule(BruteForceRule())
        self.register_rule(ApiAbuseRule())
        self.register_rule(InvalidTokenRule())
        self.register_rule(PrivilegeEscalationRule())
        self.register_rule(PasswordSprayingRule())
        self.register_rule(RapidRegistrationRule())

    def register_rule(self, rule: BaseRule):
        """Registers a rule instance into the engine."""
        self.rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Retrieves a rule by its ID."""
        return self.rules.get(rule_id)

    def enable_rule(self, rule_id: str) -> bool:
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False

    def list_rules(self) -> List[Dict[str, Any]]:
        """Returns metadata for all registered rules."""
        return [rule.to_dict() for rule in self.rules.values()]

    def evaluate_all(self, events: List[SecurityEvent]) -> List[DetectionAlert]:
        """
        Executes all active rules against the given list of security events.
        """
        if not events:
            return []

        all_alerts: List[DetectionAlert] = []
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            try:
                rule_alerts = rule.evaluate(events)
                if rule_alerts:
                    all_alerts.extend(rule_alerts)
            except Exception as e:
                print(f"[RULE ENGINE ERROR] Error evaluating rule {rule.rule_id} ({rule.name}): {e}")

        return all_alerts


# ─────────────────────────────────────────────────────────────────────────────
# Legacy function compatibility wrappers
# ─────────────────────────────────────────────────────────────────────────────
def detect_brute_force(logs, time_window_minutes=5, max_attempts=5):
    events = [log if isinstance(log, SecurityEvent) else EventProcessor.normalize(log) for log in logs]
    rule = BruteForceRule(time_window_minutes=time_window_minutes, max_attempts=max_attempts)
    return [alert.to_dict() for alert in rule.evaluate(events)]

def detect_rapid_registration(logs, time_window_minutes=10, max_registrations=3):
    events = [log if isinstance(log, SecurityEvent) else EventProcessor.normalize(log) for log in logs]
    rule = RapidRegistrationRule(time_window_minutes=time_window_minutes, max_registrations=max_registrations)
    return [alert.to_dict() for alert in rule.evaluate(events)]

def detect_password_spraying(logs, time_window_minutes=30, max_ips=3):
    events = [log if isinstance(log, SecurityEvent) else EventProcessor.normalize(log) for log in logs]
    rule = PasswordSprayingRule(time_window_minutes=time_window_minutes, max_ips=max_ips)
    return [alert.to_dict() for alert in rule.evaluate(events)]
