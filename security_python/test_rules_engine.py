"""
Unit and Integration Test Suite for Rule-Based Detection Engine.
Tests individual security rules, rule metadata, evidence generation, risk scores, and RuleEngine.
"""
import unittest
from datetime import datetime, timezone, timedelta

from models import SecurityEvent, DetectionAlert
from rules_base import BaseRule
from rules import (
    BruteForceRule,
    ApiAbuseRule,
    InvalidTokenRule,
    PrivilegeEscalationRule,
    PasswordSprayingRule,
    RapidRegistrationRule,
    RuleEngine,
)


class TestRuleImplementations(unittest.TestCase):

    def setUp(self):
        self.now = datetime.now(timezone.utc)

    def test_brute_force_rule(self):
        """Test BRUTE_FORCE_001 rule logic, severity, risk score, and evidence."""
        rule = BruteForceRule(time_window_minutes=5, max_attempts=5)
        self.assertEqual(rule.rule_id, "BRUTE_FORCE_001")
        self.assertEqual(rule.severity, "HIGH")
        self.assertEqual(rule.risk_score, 75)

        events = [
            SecurityEvent(
                event_type="LOGIN",
                username="victim@siem.local",
                source_ip="192.168.1.100",
                timestamp=self.now - timedelta(seconds=30 * (5 - i)),
                endpoint="/api/auth/login",
                result="FAILURE",
            )
            for i in range(5)
        ]

        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertIsInstance(alert, DetectionAlert)
        self.assertEqual(alert.rule_id, "BRUTE_FORCE_001")
        self.assertEqual(alert.attack_type, "BRUTE_FORCE")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.risk_score, 75)
        self.assertEqual(alert.source, "192.168.1.100")
        self.assertEqual(alert.evidence["attempts_count"], 5)
        self.assertIn("victim@siem.local", alert.evidence["targeted_accounts"])

    def test_api_abuse_rule(self):
        """Test API_ABUSE_001 rate limit abuse detection."""
        rule = ApiAbuseRule(time_window_minutes=5, max_violations=2)
        self.assertEqual(rule.rule_id, "API_ABUSE_001")
        self.assertEqual(rule.severity, "MEDIUM")
        self.assertEqual(rule.risk_score, 60)

        events = [
            SecurityEvent(
                event_type="RATE_LIMIT_EXCEEDED",
                username="spammer@siem.local",
                source_ip="203.0.113.88",
                timestamp=self.now - timedelta(minutes=1),
                endpoint="/api/dashboard",
                result="BLOCKED",
            ),
            SecurityEvent(
                event_type="RATE_LIMIT_EXCEEDED",
                username="spammer@siem.local",
                source_ip="203.0.113.88",
                timestamp=self.now,
                endpoint="/api/security/logs",
                result="BLOCKED",
            ),
        ]

        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "API_ABUSE_001")
        self.assertEqual(alert.risk_score, 60)
        self.assertEqual(alert.source, "203.0.113.88")
        self.assertEqual(alert.evidence["violations_count"], 2)
        self.assertIn("/api/dashboard", alert.evidence["targeted_endpoints"])

    def test_invalid_token_rule(self):
        """Test INVALID_TOKEN_001 token tampering burst detection."""
        rule = InvalidTokenRule(time_window_minutes=5, max_attempts=3)
        self.assertEqual(rule.rule_id, "INVALID_TOKEN_001")
        self.assertEqual(rule.severity, "HIGH")
        self.assertEqual(rule.risk_score, 70)

        events = [
            SecurityEvent(
                event_type="TOKEN_INVALID",
                username="unknown",
                source_ip="198.51.100.42",
                timestamp=self.now - timedelta(seconds=20 * (3 - i)),
                endpoint="/api/admin/users",
                result="DENIED",
            )
            for i in range(3)
        ]

        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "INVALID_TOKEN_001")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.risk_score, 70)
        self.assertEqual(alert.source, "198.51.100.42")
        self.assertEqual(alert.evidence["invalid_token_attempts"], 3)

    def test_privilege_escalation_rule(self):
        """Test PRIVILEGE_ESCALATION_001 unauthorized role escalation."""
        rule = PrivilegeEscalationRule(time_window_minutes=5, max_denials=3)
        self.assertEqual(rule.rule_id, "PRIVILEGE_ESCALATION_001")
        self.assertEqual(rule.severity, "CRITICAL")
        self.assertEqual(rule.risk_score, 95)

        # 1. Immediate alert on ROLE_ESCALATION_ATTEMPT
        escalation_event = SecurityEvent(
            event_type="ROLE_ESCALATION_ATTEMPT",
            username="attacker@siem.local",
            source_ip="10.0.0.99",
            timestamp=self.now,
            endpoint="/api/admin/users",
            result="DENIED",
            details="Attempted to modify user role to admin",
        )
        alerts = rule.evaluate([escalation_event])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "PRIVILEGE_ESCALATION_001")
        self.assertEqual(alerts[0].severity, "CRITICAL")
        self.assertEqual(alerts[0].risk_score, 95)

        # 2. Burst alert on 403 UNAUTHORIZED_ACCESS
        unauthorized_events = [
            SecurityEvent(
                event_type="UNAUTHORIZED_ACCESS",
                username="user@siem.local",
                source_ip="10.0.0.5",
                timestamp=self.now - timedelta(minutes=i),
                endpoint="/api/admin/secrets",
                result="DENIED",
            )
            for i in range(3)
        ]
        denial_alerts = rule.evaluate(unauthorized_events)
        self.assertEqual(len(denial_alerts), 1)
        self.assertEqual(denial_alerts[0].rule_id, "PRIVILEGE_ESCALATION_001")
        self.assertEqual(denial_alerts[0].evidence["unauthorized_access_count"], 3)

    def test_password_spraying_rule(self):
        """Test PASSWORD_SPRAY_001 distributed password spraying detection."""
        rule = PasswordSprayingRule(time_window_minutes=30, max_ips=3)
        self.assertEqual(rule.rule_id, "PASSWORD_SPRAY_001")
        self.assertEqual(rule.severity, "CRITICAL")
        self.assertEqual(rule.risk_score, 90)

        events = [
            SecurityEvent(
                event_type="LOGIN",
                username="ceo@siem.local",
                source_ip=f"198.51.100.{20 + i}",
                timestamp=self.now - timedelta(minutes=2 * i),
                endpoint="/api/auth/login",
                result="FAILURE",
            )
            for i in range(3)
        ]

        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "PASSWORD_SPRAY_001")
        self.assertEqual(alert.attack_type, "PASSWORD_SPRAY")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.risk_score, 90)
        self.assertEqual(alert.source, "MULTIPLE_IPS")
        self.assertEqual(alert.evidence["unique_ips_count"], 3)
        self.assertEqual(alert.evidence["target_account"], "ceo@siem.local")

    def test_rapid_registration_rule(self):
        """Test RAPID_REG_001 bot registration bursts."""
        rule = RapidRegistrationRule(time_window_minutes=10, max_registrations=3)
        self.assertEqual(rule.rule_id, "RAPID_REG_001")
        self.assertEqual(rule.severity, "MEDIUM")
        self.assertEqual(rule.risk_score, 50)

        events = [
            SecurityEvent(
                event_type="REGISTER",
                username=f"bot_user_{i}@botnet.org",
                source_ip="192.0.2.1",
                timestamp=self.now - timedelta(minutes=i),
                endpoint="/api/auth/register",
                result="SUCCESS",
            )
            for i in range(3)
        ]

        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "RAPID_REG_001")
        self.assertEqual(alert.risk_score, 50)
        self.assertEqual(alert.evidence["registrations_count"], 3)


class TestRuleEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine()
        self.now = datetime.now(timezone.utc)

    def test_rule_registration_and_listing(self):
        """Test that default rules are registered and listable."""
        rules = self.engine.list_rules()
        self.assertGreaterEqual(len(rules), 6)
        rule_ids = [r["rule_id"] for r in rules]
        self.assertIn("BRUTE_FORCE_001", rule_ids)
        self.assertIn("API_ABUSE_001", rule_ids)
        self.assertIn("INVALID_TOKEN_001", rule_ids)
        self.assertIn("PRIVILEGE_ESCALATION_001", rule_ids)
        self.assertIn("PASSWORD_SPRAY_001", rule_ids)
        self.assertIn("RAPID_REG_001", rule_ids)

    def test_enable_and_disable_rule(self):
        """Test dynamically disabling and enabling rules."""
        self.assertTrue(self.engine.disable_rule("BRUTE_FORCE_001"))
        self.assertFalse(self.engine.get_rule("BRUTE_FORCE_001").enabled)

        events = [
            SecurityEvent(
                event_type="LOGIN",
                username="user@siem.local",
                source_ip="1.2.3.4",
                timestamp=self.now - timedelta(seconds=10 * (5 - i)),
                endpoint="/api/auth/login",
                result="FAILURE",
            )
            for i in range(5)
        ]

        # Since BRUTE_FORCE_001 is disabled, evaluate_all should produce no alerts
        alerts = self.engine.evaluate_all(events)
        self.assertEqual(len(alerts), 0)

        # Re-enable rule
        self.assertTrue(self.engine.enable_rule("BRUTE_FORCE_001"))
        alerts_reenabled = self.engine.evaluate_all(events)
        self.assertEqual(len(alerts_reenabled), 1)
        self.assertEqual(alerts_reenabled[0].rule_id, "BRUTE_FORCE_001")


if __name__ == "__main__":
    unittest.main()
