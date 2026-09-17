"""
Unit and Integration Tests for Dynamic Risk Scoring and Recommended Response Layer.
"""
import unittest
from datetime import datetime, timezone, timedelta

from models import SecurityEvent, DetectionAlert
from risk_scorer import RiskScorer
from alert_generator import AlertGenerator
from rules import BruteForceRule, PrivilegeEscalationRule, PasswordSprayingRule


class TestRiskScorer(unittest.TestCase):

    def test_base_severity_weights(self):
        """Test base severity impact on initial score."""
        crit_score = RiskScorer.calculate_risk_score(base_severity="CRITICAL", event_count=1, time_window_minutes=10)
        low_score = RiskScorer.calculate_risk_score(base_severity="LOW", event_count=1, time_window_minutes=10)
        self.assertGreater(crit_score, low_score)

    def test_volume_and_frequency_factors(self):
        """Test that higher volume and rapid velocity increase the risk score."""
        slow_burst = RiskScorer.calculate_risk_score(
            base_severity="HIGH",
            event_count=5,
            time_window_minutes=10.0,
        )
        rapid_flood = RiskScorer.calculate_risk_score(
            base_severity="HIGH",
            event_count=10,
            time_window_minutes=1.0,
        )
        self.assertGreater(rapid_flood, slow_burst)

    def test_critical_account_boost(self):
        """Test that targeting sensitive accounts (e.g. admin, root, exec) boosts score."""
        regular_target = RiskScorer.calculate_risk_score(
            base_severity="HIGH",
            event_count=5,
            time_window_minutes=5.0,
            target_accounts=["user_123@siem.local"],
        )
        admin_target = RiskScorer.calculate_risk_score(
            base_severity="HIGH",
            event_count=5,
            time_window_minutes=5.0,
            target_accounts=["admin@siem.local"],
        )
        self.assertGreater(admin_target, regular_target)
        self.assertEqual(admin_target - regular_target, 15)

    def test_critical_endpoint_boost(self):
        """Test that accessing sensitive administrative endpoints elevates score."""
        public_ep = RiskScorer.calculate_risk_score(
            base_severity="MEDIUM",
            event_count=3,
            time_window_minutes=5.0,
            target_endpoints=["/api/health"],
        )
        admin_ep = RiskScorer.calculate_risk_score(
            base_severity="MEDIUM",
            event_count=3,
            time_window_minutes=5.0,
            target_endpoints=["/api/admin/users"],
        )
        self.assertGreater(admin_ep, public_ep)
        self.assertEqual(admin_ep - public_ep, 10)

    def test_clamping_boundaries(self):
        """Test that risk score is strictly bounded between 1 and 100."""
        extreme_score = RiskScorer.calculate_risk_score(
            base_severity="CRITICAL",
            event_count=500,
            time_window_minutes=0.1,
            target_accounts=["admin@siem.local", "root@siem.local"],
            target_endpoints=["/api/admin/system"],
            additional_boost=100,
        )
        self.assertEqual(extreme_score, 100)

    def test_recommended_response_generation(self):
        """Test tailored response playbook generation."""
        bf_response = RiskScorer.generate_recommended_response(
            attack_type="BRUTE_FORCE",
            risk_score=85,
            source="192.168.1.50",
            target_account="admin@siem.local",
        )
        self.assertIn("firewall/WAF IP block", bf_response)
        self.assertIn("admin@siem.local", bf_response)
        self.assertIn("Multi-Factor Authentication", bf_response)

        priv_response = RiskScorer.generate_recommended_response(
            attack_type="PRIVILEGE_ESCALATION",
            risk_score=95,
            source="10.0.0.99",
            target_account="attacker@siem.local",
        )
        self.assertIn("revoke and invalidate", priv_response)
        self.assertIn("audit recent administrative role modifications", priv_response)


class TestAlertGeneratorAndRuleIntegration(unittest.TestCase):

    def setUp(self):
        self.now = datetime.now(timezone.utc)

    def test_alert_generator_creates_complete_alert(self):
        """Test AlertGenerator synthesizes all factors into DetectionAlert."""
        alert = AlertGenerator.generate_alert(
            rule_id="BRUTE_FORCE_001",
            attack_type="BRUTE_FORCE",
            base_severity="HIGH",
            source="203.0.113.10",
            message="5 failed login attempts detected.",
            evidence={"attempts_count": 5, "threshold": 5},
            event_count=5,
            time_window_minutes=2.0,
            target_accounts=["admin@siem.local"],
            target_endpoints=["/api/auth/login"],
        )

        self.assertIsInstance(alert, DetectionAlert)
        self.assertEqual(alert.rule_id, "BRUTE_FORCE_001")
        self.assertEqual(alert.attack_type, "BRUTE_FORCE")
        self.assertGreaterEqual(alert.risk_score, 70)
        self.assertIn("calculated_risk_score", alert.evidence)
        self.assertTrue(len(alert.recommended_response) > 0)
        self.assertIn("firewall/WAF", alert.recommended_response)

    def test_rule_execution_with_dynamic_risk_assessment(self):
        """Test end-to-end detection rule produces enriched alert with response playbook."""
        rule = BruteForceRule(time_window_minutes=5, max_attempts=5)
        events = [
            SecurityEvent(
                event_type="LOGIN",
                username="admin@siem.local",
                source_ip="198.51.100.77",
                timestamp=self.now - timedelta(seconds=20 * (5 - i)),
                endpoint="/api/auth/login",
                result="FAILURE",
            )
            for i in range(5)
        ]

        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "BRUTE_FORCE_001")
        self.assertGreaterEqual(alert.risk_score, 75)
        self.assertIn("admin@siem.local", alert.recommended_response)
        self.assertEqual(alert.source, "198.51.100.77")


if __name__ == "__main__":
    unittest.main()
