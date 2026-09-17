"""
Unit and Integration Tests for Event Processing Layer and Detection Rules.
"""
import unittest
from datetime import datetime, timezone, timedelta

from models import SecurityEvent
from event_processor import EventProcessor
from rules import detect_brute_force, detect_rapid_registration, detect_password_spraying


class TestEventProcessor(unittest.TestCase):

    def test_normalize_standard_object(self):
        """Test normalization from standard format."""
        raw = {
            "id": 101,
            "event_type": "LOGIN",
            "username": "Admin@Siem.Local",
            "source_ip": "::ffff:192.168.1.50",
            "timestamp": "2026-09-17T08:00:00Z",
            "endpoint": "/api/auth/login",
            "result": "FAILURE",
            "details": {"reason": "bad password"}
        }
        event = EventProcessor.normalize(raw)
        self.assertIsInstance(event, SecurityEvent)
        self.assertEqual(event.event_type, "LOGIN")
        self.assertEqual(event.username, "admin@siem.local")
        self.assertEqual(event.source_ip, "192.168.1.50")
        self.assertEqual(event.endpoint, "/api/auth/login")
        self.assertEqual(event.result, "FAILURE")
        self.assertFalse(event.success)
        self.assertTrue(event.is_failure)
        self.assertEqual(event.timestamp.year, 2026)

    def test_normalize_legacy_fields(self):
        """Test normalization from legacy database/Node fields."""
        raw = {
            "id": 102,
            "event": "register",
            "user_email": "NEW_USER@test.com",
            "ip": "::ffff:10.0.0.1",
            "timestamp": "2026-09-17T08:05:00+00:00",
            "success": True,
            "details": '{"message":"registered"}'
        }
        event = EventProcessor.normalize(raw)
        self.assertEqual(event.event_type, "REGISTER")
        self.assertEqual(event.username, "new_user@test.com")
        self.assertEqual(event.source_ip, "10.0.0.1")
        self.assertEqual(event.result, "SUCCESS")
        self.assertTrue(event.success)
        self.assertFalse(event.is_failure)
        self.assertEqual(event.details, {"message": "registered"})

    def test_sanitize_ip(self):
        """Test IP address cleaning."""
        self.assertEqual(EventProcessor.sanitize_ip("::ffff:1.2.3.4"), "1.2.3.4")
        self.assertEqual(EventProcessor.sanitize_ip("::1"), "127.0.0.1")
        self.assertEqual(EventProcessor.sanitize_ip(""), "unknown")
        self.assertEqual(EventProcessor.sanitize_ip(None), "unknown")
        self.assertEqual(EventProcessor.sanitize_ip(" 192.168.1.10 "), "192.168.1.10")

    def test_parse_timestamp_variations(self):
        """Test timestamp parsing for multiple formats."""
        now = datetime.now(timezone.utc)
        
        # Datetime obj
        dt_parsed = EventProcessor.parse_timestamp(now)
        self.assertEqual(dt_parsed, now)

        # ISO String
        iso_str = "2026-09-17T12:30:45Z"
        iso_parsed = EventProcessor.parse_timestamp(iso_str)
        self.assertEqual(iso_parsed.hour, 12)
        self.assertEqual(iso_parsed.minute, 30)

        # Epoch seconds
        epoch_ts = 1789640000
        epoch_parsed = EventProcessor.parse_timestamp(epoch_ts)
        self.assertEqual(epoch_parsed.year, 2026)

    def test_validation_rules(self):
        """Test validation checks on events."""
        valid_event = SecurityEvent(
            event_type="LOGIN",
            username="user@siem.local",
            source_ip="192.168.1.1",
            timestamp=datetime.now(timezone.utc),
            endpoint="/api/auth/login",
            result="FAILURE"
        )
        is_valid, err = EventProcessor.validate(valid_event)
        self.assertTrue(is_valid)
        self.assertIsNone(err)

        # Invalid: missing event_type
        invalid_event = SecurityEvent(
            event_type="",
            username="user@siem.local",
            source_ip="192.168.1.1",
            timestamp=datetime.now(timezone.utc),
            endpoint="/api/auth/login",
            result="FAILURE"
        )
        is_valid, err = EventProcessor.validate(invalid_event)
        self.assertFalse(is_valid)
        self.assertIn("event_type", err)

    def test_batch_process_drops_invalid(self):
        """Test that batch processing drops corrupt logs and retains valid ones."""
        raw_batch = [
            {"event": "LOGIN", "user_email": "a@test.com", "ip": "1.1.1.1", "success": False, "timestamp": "2026-09-17T08:00:00Z"},
            {"event_type": "", "username": "", "source_ip": "", "result": ""}, # Corrupted
            {"event": "REGISTER", "user_email": "b@test.com", "ip": "1.1.1.2", "success": True, "timestamp": "2026-09-17T08:01:00Z"}
        ]
        processed = EventProcessor.process_raw_logs(raw_batch)
        self.assertEqual(len(processed), 2)
        self.assertEqual(processed[0].event_type, "LOGIN")
        self.assertEqual(processed[1].event_type, "REGISTER")


class TestDetectionRulesWithStandardEvents(unittest.TestCase):

    def test_detect_brute_force_with_security_events(self):
        """Test brute force detection with normalized SecurityEvent stream."""
        now = datetime.now(timezone.utc)
        events = [
            SecurityEvent(
                event_type="LOGIN",
                username="victim@siem.local",
                source_ip="203.0.113.5",
                timestamp=now - timedelta(seconds=30 * (5 - i)),
                endpoint="/api/auth/login",
                result="FAILURE"
            )
            for i in range(5)
        ]

        alerts = detect_brute_force(events, time_window_minutes=5, max_attempts=5)
        self.assertEqual(len(alerts), 1)
        self.assertIn(alerts[0]["type"], ("BRUTE_FORCE_001", "BRUTE_FORCE_DETECTED"))
        self.assertEqual(alerts[0]["source"], "203.0.113.5")
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_detect_password_spraying_with_security_events(self):
        """Test distributed password spray detection across multiple IPs."""
        now = datetime.now(timezone.utc)
        events = [
            SecurityEvent(
                event_type="LOGIN",
                username="target_exec@siem.local",
                source_ip=f"198.51.100.{10 + i}",
                timestamp=now - timedelta(minutes=i),
                endpoint="/api/auth/login",
                result="FAILURE"
            )
            for i in range(4)
        ]

        alerts = detect_password_spraying(events, time_window_minutes=30, max_ips=3)
        self.assertEqual(len(alerts), 1)
        self.assertIn(alerts[0]["type"], ("PASSWORD_SPRAY_001", "PASSWORD_SPRAYING"))
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["details"]["evidence"]["unique_ips_count"], 3)

    def test_detect_rapid_registration(self):
        """Test rapid registration detection from a single IP."""
        now = datetime.now(timezone.utc)
        events = [
            SecurityEvent(
                event_type="REGISTER",
                username=f"fake_user_{i}@bot.local",
                source_ip="198.51.100.99",
                timestamp=now - timedelta(minutes=i),
                endpoint="/api/auth/register",
                result="SUCCESS"
            )
            for i in range(3)
        ]

        alerts = detect_rapid_registration(events, time_window_minutes=10, max_registrations=3)
        self.assertEqual(len(alerts), 1)
        self.assertIn(alerts[0]["type"], ("RAPID_REG_001", "SUSPICIOUS_ACTIVITY"))
        self.assertEqual(alerts[0]["source"], "198.51.100.99")


if __name__ == "__main__":
    unittest.main()
