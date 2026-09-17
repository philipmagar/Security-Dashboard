"""
Event Processing Layer for Mini-SIEM Detection Engine.

Provides normalization, sanitization, and validation for all security events
before they reach the detection rules.
"""
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from models import SecurityEvent


class EventProcessor:
    """
    Standard event processing layer that ingests raw logs/events,
    normalizes their format, validates data integrity, and produces clean SecurityEvent instances.
    """

    # Known standard event types
    KNOWN_EVENT_TYPES = {
        "LOGIN",
        "LOGOUT",
        "REGISTER",
        "UNAUTHORIZED_ACCESS",
        "ACCESS_DENIED_SPIKE",
        "TOKEN_INVALID",
        "INVALID_TOKEN_SPIKE",
        "ROLE_ESCALATION_ATTEMPT",
        "BRUTE_FORCE_DETECTED",
        "BRUTE_FORCE_BLOCKED",
        "RATE_LIMIT_EXCEEDED",
        "LOGIN_RATE_LIMIT",
        "SUSPICIOUS_ACTIVITY",
        "PASSWORD_SPRAYING",
        "MULTIPLE_FAILED_LOGINS",
        "UNKNOWN",
    }

    # Standard results
    STANDARD_RESULTS = {"SUCCESS", "FAILURE", "BLOCKED", "DENIED", "ERROR", "UNKNOWN"}

    @staticmethod
    def parse_timestamp(ts_val: Any) -> datetime:
        """
        Parses various timestamp representations into a standardized UTC datetime object.
        """
        if isinstance(ts_val, datetime):
            if ts_val.tzinfo is None:
                return ts_val.replace(tzinfo=timezone.utc)
            return ts_val

        if isinstance(ts_val, (int, float)):
            # Epoch seconds or milliseconds
            if ts_val > 1e11:  # Milliseconds
                ts_val = ts_val / 1000.0
            return datetime.fromtimestamp(ts_val, tz=timezone.utc)

        if isinstance(ts_val, str) and ts_val.strip():
            cleaned = ts_val.strip().replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(cleaned)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except (ValueError, TypeError):
                pass

        # Fallback to current UTC time
        return datetime.now(timezone.utc)

    @staticmethod
    def sanitize_ip(ip_val: Any) -> str:
        """
        Normalizes and sanitizes IP address strings.
        """
        if not ip_val or not isinstance(ip_val, str):
            return "unknown"
        cleaned = ip_val.strip().replace("::ffff:", "")
        if cleaned in ("", "::1"):
            return "127.0.0.1"
        return cleaned

    @staticmethod
    def sanitize_username(user_val: Any) -> str:
        """
        Normalizes usernames/emails (lowercase, trimmed).
        """
        if not user_val or not isinstance(user_val, str):
            return "unknown"
        cleaned = user_val.strip().lower()
        return cleaned if cleaned else "unknown"

    @staticmethod
    def parse_details(details_val: Any) -> Union[Dict[str, Any], str]:
        """
        Parses details into structured dict if JSON string, or retains raw structure.
        """
        if isinstance(details_val, dict):
            return details_val
        if isinstance(details_val, str):
            details_str = details_val.strip()
            if details_str.startswith("{") and details_str.endswith("}"):
                try:
                    return json.loads(details_str)
                except Exception:
                    pass
            return details_str
        if details_val is None:
            return {}
        return str(details_val)

    @classmethod
    def normalize(cls, raw: Union[Dict[str, Any], SecurityEvent]) -> SecurityEvent:
        """
        Normalizes a raw log or dictionary into a standard SecurityEvent instance.
        """
        if isinstance(raw, SecurityEvent):
            return raw

        # Extract & normalize event type
        raw_event_type = raw.get("event_type") or raw.get("event") or "UNKNOWN"
        event_type = str(raw_event_type).strip().upper()

        # Extract & normalize username / email
        raw_user = raw.get("username") or raw.get("user_email") or raw.get("user") or "unknown"
        username = cls.sanitize_username(raw_user)

        # Extract & normalize IP
        raw_ip = raw.get("source_ip") or raw.get("ip") or "unknown"
        source_ip = cls.sanitize_ip(raw_ip)

        # Extract & normalize timestamp
        timestamp = cls.parse_timestamp(raw.get("timestamp"))

        # Extract & normalize endpoint
        raw_endpoint = raw.get("endpoint") or raw.get("path") or raw.get("url") or "internal"
        endpoint = str(raw_endpoint).strip()

        # Extract & normalize result
        raw_result = raw.get("result")
        raw_success = raw.get("success")

        if raw_result is not None:
            result = str(raw_result).strip().upper()
        elif raw_success is not None:
            result = "SUCCESS" if raw_success is True or str(raw_success).lower() == "true" else "FAILURE"
        else:
            result = "UNKNOWN"

        # Details and ID
        details = cls.parse_details(raw.get("details"))
        raw_id = raw.get("id") or raw.get("raw_id")

        return SecurityEvent(
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            timestamp=timestamp,
            endpoint=endpoint,
            result=result,
            details=details,
            raw_id=raw_id,
        )

    @classmethod
    def validate(cls, event: SecurityEvent) -> Tuple[bool, Optional[str]]:
        """
        Validates the data integrity of a SecurityEvent.
        Returns (is_valid, error_message).
        """
        if not isinstance(event, SecurityEvent):
            return False, "Object is not an instance of SecurityEvent"

        if not event.event_type or not isinstance(event.event_type, str):
            return False, "Missing or invalid event_type"

        if not event.source_ip or not isinstance(event.source_ip, str):
            return False, "Missing or invalid source_ip"

        if not isinstance(event.timestamp, datetime):
            return False, "Missing or invalid timestamp"

        if not event.endpoint or not isinstance(event.endpoint, str):
            return False, "Missing or invalid endpoint"

        if not event.result or not isinstance(event.result, str):
            return False, "Missing or invalid result"

        return True, None

    @classmethod
    def process_raw_log(cls, raw: Dict[str, Any]) -> Optional[SecurityEvent]:
        """
        Processes a single raw log dictionary: normalizes and validates it.
        Returns the SecurityEvent if valid, or None if validation fails.
        """
        try:
            event = cls.normalize(raw)
            is_valid, error = cls.validate(event)
            if not is_valid:
                print(f"[EVENT PROCESSOR WARNING] Dropping invalid event: {error} | Raw: {raw}")
                return None
            return event
        except Exception as e:
            print(f"[EVENT PROCESSOR ERROR] Failed to process event: {e} | Raw: {raw}")
            return None

    @classmethod
    def process_raw_logs(cls, raw_logs: List[Dict[str, Any]]) -> List[SecurityEvent]:
        """
        Processes a batch of raw log records, returning only validated, normalized SecurityEvent instances.
        """
        if not raw_logs:
            return []

        processed_events = []
        for record in raw_logs:
            event = cls.process_raw_log(record)
            if event is not None:
                processed_events.append(event)

        return processed_events
