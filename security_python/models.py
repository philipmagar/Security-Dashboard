"""
Data models for the Security Event Detection Engine.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, Union


@dataclass
class SecurityEvent:
    """
    Standardized security event representation across the Mini-SIEM system.
    """
    event_type: str
    username: str
    source_ip: str
    timestamp: datetime
    endpoint: str = "internal"
    result: str = "UNKNOWN"
    details: Union[Dict[str, Any], str, None] = field(default_factory=dict)
    raw_id: Optional[Union[int, str]] = None

    @property
    def success(self) -> bool:
        """Returns True if the event result represents a success."""
        return self.result == "SUCCESS"

    @property
    def is_failure(self) -> bool:
        """Returns True if the event result represents any failure or denial."""
        return self.result in ("FAILURE", "BLOCKED", "DENIED", "ERROR")

    @property
    def is_blocked(self) -> bool:
        """Returns True if the event was blocked or rate limited."""
        return self.result == "BLOCKED"

    # Compatibility aliases
    @property
    def event(self) -> str:
        return self.event_type

    @property
    def user_email(self) -> str:
        return self.username

    @property
    def ip(self) -> str:
        return self.source_ip

    def to_dict(self) -> Dict[str, Any]:
        """Convert normalized SecurityEvent to standard dictionary."""
        return {
            "id": self.raw_id,
            "event_type": self.event_type,
            "event": self.event_type,
            "username": self.username,
            "user_email": self.username,
            "source_ip": self.source_ip,
            "ip": self.source_ip,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "endpoint": self.endpoint,
            "result": self.result,
            "success": self.success,
            "details": self.details,
        }

    # Dict-like compatibility interface
    def get(self, key: str, default: Any = None) -> Any:
        aliases = {
            "event": self.event_type,
            "event_type": self.event_type,
            "user_email": self.username,
            "username": self.username,
            "user": self.username,
            "ip": self.source_ip,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
            "endpoint": self.endpoint,
            "path": self.endpoint,
            "result": self.result,
            "success": self.success,
            "details": self.details,
            "id": self.raw_id,
        }
        return aliases.get(key, default)

    def __getitem__(self, key: str) -> Any:
        val = self.get(key)
        if val is None and key not in ("details", "raw_id", "id"):
            raise KeyError(f"Key '{key}' not found in SecurityEvent")
        return val

    def __contains__(self, key: str) -> bool:
        return key in (
            "event", "event_type", "user_email", "username", "user",
            "ip", "source_ip", "timestamp", "endpoint", "path",
            "result", "success", "details", "id"
        )
