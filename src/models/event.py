"""Security event record used for logging and detection."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityEvent:
    timestamp: float
    user: str
    action: str
    target: str
    result: str  # "ALLOWED" or "BLOCKED" / "ISOLATED"
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "user": self.user,
            "action": self.action,
            "target": self.target,
            "result": self.result,
            "severity": self.severity,
            "details": self.details,
        }
