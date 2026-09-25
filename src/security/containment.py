"""Simulated automated containment and incident response engine.

SAFETY:
No operating system commands, system credentials, or real networks are touched.
Containment is represented by changing the in-memory state of the simulated
user identity (status=ISOLATED), causing all future simulation access
checks in AccessControl to reject the identity immediately.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Any

from src.models.user import User
from src.security.detection import Alert
from src.security.monitoring import SimClock


@dataclass
class IncidentRecord:
    incident_id: str
    vendor: str
    trigger_rule: str
    trigger_severity: str
    detection_timestamp: float
    containment_timestamp: float
    response_duration_seconds: float
    actions_taken: list[str]
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "vendor": self.vendor,
            "trigger_rule": self.trigger_rule,
            "trigger_severity": self.trigger_severity,
            "detection_timestamp": self.detection_timestamp,
            "containment_timestamp": self.containment_timestamp,
            "response_duration_seconds": self.response_duration_seconds,
            "actions_taken": " -> ".join(self.actions_taken),
        }


class ContainmentManager:
    """Manages simulated active containment, session revocation, and SOC alerting."""

    def __init__(
        self,
        auto_isolate: bool,
        response_delay_seconds: float = 0.5,
        criticality_trigger_severities: tuple[str, ...] = ("CRITICAL", "HIGH"),
    ):
        self.auto_isolate = auto_isolate
        self.response_delay_seconds = response_delay_seconds
        self.criticality_trigger_severities = criticality_trigger_severities

        self.detection_time: float | None = None
        self.containment_time: float | None = None
        self.isolated = False
        self.incident_history: list[IncidentRecord] = []
        self._incident_counter = 0

    def maybe_contain(
        self,
        user: User,
        alerts: list[Alert],
        clock: SimClock,
        on_response_action: Callable[[str, dict], None] | None = None,
    ) -> bool:
        """Inspect alerts and execute containment workflow if policy warrants."""
        if not alerts:
            return False

        # Filter for actionable severity alerts
        actionable_alerts = [a for a in alerts if a.severity in self.criticality_trigger_severities]
        if not actionable_alerts:
            return False

        first_alert = actionable_alerts[0]
        if self.detection_time is None:
            self.detection_time = first_alert.timestamp

        if self.isolated or user.is_isolated:
            return False

        if not self.auto_isolate:
            return False

        # Execute automated defensive workflow
        actions: list[str] = []

        # 1. Flag session
        actions.append("FLAG_SESSION")
        if on_response_action:
            on_response_action("FLAG_SESSION", {"vendor": user.username, "alert": first_alert.rule})

        # 2. Advance simulated clock by containment response latency
        self.containment_time = clock.advance(self.response_delay_seconds)

        # 3. Revoke access / isolate identity
        user.isolate()
        self.isolated = True
        actions.append("REVOKE_ACCESS")
        if on_response_action:
            on_response_action("REVOKE_ACCESS", {"vendor": user.username, "status": "ISOLATED"})

        # 4. Notify SOC administrator
        actions.append("NOTIFY_ADMIN")
        if on_response_action:
            on_response_action(
                "NOTIFY_ADMIN",
                {
                    "vendor": user.username,
                    "reason": first_alert.reason,
                    "recommended_action": first_alert.recommended_action,
                },
            )

        # 5. Record incident
        self._incident_counter += 1
        incident = IncidentRecord(
            incident_id=f"INC-{self._incident_counter:04d}",
            vendor=user.username,
            trigger_rule=first_alert.rule,
            trigger_severity=first_alert.severity,
            detection_timestamp=self.detection_time,
            containment_timestamp=self.containment_time,
            response_duration_seconds=round(self.containment_time - self.detection_time, 3),
            actions_taken=actions,
            details={"initial_reason": first_alert.reason},
        )
        self.incident_history.append(incident)
        return True

    @property
    def containment_duration(self) -> float | None:
        if self.detection_time is None or self.containment_time is None:
            return None
        return round(self.containment_time - self.detection_time, 3)

    @property
    def is_contained(self) -> bool:
        return self.isolated
