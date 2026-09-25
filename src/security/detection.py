"""Deterministic detection rules for banking third-party vendor activity.

SAFETY:
Rules operate solely on in-memory simulated event data. No machine learning
uncertainty: fixed, explainable thresholds make results reproducible and
academically defensible for CA-2 evaluation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.models.event import SecurityEvent


@dataclass
class Alert:
    timestamp: float
    rule: str
    vendor: str
    target: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    reason: str
    recommended_action: str
    risk_score: float = 0.0
    event_action: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    # Backward compatibility property for existing tests/code
    @property
    def user(self) -> str:
        return self.vendor

    @property
    def description(self) -> str:
        return self.reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "rule": self.rule,
            "vendor": self.vendor,
            "target": self.target,
            "severity": self.severity,
            "reason": self.reason,
            "recommended_action": self.recommended_action,
            "risk_score": self.risk_score,
            "event_action": self.event_action,
        }


class DetectionEngine:
    def __init__(
        self,
        enabled: bool,
        unauthorized_threshold: int = 3,
        resource_count_threshold: int = 5,
        current_risk_score: float = 50.0,
    ):
        self.enabled = enabled
        self.unauthorized_threshold = unauthorized_threshold
        self.resource_count_threshold = resource_count_threshold
        self.current_risk_score = current_risk_score

        self.alerts: list[Alert] = []
        self.first_alert_time: float | None = None
        self._fired_rules: set[str] = set()
        self._blocked_count = 0
        self._touched_resources: set[str] = set()
        self._file_ops_count = 0

    def update_risk_score(self, score: float) -> None:
        self.current_risk_score = score

    def observe(self, event: SecurityEvent) -> list[Alert]:
        if not self.enabled:
            return []

        new_alerts: list[Alert] = []
        self._touched_resources.add(event.target)
        if event.result == "BLOCKED":
            self._blocked_count += 1

        # Track file operations
        if "FILE" in event.action or "ENCRYPT" in event.action or "READ" in event.action:
            self._file_ops_count += 1

        # Rule 1: MFA Failure / Authentication Anomaly
        if event.action == "AUTHENTICATE" and event.details.get("reason") in ("MFA_FAILED", "INVALID_CREDENTIALS"):
            new_alerts.append(self._raise(
                rule="MFA_FAILURE",
                event=event,
                severity="CRITICAL",
                reason=f"Vendor identity authenticated with credentials but failed verification ({event.details.get('reason')}).",
                recommended_action="Block IP, revoke active session, and prompt immediate out-of-band re-authentication.",
            ))

        # Rule 2: Off-hours or abnormal login
        if event.action == "AUTHENTICATE" and event.details.get("abnormal_hour"):
            rule_id = f"OFF_HOURS_LOGIN_{event.user}"
            if rule_id not in self._fired_rules:
                new_alerts.append(self._raise(
                    rule="OFF_HOURS_LOGIN",
                    event=event,
                    severity="MEDIUM",
                    reason="Vendor access initiated outside designated maintenance window / business hours.",
                    recommended_action="Flag session for enhanced telemetry and verify ticket authorization with vendor manager.",
                ))
                self._fired_rules.add(rule_id)

        # Rule 3: Direct attempt to reach SENSITIVE_ZONE or BACKUP_ZONE
        zone = event.details.get("zone")
        if zone in ("SENSITIVE_ZONE", "BACKUP_ZONE"):
            rule_id = f"SENSITIVE_ZONE_ACCESS_{event.target}"
            if rule_id not in self._fired_rules:
                new_alerts.append(self._raise(
                    rule="SENSITIVE_ZONE_ACCESS",
                    event=event,
                    severity="CRITICAL" if zone == "BACKUP_ZONE" else "HIGH",
                    reason=f"Third-party vendor attempted unsegmented access to high-criticality banking asset '{event.target}' in {zone}.",
                    recommended_action="Immediately quarantine vendor session, isolate host gateway, and audit database transaction logs.",
                ))
                self._fired_rules.add(rule_id)

        # Rule 4: Simulated Privilege Escalation Attempt
        if event.action == "PRIVILEGE_ESCALATION":
            new_alerts.append(self._raise(
                rule="PRIVILEGE_ESCALATION",
                event=event,
                severity="CRITICAL",
                reason="Vendor identity attempted unauthorized role transition / privilege escalation to ADMIN.",
                recommended_action="Enforce emergency PAM session termination, lock vendor service credentials, and initiate incident response.",
            ))

        # Rule 5: Repeated Unauthorized/Blocked Access Attempts (Threshold Breached)
        if self._blocked_count >= self.unauthorized_threshold and "REPEATED_UNAUTHORIZED_ACCESS" not in self._fired_rules:
            new_alerts.append(self._raise(
                rule="REPEATED_UNAUTHORIZED_ACCESS",
                event=event,
                severity="HIGH",
                reason=f"Repeated policy violations observed: {self._blocked_count} blocked requests recorded for vendor.",
                recommended_action="Temporarily suspend vendor routing tunnel and alert SOC analyst for active intrusion inspection.",
            ))
            self._fired_rules.add("REPEATED_UNAUTHORIZED_ACCESS")

        # Rule 6: Excessive Resource Traversal / Enumeration
        if len(self._touched_resources) >= self.resource_count_threshold and "UNUSUAL_RESOURCE_COUNT" not in self._fired_rules:
            new_alerts.append(self._raise(
                rule="UNUSUAL_RESOURCE_COUNT",
                event=event,
                severity="MEDIUM",
                reason=f"Vendor identity probed {len(self._touched_resources)} distinct banking assets, indicating network scanning or recon.",
                recommended_action="Apply rate-limiting on gateway API and inspect subsequent lateral hops.",
            ))
            self._fired_rules.add("UNUSUAL_RESOURCE_COUNT")

        # Rule 7: Simulated Ransomware Behavior Event
        if "RANSOMWARE" in event.action:
            new_alerts.append(self._raise(
                rule="RANSOMWARE_BEHAVIOR_DETECTED",
                event=event,
                severity="CRITICAL",
                reason=f"Rapid unauthorized file write/rename pattern detected against asset '{event.target}'.",
                recommended_action="Trigger automated containment: isolate target, revoke credentials, and snapshot backup volumes.",
            ))

        return new_alerts

    def _raise(
        self,
        rule: str,
        event: SecurityEvent,
        severity: str,
        reason: str,
        recommended_action: str,
    ) -> Alert:
        alert = Alert(
            timestamp=event.timestamp,
            rule=rule,
            vendor=event.user,
            target=event.target,
            severity=severity,
            reason=reason,
            recommended_action=recommended_action,
            risk_score=self.current_risk_score,
            event_action=event.action,
            details=event.details,
        )
        self.alerts.append(alert)
        if self.first_alert_time is None:
            self.first_alert_time = alert.timestamp
        self._fired_rules.add(rule)
        return alert
