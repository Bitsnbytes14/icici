"""Scenario definitions and execution workflows.

Implements:
  - Scenario 1: Baseline (Unprotected / Legacy Vendor Trust Model)
  - Scenario 2: Protected (Zero-Trust Defensive Controls)

SAFETY:
All events are strictly synthetic in-memory events or safe sandbox file markers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.auth.authentication import Authenticator, AuthResult
from src.auth.rbac import RBAC
from src.models.event import SecurityEvent
from src.models.resource import RESOURCE_CATALOG, Resource, Zone
from src.models.user import User
from src.models.vendor import VendorProfile, PrivilegeLevel
from src.network.access_control import AccessControl
from src.network.segmentation import Segmentation, NETWORK_GRAPH
from src.risk.scoring import VendorRiskScorer, RiskBreakdown
from src.security.containment import ContainmentManager
from src.security.detection import DetectionEngine, Alert
from src.security.monitoring import EventLogger, SimClock
from src.simulation.lateral_movement import traverse, TraversalResult
from src.simulation.ransomware_simulator import run as run_ransomware_sim, reset_workspace, RansomwareReport


@dataclass
class ScenarioResult:
    scenario_name: str
    vendor_id: str
    authenticated: bool
    mfa_enforced: bool
    rbac_enforced: bool
    segmentation_enforced: bool
    detection_enabled: bool
    containment_enabled: bool
    initial_risk: RiskBreakdown
    post_control_risk: RiskBreakdown
    events_logged: int
    alerts_generated: list[Alert]
    incident_contained: bool
    detection_time: float | None
    containment_time: float | None
    response_latency: float | None
    lateral_result: TraversalResult
    ransomware_report: RansomwareReport
    simulated_compromised_files: list[str] = field(default_factory=list)
    simulated_blocked_files: list[str] = field(default_factory=list)
    authentication_model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_name": self.scenario_name,
            "vendor_id": self.vendor_id,
            "authenticated": self.authenticated,
            "authentication_model": self.authentication_model,
            "mfa_enforced": self.mfa_enforced,
            "rbac_enforced": self.rbac_enforced,
            "segmentation_enforced": self.segmentation_enforced,
            "detection_enabled": self.detection_enabled,
            "containment_enabled": self.containment_enabled,
            "initial_risk_score": self.initial_risk.final_score,
            "initial_risk_tier": self.initial_risk.tier.value,
            "post_control_risk_score": self.post_control_risk.final_score,
            "post_control_risk_tier": self.post_control_risk.tier.value,
            "events_logged": self.events_logged,
            "alerts_count": len(self.alerts_generated),
            "incident_contained": self.incident_contained,
            "detection_time": self.detection_time,
            "containment_time": self.containment_time,
            "response_latency": self.response_latency,
            "lateral_transitions_attempted": self.lateral_result.transitions_attempted,
            "lateral_transitions_successful": self.lateral_result.transitions_successful,
            "lateral_transitions_blocked": self.lateral_result.transitions_blocked,
            "assets_visited_count": len(self.lateral_result.visited),
            "ransomware_targeted": len(self.ransomware_report.targeted),
            "ransomware_compromised": len(self.ransomware_report.encrypted),
            "ransomware_blocked": len(self.ransomware_report.blocked),
        }


class SimulationRunner:
    """Orchestrates scenario execution through the safe simulated pipeline."""

    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        self.scorer = VendorRiskScorer()

    def run_scenario_1_baseline(
        self,
        vendor: VendorProfile,
        log_file: Path | None = None,
        is_adversarial: bool = True,
    ) -> ScenarioResult:
        """SCENARIO 1: Baseline Environment (Unprotected).

        Characteristics:
          - No MFA required (password-only compromise succeeds)
          - Over-privileged access (all banking resources permitted)
          - Flat network (no segmentation enforced)
          - Detection engine disabled / passive
          - No automated containment or revocation
        """
        # Reset safe simulation workspace for file markers
        reset_workspace(self.project_root)

        log_path = log_file or (self.project_root / "logs" / f"baseline_{vendor.vendor_id.lower()}.jsonl")
        logger = EventLogger(log_path=log_path, clock=SimClock(step_seconds=0.2))

        # Initial risk calculation (unprotected)
        initial_risk = self.scorer.evaluate(vendor, dynamic_incident_count=0, enforce_defensive_controls=False)

        # Baseline User Identity: Password compromised, no MFA token
        user = vendor.to_user(credential_compromised=is_adversarial, has_mfa_token=False)

        # Baseline Controls: Permissive
        authenticator = Authenticator(mfa_required=False)
        all_resources = set(RESOURCE_CATALOG.keys())
        rbac = RBAC(permitted_resources=all_resources)  # Excessive privilege
        segmentation = Segmentation(enforced=False)      # Flat unsegmented network
        access_control = AccessControl(rbac=rbac, segmentation=segmentation)
        detection = DetectionEngine(enabled=False, current_risk_score=initial_risk.final_score)
        containment = ContainmentManager(auto_isolate=False)

        # Execute safe simulated event pipeline:
        # Step 1: Authentication
        auth_res = authenticator.authenticate(user)
        logger.log(
            user=user.username,
            action="AUTHENTICATE",
            target="auth_gateway",
            result="ALLOWED" if auth_res.success else "BLOCKED",
            severity="LOW" if auth_res.success else "HIGH",
            details={"mfa_required": False, "reason": auth_res.reason, "vendor_id": vendor.vendor_id},
        )

        if not is_adversarial:
            # Normal benign business operation
            logger.log(
                user=user.username,
                action="VENDOR_READ",
                target="vendor_portal",
                result="ALLOWED",
                severity="LOW",
                details={"business_hours": True, "authorized": True},
            )
            lateral_res = TraversalResult(visited={"vendor_portal"}, transitions_attempted=1, transitions_successful=1)
            r_report = RansomwareReport(targeted=[], encrypted=[], blocked=[])
        else:
            # Adversarial simulation
            evt_probe = logger.log(
                user=user.username,
                action="VENDOR_PROBE",
                target="vendor_portal",
                result="ALLOWED",
                severity="MEDIUM",
                details={"abnormal_hour": True, "probe_type": "port_enumeration"},
            )
            detection.observe(evt_probe)

            user.role = PrivilegeLevel.ADMIN.value
            evt_priv = logger.log(
                user=user.username,
                action="PRIVILEGE_ESCALATION",
                target="iam_controller",
                result="ALLOWED",
                severity="CRITICAL",
                details={"escalated_role": "ADMIN", "zone": "INTERNAL_ZONE"},
            )
            detection.observe(evt_priv)

            def on_event(evt: SecurityEvent) -> None:
                alerts = detection.observe(evt)
                containment.maybe_contain(user, alerts, logger.clock)

            lateral_res = traverse(
                graph=NETWORK_GRAPH,
                resources=RESOURCE_CATALOG,
                access_control=access_control,
                user=user,
                authenticated=auth_res.success,
                log_event=logger.log,
                on_event=on_event,
                start="vendor_portal",
            )

            r_report = run_ransomware_sim(
                project_root=self.project_root,
                resources=RESOURCE_CATALOG,
                access_control=access_control,
                user=user,
                authenticated=auth_res.success,
                log_event=logger.log,
                on_event=on_event,
            )

        # Dynamic risk score after incidents
        post_risk = self.scorer.evaluate(
            vendor,
            dynamic_incident_count=len(r_report.encrypted),
            enforce_defensive_controls=False,
        )

        return ScenarioResult(
            scenario_name="Baseline (Unprotected)",
            vendor_id=vendor.vendor_id,
            authenticated=auth_res.success,
            mfa_enforced=False,
            rbac_enforced=False,
            segmentation_enforced=False,
            detection_enabled=False,
            containment_enabled=False,
            initial_risk=initial_risk,
            post_control_risk=post_risk,
            events_logged=len(logger.events),
            alerts_generated=detection.alerts,
            incident_contained=containment.is_contained,
            detection_time=containment.detection_time,
            containment_time=containment.containment_time,
            response_latency=containment.containment_duration,
            lateral_result=lateral_res,
            ransomware_report=r_report,
            simulated_compromised_files=r_report.encrypted,
            simulated_blocked_files=r_report.blocked,
            authentication_model="PASSWORD_ONLY_NO_MFA",
        )

    def run_scenario_2_protected(
        self,
        vendor: VendorProfile,
        log_file: Path | None = None,
        simulate_credential_compromise: bool = True,
        assume_authenticated_session: bool = True,
        attacker_has_mfa_token: bool = False,
        is_adversarial: bool = True,
    ) -> ScenarioResult:
        """SCENARIO 2: Protected Environment (Zero-Trust Defensive Controls).

        Characteristics:
          - Least privilege RBAC (access strictly limited to vendor authorized systems)
          - Network Segmentation (strict zone boundaries; vendor cannot cross into SENSITIVE or BACKUP zones)
          - Active Detection Engine monitoring behavioral anomalies and privilege shifts
          - Automated Containment (revokes session and isolates user upon high-severity alert)
          - MFA is part of the architecture (see ``assume_authenticated_session``)

        Research-scope assumption (``assume_authenticated_session=True``, the default):
          The research question asks what happens *after* a compromised third-party
          identity is already operating inside an authenticated session -- not how
          that session was obtained. No credential theft or MFA-bypass technique is
          implemented anywhere in this codebase; instead this flag simply sets the
          starting state described by the assumption ``credential_compromised = True``
          / ``authenticated_session = True`` so that RBAC, segmentation, detection and
          containment -- the controls this experiment is actually about -- get a
          chance to run instead of the trial terminating at the MFA challenge.

          Passing ``assume_authenticated_session=False`` instead exercises the real
          MFA challenge (gated by ``attacker_has_mfa_token``) as its own standalone
          control test: a credential-only compromise with no second factor is
          correctly blocked before it ever reaches RBAC/segmentation. MFA remains
          part of the architecture and is covered by
          ``tests/test_simulation.py::test_protected_mfa_gate_blocks_credential_only_compromise``.
        """
        # Reset safe simulation workspace for file markers
        reset_workspace(self.project_root)

        log_path = log_file or (self.project_root / "logs" / f"protected_{vendor.vendor_id.lower()}.jsonl")
        logger = EventLogger(log_path=log_path, clock=SimClock(step_seconds=0.2))

        # Initial risk evaluation under defensive policy
        initial_risk = self.scorer.evaluate(vendor, dynamic_incident_count=0, enforce_defensive_controls=True)

        effective_has_mfa = True if not is_adversarial else attacker_has_mfa_token
        effective_compromised = simulate_credential_compromise if is_adversarial else False
        user = vendor.to_user(
            credential_compromised=effective_compromised,
            has_mfa_token=effective_has_mfa,
        )

        # Defensive Controls Active
        authenticator = Authenticator(mfa_required=True)
        vendor_allowed = {
            s for s in vendor.systems_accessible
            if s in RESOURCE_CATALOG and RESOURCE_CATALOG[s].zone == Zone.VENDOR
        }
        if not vendor_allowed:
            vendor_allowed = {"vendor_portal"}
        rbac = RBAC(permitted_resources=vendor_allowed)

        segmentation = Segmentation(enforced=True, allowed_cross_zone=set())
        access_control = AccessControl(rbac=rbac, segmentation=segmentation)

        detection = DetectionEngine(
            enabled=True,
            unauthorized_threshold=2,
            resource_count_threshold=3,
            current_risk_score=initial_risk.final_score,
        )
        containment = ContainmentManager(auto_isolate=True, response_delay_seconds=0.4)

        def on_response(action: str, details: dict) -> None:
            logger.log(
                user=user.username,
                action=f"DEFENSIVE_{action}",
                target="soc_gateway",
                result="EXECUTED",
                severity="HIGH",
                details=details,
            )

        if not is_adversarial:
            # Benign normal vendor access session
            auth_res = authenticator.authenticate(user)
            logger.log(
                user=user.username,
                action="AUTHENTICATE",
                target="auth_gateway",
                result="ALLOWED" if auth_res.success else "BLOCKED",
                severity="LOW" if auth_res.success else "CRITICAL",
                details={"mfa_required": True, "reason": auth_res.reason, "vendor_id": vendor.vendor_id},
            )
            logger.log(
                user=user.username,
                action="VENDOR_READ",
                target="vendor_portal",
                result="ALLOWED",
                severity="LOW",
                details={"authorized": True, "business_hours": True},
            )
            lateral_res = TraversalResult(visited={"vendor_portal"}, transitions_attempted=1, transitions_successful=1)
            r_report = RansomwareReport(targeted=[], encrypted=[], blocked=[])
            session_model = "benign_mfa_verified"
        else:
            # Adversarial simulation.
            #
            # credential_compromised = True (see `simulate_credential_compromise`
            # above) is always true here. Whether that compromised identity also
            # already holds an authenticated_session is controlled by
            # `assume_authenticated_session` -- see the docstring for the
            # rationale. Either way, no credential-theft or MFA-bypass technique
            # is implemented: this only selects which starting state the rest of
            # the pipeline evaluates.
            if assume_authenticated_session:
                user.password_verified = True
                user.mfa_verified = True
                auth_res = AuthResult(True, "AUTHENTICATED_SESSION_ASSUMED")
                session_model = "authenticated_session_assumed"
            else:
                auth_res = authenticator.authenticate(user)
                session_model = "direct_mfa_challenge"

            evt_auth = logger.log(
                user=user.username,
                action="AUTHENTICATE",
                target="auth_gateway",
                result="ALLOWED" if auth_res.success else "BLOCKED",
                severity="LOW" if auth_res.success else "CRITICAL",
                details={
                    "mfa_required": True,
                    "reason": auth_res.reason,
                    "vendor_id": vendor.vendor_id,
                    "session_model": session_model,
                },
            )
            alerts_auth = detection.observe(evt_auth)
            containment.maybe_contain(user, alerts_auth, logger.clock, on_response_action=on_response)

            evt_probe = logger.log(
                user=user.username,
                action="VENDOR_PROBE",
                target="vendor_portal",
                result="ALLOWED" if not user.is_isolated else "BLOCKED",
                severity="MEDIUM",
                details={"abnormal_hour": True, "probe_type": "port_enumeration"},
            )
            alerts_probe = detection.observe(evt_probe)
            containment.maybe_contain(user, alerts_probe, logger.clock, on_response_action=on_response)

            def on_event(evt: SecurityEvent) -> None:
                alerts = detection.observe(evt)
                containment.maybe_contain(user, alerts, logger.clock, on_response_action=on_response)

            # Attempted lateral movement out of the vendor access zone. This is
            # evaluated through the SAME AccessControl pipeline (RBAC +
            # segmentation) used by the baseline scenario, but now against a
            # real authenticated session -- so least privilege and network
            # segmentation are the controls actually being exercised, rather
            # than the run terminating before it starts.
            lateral_res = traverse(
                graph=NETWORK_GRAPH,
                resources=RESOURCE_CATALOG,
                access_control=access_control,
                user=user,
                authenticated=auth_res.success,
                log_event=logger.log,
                on_event=on_event,
                start="vendor_portal",
            )

            # Attempted privilege escalation, evaluated after lateral movement
            # so that RBAC/segmentation (and any detection/containment they
            # trigger) are attributed correctly rather than pre-empting the
            # lateral-movement test.
            evt_priv = logger.log(
                user=user.username,
                action="PRIVILEGE_ESCALATION",
                target="iam_controller",
                result="BLOCKED",
                severity="CRITICAL",
                details={"attempted_role": "ADMIN", "policy": "LEAST_PRIVILEGE_ENFORCED"},
            )
            alerts_priv = detection.observe(evt_priv)
            containment.maybe_contain(user, alerts_priv, logger.clock, on_response_action=on_response)

            r_report = run_ransomware_sim(
                project_root=self.project_root,
                resources=RESOURCE_CATALOG,
                access_control=access_control,
                user=user,
                authenticated=auth_res.success,
                log_event=logger.log,
                on_event=on_event,
            )

        # Post-control risk calculation
        post_risk = self.scorer.evaluate(
            vendor,
            dynamic_incident_count=0,
            enforce_defensive_controls=True,
        )

        return ScenarioResult(
            scenario_name="Protected (Zero-Trust Controls)",
            vendor_id=vendor.vendor_id,
            authenticated=auth_res.success,
            mfa_enforced=True,
            rbac_enforced=True,
            segmentation_enforced=True,
            detection_enabled=True,
            containment_enabled=True,
            initial_risk=initial_risk,
            post_control_risk=post_risk,
            events_logged=len(logger.events),
            alerts_generated=detection.alerts,
            incident_contained=containment.is_contained,
            detection_time=containment.detection_time,
            containment_time=containment.containment_time,
            response_latency=containment.containment_duration,
            lateral_result=lateral_res,
            ransomware_report=r_report,
            simulated_compromised_files=r_report.encrypted,
            simulated_blocked_files=r_report.blocked,
            authentication_model=session_model,
        )
