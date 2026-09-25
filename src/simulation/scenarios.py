"""Safe baseline/protected scenarios sharing one adversarial playbook."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from src.auth.authentication import Authenticator, AuthResult
from src.auth.rbac import RBAC
from src.models.event import SecurityEvent
from src.models.resource import RESOURCE_CATALOG, Resource, Zone
from src.models.vendor import VendorProfile, PrivilegeLevel
from src.network.access_control import AccessControl
from src.network.segmentation import Segmentation, NETWORK_GRAPH
from src.risk.scoring import VendorRiskScorer, RiskBreakdown
from src.security.containment import ContainmentManager
from src.security.detection import DetectionEngine, Alert
from src.security.monitoring import EventLogger, SimClock
from src.simulation.lateral_movement import traverse, TraversalResult
from src.simulation.ransomware_simulator import run as run_ransomware_sim, reset_workspace, RansomwareReport

PLAYBOOK_ACTIONS = ("VENDOR_PROBE", "PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT", "SENSITIVE_RESOURCE_ACCESS", "RANSOMWARE_ENCRYPT")
SENSITIVE_TARGETS = tuple(n for n, r in RESOURCE_CATALOG.items() if r.zone in (Zone.SENSITIVE, Zone.BACKUP))

@dataclass
class ScenarioResult:
    scenario_name: str; vendor_id: str; authenticated: bool; mfa_enforced: bool; rbac_enforced: bool; segmentation_enforced: bool; detection_enabled: bool; containment_enabled: bool
    initial_risk: RiskBreakdown; post_control_risk: RiskBreakdown; events_logged: int; alerts_generated: list[Alert]; incident_contained: bool
    first_detection_time: float | None; actionable_detection_time: float | None; containment_time: float | None; response_latency: float | None
    lateral_result: TraversalResult; ransomware_report: RansomwareReport; simulated_compromised_files: list[str] = field(default_factory=list); simulated_blocked_files: list[str] = field(default_factory=list)
    authentication_model: str = ""; playbook_actions: tuple[str, ...] = PLAYBOOK_ACTIONS

def _access_event(logger: EventLogger, user: str, action: str, resource: Resource, decision: Any) -> SecurityEvent:
    return logger.log(user=user, action=action, target=resource.name, result="ALLOWED" if decision.allowed else "BLOCKED",
        severity="CRITICAL" if resource.sensitivity.value == "CRITICAL" else "LOW", details={"zone": resource.zone.value, "reason": decision.reason, "layers": {k: v.passed for k, v in decision.layers.items()}})

def run_adversarial_playbook(*, user: Any, authenticated: bool, access_control: AccessControl, logger: EventLogger, detection: DetectionEngine,
                             containment: ContainmentManager, privilege_allowed: bool, on_response: Callable[[str, dict], None] | None = None) -> tuple[TraversalResult, RansomwareReport]:
    """The exact same simulated actions, in the exact same order, for both configurations."""
    def observe(event: SecurityEvent) -> None:
        containment.maybe_contain(user, detection.observe(event), logger.clock, on_response_action=on_response)
    observe(logger.log(user=user.username, action="VENDOR_PROBE", target="vendor_portal", result="ALLOWED", severity="MEDIUM", details={"abnormal_hour": True, "probe_type": "catalog_enumeration"}))
    if privilege_allowed:
        user.role = PrivilegeLevel.ADMIN.value
    observe(logger.log(user=user.username, action="PRIVILEGE_ESCALATION", target="iam_controller", result="ALLOWED" if privilege_allowed else "BLOCKED", severity="CRITICAL", details={"attempted_role": "ADMIN", "policy": "PERMISSIVE" if privilege_allowed else "LEAST_PRIVILEGE_ENFORCED"}))
    lateral = traverse(graph=NETWORK_GRAPH, resources=RESOURCE_CATALOG, access_control=access_control, user=user, authenticated=authenticated, log_event=logger.log, on_event=observe, start="vendor_portal")
    for target in SENSITIVE_TARGETS:
        resource = RESOURCE_CATALOG[target]
        observe(_access_event(logger, user.username, "SENSITIVE_RESOURCE_ACCESS", resource, access_control.evaluate(user, resource, authenticated, Zone.VENDOR)))
    ransomware = run_ransomware_sim(project_root=Path(logger.context["project_root"]), resources=RESOURCE_CATALOG, access_control=access_control, user=user, authenticated=authenticated, log_event=logger.log, on_event=observe)
    return lateral, ransomware

class SimulationRunner:
    def __init__(self, project_root: Path): self.project_root = Path(project_root).resolve(); self.scorer = VendorRiskScorer()
    def _logger(self, path: Path, context: dict[str, Any] | None) -> EventLogger:
        return EventLogger(path, SimClock(step_seconds=0.2), context={"project_root": str(self.project_root), **(context or {})})
    def _benign(self, user: Any, auth: bool, access: AccessControl, logger: EventLogger, detection: DetectionEngine, permitted: set[str]) -> tuple[TraversalResult, RansomwareReport]:
        target = sorted(permitted)[0]; resource = RESOURCE_CATALOG[target]; decision = access.evaluate(user, resource, auth, resource.zone)
        detection.observe(_access_event(logger, user.username, "VENDOR_READ", resource, decision))
        return TraversalResult({target} if decision.allowed else set(), 1, int(decision.allowed), int(not decision.allowed)), RansomwareReport()
    def _result(self, name: str, vendor: VendorProfile, auth: AuthResult, model: str, flags: tuple[bool, bool, bool, bool, bool], initial: RiskBreakdown, post: RiskBreakdown, logger: EventLogger, detection: DetectionEngine, containment: ContainmentManager, lateral: TraversalResult, ransomware: RansomwareReport) -> ScenarioResult:
        return ScenarioResult(name, vendor.vendor_id, auth.success, *flags, initial, post, len(logger.events), detection.alerts, containment.is_contained, detection.first_alert_time, containment.detection_time, containment.containment_time, containment.containment_duration, lateral, ransomware, ransomware.encrypted, ransomware.blocked, model)
    def run_scenario_1_baseline(self, vendor: VendorProfile, log_file: Path | None = None, is_adversarial: bool = True, trial_context: dict[str, Any] | None = None) -> ScenarioResult:
        reset_workspace(self.project_root); logger = self._logger(log_file or self.project_root / "logs" / f"baseline_{vendor.vendor_id.lower()}.jsonl", trial_context); initial = self.scorer.evaluate(vendor, enforce_defensive_controls=False)
        user = vendor.to_user(credential_compromised=is_adversarial, has_mfa_token=False, has_valid_password=not is_adversarial); auth = Authenticator(False).authenticate(user)
        logger.log(user=user.username, action="AUTHENTICATE", target="auth_gateway", result="ALLOWED" if auth.success else "BLOCKED", severity="LOW" if auth.success else "HIGH", details={"mfa_required": False, "reason": auth.reason, "vendor_id": vendor.vendor_id})
        permitted = set(RESOURCE_CATALOG); access = AccessControl(RBAC(permitted), Segmentation(False)); detection = DetectionEngine(False, current_risk_score=initial.final_score); containment = ContainmentManager(False)
        lateral, ransomware = run_adversarial_playbook(user=user, authenticated=auth.success, access_control=access, logger=logger, detection=detection, containment=containment, privilege_allowed=True) if is_adversarial else self._benign(user, auth.success, access, logger, detection, permitted)
        return self._result("Baseline (Unprotected)", vendor, auth, "password_only", (False, False, False, False, False), initial, self.scorer.evaluate(vendor, len(ransomware.encrypted), False), logger, detection, containment, lateral, ransomware)
    def run_scenario_2_protected(self, vendor: VendorProfile, log_file: Path | None = None, simulate_credential_compromise: bool = True, assume_authenticated_session: bool = True, attacker_has_mfa_token: bool = False, is_adversarial: bool = True, trial_context: dict[str, Any] | None = None) -> ScenarioResult:
        reset_workspace(self.project_root); logger = self._logger(log_file or self.project_root / "logs" / f"protected_{vendor.vendor_id.lower()}.jsonl", trial_context); initial = self.scorer.evaluate(vendor, enforce_defensive_controls=True)
        user = vendor.to_user(credential_compromised=simulate_credential_compromise if is_adversarial else False, has_mfa_token=attacker_has_mfa_token if is_adversarial else True, has_valid_password=not is_adversarial)
        permitted = {s for s in vendor.systems_accessible if s in RESOURCE_CATALOG and RESOURCE_CATALOG[s].zone == Zone.VENDOR} or {"vendor_portal"}; access = AccessControl(RBAC(permitted), Segmentation(True, set())); detection = DetectionEngine(True, unauthorized_threshold=2, resource_count_threshold=3, current_risk_score=initial.final_score); containment = ContainmentManager(True, response_delay_seconds=0.4)
        def response(action: str, details: dict) -> None: logger.log(user=user.username, action=f"DEFENSIVE_{action}", target="soc_gateway", result="EXECUTED", severity="HIGH", details=details)
        if is_adversarial and assume_authenticated_session: user.password_verified = user.mfa_verified = True; auth, model = AuthResult(True, "AUTHENTICATED_SESSION_ASSUMED"), "authenticated_session_assumed"
        else: auth, model = Authenticator(True).authenticate(user), "direct_mfa_challenge" if is_adversarial else "benign_mfa_verified"
        event = logger.log(user=user.username, action="AUTHENTICATE", target="auth_gateway", result="ALLOWED" if auth.success else "BLOCKED", severity="LOW" if auth.success else "CRITICAL", details={"mfa_required": True, "reason": auth.reason, "vendor_id": vendor.vendor_id, "session_model": model}); containment.maybe_contain(user, detection.observe(event), logger.clock, on_response_action=response)
        lateral, ransomware = run_adversarial_playbook(user=user, authenticated=auth.success, access_control=access, logger=logger, detection=detection, containment=containment, privilege_allowed=False, on_response=response) if is_adversarial else self._benign(user, auth.success, access, logger, detection, permitted)
        return self._result("Protected (Zero-Trust Controls)", vendor, auth, model, (True, True, True, True, True), initial, self.scorer.evaluate(vendor, enforce_defensive_controls=True), logger, detection, containment, lateral, ransomware)
