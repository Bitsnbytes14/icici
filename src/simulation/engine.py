"""Deterministic Multi-Trial Experiment Engine.

Runs reproducible synthetic simulation trials across vendor cohorts, evaluating:
  - Baseline (Unprotected) environment
  - Protected (Zero-Trust) environment
across multiple attack vectors and normal baseline sessions.

Uses a fixed random seed (default=42) for statistical validity and reproducibility.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.models.resource import RESOURCE_CATALOG, Zone
from src.models.vendor import VendorProfile, load_synthetic_vendors
from src.simulation.scenarios import SimulationRunner, ScenarioResult


def _zone_reach_counts(visited: set[str]) -> tuple[int, int]:
    """Count how many visited/accessible assets fall in sensitive-tier zones.

    Returns (sensitive_or_backup_count, internal_count), derived purely from
    the actual lateral-movement result -- never hardcoded.
    """
    sensitive = sum(
        1 for name in visited
        if RESOURCE_CATALOG[name].zone in (Zone.SENSITIVE, Zone.BACKUP)
    )
    internal = sum(1 for name in visited if RESOURCE_CATALOG[name].zone == Zone.INTERNAL)
    return sensitive, internal


@dataclass
class ExperimentTrialRecord:
    trial_id: int
    seed: int
    vendor_id: str
    scenario_type: str  # "BASELINE" or "PROTECTED"
    attack_vector: str  # "NORMAL_SESSION", "CREDENTIAL_COMPROMISE", "PRIVILEGE_ESCALATION", "LATERAL_PROBE"
    authenticated: bool
    detection_occurred: bool
    is_false_positive: bool
    detection_time: float | None
    containment_occurred: bool
    containment_time: float | None
    response_latency: float | None
    initial_risk_score: float
    final_risk_score: float
    risk_delta: float
    assets_compromised: int
    assets_blocked: int
    files_compromised: int
    files_blocked: int
    lateral_transitions_successful: int
    sensitive_assets_reached: int
    internal_assets_reached: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "trial_id": self.trial_id,
            "seed": self.seed,
            "vendor_id": self.vendor_id,
            "scenario_type": self.scenario_type,
            "attack_vector": self.attack_vector,
            "authenticated": self.authenticated,
            "detection_occurred": self.detection_occurred,
            "is_false_positive": self.is_false_positive,
            "detection_time": self.detection_time,
            "containment_occurred": self.containment_occurred,
            "containment_time": self.containment_time,
            "response_latency": self.response_latency,
            "initial_risk_score": self.initial_risk_score,
            "final_risk_score": self.final_risk_score,
            "risk_delta": round(self.risk_delta, 1),
            "assets_compromised": self.assets_compromised,
            "assets_blocked": self.assets_blocked,
            "files_compromised": self.files_compromised,
            "files_blocked": self.files_blocked,
            "lateral_transitions_successful": self.lateral_transitions_successful,
            "sensitive_assets_reached": self.sensitive_assets_reached,
            "internal_assets_reached": self.internal_assets_reached,
        }


class ExperimentEngine:
    def __init__(self, project_root: Path, base_seed: int = 42):
        self.project_root = Path(project_root)
        self.base_seed = base_seed
        self.runner = SimulationRunner(self.project_root)
        self.trial_records: list[ExperimentTrialRecord] = []

    def run_benchmark(
        self,
        trials_per_vendor: int = 10,
        vendors: dict[str, VendorProfile] | None = None,
    ) -> list[ExperimentTrialRecord]:
        """Execute deterministic multi-trial benchmark across all synthetic vendors."""
        rng = random.Random(self.base_seed)
        vendor_dict = vendors or load_synthetic_vendors(self.project_root / "data" / "vendors.csv")

        self.trial_records.clear()
        trial_counter = 0

        attack_vectors = [
            "CREDENTIAL_COMPROMISE",
            "PRIVILEGE_ESCALATION",
            "LATERAL_PROBE",
            "NORMAL_SESSION",
        ]

        for vendor_id, vendor in vendor_dict.items():
            for t in range(trials_per_vendor):
                trial_counter += 1
                seed = rng.randint(1000, 999999)
                trial_rng = random.Random(seed)

                # Select vector: 75% adversarial vectors, 25% normal session
                vector = trial_rng.choice(attack_vectors)

                # --- Run Scenario 1: Baseline ---
                is_adv = (vector != "NORMAL_SESSION")
                res_baseline = self.runner.run_scenario_1_baseline(vendor, is_adversarial=is_adv)

                is_fp_base = (
                    vector == "NORMAL_SESSION" and len(res_baseline.alerts_generated) > 0
                )
                self.trial_records.append(
                    ExperimentTrialRecord(
                        trial_id=trial_counter,
                        seed=seed,
                        vendor_id=vendor_id,
                        scenario_type="BASELINE",
                        attack_vector=vector,
                        authenticated=res_baseline.authenticated,
                        detection_occurred=len(res_baseline.alerts_generated) > 0,
                        is_false_positive=is_fp_base,
                        detection_time=res_baseline.detection_time,
                        containment_occurred=res_baseline.incident_contained,
                        containment_time=res_baseline.containment_time,
                        response_latency=res_baseline.response_latency,
                        initial_risk_score=res_baseline.initial_risk.final_score,
                        final_risk_score=res_baseline.post_control_risk.final_score,
                        risk_delta=round(
                            res_baseline.post_control_risk.final_score - res_baseline.initial_risk.final_score,
                            1,
                        ),
                        assets_compromised=len(res_baseline.lateral_result.visited),
                        assets_blocked=res_baseline.lateral_result.transitions_blocked,
                        files_compromised=len(res_baseline.ransomware_report.encrypted),
                        files_blocked=len(res_baseline.ransomware_report.blocked),
                        lateral_transitions_successful=res_baseline.lateral_result.transitions_successful,
                        sensitive_assets_reached=_zone_reach_counts(res_baseline.lateral_result.visited)[0],
                        internal_assets_reached=_zone_reach_counts(res_baseline.lateral_result.visited)[1],
                    )
                )

                # --- Run Scenario 2: Protected ---
                # Main experiment: the compromised vendor identity is assumed to
                # already hold an authenticated session (see
                # SimulationRunner.run_scenario_2_protected docstring), so RBAC,
                # segmentation, detection and containment are what get tested --
                # not the MFA gate. MFA is covered separately by
                # tests/test_simulation.py::test_protected_mfa_gate_blocks_credential_only_compromise.
                attacker_has_mfa = (vector == "NORMAL_SESSION" and vendor.mfa_enabled)
                res_protected = self.runner.run_scenario_2_protected(
                    vendor,
                    simulate_credential_compromise=is_adv,
                    assume_authenticated_session=True,
                    attacker_has_mfa_token=attacker_has_mfa,
                    is_adversarial=is_adv,
                )

                # False positive: Alert fired on benign normal session
                is_fp_prot = (
                    vector == "NORMAL_SESSION"
                    and any(a.severity in ("CRITICAL", "HIGH") for a in res_protected.alerts_generated)
                )

                self.trial_records.append(
                    ExperimentTrialRecord(
                        trial_id=trial_counter,
                        seed=seed,
                        vendor_id=vendor_id,
                        scenario_type="PROTECTED",
                        attack_vector=vector,
                        authenticated=res_protected.authenticated,
                        detection_occurred=len(res_protected.alerts_generated) > 0,
                        is_false_positive=is_fp_prot,
                        detection_time=res_protected.detection_time,
                        containment_occurred=res_protected.incident_contained,
                        containment_time=res_protected.containment_time,
                        response_latency=res_protected.response_latency,
                        initial_risk_score=res_baseline.initial_risk.final_score,  # Compare from baseline risk
                        final_risk_score=res_protected.post_control_risk.final_score,
                        risk_delta=round(
                            res_protected.post_control_risk.final_score - res_baseline.initial_risk.final_score,
                            1,
                        ),
                        assets_compromised=len(res_protected.lateral_result.visited),
                        assets_blocked=res_protected.lateral_result.transitions_blocked,
                        files_compromised=len(res_protected.ransomware_report.encrypted),
                        files_blocked=len(res_protected.ransomware_report.blocked),
                        lateral_transitions_successful=res_protected.lateral_result.transitions_successful,
                        sensitive_assets_reached=_zone_reach_counts(res_protected.lateral_result.visited)[0],
                        internal_assets_reached=_zone_reach_counts(res_protected.lateral_result.visited)[1],
                    )
                )

        return self.trial_records
