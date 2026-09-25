"""Deterministic repeated-run benchmark engine."""
from __future__ import annotations
import random
from dataclasses import dataclass
from pathlib import Path
from src.models.resource import RESOURCE_CATALOG, Zone
from src.models.vendor import VendorProfile, load_synthetic_vendors
from src.simulation.scenarios import SimulationRunner

def _zone_reach_counts(visited: set[str]) -> tuple[int, int]:
    return (sum(RESOURCE_CATALOG[n].zone in (Zone.SENSITIVE, Zone.BACKUP) for n in visited), sum(RESOURCE_CATALOG[n].zone == Zone.INTERNAL for n in visited))

@dataclass
class ExperimentTrialRecord:
    trial_id: int; seed: int; vendor_id: str; scenario_type: str; attacker_behavior: str; authenticated: bool
    detection_occurred: bool; is_false_positive: bool; first_detection_time: float | None; actionable_detection_time: float | None
    containment_occurred: bool; containment_time: float | None; response_latency: float | None
    initial_risk_score: float; final_risk_score: float; risk_delta: float
    accessible_assets: int; assets_blocked: int; ransomware_targets: int; files_compromised: int; files_blocked: int
    lateral_transitions_successful: int; sensitive_assets_reached: int; internal_assets_reached: int
    def to_dict(self) -> dict:
        return self.__dict__.copy() | {"risk_delta": round(self.risk_delta, 1)}

class ExperimentEngine:
    def __init__(self, project_root: Path, base_seed: int = 42):
        self.project_root = Path(project_root); self.base_seed = base_seed; self.runner = SimulationRunner(self.project_root); self.trial_records: list[ExperimentTrialRecord] = []
    def run_benchmark(self, trials_per_vendor: int = 10, vendors: dict[str, VendorProfile] | None = None) -> list[ExperimentTrialRecord]:
        rng = random.Random(self.base_seed); vendor_dict = vendors or load_synthetic_vendors(self.project_root / "data" / "vendors.csv"); self.trial_records.clear(); counter = 0
        for vendor_id, vendor in vendor_dict.items():
            for _ in range(trials_per_vendor):
                counter += 1; seed = rng.randint(1000, 999999)
                # Seeded selection governs the documented benign/adversarial mix;
                # adversarial repetitions deliberately use the same fixed playbook.
                behavior = random.Random(seed).choice((
                    "COMPROMISED_VENDOR_SESSION", "COMPROMISED_VENDOR_SESSION",
                    "COMPROMISED_VENDOR_SESSION", "NORMAL_VENDOR_SESSION",
                ))
                adversarial = behavior == "COMPROMISED_VENDOR_SESSION"
                common = {"trial_id": counter, "seed": seed, "vendor_id": vendor_id, "attacker_behavior": behavior}
                logs = self.project_root / "logs" / "trials"
                baseline = self.runner.run_scenario_1_baseline(vendor, logs / f"trial_{counter:04d}_baseline.jsonl", adversarial, {**common, "scenario_type": "BASELINE"})
                protected = self.runner.run_scenario_2_protected(vendor, logs / f"trial_{counter:04d}_protected.jsonl", adversarial, True, False, adversarial, {**common, "scenario_type": "PROTECTED"})
                for scenario, result, initial in (("BASELINE", baseline, baseline.initial_risk.final_score), ("PROTECTED", protected, baseline.initial_risk.final_score)):
                    sensitive, internal = _zone_reach_counts(result.lateral_result.visited)
                    self.trial_records.append(ExperimentTrialRecord(counter, seed, vendor_id, scenario, behavior, result.authenticated,
                        bool(result.alerts_generated), not adversarial and any(a.severity in ("HIGH", "CRITICAL") for a in result.alerts_generated), result.first_detection_time, result.actionable_detection_time,
                        result.incident_contained, result.containment_time, result.response_latency, initial, result.post_control_risk.final_score, result.post_control_risk.final_score - initial,
                        len(result.lateral_result.visited), result.lateral_result.transitions_blocked, len(result.ransomware_report.targeted), len(result.ransomware_report.encrypted), len(result.ransomware_report.blocked), result.lateral_result.transitions_successful, sensitive, internal))
        return self.trial_records
