"""Metrics calculated from trial records, with adversarial impact kept separate from benign behavior."""
from __future__ import annotations
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from src.simulation.engine import ExperimentTrialRecord

@dataclass
class ScenarioMetrics:
    scenario_type: str; total_trials: int; adversarial_trials: int; benign_trials: int
    detection_rate_pct: float; false_positive_rate_pct: float; benign_legitimate_access_rate_pct: float
    mean_first_detection_time_sec: float; mean_actionable_detection_time_sec: float; mean_time_to_contain_sec: float; containment_rate_pct: float
    mean_initial_risk: float; mean_final_risk: float; mean_risk_reduction: float; risk_reduction_pct: float
    mean_accessible_assets: float; mean_files_compromised: float; file_protection_rate_pct: float
    mean_lateral_transitions_successful: float; mean_sensitive_assets_reached: float; mean_internal_assets_reached: float
    def to_dict(self) -> dict: return self.__dict__.copy() | {"Scenario": self.scenario_type}

def _mean(items: list[float]) -> float: return round(sum(items) / len(items), 3) if items else 0.0

class MetricsEvaluator:
    @staticmethod
    def evaluate_cohort(trials: Sequence[ExperimentTrialRecord]) -> dict[str, ScenarioMetrics]:
        out = {}
        for scenario in ("BASELINE", "PROTECTED"):
            rows = [t for t in trials if t.scenario_type == scenario]
            if not rows: continue
            adv = [t for t in rows if t.attacker_behavior == "COMPROMISED_VENDOR_SESSION"]; benign = [t for t in rows if t.attacker_behavior == "NORMAL_VENDOR_SESSION"]
            detected = [t for t in adv if t.detection_occurred]; contained = [t for t in adv if t.containment_occurred]
            initial, final = _mean([t.initial_risk_score for t in rows]), _mean([t.final_risk_score for t in rows]); reduction = round(initial - final, 1)
            targets = sum(t.ransomware_targets for t in adv); files = sum(t.files_compromised for t in adv)
            out[scenario] = ScenarioMetrics(scenario, len(rows), len(adv), len(benign), round(len(detected) / len(adv) * 100, 1) if adv else 0.0,
                round(sum(t.is_false_positive for t in benign) / len(benign) * 100, 1) if benign else 0.0,
                round(sum(t.authenticated for t in benign) / len(benign) * 100, 1) if benign else 0.0,
                _mean([t.first_detection_time for t in adv if t.first_detection_time is not None]), _mean([t.actionable_detection_time for t in adv if t.actionable_detection_time is not None]), _mean([t.response_latency for t in adv if t.response_latency is not None]), round(len(contained) / len(adv) * 100, 1) if adv else 0.0,
                initial, final, reduction, round(reduction / initial * 100, 1) if initial else 0.0,
                _mean([t.accessible_assets for t in adv]), _mean([t.files_compromised for t in adv]), round((1 - files / targets) * 100, 1) if targets else 0.0,
                _mean([t.lateral_transitions_successful for t in adv]), _mean([t.sensitive_assets_reached for t in adv]), _mean([t.internal_assets_reached for t in adv]))
        return out
    @staticmethod
    def export_metrics_to_csv(metrics: dict[str, ScenarioMetrics], output_csv: Path) -> None:
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        rows = [m.to_dict() for m in metrics.values()]
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
