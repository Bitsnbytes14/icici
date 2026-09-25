"""Academic Metrics Evaluation Engine.

Computes empirical performance metrics:
  - Detection Rate (%)
  - False Positive Rate (%)
  - Mean Detection Time (MDT in seconds)
  - Mean Time to Containment (MTTC in seconds)
  - Risk Score Reduction (Points and %)
  - Containment Rate (%)
  - Asset & File Blast Radius Prevention
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from src.simulation.engine import ExperimentTrialRecord


@dataclass
class ScenarioMetrics:
    scenario_type: str
    total_trials: int
    adversarial_trials: int
    benign_trials: int
    detection_rate_pct: float
    false_positive_rate_pct: float
    mean_detection_time_sec: float
    mean_time_to_contain_sec: float
    containment_rate_pct: float
    mean_initial_risk: float
    mean_final_risk: float
    mean_risk_reduction: float
    risk_reduction_pct: float
    mean_assets_compromised: float
    mean_files_compromised: float
    file_protection_rate_pct: float
    mean_lateral_transitions_successful: float
    mean_sensitive_assets_reached: float
    mean_internal_assets_reached: float

    def to_dict(self) -> dict:
        return {
            "Scenario": self.scenario_type,
            "Total Trials": self.total_trials,
            "Adversarial Trials": self.adversarial_trials,
            "Benign Trials": self.benign_trials,
            "Detection Rate (%)": self.detection_rate_pct,
            "False Positive Rate (%)": self.false_positive_rate_pct,
            "Mean Detection Time (s)": self.mean_detection_time_sec,
            "Mean Time to Contain (s)": self.mean_time_to_contain_sec,
            "Containment Rate (%)": self.containment_rate_pct,
            "Mean Initial Risk": self.mean_initial_risk,
            "Mean Final Risk": self.mean_final_risk,
            "Risk Reduction (pts)": self.mean_risk_reduction,
            "Risk Reduction (%)": self.risk_reduction_pct,
            "Avg Assets Compromised": self.mean_assets_compromised,
            "Avg Files Compromised": self.mean_files_compromised,
            "File Protection Rate (%)": self.file_protection_rate_pct,
            "Avg Successful Lateral Steps": self.mean_lateral_transitions_successful,
            "Avg Sensitive/Backup Assets Reached": self.mean_sensitive_assets_reached,
            "Avg Internal Assets Reached": self.mean_internal_assets_reached,
        }


class MetricsEvaluator:
    @staticmethod
    def evaluate_cohort(trials: Sequence[ExperimentTrialRecord]) -> dict[str, ScenarioMetrics]:
        results: dict[str, ScenarioMetrics] = {}

        for scenario in ("BASELINE", "PROTECTED"):
            sc_trials = [t for t in trials if t.scenario_type == scenario]
            if not sc_trials:
                continue

            adv_trials = [t for t in sc_trials if t.attack_vector != "NORMAL_SESSION"]
            ben_trials = [t for t in sc_trials if t.attack_vector == "NORMAL_SESSION"]

            # Detection Rate on Adversarial trials
            detected_adv = [t for t in adv_trials if t.detection_occurred]
            det_rate = (len(detected_adv) / len(adv_trials) * 100.0) if adv_trials else 0.0

            # False Positive Rate on Benign trials
            fp_trials = [t for t in ben_trials if t.is_false_positive]
            fpr = (len(fp_trials) / len(ben_trials) * 100.0) if ben_trials else 0.0

            # Mean Detection Time
            det_times = [t.detection_time for t in adv_trials if t.detection_time is not None]
            mdt = round(sum(det_times) / len(det_times), 3) if det_times else 0.0

            # Mean Time to Containment (MTTC)
            contain_times = [t.response_latency for t in adv_trials if t.response_latency is not None]
            mttc = round(sum(contain_times) / len(contain_times), 3) if contain_times else 0.0

            # Containment Rate
            contained_adv = [t for t in adv_trials if t.containment_occurred]
            contain_rate = (len(contained_adv) / len(adv_trials) * 100.0) if adv_trials else 0.0

            # Risk Scores
            avg_init_risk = round(sum(t.initial_risk_score for t in sc_trials) / len(sc_trials), 1)
            avg_final_risk = round(sum(t.final_risk_score for t in sc_trials) / len(sc_trials), 1)
            risk_red = round(avg_init_risk - avg_final_risk, 1)
            risk_red_pct = round((risk_red / avg_init_risk * 100.0), 1) if avg_init_risk > 0 else 0.0

            # Impact
            avg_assets = round(sum(t.assets_compromised for t in sc_trials) / len(sc_trials), 2)
            avg_files = round(sum(t.files_compromised for t in sc_trials) / len(sc_trials), 2)
            total_possible_files = 5.0  # FILE_MAP has 5 encryptable files
            prot_rate = round((1.0 - (avg_files / total_possible_files)) * 100.0, 1)
            avg_lateral_success = round(
                sum(t.lateral_transitions_successful for t in sc_trials) / len(sc_trials), 2
            )
            avg_sensitive_reached = round(
                sum(t.sensitive_assets_reached for t in sc_trials) / len(sc_trials), 2
            )
            avg_internal_reached = round(
                sum(t.internal_assets_reached for t in sc_trials) / len(sc_trials), 2
            )

            results[scenario] = ScenarioMetrics(
                scenario_type=scenario,
                total_trials=len(sc_trials),
                adversarial_trials=len(adv_trials),
                benign_trials=len(ben_trials),
                detection_rate_pct=round(det_rate, 1),
                false_positive_rate_pct=round(fpr, 1),
                mean_detection_time_sec=mdt,
                mean_time_to_contain_sec=mttc,
                containment_rate_pct=round(contain_rate, 1),
                mean_initial_risk=avg_init_risk,
                mean_final_risk=avg_final_risk,
                mean_risk_reduction=risk_red,
                risk_reduction_pct=risk_red_pct,
                mean_assets_compromised=avg_assets,
                mean_files_compromised=avg_files,
                file_protection_rate_pct=prot_rate,
                mean_lateral_transitions_successful=avg_lateral_success,
                mean_sensitive_assets_reached=avg_sensitive_reached,
                mean_internal_assets_reached=avg_internal_reached,
            )

        return results

    @staticmethod
    def export_metrics_to_csv(metrics: dict[str, ScenarioMetrics], output_csv: Path) -> None:
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            headers = [
                "Scenario",
                "Total Trials",
                "Detection Rate (%)",
                "False Positive Rate (%)",
                "MDT (s)",
                "MTTC (s)",
                "Containment Rate (%)",
                "Mean Initial Risk",
                "Mean Final Risk",
                "Risk Reduction (%)",
                "Avg Compromised Files",
                "File Protection Rate (%)",
                "Avg Successful Lateral Steps",
                "Avg Sensitive/Backup Assets Reached",
                "Avg Internal Assets Reached",
            ]
            writer.writerow(headers)
            for m in metrics.values():
                writer.writerow([
                    m.scenario_type,
                    m.total_trials,
                    m.detection_rate_pct,
                    m.false_positive_rate_pct,
                    m.mean_detection_time_sec,
                    m.mean_time_to_contain_sec,
                    m.containment_rate_pct,
                    m.mean_initial_risk,
                    m.mean_final_risk,
                    m.risk_reduction_pct,
                    m.mean_files_compromised,
                    m.file_protection_rate_pct,
                    m.mean_lateral_transitions_successful,
                    m.mean_sensitive_assets_reached,
                    m.mean_internal_assets_reached,
                ])
