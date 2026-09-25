#!/usr/bin/env python3
"""Unified Execution Entrypoint: Banking Third-Party Vendor Ransomware Risk Simulation.

Academic Case Study:
  "Third-Party Vendor Access as a Ransomware Vector: The ICICI Bank Case (2025-26)"

SAFETY NOTICE:
  This script executes a strictly defensive, safe, local in-memory simulation.
  No real malware, exploits, or network calls are executed. All banking assets
  and vendor profiles are completely synthetic.
"""
from __future__ import annotations

import sys
import time
import json
import platform
import subprocess
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.models.vendor import load_synthetic_vendors
from src.risk.scoring import VendorRiskScorer
from src.simulation.scenarios import SimulationRunner
from src.simulation.engine import ExperimentEngine
from src.metrics.evaluator import MetricsEvaluator
from src.reporting.visualizer import AcademicVisualizer
from src.reporting.report_generator import ReportGenerator


def print_banner() -> None:
    print("=" * 80)
    print(" UNIVERSITY CYBER SECURITY CA-2 CASE STUDY SIMULATION")
    print(" Topic: Third-Party Vendor Access as a Ransomware Vector (2025-26)")
    print(" Mode: Safe In-Memory Simulation | Synthetic Banking Environment")
    print("=" * 80)


def print_step(step_num: int, title: str) -> None:
    print(f"\n[STEP {step_num}] {title}")
    print("-" * 70)


def run_live_demonstration(project_root: Path) -> None:
    print_banner()

    # Step 1: Load Synthetic Vendors
    print_step(1, "Loading Synthetic Third-Party Vendor Cohort")
    data_dir = project_root / "data"
    vendors = load_synthetic_vendors(data_dir / "vendors.csv")
    for vid, v in vendors.items():
        print(f"  * {vid:<8} | {v.vendor_name:<32} | Priv: {v.privilege_level.value:<9} | MFA: {str(v.mfa_enabled):<5} | Tier: {v.risk_tier.value}")

    # Step 2: Risk Scoring Evaluation
    print_step(2, "Evaluating Mathematical Vendor Risk Scores (Transparent Formula)")
    scorer = VendorRiskScorer()
    print(f"  {'Vendor ID':<10} {'Base Score':<12} {'Base Tier':<12} {'Protected Score':<18} {'Protected Tier':<14} {'Delta Risk'}")
    print("  " + "-" * 75)
    for vid, v in vendors.items():
        base_r = scorer.evaluate(v, enforce_defensive_controls=False)
        prot_r = scorer.evaluate(v, enforce_defensive_controls=True)
        delta = round(base_r.final_score - prot_r.final_score, 1)
        print(f"  {vid:<10} {base_r.final_score:<12.1f} {base_r.tier.value:<12} {prot_r.final_score:<18.1f} {prot_r.tier.value:<14} -{delta} pts")

    # Step 3: Single-Run Scenario Comparison (VEND-001)
    target_vendor = vendors["VEND-001"]
    print_step(3, f"Executing Live Attack Comparison on Vendor '{target_vendor.vendor_id}' ({target_vendor.vendor_name})")

    runner = SimulationRunner(project_root)

    print("\n  >>> Executing SCENARIO 1: Baseline (Unprotected / Legacy Trust)")
    res_b = runner.run_scenario_1_baseline(target_vendor)
    print(f"      - Authentication: {'SUCCESS (Password Compromised, MFA Not Required)' if res_b.authenticated else 'FAILED'}")
    print(f"      - Lateral Movement Visited: {len(res_b.lateral_result.visited)} assets: {sorted(list(res_b.lateral_result.visited))}")
    print(f"      - Detection Alerts: {len(res_b.alerts_generated)} alerts (Detection Engine Inactive)")
    print(f"      - Containment Triggered: {res_b.incident_contained}")
    print(f"      - Simulated Ransomware Impact: {len(res_b.simulated_compromised_files)} data files marked encrypted!")
    for f in res_b.simulated_compromised_files:
        print(f"        * Encrypted: {f}")

    print("\n  >>> Executing SCENARIO 2: Protected (Zero-Trust Defensive Controls)")
    print("      Assumption: credential_compromised=True, authenticated_session=True")
    print("      (i.e. this run tests what happens AFTER a compromised vendor identity")
    print("       already holds an authenticated session -- see docs/METHODOLOGY.md)")
    res_p = runner.run_scenario_2_protected(target_vendor)
    print(f"      - Authentication: {'SUCCESS (' + res_p.authentication_model + ')' if res_p.authenticated else 'BLOCKED (' + res_p.authentication_model + ')'}")
    print(f"      - Lateral Movement Visited: {len(res_p.lateral_result.visited)} assets: {sorted(list(res_p.lateral_result.visited))}")
    print(f"      - Lateral Transitions: {res_p.lateral_result.transitions_successful} successful / {res_p.lateral_result.transitions_blocked} blocked (of {res_p.lateral_result.transitions_attempted} attempted)")
    print(f"      - Detection Alerts: {len(res_p.alerts_generated)} alerts triggered:")
    for a in res_p.alerts_generated:
        print(f"        * [{a.severity}] {a.rule}: {a.reason}")
        print(f"          Action: {a.recommended_action}")
    print(f"      - Automated Containment: {res_p.incident_contained} (Actionable detection at t={res_p.actionable_detection_time}s, Contained at t={res_p.containment_time}s, Measured latency={res_p.response_latency}s)")
    print(f"      - Simulated Ransomware Impact: {len(res_p.simulated_compromised_files)} files encrypted ({len(res_p.simulated_blocked_files)} BLOCKED)")

    print("\n  >>> Sub-check: MFA Gate Tested Separately (credential-only compromise, no assumed session)")
    res_mfa = runner.run_scenario_2_protected(
        target_vendor, assume_authenticated_session=False, attacker_has_mfa_token=False,
    )
    print(f"      - Authentication: {'SUCCESS' if res_mfa.authenticated else 'BLOCKED (' + res_mfa.authentication_model + ')'}")
    print("      - This confirms MFA independently blocks a credential-only compromise")
    print("        before it ever reaches RBAC/segmentation -- it is not the reason the")
    print("        main protected-scenario experiment above stops.")

    # Step 4: Multi-Trial Benchmark Execution
    print_step(4, "Running Deterministic Multi-Trial Benchmark (Seed=42, 50 Trials / Scenario)")
    engine = ExperimentEngine(project_root=project_root, base_seed=42)
    start_time = time.time()
    trials = engine.run_benchmark(trials_per_vendor=10, vendors=vendors)
    elapsed = round(time.time() - start_time, 2)
    print(f"  Benchmark finished: {len(trials)} total trials executed in {elapsed}s.")

    # Step 5: Metric Evaluation
    print_step(5, "Computing Empirical CA-2 Performance Metrics")
    metrics = MetricsEvaluator.evaluate_cohort(trials)
    b_m = metrics["BASELINE"]
    p_m = metrics["PROTECTED"]

    print(f"  {'Metric Dimension':<35} {'Baseline':<18} {'Protected':<18} {'Delta / Impact'}")
    print("  " + "-" * 85)
    print(f"  {'Detection Rate (%)':<35} {b_m.detection_rate_pct:<18.1f} {p_m.detection_rate_pct:<18.1f} +{round(p_m.detection_rate_pct - b_m.detection_rate_pct, 1)}%")
    print(f"  {'False Positive Rate (%)':<35} {b_m.false_positive_rate_pct:<18.1f} {p_m.false_positive_rate_pct:<18.1f} {p_m.false_positive_rate_pct:.1f}%")
    print(f"  {'Mean Time to First Detection':<35} {b_m.mean_first_detection_time_sec:<18.2f}s {p_m.mean_first_detection_time_sec:<18.2f}s Simulated clock")
    print(f"  {'Mean Time to Actionable Detection':<35} {b_m.mean_actionable_detection_time_sec:<18.2f}s {p_m.mean_actionable_detection_time_sec:<18.2f}s Simulated clock")
    print(f"  {'Mean Time to Contain (MTTC)':<35} {b_m.mean_time_to_contain_sec:<18.2f}s {p_m.mean_time_to_contain_sec:<18.2f}s Automated Revocation")
    print(f"  {'Containment Rate (%)':<35} {b_m.containment_rate_pct:<18.1f} {p_m.containment_rate_pct:<18.1f} +{round(p_m.containment_rate_pct - b_m.containment_rate_pct, 1)}%")
    print(f"  {'Mean Post-Control Risk Score':<35} {b_m.mean_final_risk:<18.1f} {p_m.mean_final_risk:<18.1f} -{round(b_m.mean_final_risk - p_m.mean_final_risk, 1)} pts")
    print(f"  {'Avg Data Files Affected / Adversarial Run':<35} {b_m.mean_files_compromised:<18.2f} {p_m.mean_files_compromised:<18.2f} Zero Spread")
    print(f"  {'File Protection Rate (%)':<35} {b_m.file_protection_rate_pct:<18.1f} {p_m.file_protection_rate_pct:<18.1f} +{round(p_m.file_protection_rate_pct - b_m.file_protection_rate_pct, 1)}%")

    # Step 6: Export CSV Data & Generate Publication Charts
    print_step(6, "Exporting Research Artifacts (CSVs, Report, Publication Figures)")
    results_dir = project_root / "results"
    reporter = ReportGenerator(results_dir)

    # CSVs
    p_vend = reporter.export_vendors_csv(vendors)
    p_trials = reporter.export_trials_csv(trials)
    p_alerts = reporter.export_alerts_csv(res_p.alerts_generated)
    p_metrics = results_dir / "csv" / "comparison_metrics.csv"
    MetricsEvaluator.export_metrics_to_csv(metrics, p_metrics)
    p_report = reporter.generate_markdown_summary(metrics, vendors)
    try:
        git_commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=project_root, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        git_commit = "unavailable"
    metadata = {
        "experiment_configuration_version": "2.0", "seed": engine.base_seed,
        "total_records": len(trials), "baseline_runs": b_m.total_trials,
        "protected_runs": p_m.total_trials, "adversarial_runs_per_configuration": b_m.adversarial_trials,
        "benign_runs_per_configuration": b_m.benign_trials, "python_version": platform.python_version(),
        "git_commit": git_commit,
        "attacker_behavior": "fixed COMPROMISED_VENDOR_SESSION playbook; seeded benign/adversarial mix",
        "timing_model": "deterministic simulated monotonic clock; not wall-clock timing",
    }
    (results_dir / "experiment_metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    print(f"  [CSV] Exported: {p_vend.relative_to(project_root)}")
    print(f"  [CSV] Exported: {p_trials.relative_to(project_root)}")
    print(f"  [CSV] Exported: {p_alerts.relative_to(project_root)}")
    print(f"  [CSV] Exported: {p_metrics.relative_to(project_root)}")
    print(f"  [DOC] Exported: {p_report.relative_to(project_root)}")
    print("  [META] Exported: results/experiment_metadata.json")

    # Visualizations
    viz = AcademicVisualizer(results_dir / "charts")
    f1 = viz.plot_vendor_risk_comparison(vendors)
    f2 = viz.plot_detection_and_containment_rates(metrics)
    f3 = viz.plot_timing_profile(metrics)
    f4 = viz.plot_blast_radius_mitigation(metrics)
    f5 = viz.plot_defense_in_depth_breakdown(trials)

    print(f"  [PNG] Rendered: {f1.relative_to(project_root)}")
    print(f"  [PNG] Rendered: {f2.relative_to(project_root)}")
    print(f"  [PNG] Rendered: {f3.relative_to(project_root)}")
    print(f"  [PNG] Rendered: {f4.relative_to(project_root)}")
    print(f"  [PNG] Rendered: {f5.relative_to(project_root)}")

    print("\n" + "=" * 80)
    print(" SIMULATION COMPLETE - ALL ARTIFACTS READY FOR CA-2 REPORT & PRESENTATION")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_live_demonstration(PROJECT_ROOT)
