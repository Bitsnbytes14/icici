"""Report and CSV artifact generator for CA-2 submission.

Exports:
  - CSV files of synthetic vendors, simulation trials, metrics, alerts, and incidents
  - A formatted markdown executive report with tables ready for the academic paper
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Sequence

from src.models.vendor import VendorProfile
from src.metrics.evaluator import ScenarioMetrics
from src.security.detection import Alert
from src.security.containment import IncidentRecord
from src.simulation.engine import ExperimentTrialRecord


class ReportGenerator:
    def __init__(self, results_dir: Path):
        self.results_dir = Path(results_dir)
        self.csv_dir = self.results_dir / "csv"
        self.charts_dir = self.results_dir / "charts"
        self.csv_dir.mkdir(parents=True, exist_ok=True)
        self.charts_dir.mkdir(parents=True, exist_ok=True)

    def export_vendors_csv(self, vendors: dict[str, VendorProfile]) -> Path:
        out_path = self.csv_dir / "vendors_summary.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Vendor ID", "Name", "Category", "Access Type", "Privilege Level",
                "MFA Enabled", "Duration (h)", "Accessible Systems", "Risk Tier",
                "Failed Auth", "Suspicious Flags"
            ])
            for v in vendors.values():
                writer.writerow([
                    v.vendor_id,
                    v.vendor_name,
                    v.vendor_type,
                    v.access_type.value,
                    v.privilege_level.value,
                    v.mfa_enabled,
                    v.access_duration_hours,
                    "; ".join(v.systems_accessible),
                    v.risk_tier.value,
                    v.failed_auth_count,
                    "; ".join(v.suspicious_flags) if v.suspicious_flags else "none",
                ])
        return out_path

    def export_trials_csv(self, trials: Sequence[ExperimentTrialRecord]) -> Path:
        out_path = self.csv_dir / "trial_records.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            if not trials:
                return out_path
            headers = list(trials[0].to_dict().keys())
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for t in trials:
                writer.writerow(t.to_dict())
        return out_path

    def export_alerts_csv(self, alerts: Sequence[Alert]) -> Path:
        out_path = self.csv_dir / "sample_alerts.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Rule", "Vendor", "Target", "Severity", "Risk Score", "Reason", "Action"])
            for a in alerts:
                writer.writerow([
                    a.timestamp,
                    a.rule,
                    a.vendor,
                    a.target,
                    a.severity,
                    a.risk_score,
                    a.reason,
                    a.recommended_action,
                ])
        return out_path

    def export_incident_timeline_csv(self, incidents: Sequence[IncidentRecord]) -> Path:
        out_path = self.csv_dir / "incident_timeline.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Incident ID", "Vendor", "Trigger Rule", "Severity",
                "Detection Time (s)", "Containment Time (s)", "Latency (s)", "Mitigation Actions"
            ])
            for inc in incidents:
                writer.writerow([
                    inc.incident_id,
                    inc.vendor,
                    inc.trigger_rule,
                    inc.trigger_severity,
                    inc.detection_timestamp,
                    inc.containment_timestamp,
                    inc.response_duration_seconds,
                    " -> ".join(inc.actions_taken),
                ])
        return out_path

    def generate_markdown_summary(
        self,
        metrics: dict[str, ScenarioMetrics],
        vendors: dict[str, VendorProfile],
        output_file: Path | None = None,
    ) -> Path:
        out_path = output_file or (self.results_dir / "summary_report.md")
        b = metrics["BASELINE"]
        p = metrics["PROTECTED"]

        content = f"""# CA-2 Experimental Results & Findings

## Academic Case Study: Third-Party Vendor Access as a Ransomware Vector
**Target Institutional Context:** Banking Environment (Inspired by 2025–26 Threat Claims)  
**Safety Protocol:** Strictly Safe In-Memory Simulation & Sandboxed File Markers  
**Random Seed:** 42 (Fully Reproducible)

---

### 1. Comparative Performance Summary

| Metric Dimension | Baseline (Legacy Trust) | Protected (Zero-Trust Controls) | Improvement / Delta |
| :--- | :--- | :--- | :--- |
| **Total Multi-Vendor Trials** | {b.total_trials} | {p.total_trials} | Identical cohort size |
| **Detection Rate (%)** | {b.detection_rate_pct}% | {p.detection_rate_pct}% | **+{round(p.detection_rate_pct - b.detection_rate_pct, 1)}%** |
| **False Positive Rate (%)** | {b.false_positive_rate_pct}% | {p.false_positive_rate_pct}% | {p.false_positive_rate_pct}% (Low friction) |
| **Mean Detection Time (s)** | {b.mean_detection_time_sec}s | {p.mean_detection_time_sec}s | Fast anomaly triage |
| **Mean Time to Contain (s)** | {b.mean_time_to_contain_sec}s | {p.mean_time_to_contain_sec}s | Rapid automated isolation |
| **Containment Rate (%)** | {b.containment_rate_pct}% | {p.containment_rate_pct}% | **+{round(p.containment_rate_pct - b.containment_rate_pct, 1)}%** |
| **Mean Pre-Control Risk Score** | {b.mean_initial_risk} | {b.mean_initial_risk} | Identical baseline posture |
| **Mean Post-Control Risk Score** | {b.mean_final_risk} | {p.mean_final_risk} | **-{round(b.mean_final_risk - p.mean_final_risk, 1)} pts** |
| **Relative Risk Reduction (%)** | {b.risk_reduction_pct}% | {p.risk_reduction_pct}% | **+{p.risk_reduction_pct}%** |
| **Avg Assets Compromised / Run** | {b.mean_assets_compromised} | {p.mean_assets_compromised} | Reduced lateral spread |
| **Avg Successful Lateral Steps / Run** | {b.mean_lateral_transitions_successful} | {p.mean_lateral_transitions_successful} | Segmentation attenuation |
| **Avg Sensitive/Backup Assets Reached** | {b.mean_sensitive_assets_reached} | {p.mean_sensitive_assets_reached} | Tier-0 exposure |
| **Avg Files Encrypted / Run** | {b.mean_files_compromised} | {p.mean_files_compromised} | Blast radius halted |
| **File Protection Rate (%)** | {b.file_protection_rate_pct}% | {p.file_protection_rate_pct}% | **+{round(p.file_protection_rate_pct - b.file_protection_rate_pct, 1)}%** |

---

### 2. Key Academic Findings for Report Discussion

**Experimental configuration note:** the Protected scenario below models a vendor
identity that has **already compromised credentials and holds an authenticated
session** (`credential_compromised = True`, `authenticated_session = True`) --
the research question is what happens *after* that point, not whether MFA can
be defeated. MFA remains part of the architecture and is evaluated separately
as a standalone control test (see `docs/METHODOLOGY.md` and
`tests/test_simulation.py::test_protected_mfa_gate_blocks_credential_only_compromise`),
where a credential-only compromise with no second factor is correctly blocked
before it ever reaches RBAC or segmentation.

1. **Ransomware Vector Elimination via Defense-in-Depth:**
   - In the baseline environment, a single compromised vendor credential allowed full traversal from `vendor_portal` across internal tiers to `customer_database` and `backup_server`, resulting in an average of **{b.mean_files_compromised} files marked as encrypted** per run.
   - Under Zero-Trust controls, an *already-authenticated* compromised session was still confined by least-privilege RBAC and strict zone segmentation, which limited lateral movement to **{p.mean_lateral_transitions_successful} successful hop(s)/run** and **{p.mean_sensitive_assets_reached} sensitive/backup asset(s) reached/run** on average -- yielding a **{p.file_protection_rate_pct}% file protection rate** once detection and automated containment isolated the session.

2. **Automated Incident Response vs Lateral Traversal:**
   - Active detection identified anomalies within **{p.mean_detection_time_sec}s** and triggered automated session isolation in **{p.mean_time_to_contain_sec}s**, halting lateral movement before sensitive data stores could be enumerated.

3. **Vendor Risk Scoring Governance:**
   - The multi-factor scoring model effectively differentiated low-privilege contractors from high-privilege administrators. This is a project-specific, transparent scoring model (see `docs/METHODOLOGY.md` Section 6) -- not an industry-standard cybersecurity metric.
   - Enforcing Just-in-Time (JIT) access windows and least-privilege RBAC reduced average vendor risk exposure by **{p.risk_reduction_pct}%**.

4. **Repeated vs. independent trials:** each configuration is evaluated over **50 repeated simulation runs** (5 synthetic vendor profiles x 10 runs each, seed=42). The attacker follows a fixed, deterministic playbook (probe -> attempted privilege escalation -> attempted lateral movement -> attempted ransomware impact) per vendor, so repeated runs for the same vendor produce identical outcomes; per-vendor variation (privilege level, MFA posture, accessible systems) is what drives the differences seen across the cohort. These are **50 repeated simulation runs per configuration**, not 100 independent real-world experiments.

---

### 3. Generated Visualizations for CA Report

- `results/charts/fig1_vendor_risk_comparison.png`: Risk Score before and after defensive controls.
- `results/charts/fig2_detection_containment_efficacy.png`: Detection and containment percentage rates.
- `results/charts/fig3_response_timing_profile.png`: Mean detection time vs containment latency.
- `results/charts/fig4_blast_radius_mitigation.png`: Asset and file blast radius comparison.
- `results/charts/fig5_defense_in_depth_layers.png`: Proportion of attacks blocked at each control layer.
"""
        out_path.write_text(content, encoding="utf-8")
        return out_path
