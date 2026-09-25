"""Academic Figure Generator for CA-2 Case Study Report.

Renders publication-quality, high-DPI (300 DPI) comparison charts:
  1. Vendor Risk Score Reduction (Before vs After Controls)
  2. Detection & Containment Efficacy (Baseline vs Protected)
  3. Response Timing Profile (Mean Detection Time vs Containment Latency)
  4. Blast Radius Mitigation (Compromised Banking Files & Assets)
  5. False Positive vs True Positive Trade-off
  6. Defense-in-Depth Layer Attribution
"""
from __future__ import annotations

from pathlib import Path
from typing import Sequence
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np

from src.models.vendor import VendorProfile
from src.risk.scoring import VendorRiskScorer
from src.metrics.evaluator import ScenarioMetrics
from src.simulation.engine import ExperimentTrialRecord


class AcademicVisualizer:
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Apply clean publication style
        plt.rcParams.update({
            "font.family": "sans-serif",
            "font.size": 10,
            "axes.titlesize": 12,
            "axes.titleweight": "bold",
            "axes.labelsize": 10,
            "axes.labelweight": "semibold",
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "legend.fontsize": 9,
            "figure.titlesize": 14,
        })

    def plot_vendor_risk_comparison(
        self,
        vendors: dict[str, VendorProfile],
        filename: str = "fig1_vendor_risk_comparison.png",
    ) -> Path:
        """Figure 1: Vendor Risk Score Before vs After Defensive Controls."""
        scorer = VendorRiskScorer()
        vendor_ids = list(vendors.keys())
        baseline_scores = [
            scorer.evaluate(v, enforce_defensive_controls=False).final_score
            for v in vendors.values()
        ]
        protected_scores = [
            scorer.evaluate(v, enforce_defensive_controls=True).final_score
            for v in vendors.values()
        ]

        x = np.arange(len(vendor_ids))
        width = 0.35

        fig, ax = plt.subplots(figsize=(8, 4.8), dpi=300)
        rects1 = ax.bar(x - width / 2, baseline_scores, width, label="Baseline (Legacy Trust)", color="#dc2626")
        rects2 = ax.bar(x + width / 2, protected_scores, width, label="Protected (Zero-Trust)", color="#16a34a")

        # Threshold bands
        ax.axhline(80, color="#7f1d1d", linestyle="--", alpha=0.5, label="Critical Risk Threshold (80)")
        ax.axhline(60, color="#ea580c", linestyle=":", alpha=0.5, label="High Risk Threshold (60)")
        ax.axhline(30, color="#ca8a04", linestyle="-.", alpha=0.4, label="Medium Risk Threshold (30)")

        ax.set_ylabel("Calculated Risk Score (0 - 100)")
        ax.set_title("Vendor Risk Score Mitigation Across Synthetic Cohorts")
        ax.set_xticks(x)
        ax.set_xticklabels([f"{vid}\n({vendors[vid].vendor_name[:12]}..)" for vid in vendor_ids])
        ax.set_ylim(0, 105)
        ax.legend(loc="upper right", framealpha=0.9)
        ax.grid(axis="y", linestyle=":", alpha=0.6)

        # Bar value annotations
        for rect in rects1:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}", xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)
        for rect in rects2:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}", xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)

        fig.tight_layout()
        out_path = self.output_dir / filename
        fig.savefig(out_path)
        plt.close(fig)
        return out_path

    def plot_detection_and_containment_rates(
        self,
        metrics: dict[str, ScenarioMetrics],
        filename: str = "fig2_detection_containment_efficacy.png",
    ) -> Path:
        """Figure 2: Detection Rate and Containment Rate Comparison."""
        categories = ["Detection Rate (%)", "Containment Rate (%)", "File Protection Rate (%)"]
        baseline_vals = [
            metrics["BASELINE"].detection_rate_pct,
            metrics["BASELINE"].containment_rate_pct,
            metrics["BASELINE"].file_protection_rate_pct,
        ]
        protected_vals = [
            metrics["PROTECTED"].detection_rate_pct,
            metrics["PROTECTED"].containment_rate_pct,
            metrics["PROTECTED"].file_protection_rate_pct,
        ]

        x = np.arange(len(categories))
        width = 0.35

        fig, ax = plt.subplots(figsize=(7.5, 4.5), dpi=300)
        ax.bar(x - width / 2, baseline_vals, width, label="Baseline (Unprotected)", color="#ef4444")
        ax.bar(x + width / 2, protected_vals, width, label="Protected (Zero-Trust)", color="#059669")

        ax.set_ylabel("Efficacy Percentage (%)")
        ax.set_title("Defensive Security Posture: Baseline vs Protected Controls")
        ax.set_xticks(x)
        ax.set_xticklabels(categories)
        ax.set_ylim(0, 115)
        ax.legend(loc="lower left")
        ax.grid(axis="y", linestyle=":", alpha=0.6)

        for i, v in enumerate(baseline_vals):
            ax.text(i - width / 2, v + 2, f"{v:.1f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")
        for i, v in enumerate(protected_vals):
            ax.text(i + width / 2, v + 2, f"{v:.1f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")

        fig.tight_layout()
        out_path = self.output_dir / filename
        fig.savefig(out_path)
        plt.close(fig)
        return out_path

    def plot_timing_profile(
        self,
        metrics: dict[str, ScenarioMetrics],
        filename: str = "fig3_response_timing_profile.png",
    ) -> Path:
        """Figure 3: Mean Detection Time vs Containment Latency."""
        fig, ax = plt.subplots(figsize=(6.5, 4.2), dpi=300)
        scenarios = ["Baseline", "Protected"]
        mdt_vals = [metrics["BASELINE"].mean_detection_time_sec, metrics["PROTECTED"].mean_detection_time_sec]
        mttc_vals = [metrics["BASELINE"].mean_time_to_contain_sec, metrics["PROTECTED"].mean_time_to_contain_sec]

        x = np.arange(len(scenarios))
        width = 0.35

        ax.bar(x - width / 2, mdt_vals, width, label="Mean Detection Time (s)", color="#3b82f6")
        ax.bar(x + width / 2, mttc_vals, width, label="Mean Time to Contain (s)", color="#8b5cf6")

        ax.set_ylabel("Simulated Seconds (s)")
        ax.set_title("Detection Latency and Containment Response Duration")
        ax.set_xticks(x)
        ax.set_xticklabels(scenarios)
        ax.set_ylim(0, max(max(mdt_vals), max(mttc_vals), 1.0) * 1.3)
        ax.legend(loc="upper right")
        ax.grid(axis="y", linestyle=":", alpha=0.6)

        for i, v in enumerate(mdt_vals):
            ax.text(i - width / 2, v + 0.05, f"{v:.2f}s", ha="center", va="bottom", fontsize=9)
        for i, v in enumerate(mttc_vals):
            ax.text(i + width / 2, v + 0.05, f"{v:.2f}s", ha="center", va="bottom", fontsize=9)

        fig.tight_layout()
        out_path = self.output_dir / filename
        fig.savefig(out_path)
        plt.close(fig)
        return out_path

    def plot_blast_radius_mitigation(
        self,
        metrics: dict[str, ScenarioMetrics],
        filename: str = "fig4_blast_radius_mitigation.png",
    ) -> Path:
        """Figure 4: Average Assets and Files Impacted by Ransomware Traversal."""
        fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
        labels = ["Avg Compromised Banking Assets", "Avg Encrypted Data Stores"]
        baseline_impact = [metrics["BASELINE"].mean_assets_compromised, metrics["BASELINE"].mean_files_compromised]
        protected_impact = [metrics["PROTECTED"].mean_assets_compromised, metrics["PROTECTED"].mean_files_compromised]

        x = np.arange(len(labels))
        width = 0.35

        ax.bar(x - width / 2, baseline_impact, width, label="Baseline Exposure", color="#b91c1c")
        ax.bar(x + width / 2, protected_impact, width, label="Protected Containment", color="#15803d")

        ax.set_ylabel("Count of Impacted Objects")
        ax.set_title("Blast Radius Mitigation: Lateral Movement & Simulated Ransomware")
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.set_ylim(0, max(max(baseline_impact), 5.0) * 1.3)
        ax.legend(loc="upper right")
        ax.grid(axis="y", linestyle=":", alpha=0.6)

        for i, v in enumerate(baseline_impact):
            ax.text(i - width / 2, v + 0.1, f"{v:.2f}", ha="center", va="bottom", fontsize=9, fontweight="bold")
        for i, v in enumerate(protected_impact):
            ax.text(i + width / 2, v + 0.1, f"{v:.2f}", ha="center", va="bottom", fontsize=9, fontweight="bold")

        fig.tight_layout()
        out_path = self.output_dir / filename
        fig.savefig(out_path)
        plt.close(fig)
        return out_path

    def plot_defense_in_depth_breakdown(
        self,
        trials: Sequence[ExperimentTrialRecord],
        filename: str = "fig5_defense_in_depth_layers.png",
    ) -> Path:
        """Figure 5: Defense-in-depth layer attribution across protected trials."""
        prot_adv = [t for t in trials if t.scenario_type == "PROTECTED" and t.attack_vector != "NORMAL_SESSION"]
        total = len(prot_adv) or 1

        # Calculate stopping points
        auth_stopped = len([t for t in prot_adv if not t.authenticated])
        lateral_stopped = len([t for t in prot_adv if t.authenticated and t.assets_compromised <= 1])
        contained_early = len([t for t in prot_adv if t.containment_occurred])

        labels = ["Authentication / MFA", "RBAC & Segmentation", "Automated Session Containment"]
        percentages = [
            (auth_stopped / total) * 100.0,
            (lateral_stopped / total) * 100.0,
            (contained_early / total) * 100.0,
        ]

        fig, ax = plt.subplots(figsize=(7, 4.2), dpi=300)
        bars = ax.barh(labels, percentages, color=["#2563eb", "#0d9488", "#7c3aed"], height=0.55)

        ax.set_xlabel("Adversarial Attempts Blocked / Contained (%)")
        ax.set_title("Multi-Layer Defense-in-Depth Control Attribution")
        ax.set_xlim(0, 115)
        ax.grid(axis="x", linestyle=":", alpha=0.6)

        for bar in bars:
            w = bar.get_width()
            ax.text(w + 2, bar.get_y() + bar.get_height() / 2, f"{w:.1f}%", va="center", ha="left", fontsize=9, fontweight="bold")

        fig.tight_layout()
        out_path = self.output_dir / filename
        fig.savefig(out_path)
        plt.close(fig)
        return out_path
