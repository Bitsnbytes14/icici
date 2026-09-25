"""Transparent Vendor Risk Scoring Model.

Academic Formula:
  Risk Score (0 - 100) = 100 * (
      w_p * PrivilegeRisk +
      w_a * AuthRisk +
      w_d * DurationRisk +
      w_s * AssetSensitivityRisk +
      w_b * BehavioralAnomalyRisk
  )

Weights (sum = 1.00):
  w_p = 0.25 : Weight for privilege breadth and administrative authority
  w_a = 0.25 : Weight for authentication robustness (MFA and failed attempts)
  w_d = 0.15 : Weight for duration of access window (Just-in-Time alignment)
  w_s = 0.20 : Weight for sensitivity of reachable network zones / assets
  w_b = 0.15 : Weight for real-time behavioral anomalies and event alerts

All sub-factors are strictly normalized to [0.0, 1.0].
The formula and rationales are academically defensible for viva presentation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence
from src.models.vendor import VendorProfile, PrivilegeLevel, RiskTier
from src.models.resource import RESOURCE_CATALOG, Zone, Sensitivity


@dataclass(frozen=True)
class RiskWeights:
    privilege: float = 0.25
    auth: float = 0.25
    duration: float = 0.15
    asset: float = 0.20
    behavior: float = 0.15


@dataclass
class RiskBreakdown:
    privilege_factor: float
    auth_factor: float
    duration_factor: float
    asset_factor: float
    behavior_factor: float
    raw_weighted_score: float
    final_score: float
    tier: RiskTier
    rationale: list[str]

    def to_dict(self) -> dict:
        return {
            "privilege_factor": round(self.privilege_factor, 3),
            "auth_factor": round(self.auth_factor, 3),
            "duration_factor": round(self.duration_factor, 3),
            "asset_factor": round(self.asset_factor, 3),
            "behavior_factor": round(self.behavior_factor, 3),
            "raw_weighted_score": round(self.raw_weighted_score, 4),
            "final_score": round(self.final_score, 1),
            "tier": self.tier.value,
            "rationale": "; ".join(self.rationale),
        }


class VendorRiskScorer:
    """Calculates deterministic, transparent risk scores for synthetic vendor profiles."""

    def __init__(self, weights: RiskWeights | None = None):
        self.weights = weights or RiskWeights()

    def compute_privilege_factor(self, level: PrivilegeLevel) -> float:
        mapping = {
            PrivilegeLevel.READ_ONLY: 0.10,
            PrivilegeLevel.STANDARD: 0.35,
            PrivilegeLevel.ELEVATED: 0.70,
            PrivilegeLevel.ADMIN: 1.00,
        }
        return mapping.get(level, 0.50)

    def compute_auth_factor(self, mfa_enabled: bool, failed_auth_count: int) -> float:
        mfa_risk = 0.10 if mfa_enabled else 0.85
        failure_risk = min(1.0, failed_auth_count * 0.20)
        return min(1.0, (0.60 * mfa_risk) + (0.40 * failure_risk))

    def compute_duration_factor(self, hours: float) -> float:
        # Standard PAM benchmark: 2 hours or less is optimal for third-party access.
        # Continuous access >= 24 hours poses maximum persistent exposure.
        return min(1.0, max(0.05, hours / 24.0))

    def compute_asset_sensitivity_factor(self, systems_accessible: Sequence[str]) -> float:
        if not systems_accessible:
            return 0.10
        has_backup = any(
            sys == "backup_server" or (sys in RESOURCE_CATALOG and RESOURCE_CATALOG[sys].zone == Zone.BACKUP)
            for sys in systems_accessible
        )
        if has_backup:
            return 1.00
        has_critical = any(
            sys in RESOURCE_CATALOG and RESOURCE_CATALOG[sys].sensitivity == Sensitivity.CRITICAL
            for sys in systems_accessible
        )
        if has_critical:
            return 0.85
        has_internal = any(
            sys in RESOURCE_CATALOG and RESOURCE_CATALOG[sys].zone == Zone.INTERNAL
            for sys in systems_accessible
        )
        if has_internal:
            return 0.45
        return 0.20

    def compute_behavior_factor(self, suspicious_flags: Sequence[str], dynamic_incident_count: int = 0) -> float:
        total_signals = len(suspicious_flags) + dynamic_incident_count
        return min(1.0, total_signals * 0.25)

    def evaluate(
        self,
        vendor: VendorProfile,
        dynamic_incident_count: int = 0,
        enforce_defensive_controls: bool = False,
    ) -> RiskBreakdown:
        """Evaluate vendor risk.

        When defensive controls are enforced (Protected Scenario):
        - MFA is enforced (reduces auth factor)
        - Least-privilege/PAM reduces duration to bounded JIT window (e.g., 2h)
        - Segmentation prevents direct access to critical/backup zones
        """
        rationale: list[str] = []

        # Privilege
        effective_privilege = (
            PrivilegeLevel.STANDARD
            if enforce_defensive_controls and vendor.privilege_level == PrivilegeLevel.ADMIN
            else vendor.privilege_level
        )
        f_priv = self.compute_privilege_factor(effective_privilege)
        rationale.append(f"Privilege '{effective_privilege.value}' -> factor {f_priv:.2f}")

        # Auth
        effective_mfa = True if enforce_defensive_controls else vendor.mfa_enabled
        effective_failures = 0 if enforce_defensive_controls else vendor.failed_auth_count
        f_auth = self.compute_auth_factor(effective_mfa, effective_failures)
        rationale.append(f"Auth (MFA={effective_mfa}, Fails={effective_failures}) -> factor {f_auth:.2f}")

        # Duration
        effective_duration = min(2.0, vendor.access_duration_hours) if enforce_defensive_controls else vendor.access_duration_hours
        f_dur = self.compute_duration_factor(effective_duration)
        rationale.append(f"Duration {effective_duration}h -> factor {f_dur:.2f}")

        # Assets
        if enforce_defensive_controls:
            # Under least privilege and network segmentation, vendor is restricted to VENDOR_ZONE
            effective_systems = [
                s for s in vendor.systems_accessible
                if s in RESOURCE_CATALOG and RESOURCE_CATALOG[s].zone == Zone.VENDOR
            ] or ["vendor_portal"]
        else:
            effective_systems = vendor.systems_accessible
        f_asset = self.compute_asset_sensitivity_factor(effective_systems)
        rationale.append(f"Assets ({len(effective_systems)} reachable) -> factor {f_asset:.2f}")

        # Behavioral
        effective_flags = [] if enforce_defensive_controls else vendor.suspicious_flags
        effective_incidents = 0 if enforce_defensive_controls else dynamic_incident_count
        f_beh = self.compute_behavior_factor(effective_flags, effective_incidents)
        rationale.append(f"Behavior ({len(effective_flags)} flags, {effective_incidents} incidents) -> factor {f_beh:.2f}")

        # Weighted combination
        raw_score = (
            self.weights.privilege * f_priv
            + self.weights.auth * f_auth
            + self.weights.duration * f_dur
            + self.weights.asset * f_asset
            + self.weights.behavior * f_beh
        )
        final_score = round(raw_score * 100.0, 1)

        # Risk tiering
        if final_score >= 80.0:
            tier = RiskTier.CRITICAL
        elif final_score >= 60.0:
            tier = RiskTier.HIGH
        elif final_score >= 30.0:
            tier = RiskTier.MEDIUM
        else:
            tier = RiskTier.LOW

        return RiskBreakdown(
            privilege_factor=f_priv,
            auth_factor=f_auth,
            duration_factor=f_dur,
            asset_factor=f_asset,
            behavior_factor=f_beh,
            raw_weighted_score=raw_score,
            final_score=final_score,
            tier=tier,
            rationale=rationale,
        )
