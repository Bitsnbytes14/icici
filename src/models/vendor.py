"""Synthetic Vendor Profile and Catalog Model.

This module models third-party vendor identities with attributes reflecting
access privileges, operational patterns, authentication posture, and risk factors.
All vendor profiles are completely synthetic.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from src.models.user import User, AccountStatus


class PrivilegeLevel(str, Enum):
    READ_ONLY = "READ_ONLY"
    STANDARD = "STANDARD"
    ELEVATED = "ELEVATED"
    ADMIN = "ADMIN"


class AccessType(str, Enum):
    BATCH_SFTP = "Batch SFTP"
    API_ACCESS = "API Access"
    REMOTE_SUPPORT = "Remote Support"
    REMOTE_ACCESS = "Remote Access"
    PRIVILEGED_ACCESS = "Privileged Access"


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class VendorProfile:
    vendor_id: str
    vendor_name: str
    vendor_type: str
    access_type: AccessType
    privilege_level: PrivilegeLevel
    mfa_enabled: bool
    access_duration_hours: float
    systems_accessible: list[str]
    risk_tier: RiskTier
    last_access_time: str
    failed_auth_count: int = 0
    suspicious_flags: list[str] = field(default_factory=list)

    def to_user(
        self,
        credential_compromised: bool = True,
        has_mfa_token: bool | None = None,
        has_valid_password: bool = False,
    ) -> User:
        """Map synthetic vendor profile to an active simulation User identity."""
        effective_mfa_token = self.mfa_enabled if has_mfa_token is None else has_mfa_token
        user = User(
            username=f"{self.vendor_id.lower()}_{self.privilege_level.value.lower()}",
            role=self.privilege_level.value,
            credential_compromised=credential_compromised,
            has_valid_password=has_valid_password,
            has_mfa_token=effective_mfa_token,
            status=AccountStatus.ACTIVE,
        )
        return user

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor_id": self.vendor_id,
            "vendor_name": self.vendor_name,
            "vendor_type": self.vendor_type,
            "access_type": self.access_type.value,
            "privilege_level": self.privilege_level.value,
            "mfa_enabled": self.mfa_enabled,
            "access_duration_hours": self.access_duration_hours,
            "systems_accessible": ";".join(self.systems_accessible),
            "risk_tier": self.risk_tier.value,
            "last_access_time": self.last_access_time,
            "failed_auth_count": self.failed_auth_count,
            "suspicious_flags": ";".join(self.suspicious_flags) if self.suspicious_flags else "none",
        }


def load_synthetic_vendors(csv_path: Path | None = None) -> dict[str, VendorProfile]:
    """Load synthetic vendors from CSV or fall back to canonical defaults."""
    catalog: dict[str, VendorProfile] = {}
    if csv_path and csv_path.exists():
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                flags = [x.strip() for x in row["suspicious_flags"].split(";") if x.strip() and x.strip() != "none"]
                systems = [x.strip() for x in row["systems_accessible"].split(";") if x.strip()]
                vp = VendorProfile(
                    vendor_id=row["vendor_id"],
                    vendor_name=row["vendor_name"],
                    vendor_type=row["vendor_type"],
                    access_type=AccessType(row["access_type"]),
                    privilege_level=PrivilegeLevel(row["privilege_level"]),
                    mfa_enabled=row["mfa_enabled"].strip().lower() in ("true", "1", "yes"),
                    access_duration_hours=float(row["access_duration_hours"]),
                    systems_accessible=systems,
                    risk_tier=RiskTier(row["risk_tier"]),
                    last_access_time=row["last_access_time"],
                    failed_auth_count=int(row["failed_auth_count"]),
                    suspicious_flags=flags,
                )
                catalog[vp.vendor_id] = vp
        return catalog

    # Built-in canonical synthetic vendors
    defaults = [
        VendorProfile(
            vendor_id="VEND-001",
            vendor_name="Alpha Cloud Solutions",
            vendor_type="Infrastructure & Hosting",
            access_type=AccessType.REMOTE_ACCESS,
            privilege_level=PrivilegeLevel.ELEVATED,
            mfa_enabled=False,
            access_duration_hours=12.0,
            systems_accessible=["vendor_portal", "support_api", "application_server"],
            risk_tier=RiskTier.HIGH,
            last_access_time="2026-09-24T02:15:00",
            failed_auth_count=4,
            suspicious_flags=["abnormal_login_hour", "repeated_failures"],
        ),
        VendorProfile(
            vendor_id="VEND-002",
            vendor_name="FinTech Bridge Gateways",
            vendor_type="Payment Gateway Integration",
            access_type=AccessType.API_ACCESS,
            privilege_level=PrivilegeLevel.STANDARD,
            mfa_enabled=True,
            access_duration_hours=4.0,
            systems_accessible=["support_api", "transaction_server"],
            risk_tier=RiskTier.MEDIUM,
            last_access_time="2026-09-25T10:30:00",
            failed_auth_count=0,
            suspicious_flags=[],
        ),
        VendorProfile(
            vendor_id="VEND-003",
            vendor_name="SecureATM Maintenance Inc",
            vendor_type="ATM Hardware & Terminal Support",
            access_type=AccessType.REMOTE_SUPPORT,
            privilege_level=PrivilegeLevel.STANDARD,
            mfa_enabled=False,
            access_duration_hours=8.0,
            systems_accessible=["vendor_portal", "support_api"],
            risk_tier=RiskTier.MEDIUM,
            last_access_time="2026-09-25T08:45:00",
            failed_auth_count=1,
            suspicious_flags=["unauthorized_path_probe"],
        ),
        VendorProfile(
            vendor_id="VEND-004",
            vendor_name="Apex Core Banking Consultants",
            vendor_type="Advisory & Configuration",
            access_type=AccessType.PRIVILEGED_ACCESS,
            privilege_level=PrivilegeLevel.ADMIN,
            mfa_enabled=False,
            access_duration_hours=24.0,
            systems_accessible=[
                "vendor_portal",
                "application_server",
                "customer_database",
                "transaction_database",
                "backup_server",
            ],
            risk_tier=RiskTier.CRITICAL,
            last_access_time="2026-09-23T23:10:00",
            failed_auth_count=5,
            suspicious_flags=["privilege_escalation_attempt", "lateral_movement_spike"],
        ),
        VendorProfile(
            vendor_id="VEND-005",
            vendor_name="DocuVault Archival Services",
            vendor_type="Document Records Management",
            access_type=AccessType.BATCH_SFTP,
            privilege_level=PrivilegeLevel.READ_ONLY,
            mfa_enabled=True,
            access_duration_hours=2.0,
            systems_accessible=["vendor_portal", "vendor_documents"],
            risk_tier=RiskTier.LOW,
            last_access_time="2026-09-25T11:00:00",
            failed_auth_count=0,
            suspicious_flags=[],
        ),
    ]
    return {v.vendor_id: v for v in defaults}
