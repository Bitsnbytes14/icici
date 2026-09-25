"""Simulated third-party vendor identity management.

SAFETY:
No real credentials, accounts, or tokens are created or modified.
Identities are purely in-memory representations evaluated against the
access-control rules.
"""
from __future__ import annotations

from pathlib import Path
from src.models.user import User
from src.models.vendor import (
    VendorProfile,
    load_synthetic_vendors,
    PrivilegeLevel,
    AccessType,
    RiskTier,
)

VENDOR_USERNAME = "vendor_support"
VENDOR_ROLE = "SUPPORT_VENDOR"


def create_compromised_vendor_identity() -> User:
    """Legacy helper returning a single simulated compromised vendor user."""
    user = User(username=VENDOR_USERNAME, role=VENDOR_ROLE, has_mfa_token=False)
    user.credential_compromised = True
    return user


def get_all_synthetic_vendors(data_dir: Path | None = None) -> dict[str, VendorProfile]:
    """Retrieve full catalog of synthetic vendor profiles."""
    csv_path = (data_dir / "vendors.csv") if data_dir else None
    return load_synthetic_vendors(csv_path)
