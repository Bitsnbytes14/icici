"""Harmless ransomware-impact simulator.

SAFETY:
  * This module NEVER executes real encryption and NEVER contains any
    real malware code.
  * It operates exclusively on files inside data/simulation_workspace/,
    which is rebuilt from the canonical dummy data in data/ at the start
    of every experiment run.
  * "Encrypting" a file means overwriting its content with a harmless
    marker string and renaming it with a `.simulated_encrypted` suffix.
  * The original files under data/ are only ever read, never modified.
  * No path outside the project directory is ever touched.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from src.models.event import SecurityEvent
from src.models.resource import Resource, Zone
from src.models.user import User
from src.network.access_control import AccessControl

MARKER = "SIMULATED_RANSOMWARE_STATE\n"

# This module lives at <repository>/src/simulation/.  Resolve the canonical
# repository root from the module itself so a caller cannot redirect the
# destructive workspace reset by supplying a lookalike directory.
CANONICAL_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

# resource name -> (source dummy data file, workspace file name)
FILE_MAP: dict[str, tuple[str, str]] = {
    "vendor_documents": ("dummy_documents/vendor_contract.csv", "vendor_contract.csv"),
    "customer_database": ("dummy_customers.csv", "customer_data.csv"),
    "transaction_database": ("dummy_transactions.csv", "transaction_data.csv"),
    "employee_records": ("dummy_employees.csv", "employee_data.csv"),
    "backup_server": ("dummy_documents/backup_manifest.csv", "backup_manifest.csv"),
}


def workspace_dir(project_root: Path) -> Path:
    return project_root / "data" / "simulation_workspace"


def reset_workspace(project_root: Path) -> Path:
    """Recreate data/simulation_workspace/ fresh from the canonical dummy data."""
    root = Path(project_root).resolve()
    if root != CANONICAL_REPOSITORY_ROOT:
        raise ValueError("Refusing to reset a workspace outside the canonical simulation repository")
    data_dir = (root / "data").resolve()
    ws = workspace_dir(root).resolve()
    expected_workspace = (data_dir / "simulation_workspace").resolve()
    # The destructive reset is deliberately limited to this exact directory.
    # Refuse any caller-supplied root that resolves to a different target.
    if ws != expected_workspace or ws.parent != data_dir:
        raise ValueError("Refusing to reset a workspace outside data/simulation_workspace")
    if not data_dir.is_dir():
        raise ValueError("Simulation data directory does not exist")
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    for _resource, (source_rel, workspace_name) in FILE_MAP.items():
        shutil.copy(data_dir / source_rel, ws / workspace_name)
    return ws


@dataclass
class RansomwareReport:
    targeted: list[str] = field(default_factory=list)
    encrypted: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)


def run(
    project_root: Path,
    resources: dict[str, Resource],
    access_control: AccessControl,
    user: User,
    authenticated: bool,
    log_event: Callable[..., SecurityEvent],
    on_event: Callable[[SecurityEvent], None],
) -> RansomwareReport:
    ws = workspace_dir(project_root)
    report = RansomwareReport()

    for resource_name, (_source_rel, workspace_name) in FILE_MAP.items():
        resource = resources[resource_name]
        decision = access_control.evaluate(user, resource, authenticated, src_zone=Zone.VENDOR)
        report.targeted.append(resource_name)

        file_path = ws / workspace_name
        if decision.allowed and file_path.exists():
            _encrypt_file(file_path)
            report.encrypted.append(resource_name)
            result, severity = "ALLOWED", "CRITICAL"
        else:
            report.blocked.append(resource_name)
            result, severity = "BLOCKED", "LOW"

        evt = log_event(
            user=user.username,
            action="RANSOMWARE_ENCRYPT",
            target=resource_name,
            result=result,
            severity=severity,
            details={"zone": resource.zone.value, "reason": decision.reason, "file": workspace_name},
        )
        on_event(evt)

    return report


def _encrypt_file(file_path: Path) -> None:
    file_path.write_text(MARKER, encoding="utf-8")
    encrypted_path = file_path.with_name(file_path.name + ".simulated_encrypted")
    file_path.rename(encrypted_path)
