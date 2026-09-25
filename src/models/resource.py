"""Fictional banking resource catalog used by the simulation.

Every resource here is synthetic. Names resemble a generic banking
environment (vendor / internal / sensitive / backup zones) but do not
correspond to any real institution's systems.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Zone(str, Enum):
    VENDOR = "VENDOR_ZONE"
    INTERNAL = "INTERNAL_ZONE"
    SENSITIVE = "SENSITIVE_ZONE"
    BACKUP = "BACKUP_ZONE"


class Sensitivity(str, Enum):
    NORMAL = "NORMAL"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Resource:
    name: str
    zone: Zone
    sensitivity: Sensitivity
    description: str
    # Filename inside data/simulation_workspace/ this resource maps to,
    # if it carries encryptable "data" for the ransomware simulation.
    data_file: str | None = None


RESOURCE_CATALOG: dict[str, Resource] = {
    "vendor_portal": Resource(
        "vendor_portal", Zone.VENDOR, Sensitivity.NORMAL,
        "Vendor-facing support portal used for remote assistance tickets.",
    ),
    "support_api": Resource(
        "support_api", Zone.VENDOR, Sensitivity.NORMAL,
        "API used by the vendor's support tooling to reach internal systems.",
    ),
    "vendor_documents": Resource(
        "vendor_documents", Zone.VENDOR, Sensitivity.NORMAL,
        "Vendor contract and onboarding documents store.",
        data_file="vendor_contract.csv",
    ),
    "application_server": Resource(
        "application_server", Zone.INTERNAL, Sensitivity.NORMAL,
        "Core banking application server.",
    ),
    "employee_server": Resource(
        "employee_server", Zone.INTERNAL, Sensitivity.NORMAL,
        "Internal HR / employee services server.",
    ),
    "transaction_server": Resource(
        "transaction_server", Zone.INTERNAL, Sensitivity.NORMAL,
        "Transaction processing server.",
    ),
    "customer_database": Resource(
        "customer_database", Zone.SENSITIVE, Sensitivity.CRITICAL,
        "Customer master data store.",
        data_file="customer_data.csv",
    ),
    "transaction_database": Resource(
        "transaction_database", Zone.SENSITIVE, Sensitivity.CRITICAL,
        "Transaction records data store.",
        data_file="transaction_data.csv",
    ),
    "employee_records": Resource(
        "employee_records", Zone.SENSITIVE, Sensitivity.CRITICAL,
        "Employee records data store.",
        data_file="employee_data.csv",
    ),
    "backup_server": Resource(
        "backup_server", Zone.BACKUP, Sensitivity.CRITICAL,
        "Offline/near-line backup repository.",
        data_file="backup_manifest.csv",
    ),
}

TOTAL_ASSET_COUNT = len(RESOURCE_CATALOG)
