"""Simulated network topology and zone segmentation rules.

NETWORK_GRAPH is a purely in-memory adjacency list — it is not a real
network map and no scanning of any kind is performed. It models which
resource a compromised identity could logically attempt to reach next
from a given resource, e.g. "from the support API you could try to
reach the application server".
"""
from __future__ import annotations

from src.models.resource import Zone

NETWORK_GRAPH: dict[str, list[str]] = {
    "vendor_portal": ["support_api", "vendor_documents"],
    "support_api": ["application_server"],
    "vendor_documents": [],
    "application_server": ["employee_server", "transaction_server"],
    "employee_server": ["employee_records"],
    "transaction_server": ["transaction_database", "customer_database", "backup_server"],
    "employee_records": [],
    "transaction_database": [],
    "customer_database": [],
    "backup_server": [],
}

ENTRY_POINT = "vendor_portal"

# Maps the short zone names used in config YAML files to the Zone enum.
SHORT_ZONE = {
    "VENDOR": Zone.VENDOR,
    "INTERNAL": Zone.INTERNAL,
    "SENSITIVE": Zone.SENSITIVE,
    "BACKUP": Zone.BACKUP,
}


class Segmentation:
    """Decides whether traffic may cross from one zone into another."""

    def __init__(self, enforced: bool, allowed_cross_zone: set[tuple[Zone, Zone]] | None = None):
        self.enforced = enforced
        self.allowed_cross_zone = allowed_cross_zone or set()

    def zone_allowed(self, src: Zone, dst: Zone) -> bool:
        if not self.enforced:
            return True
        if src == dst:
            return True
        return (src, dst) in self.allowed_cross_zone
