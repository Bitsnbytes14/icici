"""Role-Based Access Control.

Maps a role to the explicit set of resources it is permitted to touch.
There is no privilege-escalation path defined anywhere: a role's
permission set is fixed for the lifetime of the simulation.
"""
from __future__ import annotations


class RBAC:
    def __init__(self, permitted_resources: set[str]):
        self.permitted_resources = set(permitted_resources)

    def is_permitted(self, resource_name: str) -> bool:
        return resource_name in self.permitted_resources
