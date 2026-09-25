"""Combined access-control decision pipeline.

Every access attempt in the simulation is decided here. Five independent
layers are evaluated on every single call, regardless of whether an
earlier layer already fails — this lets the metrics later show exactly
which control(s) would have stopped a given attempt, not just the first
one that did. The final decision is ALLOWED only if all five pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from src.auth.rbac import RBAC
from src.models.resource import Resource, Zone
from src.models.user import User
from src.network.segmentation import Segmentation


@dataclass
class LayerResult:
    passed: bool
    detail: str


@dataclass
class AccessDecision:
    allowed: bool
    resource: str
    reason: str
    layers: dict[str, LayerResult] = field(default_factory=dict)


class AccessControl:
    def __init__(self, rbac: RBAC, segmentation: Segmentation):
        self.rbac = rbac
        self.segmentation = segmentation

    def evaluate(self, user: User, resource: Resource, authenticated: bool, src_zone: Zone) -> AccessDecision:
        layers: dict[str, LayerResult] = {
            "isolation": LayerResult(
                not user.is_isolated,
                "Account not isolated" if not user.is_isolated else "Account has been isolated",
            ),
            "authentication": LayerResult(
                authenticated,
                "Session authenticated" if authenticated else "No authenticated session",
            ),
            "mfa": LayerResult(
                user.mfa_verified,
                "MFA satisfied" if user.mfa_verified else "MFA not satisfied",
            ),
            "rbac": LayerResult(
                self.rbac.is_permitted(resource.name),
                "Permitted by role" if self.rbac.is_permitted(resource.name) else "Not permitted for this role",
            ),
            "segmentation": LayerResult(
                self.segmentation.zone_allowed(src_zone, resource.zone),
                "Zone transition allowed"
                if self.segmentation.zone_allowed(src_zone, resource.zone)
                else f"Segmentation blocks {src_zone.value} -> {resource.zone.value}",
            ),
        }

        allowed = all(layer.passed for layer in layers.values())
        if allowed:
            reason = "ALLOWED"
        else:
            reason = next(name for name, layer in layers.items() if not layer.passed)

        return AccessDecision(allowed=allowed, resource=resource.name, reason=reason, layers=layers)
