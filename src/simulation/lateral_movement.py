"""Simulated lateral movement via breadth-first graph traversal.

Every edge in NETWORK_GRAPH is evaluated through AccessControl before
the traversal is allowed to "move" across it. No real network traffic
or exploitation is generated; this purely walks an in-memory adjacency
list and records which hops the security controls allowed or blocked.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from src.models.event import SecurityEvent
from src.models.resource import Resource
from src.models.user import User
from src.network.access_control import AccessControl

OnEvent = Callable[[SecurityEvent], None]


@dataclass
class TraversalResult:
    visited: set[str] = field(default_factory=set)
    transitions_attempted: int = 0
    transitions_successful: int = 0
    transitions_blocked: int = 0


def traverse(
    graph: dict[str, list[str]],
    resources: dict[str, Resource],
    access_control: AccessControl,
    user: User,
    authenticated: bool,
    log_event: Callable[..., SecurityEvent],
    on_event: OnEvent,
    start: str,
) -> TraversalResult:
    result = TraversalResult()

    start_resource = resources[start]
    start_decision = access_control.evaluate(user, start_resource, authenticated, src_zone=start_resource.zone)
    evt = log_event(
        user=user.username,
        action="LATERAL_MOVEMENT",
        target=start,
        result="ALLOWED" if start_decision.allowed else "BLOCKED",
        severity="CRITICAL" if start_resource.sensitivity.value == "CRITICAL" else "LOW",
        details={"zone": start_resource.zone.value, "reason": start_decision.reason,
                 "layers": {k: v.passed for k, v in start_decision.layers.items()}, "hop": "entry"},
    )
    on_event(evt)

    if not start_decision.allowed:
        return result

    result.visited.add(start)
    frontier: deque[str] = deque([start])

    while frontier:
        current = frontier.popleft()
        current_zone = resources[current].zone
        for neighbor in graph.get(current, []):
            result.transitions_attempted += 1
            neighbor_resource = resources[neighbor]
            decision = access_control.evaluate(user, neighbor_resource, authenticated, src_zone=current_zone)

            # If containment isolates the account mid-traversal, re-check
            # isolation live via user.is_isolated (AccessControl already does).
            evt = log_event(
                user=user.username,
                action="LATERAL_MOVEMENT",
                target=neighbor,
                result="ALLOWED" if decision.allowed else "BLOCKED",
                severity="CRITICAL" if neighbor_resource.sensitivity.value == "CRITICAL" else "LOW",
                details={"zone": neighbor_resource.zone.value, "reason": decision.reason,
                         "layers": {k: v.passed for k, v in decision.layers.items()}, "hop": f"{current}->{neighbor}"},
            )
            on_event(evt)

            if decision.allowed:
                result.transitions_successful += 1
                if neighbor not in result.visited:
                    result.visited.add(neighbor)
                    frontier.append(neighbor)
            else:
                result.transitions_blocked += 1

    return result
