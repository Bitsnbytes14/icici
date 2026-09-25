"""Simulated resource discovery / recon.

Represents an attacker enumerating the resource catalog from
documentation, support tooling, or prior vendor knowledge. This is a
purely in-memory lookup — no scanning of any real network happens.
"""
from __future__ import annotations

from src.models.resource import Resource
from src.network.segmentation import NETWORK_GRAPH


def discover_resources(resources: dict[str, Resource]) -> list[dict]:
    return [
        {"name": name, "zone": res.zone.value, "sensitivity": res.sensitivity.value}
        for name, res in resources.items()
    ]


def discover_topology() -> dict[str, list[str]]:
    return {node: list(neighbors) for node, neighbors in NETWORK_GRAPH.items()}
