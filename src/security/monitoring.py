"""Continuous monitoring: structured event logging.

Timing uses a simulated monotonic clock rather than wall-clock time.
An in-process simulation completes in microseconds, which would make
"detection time" / "containment time" metrics meaningless noise. The
SimClock instead advances by a fixed, documented step on every logged
action, giving reproducible, human-readable timings that are still
derived directly from what actually happened during the run (the
number and order of real events), not invented after the fact.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.models.event import SecurityEvent


@dataclass
class SimClock:
    step_seconds: float = 0.2
    _t: float = 0.0

    def tick(self) -> float:
        self._t = round(self._t + self.step_seconds, 3)
        return self._t

    def advance(self, seconds: float) -> float:
        self._t = round(self._t + seconds, 3)
        return self._t


@dataclass
class EventLogger:
    log_path: Path
    clock: SimClock = field(default_factory=SimClock)
    events: list[SecurityEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.log_path = Path(self.log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("", encoding="utf-8")

    def log(self, *, user: str, action: str, target: str, result: str, severity: str,
             details: dict[str, Any] | None = None) -> SecurityEvent:
        event = SecurityEvent(
            timestamp=self.clock.tick(),
            user=user,
            action=action,
            target=target,
            result=result,
            severity=severity,
            details=details or {},
        )
        self.events.append(event)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict()) + "\n")
        return event
