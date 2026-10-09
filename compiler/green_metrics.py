from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class GreenMetrics:
    phase_starts: Dict[str, float] = field(default_factory=dict)
    phase_ms: Dict[str, float] = field(default_factory=dict)
    counters: Dict[str, int] = field(default_factory=dict)
    values: Dict[str, Any] = field(default_factory=dict)

    def start(self, phase: str) -> None:
        self.phase_starts[phase] = time.perf_counter()

    def start_total(self) -> None:
        self.start("total")

    def end_total(self) -> None:
        self.end("total")

    def end(self, phase: str) -> None:
        started = self.phase_starts.get(phase)
        if started is None:
            return
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        self.phase_ms[phase] = self.phase_ms.get(phase, 0.0) + elapsed_ms
        del self.phase_starts[phase]

    def inc(self, key: str, value: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + value

    def set(self, key: str, value: Any) -> None:
        self.values[key] = value

    def to_dict(self) -> Dict[str, Any]:
        total_ms = sum(self.phase_ms.values())
        return {
            "total_runtime_ms": round(total_ms, 2),
            "phase_ms": {k: round(v, 2) for k, v in self.phase_ms.items()},
            "counters": dict(self.counters),
            "values": dict(self.values),
        }