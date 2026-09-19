"""Phase 0 timing instrumentation (optimisation plan §4).

Stdlib-only stage timer: records per-stage wall time for
inventory / source candidate scan / parsing / dataflow-resolution /
fingerprinting / correlation / risk / recommendation / report assembly.
Used by orchestrator, benchmark runner and tests. Deterministic output
ordering; zero dependencies.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

__all__ = ["StageTimer", "STAGES"]

STAGES = (
    "inventory",
    "source_candidate_scan",
    "parsing",
    "dataflow_resolution",
    "fingerprinting",
    "correlation",
    "risk",
    "recommendation",
    "report_assembly",
)


@dataclass
class StageTimer:
    marks: dict[str, float] = field(default_factory=dict)
    _starts: dict[str, float] = field(default_factory=dict, repr=False)

    def start(self, stage: str) -> None:
        self._starts[stage] = time.monotonic()

    def stop(self, stage: str) -> float:
        s = self._starts.pop(stage, None)
        dt = time.monotonic() - s if s is not None else 0.0
        self.marks[stage] = self.marks.get(stage, 0.0) + dt
        return dt

    def __enter__(self):  # context for whole scan
        self._t0 = time.monotonic()
        return self

    def __exit__(self, *exc):
        self.marks["total"] = time.monotonic() - getattr(self, "_t0", time.monotonic())
        return False

    def section(self, stage: str):
        timer = self

        class _S:
            def __enter__(self):
                timer.start(stage)
                return timer

            def __exit__(self, *exc):
                timer.stop(stage)
                return False

        return _S()

    def as_dict(self) -> dict[str, float]:
        return {k: round(v, 4) for k, v in sorted(self.marks.items())}
