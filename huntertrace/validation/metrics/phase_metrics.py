from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from ..schema import PhaseResult, SampleRunResult


@dataclass
class PhaseMetrics:
    by_phase: Dict[str, Dict[str, float]] = field(default_factory=dict)
    pass_rate: float = 0.0
    failure_count: int = 0


def compute_phase_metrics(sample_results: List[SampleRunResult]) -> PhaseMetrics:
    totals: Dict[str, Dict[str, float]] = {}
    passed = 0
    failed = 0
    for sample in sample_results:
        for phase_name, phase_result in sample.phase_results.items():
            bucket = totals.setdefault(phase_name, {"count": 0.0, "passed": 0.0})
            bucket["count"] += 1.0
            bucket["passed"] += 1.0 if phase_result.passed else 0.0
            passed += 1 if phase_result.passed else 0
            failed += 0 if phase_result.passed else 1
    by_phase = {
        phase: {
            "count": values["count"],
            "pass_rate": (values["passed"] / values["count"]) if values["count"] else 0.0,
        }
        for phase, values in totals.items()
    }
    overall = passed / max(passed + failed, 1)
    return PhaseMetrics(by_phase=by_phase, pass_rate=overall, failure_count=failed)
