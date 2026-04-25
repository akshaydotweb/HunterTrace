from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..schema import SampleRunResult


@dataclass
class ConfidenceMetrics:
    ece: float = 0.0
    brier: float = 0.0
    reliability_diagram: List[Dict[str, float]] = field(default_factory=list)
    abstention_correctness: float = 0.0
    strong_confidence_rate: float = 0.0
    weak_confidence_rate: float = 0.0


def compute_confidence_metrics(sample_results: List[SampleRunResult], bins: int = 10) -> ConfidenceMetrics:
    points: List[tuple[float, int]] = []
    abstention_hits = 0
    strong = 0
    weak = 0
    for item in sample_results:
        correct = 1 if _is_correct(item) else 0
        points.append((float(item.confidence), correct))
        if item.predicted_verdict != "attributed" and item.sample.expected_verdict == "inconclusive":
            abstention_hits += 1
        if item.sample.scenario_type in {"clean"} and item.confidence >= 0.75:
            strong += 1
        if item.sample.scenario_type in {"forwarded", "mailing_list", "spoofed", "anonymized"} and 0.40 <= item.confidence <= 0.75:
            weak += 1
    ece, diagram = _ece(points, bins=bins)
    brier = sum((conf - corr) ** 2 for conf, corr in points) / max(len(points), 1)
    return ConfidenceMetrics(
        ece=ece,
        brier=brier,
        reliability_diagram=diagram,
        abstention_correctness=abstention_hits / max(len(sample_results), 1),
        strong_confidence_rate=strong / max(len([r for r in sample_results if r.sample.scenario_type == "clean"]), 1),
        weak_confidence_rate=weak / max(len([r for r in sample_results if r.sample.scenario_type in {"forwarded", "mailing_list", "spoofed", "anonymized"}]), 1),
    )


def _is_correct(result: SampleRunResult) -> int:
    if result.sample.expected_region is not None:
        return 1 if result.predicted_region == result.sample.expected_region else 0
    if result.sample.expected_verdict is not None:
        return 1 if result.predicted_verdict == result.sample.expected_verdict else 0
    return 0


def _ece(points: List[tuple[float, int]], bins: int = 10) -> tuple[float, List[Dict[str, float]]]:
    if not points:
        return 0.0, []
    diagram: List[Dict[str, float]] = []
    total = len(points)
    error = 0.0
    for i in range(bins):
        lo = i / bins
        hi = (i + 1) / bins
        bucket = [p for p in points if lo <= p[0] < hi or (i == bins - 1 and p[0] == 1.0)]
        if not bucket:
            continue
        avg_conf = sum(p[0] for p in bucket) / len(bucket)
        acc = sum(p[1] for p in bucket) / len(bucket)
        diagram.append({"bin_lower": lo, "bin_upper": hi, "avg_confidence": avg_conf, "accuracy": acc, "count": float(len(bucket))})
        error += (len(bucket) / total) * abs(avg_conf - acc)
    return error, diagram
