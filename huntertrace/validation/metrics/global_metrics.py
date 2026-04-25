from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..schema import SampleRunResult


@dataclass
class GlobalMetrics:
    accuracy: float = 0.0
    false_attribution_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    abstention_rate: float = 0.0
    confidence_distribution: Dict[str, float] = field(default_factory=dict)


def compute_global_metrics(sample_results: List[SampleRunResult]) -> GlobalMetrics:
    total = len(sample_results)
    attributed = [r for r in sample_results if r.predicted_verdict == "attributed"]
    correct = [r for r in sample_results if _is_correct(r)]
    wrong_confident = [r for r in attributed if not _is_correct(r)]
    abstained = [r for r in sample_results if r.predicted_verdict != "attributed"]
    accuracy = len(correct) / max(total, 1)
    far = len(wrong_confident) / max(len(attributed), 1)
    precision = len(correct) / max(len(attributed), 1)
    recall = len(correct) / max(len([r for r in sample_results if r.sample.expected_region]), 1)
    abstention = len(abstained) / max(total, 1)
    dist = _confidence_distribution(sample_results)
    return GlobalMetrics(
        accuracy=accuracy,
        false_attribution_rate=far,
        precision=precision,
        recall=recall,
        abstention_rate=abstention,
        confidence_distribution=dist,
    )


def _is_correct(result: SampleRunResult) -> bool:
    if result.sample.expected_region is not None:
        return result.predicted_region == result.sample.expected_region
    if result.sample.expected_verdict is not None:
        return result.predicted_verdict == result.sample.expected_verdict
    return False


def _confidence_distribution(sample_results: List[SampleRunResult]) -> Dict[str, float]:
    buckets = {"low": 0, "medium": 0, "high": 0}
    for item in sample_results:
        if item.confidence >= 0.75:
            buckets["high"] += 1
        elif item.confidence >= 0.40:
            buckets["medium"] += 1
        else:
            buckets["low"] += 1
    total = max(len(sample_results), 1)
    return {k: v / total for k, v in buckets.items()}
