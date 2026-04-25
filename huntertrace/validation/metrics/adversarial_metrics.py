from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..schema import AdversarialResult


@dataclass
class AdversarialMetrics:
    attacks_run: int = 0
    attacks_detected: int = 0
    mean_confidence_drop: float = 0.0
    far_increase: float = 0.0
    robustness_score: float = 0.0


def compute_adversarial_metrics(results: List[AdversarialResult]) -> AdversarialMetrics:
    if not results:
        return AdversarialMetrics()
    return AdversarialMetrics(
        attacks_run=len(results),
        attacks_detected=sum(1 for r in results if r.detected),
        mean_confidence_drop=sum(r.confidence_drop for r in results) / len(results),
        far_increase=sum(r.far_increase for r in results) / len(results),
        robustness_score=sum(r.robustness_score for r in results) / len(results),
    )
