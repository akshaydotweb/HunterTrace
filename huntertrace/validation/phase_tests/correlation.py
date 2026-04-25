from __future__ import annotations

from typing import Any, Optional

from ..schema import PhaseResult, ValidationSample


def validate_correlation(sample: ValidationSample, result: Any, repeated_result: Optional[Any] = None) -> PhaseResult:
    corr = getattr(result, "correlation_analysis", None)
    repeated = getattr(repeated_result, "correlation_analysis", None) if repeated_result is not None else corr
    score_a = _score(corr)
    score_b = _score(repeated)
    stability = 1.0 - abs(score_a - score_b)
    metrics = {"consistency_score_stability": max(0.0, stability), "consistency_score": score_a}
    errors = []
    if stability < 0.95:
        errors.append("Correlation stability below threshold")
    return PhaseResult("correlation", stability >= 0.95, metrics=metrics, errors=errors)


def _score(corr: Any) -> float:
    if corr is None:
        return 0.0
    clusters = getattr(corr, "clusters", None)
    patterns = getattr(corr, "patterns", None)
    if clusters is None and patterns is None:
        return 0.0
    return min(1.0, (float(len(clusters or [])) + float(len(patterns or []))) / 10.0)
