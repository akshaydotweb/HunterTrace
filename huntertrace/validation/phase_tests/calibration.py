from __future__ import annotations

from typing import Any

from ..schema import PhaseResult, ValidationSample


def validate_calibration(sample: ValidationSample, result: Any) -> PhaseResult:
    bayes = getattr(result, "bayesian_attribution", None)
    conf = float(getattr(bayes, "aci_adjusted_prob", 0.0) or 0.0)
    expected = sample.expected_region
    correct = 1.0 if expected and _predict_region(result) == expected else 0.0
    brier = (conf - correct) ** 2
    metrics = {
        "confidence": conf,
        "correctness": correct,
        "brier": brier,
    }
    return PhaseResult("calibration", True, metrics=metrics, errors=[])


def _predict_region(result: Any) -> str | None:
    bayes = getattr(result, "bayesian_attribution", None)
    return getattr(bayes, "primary_region", None) if bayes else None
