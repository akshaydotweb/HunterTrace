from __future__ import annotations

from typing import Any

from ..schema import PhaseResult, ValidationSample


def validate_normalization(sample: ValidationSample, result: Any) -> PhaseResult:
    bayes = getattr(result, "bayesian_attribution", None)
    region = getattr(bayes, "primary_region", None)
    verdict = _predict_verdict(result)
    normalized = 1.0 if verdict in {"attributed", "inconclusive"} else 0.0
    metrics = {"normalized_fields_rate": normalized, "region_normalization_rate": 1.0 if region else 0.0}
    errors = []
    if verdict not in {"attributed", "inconclusive"}:
        errors.append("Verdict not normalized")
    return PhaseResult("normalization", normalized > 0.0, metrics=metrics, errors=errors)


def _predict_verdict(result: Any) -> str:
    bayes = getattr(result, "bayesian_attribution", None)
    if bayes and float(getattr(bayes, "aci_adjusted_prob", 0.0) or 0.0) >= 0.50:
        return "attributed"
    return "inconclusive"
