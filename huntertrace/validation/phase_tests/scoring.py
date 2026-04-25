from __future__ import annotations

from typing import Any

from ..schema import PhaseResult, ValidationSample


def validate_scoring(sample: ValidationSample, result: Any) -> PhaseResult:
    bayes = getattr(result, "bayesian_attribution", None)
    if bayes is None:
        return PhaseResult("scoring", False, metrics={"score_distribution": 0.0, "signal_contribution_balance": 0.0}, errors=["Missing bayesian_attribution"])
    confidence = float(getattr(bayes, "aci_adjusted_prob", 0.0) or 0.0)
    signals = list(getattr(bayes, "signals_used", []) or [])
    balance = 1.0 / max(len(signals), 1)
    metrics = {"score_distribution": confidence, "signal_contribution_balance": balance}
    errors = []
    if confidence < 0.0 or confidence > 1.0:
        errors.append("Confidence out of bounds")
    return PhaseResult("scoring", True, metrics=metrics, errors=errors)
