from __future__ import annotations

from typing import Any, Iterable

from ..schema import PhaseResult, ValidationSample


def validate_signals(sample: ValidationSample, result: Any) -> PhaseResult:
    bayes = getattr(result, "bayesian_attribution", None)
    signals = list(getattr(bayes, "signals_used", []) or [])
    provenance = dict(getattr(bayes, "signal_provenance", {}) or {})
    coverage = len(signals) / max(len(signals), 1)
    correctness = 1.0 if all(sig in provenance or provenance == {} for sig in signals) else 0.0
    metrics = {"signal_coverage": coverage, "signal_correctness": correctness}
    errors = []
    if not signals:
        errors.append("No signals used by attribution engine")
    return PhaseResult("signals", bool(signals), metrics=metrics, errors=errors)
