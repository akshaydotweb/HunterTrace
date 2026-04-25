from __future__ import annotations

from typing import Any

from ..schema import PhaseResult, ValidationSample


def validate_explainability(sample: ValidationSample, result: Any) -> PhaseResult:
    bayes = getattr(result, "bayesian_attribution", None)
    signals = list(getattr(bayes, "signals_used", []) or [])
    provenance = dict(getattr(bayes, "signal_provenance", {}) or {})
    mapped = sum(1 for sig in signals if sig in provenance)
    completeness = mapped / max(len(signals), 1)
    metrics = {
        "trace_completeness": completeness,
        "evidence_mapping_accuracy": completeness,
    }
    errors = []
    if signals and completeness < 1.0:
        errors.append("Incomplete evidence mapping")
    return PhaseResult("explainability", completeness >= 1.0 if signals else True, metrics=metrics, errors=errors)
