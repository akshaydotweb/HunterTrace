from __future__ import annotations

from typing import Any

from ..schema import PhaseResult, ValidationSample


def validate_provenance(sample: ValidationSample, result: Any) -> PhaseResult:
    bayes = getattr(result, "bayesian_attribution", None)
    provenance = dict(getattr(bayes, "signal_provenance", {}) or {})
    signals = list(getattr(bayes, "signals_used", []) or [])
    classified = 0
    for sig in signals:
        meta = provenance.get(sig) or {}
        if meta.get("provenance_class") or meta.get("source_header"):
            classified += 1
    rate = classified / max(len(signals), 1)
    metrics = {"correct_classification_rate": rate}
    errors = []
    if signals and not provenance:
        errors.append("Missing signal provenance")
    return PhaseResult("provenance", rate >= 0.90 if signals else True, metrics=metrics, errors=errors)
