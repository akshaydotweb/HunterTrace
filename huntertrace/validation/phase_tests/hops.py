from __future__ import annotations

from typing import Any

from ..schema import PhaseResult, ValidationSample


def validate_hops(sample: ValidationSample, result: Any) -> PhaseResult:
    header = getattr(result, "header_analysis", None)
    hops = list(getattr(header, "hops", []) or [])
    if not hops:
        return PhaseResult("hop_reconstruction", False, metrics={"hop_completeness": 0.0, "ordering_correctness": 0.0}, errors=["No hops reconstructed"])

    hop_numbers = [getattr(hop, "hop_number", idx) for idx, hop in enumerate(hops)]
    asc = hop_numbers == sorted(hop_numbers)
    desc = hop_numbers == sorted(hop_numbers, reverse=True)
    metrics = {
        "hop_completeness": 1.0 if len(hops) > 0 else 0.0,
        "ordering_correctness": 1.0 if (asc or desc) else 0.0,
    }
    errors = []
    if not (asc or desc):
        errors.append("Hop ordering is not monotonic")
    return PhaseResult("hop_reconstruction", bool(hops) and (asc or desc), metrics=metrics, errors=errors)
