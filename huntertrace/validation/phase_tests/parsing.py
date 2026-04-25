from __future__ import annotations

from typing import Any

from ..schema import PhaseResult, ValidationSample


def validate_parsing(sample: ValidationSample, result: Any) -> PhaseResult:
    header = getattr(result, "header_analysis", None)
    if header is None:
        return PhaseResult("parsing", False, metrics={"header_parse_accuracy": 0.0, "malformed_header_handling_rate": 1.0}, errors=["Missing header_analysis"])

    required = ["email_from", "email_to", "email_subject", "email_date", "message_id"]
    present = sum(1 for field in required if getattr(header, field, None))
    total = float(len(required))
    metrics = {
        "header_parse_accuracy": present / total,
        "malformed_header_handling_rate": 1.0 if getattr(header, "hops", None) is not None else 0.0,
    }
    errors = []
    if present < len(required):
        errors.append("Missing one or more required header fields")
    return PhaseResult("parsing", present == len(required), metrics=metrics, errors=errors)
