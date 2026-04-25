from __future__ import annotations

from typing import Any

from ..schema import PhaseResult, ValidationSample


def validate_semantic(sample: ValidationSample, result: Any) -> PhaseResult:
    header = getattr(result, "header_analysis", None)
    spoof_risk = float(getattr(header, "spoofing_risk", 0.0) or 0.0)
    auth = getattr(header, "authentication_evaluation", {}) or {}
    suspicious = bool(auth.get("verdict") == "SUSPICIOUS" or spoof_risk >= 0.6)
    expected_anomaly = sample.scenario_type in {"spoofed", "malformed", "anonymized", "forwarded", "mailing_list"}
    anomaly_rate = 1.0 if suspicious else 0.0
    false_anomaly = 1.0 if suspicious and sample.scenario_type == "clean" else 0.0
    metrics = {"anomaly_detection_rate": anomaly_rate, "false_anomaly_rate": false_anomaly}
    errors = []
    if expected_anomaly and not suspicious:
        errors.append("Expected anomaly not detected")
    if sample.scenario_type == "clean" and suspicious:
        errors.append("False anomaly on clean sample")
    return PhaseResult("semantic", not errors, metrics=metrics, errors=errors)
