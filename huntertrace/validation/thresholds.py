from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class ThresholdRule:
    metric: str
    operator: str
    value: float


DEFAULT_THRESHOLDS: Dict[str, ThresholdRule] = {
    "parsing_accuracy": ThresholdRule("parsing_accuracy", ">=", 0.98),
    "hop_ordering": ThresholdRule("hop_ordering", "==", 1.0),
    "signal_coverage": ThresholdRule("signal_coverage", ">=", 0.90),
    "enrichment_rate": ThresholdRule("enrichment_rate", ">=", 0.85),
    "provenance_accuracy": ThresholdRule("provenance_accuracy", ">=", 0.90),
    "anomaly_detection": ThresholdRule("anomaly_detection", ">=", 0.90),
    "false_anomaly": ThresholdRule("false_anomaly", "<=", 0.10),
    "ece": ThresholdRule("ece", "<=", 0.10),
    "brier": ThresholdRule("brier", "<=", 0.15),
}


def evaluate_threshold(metric: str, value: float) -> bool:
    rule = DEFAULT_THRESHOLDS.get(metric)
    if rule is None:
        return True
    if rule.operator == ">=":
        return float(value) >= rule.value
    if rule.operator == "<=":
        return float(value) <= rule.value
    if rule.operator == "==":
        return float(value) == rule.value
    raise ValueError(f"Unsupported operator: {rule.operator}")


def threshold_target(metric: str) -> Tuple[str, float]:
    rule = DEFAULT_THRESHOLDS[metric]
    return rule.operator, rule.value
