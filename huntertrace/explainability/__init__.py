"""HunterTrace Atlas explainability engine for auditable attribution."""

from huntertrace.explainability.engine import ExplainabilityEngine
from huntertrace.explainability.formatter import FormatterFactory
from huntertrace.explainability.models import (
    Anomaly,
    Contribution,
    EvidenceLink,
    ExplainabilityResult,
    Limitation,
    RejectedSignal,
)
from huntertrace.explainability.tracer import EvidenceTracer

__all__ = [
    "ExplainabilityEngine",
    "FormatterFactory",
    "EvidenceTracer",
    "ExplainabilityResult",
    "Contribution",
    "EvidenceLink",
    "Anomaly",
    "Limitation",
    "RejectedSignal",
]
