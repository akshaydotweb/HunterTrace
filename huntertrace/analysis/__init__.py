"""HunterTrace Atlas correlation analysis layer."""

from huntertrace.analysis.correlation import AtlasCorrelationEngine
from huntertrace.analysis.models import (
    AnonymizationResult,
    AttributionResult,
    Contradiction,
    CorrelationConfig,
    CorrelationResult,
    Relationship,
    RejectedSignalDetail,
    ScoringConfig,
    Signal,
    SignalContribution,
)
from huntertrace.analysis.rules import group_signals
from huntertrace.analysis.scoring import AtlasScoringEngine

__all__ = [
    "AnonymizationResult",
    "AtlasCorrelationEngine",
    "AtlasScoringEngine",
    "AttributionResult",
    "Contradiction",
    "CorrelationConfig",
    "CorrelationResult",
    "Relationship",
    "RejectedSignalDetail",
    "ScoringConfig",
    "Signal",
    "SignalContribution",
    "group_signals",
]

