"""
attribution — Bayesian multi-signal attribution with ACI confidence scoring.

Key constants (importable for custom configurations):
  REGION_PRIORS           — per-country prior probabilities (33 countries)
  SIGNAL_LIKELIHOOD_RATIOS — per-signal LR weights
"""
from huntertrace.attribution.engine import (
    AttributionEngine,
    AttributionResult,
    RegionProbability,
    ACIBreakdown,
    TierAssigner,
    REGION_PRIORS,
    SIGNAL_LIKELIHOOD_RATIOS,
)
from huntertrace.attribution.analysis import (
    AttributionAnalysisEngine,
    Stage5Attribution,
    AttackerProfile,
    AttributionGraph,
    AttributionConfidence,
    EvidenceItem,
)

__all__ = [
    "AttributionEngine", "AttributionResult", "RegionProbability",
    "ACIBreakdown", "TierAssigner",
    "REGION_PRIORS", "SIGNAL_LIKELIHOOD_RATIOS",
    "AttributionAnalysisEngine", "Stage5Attribution", "AttackerProfile",
    "AttributionGraph", "AttributionConfidence", "EvidenceItem",
]
