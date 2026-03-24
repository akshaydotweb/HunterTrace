"""
analysis — Behavioural analysis: actor profiling, campaign correlation,
sender fingerprinting, timezone validation.
"""
from huntertrace.analysis.actorProfiler import (
    ActorProfiler,
    ActorTTPProfile,
    MITREMapping,
    TemporalPattern,
    InfrastructurePattern,
    ContentPattern,
)
from huntertrace.analysis.campaignCorrelator import (
    CampaignCorrelator,
    ThreatActorCluster,
    CorrelationReport,
    FingerprintSimilarity,
)
from huntertrace.analysis.senderClassifier import (
    HopTimestampAnomalyDetector,
    TimezoneValidityChecker,
    SendRegularityScorer,
    HopChainAnalysis,
    TimezoneAnalysis,
    SenderClassification,
)

__all__ = [
    "ActorProfiler", "ActorTTPProfile", "MITREMapping",
    "TemporalPattern", "InfrastructurePattern", "ContentPattern",
    "CampaignCorrelator", "ThreatActorCluster", "CorrelationReport",
    "HopTimestampAnomalyDetector", "TimezoneValidityChecker", "SendRegularityScorer",
    "HopChainAnalysis", "TimezoneAnalysis", "SenderClassification",
]
