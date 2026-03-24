#!/usr/bin/env python3
"""
huntertrace/analysis/correlator.py
====================================
SHIM — re-exports everything from campaignCorrelator.py (the canonical module).

This file exists for backwards compatibility only.
All development happens in campaignCorrelator.py which has:
  - ConvergenceDetector / ConvergenceZone (new in v3)
  - CorrelationReport with convergence_zones field
  - Improved behavioral fingerprinting

Importing from correlator.py is equivalent to importing from campaignCorrelator.py.
"""

from campaignCorrelator import (
    EmailFingerprint,
    SignalMatch,
    FingerprintSimilarity,
    ThreatActorCluster,
    CorrelationReport,
    FingerprintExtractor,
    SimilarityEngine,
    ClusterBuilder,
    CampaignCorrelator,
    # v3 additions
    ConvergenceZone,
    ConvergenceDetector,
)

__all__ = [
    "EmailFingerprint",
    "SignalMatch",
    "FingerprintSimilarity",
    "ThreatActorCluster",
    "CorrelationReport",
    "FingerprintExtractor",
    "SimilarityEngine",
    "ClusterBuilder",
    "CampaignCorrelator",
    "ConvergenceZone",
    "ConvergenceDetector",
]