#!/usr/bin/env python3
"""
huntertrace/attribution/attribution.py
=======================================
SHIM — re-exports everything from engine.py (the canonical module).

This file exists for backwards compatibility only.
All development happens in engine.py which has:
  - FalseFlagDetector / FalseFlagResult
  - SignalReliabilityWeighter
  - IPv6 signal support
  - Calibration layer (load_calibrator)

Importing from attribution.py is equivalent to importing from engine.py.
"""

# Re-export everything the old attribution.py used to provide.
# Any code doing `from attribution import X` continues to work unchanged.
from engine import (
    SIGNAL_LIKELIHOOD_RATIOS,
    SIGNAL_SOURCE_RELIABILITY,
    RegionProbability,
    ACIBreakdown,
    AttributionResult,
    SignalExtractor,
    BayesianUpdater,
    ACICalculator,
    TierAssigner,
    AttributionEngine,
    # Layer 5 additions (new in engine.py)
    FalseFlagResult,
    FalseFlagDetector,
    SignalReliabilityWeighter,
)

# Aliases for any code that used the old module-level names
AttributionEngineV3 = AttributionEngine  # legacy alias

__all__ = [
    "SIGNAL_LIKELIHOOD_RATIOS",
    "SIGNAL_SOURCE_RELIABILITY",
    "RegionProbability",
    "ACIBreakdown",
    "AttributionResult",
    "SignalExtractor",
    "BayesianUpdater",
    "ACICalculator",
    "TierAssigner",
    "AttributionEngine",
    "AttributionEngineV3",
    "FalseFlagResult",
    "FalseFlagDetector",
    "SignalReliabilityWeighter",
]