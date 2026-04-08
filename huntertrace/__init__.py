#!/usr/bin/env python3
"""
HUNTЕRТRACE — Advanced Phishing Actor Attribution

A comprehensive system for attributing phishing emails to geographic regions
using multi-signal Bayesian inference, infrastructure graph analysis, and
behavioral fingerprinting.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("huntertrace")
except PackageNotFoundError:
    __version__ = "1.2.3"

# Core imports
try:
    from .core.pipeline import CompletePipeline as HunterTrace
    from .core.orchestrator import HunterTraceV3
except ImportError:
    HunterTrace = None
    HunterTraceV3 = None

# Graph imports
try:
    from .graph.centrality import InfrastructureGraphAnalyzer
    from .graph.correlator import CampaignCorrelator
except ImportError:
    InfrastructureGraphAnalyzer = None
    CampaignCorrelator = None

__all__ = [
    '__version__',
    'HunterTrace',
    'HunterTraceV3',
    'InfrastructureGraphAnalyzer',
    'CampaignCorrelator',
]
