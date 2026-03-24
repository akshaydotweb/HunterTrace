"""
forensics — 8-detector email forensics scan suite.

Detectors
---------
  HopTimestampForgeryDetector   out-of-order / zero-second Received: hops
  BotSendPatternScorer          inter-send-interval coefficient of variation
  AIContentDetector             TTR, sentence variance, function-word ratio
  TrackingPixelDetector         1×1 img, display:none, known tracker domains
  HTMLSmugglingDetector         JS blob URLs, createObjectURL, atob()
  HomoglyphDomainDetector       Unicode lookalike characters in From/Reply-To
  ZeroPointFontDetector         font-size:0, white-on-white hidden text
"""
from huntertrace.forensics.scanner import (
    ForensicScanSummary,
    HopTimestampForgeryDetector,
    HopForgeryResult,
    BotSendPatternScorer,
    SendPatternResult,
    AIContentDetector,
    AIContentResult,
    TrackingPixelDetector,
    TrackingPixelResult,
    HTMLSmugglingDetector,
    HTMLSmugglingResult,
    HomoglyphDomainDetector,
    HomoglyphResult,
    ZeroPointFontDetector,
    ZeroFontResult,
)

__all__ = [
    "ForensicScanSummary",
    "HopTimestampForgeryDetector", "HopForgeryResult",
    "BotSendPatternScorer", "SendPatternResult",
    "AIContentDetector", "AIContentResult",
    "TrackingPixelDetector", "TrackingPixelResult",
    "HTMLSmugglingDetector", "HTMLSmugglingResult",
    "HomoglyphDomainDetector", "HomoglyphResult",
    "ZeroPointFontDetector", "ZeroFontResult",
]
