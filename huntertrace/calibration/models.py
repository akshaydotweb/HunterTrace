"""Data models for calibration layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from huntertrace.analysis.models import Contradiction


@dataclass(frozen=True)
class SignalQuality:
    """Signal quality metrics used for confidence calibration."""

    hop_completeness: float
    signal_diversity: float
    signal_agreement: float


@dataclass(frozen=True)
class CalibrationMetadata:
    """Metadata about the email structure."""

    hop_count: int
    routing_complexity: float  # 0.0-1.0, measure of routing diversity
    has_anonymization: bool = False
    anomaly_count: int = 0


@dataclass(frozen=True)
class RegionScore:
    """Regional candidate with its score."""

    region: str
    score: float
    signal_count: int


@dataclass(frozen=True)
class CalibrationInput:
    """Input to calibration engine: correlation + signal quality + metadata."""

    candidate_region: str
    base_confidence: float
    candidate_regions: List[RegionScore]
    consistency_score: float
    contradictions: List[Contradiction]
    anonymization_detected: bool
    anonymization_confidence: float
    anonymization_strength: str
    signal_quality: SignalQuality
    metadata: CalibrationMetadata

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for debugging."""
        return {
            "candidate_region": self.candidate_region,
            "base_confidence": round(self.base_confidence, 4),
            "consistency_score": round(self.consistency_score, 4),
            "contradictions": [
                {
                    "type": c.type,
                    "signals": list(c.signals),
                    "severity": c.severity,
                }
                for c in self.contradictions
            ],
            "anonymization_detected": self.anonymization_detected,
            "anonymization_confidence": round(self.anonymization_confidence, 4),
            "anonymization_strength": self.anonymization_strength,
            "signal_quality": {
                "hop_completeness": round(self.signal_quality.hop_completeness, 4),
                "signal_diversity": round(self.signal_quality.signal_diversity, 4),
                "signal_agreement": round(self.signal_quality.signal_agreement, 4),
            },
            "metadata": {
                "hop_count": self.metadata.hop_count,
                "routing_complexity": round(self.metadata.routing_complexity, 4),
                "has_anonymization": self.metadata.has_anonymization,
                "anomaly_count": self.metadata.anomaly_count,
            },
        }


@dataclass
class CalibrationOutput:
    """Output from calibration engine: refined attribution decision."""

    final_region: Optional[str]
    calibrated_confidence: float
    verdict: str  # "attributed" | "inconclusive"
    adjustments_applied: List[str] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "final_region": self.final_region,
            "calibrated_confidence": round(self.calibrated_confidence, 4),
            "verdict": self.verdict,
            "adjustments_applied": list(self.adjustments_applied),
            "reasoning": self.reasoning,
        }
