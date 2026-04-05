"""Typed models for HunterTrace Atlas correlation analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


@dataclass(frozen=True)
class Signal:
    """Normalized input signal consumed by correlation rules."""

    signal_id: str
    name: str
    value: Any
    source: str
    validation_flags: Sequence[str] = field(default_factory=tuple)
    confidence: float = 0.5
    evidence: str = ""
    candidate_region: Optional[str] = None
    group: Optional[str] = None


@dataclass(frozen=True)
class Contradiction:
    """Explainable contradiction produced by correlation checks."""

    type: str
    signals: List[str]
    reason: str
    severity: str


@dataclass(frozen=True)
class Relationship:
    """Directed relationship between two signals."""

    type: str
    source_signal: str
    target_signal: str
    rationale: str


@dataclass(frozen=True)
class AnonymizationResult:
    """Pattern-based anonymization assessment without identity claims."""

    detected: bool
    confidence: float
    indicators: List[str]
    strength: str


@dataclass(frozen=True)
class CorrelationResult:
    """Final deterministic correlation output."""

    consistency_score: float
    contradictions: List[Contradiction]
    relationships: List[Relationship]
    anonymization: AnonymizationResult
    group_scores: Dict[str, float]
    limitations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "consistency_score": self.consistency_score,
            "contradictions": [
                {
                    "type": item.type,
                    "signals": list(item.signals),
                    "reason": item.reason,
                    "severity": item.severity,
                }
                for item in self.contradictions
            ],
            "relationships": [
                {
                    "type": item.type,
                    "source_signal": item.source_signal,
                    "target_signal": item.target_signal,
                    "rationale": item.rationale,
                }
                for item in self.relationships
            ],
            "anonymization": {
                "detected": self.anonymization.detected,
                "confidence": self.anonymization.confidence,
                "indicators": list(self.anonymization.indicators),
                "strength": self.anonymization.strength,
            },
            "group_scores": dict(self.group_scores),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class CorrelationConfig:
    """Config-driven thresholds for deterministic correlation behavior."""

    temporal_large_delta_minutes: int = 30
    anonymization_min_hops_weak: int = 5
    relay_repetition_strong_hops: int = 4
    mixed_private_public_min_ips: int = 2


@dataclass(frozen=True)
class ScoringConfig:
    """Config-driven weights and thresholds for deterministic scoring."""

    # Group weights in supporting score
    group_weights: Dict[str, float] = field(
        default_factory=lambda: {
            "temporal": 0.35,
            "infrastructure": 0.30,
            "structure": 0.20,
            "quality": 0.15,
        }
    )

    # Signal name weights (base multiplier for supporting signals)
    signal_weights: Dict[str, float] = field(
        default_factory=lambda: {
            "hop_from_ip": 0.25,
            "hop_from_host": 0.20,
            "hop_by_host": 0.15,
            "hop_protocol": 0.10,
            "hop_timestamp_utc": 0.12,
            "hop_count": 0.08,
            "chain_completeness_score": 0.10,
            "chain_anomaly_count": -0.05,
            "anonymity_detected": -0.15,
        }
    )

    # Penalty weights
    conflict_weight: float = 0.10
    consistency_penalty_factor: float = 0.20

    # Anonymization penalties by strength
    anonymization_penalties: Dict[str, float] = field(
        default_factory=lambda: {
            "low": 0.10,
            "medium": 0.20,
            "high": 0.30,
        }
    )

    # Contradiction penalties by severity
    contradiction_penalties: Dict[str, float] = field(
        default_factory=lambda: {
            "low": 0.05,
            "medium": 0.10,
            "high": 0.20,
        }
    )

    # Evidence quality adjustment factors
    quality_factor: float = 0.15

    # Confidence caps and thresholds
    max_confidence_cap: float = 0.99
    confidence_threshold: float = 0.30

    # Minimum evidence requirements (geographic groups only)
    minimum_supporting_signals: int = 2
    minimum_signal_groups: int = 1


@dataclass
class SignalContribution:
    """Explainable contribution of a signal to final score."""

    signal_id: str
    name: str
    value: str
    role: str  # "supporting", "conflicting", "non_attributable"
    group: Optional[str]
    contribution: float  # positive or negative
    penalty: float


@dataclass
class RejectedSignalDetail:
    """Detailed rejection information for audit trail."""

    signal_id: str
    name: str
    reason: str


@dataclass
class AttributionResult:
    """Final deterministic attribution decision with full explainability."""

    region: Optional[str]
    confidence: float
    verdict: str  # "attributed" | "inconclusive"
    consistency_score: float
    signals_used: List[SignalContribution] = field(default_factory=list)
    signals_rejected: List[RejectedSignalDetail] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "region": self.region,
            "confidence": round(self.confidence, 4),
            "verdict": self.verdict,
            "consistency_score": round(self.consistency_score, 4),
            "signals_used": [
                {
                    "signal_id": s.signal_id,
                    "name": s.name,
                    "value": s.value,
                    "role": s.role,
                    "group": s.group,
                    "contribution": round(s.contribution, 4),
                    "penalty": round(s.penalty, 4),
                }
                for s in self.signals_used
            ],
            "signals_rejected": [
                {
                    "signal_id": s.signal_id,
                    "name": s.name,
                    "reason": s.reason,
                }
                for s in self.signals_rejected
            ],
            "anomalies": self.anomalies,
            "limitations": list(self.limitations),
            "reasoning": self.reasoning,
        }

