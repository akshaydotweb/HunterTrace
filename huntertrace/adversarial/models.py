"""Core data models for adversarial testing framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class AttackType(str, Enum):
    """Enumeration of attack types."""

    HEADER_INJECTION = "header_injection"
    TIMESTAMP_SPOOFING = "timestamp_spoofing"
    HOP_CHAIN_BREAK = "hop_chain_break"
    RELAY_MIMICRY = "relay_mimicry"
    INFRASTRUCTURE_CONFLICT = "infrastructure_conflict"
    HEADER_OBFUSCATION = "header_obfuscation"


class AttackSeverity(str, Enum):
    """Severity levels for attacks."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class MutationTrace:
    """Record of mutations applied to a sample."""

    attack_type: str
    severity: str
    mutations: List[Tuple[str, str]]  # (location, description)
    mutation_count: int
    parser_valid: bool
    description: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "attack_type": self.attack_type,
            "severity": self.severity,
            "mutations": self.mutations,
            "mutation_count": self.mutation_count,
            "parser_valid": self.parser_valid,
            "description": self.description,
        }


@dataclass(frozen=True)
class AdversarialSample:
    """Adversarial variant of an evaluation sample."""

    original_path: str  # Path to original email file
    modified_content: str  # Modified email content
    attack_type: str
    severity: str
    seed: int
    mutation_trace: MutationTrace

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "original_path": self.original_path,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "seed": self.seed,
            "mutation_trace": self.mutation_trace.to_dict(),
        }


@dataclass
class PredictionRecord:
    """Prediction result from pipeline."""

    region: Optional[str]
    confidence: float
    verdict: str  # "attributed", "abstained"
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "region": self.region,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "anomalies": self.anomalies,
        }


@dataclass
class BaselineComparison:
    """Comparison between baseline and adversarial prediction."""

    baseline_prediction: PredictionRecord
    adversarial_prediction: PredictionRecord
    changed: bool  # Did verdict or confidence change?
    prediction_delta: float  # Confidence difference
    verdict_changed: bool  # Did verdict change?

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "baseline": self.baseline_prediction.to_dict(),
            "adversarial": self.adversarial_prediction.to_dict(),
            "changed": self.changed,
            "prediction_delta": self.prediction_delta,
            "verdict_changed": self.verdict_changed,
        }
