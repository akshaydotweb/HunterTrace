"""Typed models for HunterTrace Atlas signal construction and audit output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceSignal:
    """Observable, reproducible signal derived from parsed email evidence."""

    name: str
    value: Any
    source: str
    extraction_method: str
    raw_reference: str
    confidence_initial: float
    validation_basis: str
    research_reference: str


@dataclass
class RejectedSignal:
    """Signal candidate excluded from downstream reasoning with explicit rationale."""

    name: str
    source: str
    reason: str
    raw_reference: str


@dataclass
class TechniqueApplication:
    """Technique execution trace for explainability and auditability."""

    name: str
    technique: str
    evidence: List[str]
    result: str
    confidence_impact: float


@dataclass
class Observability:
    """Signal quality summary used to scope confidence responsibly."""

    hop_completeness: float
    signal_diversity: float
    signal_agreement: float
    score: float


@dataclass
class AtlasAuditResult:
    """Final Atlas output payload for evidence-backed downstream consumption."""

    region: str
    confidence: float
    verdict: str
    observability_score: float
    signals_used: List[EvidenceSignal] = field(default_factory=list)
    signals_rejected: List[RejectedSignal] = field(default_factory=list)
    techniques_applied: List[TechniqueApplication] = field(default_factory=list)
    evidence_sources: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "region": self.region,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "observability_score": self.observability_score,
            "signals_used": [signal.__dict__ for signal in self.signals_used],
            "signals_rejected": [signal.__dict__ for signal in self.signals_rejected],
            "techniques_applied": [technique.__dict__ for technique in self.techniques_applied],
            "evidence_sources": list(self.evidence_sources),
            "limitations": list(self.limitations),
        }

