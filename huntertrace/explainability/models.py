"""Typed models for HunterTrace Atlas explainability output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class RejectedSignal:
    """Signal that was rejected or excluded from attribution."""

    signal_id: str
    signal_name: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_name": self.signal_name,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Contribution:
    """Quantified contribution of a signal to final attribution decision."""

    signal_id: str
    signal_name: str
    role: str  # "supporting" | "conflicting" | "neutral"
    group: Optional[str]  # temporal | infrastructure | structure | quality
    contribution_score: float  # positive or negative
    penalty_score: float  # non-negative
    net_effect: float  # contribution_score - penalty_score
    normalized_effect: float = 0.0  # net_effect / sum(abs(net_effects))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_name": self.signal_name,
            "role": self.role,
            "group": self.group,
            "contribution_score": round(self.contribution_score, 4),
            "penalty_score": round(self.penalty_score, 4),
            "net_effect": round(self.net_effect, 4),
            "normalized_effect": round(self.normalized_effect, 4),
        }


@dataclass(frozen=True)
class EvidenceLink:
    """Traceable link from decision to signal to hop to raw header."""

    signal_id: str
    signal_name: str
    hop_index: int
    hop_from_ip: Optional[str]
    hop_from_host: Optional[str]
    raw_header_snippet: str  # minimal excerpt, not full dump
    extracted_fields: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_name": self.signal_name,
            "hop_index": self.hop_index,
            "hop_from_ip": self.hop_from_ip,
            "hop_from_host": self.hop_from_host,
            "raw_header_snippet": self.raw_header_snippet,
            "extracted_fields": self.extracted_fields,
        }


@dataclass(frozen=True)
class Anomaly:
    """Extracted anomaly from correlation analysis."""

    type: str  # contradiction, anonymization, temporal, structural, quality
    severity: str  # low | medium | high
    description: str
    source: str  # correlation | signal | chain

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "source": self.source,
        }


@dataclass(frozen=True)
class Limitation:
    """Documented limitation of the analysis."""

    category: str  # evidence | observability | correlation | inference
    description: str
    impact: str  # low | medium | high

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "description": self.description,
            "impact": self.impact,
        }


@dataclass
class ExplainabilityResult:
    """Complete explainability output for attribution decision."""

    verdict: str  # "attributed" | "inconclusive"
    region: Optional[str]
    confidence: float

    # Phase 1: Ordered decision reasoning
    decision_trace: List[str] = field(default_factory=list)

    # Phase 2: Signal contribution breakdown
    contributions: List[Contribution] = field(default_factory=list)

    # Phase 2b: Rejected signals (for audit trail)
    rejected_signals: List[RejectedSignal] = field(default_factory=list)

    # Phase 3: Evidence traceability
    evidence_links: List[EvidenceLink] = field(default_factory=list)

    # Phase 4: Detected anomalies
    anomalies: List[Anomaly] = field(default_factory=list)

    # Phase 5: Analysis limitations
    limitations: List[Limitation] = field(default_factory=list)

    # Phase 5: Human-readable explanation
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "region": self.region,
            "confidence": round(self.confidence, 4),
            "decision_trace": self.decision_trace,
            "contributions": [c.to_dict() for c in self.contributions],
            "rejected_signals": [r.to_dict() for r in self.rejected_signals],
            "evidence_links": [e.to_dict() for e in self.evidence_links],
            "anomalies": [a.to_dict() for a in self.anomalies],
            "limitations": [l.to_dict() for l in self.limitations],
            "explanation": self.explanation,
        }
