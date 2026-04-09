#!/usr/bin/env python3
"""
huntertrace/attribution/scoring.py
==================================
Phase 5 — deterministic forensic inference engine.

Design constraints
------------------
- Regions come only from upstream-enriched signals or the legacy adapter.
- No signal -> country/region mapping exists in this module.
- Every signal influences the outcome:
  * supporting signals increase candidate score
  * conflicting signals apply candidate penalties
  * non-attributable / unusable signals reduce evidence quality and are
    preserved in limitations / rejected-signal accounting
- Confidence is deterministic:
      weighted_score = max(0, supporting_score - penalty_score)
      confidence     = weighted_score / max_possible_score
  with candidate-scoped denominators, bounded to [0, 0.8].
- Abstention is explicit and preferred over over-confident attribution.
"""
#!/usr/bin/env python3
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from huntertrace.atlas.provenance import PROVENANCE_RANK, ProvenanceClass


# --------------------------
# Helpers
# --------------------------

def _coerce_number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


# --------------------------
# Models
# --------------------------

@dataclass(frozen=True)
class NormalizedSignal:
    signal_id: str
    name: str
    group: str
    value: Any
    candidate_region: Optional[str]
    source: str
    source_header: Optional[str] = None
    trust_label: str = "UNKNOWN"
    validation_flags: Tuple[str, ...] = ()
    anomaly_detail: Optional[str] = None
    excluded_reason: Optional[str] = None
    provenance_class: str = "sender_controlled"
    trust_weight_base: float = 0.2
    confidence: float = 1.0


@dataclass(frozen=True)
class SignalContribution:
    signal_id: str
    name: str
    group: str
    role: str
    candidate_region: Optional[str]
    value: Any
    base_weight: float
    effective_weight: float
    penalty: float
    source_header: Optional[str]
    provenance_class: str
    trust_weight_base: float
    confidence: float
    explanation: str
    trust_label: str
    validation_flags: Tuple[str, ...]
    source: str


@dataclass(frozen=True)
class CandidateEvaluation:
    candidate: str
    supporting_score: float
    penalty_score: float
    weighted_score: float
    max_possible_score: float
    confidence: float
    supporting_signals: Tuple[SignalContribution, ...]
    conflicting_signals: Tuple[SignalContribution, ...]
    supporting_groups: Tuple[str, ...]


@dataclass
class AttributionResult:
    region: Optional[str]
    confidence: float
    signals_used: List[Dict[str, Any]]
    signals_rejected: List[Dict[str, Any]]
    anomalies: List[Dict[str, Any]]
    limitations: List[str]
    verdict: str


# --------------------------
# Config
# --------------------------

@dataclass
class ScoringConfig:
    group_weights: Mapping[str, float] = field(default_factory=lambda: {
        "temporal": 1.0,
        "infrastructure": 1.2,
        "identity": 1.1,
        "authentication": 1.05,
    })

    signal_weights: Mapping[str, float] = field(default_factory=lambda: {
        # DKIM signals
        "dkim_valid": 1.15,
        "dkim_domain": 1.05,

        # Authentication group signals (Phase 9)
        "dmarc_result": 1.40,           # DMARC pass = strong positive signal
        "dmarc_policy": 1.10,           # Policy presence = moderate positive
        "spf_result": 1.20,             # SPF pass = strong positive
        "spf_aligned": 1.25,            # Alignment critical for DMARC
        "dkim_aligned": 1.20,           # DKIM alignment = strong indicator
        "arc_valid": 1.15,              # ARC chain = forwarding indicator
        "arc_chain_length": 0.10,
        "arc_upstream_auth": 0.20,
        "arc_forwarded": 0.35,
        "arc_failure_reason": 0.0,
    })

    trust_multipliers: Mapping[str, float] = field(default_factory=lambda: {
        "TRUSTED": 1.0,
        "UNKNOWN": 0.6,
    })

    validation_multipliers: Mapping[str, float] = field(default_factory=lambda: {
        "CLEAN": 1.0,
        "MALFORMED": 0.0,
    })

    conflict_multipliers: Mapping[str, float] = field(default_factory=lambda: {
        "default": 0.6
    })

    evidence_penalties: Mapping[str, float] = field(default_factory=lambda: {
        "non_attributable": 0.1,
        "anomaly": 0.05,
        "relay_disagreement": 0.12,
    })

    confidence_cap: float = 0.8


# --------------------------
# Engine
# --------------------------

class InferenceEngine:

    def __init__(self, config: Optional[ScoringConfig] = None):
        self.config = config or ScoringConfig()

    # --------------------------
    # Resolvers
    # --------------------------

    def _resolve_base_weight(self, s: NormalizedSignal) -> float:
        return (
            self.config.group_weights.get(s.group, 0.0)
            * self.config.signal_weights.get(s.name, 1.0)
        )

    def _resolve_validation_multiplier(self, s: NormalizedSignal) -> float:
        if not s.validation_flags:
            return 1.0
        return min(
            self.config.validation_multipliers.get(f, 1.0)
            for f in s.validation_flags
        )

    def _resolve_trust_multiplier(self, s: NormalizedSignal) -> float:
        return self.config.trust_multipliers.get(s.trust_label, 1.0)

    def _resolve_trust_weight_base(self, s: NormalizedSignal) -> float:
        return max(0.0, min(1.0, float(getattr(s, "trust_weight_base", 1.0))))

    def _resolve_confidence(self, s: NormalizedSignal) -> float:
        return max(0.0, min(1.0, float(getattr(s, "confidence", 1.0))))

    def _provenance_rank(self, s: NormalizedSignal) -> int:
        label = str(getattr(s, "provenance_class", "sender_controlled"))
        try:
            return PROVENANCE_RANK.get(ProvenanceClass(label), 0)
        except ValueError:
            return 0

    def _build_signal_explanation(self, s: NormalizedSignal) -> str:
        header = s.source_header or "unknown header"
        prov = str(getattr(s, "provenance_class", "unknown"))
        trust_weight = self._resolve_trust_weight_base(s)
        if trust_weight >= 0.9:
            trust_label = "high trust"
        elif trust_weight >= 0.6:
            trust_label = "medium trust"
        else:
            trust_label = "low trust"
        return f"{header} header classified as {prov} ({trust_label}, weight={trust_weight:.2f})"

    # --------------------------
    # Evidence penalty
    # --------------------------

    def _compute_evidence_penalty(self, signals, anomalies):
        penalty = 0.0

        for s in signals:
            if not s.candidate_region:
                penalty += self.config.evidence_penalties["non_attributable"]

        penalty += len(anomalies) * self.config.evidence_penalties["anomaly"]

        relay_regions = {
            s.candidate_region
            for s in signals
            if s.candidate_region
            and str(getattr(s, "provenance_class", ""))
            in {"sending_mta_generated", "intermediary_relay_generated"}
        }
        if len(relay_regions) > 1:
            penalty += self.config.evidence_penalties.get("relay_disagreement", 0.12)

        return min(1.0, penalty)

    # --------------------------
    # Candidate scoring (FINAL FIXED)
    # --------------------------

    def _evaluate_candidate(self, candidate, signals, anomalies):

        cryptographic_regions = {
            s.candidate_region
            for s in signals
            if s.candidate_region
            and str(getattr(s, "provenance_class", "")) == "cryptographic"
        }
        recipient_regions = {
            s.candidate_region
            for s in signals
            if s.candidate_region
            and str(getattr(s, "provenance_class", "")) == "recipient_mta_generated"
        }

        supporting_score = 0.0
        conflict_penalty = 0.0

        supporting = []
        conflicting = []
        groups = []

        # --------------------------
        # Candidate-specific denominator
        # --------------------------

        max_possible_score = 0.0

        for s in signals:

            if (
                str(getattr(s, "provenance_class", "")) == "sender_controlled"
                and cryptographic_regions
                and s.candidate_region not in cryptographic_regions
            ):
                continue

            if s.candidate_region is None:
                continue

            base = self._resolve_base_weight(s)
            if base <= 0:
                continue

            if s.excluded_reason:
                continue

            val = self._resolve_validation_multiplier(s)
            if val <= 0:
                continue

            # IMPORTANT:
            # include signals that participate in this candidate's hypothesis space
            if s.candidate_region == candidate or s.candidate_region != candidate:
                max_possible_score += base

        # --------------------------
        # Scoring
        # --------------------------

        support_ranks = [
            self._provenance_rank(s)
            for s in signals
            if s.candidate_region == candidate and not s.excluded_reason
        ]
        max_support_rank = max(support_ranks) if support_ranks else 0

        for s in signals:

            if (
                str(getattr(s, "provenance_class", "")) == "sender_controlled"
                and cryptographic_regions
                and s.candidate_region not in cryptographic_regions
            ):
                continue

            base = self._resolve_base_weight(s)
            if base <= 0:
                continue

            val = self._resolve_validation_multiplier(s)
            if val <= 0 or s.excluded_reason:
                continue

            if not s.candidate_region:
                continue

            trust = self._resolve_trust_multiplier(s)
            trust_weight = self._resolve_trust_weight_base(s)
            confidence = self._resolve_confidence(s)

            provenance_adjustment = 1.0
            if recipient_regions and str(getattr(s, "provenance_class", "")) in {
                "sending_mta_generated",
                "intermediary_relay_generated",
            }:
                if s.candidate_region not in recipient_regions:
                    provenance_adjustment *= 0.6

            eff = base * trust * val * trust_weight * confidence * provenance_adjustment

            if s.candidate_region == candidate:
                supporting_score += eff
                groups.append(s.group)

                supporting.append(SignalContribution(
                    s.signal_id, s.name, s.group, "supporting",
                    s.candidate_region, s.value,
                    base, eff, 0.0,
                    s.source_header,
                    str(getattr(s, "provenance_class", "unknown")),
                    trust_weight,
                    confidence,
                    self._build_signal_explanation(s),
                    s.trust_label, s.validation_flags, s.source
                ))

            else:
                conflict_adjustment = provenance_adjustment
                if self._provenance_rank(s) < max_support_rank:
                    conflict_adjustment *= 0.7

                penalty = (
                    base
                    * self.config.conflict_multipliers["default"]
                    * trust
                    * val
                    * trust_weight
                    * confidence
                    * conflict_adjustment
                )

                conflict_penalty += penalty

                conflicting.append(SignalContribution(
                    s.signal_id, s.name, s.group, "conflicting",
                    s.candidate_region, s.value,
                    base, 0.0, penalty,
                    s.source_header,
                    str(getattr(s, "provenance_class", "unknown")),
                    trust_weight,
                    confidence,
                    self._build_signal_explanation(s),
                    s.trust_label, s.validation_flags, s.source
                ))

        # --------------------------
        # Final math
        # --------------------------

        weighted = max(0.0, supporting_score - conflict_penalty)

        if max_possible_score > 0:
            confidence = weighted / max_possible_score
        else:
            confidence = 0.0

        # multiplicative uncertainty
        evidence_penalty = self._compute_evidence_penalty(signals, anomalies)
        confidence *= (1.0 - evidence_penalty)

        confidence = round(confidence, 12)
        confidence = min(self.config.confidence_cap, max(0.0, confidence))

        return CandidateEvaluation(
            candidate,
            round(supporting_score, 12),
            round(conflict_penalty, 12),
            round(weighted, 12),
            round(max_possible_score, 12),
            confidence,
            tuple(supporting),
            tuple(conflicting),
            tuple(sorted(set(groups))),
        )
