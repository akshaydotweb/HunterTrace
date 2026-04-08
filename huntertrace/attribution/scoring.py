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
    trust_label: str = "UNKNOWN"
    validation_flags: Tuple[str, ...] = ()
    anomaly_detail: Optional[str] = None
    excluded_reason: Optional[str] = None


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
        "dkim_valid": 1.15,
        "dkim_domain": 1.05,
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

    # --------------------------
    # Evidence penalty
    # --------------------------

    def _compute_evidence_penalty(self, signals, anomalies):
        penalty = 0.0

        for s in signals:
            if not s.candidate_region:
                penalty += self.config.evidence_penalties["non_attributable"]

        penalty += len(anomalies) * self.config.evidence_penalties["anomaly"]

        return min(1.0, penalty)

    # --------------------------
    # Candidate scoring (FINAL FIXED)
    # --------------------------

    def _evaluate_candidate(self, candidate, signals, anomalies):

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

        for s in signals:

            base = self._resolve_base_weight(s)
            if base <= 0:
                continue

            val = self._resolve_validation_multiplier(s)
            if val <= 0 or s.excluded_reason:
                continue

            if not s.candidate_region:
                continue

            trust = self._resolve_trust_multiplier(s)
            eff = base * trust * val

            if s.candidate_region == candidate:
                supporting_score += eff
                groups.append(s.group)

                supporting.append(SignalContribution(
                    s.signal_id, s.name, s.group, "supporting",
                    s.candidate_region, s.value,
                    base, eff, 0.0,
                    s.trust_label, s.validation_flags, s.source
                ))

            else:
                penalty = (
                    base
                    * self.config.conflict_multipliers["default"]
                    * trust
                    * val
                )

                conflict_penalty += penalty

                conflicting.append(SignalContribution(
                    s.signal_id, s.name, s.group, "conflicting",
                    s.candidate_region, s.value,
                    base, 0.0, penalty,
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
