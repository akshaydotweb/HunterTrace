"""Deterministic scoring engine for final attribution decision."""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from huntertrace.analysis.models import (
    AttributionResult,
    CorrelationResult,
    RejectedSignalDetail,
    ScoringConfig,
    Signal,
    SignalContribution,
)
from huntertrace.analysis.utils import clamp01


class AtlasScoringEngine:
    """
    Deterministic, explainable scoring engine that produces final attribution.

    Implements 16-phase algorithm:
    1. Build candidate set
    2. Classify signals
    3. Calculate supporting score
    4. Apply penalties
    5. Compute raw score
    6. Calculate max possible score
    7. Base confidence
    8. Evidence quality adjustment
    9. Clamp & cap
    10. Minimum evidence checks
    11. Winner selection
    12. Abstention rules
    13. Output
    14. Determinism
    15. Configuration (external)
    16. Testing
    """

    @staticmethod
    def score(
        signals: List[Signal],
        correlation: CorrelationResult,
        config: ScoringConfig | None = None,
    ) -> AttributionResult:
        """
        Score signals and correlation to produce deterministic attribution.

        Args:
            signals: Normalized signals from upstream
            correlation: CorrelationResult from correlation engine
            config: ScoringConfig (uses defaults if None)

        Returns:
            AttributionResult with region, confidence, verdict, and full explainability
        """
        cfg = config or ScoringConfig()
        engine = AtlasScoringEngine(cfg)
        return engine._score_internal(signals, correlation)

    def __init__(self, config: ScoringConfig):
        self.config = config
        self.signal_group_map: Dict[str, str] = {}

    def _score_internal(
        self,
        signals: List[Signal],
        correlation: CorrelationResult,
    ) -> AttributionResult:
        """Internal scoring implementation."""

        # PHASE 1: Build candidate set
        candidates = self._extract_candidates(signals)

        if not candidates:
            return AttributionResult(
                region=None,
                confidence=0.0,
                verdict="inconclusive",
                consistency_score=correlation.consistency_score,
                signals_rejected=[],
                limitations=["No candidate regions found in signals"],
                reasoning="No signals provided candidate regions for attribution.",
            )

        # Build signal-to-group map for later use
        self.signal_group_map = self._map_signals_to_groups(signals)

        # PHASE 2-6: Score each candidate
        candidate_scores: Dict[str, Dict] = {}
        for candidate in candidates:
            score_result = self._score_candidate(signals, candidate, correlation)
            candidate_scores[candidate] = score_result

        # PHASE 11: Winner selection (deterministic)
        winner = self._select_winner_deterministic(candidate_scores)

        if winner is None:
            return AttributionResult(
                region=None,
                confidence=0.0,
                verdict="inconclusive",
                consistency_score=correlation.consistency_score,
                signals_rejected=[],
                limitations=["No candidate regions met attribution threshold"],
                reasoning="All candidates scored below minimum thresholds.",
            )

        winner_score = candidate_scores[winner]

        # PHASE 12: Abstention rules
        final_confidence = winner_score["confidence"]
        must_abstain = self._check_abstention_rules(
            final_confidence,
            winner_score["supporting_count"],
            winner_score["geographic_group_count"],
            correlation,
        )

        # PHASE 13: Output
        if must_abstain:
            return AttributionResult(
                region=None,
                confidence=final_confidence,
                verdict="inconclusive",
                consistency_score=correlation.consistency_score,
                signals_used=winner_score["signals_used"],
                signals_rejected=winner_score["signals_rejected"],
                anomalies=self._format_anomalies(correlation),
                limitations=winner_score["limitations"] + correlation.limitations,
                reasoning=f"Abstention triggered: {winner_score['abstention_reason']}",
            )

        return AttributionResult(
            region=winner,
            confidence=final_confidence,
            verdict="attributed",
            consistency_score=correlation.consistency_score,
            signals_used=winner_score["signals_used"],
            signals_rejected=winner_score["signals_rejected"],
            anomalies=self._format_anomalies(correlation),
            limitations=winner_score["limitations"] + correlation.limitations,
            reasoning=f"Attribution to {winner} with {final_confidence:.1%} confidence based on {winner_score['supporting_count']} supporting signals across {winner_score['group_count']} groups.",
        )

    def _extract_candidates(self, signals: List[Signal]) -> Set[str]:
        """PHASE 1: Extract set of candidate regions from signals."""
        candidates = set()
        for signal in signals:
            if signal.candidate_region and signal.candidate_region not in ("internal", "local"):
                candidates.add(signal.candidate_region)
        return candidates

    def _map_signals_to_groups(self, signals: List[Signal]) -> Dict[str, str]:
        """Build mapping of signal_id to group."""
        mapping = {}
        for signal in signals:
            if signal.group:
                mapping[signal.signal_id] = signal.group
        return mapping

    def _score_candidate(
        self,
        signals: List[Signal],
        candidate: str,
        correlation: CorrelationResult,
    ) -> Dict:
        """PHASE 2-10: Score a single candidate region."""

        # PHASE 2: Classify signals
        supporting, conflicting, non_attributable = self._classify_signals(
            signals, candidate
        )

        # PHASE 3: Supporting score
        supporting_score = self._calculate_supporting_score(supporting)

        # PHASE 4: Penalties
        penalty_score = self._calculate_penalties(
            supporting, conflicting, non_attributable, correlation, candidate
        )

        # PHASE 5: Raw score
        weighted_score = max(0.0, supporting_score - penalty_score)

        # PHASE 6: Max possible score
        max_possible = self._calculate_max_possible_score(signals, candidate)

        # PHASE 7: Base confidence
        if max_possible > 0:
            base_confidence = weighted_score / max_possible
        else:
            base_confidence = 0.0

        # PHASE 8: Evidence quality adjustment
        quality_adjusted_confidence = self._apply_quality_adjustment(
            base_confidence, non_attributable, correlation
        )

        # PHASE 9: Clamp & cap
        final_confidence = clamp01(quality_adjusted_confidence)
        final_confidence = min(final_confidence, self.config.max_confidence_cap)

        # Prepare signals used/rejected details
        signals_used = self._build_signal_contributions(supporting, conflicting)
        signals_rejected = self._build_rejected_signals(non_attributable)

        limitations = self._build_limitations(
            supporting, non_attributable, correlation
        )

        return {
            "confidence": final_confidence,
            "supporting_count": len(supporting),
            "group_count": len(self._count_groups(supporting)),
            "geographic_group_count": len(self._count_geographic_groups(supporting)),
            "signals_used": signals_used,
            "signals_rejected": signals_rejected,
            "limitations": limitations,
            "supporting": supporting,
            "conflicting": conflicting,
            "abstention_reason": None,
        }

    def _classify_signals(
        self, signals: List[Signal], candidate: str
    ) -> Tuple[List[Signal], List[Signal], List[Signal]]:
        """PHASE 2: Classify signals into supporting/conflicting/non_attributable."""
        supporting = []
        conflicting = []
        non_attributable = []

        for signal in signals:
            if signal.candidate_region == candidate:
                supporting.append(signal)
            elif signal.candidate_region and signal.candidate_region != candidate:
                conflicting.append(signal)
            else:
                non_attributable.append(signal)

        return supporting, conflicting, non_attributable

    def _calculate_supporting_score(self, supporting: List[Signal]) -> float:
        """PHASE 3: Calculate supporting score with weights."""
        total = 0.0

        for signal in supporting:
            group = self.signal_group_map.get(signal.signal_id, "quality")
            group_weight = self.config.group_weights.get(group, 0.15)
            signal_weight = self.config.signal_weights.get(signal.name, 0.05)

            contribution = group_weight * signal_weight * signal.confidence
            total += contribution

        return total

    def _calculate_penalties(
        self,
        supporting: List[Signal],
        conflicting: List[Signal],
        non_attributable: List[Signal],
        correlation: CorrelationResult,
        candidate: str,
    ) -> float:
        """PHASE 4: Calculate total penalties."""
        penalty = 0.0

        # Conflicting signals
        for signal in conflicting:
            signal_weight = self.config.signal_weights.get(signal.name, 0.05)
            penalty += self.config.conflict_weight * signal_weight

        # Contradiction penalties
        for contradiction in correlation.contradictions:
            severity = contradiction.severity.lower()
            contradiction_penalty = self.config.contradiction_penalties.get(
                severity, 0.05
            )
            penalty += contradiction_penalty

        # Anonymization penalty
        if correlation.anonymization.detected:
            strength = correlation.anonymization.strength.lower()
            anon_penalty = self.config.anonymization_penalties.get(strength, 0.15)
            penalty += anon_penalty

        # Low consistency penalty
        penalty += (1 - correlation.consistency_score) * self.config.consistency_penalty_factor

        return penalty

    def _calculate_max_possible_score(self, signals: List[Signal], candidate: str) -> float:
        """PHASE 6: Calculate max possible score (no penalties, no confidence)."""
        total = 0.0

        for signal in signals:
            # Only count signals that *could* support or conflict with this candidate
            # Exclude non-geographic signals (temporal, structure, quality) that lack region info
            if self._is_non_geographic_signal(signal) and not signal.candidate_region:
                continue  # Skip non-geographic signals with no region

            if signal.candidate_region is None or signal.candidate_region == candidate:
                group = self.signal_group_map.get(signal.signal_id, "quality")
                group_weight = self.config.group_weights.get(group, 0.15)
                signal_weight = self.config.signal_weights.get(signal.name, 0.05)
                total += group_weight * signal_weight

        return total

    def _apply_quality_adjustment(
        self,
        base_confidence: float,
        non_attributable: List[Signal],
        correlation: CorrelationResult,
    ) -> float:
        """PHASE 8: Apply evidence quality adjustments."""
        adjusted = base_confidence

        # No quality penalties - the presence of unattributable signals is already
        # reflected in the base confidence through reduced max_possible score.
        # Only apply penalties for genuine issues (anonymization, contradictions)

        # Anonymization impact
        if correlation.anonymization.detected:
            confidence_reduction = correlation.anonymization.confidence * 0.2
            adjusted -= confidence_reduction

        # Multiple contradictions impact
        contradiction_count = len(correlation.contradictions)
        if contradiction_count > 2:
            adjusted -= 0.1

        return adjusted

    def _is_non_geographic_signal(self, signal: Signal) -> bool:
        """Check if signal is inherently non-geographic (temporal, structure, quality, internal)."""
        group = self.signal_group_map.get(signal.signal_id, signal.group or "quality")
        # Non-geographic groups + internal region
        return group in ("temporal", "structure", "quality") or signal.candidate_region == "internal"

    def _select_winner_deterministic(
        self, candidate_scores: Dict[str, Dict]
    ) -> str | None:
        """PHASE 11: Select winner deterministically, with tie detection."""
        if not candidate_scores:
            return None

        # Sort by confidence descending, then by region name for determinism
        sorted_candidates = sorted(
            candidate_scores.items(),
            key=lambda x: (-x[1]["confidence"], x[0]),
        )

        if not sorted_candidates:
            return None

        best_candidate, best_score = sorted_candidates[0]
        best_confidence = best_score["confidence"]

        # Check for ties (within 0.001 tolerance)
        tie_threshold = 1e-3
        tied_candidates = [
            cand
            for cand, score in sorted_candidates
            if abs(score["confidence"] - best_confidence) < tie_threshold
        ]

        if len(tied_candidates) > 1:
            return None  # Tie detected, force abstention

        return best_candidate

    def _check_abstention_rules(
        self,
        confidence: float,
        supporting_count: int,
        group_count: int,
        correlation: CorrelationResult,
    ) -> bool:
        """PHASE 12: Check if abstention is required."""

        # Confidence below threshold
        if confidence < self.config.confidence_threshold:
            return True

        # Insufficient supporting signals
        if supporting_count < self.config.minimum_supporting_signals:
            return True

        # Insufficient signal groups
        if group_count < self.config.minimum_signal_groups:
            return True

        # High anonymization + low consistency
        if (
            correlation.anonymization.detected
            and correlation.anonymization.strength == "high"
            and correlation.consistency_score < 0.4
        ):
            return True

        return False

    def _build_signal_contributions(
        self, supporting: List[Signal], conflicting: List[Signal]
    ) -> List[SignalContribution]:
        """Build explicit signal contribution details."""
        contributions = []

        for signal in supporting:
            group = self.signal_group_map.get(signal.signal_id, "quality")
            group_weight = self.config.group_weights.get(group, 0.15)
            signal_weight = self.config.signal_weights.get(signal.name, 0.05)
            contribution = group_weight * signal_weight * signal.confidence

            contributions.append(
                SignalContribution(
                    signal_id=signal.signal_id,
                    name=signal.name,
                    value=str(signal.value)[:100],
                    role="supporting",
                    group=group,
                    contribution=contribution,
                    penalty=0.0,
                )
            )

        for signal in conflicting:
            signal_weight = self.config.signal_weights.get(signal.name, 0.05)
            penalty = self.config.conflict_weight * signal_weight

            contributions.append(
                SignalContribution(
                    signal_id=signal.signal_id,
                    name=signal.name,
                    value=str(signal.value)[:100],
                    role="conflicting",
                    group=self.signal_group_map.get(signal.signal_id, "quality"),
                    contribution=0.0,
                    penalty=penalty,
                )
            )

        return contributions

    def _build_rejected_signals(
        self, non_attributable: List[Signal]
    ) -> List[RejectedSignalDetail]:
        """Build rejected signal details."""
        rejected = []
        for signal in non_attributable:
            rejected.append(
                RejectedSignalDetail(
                    signal_id=signal.signal_id,
                    name=signal.name,
                    reason="No candidate region or insufficient evidence",
                )
            )
        return rejected

    def _build_limitations(
        self,
        supporting: List[Signal],
        non_attributable: List[Signal],
        correlation: CorrelationResult,
    ) -> List[str]:
        """Build limitation messages."""
        limitations = []

        if non_attributable:
            limitations.append(
                f"{len(non_attributable)} signals lack clear attribution"
            )

        if not supporting:
            limitations.append("No supporting signals available")

        if correlation.anonymization.detected:
            strength = correlation.anonymization.strength
            limitations.append(
                f"Anonymization patterns detected ({strength} strength)"
            )

        return limitations

    def _count_groups(self, signals: List[Signal]) -> Set[str]:
        """Count unique groups in signals."""
        groups = set()
        for signal in signals:
            group = self.signal_group_map.get(signal.signal_id, "quality")
            groups.add(group)
        return groups

    def _count_geographic_groups(self, signals: List[Signal]) -> Set[str]:
        """Count unique geographic groups (infrastructure only) in supporting signals."""
        groups = set()
        for signal in signals:
            group = self.signal_group_map.get(signal.signal_id, "quality")
            # Only count infrastructure group as geographic (has region info)
            if group == "infrastructure":
                groups.add(group)
        return groups

    def _format_anomalies(self, correlation: CorrelationResult) -> List[Dict]:
        """Format correlation anomalies for output."""
        anomalies = []
        for contradiction in correlation.contradictions:
            anomalies.append(
                {
                    "type": contradiction.type,
                    "severity": contradiction.severity,
                    "signals": list(contradiction.signals),
                    "reason": contradiction.reason,
                }
            )
        return anomalies
