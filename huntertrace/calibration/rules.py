"""Calibration rules for deterministic confidence refinement."""

from __future__ import annotations

from typing import List, Tuple

from huntertrace.calibration.models import CalibrationInput, CalibrationOutput


class CalibrationRules:
    """
    12-phase deterministic calibration rules for reducing false attribution.

    Operates on: correlation + signal quality outputs
    Does NOT modify: parsing, signals, correlation logic
    """

    @staticmethod
    def apply_all_phases(calibration_input: CalibrationInput) -> CalibrationOutput:
        """Apply all 12 calibration phases deterministically."""

        confidence = calibration_input.base_confidence
        verdict = "attributed"
        adjustments: List[str] = []
        reasoning_parts: List[str] = []

        # PHASE 1: Contradiction Guard (CRITICAL)
        confidence, phase1_adjustments = CalibrationRules.phase_1_contradiction_guard(
            confidence, calibration_input.contradictions
        )
        adjustments.extend(phase1_adjustments)
        if phase1_adjustments:
            reasoning_parts.append(
                f"Phase 1: Applied contradiction penalty ({phase1_adjustments})"
            )

        # PHASE 2: Anonymization Penalty
        confidence, phase2_adjustments, phase2_verdict = (
            CalibrationRules.phase_2_anonymization_penalty(
                confidence,
                calibration_input.anonymization_detected,
                calibration_input.signal_quality.signal_agreement,
                calibration_input.anonymization_strength,
            )
        )
        adjustments.extend(phase2_adjustments)
        if phase2_verdict:
            verdict = phase2_verdict
        if phase2_adjustments:
            reasoning_parts.append(f"Phase 2: Applied anonymization penalty ({phase2_adjustments})")

        # PHASE 3: Signal Quality Calibration
        confidence, phase3_adjustments = CalibrationRules.phase_3_signal_quality(
            confidence, calibration_input.signal_quality
        )
        adjustments.extend(phase3_adjustments)
        if phase3_adjustments:
            reasoning_parts.append(f"Phase 3: Applied signal quality calibration ({phase3_adjustments})")

        # PHASE 4: Multi-Hop Boost (IMPORTANT)
        confidence, phase4_adjustments = CalibrationRules.phase_4_multi_hop_boost(
            confidence, calibration_input.metadata.hop_count, calibration_input.signal_quality.signal_agreement
        )
        adjustments.extend(phase4_adjustments)
        if phase4_adjustments:
            reasoning_parts.append(f"Phase 4: Applied multi-hop boost ({phase4_adjustments})")

        # PHASE 5: International Routing Handling
        confidence, phase5_adjustments = CalibrationRules.phase_5_international_routing(
            confidence,
            calibration_input.metadata.routing_complexity,
            calibration_input.signal_quality.signal_agreement,
        )
        adjustments.extend(phase5_adjustments)
        if phase5_adjustments:
            reasoning_parts.append(f"Phase 5: Applied international routing handling ({phase5_adjustments})")

        # PHASE 6: Low Signal Safety
        confidence, phase6_adjustments, phase6_verdict = (
            CalibrationRules.phase_6_low_signal_safety(
                confidence,
                calibration_input.signal_quality.hop_completeness,
                calibration_input.metadata,
            )
        )
        adjustments.extend(phase6_adjustments)
        if phase6_verdict:
            verdict = phase6_verdict
        if phase6_adjustments:
            reasoning_parts.append(f"Phase 6: Applied low signal safety ({phase6_adjustments})")

        # PHASE 7: Confidence Normalization
        confidence = CalibrationRules.phase_7_normalize_confidence(confidence)

        # PHASE 8: Abstention Rule
        verdict = CalibrationRules.phase_8_abstention(confidence, verdict)

        # PHASE 9: False Attribution Prevention
        confidence, phase9_adjustments = CalibrationRules.phase_9_false_attribution_prevention(
            confidence, calibration_input.contradictions
        )
        adjustments.extend(phase9_adjustments)
        if phase9_adjustments:
            reasoning_parts.append(f"Phase 9: Applied false attribution prevention ({phase9_adjustments})")

        # PHASE 10: Reasoning Output (built incrementally above)

        # PHASE 11: Determinism (no randomness - implicit, all operations deterministic)

        # PHASE 12: Testing (separate test file)

        # Determine final region
        final_region = None
        if verdict == "attributed":
            final_region = calibration_input.candidate_region

        reasoning = "; ".join(reasoning_parts)
        if not reasoning:
            if verdict == "attributed":
                reasoning = f"Attribution confirmed with {confidence:.1%} confidence after calibration"
            else:
                reasoning = "Abstained due to insufficient confidence after calibration"

        return CalibrationOutput(
            final_region=final_region,
            calibrated_confidence=confidence,
            verdict=verdict,
            adjustments_applied=adjustments,
            reasoning=reasoning,
        )

    @staticmethod
    def phase_1_contradiction_guard(
        confidence: float, contradictions: List
    ) -> Tuple[float, List[str]]:
        """PHASE 1: Guard against contradictions."""
        adjustments: List[str] = []

        if not contradictions:
            return confidence, adjustments

        # Separate by severity
        high_severity = [c for c in contradictions if c.severity == "high"]
        medium_severity = [c for c in contradictions if c.severity == "medium"]
        low_severity = [c for c in contradictions if c.severity == "low"]

        if high_severity:
            confidence = 0.0
            adjustments.append("high_contradiction_guard")
        elif medium_severity:
            confidence *= 0.3
            adjustments.append("medium_contradiction_penalty")
        elif low_severity:
            confidence *= 0.6
            adjustments.append("low_contradiction_penalty")

        return confidence, adjustments

    @staticmethod
    def phase_2_anonymization_penalty(
        confidence: float,
        anonymization_detected: bool,
        signal_agreement: float,
        anonymization_strength: str,
    ) -> Tuple[float, List[str], str | None]:
        """PHASE 2: Penalty for anonymization detection."""
        adjustments: List[str] = []
        verdict = None

        if not anonymization_detected:
            return confidence, adjustments, verdict

        # Apply penalty based on strength
        if anonymization_strength == "high":
            confidence *= 0.15
            adjustments.append("high_anonymization_penalty")
        elif anonymization_strength == "medium":
            confidence *= 0.25
            adjustments.append("medium_anonymization_penalty")
        elif anonymization_strength == "low":
            confidence *= 0.4
            adjustments.append("low_anonymization_penalty")
        else:
            confidence *= 0.2
            adjustments.append("anonymization_penalty")

        # If anonymization + low signal agreement, force inconclusive
        if anonymization_detected and signal_agreement < 0.5:
            verdict = "inconclusive"
            adjustments.append("anonymization_low_agreement_abstention")

        return confidence, adjustments, verdict

    @staticmethod
    def phase_3_signal_quality(confidence: float, signal_quality) -> Tuple[float, List[str]]:
        """PHASE 3: Multiplicative signal quality calibration."""
        adjustments: List[str] = []

        # Apply multiplicative adjustments
        initial_confidence = confidence

        # Hop completeness: direct multiplier
        confidence *= signal_quality.hop_completeness

        # Signal agreement: direct multiplier
        confidence *= signal_quality.signal_agreement

        # Signal diversity: clamped to [0.3, 1.0] before multiplication
        diversity_factor = max(0.3, min(1.0, signal_quality.signal_diversity))
        confidence *= diversity_factor

        if confidence < initial_confidence:
            adjustments.append("signal_quality_degradation")
        elif confidence > initial_confidence:
            adjustments.append("signal_quality_boost")

        return confidence, adjustments

    @staticmethod
    def phase_4_multi_hop_boost(confidence: float, hop_count: int, signal_agreement: float) -> Tuple[float, List[str]]:
        """PHASE 4: Boost for multi-hop emails with consistent signals."""
        adjustments: List[str] = []

        if hop_count >= 3 and signal_agreement > 0.7:
            confidence += 0.15
            adjustments.append("multi_hop_consistency_boost")

        return confidence, adjustments

    @staticmethod
    def phase_5_international_routing(
        confidence: float, routing_complexity: float, signal_agreement: float
    ) -> Tuple[float, List[str]]:
        """PHASE 5: Handle international routing edge cases."""
        adjustments: List[str] = []

        # High routing diversity with poor agreement = penalty
        if routing_complexity > 0.7 and signal_agreement < 0.6:
            confidence *= 0.7
            adjustments.append("international_routing_penalty")

        # Don't penalize high diversity with strong agreement
        return confidence, adjustments

    @staticmethod
    def phase_6_low_signal_safety(
        confidence: float, hop_completeness: float, metadata
    ) -> Tuple[float, List[str], str | None]:
        """PHASE 6: Enforce abstention for insufficient signal coverage."""
        adjustments: List[str] = []
        verdict = None

        # Threshold: hop completeness < 0.4
        if hop_completeness < 0.4:
            confidence *= 0.2
            adjustments.append("low_hop_completeness_penalty")
            verdict = "inconclusive"

        # Threshold: very few hops
        if metadata.hop_count < 2:
            confidence *= 0.3
            adjustments.append("minimal_hop_count_penalty")
            if hop_completeness < 0.5:
                verdict = "inconclusive"

        return confidence, adjustments, verdict

    @staticmethod
    def phase_7_normalize_confidence(confidence: float) -> float:
        """PHASE 7: Normalize confidence to [0.0, 0.99]."""
        return max(0.0, min(0.99, confidence))

    @staticmethod
    def phase_8_abstention(confidence: float, current_verdict: str) -> str:
        """PHASE 8: Enforce abstention rule for low confidence."""
        if confidence < 0.4:
            return "inconclusive"
        return current_verdict

    @staticmethod
    def phase_9_false_attribution_prevention(
        confidence: float, contradictions: List
    ) -> Tuple[float, List[str]]:
        """
        PHASE 9: Final safety check - force lower confidence
        if contradictions exist and confidence is high.
        """
        adjustments: List[str] = []

        if contradictions and confidence > 0.6:
            confidence *= 0.4
            adjustments.append("contradiction_high_confidence_penalty")

        return confidence, adjustments
