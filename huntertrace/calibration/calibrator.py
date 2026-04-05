"""Main calibration engine orchestrator."""

from __future__ import annotations

from typing import List, Optional

from huntertrace.analysis.models import CorrelationResult
from huntertrace.calibration.models import (
    CalibrationInput,
    CalibrationMetadata,
    CalibrationOutput,
    RegionScore,
    SignalQuality,
)
from huntertrace.calibration.rules import CalibrationRules
from huntertrace.signals.models import Observability


class CalibrationEngine:
    """
    Production-grade calibration engine for false attribution prevention.

    Takes pre-scored candidate regions and refines them using:
    - Contradiction analysis
    - Anonymization detection
    - Signal quality metrics
    - Multi-hop routing patterns
    - International routing complexity

    Does NOT modify:
    - Parsing logic
    - Signal generation
    - Correlation analysis

    ONLY operates on:
    - Candidate region scores
    - Correlation results (contradictions, consistency)
    - Signal quality metrics
    """

    @staticmethod
    def calibrate(
        candidate_region: str,
        base_confidence: float,
        candidate_regions: Optional[List[RegionScore]] = None,
        correlation_result: Optional[CorrelationResult] = None,
        observability: Optional[Observability] = None,
        hop_count: int = 0,
        routing_complexity: float = 0.0,
        anomaly_count: int = 0,
    ) -> CalibrationOutput:
        """
        Calibrate a scoring decision with multi-phase refinement.

        Args:
            candidate_region: Proposed region from scoring engine
            base_confidence: Raw confidence score from scoring engine (0.0-1.0)
            candidate_regions: List of all candidate regions with scores
            correlation_result: CorrelationResult with contradictions, anonymization
            observability: Signal quality metrics (hop_completeness, diversity, agreement)
            hop_count: Number of hops in email chain
            routing_complexity: Measure of geographic routing diversity (0.0-1.0)
            anomaly_count: Number of anomalies detected in chain

        Returns:
            CalibrationOutput with refined region, confidence, verdict, and reasoning
        """

        # Build CalibrationInput
        calibration_input = CalibrationEngine._build_calibration_input(
            candidate_region=candidate_region,
            base_confidence=base_confidence,
            candidate_regions=candidate_regions or [],
            correlation_result=correlation_result,
            observability=observability,
            hop_count=hop_count,
            routing_complexity=routing_complexity,
            anomaly_count=anomaly_count,
        )

        # Apply all calibration phases
        return CalibrationRules.apply_all_phases(calibration_input)

    @staticmethod
    def _build_calibration_input(
        candidate_region: str,
        base_confidence: float,
        candidate_regions: List[RegionScore],
        correlation_result: Optional[CorrelationResult],
        observability: Optional[Observability],
        hop_count: int,
        routing_complexity: float,
        anomaly_count: int,
    ) -> CalibrationInput:
        """Build CalibrationInput from discrete components."""

        # Default to zero if not provided
        consistency_score = 0.0
        contradictions = []
        anonymization_detected = False
        anonymization_confidence = 0.0
        anonymization_strength = "none"

        if correlation_result:
            consistency_score = correlation_result.consistency_score
            contradictions = correlation_result.contradictions
            anonymization_detected = correlation_result.anonymization.detected
            anonymization_confidence = correlation_result.anonymization.confidence
            anonymization_strength = correlation_result.anonymization.strength

        # Default signal quality if not provided
        hop_completeness = 1.0
        signal_diversity = 1.0
        signal_agreement = 1.0

        if observability:
            hop_completeness = observability.hop_completeness
            signal_diversity = observability.signal_diversity
            signal_agreement = observability.signal_agreement

        signal_quality = SignalQuality(
            hop_completeness=hop_completeness,
            signal_diversity=signal_diversity,
            signal_agreement=signal_agreement,
        )

        metadata = CalibrationMetadata(
            hop_count=hop_count,
            routing_complexity=routing_complexity,
            has_anonymization=anonymization_detected,
            anomaly_count=anomaly_count,
        )

        return CalibrationInput(
            candidate_region=candidate_region,
            base_confidence=base_confidence,
            candidate_regions=candidate_regions,
            consistency_score=consistency_score,
            contradictions=contradictions,
            anonymization_detected=anonymization_detected,
            anonymization_confidence=anonymization_confidence,
            anonymization_strength=anonymization_strength,
            signal_quality=signal_quality,
            metadata=metadata,
        )

    @staticmethod
    def calibrate_from_context(
        candidate_region: str,
        base_confidence: float,
        hop_chain,
        signals: List,
        correlation_result: Optional[CorrelationResult],
        observability: Optional[Observability],
    ) -> CalibrationOutput:
        """
        High-level convenience method for calibration given full context.

        This extracts calibration inputs from the hop chain, signals, and
        correlation result, then applies calibration.

        Args:
            candidate_region: Proposed region
            base_confidence: Raw score from scoring engine
            hop_chain: HopChain for hop count and anomaly extraction
            signals: List of signals for metadata extraction
            correlation_result: CorrelationResult with contradictions
            observability: Signal quality metrics

        Returns:
            CalibrationOutput
        """

        # Extract metadata from hop_chain
        hop_count = len(hop_chain.hops) if hop_chain else 0
        anomaly_count = len(hop_chain.anomalies) if hop_chain else 0

        # Calculate routing complexity: measure of geographic diversity
        routing_complexity = CalibrationEngine._calculate_routing_complexity(
            hop_chain, signals
        )

        # Apply calibration
        return CalibrationEngine.calibrate(
            candidate_region=candidate_region,
            base_confidence=base_confidence,
            candidate_regions=[],
            correlation_result=correlation_result,
            observability=observability,
            hop_count=hop_count,
            routing_complexity=routing_complexity,
            anomaly_count=anomaly_count,
        )

    @staticmethod
    def _calculate_routing_complexity(hop_chain, signals) -> float:
        """
        Calculate routing complexity as measure of geographic diversity.

        Returns 0.0 (simple, single region) to 1.0 (highly diverse, multi-continent).
        """
        if not hop_chain or not hop_chain.hops:
            return 0.0

        # Count unique regions/countries from signals
        unique_regions = set()
        for signal in signals:
            if signal.candidate_region and signal.candidate_region not in ("internal", "local"):
                unique_regions.add(signal.candidate_region)

        if not unique_regions:
            return 0.0

        # Simple heuristic: complexity increases with count and diversity
        # Max out at 1.0
        return min(1.0, (len(unique_regions) - 1) / 10.0)
