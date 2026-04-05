"""
Example: Integrating calibration layer with scoring pipeline.

Shows how calibration fits into the full analysis workflow.
"""

from huntertrace.analysis.models import (
    AnonymizationResult,
    Contradiction,
    CorrelationResult,
    ScoringConfig,
)
from huntertrace.calibration.calibrator import CalibrationEngine
from huntertrace.signals.models import Observability

# Example: Process a suspicious email


def analyze_email_with_calibration(
    hop_chain,
    signals,
    correlation_result,
    observability,
    base_region,
    base_confidence,
):
    """
    Complete analysis pipeline with calibration refinement.

    Workflow:
    1. Parse email headers → HopChain
    2. Extract signals → List[Signal]
    3. Correlate signals → CorrelationResult
    4. Score attribution → base_confidence
    5. CALIBRATE → refined_confidence [NEW]
    6. Return final result
    """

    print("=" * 70)
    print("EMAIL ANALYSIS WITH CALIBRATION")
    print("=" * 70)

    print("\n[1] Pipeline Setup")
    print(f"    Candidate region: {base_region}")
    print(f"    Base confidence: {base_confidence:.4f}")
    print(f"    Correlation consistency: {correlation_result.consistency_score:.4f}")
    print(f"    Hops: {len(hop_chain.hops)}")
    print(f"    Anomalies: {len(hop_chain.anomalies)}")

    print("\n[2] Pre-Calibration State")
    print(f"    Contradictions: {len(correlation_result.contradictions)}")
    for i, contradiction in enumerate(correlation_result.contradictions):
        print(f"      {i+1}. {contradiction.type} ({contradiction.severity})")
    print(f"    Anonymization: {correlation_result.anonymization.detected}")
    if correlation_result.anonymization.detected:
        print(f"      Strength: {correlation_result.anonymization.strength}")
        print(f"      Confidence: {correlation_result.anonymization.confidence:.4f}")

    print("\n[3] Signal Quality")
    print(f"    Hop completeness: {observability.hop_completeness:.4f}")
    print(f"    Signal diversity: {observability.signal_diversity:.4f}")
    print(f"    Signal agreement: {observability.signal_agreement:.4f}")

    # CALIBRATION: Apply 12-phase refinement
    print("\n[4] Applying Calibration Refinement...")

    calibrated = CalibrationEngine.calibrate(
        candidate_region=base_region,
        base_confidence=base_confidence,
        correlation_result=correlation_result,
        observability=observability,
        hop_count=len(hop_chain.hops),
        routing_complexity=0.3,  # Example value
        anomaly_count=len(hop_chain.anomalies),
    )

    print(f"\n[5] Calibration Results")
    print(f"    Calibrated confidence: {calibrated.calibrated_confidence:.4f}")
    print(f"    Verdict: {calibrated.verdict}")
    print(f"    Final region: {calibrated.final_region}")
    print(f"\n    Adjustments applied:")
    for adjustment in calibrated.adjustments_applied:
        print(f"      • {adjustment}")

    print(f"\n    Reasoning:")
    print(f"      {calibrated.reasoning}")

    print("\n[6] Attribution Decision")
    if calibrated.verdict == "attributed":
        print(f"    ✓ ATTRIBUTED to {calibrated.final_region}")
        print(
            f"      Confidence: {calibrated.calibrated_confidence:.1%} "
            f"(down from {base_confidence:.1%})"
        )
    else:
        print(f"    ✗ INCONCLUSIVE")
        print(f"      Confidence too low: {calibrated.calibrated_confidence:.1%}")

    print("\n" + "=" * 70)

    return calibrated


# Example scenarios

if __name__ == "__main__":
    # Mock data
    class MockHop:
        def __init__(self):
            self.validation_flags = []

    class MockHopChain:
        def __init__(self, hop_count=3):
            self.hops = [MockHop() for _ in range(hop_count)]
            self.anomalies = []

    print("\n\n###############################################################")
    print("#  SCENARIO 1: Clean Email (Expected: HIGH CONFIDENCE)")
    print("###############################################################\n")

    clean_correlation = CorrelationResult(
        consistency_score=0.92,
        contradictions=[],
        relationships=[],
        anonymization=AnonymizationResult(
            detected=False, confidence=0.0, indicators=[], strength="none"
        ),
        group_scores={},
        limitations=[],
    )

    clean_observability = Observability(
        hop_completeness=0.94,
        signal_diversity=0.88,
        signal_agreement=0.92,
        score=0.91,
    )

    analyze_email_with_calibration(
        hop_chain=MockHopChain(hop_count=3),
        signals=[],
        correlation_result=clean_correlation,
        observability=clean_observability,
        base_region="US",
        base_confidence=0.82,
    )

    print("\n\n###############################################################")
    print("#  SCENARIO 2: Spoofed Email (Expected: INCONCLUSIVE)")
    print("###############################################################\n")

    spoofed_correlation = CorrelationResult(
        consistency_score=0.25,
        contradictions=[
            Contradiction(
                type="region_mismatch",
                signals=["hop_from_ip", "hop_from_host"],
                reason="IP from US, hostname from CN - likely spoofed",
                severity="high",
            )
        ],
        relationships=[],
        anonymization=AnonymizationResult(
            detected=False, confidence=0.0, indicators=[], strength="none"
        ),
        group_scores={},
        limitations=[],
    )

    spoofed_observability = Observability(
        hop_completeness=0.65,
        signal_diversity=0.72,
        signal_agreement=0.45,
        score=0.60,
    )

    analyze_email_with_calibration(
        hop_chain=MockHopChain(hop_count=2),
        signals=[],
        correlation_result=spoofed_correlation,
        observability=spoofed_observability,
        base_region="CN",
        base_confidence=0.68,
    )

    print("\n\n###############################################################")
    print("#  SCENARIO 3: Anonymized Email (Expected: LOW/INCONCLUSIVE)")
    print("###############################################################\n")

    anon_correlation = CorrelationResult(
        consistency_score=0.71,
        contradictions=[],
        relationships=[],
        anonymization=AnonymizationResult(
            detected=True,
            confidence=0.88,
            indicators=["vpn_exit_node", "proxy_headers"],
            strength="high",
        ),
        group_scores={},
        limitations=["Anonymization detected"],
    )

    anon_observability = Observability(
        hop_completeness=0.79,
        signal_diversity=0.58,
        signal_agreement=0.68,
        score=0.68,
    )

    analyze_email_with_calibration(
        hop_chain=MockHopChain(hop_count=3),
        signals=[],
        correlation_result=anon_correlation,
        observability=anon_observability,
        base_region="NL",
        base_confidence=0.74,
    )

    print("\n\n###############################################################")
    print("#  SCENARIO 4: Multi-Hop Enterprise (Expected: MAINTAINED)")
    print("###############################################################\n")

    enterprise_correlation = CorrelationResult(
        consistency_score=0.88,
        contradictions=[],
        relationships=[],
        anonymization=AnonymizationResult(
            detected=False, confidence=0.0, indicators=[], strength="none"
        ),
        group_scores={},
        limitations=[],
    )

    enterprise_observability = Observability(
        hop_completeness=0.91,
        signal_diversity=0.85,
        signal_agreement=0.89,
        score=0.88,
    )

    analyze_email_with_calibration(
        hop_chain=MockHopChain(hop_count=6),
        signals=[],
        correlation_result=enterprise_correlation,
        observability=enterprise_observability,
        base_region="US",
        base_confidence=0.71,
    )

    print("\n\n###############################################################")
    print("#  SCENARIO 5: Contradictory Signals (Expected: REDUCED)")
    print("###############################################################\n")

    conflict_correlation = CorrelationResult(
        consistency_score=0.45,
        contradictions=[
            Contradiction(
                type="timestamp_anomaly",
                signals=["hop_timestamp_utc", "hop_by_host"],
                reason="Timestamps indicate different regions",
                severity="medium",
            ),
            Contradiction(
                type="protocol_inconsistency",
                signals=["hop_protocol", "hop_from_ip"],
                reason="Protocol doesn't match network location",
                severity="low",
            ),
        ],
        relationships=[],
        anonymization=AnonymizationResult(
            detected=False, confidence=0.0, indicators=[], strength="none"
        ),
        group_scores={},
        limitations=["Multiple contradictions detected"],
    )

    conflict_observability = Observability(
        hop_completeness=0.82,
        signal_diversity=0.76,
        signal_agreement=0.62,
        score=0.73,
    )

    analyze_email_with_calibration(
        hop_chain=MockHopChain(hop_count=4),
        signals=[],
        correlation_result=conflict_correlation,
        observability=conflict_observability,
        base_region="DE",
        base_confidence=0.69,
    )

    print("\n" + "=" * 70)
    print("EXAMPLE ANALYSIS COMPLETE")
    print("=" * 70)
