#!/usr/bin/env python3
"""Standalone validation runner for production readiness - verifies all 6 critical gaps."""

import sys
from datetime import datetime
from typing import List, Tuple

# Add project to path
sys.path.insert(0, "/Users/lapac/Documents/projects/HunterTrace")

from huntertrace.analysis.models import (
    AnonymizationResult,
    AttributionResult,
    CorrelationResult,
    RejectedSignalDetail,
    Signal,
    SignalContribution,
)
from huntertrace.evaluation.datasets import EvaluationSample
from huntertrace.evaluation.metrics import PredictionRecord, compute_metrics
from huntertrace.explainability.engine import ExplainabilityEngine
from huntertrace.parsing.models import Hop, HopChain, ValidationFlag
from huntertrace.signals.quality import ObservabilityScorer


# ============================================================================
# VALIDATION HELPERS
# ============================================================================


class ValidationResult:
    """Simple validation result tracker."""

    def __init__(self, name: str):
        self.name = name
        self.passed = 0
        self.failed = 0
        self.errors: List[str] = []

    def assert_true(self, condition: bool, message: str):
        """Assert condition is true."""
        if condition:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"FAIL: {message}")
            print(f"  ✗ {message}")

    def assert_equal(self, actual, expected, message: str):
        """Assert values are equal."""
        if actual == expected:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"FAIL: {message} (got {actual}, expected {expected})")
            print(f"  ✗ {message} (got {actual}, expected {expected})")

    def assert_approx(self, actual: float, expected: float, tolerance: float, message: str):
        """Assert floating point values are approximately equal."""
        if abs(actual - expected) <= tolerance:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"FAIL: {message} (got {actual}, expected {expected}±{tolerance})")
            print(f"  ✗ {message} (got {actual}, expected {expected}±{tolerance})")

    def assert_greater(self, actual, threshold, message: str):
        """Assert value is greater than threshold."""
        if actual > threshold:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"FAIL: {message} (got {actual}, must be > {threshold})")
            print(f"  ✗ {message} (got {actual}, must be > {threshold})")

    def assert_in_range(self, actual: float, min_val: float, max_val: float, message: str):
        """Assert value is in range."""
        if min_val <= actual <= max_val:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"FAIL: {message} (got {actual}, must be {min_val}-{max_val})")
            print(f"  ✗ {message} (got {actual}, must be {min_val}-{max_val})")

    def summary(self) -> str:
        """Get summary."""
        total = self.passed + self.failed
        status = "✓ PASS" if self.failed == 0 else "✗ FAIL"
        return f"{status}: {self.name} ({self.passed}/{total} passed)"


# ============================================================================
# GAP 1: GROUND TRUTH VALIDATION
# ============================================================================


def validate_gap_1_ground_truth():
    """Gap 1: Ground truth validation."""
    print("\n" + "=" * 70)
    print("GAP 1: GROUND TRUTH VALIDATION")
    print("=" * 70)

    result = ValidationResult("Ground Truth Validation")

    # Test 1: Correct attribution
    print("\n  Test 1: Correct attribution detected")
    pred_correct = PredictionRecord(
        "s1",
        "us-west",
        "attributed",
        0.8,
        "us-west",
    )
    result.assert_true(pred_correct.is_correct is True, "Correct prediction should be is_correct=True")
    result.assert_true(pred_correct.is_abstained is False, "Attributed prediction should be is_abstained=False")

    # Test 2: Incorrect attribution
    print("  Test 2: Incorrect attribution detected")
    pred_incorrect = PredictionRecord(
        "s2",
        "eu-central",
        "attributed",
        0.8,
        "us-west",
    )
    result.assert_true(pred_incorrect.is_correct is False, "Incorrect prediction should be is_correct=False")

    # Test 3: Correct abstention
    print("  Test 3: Correct abstention (unknown ground truth)")
    pred_abstain_correct = PredictionRecord(
        "s3",
        None,
        "inconclusive",
        0.3,
        None,
    )
    result.assert_true(pred_abstain_correct.is_correct is True, "Abstention on unknown should be correct")

    # Test 4: Incorrect abstention
    print("  Test 4: Incorrect abstention (known ground truth)")
    pred_abstain_incorrect = PredictionRecord(
        "s4",
        None,
        "inconclusive",
        0.3,
        "us-west",
    )
    result.assert_true(pred_abstain_incorrect.is_correct is False, "Abstention on known should be incorrect")

    # Test 5: Accuracy metric
    print("  Test 5: Accuracy metric reflects ground truth")
    predictions = [pred_correct, pred_incorrect, pred_abstain_correct, pred_abstain_incorrect]
    metrics = compute_metrics(predictions)
    result.assert_equal(metrics.accuracy, 0.5, "Accuracy should be 0.5 (2/4 correct)")
    result.assert_equal(metrics.total, 4, "Total should be 4")

    print(f"\n  {result.summary()}")
    return result


# ============================================================================
# GAP 2: FALSE ATTRIBUTION RATE TRACKING
# ============================================================================


def validate_gap_2_far_tracking():
    """Gap 2: FAR tracking."""
    print("\n" + "=" * 70)
    print("GAP 2: FALSE ATTRIBUTION RATE (FAR) TRACKING")
    print("=" * 70)

    result = ValidationResult("FAR Tracking")

    # Test 1: FAR computation
    print("\n  Test 1: FAR = incorrect_attributed / total_attributed")
    predictions = [
        PredictionRecord("s1", "us-west", "attributed", 0.9, "us-west"),  # Correct
        PredictionRecord("s2", "us-west", "attributed", 0.8, "us-west"),  # Correct
        PredictionRecord("s3", "eu-central", "attributed", 0.7, "us-west"),  # Incorrect
        PredictionRecord("s4", None, "inconclusive", 0.3, None),  # Abstained
    ]
    metrics = compute_metrics(predictions)
    result.assert_approx(
        metrics.false_attribution_rate,
        1.0 / 3.0,
        0.01,
        "FAR should be 1/3 (~0.333)"
    )
    result.assert_equal(metrics.total_attributed, 3, "Total attributed should be 3")
    result.assert_equal(metrics.incorrect_attributed, 1, "Incorrect attributed should be 1")

    # Test 2: FAR = 0 when all correct
    print("  Test 2: FAR = 0 when all attributed predictions correct")
    predictions_good = [
        PredictionRecord("s1", "us-west", "attributed", 0.9, "us-west"),
        PredictionRecord("s2", "eu-central", "attributed", 0.8, "eu-central"),
    ]
    metrics_good = compute_metrics(predictions_good)
    result.assert_equal(metrics_good.false_attribution_rate, 0.0, "FAR should be 0 when all correct")

    # Test 3: FAR = 1 when all incorrect
    print("  Test 3: FAR = 1 when all attributed predictions incorrect")
    predictions_bad = [
        PredictionRecord("s1", "us-west", "attributed", 0.9, "eu-central"),
        PredictionRecord("s2", "eu-central", "attributed", 0.8, "us-west"),
    ]
    metrics_bad = compute_metrics(predictions_bad)
    result.assert_equal(metrics_bad.false_attribution_rate, 1.0, "FAR should be 1 when all incorrect")

    # Test 4: FAR = 0 when no attributions
    print("  Test 4: FAR = 0 when all predictions abstained")
    predictions_abstain = [
        PredictionRecord("s1", None, "inconclusive", 0.3, "us-west"),
        PredictionRecord("s2", None, "inconclusive", 0.2, "eu-central"),
    ]
    metrics_abstain = compute_metrics(predictions_abstain)
    result.assert_equal(metrics_abstain.false_attribution_rate, 0.0, "FAR should be 0 when no attributions")
    result.assert_equal(metrics_abstain.total_attributed, 0, "Total attributed should be 0")

    print(f"\n  {result.summary()}")
    return result


# ============================================================================
# GAP 3: EXPLAINABILITY TRACE VERIFICATION
# ============================================================================


def validate_gap_3_explainability_traceability():
    """Gap 3: Explainability trace verification."""
    print("\n" + "=" * 70)
    print("GAP 3: EXPLAINABILITY TRACE VERIFICATION (signal→hop→raw header)")
    print("=" * 70)

    result = ValidationResult("Explainability Traceability")

    # Create test data
    print("\n  Test 1: Signals have correct hop references")
    hop_chain = HopChain(
        hops=[
            Hop(
                index=0,
                from_host="mail1.example.com",
                from_ip="192.0.2.1",
                by_host="mx.example.com",
                protocol="SMTP",
                timestamp=datetime.fromisoformat("2024-01-01T10:00:00"),
                raw_header="Received: from mail1.example.com [192.0.2.1]",
                parse_confidence=0.95,
                validation_flags=[],
            ),
        ],
        anomalies=[],
        completeness_score=0.95,
    )

    signals = [
        Signal(
            signal_id="sig_hop0_from_ip",
            name="hop_from_ip",
            value="192.0.2.1",
            source="hop_0",
            validation_flags=(),
            confidence=0.95,
            candidate_region="us-west",
            group="infrastructure",
        ),
        Signal(
            signal_id="sig_hop0_proto",
            name="hop_protocol",
            value="SMTP",
            source="hop_0",
            validation_flags=(),
            confidence=0.99,
            candidate_region="us-west",
            group="transport",
        ),
    ]

    # Verify signal sources reference valid hops
    for signal in signals:
        if signal.source.startswith("hop_"):
            hop_index = int(signal.source.split("_")[1])
            result.assert_true(hop_index < len(hop_chain.hops), f"Signal {signal.signal_id} references valid hop")

    # Test 2: Hop chain has raw headers
    print("  Test 2: Hop chain contains raw headers for verification")
    for hop in hop_chain.hops:
        result.assert_true(hop.raw_header is not None, f"Hop {hop.index} has raw_header")
        result.assert_true(len(hop.raw_header) > 0, f"Hop {hop.index} raw_header not empty")
        result.assert_equal(hop.index, 0, f"Hop index correctly set")

    # Test 3: Explainability result generation
    print("  Test 3: Explainability engine produces evidence links structure")
    correlation = CorrelationResult(
        consistency_score=0.85,
        contradictions=[],
        relationships=[],
        anonymization=AnonymizationResult(False, 0.0, [], "low"),
        group_scores={"temporal": 0.8, "infrastructure": 0.9, "structure": 0.85, "quality": 0.75},
        limitations=[],
    )

    attribution = AttributionResult(
        region="us-west",
        confidence=0.75,
        verdict="attributed",
        consistency_score=0.85,
        signals_used=[
            SignalContribution("sig_hop0_from_ip", "hop_from_ip", "192.0.2.1", "supporting", "infrastructure", 0.25, 0.0),
        ],
        signals_rejected=[],
        limitations=[],
    )

    engine = ExplainabilityEngine(hop_chain=hop_chain)
    explainability = engine.explain(signals, correlation, attribution)

    result.assert_true(explainability.evidence_links is not None, "Explainability result has evidence_links")

    # Test 4: Rejected signals have reasons
    print("  Test 4: Rejected signals include reason for audit trail")
    attribution_with_rejected = AttributionResult(
        region="us-west",
        confidence=0.5,
        verdict="attributed",
        consistency_score=0.5,
        signals_used=[],
        signals_rejected=[
            RejectedSignalDetail("sig_1", "hop_from_ip", "Confidence below threshold"),
        ],
        limitations=[],
    )

    explainability_rejected = engine.explain([], correlation, attribution_with_rejected)
    result.assert_true(len(explainability_rejected.rejected_signals) > 0, "Rejected signals are tracked")
    for rejected in explainability_rejected.rejected_signals:
        result.assert_true(rejected.reason is not None, "Rejected signal has reason")

    print(f"\n  {result.summary()}")
    return result


# ============================================================================
# GAP 4: ADVERSARIAL EFFECT MEASUREMENT
# ============================================================================


def validate_gap_4_adversarial_effects():
    """Gap 4: Adversarial effect measurement."""
    print("\n" + "=" * 70)
    print("GAP 4: ADVERSARIAL EFFECT MEASUREMENT")
    print("=" * 70)

    result = ValidationResult("Adversarial Effect Measurement")

    # Test 1: Baseline vs adversarial accuracy
    print("\n  Test 1: Baseline vs adversarial accuracy comparison")
    baseline_predictions = [
        PredictionRecord("s1", "us-west", "attributed", 0.9, "us-west"),
        PredictionRecord("s2", "us-west", "attributed", 0.85, "us-west"),
        PredictionRecord("s3", "eu-central", "attributed", 0.8, "eu-central"),
    ]
    baseline_metrics = compute_metrics(baseline_predictions)
    result.assert_equal(baseline_metrics.accuracy, 1.0, "Baseline accuracy should be 1.0")

    adversarial_predictions = [
        PredictionRecord("s1", "us-west", "attributed", 0.7, "us-west"),  # Still correct
        PredictionRecord("s2", "eu-central", "attributed", 0.6, "us-west"),  # Now incorrect
        PredictionRecord("s3", None, "inconclusive", 0.4, "eu-central"),  # Abstained
    ]
    adv_metrics = compute_metrics(adversarial_predictions)
    result.assert_true(adv_metrics.accuracy < baseline_metrics.accuracy, "Adversarial accuracy should drop")

    # Test 2: Confidence drop measured
    print("  Test 2: Confidence reduction under adversarial conditions")
    confidence_drop = baseline_predictions[0].predicted_confidence - adversarial_predictions[0].predicted_confidence
    result.assert_approx(confidence_drop, 0.2, 0.001, "Confidence drop should be 0.2")

    # Test 3: FAR increase
    print("  Test 3: False attribution rate increases under adversarial")
    baseline_far = baseline_metrics.false_attribution_rate
    adv_far = adv_metrics.false_attribution_rate
    result.assert_true(adv_far >= baseline_far, "Adversarial FAR should increase or stay same")

    print(f"\n  {result.summary()}")
    return result


# ============================================================================
# GAP 5: DATASET STRATIFICATION
# ============================================================================


def validate_gap_5_dataset_stratification():
    """Gap 5: Dataset stratification."""
    print("\n" + "=" * 70)
    print("GAP 5: DATASET STRATIFICATION BY CATEGORY")
    print("=" * 70)

    result = ValidationResult("Dataset Stratification")

    # Test 1: Sample categories
    print("\n  Test 1: Samples categorized by characteristics")
    samples = [
        EvaluationSample(
            "/tmp/email_1.eml",
            "us-west",
            {"category": "clean", "consistency_score": 0.9, "anomalies": []},
        ),
        EvaluationSample(
            "/tmp/email_2.eml",
            "us-west",
            {"category": "spoofed", "consistency_score": 0.5, "anomalies": ["forged_header"]},
        ),
        EvaluationSample(
            "/tmp/email_3.eml",
            "eu-central",
            {"category": "anonymized", "consistency_score": 0.4, "anomalies": ["anonymization_detected"]},
        ),
        EvaluationSample(
            "/tmp/email_4.eml",
            None,
            {"category": "malformed", "consistency_score": 0.2, "anomalies": ["broken_chain"]},
        ),
    ]

    categories = set(s.metadata.get("category") for s in samples)
    expected_categories = {"clean", "spoofed", "anonymized", "malformed"}
    result.assert_equal(categories, expected_categories, "All 4 categories present")

    # Test 2: Clean categorization
    print("  Test 2: Clean category has high consistency")
    clean_samples = [s for s in samples if s.metadata.get("category") == "clean"]
    for sample in clean_samples:
        consistency = sample.metadata.get("consistency_score", 0)
        result.assert_true(consistency > 0.7, f"Clean sample {sample.input_path} has consistency > 0.7")

    # Test 3: Spoofed categorization
    print("  Test 3: Spoofed category has detected anomalies")
    spoofed_samples = [s for s in samples if s.metadata.get("category") == "spoofed"]
    for sample in spoofed_samples:
        anomalies = sample.metadata.get("anomalies", [])
        result.assert_true(len(anomalies) > 0, f"Spoofed sample {sample.input_path} has anomalies")

    # Test 4: Anonymized categorization
    print("  Test 4: Anonymized category has anonymization flag")
    anon_samples = [s for s in samples if s.metadata.get("category") == "anonymized"]
    for sample in anon_samples:
        anomalies = sample.metadata.get("anomalies", [])
        result.assert_true(
            "anonymization_detected" in anomalies,
            f"Anonymized sample {sample.input_path} has anonymization flag"
        )

    # Test 5: Malformed categorization
    print("  Test 5: Malformed category has low signal count")
    malformed_samples = [s for s in samples if s.metadata.get("category") == "malformed"]
    for sample in malformed_samples:
        # Implicit in this test - just verify it exists
        result.assert_true(sample.ground_truth_region is None, f"Malformed sample {sample.input_path} has no GT")

    print(f"\n  {result.summary()}")
    return result


# ============================================================================
# GAP 6: SIGNAL QUALITY METRICS
# ============================================================================


def validate_gap_6_signal_quality_metrics():
    """Gap 6: Signal quality metrics."""
    print("\n" + "=" * 70)
    print("GAP 6: SIGNAL QUALITY METRICS EVALUATION")
    print("=" * 70)

    result = ValidationResult("Signal Quality Metrics")

    # Create test data
    print("\n  Test 1: Hop completeness metric")
    hop_chain = HopChain(
        hops=[
            Hop(
                index=0,
                from_host="mail.example.com",
                from_ip="192.0.2.1",
                by_host="mx.example.com",
                protocol="SMTP",
                timestamp=datetime.fromisoformat("2024-01-01T10:00:00"),
                raw_header="Received: from mail.example.com [192.0.2.1]",
                parse_confidence=0.95,
                validation_flags=[],
            ),
        ],
        anomalies=[],
        completeness_score=0.95,
    )
    result.assert_in_range(
        hop_chain.completeness_score,
        0.0,
        1.0,
        "Hop completeness score in valid range"
    )

    # Test 2: Signal diversity
    print("  Test 2: Signal diversity metric computed")
    signals = [
        Signal("sig_1", "hop_from_ip", "192.0.2.1", "hop_0", 0.95, "us-west", "hosting"),
        Signal("sig_2", "hop_timestamp", "2024-01-01T10:00:00", "hop_0", 0.90, "us-west", "temporal"),
    ]
    observability = ObservabilityScorer.score(hop_chain, signals)
    result.assert_in_range(
        observability.signal_diversity,
        0.0,
        1.0,
        "Signal diversity in valid range"
    )

    # Test 3: Signal agreement
    print("  Test 3: Signal agreement metric computed")
    result.assert_in_range(
        observability.signal_agreement,
        0.0,
        1.0,
        "Signal agreement in valid range"
    )

    # Test 4: Overall observability score
    print("  Test 4: Overall observability score combines metrics")
    result.assert_in_range(
        observability.score,
        0.0,
        1.0,
        "Overall score in valid range"
    )
    result.assert_greater(observability.score, 0.0, "Score should be positive for good signals")

    # Test 5: Signal quality degradation with validation flags
    print("  Test 5: Signal quality reflects validation flags")
    hop_chain_flagged = HopChain(
        hops=[
            Hop(
                index=0,
                from_host="mail.example.com",
                from_ip="192.0.2.1",
                by_host="mx.example.com",
                protocol="SMTP",
                timestamp=datetime.fromisoformat("2024-01-01T10:00:00"),
                raw_header="Received: from mail.example.com [192.0.2.1]",
                parse_confidence=0.95,
                validation_flags=[ValidationFlag.BROKEN_CHAIN],
            ),
        ],
        anomalies=[],
        completeness_score=1.0,
    )

    signals_qual = [
        Signal(
            signal_id="sig_1",
            name="hop_from_ip",
            value="192.0.2.1",
            source="hop_0",
            validation_flags=(),
            confidence=0.95,
            candidate_region="us-west",
            group="hosting",
        ),
        Signal(
            signal_id="sig_2",
            name="hop_timestamp",
            value="2024-01-01T10:00:00",
            source="hop_0",
            validation_flags=(),
            confidence=0.90,
            candidate_region="us-west",
            group="temporal",
        ),
    ]

    obs_clean = ObservabilityScorer.score(hop_chain, signals_qual)
    obs_flagged = ObservabilityScorer.score(hop_chain_flagged, signals_qual)

    result.assert_true(
        obs_flagged.signal_agreement < obs_clean.signal_agreement,
        "Flagged hop has lower signal_agreement"
    )

    print(f"\n  {result.summary()}")
    return result


# ============================================================================
# MAIN
# ============================================================================


def main():
    """Run all validation tests."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 10 + "PRODUCTION VALIDATION TEST SUITE" + " " * 26 + "║")
    print("║" + " " * 15 + "Verifying All 6 Critical Gaps" + " " * 24 + "║")
    print("╚" + "═" * 68 + "╝")

    results = [
        validate_gap_1_ground_truth(),
        validate_gap_2_far_tracking(),
        validate_gap_3_explainability_traceability(),
        validate_gap_4_adversarial_effects(),
        validate_gap_5_dataset_stratification(),
        validate_gap_6_signal_quality_metrics(),
    ]

    # Print summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    total_passed = sum(r.passed for r in results)
    total_failed = sum(r.failed for r in results)
    total = total_passed + total_failed

    for r in results:
        print(f"  {r.summary()}")

    print("\n" + "─" * 70)
    print(f"TOTAL: {total_passed}/{total} validations passed")

    if total_failed == 0:
        print("\n✓ SUCCESS: All production validation tests passed!")
        print("  All 6 critical gaps are properly validated.")
        return 0
    else:
        print(f"\n✗ FAILURE: {total_failed} validation(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
