"""Metrics computation for testing framework.

Calculates layer-wise and pipeline-wide metrics.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Optional, Any


@dataclass
class TestResult:
    """Result of a single test execution."""

    sample_id: str
    stage: str  # "parsing", "signals", "correlation", "scoring", "explainability", "full"
    passed: bool
    error: Optional[str] = None
    duration_ms: float = 0.0
    output: dict = field(default_factory=dict)  # Actual layer output (serializable)
    validated_checks: dict = field(default_factory=dict)  # Validation check results
    output_hash: Optional[str] = None  # Hash for determinism checks

    def to_dict(self):
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class LayerMetrics:
    """Per-layer success metrics."""

    stage: str
    total_samples: int
    passed: int = 0
    failed: int = 0
    success_rate: float = 0.0
    avg_duration_ms: float = 0.0
    avg_confidence: Optional[float] = None
    anomalies_detected: int = 0
    abstentions: int = 0

    def to_dict(self):
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class PipelineMetrics:
    """Aggregate pipeline metrics."""

    total_samples: int
    end_to_end_passed: int = 0
    end_to_end_success_rate: float = 0.0
    determinism_rate: float = 0.0  # % where same-input produces identical output
    abstention_rate: float = 0.0  # % of "abstain" verdicts
    anomaly_detection_rate: float = 0.0  # % of samples with anomalies
    avg_pipeline_duration_ms: float = 0.0
    expectations_met_rate: float = 0.0  # For synthetic samples

    def to_dict(self):
        """Convert to dictionary."""
        return asdict(self)


def compute_layer_metrics(results: list[TestResult]) -> LayerMetrics:
    """Compute metrics from test results for a single layer.

    Args:
        results: List of TestResult objects from same layer

    Returns:
        LayerMetrics with computed statistics
    """
    if not results:
        return LayerMetrics(stage="unknown", total_samples=0)

    stage = results[0].stage
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    success_rate = passed / total if total > 0 else 0.0
    avg_duration = sum(r.duration_ms for r in results) / total if total > 0 else 0.0

    # Compute confidence statistics (for output stages)
    confidences = []
    anomalies_detected = 0
    abstentions = 0

    for result in results:
        # Look for confidence in output
        if "output" in result.output and isinstance(result.output["output"], dict):
            output_obj = result.output["output"]
            if "confidence" in output_obj:
                try:
                    confidences.append(float(output_obj["confidence"]))
                except (ValueError, TypeError):
                    pass

            # Count anomalies
            if "anomalies" in output_obj:
                anomaly_list = output_obj.get("anomalies", [])
                if anomaly_list:
                    anomalies_detected += 1

            # Count abstentions
            if output_obj.get("verdict") == "abstain":
                abstentions += 1

    avg_confidence = sum(confidences) / len(confidences) if confidences else None

    return LayerMetrics(
        stage=stage,
        total_samples=total,
        passed=passed,
        failed=failed,
        success_rate=success_rate,
        avg_duration_ms=avg_duration,
        avg_confidence=avg_confidence,
        anomalies_detected=anomalies_detected,
        abstentions=abstentions,
    )


def compute_pipeline_metrics(
    full_results: list[TestResult],
    layer_results: Optional[dict[str, list[TestResult]]] = None,
    synthetic_expectations: Optional[dict[str, bool]] = None,
) -> PipelineMetrics:
    """Compute aggregate pipeline metrics.

    Args:
        full_results: Results from full end-to-end pipeline runs
        layer_results: Optional per-layer results dict
        synthetic_expectations: Optional dict of expectations_met per sample

    Returns:
        PipelineMetrics with aggregate statistics
    """
    if not full_results:
        return PipelineMetrics(total_samples=0)

    total = len(full_results)
    passed = sum(1 for r in full_results if r.passed)
    success_rate = passed / total if total > 0 else 0.0

    # Calculate abstention rate
    abstentions = 0
    anomalies_detected = 0
    total_duration = 0.0

    for result in full_results:
        total_duration += result.duration_ms

        if "output" in result.output and isinstance(result.output["output"], dict):
            output_obj = result.output["output"]
            if output_obj.get("verdict") == "abstain":
                abstentions += 1
            if output_obj.get("anomalies"):
                anomalies_detected += 1

    abstention_rate = abstentions / total if total > 0 else 0.0
    anomaly_detection_rate = anomalies_detected / total if total > 0 else 0.0
    avg_pipeline_duration = total_duration / total if total > 0 else 0.0

    # Expectations met rate (for synthetic samples)
    expectations_met = 0.0
    if synthetic_expectations:
        expectations_met = sum(synthetic_expectations.values()) / len(
            synthetic_expectations
        )

    return PipelineMetrics(
        total_samples=total,
        end_to_end_passed=passed,
        end_to_end_success_rate=success_rate,
        abstention_rate=abstention_rate,
        anomaly_detection_rate=anomaly_detection_rate,
        avg_pipeline_duration_ms=avg_pipeline_duration,
        expectations_met_rate=expectations_met,
    )


def check_determinism(results_per_run: list[list[TestResult]], runs: int = 3) -> float:
    """Check determinism across multiple runs.

    Same input should produce identical outputs.

    Args:
        results_per_run: List of result lists from multiple runs
        runs: Number of runs for verification

    Returns:
        Percentage of samples with identical outputs across all runs
    """
    if not results_per_run or len(results_per_run) < 2:
        return 0.0

    # Group results by sample_id across runs
    samples_by_id = {}

    for run_results in results_per_run:
        for result in run_results:
            if result.sample_id not in samples_by_id:
                samples_by_id[result.sample_id] = []
            samples_by_id[result.sample_id].append(result)

    # Check determinism for each sample
    deterministic_count = 0

    for sample_id, results in samples_by_id.items():
        if len(results) < runs:
            continue  # Skip samples not in all runs

        # Hash outputs for comparison (exclude timing info)
        output_hashes = []
        for result in results:
            # Create hashable output (exclude duration_ms)
            output_dict = {
                "stage": result.stage,
                "passed": result.passed,
                "output": result.output,
            }
            output_json = json.dumps(output_dict, sort_keys=True, default=str)
            output_hash = hashlib.sha256(output_json.encode()).hexdigest()
            output_hashes.append(output_hash)

        # Check if all hashes are identical
        if len(set(output_hashes)) == 1:
            deterministic_count += 1

    total_samples = len(samples_by_id)
    determinism_rate = (
        deterministic_count / total_samples if total_samples > 0 else 0.0
    )

    return determinism_rate
