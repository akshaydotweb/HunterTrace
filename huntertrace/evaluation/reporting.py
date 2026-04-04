"""Evaluation reporting."""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from huntertrace.evaluation.evaluator import EvaluationContext


@dataclass
class EvaluationReport:
    """Complete evaluation report."""

    timestamp: str
    summary_metrics: Dict[str, Any]
    calibration_metrics: Dict[str, Any]
    stratified_metrics: List[Dict[str, Any]]
    threshold_analysis: List[Dict[str, Any]]
    error_samples: List[Dict[str, Any]]
    sample_count: int

    # NEW: Statistical significance
    metric_confidence_intervals: Dict[str, Dict[str, float]] = None

    # NEW: Cost-sensitive evaluation
    cost_metrics: Optional[Dict[str, Any]] = None

    # NEW: Adversarial robustness
    adversarial_metrics: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str | Path) -> None:
        """Save report to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(self.to_json())


def generate_report(
    context: EvaluationContext,
    error_sample_limit: int = 10,
) -> EvaluationReport:
    """
    Generate evaluation report from context.

    Args:
        context: EvaluationContext with results
        error_sample_limit: Max error samples to include

    Returns:
        EvaluationReport ready for output
    """
    # Summary metrics with confidence intervals (NEW)
    summary_metrics = {
        **context.overall_metrics.to_dict(),
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Add confidence intervals to summary if available (NEW)
    if context.metric_confidence_intervals:
        for metric_name, ci in context.metric_confidence_intervals.items():
            summary_metrics[f"{metric_name}_ci"] = [ci.ci_lower, ci.ci_upper]

    # Calibration metrics
    calibration_metrics = context.calibration_metrics.to_dict()

    # Stratified metrics
    stratified_metrics = [
        {
            "stratum": s.stratum_name,
            "filter": s.stratum_filter,
            "sample_count": s.sample_count,
            **s.metrics.to_dict(),
        }
        for s in context.stratified_metrics
    ]

    # Threshold analysis
    threshold_analysis = [
        {
            "threshold": round(t.threshold, 2),
            "accuracy": round(t.accuracy, 4),
            "false_attribution_rate": round(t.false_attribution_rate, 4),
            "abstention_rate": round(t.abstention_rate, 4),
            "coverage_rate": round(t.coverage_rate, 4),
        }
        for t in context.threshold_analysis
    ]

    # Error samples
    error_samples = [
        {
            "sample_id": e.sample_id,
            "input_path": e.input_path,
            "predicted_region": e.predicted_region,
            "ground_truth_region": e.ground_truth_region,
            "predicted_confidence": round(e.predicted_confidence, 4),
            "predicted_verdict": e.predicted_verdict,
            "error_type": e.error_type,
            "correlation_summary": e.correlation_summary,
            "reasoning": e.reasoning,
        }
        for e in context.error_cases[:error_sample_limit]
    ]

    # Cost-sensitive metrics (NEW)
    cost_metrics = None
    if context.cost_metrics:
        cost_metrics = context.cost_metrics.to_dict()

    # Adversarial robustness metrics (NEW)
    adversarial_metrics = None
    if context.robustness_metrics:
        adversarial_metrics = context.robustness_metrics.to_dict()

    return EvaluationReport(
        timestamp=datetime.utcnow().isoformat(),
        summary_metrics=summary_metrics,
        calibration_metrics=calibration_metrics,
        stratified_metrics=stratified_metrics,
        threshold_analysis=threshold_analysis,
        error_samples=error_samples,
        sample_count=context.overall_metrics.total,
        metric_confidence_intervals={
            name: ci.to_dict() for name, ci in context.metric_confidence_intervals.items()
        } if context.metric_confidence_intervals else None,
        cost_metrics=cost_metrics,
        adversarial_metrics=adversarial_metrics,
    )
