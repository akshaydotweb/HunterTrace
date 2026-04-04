"""HunterTrace Atlas Phase 5: Evaluation & Validation Framework."""

from huntertrace.evaluation.adversarial import AdversarialGenerator, RobustnessAnalyzer, RobustnessMetrics
from huntertrace.evaluation.calibration import CalibrationAnalyzer, CalibrationMetrics
from huntertrace.evaluation.cost import CostAnalyzer, CostConfig, CostMetrics
from huntertrace.evaluation.datasets import EvaluationSample, load_dataset
from huntertrace.evaluation.evaluator import AtlasEvaluator, EvaluationContext
from huntertrace.evaluation.metrics import Metrics, PredictionRecord, compute_metrics
from huntertrace.evaluation.reporting import EvaluationReport, generate_report
from huntertrace.evaluation.statistics import BootstrapAnalyzer, MetricCI

__all__ = [
    "EvaluationSample",
    "load_dataset",
    "AtlasEvaluator",
    "EvaluationContext",
    "Metrics",
    "PredictionRecord",
    "compute_metrics",
    "CalibrationAnalyzer",
    "CalibrationMetrics",
    "EvaluationReport",
    "generate_report",
    "BootstrapAnalyzer",
    "MetricCI",
    "CostAnalyzer",
    "CostConfig",
    "CostMetrics",
    "AdversarialGenerator",
    "RobustnessAnalyzer",
    "RobustnessMetrics",
]
