"""HunterTrace Testing Framework.

Comprehensive testing system for validating the pipeline with synthetic and real-world datasets.

Modules:
- generator: Synthetic .eml sample generation
- datasets: Real dataset ingestion and indexing
- runner: Layer-wise and full pipeline test execution
- validators: Output validation for each layer
- metrics: Metrics computation (layer, pipeline, determinism)
- reporting: JSON report generation
"""

from huntertrace.testing.generator import SyntheticSample, SyntheticGenerator
from huntertrace.testing.datasets import DatasetSample, DatasetLoader
from huntertrace.testing.runner import TestRunner
from huntertrace.testing.metrics import TestResult, LayerMetrics, PipelineMetrics
from huntertrace.testing.reporting import TestReport, ReportGenerator

__all__ = [
    "SyntheticSample",
    "SyntheticGenerator",
    "DatasetSample",
    "DatasetLoader",
    "TestRunner",
    "TestResult",
    "LayerMetrics",
    "PipelineMetrics",
    "TestReport",
    "ReportGenerator",
]
