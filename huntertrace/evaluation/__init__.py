"""
evaluation — Accuracy benchmarking, calibration, false-positive auditing,
geo cross-validation.

CLI tools
---------
  python -m huntertrace.evaluation.runner       # run full eval
  python -m huntertrace.evaluation.fp_auditor   # VPN false-positive audit
  python -m huntertrace.evaluation.geo_validator # 3-API geolocation cross-check
"""
from huntertrace.evaluation.framework import (
    EvaluationFramework,
    EvaluationMetrics,
    PerCountryMetrics,
    CalibrationBin,
    AblationStudy,
    BaselineModels,
)
from huntertrace.evaluation.dataset import (
    DatasetLoader,
    BatchEvaluator,
    DatasetCreator,
    EmailEntry,
    Prediction,
    GroundTruth,
)

__all__ = [
    "EvaluationFramework", "EvaluationMetrics", "PerCountryMetrics",
    "CalibrationBin", "AblationStudy", "BaselineModels",
    "DatasetLoader", "BatchEvaluator", "DatasetCreator",
    "EmailEntry", "Prediction", "GroundTruth",
]
