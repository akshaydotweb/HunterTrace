from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ValidationSample:
    sample_id: str
    input_path: str
    expected_region: Optional[str] = None
    expected_verdict: Optional[str] = None
    scenario_type: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def resolve_path(self, base_dir: Optional[Path] = None) -> Path:
        path = Path(self.input_path)
        if path.is_absolute() or str(path).startswith("synthetic://"):
            return path
        if base_dir is not None:
            return (base_dir / path).resolve()
        return path.resolve()


@dataclass
class PhaseResult:
    phase: str
    passed: bool
    metrics: Dict[str, float] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class SampleRunResult:
    sample: ValidationSample
    predicted_region: Optional[str]
    predicted_verdict: Optional[str]
    confidence: float
    repeat_hash: str
    deterministic: bool
    runtime_ms: float
    phase_results: Dict[str, PhaseResult] = field(default_factory=dict)
    raw_result: Any = None
    raw_result_hash: str = ""


@dataclass
class AdversarialResult:
    attack_type: str
    baseline_confidence: float
    attacked_confidence: float
    confidence_drop: float
    baseline_verdict: Optional[str]
    attacked_verdict: Optional[str]
    far_increase: float
    detected: bool
    robustness_score: float
    notes: List[str] = field(default_factory=list)


@dataclass
class FailureDiagnostic:
    phase: str
    metric: str
    expected: Any
    actual: Any
    probable_cause: str
    suggested_fix: str


@dataclass
class EvaluationReport:
    dataset_name: str
    code_version: str
    phase_metrics: Dict[str, Any]
    global_metrics: Dict[str, Any]
    confidence_metrics: Dict[str, Any]
    adversarial_metrics: Dict[str, Any]
    determinism_check: Dict[str, Any]
    pass_fail_summary: Dict[str, Any]
    failure_diagnostics: List[FailureDiagnostic]
    sample_results: List[SampleRunResult] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        from .reporting.serializers import to_jsonable

        return to_jsonable(self)
