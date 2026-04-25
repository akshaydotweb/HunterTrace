from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


def to_jsonable(value: Any) -> Any:
    try:
        from ..schema import EvaluationReport, SampleRunResult
    except Exception:  # pragma: no cover - import cycle safety
        EvaluationReport = None
        SampleRunResult = None

    if SampleRunResult is not None and isinstance(value, SampleRunResult):
        return {
            "sample": to_jsonable(value.sample),
            "predicted_region": value.predicted_region,
            "predicted_verdict": value.predicted_verdict,
            "confidence": value.confidence,
            "repeat_hash": value.repeat_hash,
            "deterministic": value.deterministic,
            "runtime_ms": value.runtime_ms,
            "phase_results": to_jsonable(value.phase_results),
            "raw_result_hash": value.raw_result_hash,
        }
    if EvaluationReport is not None and isinstance(value, EvaluationReport):
        return {
            "dataset_name": value.dataset_name,
            "code_version": value.code_version,
            "phase_metrics": to_jsonable(value.phase_metrics),
            "global_metrics": to_jsonable(value.global_metrics),
            "confidence_metrics": to_jsonable(value.confidence_metrics),
            "adversarial_metrics": to_jsonable(value.adversarial_metrics),
            "determinism_check": to_jsonable(value.determinism_check),
            "pass_fail_summary": to_jsonable(value.pass_fail_summary),
            "failure_diagnostics": to_jsonable(value.failure_diagnostics),
            "sample_results": to_jsonable(value.sample_results),
            "generated_at": value.generated_at,
        }
    if is_dataclass(value):
        return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return to_jsonable(value.to_dict())
    if hasattr(value, "__dict__") and not isinstance(value, type):
        return {k: to_jsonable(v) for k, v in vars(value).items() if not k.startswith("_")}
    return value


def dump_json(payload: Any, path: str | Path) -> None:
    Path(path).write_text(json.dumps(to_jsonable(payload), indent=2, sort_keys=True), encoding="utf-8")
