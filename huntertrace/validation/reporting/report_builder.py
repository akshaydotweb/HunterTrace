from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from ..metrics import (
    AdversarialMetrics,
    ConfidenceMetrics,
    GlobalMetrics,
    PhaseMetrics,
)
from ..schema import (
    AdversarialResult,
    EvaluationReport,
    FailureDiagnostic,
    SampleRunResult,
)
from ..thresholds import DEFAULT_THRESHOLDS, evaluate_threshold, threshold_target
from .serializers import to_jsonable


def build_report(
    dataset_name: str,
    sample_results: List[SampleRunResult],
    phase_metrics: PhaseMetrics,
    global_metrics: GlobalMetrics,
    confidence_metrics: ConfidenceMetrics,
    adversarial_metrics: AdversarialMetrics,
    determinism_check: Dict[str, Any],
    code_version: str = "unknown",
) -> EvaluationReport:
    pass_fail_summary = _build_summary(phase_metrics, global_metrics, confidence_metrics)
    diagnostics = build_failure_diagnostics(phase_metrics, global_metrics, confidence_metrics)
    return EvaluationReport(
        dataset_name=dataset_name,
        code_version=code_version,
        phase_metrics=to_jsonable(phase_metrics),
        global_metrics=to_jsonable(global_metrics),
        confidence_metrics=to_jsonable(confidence_metrics),
        adversarial_metrics=to_jsonable(adversarial_metrics),
        determinism_check=determinism_check,
        pass_fail_summary=pass_fail_summary,
        failure_diagnostics=diagnostics,
        sample_results=sample_results,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def build_failure_diagnostics(
    phase_metrics: PhaseMetrics,
    global_metrics: GlobalMetrics,
    confidence_metrics: ConfidenceMetrics,
) -> List[FailureDiagnostic]:
    diagnostics: List[FailureDiagnostic] = []
    for metric_name, rule in DEFAULT_THRESHOLDS.items():
        actual = _metric_value(metric_name, phase_metrics, global_metrics, confidence_metrics)
        if actual is None:
            continue
        if not evaluate_threshold(metric_name, actual):
            expected = f"{rule.operator} {rule.value}"
            probable, fix = _diagnose(metric_name)
            diagnostics.append(
                FailureDiagnostic(
                    phase=metric_name,
                    metric=metric_name,
                    expected=expected,
                    actual=actual,
                    probable_cause=probable,
                    suggested_fix=fix,
                )
            )
    return diagnostics


def build_summary_text(report: EvaluationReport) -> str:
    lines = [
        "HUNTERTRACE VALIDATION REPORT",
        f"Dataset: {report.dataset_name}",
        f"Generated at: {report.generated_at}",
        "",
        "Global Metrics:",
    ]
    for key, value in report.global_metrics.items():
        lines.append(f"  {key}: {value}")
    lines.append("")
    lines.append("Confidence Metrics:")
    for key, value in report.confidence_metrics.items():
        if key == "reliability_diagram":
            continue
        lines.append(f"  {key}: {value}")
    lines.append("")
    lines.append("Pass/Fail:")
    for key, value in report.pass_fail_summary.items():
        lines.append(f"  {key}: {'PASS' if value else 'FAIL'}")
    if report.failure_diagnostics:
        lines.append("")
        lines.append("Diagnostics:")
        for diag in report.failure_diagnostics:
            lines.append(f"  [{diag.phase}] {diag.metric}: {diag.probable_cause}")
    return "\n".join(lines)


def _build_summary(phase_metrics: PhaseMetrics, global_metrics: GlobalMetrics, confidence_metrics: ConfidenceMetrics) -> Dict[str, bool]:
    return {
        "parsing_accuracy": evaluate_threshold("parsing_accuracy", _metric_value("parsing_accuracy", phase_metrics, global_metrics, confidence_metrics) or 0.0),
        "hop_ordering": evaluate_threshold("hop_ordering", _metric_value("hop_ordering", phase_metrics, global_metrics, confidence_metrics) or 0.0),
        "signal_coverage": evaluate_threshold("signal_coverage", _metric_value("signal_coverage", phase_metrics, global_metrics, confidence_metrics) or 0.0),
        "enrichment_rate": evaluate_threshold("enrichment_rate", _metric_value("enrichment_rate", phase_metrics, global_metrics, confidence_metrics) or 0.0),
        "provenance_accuracy": evaluate_threshold("provenance_accuracy", _metric_value("provenance_accuracy", phase_metrics, global_metrics, confidence_metrics) or 0.0),
        "anomaly_detection": evaluate_threshold("anomaly_detection", _metric_value("anomaly_detection", phase_metrics, global_metrics, confidence_metrics) or 0.0),
        "false_anomaly": evaluate_threshold("false_anomaly", _metric_value("false_anomaly", phase_metrics, global_metrics, confidence_metrics) or 0.0),
        "ece": evaluate_threshold("ece", confidence_metrics.ece),
        "brier": evaluate_threshold("brier", confidence_metrics.brier),
    }


def _metric_value(metric_name: str, phase_metrics: PhaseMetrics, global_metrics: GlobalMetrics, confidence_metrics: ConfidenceMetrics) -> float | None:
    if metric_name == "parsing_accuracy":
        return phase_metrics.by_phase.get("parsing", {}).get("pass_rate")
    if metric_name == "hop_ordering":
        return phase_metrics.by_phase.get("hop_reconstruction", {}).get("pass_rate")
    if metric_name == "signal_coverage":
        return phase_metrics.by_phase.get("signals", {}).get("pass_rate")
    if metric_name == "enrichment_rate":
        return phase_metrics.by_phase.get("enrichment", {}).get("pass_rate")
    if metric_name == "provenance_accuracy":
        return phase_metrics.by_phase.get("provenance", {}).get("pass_rate")
    if metric_name == "anomaly_detection":
        return phase_metrics.by_phase.get("semantic", {}).get("pass_rate")
    if metric_name == "false_anomaly":
        return 1.0 - phase_metrics.by_phase.get("semantic", {}).get("pass_rate", 0.0)
    if metric_name == "ece":
        return confidence_metrics.ece
    if metric_name == "brier":
        return confidence_metrics.brier
    return None


def _diagnose(metric_name: str) -> tuple[str, str]:
    mapping = {
        "parsing_accuracy": ("Header parser is missing fields or misreading the message structure", "Inspect raw header parsing and malformed sample handling"),
        "hop_ordering": ("Received chain is not monotonic or is reversed", "Verify hop reconstruction order and chain normalization"),
        "signal_coverage": ("Signals are not being extracted or summarized", "Check signal extraction and signal inventory mapping"),
        "enrichment_rate": ("Geolocation/enrichment returned no usable outputs", "Confirm offline enrichment fallback and IP candidate extraction"),
        "provenance_accuracy": ("Signals lack provenance labels", "Ensure provenance metadata is attached to each signal"),
        "anomaly_detection": ("Semantic anomaly rules are too weak or missing", "Tighten spoofing and chain-consistency validation"),
        "false_anomaly": ("Clean cases are over-flagged", "Relax semantic thresholds for benign mail"),
        "ece": ("Confidence bins do not match empirical accuracy", "Recalibrate scoring or confidence mapping"),
        "brier": ("Confidence values are poorly calibrated", "Adjust the confidence model or abstention thresholds"),
    }
    return mapping.get(metric_name, ("Metric failed threshold", "Inspect the phase-specific validator"))
