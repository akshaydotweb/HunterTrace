"""JSON report generation for test runs.

Generates structured, audit-ready test reports.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from huntertrace.testing.metrics import LayerMetrics, PipelineMetrics, TestResult


@dataclass
class TestReport:
    """Complete test execution report."""

    timestamp: str  # ISO 8601
    test_session_id: str  # UUID
    dataset_info: dict  # {category, sample_count, seed, ...}
    layer_metrics: dict[str, LayerMetrics]  # stage -> LayerMetrics
    pipeline_metrics: PipelineMetrics
    failed_cases: list[dict]  # First N failures with details
    config: dict  # Test config (layers run, limits, etc.)
    summary: Optional[dict] = None  # High-level summary

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp,
            "test_session_id": self.test_session_id,
            "dataset_info": self.dataset_info,
            "layer_metrics": {
                stage: metrics.to_dict()
                for stage, metrics in self.layer_metrics.items()
            },
            "pipeline_metrics": self.pipeline_metrics.to_dict(),
            "failed_cases": self.failed_cases,
            "config": self.config,
            "summary": self.summary or self._generate_summary(),
        }

    def _generate_summary(self) -> dict:
        """Generate high-level summary."""
        return {
            "total_samples": self.pipeline_metrics.total_samples,
            "end_to_end_success_rate": self.pipeline_metrics.end_to_end_success_rate,
            "determinism_rate": self.pipeline_metrics.determinism_rate,
            "abstention_rate": self.pipeline_metrics.abstention_rate,
            "anomaly_detection_rate": self.pipeline_metrics.anomaly_detection_rate,
            "avg_pipeline_duration_ms": self.pipeline_metrics.avg_pipeline_duration_ms,
        }


class ReportGenerator:
    """Generate JSON reports."""

    MAX_FAILED_CASES = 20

    @staticmethod
    def generate_report(
        dataset_category: str,
        dataset_sample_count: int,
        layer_results: dict[str, list[TestResult]],
        pipeline_results: list[TestResult],
        config: dict,
        determinism_rate: Optional[float] = None,
        synthetic_expectations: Optional[dict[str, bool]] = None,
    ) -> TestReport:
        """Generate complete test report.

        Args:
            dataset_category: Category of dataset tested
            dataset_sample_count: Number of samples tested
            layer_results: Dict mapping stage name to TestResult list
            pipeline_results: Full pipeline TestResult list
            config: Test configuration dict
            determinism_rate: Optional pre-computed determinism rate
            synthetic_expectations: Optional expectations met per sample

        Returns:
            TestReport object
        """
        now = datetime.now(timezone.utc).isoformat()
        session_id = str(uuid.uuid4())

        # Compute layer metrics
        layer_metrics = {}
        for stage, results in layer_results.items():
            from huntertrace.testing.metrics import compute_layer_metrics

            layer_metrics[stage] = compute_layer_metrics(results)

        # Compute pipeline metrics
        from huntertrace.testing.metrics import compute_pipeline_metrics

        pipeline_metrics = compute_pipeline_metrics(
            pipeline_results,
            layer_results=layer_results,
            synthetic_expectations=synthetic_expectations,
        )

        # Set determinism rate if provided
        if determinism_rate is not None:
            pipeline_metrics.determinism_rate = determinism_rate

        # Extract failed cases
        failed_cases = []
        for result in pipeline_results:
            if not result.passed:
                failed_cases.append({
                    "sample_id": result.sample_id,
                    "stage": result.stage,
                    "error": result.error,
                    "validated_checks": result.validated_checks,
                })
                if len(failed_cases) >= ReportGenerator.MAX_FAILED_CASES:
                    break

        # Create dataset info
        dataset_info = {
            "category": dataset_category,
            "sample_count": dataset_sample_count,
            "seed": config.get("seed", "not_set"),
        }

        return TestReport(
            timestamp=now,
            test_session_id=session_id,
            dataset_info=dataset_info,
            layer_metrics=layer_metrics,
            pipeline_metrics=pipeline_metrics,
            failed_cases=failed_cases,
            config=config,
        )

    @staticmethod
    def save_report(
        report: TestReport,
        output_dir: Path,
        layer_name: str = "full",
        dataset_name: Optional[str] = None,
    ) -> Path:
        """Save report to JSON file.

        Args:
            report: TestReport to save
            output_dir: Output directory base
            layer_name: Layer name for subdirectory
            dataset_name: Dataset name for filename (auto-generated if None)

        Returns:
            Path to saved report file
        """
        # Create layer subdirectory
        layer_dir = output_dir / layer_name
        layer_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename
        if dataset_name is None:
            dataset_name = report.dataset_info.get("category", "unknown")

        timestamp_str = report.timestamp.replace(":", "-").split(".")[0]
        filename = f"{dataset_name}_{timestamp_str}.json"
        report_path = layer_dir / filename

        # Write report
        report_dict = report.to_dict()
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, default=str)

        # Create/update latest.json symlink
        latest_path = layer_dir / "latest.json"
        try:
            if latest_path.exists() or latest_path.is_symlink():
                latest_path.unlink()
            latest_path.symlink_to(report_path.name)
        except (OSError, NotImplementedError):
            # Fallback to copy if symlink not supported
            import shutil

            shutil.copy2(report_path, latest_path)

        return report_path

    @staticmethod
    def save_summary(
        reports: list[TestReport],
        output_dir: Path,
    ) -> Path:
        """Save summary of multiple reports.

        Args:
            reports: List of TestReport objects
            output_dir: Output directory

        Returns:
            Path to summary file
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_reports": len(reports),
            "reports": [
                {
                    "dataset": r.dataset_info.get("category"),
                    "session_id": r.test_session_id,
                    "success_rate": r.pipeline_metrics.end_to_end_success_rate,
                    "determinism_rate": r.pipeline_metrics.determinism_rate,
                }
                for r in reports
            ],
        }

        summary_path = output_dir / "summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str)

        return summary_path
