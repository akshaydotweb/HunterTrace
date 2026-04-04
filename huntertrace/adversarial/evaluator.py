"""Adversarial evaluation orchestrator - pipeline execution and result collection."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from huntertrace.adversarial.generator import AdversarialGenerator
from huntertrace.adversarial.metrics import RobustnessAnalyzer, RobustnessMetrics, RobustnessReport
from huntertrace.adversarial.models import AttackSeverity, AttackType, PredictionRecord
from huntertrace.adversarial.scenarios import Scenario, ScenarioLibrary


@dataclass
class AdversarialRunConfig:
    """Configuration for adversarial evaluation run."""

    seed: int = 42
    attack_types: Optional[List[str]] = None
    severity: str = AttackSeverity.MEDIUM.value
    scenarios: Optional[List[str]] = None
    limit: Optional[int] = None  # Max samples to test
    max_variants_per_sample: int = 6  # Max variants per sample
    include_explanations: bool = False
    temp_dir: Optional[str] = None

    def __post_init__(self):
        """Validate config."""
        if self.severity not in [s.value for s in AttackSeverity]:
            raise ValueError(f"Invalid severity: {self.severity}")


class AdversarialEvaluator:
    """Orchestrate adversarial testing of the full pipeline."""

    def __init__(
        self,
        pipeline_executor: Callable[
            [str], Tuple[Optional[str], float, Optional[List[str]]]
        ],
        ground_truth_extractor: Optional[Callable[[str], Optional[str]]] = None,
    ):
        """
        Initialize adversarial evaluator.

        Args:
            pipeline_executor: Callable that takes email content and returns (region, confidence, anomalies)
            ground_truth_extractor: Optional callable to extract ground truth from file path
        """
        self.pipeline_executor = pipeline_executor
        self.ground_truth_extractor = ground_truth_extractor
        self._temp_files: List[str] = []

    def evaluate_samples(
        self,
        sample_paths: List[str],
        config: AdversarialRunConfig,
    ) -> RobustnessReport:
        """
        Run adversarial evaluation on samples.

        Args:
            sample_paths: List of paths to email samples
            config: Evaluation configuration

        Returns:
            RobustnessReport with comprehensive results
        """
        # Limit samples if specified
        if config.limit:
            sample_paths = sample_paths[: config.limit]

        # Get baseline predictions with index tracking
        baseline_predictions = []
        ground_truth_regions = []
        valid_indices = []  # Track which sample indices are valid

        for idx, path in enumerate(sample_paths):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                region, confidence, anomalies = self.pipeline_executor(content)

                baseline_predictions.append(
                    PredictionRecord(
                        region=region,
                        confidence=confidence,
                        verdict="attributed" if region else "abstained",
                        anomalies=anomalies or [],
                    )
                )

                # Extract ground truth if extractor provided
                if self.ground_truth_extractor:
                    gt = self.ground_truth_extractor(path)
                    ground_truth_regions.append(gt)
                else:
                    ground_truth_regions.append(None)

                valid_indices.append(idx)

            except Exception as e:
                # Skip samples that fail
                continue

        if not baseline_predictions:
            raise ValueError("No valid samples to evaluate")

        # Generate adversarial variants and test
        adversarial_predictions_per_attack: Dict[str, List[PredictionRecord]] = {}
        sample_variants_per_attack: Dict[str, List[Optional[Any]]] = {}  # Track variants for evidence

        attack_types = config.attack_types or [t.value for t in AttackType]

        for attack_type in attack_types:
            attack_predictions = []
            attack_variants = []

            for valid_idx, sample_idx in enumerate(valid_indices):
                path = sample_paths[sample_idx]
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        original_content = f.read()

                    # Generate adversarial variants
                    variants = AdversarialGenerator.generate_variants(
                        email_content=original_content,
                        original_path=path,
                        attack_types=[attack_type],
                        severity=config.severity,
                        seed=config.seed,
                    )

                    if not variants:
                        # If variant generation fails, use baseline
                        attack_predictions.append(baseline_predictions[valid_idx])
                        attack_variants.append(None)
                        continue

                    # Use multiple variants for robustness (best-case/worst-case/average)
                    max_variants = min(config.max_variants_per_sample, len(variants))
                    predictions_for_variants = []

                    for variant_idx in range(max_variants):
                        variant = variants[variant_idx]
                        region, confidence, anomalies = self.pipeline_executor(
                            variant.modified_content
                        )
                        predictions_for_variants.append(
                            PredictionRecord(
                                region=region,
                                confidence=confidence,
                                verdict="attributed" if region else "abstained",
                                anomalies=anomalies or [],
                            )
                        )

                    # Use worst-case prediction (lowest confidence or abstained)
                    worst_pred = min(
                        predictions_for_variants,
                        key=lambda p: (p.confidence, p.verdict == "attributed")
                    )
                    attack_predictions.append(worst_pred)
                    attack_variants.append(variants[0])  # Store first variant for evidence linking

                except Exception:
                    # Skip on error
                    attack_predictions.append(
                        PredictionRecord(
                            region=None, confidence=0.0, verdict="abstained"
                        )
                    )
                    attack_variants.append(None)

            adversarial_predictions_per_attack[attack_type] = attack_predictions
            sample_variants_per_attack[attack_type] = attack_variants

        # Compute metrics with evidence linking
        robustness_metrics = RobustnessAnalyzer.compute_metrics(
            baseline_predictions=baseline_predictions,
            adversarial_predictions_per_attack=adversarial_predictions_per_attack,
            ground_truth_regions=ground_truth_regions,
            variants_per_attack=sample_variants_per_attack,
        )

        # Compute baseline metrics
        baseline_accuracy = RobustnessAnalyzer._compute_accuracy(
            baseline_predictions, ground_truth_regions
        )
        baseline_far = RobustnessAnalyzer._compute_false_attribution_rate(
            baseline_predictions, ground_truth_regions
        )
        baseline_abstention = RobustnessAnalyzer._compute_abstention_rate(
            baseline_predictions
        )

        # Compute adversarial metrics (average + worst-case across attacks)
        if robustness_metrics.metrics_by_attack:
            adv_accuracies = [m["accuracy"] for m in robustness_metrics.metrics_by_attack.values()]
            adv_fars = [m["far"] for m in robustness_metrics.metrics_by_attack.values()]
            adv_abstentions = [m["abstention"] for m in robustness_metrics.metrics_by_attack.values()]

            adv_accuracy_avg = sum(adv_accuracies) / len(adv_accuracies)
            adv_accuracy_worst = min(adv_accuracies)
            adv_far_avg = sum(adv_fars) / len(adv_fars)
            adv_far_worst = max(adv_fars)
            adv_abstention_avg = sum(adv_abstentions) / len(adv_abstentions)
        else:
            adv_accuracy_avg = baseline_accuracy
            adv_accuracy_worst = baseline_accuracy
            adv_far_avg = baseline_far
            adv_far_worst = baseline_far
            adv_abstention_avg = baseline_abstention

        baseline_metrics = {
            "accuracy": baseline_accuracy,
            "far": baseline_far,
            "abstention": baseline_abstention,
        }

        adversarial_metrics = {
            "accuracy_avg": adv_accuracy_avg,
            "accuracy_worst": adv_accuracy_worst,
            "far_avg": adv_far_avg,
            "far_worst": adv_far_worst,
            "abstention_avg": adv_abstention_avg,
        }

        # Scenario breakdown - actually execute scenarios
        scenario_breakdown = {}
        if config.scenarios:
            for scenario_name in config.scenarios:
                scenario = ScenarioLibrary.get_scenario(scenario_name)
                if scenario:
                    # Temporarily override config to use scenario's attacks
                    scenario_config = AdversarialRunConfig(
                        seed=config.seed,
                        attack_types=scenario.attack_sequence,
                        severity=scenario.severity_level,
                        limit=config.limit,
                        max_variants_per_sample=config.max_variants_per_sample,
                        include_explanations=config.include_explanations,
                        temp_dir=config.temp_dir,
                    )
                    # Recursively evaluate scenario
                    scenario_report = self.evaluate_samples(sample_paths, scenario_config)
                    scenario_breakdown[scenario_name] = {
                        "attacks": len(scenario.attack_sequence),
                        "severity": scenario.severity_level,
                        "accuracy_drop": scenario_report.robustness_metrics.accuracy_drop,
                        "far_increase": scenario_report.robustness_metrics.false_attribution_increase,
                        "metrics": scenario_report.robustness_metrics.to_dict(),
                    }

        total_variants = len(valid_indices) * len(attack_types) * config.max_variants_per_sample

        report = RobustnessReport(
            baseline_metrics=baseline_metrics,
            adversarial_metrics=adversarial_metrics,
            robustness_metrics=robustness_metrics,
            scenario_breakdown=scenario_breakdown,
            total_samples=len(sample_paths),
            total_variants=total_variants,
            seed=config.seed,
        )

        return report

    def evaluate_scenario(
        self,
        sample_paths: List[str],
        scenario: Scenario,
        config: AdversarialRunConfig,
    ) -> RobustnessMetrics:
        """
        Run adversarial evaluation for specific scenario.

        Args:
            sample_paths: List of sample paths
            scenario: Scenario to test
            config: Evaluation config

        Returns:
            RobustnessMetrics for the scenario
        """
        # Use scenario's attack sequence
        config.attack_types = scenario.attack_sequence
        config.severity = scenario.severity_level

        report = self.evaluate_samples(sample_paths, config)
        return report.robustness_metrics

    def cleanup(self):
        """Clean up temporary files."""
        for path in self._temp_files:
            try:
                Path(path).unlink()
            except Exception:
                pass
        self._temp_files = []

    def __del__(self):
        """Cleanup on deletion."""
        self.cleanup()
