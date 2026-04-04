"""Robustness metrics computation and failure analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from huntertrace.adversarial.models import BaselineComparison, PredictionRecord


@dataclass(frozen=True)
class FailureCase:
    """Single failure case under adversarial attack."""

    attack_type: str
    severity: str
    baseline_prediction: PredictionRecord
    adversarial_prediction: PredictionRecord
    failure_type: str  # "false_attribution", "overconfidence", "instability", "missed_detection"
    confidence_delta: float
    reason: str
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "attack_type": self.attack_type,
            "severity": self.severity,
            "baseline": self.baseline_prediction.to_dict(),
            "adversarial": self.adversarial_prediction.to_dict(),
            "failure_type": self.failure_type,
            "confidence_delta": round(self.confidence_delta, 4),
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class RobustnessMetrics:
    """Aggregate robustness evaluation results."""

    accuracy_drop: float  # baseline_accuracy - adversarial_accuracy (average)
    accuracy_drop_worst: float = 0.0  # Worst-case accuracy drop
    false_attribution_increase: float = 0.0  # adversarial_FAR - baseline_FAR (average)
    false_attribution_increase_worst: float = 0.0  # Worst-case FAR increase
    abstention_shift: float = 0.0  # adversarial_abstention - baseline_abstention
    confidence_instability: float = 0.0  # avg |confidence_adv - confidence_base|
    attack_success_rate: float = 0.0  # % of samples where prediction changed

    # Per-attack breakdown
    metrics_by_attack: Dict[str, Dict[str, float]] = field(default_factory=dict)

    # Failure analysis
    failure_cases: List[FailureCase] = field(default_factory=list)
    failure_distribution: Dict[str, int] = field(default_factory=dict)  # failure_type -> count

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "accuracy_drop": round(self.accuracy_drop, 4),
            "accuracy_drop_worst": round(self.accuracy_drop_worst, 4),
            "false_attribution_increase": round(self.false_attribution_increase, 4),
            "false_attribution_increase_worst": round(self.false_attribution_increase_worst, 4),
            "abstention_shift": round(self.abstention_shift, 4),
            "confidence_instability": round(self.confidence_instability, 4),
            "attack_success_rate": round(self.attack_success_rate, 4),
            "metrics_by_attack": {
                attack: {k: round(v, 4) for k, v in metrics.items()}
                for attack, metrics in self.metrics_by_attack.items()
            },
            "failure_distribution": dict(self.failure_distribution),
            "top_failures": [f.to_dict() for f in self.failure_cases[:10]],
        }


@dataclass
class RobustnessReport:
    """Complete adversarial robustness report."""

    baseline_metrics: Dict[str, float]  # accuracy, FAR, abstention, etc.
    adversarial_metrics: Dict[str, float]
    robustness_metrics: RobustnessMetrics
    scenario_breakdown: Dict[str, Dict[str, float]] = field(default_factory=dict)
    total_samples: int = 0
    total_variants: int = 0
    seed: int = 42

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "baseline_metrics": {k: round(v, 4) for k, v in self.baseline_metrics.items()},
            "adversarial_metrics": {k: round(v, 4) for k, v in self.adversarial_metrics.items()},
            "robustness_metrics": self.robustness_metrics.to_dict(),
            "scenario_breakdown": {
                scenario: {k: round(v, 4) for k, v in metrics.items()}
                for scenario, metrics in self.scenario_breakdown.items()
            },
            "total_samples": self.total_samples,
            "total_variants": self.total_variants,
            "seed": self.seed,
        }


class RobustnessAnalyzer:
    """Compute robustness metrics from baseline vs adversarial predictions."""

    @staticmethod
    def compute_metrics(
        baseline_predictions: List[PredictionRecord],
        adversarial_predictions_per_attack: Dict[str, List[PredictionRecord]],
        ground_truth_regions: Optional[List[str]] = None,
        variants_per_attack: Optional[Dict[str, List]] = None,
    ) -> RobustnessMetrics:
        """
        Compute robustness metrics comparing baseline to adversarial predictions.

        Args:
            baseline_predictions: Predictions on original samples
            adversarial_predictions_per_attack: Dict of {attack_type -> predictions}
            ground_truth_regions: Optional ground truth for accuracy computation
            variants_per_attack: Optional variants for evidence linking

        Returns:
            RobustnessMetrics with comprehensive analysis
        """
        if not baseline_predictions:
            return RobustnessMetrics(
                accuracy_drop=0.0,
                false_attribution_increase=0.0,
                abstention_shift=0.0,
                confidence_instability=0.0,
                attack_success_rate=0.0,
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

        # Compute per-attack metrics
        metrics_by_attack = {}
        all_failures = []
        total_changed = 0
        total_comparisons = 0

        for attack_type, adv_preds in adversarial_predictions_per_attack.items():
            if not adv_preds or len(adv_preds) != len(baseline_predictions):
                continue

            # Per-attack metrics
            adv_accuracy = RobustnessAnalyzer._compute_accuracy(
                adv_preds, ground_truth_regions
            )
            adv_far = RobustnessAnalyzer._compute_false_attribution_rate(
                adv_preds, ground_truth_regions
            )
            adv_abstention = RobustnessAnalyzer._compute_abstention_rate(adv_preds)

            metrics_by_attack[attack_type] = {
                "accuracy": adv_accuracy,
                "far": adv_far,
                "abstention": adv_abstention,
                "accuracy_drop": baseline_accuracy - adv_accuracy,
                "far_increase": adv_far - baseline_far,
                "abstention_delta": adv_abstention - baseline_abstention,
            }

            # Track failures with evidence linking
            attack_variants = (
                variants_per_attack.get(attack_type, [])
                if variants_per_attack else []
            )

            for i, (baseline, adv) in enumerate(zip(baseline_predictions, adv_preds)):
                comparison = BaselineComparison(
                    baseline_prediction=baseline,
                    adversarial_prediction=adv,
                    changed=baseline.region != adv.region
                    or baseline.verdict != adv.verdict,
                    prediction_delta=abs(baseline.confidence - adv.confidence),
                    verdict_changed=baseline.verdict != adv.verdict,
                )

                if comparison.changed:
                    total_changed += 1

                total_comparisons += 1

                # Classify failure
                failure_type = RobustnessAnalyzer._classify_failure(
                    baseline, adv, ground_truth_regions[i] if ground_truth_regions else None
                )
                if failure_type:
                    # Extract evidence from mutation trace if available
                    evidence = None
                    if attack_variants and i < len(attack_variants) and attack_variants[i]:
                        variant = attack_variants[i]
                        if hasattr(variant, "mutation_trace"):
                            evidence = variant.mutation_trace.description

                    # Build detailed reason with context
                    base_reason = f"{attack_type} attack caused {failure_type}"
                    if baseline.verdict == "abstained" and adv.verdict != "abstained":
                        reason = f"{base_reason}: system overconfident after attack, attributed to {adv.region}"
                    elif adv.verdict == "abstained" and baseline.verdict != "abstained":
                        reason = f"{base_reason}: system became uncertain after attack, lost attribution to {baseline.region}"
                    elif baseline.region != adv.region:
                        reason = f"{base_reason}: misattribution shift from {baseline.region} to {adv.region}"
                    else:
                        confidence_shift = adv.confidence - baseline.confidence
                        reason = f"{base_reason}: confidence shifted by {confidence_shift:.3f}"

                    failure = FailureCase(
                        attack_type=attack_type,
                        severity="unknown",
                        baseline_prediction=baseline,
                        adversarial_prediction=adv,
                        failure_type=failure_type,
                        confidence_delta=comparison.prediction_delta,
                        reason=reason,
                        evidence=evidence,
                    )
                    all_failures.append(failure)

        # Compute aggregate metrics (average + worst-case)
        avg_accuracy_drop = (
            sum(m["accuracy_drop"] for m in metrics_by_attack.values())
            / len(metrics_by_attack)
            if metrics_by_attack
            else 0.0
        )
        worst_accuracy_drop = (
            max(m["accuracy_drop"] for m in metrics_by_attack.values())
            if metrics_by_attack
            else 0.0
        )

        avg_far_increase = (
            sum(m["far_increase"] for m in metrics_by_attack.values())
            / len(metrics_by_attack)
            if metrics_by_attack
            else 0.0
        )
        worst_far_increase = (
            max(m["far_increase"] for m in metrics_by_attack.values())
            if metrics_by_attack
            else 0.0
        )

        avg_abstention_shift = (
            sum(m["abstention_delta"] for m in metrics_by_attack.values())
            / len(metrics_by_attack)
            if metrics_by_attack
            else 0.0
        )

        # Confidence instability
        confidence_deltas = []
        for attack_preds in adversarial_predictions_per_attack.values():
            if len(attack_preds) != len(baseline_predictions):
                continue
            for baseline, adv in zip(baseline_predictions, attack_preds):
                confidence_deltas.append(abs(baseline.confidence - adv.confidence))

        avg_instability = (
            sum(confidence_deltas) / len(confidence_deltas)
            if confidence_deltas
            else 0.0
        )

        attack_success_rate = (
            total_changed / total_comparisons if total_comparisons > 0 else 0.0
        )

        # Failure distribution
        failure_distribution = {}
        for failure in all_failures:
            failure_distribution[failure.failure_type] = (
                failure_distribution.get(failure.failure_type, 0) + 1
            )

        return RobustnessMetrics(
            accuracy_drop=max(0.0, avg_accuracy_drop),
            accuracy_drop_worst=max(0.0, worst_accuracy_drop),
            false_attribution_increase=max(0.0, avg_far_increase),
            false_attribution_increase_worst=max(0.0, worst_far_increase),
            abstention_shift=avg_abstention_shift,
            confidence_instability=avg_instability,
            attack_success_rate=attack_success_rate,
            metrics_by_attack=metrics_by_attack,
            failure_cases=sorted(
                all_failures, key=lambda f: f.confidence_delta, reverse=True
            ),
            failure_distribution=failure_distribution,
        )

    @staticmethod
    def _compute_accuracy(
        predictions: List[PredictionRecord],
        ground_truth: Optional[List[str]] = None,
    ) -> float:
        """Compute accuracy against ground truth."""
        if not predictions or not ground_truth:
            return 0.0

        correct = sum(
            1
            for pred, truth in zip(predictions, ground_truth)
            if pred.region == truth and pred.verdict != "abstained"
        )
        return correct / len(predictions)

    @staticmethod
    def _compute_false_attribution_rate(
        predictions: List[PredictionRecord],
        ground_truth: Optional[List[str]] = None,
    ) -> float:
        """Compute false attribution rate."""
        if not predictions:
            return 0.0

        attributed = [p for p in predictions if p.verdict != "abstained"]
        if not attributed:
            return 0.0

        if ground_truth:
            incorrect = sum(
                1 for pred, truth in zip(attributed, ground_truth)
                if pred.region != truth
            )
        else:
            # Without ground truth, use verdict changes as proxy
            incorrect = sum(1 for p in attributed if p.confidence < 0.5)

        return incorrect / len(attributed) if attributed else 0.0

    @staticmethod
    def _compute_abstention_rate(predictions: List[PredictionRecord]) -> float:
        """Compute abstention (non-attribution) rate."""
        if not predictions:
            return 0.0
        abstained = sum(1 for p in predictions if p.verdict == "abstained")
        return abstained / len(predictions)

    @staticmethod
    def _classify_failure(
        baseline: PredictionRecord,
        adversarial: PredictionRecord,
        ground_truth: Optional[str] = None,
    ) -> Optional[str]:
        """Classify type of failure."""
        if baseline.verdict == adversarial.verdict and baseline.region == adversarial.region:
            return None  # No failure

        if adversarial.verdict == "abstained" and baseline.verdict != "abstained":
            return "overconfidence_abstention"

        if baseline.verdict != "abstained" and adversarial.region != baseline.region:
            if ground_truth and adversarial.region != ground_truth:
                return "false_attribution"
            return "verdict_instability"

        if (
            adversarial.confidence < baseline.confidence
            and adversarial.confidence < 0.5
        ):
            return "confidence_degradation"

        return "other_instability"
