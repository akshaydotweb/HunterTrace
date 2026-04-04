"""Cost-sensitive evaluation aligned with DFIR priorities."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class CostConfig:
    """Cost model for different error types in DFIR."""

    false_attribution: float = 10.0  # HIGH: Wrong region = costly investigation
    missed_attribution: float = 3.0  # MEDIUM: Missed signal = incomplete investigation
    abstention: float = 1.0  # LOW: "I don't know" = acceptable cost


@dataclass(frozen=True)
class CostMetrics:
    """Cost-based evaluation metrics."""

    expected_cost: float  # Total cost / num_samples
    cost_false_attribution: float  # Cost from false attributions
    cost_missed: float  # Cost from missed attributions
    cost_abstention: float  # Cost from abstentions
    cost_per_attributed: float  # Cost per attributed prediction
    cost_per_correct: float  # Cost per correct prediction
    cost_breakdown: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for JSON serialization."""
        return {
            "expected_cost": round(self.expected_cost, 4),
            "cost_breakdown": {
                "false_attribution": round(self.cost_false_attribution, 4),
                "missed_attribution": round(self.cost_missed, 4),
                "abstention": round(self.cost_abstention, 4),
            },
            "cost_per_attributed": round(self.cost_per_attributed, 4),
            "cost_per_correct": round(self.cost_per_correct, 4),
        }


class CostAnalyzer:
    """Cost-sensitive evaluation for DFIR alignment."""

    @staticmethod
    def compute_cost_metrics(
        predictions: List,
        config: CostConfig,
    ) -> CostMetrics:
        """
        Compute cost-based metrics from predictions.

        Predictions should have:
        - .is_abstained: bool
        - .is_correct: bool
        - .ground_truth_region: Optional[str]

        Args:
            predictions: List of prediction records
            config: CostConfig with error weights

        Returns:
            CostMetrics with total and breakdown costs
        """
        if not predictions:
            return CostMetrics(
                expected_cost=0.0,
                cost_false_attribution=0.0,
                cost_missed=0.0,
                cost_abstention=0.0,
                cost_per_attributed=0.0,
                cost_per_correct=0.0,
            )

        # Count error types
        false_attribution_count = 0
        missed_count = 0
        abstention_count = 0
        attributed_count = 0
        correct_count = 0

        for pred in predictions:
            if pred.is_abstained:
                abstention_count += 1
                # Check if it was a miss (ground truth existed)
                if pred.ground_truth_region is not None:
                    missed_count += 1
            else:
                attributed_count += 1
                if pred.is_correct:
                    correct_count += 1
                else:
                    # Incorrect attribution
                    false_attribution_count += 1

        # Compute costs
        cost_fa = false_attribution_count * config.false_attribution
        cost_miss = missed_count * config.missed_attribution
        cost_abs = abstention_count * config.abstention

        total_cost = cost_fa + cost_miss + cost_abs
        expected_cost = total_cost / len(predictions) if predictions else 0.0

        # Compute per-decision costs
        cost_per_attributed = (
            cost_fa / attributed_count if attributed_count > 0 else 0.0
        )
        cost_per_correct = total_cost / correct_count if correct_count > 0 else 0.0

        return CostMetrics(
            expected_cost=expected_cost,
            cost_false_attribution=cost_fa,
            cost_missed=cost_miss,
            cost_abstention=cost_abs,
            cost_per_attributed=cost_per_attributed,
            cost_per_correct=cost_per_correct,
            cost_breakdown={
                "false_attribution_count": false_attribution_count,
                "missed_count": missed_count,
                "abstention_count": abstention_count,
                "total": len(predictions),
            },
        )

    @staticmethod
    def optimize_threshold(
        predictions: List,
        config: CostConfig,
        thresholds: Optional[List[float]] = None,
    ) -> Dict[str, Any]:
        """
        Find confidence threshold that minimizes expected cost.

        For each threshold, treats predictions below threshold as abstention.

        Args:
            predictions: List of predictions with .predicted_confidence
            config: CostConfig
            thresholds: Thresholds to evaluate (default: 0.0-0.8 in 0.1 steps)

        Returns:
            Dict with optimal threshold and cost sweep results
        """
        if thresholds is None:
            thresholds = [i / 10.0 for i in range(9)]

        if not predictions:
            return {"optimal_threshold": 0.0, "results": []}

        results = []
        best_threshold = 0.0
        best_cost = float("inf")

        for threshold in thresholds:
            # Adjust predictions based on threshold
            adjusted_predictions = []
            for pred in predictions:
                if pred.predicted_confidence >= threshold or pred.is_abstained:
                    adjusted_predictions.append(pred)
                else:
                    # Below threshold - treat as abstention
                    class ModifiedPred:
                        def __init__(self, orig):
                            self.is_abstained = True
                            self.is_correct = orig.ground_truth_region is None
                            self.ground_truth_region = orig.ground_truth_region

                    adjusted_predictions.append(ModifiedPred(pred))

            metrics = CostAnalyzer.compute_cost_metrics(adjusted_predictions, config)
            results.append({
                "threshold": round(threshold, 2),
                "expected_cost": round(metrics.expected_cost, 4),
                "cost_breakdown": metrics.cost_breakdown,
            })

            if metrics.expected_cost < best_cost:
                best_cost = metrics.expected_cost
                best_threshold = threshold

        return {
            "optimal_threshold": round(best_threshold, 2),
            "optimal_cost": round(best_cost, 4),
            "sweep_results": results,
        }
