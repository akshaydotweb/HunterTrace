"""Statistical significance and bootstrap confidence intervals."""

from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


@dataclass(frozen=True)
class MetricCI:
    """Confidence interval for a metric."""

    mean: float
    std: float
    ci_lower: float
    ci_upper: float

    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization."""
        return {
            "mean": round(self.mean, 4),
            "std": round(self.std, 4),
            "ci_lower": round(self.ci_lower, 4),
            "ci_upper": round(self.ci_upper, 4),
        }


class BootstrapAnalyzer:
    """Deterministic bootstrap confidence interval computation."""

    @staticmethod
    def bootstrap_ci(
        metric_fn: Callable[[List], float],
        data: List,
        n_bootstrap: int = 1000,
        ci: float = 0.95,
        seed: int = 42,
    ) -> MetricCI:
        """
        Compute bootstrap confidence interval for a metric.

        Args:
            metric_fn: Function that computes metric from data subset
            data: Data to bootstrap (e.g., list of predictions)
            n_bootstrap: Number of bootstrap iterations
            ci: Confidence interval level (0.95 = 95%)
            seed: Random seed for reproducibility

        Returns:
            MetricCI with mean, std, and CI bounds
        """
        if not data:
            return MetricCI(mean=0.0, std=0.0, ci_lower=0.0, ci_upper=0.0)

        # Generate deterministic samples using pseudo-random approach
        bootstrap_metrics = []
        rng = _DeterministicRNG(seed)

        for _ in range(n_bootstrap):
            # Sample with replacement
            sample_indices = _sample_with_replacement(len(data), rng)
            sample = [data[i] for i in sample_indices]

            # Compute metric for this bootstrap sample
            try:
                metric_value = metric_fn(sample)
                bootstrap_metrics.append(metric_value)
            except Exception:
                # Skip if metric computation fails on this sample
                continue

        if not bootstrap_metrics:
            return MetricCI(mean=0.0, std=0.0, ci_lower=0.0, ci_upper=0.0)

        # Compute statistics
        mean = sum(bootstrap_metrics) / len(bootstrap_metrics)
        variance = sum((x - mean) ** 2 for x in bootstrap_metrics) / len(bootstrap_metrics)
        std = variance ** 0.5

        # Compute percentile-based CI
        sorted_metrics = sorted(bootstrap_metrics)
        alpha = 1 - ci
        lower_idx = int((alpha / 2) * len(sorted_metrics))
        upper_idx = int((1 - alpha / 2) * len(sorted_metrics))

        ci_lower = sorted_metrics[max(0, lower_idx)]
        ci_upper = sorted_metrics[min(len(sorted_metrics) - 1, upper_idx)]

        return MetricCI(mean=mean, std=std, ci_lower=ci_lower, ci_upper=ci_upper)

    @staticmethod
    def bootstrap_accuracy_ci(
        predictions: List,
        n_bootstrap: int = 1000,
        seed: int = 42,
    ) -> MetricCI:
        """
        Bootstrap CI for accuracy.

        Predictions should have .is_correct attribute.
        """

        def accuracy_fn(sample):
            if not sample:
                return 0.0
            correct = sum(1 for p in sample if p.is_correct)
            return correct / len(sample)

        return BootstrapAnalyzer.bootstrap_ci(accuracy_fn, predictions, n_bootstrap, seed=seed)

    @staticmethod
    def bootstrap_far_ci(
        predictions: List,
        n_bootstrap: int = 1000,
        seed: int = 42,
    ) -> MetricCI:
        """
        Bootstrap CI for False Attribution Rate.

        Predictions should have .is_correct and .is_abstained attributes.
        """

        def far_fn(sample):
            if not sample:
                return 0.0

            # Find attributed predictions
            attributed = [p for p in sample if not p.is_abstained]
            if not attributed:
                return 0.0

            incorrect_attributed = sum(1 for p in attributed if not p.is_correct)
            return incorrect_attributed / len(attributed)

        return BootstrapAnalyzer.bootstrap_ci(far_fn, predictions, n_bootstrap, seed=seed)

    @staticmethod
    def bootstrap_precision_ci(
        predictions: List,
        n_bootstrap: int = 1000,
        seed: int = 42,
    ) -> MetricCI:
        """Bootstrap CI for Precision."""

        def precision_fn(sample):
            if not sample:
                return 0.0
            attributed = [p for p in sample if not p.is_abstained]
            if not attributed:
                return 0.0
            correct_attributed = sum(1 for p in attributed if p.is_correct)
            return correct_attributed / len(attributed)

        return BootstrapAnalyzer.bootstrap_ci(precision_fn, predictions, n_bootstrap, seed=seed)

    @staticmethod
    def bootstrap_recall_ci(
        predictions: List,
        n_bootstrap: int = 1000,
        seed: int = 42,
    ) -> MetricCI:
        """Bootstrap CI for Recall."""

        def recall_fn(sample):
            if not sample:
                return 0.0
            ground_truth_positive = [
                p for p in sample if p.ground_truth_region is not None
            ]
            if not ground_truth_positive:
                return 0.0
            correct = sum(1 for p in ground_truth_positive if p.is_correct)
            return correct / len(ground_truth_positive)

        return BootstrapAnalyzer.bootstrap_ci(recall_fn, predictions, n_bootstrap, seed=seed)

    @staticmethod
    def bootstrap_f1_ci(
        predictions: List,
        n_bootstrap: int = 1000,
        seed: int = 42,
    ) -> MetricCI:
        """Bootstrap CI for F1 Score."""

        def f1_fn(sample):
            if not sample:
                return 0.0

            # Compute precision
            attributed = [p for p in sample if not p.is_abstained]
            if not attributed:
                precision = 0.0
            else:
                correct_attributed = sum(1 for p in attributed if p.is_correct)
                precision = correct_attributed / len(attributed)

            # Compute recall
            ground_truth_positive = [
                p for p in sample if p.ground_truth_region is not None
            ]
            if not ground_truth_positive:
                recall = 0.0
            else:
                correct = sum(1 for p in ground_truth_positive if p.is_correct)
                recall = correct / len(ground_truth_positive)

            # Compute F1
            if precision + recall == 0:
                return 0.0
            return 2 * (precision * recall) / (precision + recall)

        return BootstrapAnalyzer.bootstrap_ci(f1_fn, predictions, n_bootstrap, seed=seed)


class _DeterministicRNG:
    """Deterministic pseudo-random number generator using LCG."""

    def __init__(self, seed: int):
        """Initialize with seed."""
        self.state = seed
        self.a = 1664525
        self.c = 1013904223
        self.m = 2**32

    def next_int(self, max_val: int) -> int:
        """Generate next deterministic integer in [0, max_val)."""
        self.state = (self.a * self.state + self.c) % self.m
        return self.state % max_val

    def shuffle(self, lst: List) -> List:
        """Deterministically shuffle a list."""
        result = lst.copy()
        for i in range(len(result) - 1, 0, -1):
            j = self.next_int(i + 1)
            result[i], result[j] = result[j], result[i]
        return result


def _sample_with_replacement(n: int, rng: _DeterministicRNG) -> List[int]:
    """Generate deterministic sample with replacement indices."""
    return [rng.next_int(n) for _ in range(n)]
