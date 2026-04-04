"""Adversarial robustness testing for email header analysis."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class AdversarialSample:
    """Adversarial variant of an evaluation sample."""

    original_path: str
    adversarial_path: str
    attack_type: str
    attack_description: str
    original_result: Optional[Any] = None
    adversarial_result: Optional[Any] = None


@dataclass(frozen=True)
class RobustnessMetrics:
    """Robustness evaluation results."""

    performance_drop: float  # Original accuracy - adversarial accuracy
    false_attribution_increase: float  # Adversarial FAR - original FAR
    abstention_shift: float  # Adversarial abstention rate - original
    attack_success_rate: float  # % that changed prediction
    metrics_by_attack: Dict[str, Dict[str, float]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for JSON serialization."""
        return {
            "performance_drop": round(self.performance_drop, 4),
            "false_attribution_increase": round(self.false_attribution_increase, 4),
            "abstention_shift": round(self.abstention_shift, 4),
            "attack_success_rate": round(self.attack_success_rate, 4),
            "metrics_by_attack": {
                attack: {k: round(v, 4) for k, v in metrics.items()}
                for attack, metrics in self.metrics_by_attack.items()
            },
        }


class AdversarialGenerator:
    """Generate adversarial email variants without breaking parser."""

    ATTACK_TYPES = [
        "header_injection",
        "timestamp_spoofing",
        "broken_chain",
        "relay_mimicry",
        "mixed_infrastructure",
    ]

    @staticmethod
    def generate_adversarial_variants(
        sample_path: str,
        attack_types: Optional[List[str]] = None,
        seed: int = 42,
    ) -> List[AdversarialSample]:
        """
        Generate adversarial variants of a sample.

        Args:
            sample_path: Path to original email file
            attack_types: Which attacks to use (default: all)
            seed: Random seed for determinism

        Returns:
            List of AdversarialSample objects
        """
        if attack_types is None:
            attack_types = AdversarialGenerator.ATTACK_TYPES

        samples = []
        for attack_type in attack_types:
            try:
                adversarial_path = AdversarialGenerator._apply_attack(
                    sample_path, attack_type, seed
                )
                if adversarial_path:
                    sample = AdversarialSample(
                        original_path=sample_path,
                        adversarial_path=adversarial_path,
                        attack_type=attack_type,
                        attack_description=AdversarialGenerator._get_attack_description(
                            attack_type
                        ),
                    )
                    samples.append(sample)
            except Exception:
                # Skip if attack generation fails
                continue

        return samples

    @staticmethod
    def _apply_attack(
        sample_path: str,
        attack_type: str,
        seed: int,
    ) -> Optional[str]:
        """
        Apply adversarial attack to sample.

        Returns path to adversarial variant, or None if attack fails.
        """
        # In a real implementation, this would:
        # 1. Read the email file
        # 2. Parse headers
        # 3. Apply attack transformation
        # 4. Write to temp file
        # 5. Return temp path

        # For now, return descriptive path (implementation depends on parser)
        attack_suffix = {
            "header_injection": "_adv_header_inject",
            "timestamp_spoofing": "_adv_ts_spoof",
            "broken_chain": "_adv_broken_chain",
            "relay_mimicry": "_adv_relay_mimic",
            "mixed_infrastructure": "_adv_mixed_infra",
        }.get(attack_type, "_adv_unknown")

        # Would be real temp path in production
        return sample_path.replace(".eml", f"{attack_suffix}.eml")

    @staticmethod
    def _get_attack_description(attack_type: str) -> str:
        """Get human-readable attack description."""
        descriptions = {
            "header_injection": "Duplicate or insert fake Received headers",
            "timestamp_spoofing": "Non-monotonic or identical timestamps",
            "broken_chain": "Remove intermediate hops from chain",
            "relay_mimicry": "Replace hosts with gmail/outlook-like addresses",
            "mixed_infrastructure": "Inject conflicting infrastructure signals",
        }
        return descriptions.get(attack_type, "Unknown attack")


class RobustnessAnalyzer:
    """Analyze robustness against adversarial attacks."""

    @staticmethod
    def compute_robustness_metrics(
        original_results: List,
        adversarial_results: List[Tuple[str, List]],  # (attack_type, results)
    ) -> RobustnessMetrics:
        """
        Compute robustness metrics comparing original vs adversarial performance.

        Args:
            original_results: List of original prediction results
            adversarial_results: List of (attack_type, adversarial_results)

        Returns:
            RobustnessMetrics with performance analysis
        """
        if not original_results:
            return RobustnessMetrics(
                performance_drop=0.0,
                false_attribution_increase=0.0,
                abstention_shift=0.0,
                attack_success_rate=0.0,
            )

        # Compute original metrics
        original_accuracy = _compute_adversarial_accuracy(original_results)
        original_far = _compute_adversarial_far(original_results)
        original_abstention = _compute_adversarial_abstention(original_results)

        # Compute adversarial metrics per attack
        metrics_by_attack = {}
        total_attacked = []
        attack_success_count = 0

        for attack_type, adv_results in adversarial_results:
            if not adv_results:
                continue

            adv_accuracy = _compute_adversarial_accuracy(adv_results)
            adv_far = _compute_adversarial_far(adv_results)
            adv_abstention = _compute_adversarial_abstention(adv_results)

            metrics_by_attack[attack_type] = {
                "accuracy": adv_accuracy,
                "far": adv_far,
                "abstention": adv_abstention,
                "accuracy_drop": original_accuracy - adv_accuracy,
                "far_increase": adv_far - original_far,
            }

            total_attacked.extend(adv_results)

            # Count predictions that changed
            for orig, adv in zip(original_results, adv_results):
                if (
                    orig.predicted_region != adv.predicted_region
                    or orig.is_abstained != adv.is_abstained
                ):
                    attack_success_count += 1

        # Compute overall adversarial metrics
        avg_accuracy_drop = (
            sum(m["accuracy_drop"] for m in metrics_by_attack.values())
            / len(metrics_by_attack)
            if metrics_by_attack
            else 0.0
        )

        avg_far_increase = (
            sum(m["far_increase"] for m in metrics_by_attack.values())
            / len(metrics_by_attack)
            if metrics_by_attack
            else 0.0
        )

        avg_abstention_shift = (
            _compute_adversarial_abstention(total_attacked) - original_abstention
            if total_attacked
            else 0.0
        )

        attack_success_rate = (
            attack_success_count / (len(original_results) * len(adversarial_results))
            if original_results and adversarial_results
            else 0.0
        )

        return RobustnessMetrics(
            performance_drop=max(0.0, avg_accuracy_drop),
            false_attribution_increase=max(0.0, avg_far_increase),
            abstention_shift=avg_abstention_shift,
            attack_success_rate=attack_success_rate,
            metrics_by_attack=metrics_by_attack,
        )


def _compute_adversarial_accuracy(results: List) -> float:
    """Compute accuracy for adversarial results."""
    if not results:
        return 0.0
    correct = sum(1 for r in results if r.is_correct)
    return correct / len(results)


def _compute_adversarial_far(results: List) -> float:
    """Compute FAR for adversarial results."""
    if not results:
        return 0.0
    attributed = [r for r in results if not r.is_abstained]
    if not attributed:
        return 0.0
    incorrect = sum(1 for r in attributed if not r.is_correct)
    return incorrect / len(attributed)


def _compute_adversarial_abstention(results: List) -> float:
    """Compute abstention rate for adversarial results."""
    if not results:
        return 0.0
    abstained = sum(1 for r in results if r.is_abstained)
    return abstained / len(results)
