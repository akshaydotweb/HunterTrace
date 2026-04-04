"""Core metrics computation for evaluation."""

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class Metrics:
    """Core evaluation metrics."""

    # Accuracy metrics
    accuracy: float  # correct_predictions / total
    false_attribution_rate: float  # incorrect_attributed / total_attributed (CRITICAL)
    abstention_rate: float  # inconclusive / total
    coverage_rate: float  # attributed / total

    # Precision/Recall
    precision: float  # correct_attributed / total_attributed
    recall: float  # correct_attributed / total_ground_truth_positive

    # F1 Score
    f1_score: float

    # Confidence metrics
    avg_confidence_correct: float
    avg_confidence_incorrect: float
    avg_confidence_abstained: float

    # Confusion matrix counts
    correct_attributed: int = 0
    incorrect_attributed: int = 0
    correct_abstained: int = 0
    incorrect_abstained: int = 0
    total: int = 0

    # Additional tracking
    total_attributed: int = 0
    total_ground_truth_positive: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "accuracy": round(self.accuracy, 4),
            "false_attribution_rate": round(self.false_attribution_rate, 4),
            "abstention_rate": round(self.abstention_rate, 4),
            "coverage_rate": round(self.coverage_rate, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "avg_confidence_correct": round(self.avg_confidence_correct, 4),
            "avg_confidence_incorrect": round(self.avg_confidence_incorrect, 4),
            "avg_confidence_abstained": round(self.avg_confidence_abstained, 4),
            "confusion_matrix": {
                "correct_attributed": self.correct_attributed,
                "incorrect_attributed": self.incorrect_attributed,
                "correct_abstained": self.correct_abstained,
                "incorrect_abstained": self.incorrect_abstained,
                "total": self.total,
            },
        }


class PredictionRecord:
    """Single prediction record for metric computation."""

    def __init__(
        self,
        sample_id: str,
        predicted_region: str | None,
        predicted_verdict: str,
        predicted_confidence: float,
        ground_truth_region: str | None,
    ):
        self.sample_id = sample_id
        self.predicted_region = predicted_region
        self.predicted_verdict = predicted_verdict
        self.predicted_confidence = predicted_confidence
        self.ground_truth_region = ground_truth_region

        # Compute correctness
        if predicted_verdict == "inconclusive":
            self.is_abstained = True
            self.is_correct = ground_truth_region is None
        else:
            self.is_abstained = False
            self.is_correct = predicted_region == ground_truth_region


def compute_metrics(predictions: list[PredictionRecord]) -> Metrics:
    """
    Compute evaluation metrics from predictions.

    Args:
        predictions: List of PredictionRecord objects

    Returns:
        Metrics object with all computed metrics
    """
    if not predictions:
        return Metrics(
            accuracy=0.0,
            false_attribution_rate=0.0,
            abstention_rate=0.0,
            coverage_rate=0.0,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            avg_confidence_correct=0.0,
            avg_confidence_incorrect=0.0,
            avg_confidence_abstained=0.0,
            total=0,
        )

    total = len(predictions)

    # Count outcomes
    correct_attributed = 0
    incorrect_attributed = 0
    correct_abstained = 0
    incorrect_abstained = 0

    # Collect confidences
    confidences_correct = []
    confidences_incorrect = []
    confidences_abstained = []

    for pred in predictions:
        if pred.is_abstained:
            if pred.is_correct:
                correct_abstained += 1
            else:
                incorrect_abstained += 1
            confidences_abstained.append(pred.predicted_confidence)
        else:
            if pred.is_correct:
                correct_attributed += 1
                confidences_correct.append(pred.predicted_confidence)
            else:
                incorrect_attributed += 1
                confidences_incorrect.append(pred.predicted_confidence)

    # Compute totals
    total_attributed = correct_attributed + incorrect_attributed
    total_abstained = correct_abstained + incorrect_abstained

    # Count ground truth positives
    total_ground_truth_positive = sum(1 for p in predictions if p.ground_truth_region is not None)

    # Compute rates
    accuracy = (correct_attributed + correct_abstained) / total if total > 0 else 0.0
    abstention_rate = total_abstained / total if total > 0 else 0.0
    coverage_rate = total_attributed / total if total > 0 else 0.0

    # False attribution rate (CRITICAL)
    false_attribution_rate = (
        incorrect_attributed / total_attributed if total_attributed > 0 else 0.0
    )

    # Precision: correct_attributed / total_attributed
    precision = correct_attributed / total_attributed if total_attributed > 0 else 0.0

    # Recall: correct_attributed / total_ground_truth_positive
    recall = correct_attributed / total_ground_truth_positive if total_ground_truth_positive > 0 else 0.0

    # F1 Score
    if precision + recall > 0:
        f1_score = 2 * (precision * recall) / (precision + recall)
    else:
        f1_score = 0.0

    # Average confidences
    avg_confidence_correct = sum(confidences_correct) / len(confidences_correct) if confidences_correct else 0.0
    avg_confidence_incorrect = (
        sum(confidences_incorrect) / len(confidences_incorrect) if confidences_incorrect else 0.0
    )
    avg_confidence_abstained = (
        sum(confidences_abstained) / len(confidences_abstained) if confidences_abstained else 0.0
    )

    return Metrics(
        accuracy=accuracy,
        false_attribution_rate=false_attribution_rate,
        abstention_rate=abstention_rate,
        coverage_rate=coverage_rate,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        avg_confidence_correct=avg_confidence_correct,
        avg_confidence_incorrect=avg_confidence_incorrect,
        avg_confidence_abstained=avg_confidence_abstained,
        correct_attributed=correct_attributed,
        incorrect_attributed=incorrect_attributed,
        correct_abstained=correct_abstained,
        incorrect_abstained=incorrect_abstained,
        total=total,
        total_attributed=total_attributed,
        total_ground_truth_positive=total_ground_truth_positive,
    )
