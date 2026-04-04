"""Confidence calibration analysis."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class CalibrationBin:
    """Single bin for confidence calibration analysis."""

    bin_lower: float
    bin_upper: float
    count: int = 0
    correct: int = 0
    avg_confidence: float = 0.0
    accuracy: float = 0.0


@dataclass
class CalibrationMetrics:
    """Calibration analysis results."""

    ece: float  # Expected Calibration Error
    mce: float  # Maximum Calibration Error
    brier_score: float  # Mean squared error of confidence predictions
    bins: List[CalibrationBin] = field(default_factory=list)
    reliability_data: List[Dict[str, float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ece": round(self.ece, 4),
            "mce": round(self.mce, 4),
            "brier_score": round(self.brier_score, 4),
            "bins": [
                {
                    "bin_range": f"[{bin.bin_lower:.2f}, {bin.bin_upper:.2f}]",
                    "count": bin.count,
                    "correct": bin.correct,
                    "avg_confidence": round(bin.avg_confidence, 4),
                    "accuracy": round(bin.accuracy, 4),
                    "calibration_error": round(abs(bin.accuracy - bin.avg_confidence), 4),
                }
                for bin in self.bins
            ],
        }


class PredictionForCalibration:
    """Prediction record for calibration analysis."""

    def __init__(self, confidence: float, is_correct: bool):
        self.confidence = confidence
        self.is_correct = is_correct


class CalibrationAnalyzer:
    """Compute confidence calibration metrics."""

    @staticmethod
    def compute_ece(
        predictions: List[PredictionForCalibration],
        n_bins: int = 10,
    ) -> CalibrationMetrics:
        """
        Compute Expected Calibration Error and related metrics.

        Args:
            predictions: List of predictions with confidence and correctness
            n_bins: Number of bins for ECE calculation

        Returns:
            CalibrationMetrics with ECE, MCE, and Brier score
        """
        if not predictions:
            return CalibrationMetrics(ece=0.0, mce=0.0, brier_score=0.0)

        # Create bins
        bins = []
        for i in range(n_bins):
            bin_lower = i / n_bins
            bin_upper = (i + 1) / n_bins
            bins.append(CalibrationBin(bin_lower=bin_lower, bin_upper=bin_upper))

        # Assign predictions to bins
        for pred in predictions:
            for bin in bins:
                if bin.bin_lower <= pred.confidence < bin.bin_upper or (
                    bin.bin_upper == 1.0 and pred.confidence == 1.0
                ):
                    bin.count += 1
                    if pred.is_correct:
                        bin.correct += 1
                    break

        # Compute bin metrics
        total = len(predictions)
        ece = 0.0
        mce = 0.0
        brier_score = 0.0

        for bin in bins:
            if bin.count == 0:
                bin.accuracy = 0.0
                bin.avg_confidence = (bin.bin_lower + bin.bin_upper) / 2
            else:
                bin.accuracy = bin.correct / bin.count
                bin.avg_confidence = sum(
                    pred.confidence for pred in predictions
                    if bin.bin_lower <= pred.confidence < bin.bin_upper or (
                        bin.bin_upper == 1.0 and pred.confidence == 1.0
                    )
                ) / bin.count

            # ECE: weighted average of |accuracy - confidence|
            weight = bin.count / total
            calibration_error = abs(bin.accuracy - bin.avg_confidence)
            ece += weight * calibration_error
            mce = max(mce, calibration_error)

        # Brier Score: mean squared error
        brier_score = sum((pred.confidence - (1.0 if pred.is_correct else 0.0)) ** 2
                          for pred in predictions) / total

        # Build reliability data
        reliability_data = [
            {
                "confidence": round(bin.avg_confidence, 4),
                "accuracy": round(bin.accuracy, 4),
                "count": bin.count,
            }
            for bin in bins
            if bin.count > 0
        ]

        return CalibrationMetrics(
            ece=ece,
            mce=mce,
            brier_score=brier_score,
            bins=[b for b in bins if b.count > 0],
            reliability_data=reliability_data,
        )
