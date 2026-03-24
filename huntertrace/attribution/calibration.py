#!/usr/bin/env python3
"""
huntertrace/attribution/calibration.py
=======================================
Isotonic-regression calibration layer for HunterTrace's attribution engine.

PROBLEM
-------
The raw aci_adjusted_prob from AttributionEngine is systematically
over-confident at high values (ECE = 0.223, target < 0.15).

Root cause: the Bayesian update compounds likelihood ratios multiplicatively,
which pushes posteriors toward 0 or 1 faster than empirical accuracy justifies.
The signal-count cap (min(0.50 + n_sig * 0.075, 0.92)) partially corrects this
but is a constant function that doesn't adapt to the actual calibration curve
of the training data.

SOLUTION
--------
Isotonic regression is the canonical post-hoc calibration method for
classification systems (Zadrozny & Elkan 2002). It fits a monotone non-
decreasing step function f: raw_score → calibrated_score on a held-out
calibration set, then applies it at inference time.

Isotonic regression is ideal here because:
  - It makes no distributional assumptions (unlike Platt scaling)
  - It preserves the rank ordering of attributions
  - It is guaranteed to reduce ECE on the calibration set
  - It requires very few labelled examples (40+ is enough)

INTEGRATION
-----------
Engine-level (recommended):
    engine = AttributionEngine()
    engine.load_calibrator("calibration/isotonic_calibrator.json")
    result = engine.attribute(pipeline_result)
    # result.aci_adjusted_prob is now calibrated
    # result.raw_aci_adjusted_prob holds the original score

Standalone calibration training:
    from calibration import IsotonicCalibrator, CalibrationTrainer

    trainer = CalibrationTrainer()
    trainer.add_samples(predictions, ground_truth_labels)
    calibrator = trainer.fit()
    calibrator.save("calibration/isotonic_calibrator.json")

    # Then inject into engine:
    engine.load_calibrator("calibration/isotonic_calibrator.json")
"""

from __future__ import annotations

import json
import math
import bisect
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
#  CALIBRATION DATA POINT
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CalibrationSample:
    """One labelled prediction for calibration training."""
    email_id:      str
    raw_score:     float   # aci_adjusted_prob before calibration
    is_correct:    bool    # True if predicted_country == ground_truth_country
    n_signals:     int     # number of signals used
    has_vpn:       bool
    has_tor:       bool
    scenario:      str = "unknown"   # "vpn" | "tor" | "webmail" | "direct" | "unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  ISOTONIC CALIBRATOR
# ─────────────────────────────────────────────────────────────────────────────

class IsotonicCalibrator:
    """
    Piecewise-constant isotonic regression calibrator.

    Stores a sorted list of (breakpoint, calibrated_value) pairs
    and maps raw scores to calibrated probabilities via linear
    interpolation between breakpoints.

    Serialisable to/from JSON — no sklearn dependency required.

    Attributes
    ----------
    breakpoints     : sorted list of raw score thresholds
    calibrated_vals : calibrated probability for each bin
    n_samples       : training set size (for reporting)
    ece_before      : ECE on training set before calibration
    ece_after       : ECE on training set after calibration
    """

    # Default calibration table — derived from empirical results:
    #   n=53 labelled emails, 40 ground-truthed, ECE=0.223
    # This default provides reasonable calibration even with no training data.
    # Overwritten when fit() or load() is called.
    #
    # Interpretation: raw score 0.85 maps to calibrated 0.62 (was over-confident).
    # Source: uniform grid fit to (accuracy=52.8%, ECE=0.223) constraint.
    _DEFAULT_BREAKPOINTS = [0.00, 0.10, 0.20, 0.30, 0.40, 0.50,
                            0.60, 0.70, 0.80, 0.90, 1.00]
    _DEFAULT_CALIBRATED  = [0.00, 0.08, 0.17, 0.25, 0.33, 0.41,
                            0.50, 0.57, 0.63, 0.68, 0.72]

    def __init__(self):
        self.breakpoints:     List[float] = list(self._DEFAULT_BREAKPOINTS)
        self.calibrated_vals: List[float] = list(self._DEFAULT_CALIBRATED)
        self.n_samples:       int   = 0
        self.ece_before:      float = 0.223   # known baseline
        self.ece_after:       float = 0.223   # updated after fit()
        self.fitted:          bool  = False
        self.fitted_at:       str   = ""

    # ── Inference ────────────────────────────────────────────────────────────

    def calibrate(self, raw_score: float) -> float:
        """
        Map a raw aci_adjusted_prob to a calibrated probability.

        Uses linear interpolation between adjacent breakpoints.
        Scores outside [0,1] are clamped.

        Parameters
        ----------
        raw_score : float in [0, 1]

        Returns
        -------
        calibrated probability in [0, 1]
        """
        if not self.breakpoints:
            return raw_score

        x = max(0.0, min(1.0, raw_score))

        # Find surrounding breakpoints
        idx = bisect.bisect_right(self.breakpoints, x) - 1
        idx = max(0, min(idx, len(self.breakpoints) - 2))

        x0, x1 = self.breakpoints[idx], self.breakpoints[idx + 1]
        y0, y1 = self.calibrated_vals[idx], self.calibrated_vals[idx + 1]

        if x1 == x0:
            return float(y0)

        # Linear interpolation
        t = (x - x0) / (x1 - x0)
        return float(y0 + t * (y1 - y0))

    # ── Serialisation ─────────────────────────────────────────────────────────

    def save(self, path: str) -> None:
        """Save calibrator to JSON."""
        data = {
            "version":         "1.0",
            "type":            "isotonic_piecewise_linear",
            "breakpoints":     self.breakpoints,
            "calibrated_vals": self.calibrated_vals,
            "n_samples":       self.n_samples,
            "ece_before":      round(self.ece_before, 4),
            "ece_after":       round(self.ece_after, 4),
            "fitted":          self.fitted,
            "fitted_at":       self.fitted_at,
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[Calibrator] Saved → {path}  "
              f"(ECE {self.ece_before:.4f} → {self.ece_after:.4f}, n={self.n_samples})")

    @classmethod
    def load(cls, path: str) -> "IsotonicCalibrator":
        """Load calibrator from JSON."""
        with open(path) as f:
            data = json.load(f)
        cal = cls()
        cal.breakpoints     = data["breakpoints"]
        cal.calibrated_vals = data["calibrated_vals"]
        cal.n_samples       = data.get("n_samples", 0)
        cal.ece_before      = data.get("ece_before", 0.0)
        cal.ece_after       = data.get("ece_after", 0.0)
        cal.fitted          = data.get("fitted", True)
        cal.fitted_at       = data.get("fitted_at", "")
        print(f"[Calibrator] Loaded from {path}  "
              f"(ECE {cal.ece_before:.4f} → {cal.ece_after:.4f}, n={cal.n_samples})")
        return cal

    def to_dict(self) -> dict:
        return {
            "breakpoints":     self.breakpoints,
            "calibrated_vals": self.calibrated_vals,
            "n_samples":       self.n_samples,
            "ece_before":      round(self.ece_before, 4),
            "ece_after":       round(self.ece_after, 4),
            "fitted":          self.fitted,
        }

    def __repr__(self) -> str:
        return (f"IsotonicCalibrator(fitted={self.fitted}, "
                f"n={self.n_samples}, "
                f"ECE {self.ece_before:.4f}→{self.ece_after:.4f})")


# ─────────────────────────────────────────────────────────────────────────────
#  CALIBRATION TRAINER
# ─────────────────────────────────────────────────────────────────────────────

class CalibrationTrainer:
    """
    Fits an IsotonicCalibrator from (raw_score, is_correct) pairs.

    Uses the pool-adjacent-violators (PAV) algorithm — a standard O(n log n)
    isotonic regression implementation with no external dependencies.

    Usage
    -----
        trainer = CalibrationTrainer()

        # Add samples from BatchEvaluator predictions
        for pred, truth in zip(predictions, ground_truth):
            correct = (pred.predicted_country == truth.country_name)
            trainer.add_sample(CalibrationSample(
                email_id   = pred.email_id,
                raw_score  = pred.confidence_score,
                is_correct = correct,
                n_signals  = pred.signals_used,
                has_vpn    = truth.metadata.get("has_vpn", False),
                has_tor    = truth.metadata.get("has_tor", False),
            ))

        calibrator = trainer.fit(n_bins=10)
        calibrator.save("calibration/isotonic_calibrator.json")
    """

    def __init__(self):
        self._samples: List[CalibrationSample] = []

    def add_sample(self, sample: CalibrationSample) -> None:
        self._samples.append(sample)

    def add_samples(
        self,
        raw_scores:  List[float],
        is_correct:  List[bool],
        email_ids:   Optional[List[str]] = None,
        n_signals:   Optional[List[int]] = None,
    ) -> None:
        """
        Bulk-add samples from parallel lists.

        Parameters
        ----------
        raw_scores  : aci_adjusted_prob for each prediction
        is_correct  : True if top-1 country matched ground truth
        email_ids   : optional email identifiers (for reporting)
        n_signals   : optional signal counts per prediction
        """
        if len(raw_scores) != len(is_correct):
            raise ValueError("raw_scores and is_correct must be the same length")
        for i, (score, correct) in enumerate(zip(raw_scores, is_correct)):
            self._samples.append(CalibrationSample(
                email_id  = (email_ids[i] if email_ids else f"email_{i:04d}"),
                raw_score = float(score),
                is_correct= bool(correct),
                n_signals = (n_signals[i] if n_signals else 0),
                has_vpn   = False,
                has_tor   = False,
            ))

    def fit(self, n_bins: int = 10) -> IsotonicCalibrator:
        """
        Fit isotonic regression and return a calibrated IsotonicCalibrator.

        Parameters
        ----------
        n_bins : number of equal-width bins for calibration.
                 10 bins is a good default for n=40–200 samples.
                 Reduce to 5–7 for very small datasets (n < 30).

        Returns
        -------
        IsotonicCalibrator ready to use

        Raises
        ------
        ValueError if fewer than 2 labelled samples are available.
        """
        if len(self._samples) < 2:
            raise ValueError(
                f"Need at least 2 labelled samples to fit calibrator; "
                f"got {len(self._samples)}."
            )

        # Sort by raw score
        sorted_samples = sorted(self._samples, key=lambda s: s.raw_score)
        scores   = [s.raw_score  for s in sorted_samples]
        labels   = [float(s.is_correct) for s in sorted_samples]

        # ── ECE before calibration ────────────────────────────────────────
        ece_before = self._compute_ece(scores, labels, n_bins=min(n_bins, 5))

        # ── Pool-adjacent-violators (PAV) isotonic regression ─────────────
        # Works on the sorted (score, label) sequence.
        # Merges adjacent blocks that violate monotonicity.
        calibrated_scores = self._pav(scores, labels)

        # ── Bin the calibration mapping ───────────────────────────────────
        # Build n_bins breakpoints and compute mean calibrated value per bin.
        bin_edges = [i / n_bins for i in range(n_bins + 1)]
        bin_means: List[float] = []

        for b in range(n_bins):
            lo, hi = bin_edges[b], bin_edges[b + 1]
            in_bin = [
                calibrated_scores[i]
                for i, s in enumerate(scores)
                if lo <= s < hi
            ]
            if in_bin:
                bin_means.append(sum(in_bin) / len(in_bin))
            elif b == 0:
                bin_means.append(0.0)
            else:
                # Carry forward previous bin value (isotonic constraint)
                bin_means.append(bin_means[-1])

        # Final bin includes upper edge (score == 1.0)
        if scores and scores[-1] == 1.0:
            bin_means[-1] = calibrated_scores[-1]

        # Enforce strict monotonicity after binning
        bin_means = self._enforce_monotone(bin_means)

        # calibrated_vals must be the same length as breakpoints (n_bins+1)
        # so calibrate() can always access both [idx] and [idx+1].
        bin_means_full = bin_means + [bin_means[-1]]

        # ── Build calibrator ──────────────────────────────────────────────
        cal = IsotonicCalibrator()
        cal.breakpoints     = bin_edges
        cal.calibrated_vals = bin_means_full
        cal.n_samples       = len(self._samples)
        cal.ece_before      = ece_before
        cal.ece_after       = self._compute_ece_calibrated(scores, labels, cal)
        cal.fitted          = True
        cal.fitted_at       = datetime.now().isoformat()

        print(f"[CalibrationTrainer] Fit on {len(self._samples)} samples  "
              f"ECE: {ece_before:.4f} → {cal.ece_after:.4f}  "
              f"(Δ = {ece_before - cal.ece_after:+.4f})")

        return cal

    # ── PAV algorithm ────────────────────────────────────────────────────────

    @staticmethod
    def _pav(scores: List[float], labels: List[float]) -> List[float]:
        """
        Pool-adjacent-violators isotonic regression.
        Returns calibrated scores in the same order as input (sorted by raw score).

        Time complexity: O(n)
        """
        n = len(scores)
        if n == 0:
            return []

        # Each block: (sum_labels, count) → mean = sum_labels / count
        blocks: List[List] = [[label, 1] for label in labels]

        # Forward pass — merge blocks that violate monotonicity
        i = 0
        while i < len(blocks) - 1:
            if blocks[i][0] / blocks[i][1] > blocks[i + 1][0] / blocks[i + 1][1]:
                # Merge block i and i+1
                blocks[i][0] += blocks[i + 1][0]
                blocks[i][1] += blocks[i + 1][1]
                blocks.pop(i + 1)
                # Back up to check if merge created new violation
                if i > 0:
                    i -= 1
            else:
                i += 1

        # Expand blocks back to per-sample list
        result = []
        for block in blocks:
            mean = block[0] / block[1]
            result.extend([mean] * block[1])

        return result

    @staticmethod
    def _enforce_monotone(values: List[float]) -> List[float]:
        """Forward pass to ensure list is non-decreasing."""
        out = list(values)
        for i in range(1, len(out)):
            out[i] = max(out[i], out[i - 1])
        return out

    # ── ECE computation ───────────────────────────────────────────────────────

    @staticmethod
    def _compute_ece(
        scores: List[float],
        labels: List[float],
        n_bins: int = 5,
    ) -> float:
        """Expected Calibration Error across n_bins uniform bins."""
        n = len(scores)
        if n == 0:
            return 0.0
        ece = 0.0
        for b in range(n_bins):
            lo = b / n_bins
            hi = (b + 1) / n_bins
            in_bin = [(s, l) for s, l in zip(scores, labels) if lo <= s < hi]
            if in_bin:
                acc  = sum(l for _, l in in_bin) / len(in_bin)
                conf = sum(s for s, _ in in_bin) / len(in_bin)
                ece += abs(acc - conf) * len(in_bin) / n
        return ece

    @staticmethod
    def _compute_ece_calibrated(
        raw_scores: List[float],
        labels:     List[float],
        calibrator: "IsotonicCalibrator",
        n_bins:     int = 5,
    ) -> float:
        """ECE after applying calibrator."""
        cal_scores = [calibrator.calibrate(s) for s in raw_scores]
        return CalibrationTrainer._compute_ece(cal_scores, labels, n_bins)


# ─────────────────────────────────────────────────────────────────────────────
#  CALIBRATION REPORT
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CalibrationReport:
    """Summary of calibration quality across scoring bins."""
    n_samples:      int
    ece_before:     float
    ece_after:      float
    ece_improvement: float
    bin_reports:    List[Dict]   # per-bin: {lo, hi, n, acc, conf_raw, conf_cal}
    calibrator:     IsotonicCalibrator

    def print_summary(self) -> None:
        W = 65
        print()
        print("=" * W)
        print("  HUNTЕРТRACE — CONFIDENCE CALIBRATION REPORT")
        print("=" * W)
        print(f"  Samples evaluated : {self.n_samples}")
        print(f"  ECE before        : {self.ece_before:.4f}")
        print(f"  ECE after         : {self.ece_after:.4f}"
              f"  (improvement: {self.ece_improvement:+.4f})")
        print()
        print(f"  {'Bin':>10}  {'n':>5}  {'Accuracy':>10}  "
              f"{'Raw conf':>10}  {'Cal conf':>10}  {'Δ':>6}")
        print("  " + "-" * (W - 2))
        for b in self.bin_reports:
            print(f"  [{b['lo']:.1f}–{b['hi']:.1f}]  "
                  f"{b['n']:>5}  "
                  f"{b['acc']:>10.1%}  "
                  f"{b['conf_raw']:>10.1%}  "
                  f"{b['conf_cal']:>10.1%}  "
                  f"{b['conf_cal'] - b['conf_raw']:>+5.1%}")
        print("=" * W)
        print()

    def save_json(self, path: str) -> None:
        data = {
            "n_samples":       self.n_samples,
            "ece_before":      round(self.ece_before, 4),
            "ece_after":       round(self.ece_after, 4),
            "ece_improvement": round(self.ece_improvement, 4),
            "bin_reports":     self.bin_reports,
            "calibrator":      self.calibrator.to_dict(),
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[CalibrationReport] Saved → {path}")


def evaluate_calibration(
    raw_scores:  List[float],
    is_correct:  List[bool],
    calibrator:  IsotonicCalibrator,
    n_bins:      int = 5,
) -> CalibrationReport:
    """
    Compute a full calibration report for a set of predictions.

    Parameters
    ----------
    raw_scores  : aci_adjusted_prob before calibration
    is_correct  : True if predicted_country == ground_truth_country
    calibrator  : fitted IsotonicCalibrator
    n_bins      : number of bins for ECE computation

    Returns
    -------
    CalibrationReport
    """
    n = len(raw_scores)
    labels = [float(c) for c in is_correct]

    ece_before = CalibrationTrainer._compute_ece(raw_scores, labels, n_bins)
    ece_after  = CalibrationTrainer._compute_ece_calibrated(
        raw_scores, labels, calibrator, n_bins)

    bin_reports = []
    for b in range(n_bins):
        lo = b / n_bins
        hi = (b + 1) / n_bins
        in_bin = [(raw_scores[i], labels[i]) for i in range(n) if lo <= raw_scores[i] < hi]
        if in_bin:
            acc_b       = sum(l for _, l in in_bin) / len(in_bin)
            conf_raw_b  = sum(s for s, _ in in_bin) / len(in_bin)
            conf_cal_b  = sum(calibrator.calibrate(s) for s, _ in in_bin) / len(in_bin)
        else:
            acc_b = conf_raw_b = conf_cal_b = 0.0
        bin_reports.append({
            "lo":       round(lo, 2),
            "hi":       round(hi, 2),
            "n":        len(in_bin),
            "acc":      round(acc_b, 4),
            "conf_raw": round(conf_raw_b, 4),
            "conf_cal": round(conf_cal_b, 4),
        })

    return CalibrationReport(
        n_samples       = n,
        ece_before      = ece_before,
        ece_after       = ece_after,
        ece_improvement = ece_before - ece_after,
        bin_reports     = bin_reports,
        calibrator      = calibrator,
    )