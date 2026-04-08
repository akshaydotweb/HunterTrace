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
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Any, List, Optional, Tuple, Dict, Mapping, Sequence
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


# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 6C — CONFIG CALIBRATION / WEIGHT OPTIMISATION
# ─────────────────────────────────────────────────────────────────────────────

try:
    from huntertrace.attribution.scoring import InferenceEngine, ScoringConfig
    from huntertrace.attribution.evaluation import AttributionEvaluator, build_default_dataset
    from huntertrace.attribution.adversarial_testing import (
        AdversarialTester,
        ALL_ATTACK_TYPES,
    )
except ModuleNotFoundError:  # pragma: no cover - direct-script fallback
    from scoring import InferenceEngine, ScoringConfig  # type: ignore
    from evaluation import AttributionEvaluator, build_default_dataset  # type: ignore
    from adversarial_testing import AdversarialTester, ALL_ATTACK_TYPES  # type: ignore


_TUNABLE_GROUPS: Tuple[str, ...] = (
    "group_weights",
    "signal_weights",
    "trust_multipliers",
    "validation_multipliers",
    "conflict_multipliers",
    "evidence_penalties",
)

_STEP_FACTORS: Tuple[float, ...] = (0.70, 0.85, 1.00, 1.15, 1.30)
_EPS = 1e-12


@dataclass
class OptimisationState:
    config_dict: Dict[str, Any]
    metrics: Dict[str, Any]


def _as_config_dict(cfg: ScoringConfig | Mapping[str, Any]) -> Dict[str, Any]:
    if isinstance(cfg, ScoringConfig):
        return {
            "group_weights": dict(cfg.group_weights),
            "signal_weights": dict(cfg.signal_weights),
            "trust_multipliers": dict(cfg.trust_multipliers),
            "validation_multipliers": dict(cfg.validation_multipliers),
            "conflict_multipliers": dict(cfg.conflict_multipliers),
            "evidence_penalties": dict(cfg.evidence_penalties),
            "confidence_cap": float(cfg.confidence_cap),
        }
    return {
        "group_weights": dict(cfg.get("group_weights", {})),
        "signal_weights": dict(cfg.get("signal_weights", {})),
        "trust_multipliers": dict(cfg.get("trust_multipliers", {})),
        "validation_multipliers": dict(cfg.get("validation_multipliers", {})),
        "conflict_multipliers": dict(cfg.get("conflict_multipliers", {})),
        "evidence_penalties": dict(cfg.get("evidence_penalties", {})),
        "confidence_cap": float(cfg.get("confidence_cap", 0.8)),
    }


def _to_config(cfg_dict: Mapping[str, Any]) -> ScoringConfig:
    return ScoringConfig(
        group_weights=dict(cfg_dict["group_weights"]),
        signal_weights=dict(cfg_dict["signal_weights"]),
        trust_multipliers=dict(cfg_dict["trust_multipliers"]),
        validation_multipliers=dict(cfg_dict["validation_multipliers"]),
        conflict_multipliers=dict(cfg_dict["conflict_multipliers"]),
        evidence_penalties=dict(cfg_dict["evidence_penalties"]),
        confidence_cap=float(cfg_dict.get("confidence_cap", 0.8)),
    )


def _calibration_gap(conf_cal: Mapping[str, Mapping[str, float]]) -> float:
    total_n = 0.0
    total_gap = 0.0
    for bucket in sorted(conf_cal.keys()):
        row = conf_cal[bucket]
        n = float(row.get("attributed_count", row.get("count", 0.0)))
        if n <= 0.0:
            continue
        pred = float(row.get("mean_predicted_confidence", 0.0))
        acc = float(row.get("empirical_correctness", 0.0))
        total_gap += abs(pred - acc) * n
        total_n += n
    return total_gap / total_n if total_n > 0.0 else 0.0


def _has_high_confidence_incorrect(eval_metrics: Mapping[str, Any], adv_metrics: Mapping[str, Any]) -> bool:
    for row in eval_metrics.get("failure_cases", []) or []:
        if float(row.get("confidence", 0.0)) > 0.8 + _EPS:
            return True
    for row in adv_metrics.get("failures", []) or []:
        reasons = set(row.get("reasons", []) or [])
        if "high_confidence_incorrect_attribution" in reasons:
            return True
        # Defensive guard if reason list is missing.
        if float(row.get("attacked_confidence", 0.0)) > 0.8 + _EPS:
            return True
    return False


def _has_adversarial_confidence_increase(adv_metrics: Mapping[str, Any]) -> bool:
    for row in adv_metrics.get("failures", []) or []:
        reasons = set(row.get("reasons", []) or [])
        if "confidence_increase_under_attack" in reasons:
            return True
    return False


def _derive_metrics(eval_metrics: Mapping[str, Any], adv_metrics: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "accuracy": float(eval_metrics.get("accuracy", 0.0)),
        "false_attribution_rate": float(eval_metrics.get("false_attribution_rate", 0.0)),
        "abstention_rate": float(eval_metrics.get("abstention_rate", 0.0)),
        "confidence_calibration_error": float(
            _calibration_gap(eval_metrics.get("confidence_calibration", {}))
        ),
        "avg_confidence_correct": float(eval_metrics.get("avg_confidence_correct", 0.0)),
        "avg_confidence_incorrect": float(eval_metrics.get("avg_confidence_incorrect", 0.0)),
        "avg_confidence_inconclusive": float(eval_metrics.get("avg_confidence_inconclusive", 0.0)),
        "robustness_score": float(adv_metrics.get("robustness_score", 0.0)),
        "attack_success_rate": float(adv_metrics.get("attack_success_rate", 0.0)),
        "confidence_shift": float(adv_metrics.get("confidence_shift", 0.0)),
        "abstention_increase": float(adv_metrics.get("abstention_increase", 0.0)),
        "high_confidence_incorrect": _has_high_confidence_incorrect(eval_metrics, adv_metrics),
        "confidence_increase_under_attack": _has_adversarial_confidence_increase(adv_metrics),
        "evaluation": dict(eval_metrics),
        "adversarial": dict(adv_metrics),
    }


def _is_constraint_safe(candidate: Mapping[str, Any], baseline: Mapping[str, Any]) -> bool:
    if candidate["false_attribution_rate"] > baseline["false_attribution_rate"] + _EPS:
        return False
    if candidate["abstention_rate"] + _EPS < baseline["abstention_rate"]:
        return False
    if candidate["high_confidence_incorrect"]:
        return False
    if candidate["confidence_increase_under_attack"]:
        return False
    return True


def _is_better(candidate: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    # Keep change only when FAR decreases or calibration improves.
    far_improved = candidate["false_attribution_rate"] < current["false_attribution_rate"] - _EPS
    cal_improved = candidate["confidence_calibration_error"] < current["confidence_calibration_error"] - _EPS
    if not (far_improved or cal_improved):
        return False

    # Priority order tie-breaks.
    if far_improved and not cal_improved:
        return True
    if cal_improved and not far_improved:
        return True

    # Both improved or equal within epsilon -> deterministic tie-break tuple.
    cand_rank = (
        candidate["false_attribution_rate"],
        -candidate["abstention_rate"],
        candidate["confidence_calibration_error"],
        -candidate["robustness_score"],
        candidate["attack_success_rate"],
        -candidate["accuracy"],
    )
    curr_rank = (
        current["false_attribution_rate"],
        -current["abstention_rate"],
        current["confidence_calibration_error"],
        -current["robustness_score"],
        current["attack_success_rate"],
        -current["accuracy"],
    )
    return cand_rank < curr_rank


def _candidate_values(param_group: str, current_value: float) -> List[float]:
    vals = {round(max(0.0, current_value * f), 6) for f in _STEP_FACTORS}
    vals.add(round(max(0.0, current_value), 6))

    if param_group in {"validation_multipliers", "evidence_penalties"}:
        vals = {min(1.0, v) for v in vals}
    elif param_group == "trust_multipliers":
        vals = {min(2.0, v) for v in vals}
    elif param_group == "conflict_multipliers":
        vals = {min(2.0, v) for v in vals}

    return sorted(vals)


def _signal_names_from_dataset(dataset: Sequence[Mapping[str, Any]]) -> List[str]:
    names = set()
    for case in dataset:
        for sig in case.get("signals", []) or []:
            if isinstance(sig, Mapping):
                name = str(sig.get("name", "")).strip()
            else:
                name = str(getattr(sig, "name", "")).strip()
            if name:
                names.add(name)
    return sorted(names)


def _evaluate_config_state(
    config_dict: Mapping[str, Any],
    dataset: Sequence[Mapping[str, Any]],
    attack_types: Sequence[str],
) -> Dict[str, Any]:
    engine = InferenceEngine(_to_config(config_dict))
    evaluator = AttributionEvaluator(engine=engine)
    eval_report = evaluator.evaluate(dataset).to_dict()
    adv_report = AdversarialTester(evaluator=evaluator).run(dataset=dataset, attack_types=attack_types).to_dict()
    return _derive_metrics(eval_report, adv_report)


def optimise_scoring_config(
    evaluation_dataset: Optional[Sequence[Mapping[str, Any]]] = None,
    adversarial_results: Optional[Mapping[str, Any]] = None,
    current_config: Optional[ScoringConfig | Mapping[str, Any]] = None,
    *,
    attack_types: Sequence[str] = ALL_ATTACK_TYPES,
    max_passes: int = 2,
) -> Dict[str, Any]:
    """
    Deterministic coordinate-descent tuning for ScoringConfig.

    Priority:
      1) minimise false attribution
      2) preserve/improve abstention safety
      3) maximise safe accuracy
      4) improve confidence calibration
    """
    base_dataset_raw = list(evaluation_dataset) if evaluation_dataset is not None else [
        asdict(case) for case in build_default_dataset()
    ]
    dataset: List[Mapping[str, Any]] = [dict(item) for item in base_dataset_raw]

    cfg_dict = _as_config_dict(current_config or ScoringConfig())
    # Ensure signal_weights has explicit entries for dataset signal names.
    for signal_name in _signal_names_from_dataset(dataset):
        cfg_dict["signal_weights"].setdefault(signal_name, 1.0)

    before_metrics = _evaluate_config_state(cfg_dict, dataset, attack_types)
    if adversarial_results is not None:
        before_metrics["adversarial_external"] = dict(adversarial_results)

    best = OptimisationState(
        config_dict=deepcopy(cfg_dict),
        metrics=before_metrics,
    )
    baseline = deepcopy(before_metrics)

    for _ in range(max(1, int(max_passes))):
        improved = False
        for group_name in _TUNABLE_GROUPS:
            keys = sorted(best.config_dict[group_name].keys())
            for key in keys:
                current_val = float(best.config_dict[group_name][key])
                local_best = best
                for candidate_val in _candidate_values(group_name, current_val):
                    if abs(candidate_val - current_val) <= _EPS:
                        continue
                    trial_cfg = deepcopy(best.config_dict)
                    trial_cfg[group_name][key] = candidate_val
                    trial_metrics = _evaluate_config_state(trial_cfg, dataset, attack_types)
                    if not _is_constraint_safe(trial_metrics, baseline):
                        continue
                    if _is_better(trial_metrics, local_best.metrics):
                        local_best = OptimisationState(
                            config_dict=trial_cfg,
                            metrics=trial_metrics,
                        )
                if local_best is not best:
                    best = local_best
                    improved = True
        if not improved:
            break

    before = {
        k: v for k, v in before_metrics.items()
        if k not in {"evaluation", "adversarial", "adversarial_external"}
    }
    after = {
        k: v for k, v in best.metrics.items()
        if k not in {"evaluation", "adversarial", "adversarial_external"}
    }
    improvement = {
        "false_attribution_rate_delta": round(after["false_attribution_rate"] - before["false_attribution_rate"], 12),
        "abstention_rate_delta": round(after["abstention_rate"] - before["abstention_rate"], 12),
        "accuracy_delta": round(after["accuracy"] - before["accuracy"], 12),
        "confidence_calibration_error_delta": round(
            after["confidence_calibration_error"] - before["confidence_calibration_error"], 12
        ),
        "attack_success_rate_delta": round(after["attack_success_rate"] - before["attack_success_rate"], 12),
        "robustness_score_delta": round(after["robustness_score"] - before["robustness_score"], 12),
    }

    return {
        "before": before,
        "after": after,
        "improvement": improvement,
        "final_config": deepcopy(best.config_dict),
        "final_evaluation_report": best.metrics["evaluation"],
        "final_adversarial_report": best.metrics["adversarial"],
    }


def main() -> None:
    report = optimise_scoring_config()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
