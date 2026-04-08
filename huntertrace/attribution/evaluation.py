#!/usr/bin/env python3
"""
huntertrace/attribution/evaluation.py
=====================================
Phase 6 evaluation framework for attribution scoring.

This module provides:
- deterministic evaluation dataset format
- core DFIR-focused metrics
- confidence calibration analysis
- adversarial/noisy scenario coverage
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from huntertrace.analysis.correlation import apply_correlation_adjustment
    from huntertrace.attribution.scoring import (
        AttributionResult,
        InferenceEngine,
        NormalizedSignal,
        SignalContribution,
    )
except ModuleNotFoundError:  # pragma: no cover - direct-script fallback
    from correlation import apply_correlation_adjustment  # type: ignore
    from scoring import (  # type: ignore
        AttributionResult,
        InferenceEngine,
        NormalizedSignal,
        SignalContribution,
    )


_CALIBRATION_BUCKETS: Tuple[Tuple[float, float], ...] = (
    (0.0, 0.2),
    (0.2, 0.4),
    (0.4, 0.6),
    (0.6, 0.8),
)


def _mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _normalize_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _bucket_key(confidence: float) -> str:
    value = max(0.0, min(0.8, float(confidence)))
    for low, high in _CALIBRATION_BUCKETS:
        # Include high endpoint in final bucket.
        if (low <= value < high) or (high == 0.8 and low <= value <= high):
            return f"{low:.1f}-{high:.1f}"
    return "0.6-0.8"


def _as_signal(signal: Any) -> NormalizedSignal:
    if isinstance(signal, NormalizedSignal):
        return signal
    if not isinstance(signal, Mapping):
        raise TypeError(f"Unsupported signal type: {type(signal)!r}")
    return NormalizedSignal(
        signal_id=str(signal.get("signal_id", "")),
        name=str(signal.get("name", "")),
        group=str(signal.get("group", "identity")),
        value=signal.get("value"),
        candidate_region=_normalize_text(signal.get("candidate_region")),
        source=str(signal.get("source", "evaluation")),
        trust_label=str(signal.get("trust_label", "UNKNOWN")),
        validation_flags=tuple(signal.get("validation_flags", ()) or ()),
        anomaly_detail=_normalize_text(signal.get("anomaly_detail")),
        excluded_reason=_normalize_text(signal.get("excluded_reason")),
    )


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    signals: List[NormalizedSignal]
    true_region: Optional[str]
    difficulty: str
    notes: str


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    predicted_region: Optional[str]
    verdict: str
    confidence: float
    true_region: Optional[str]
    difficulty: str
    notes: str
    is_correct: bool
    is_inconclusive: bool
    is_false_attribution: bool
    signals_used_count: int
    signals_rejected_count: int
    limitations: Tuple[str, ...] = ()


@dataclass
class EvaluationReport:
    accuracy: float
    false_attribution_rate: float
    abstention_rate: float
    avg_confidence_correct: float
    avg_confidence_incorrect: float
    avg_confidence_inconclusive: float
    confidence_calibration: Dict[str, Dict[str, float]]
    failure_cases: List[Dict[str, Any]]
    case_count: int
    attributed_count: int
    inconclusive_count: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AttributionEvaluator:
    """Deterministic Phase 6 evaluator for attribution inference outputs."""

    def __init__(
        self,
        engine: Optional[InferenceEngine] = None,
        *,
        confidence_threshold: float = 0.35,
        tie_epsilon: float = 1e-9,
        min_supporting_signals: int = 2,
        min_contributing_groups: int = 2,
        min_winning_groups: int = 2,
    ):
        self.engine = engine or InferenceEngine()
        self.confidence_threshold = float(confidence_threshold)
        self.tie_epsilon = float(tie_epsilon)
        self.min_supporting_signals = int(min_supporting_signals)
        self.min_contributing_groups = int(min_contributing_groups)
        self.min_winning_groups = int(min_winning_groups)

    def evaluate(
        self,
        dataset: Sequence[EvaluationCase | Mapping[str, Any]],
    ) -> EvaluationReport:
        outcomes = [self._evaluate_case(self._as_case(item)) for item in dataset]

        known_truth = [o for o in outcomes if o.true_region is not None]
        attributed = [o for o in outcomes if not o.is_inconclusive]
        incorrect_attributed = [o for o in attributed if o.is_false_attribution]
        correct_attributed = [o for o in attributed if o.is_correct]
        inconclusive = [o for o in outcomes if o.is_inconclusive]

        accuracy = (
            sum(1 for o in known_truth if o.is_correct) / len(known_truth)
            if known_truth
            else 0.0
        )
        false_attribution_rate = (
            len(incorrect_attributed) / len(attributed)
            if attributed
            else 0.0
        )
        abstention_rate = len(inconclusive) / len(outcomes) if outcomes else 0.0

        calibration = self._build_calibration(outcomes)

        failure_cases = [
            {
                "case_id": o.case_id,
                "true_region": o.true_region,
                "predicted_region": o.predicted_region,
                "verdict": o.verdict,
                "confidence": round(o.confidence, 12),
                "difficulty": o.difficulty,
                "notes": o.notes,
                "limitations": list(o.limitations),
            }
            for o in outcomes
            if o.is_false_attribution
        ]

        return EvaluationReport(
            accuracy=round(accuracy, 12),
            false_attribution_rate=round(false_attribution_rate, 12),
            abstention_rate=round(abstention_rate, 12),
            avg_confidence_correct=round(_mean([o.confidence for o in correct_attributed]), 12),
            avg_confidence_incorrect=round(_mean([o.confidence for o in incorrect_attributed]), 12),
            avg_confidence_inconclusive=round(_mean([o.confidence for o in inconclusive]), 12),
            confidence_calibration=calibration,
            failure_cases=failure_cases,
            case_count=len(outcomes),
            attributed_count=len(attributed),
            inconclusive_count=len(inconclusive),
        )

    def _as_case(self, raw: EvaluationCase | Mapping[str, Any]) -> EvaluationCase:
        if isinstance(raw, EvaluationCase):
            return raw
        if not isinstance(raw, Mapping):
            raise TypeError(f"Unsupported case type: {type(raw)!r}")

        return EvaluationCase(
            case_id=str(raw["case_id"]),
            signals=[_as_signal(item) for item in list(raw.get("signals", []))],
            true_region=_normalize_text(raw.get("true_region")),
            difficulty=str(raw.get("difficulty", "medium")),
            notes=str(raw.get("notes", "")),
        )

    def _evaluate_case(self, case: EvaluationCase) -> CaseOutcome:
        result = self._run_engine(case.signals)
        predicted_region = _normalize_text(getattr(result, "region", None))
        verdict = str(getattr(result, "verdict", "inconclusive"))
        confidence = float(getattr(result, "confidence", 0.0))
        if verdict == "inconclusive":
            predicted_region = None

        is_inconclusive = verdict == "inconclusive"
        is_correct = (
            (not is_inconclusive)
            and (case.true_region is not None)
            and (predicted_region == case.true_region)
        )
        is_false = (
            (not is_inconclusive)
            and (case.true_region is not None)
            and (predicted_region != case.true_region)
        )

        return CaseOutcome(
            case_id=case.case_id,
            predicted_region=predicted_region,
            verdict=verdict,
            confidence=round(confidence, 12),
            true_region=case.true_region,
            difficulty=case.difficulty,
            notes=case.notes,
            is_correct=is_correct,
            is_inconclusive=is_inconclusive,
            is_false_attribution=is_false,
            signals_used_count=len(getattr(result, "signals_used", []) or []),
            signals_rejected_count=len(getattr(result, "signals_rejected", []) or []),
            limitations=tuple(getattr(result, "limitations", []) or ()),
        )

    def _run_engine(self, signals: Sequence[NormalizedSignal]) -> AttributionResult:
        adjustment = apply_correlation_adjustment(signals, [])
        scoring_signals = adjustment.adjusted_signals

        # Preferred path: native engine score API.
        score_fn = getattr(self.engine, "score", None)
        if callable(score_fn):
            payload = {"signals": list(scoring_signals), "anomalies": [], "validation_notes": []}
            result = score_fn(payload)
            confidence = float(getattr(result, "confidence", 0.0))
            confidence = round(max(0.0, confidence * (1.0 - adjustment.confidence_penalty)), 12)
            limitations = list(getattr(result, "limitations", []) or [])
            if adjustment.anonymization.anonymization_detected:
                limitations.append(
                    "Anonymization indicators detected: "
                    + ", ".join(adjustment.anonymization.indicators)
                )
            limitations.extend(list(adjustment.reasoning))
            if isinstance(result, AttributionResult):
                result.confidence = confidence
                result.limitations = limitations
                return result
            return AttributionResult(
                region=_normalize_text(getattr(result, "region", None)),
                confidence=confidence,
                signals_used=list(getattr(result, "signals_used", []) or []),
                signals_rejected=list(getattr(result, "signals_rejected", []) or []),
                anomalies=list(getattr(result, "anomalies", []) or []),
                limitations=limitations,
                verdict=str(getattr(result, "verdict", "inconclusive")),
            )

        # Fallback path for engines exposing candidate evaluator only.
        eval_fn = getattr(self.engine, "_evaluate_candidate", None)
        if not callable(eval_fn):
            return AttributionResult(
                region=None,
                confidence=0.0,
                signals_used=[],
                signals_rejected=[],
                anomalies=[],
                limitations=["Engine does not expose score or _evaluate_candidate."],
                verdict="inconclusive",
            )

        candidates = sorted({
            _normalize_text(s.candidate_region)
            for s in scoring_signals
            if _normalize_text(s.candidate_region) is not None
        })
        if not candidates:
            return AttributionResult(
                region=None,
                confidence=0.0,
                signals_used=[],
                signals_rejected=self._rejected_for_fallback(scoring_signals),
                anomalies=[],
                limitations=["No candidate regions available from upstream signals."],
                verdict="inconclusive",
            )

        evaluations = [eval_fn(c, scoring_signals, []) for c in candidates]
        evaluations.sort(
            key=lambda item: (-float(item.confidence), -float(item.weighted_score), str(item.candidate))
        )
        best = evaluations[0]
        top = [
            e for e in evaluations
            if abs(float(e.confidence) - float(best.confidence)) <= self.tie_epsilon
        ]

        winner_support = list(getattr(best, "supporting_signals", ()) or ())
        winner_groups = {
            str(getattr(sig, "group", ""))
            for sig in winner_support
            if str(getattr(sig, "group", ""))
        }
        contributing_groups = {
            str(s.group)
            for s in scoring_signals
            if (s.candidate_region is not None)
            and (self.engine._resolve_base_weight(s) > 0)
            and (self.engine._resolve_validation_multiplier(s) > 0)
            and (not s.excluded_reason)
        }

        verdict = "attributed"
        region = str(getattr(best, "candidate"))
        limitations: List[str] = []

        if len(top) > 1:
            verdict = "inconclusive"
            region = None
            limitations.append("Tie between top candidates.")

        confidence = float(getattr(best, "confidence", 0.0))
        confidence = round(max(0.0, confidence * (1.0 - adjustment.confidence_penalty)), 12)
        if confidence < self.confidence_threshold:
            verdict = "inconclusive"
            region = None
            limitations.append(
                f"Confidence {confidence:.12f} below threshold {self.confidence_threshold:.12f}."
            )

        if len(winner_support) < self.min_supporting_signals:
            verdict = "inconclusive"
            region = None
            limitations.append(
                f"Supporting signals {len(winner_support)} below minimum {self.min_supporting_signals}."
            )

        if len(contributing_groups) < self.min_contributing_groups:
            verdict = "inconclusive"
            region = None
            limitations.append(
                f"Contributing groups {len(contributing_groups)} below minimum {self.min_contributing_groups}."
            )

        if len(winner_groups) < self.min_winning_groups:
            verdict = "inconclusive"
            region = None
            limitations.append(
                f"Winning groups {len(winner_groups)} below minimum {self.min_winning_groups}."
            )
        if adjustment.anonymization.confidence >= 0.70:
            verdict = "inconclusive"
            region = None
            limitations.append(
                f"High anonymization confidence ({adjustment.anonymization.confidence:.12f}) forces abstention."
            )
        limitations.extend(list(adjustment.reasoning))

        signals_used = [
            asdict(entry)
            for entry in (list(getattr(best, "supporting_signals", ()) or [])
                          + list(getattr(best, "conflicting_signals", ()) or []))
        ]

        anomalies = []
        if getattr(best, "conflicting_signals", ()):
            anomalies.append(
                {
                    "type": "scoring_conflict",
                    "candidate": str(getattr(best, "candidate")),
                    "penalty_score": float(getattr(best, "penalty_score", 0.0)),
                }
            )

        return AttributionResult(
            region=region,
            confidence=confidence,
            signals_used=signals_used,
            signals_rejected=self._rejected_for_fallback(scoring_signals),
            anomalies=anomalies,
            limitations=limitations,
            verdict=verdict,
        )

    def _rejected_for_fallback(self, signals: Sequence[NormalizedSignal]) -> List[Dict[str, Any]]:
        rejected = []
        for signal in signals:
            if signal.candidate_region is None:
                rejected.append(
                    {
                        "signal_id": signal.signal_id,
                        "name": signal.name,
                        "group": signal.group,
                        "reason": "non_attributable",
                    }
                )
        rejected.sort(key=lambda item: (item["name"], item["signal_id"]))
        return rejected

    def _build_calibration(self, outcomes: Sequence[CaseOutcome]) -> Dict[str, Dict[str, float]]:
        bucket_rows: Dict[str, List[CaseOutcome]] = {}
        for low, high in _CALIBRATION_BUCKETS:
            bucket_rows[f"{low:.1f}-{high:.1f}"] = []

        for outcome in outcomes:
            bucket_rows[_bucket_key(outcome.confidence)].append(outcome)

        result: Dict[str, Dict[str, float]] = {}
        for bucket, rows in bucket_rows.items():
            truth_rows = [r for r in rows if r.true_region is not None]
            attributed_truth_rows = [r for r in truth_rows if not r.is_inconclusive]
            if attributed_truth_rows:
                empirical = sum(1 for r in attributed_truth_rows if r.is_correct) / len(attributed_truth_rows)
            else:
                empirical = 0.0

            result[bucket] = {
                "count": float(len(rows)),
                "attributed_count": float(sum(1 for r in rows if not r.is_inconclusive)),
                "mean_predicted_confidence": round(_mean([r.confidence for r in rows]), 12),
                "empirical_correctness": round(empirical, 12),
            }

        return result


def _signal(
    signal_id: str,
    name: str,
    group: str,
    candidate_region: Optional[str],
    *,
    value: Any = None,
    trust_label: str = "TRUSTED",
    validation_flags: Tuple[str, ...] = ("CLEAN",),
    excluded_reason: Optional[str] = None,
) -> NormalizedSignal:
    return NormalizedSignal(
        signal_id=signal_id,
        name=name,
        group=group,
        value=value if value is not None else name,
        candidate_region=candidate_region,
        source="phase6.dataset",
        trust_label=trust_label,
        validation_flags=validation_flags,
        excluded_reason=excluded_reason,
    )


def build_default_dataset() -> List[EvaluationCase]:
    """
    Build deterministic Phase 6 scenario set.

    Required scenarios:
    - single strong signal -> inconclusive
    - conflicting signals -> inconclusive
    - aligned signals -> correct attribution
    - noisy signals -> low confidence
    - adversarial signals -> inconclusive
    """
    return [
        EvaluationCase(
            case_id="case_single_strong_signal",
            signals=[
                _signal("s1", "real_ip_country", "infrastructure", "Region-A", value="ip-1"),
                _signal("s2", "timezone_offset", "temporal", None, value="+0530"),
            ],
            true_region="Region-A",
            difficulty="easy",
            notes="single strong signal -> must be inconclusive",
        ),
        EvaluationCase(
            case_id="case_conflicting_signals",
            signals=[
                _signal("s1", "real_ip_country", "infrastructure", "Region-A", value="ip-a"),
                _signal("s2", "isp_country", "infrastructure", "Region-B", value="asn-b"),
                _signal("s3", "timezone_offset", "temporal", None, value="+0000"),
            ],
            true_region=None,
            difficulty="hard",
            notes="conflicting candidate evidence -> inconclusive",
        ),
        EvaluationCase(
            case_id="case_aligned_signals",
            signals=[
                _signal("s1", "real_ip_country", "infrastructure", "Region-C", value="ip-c"),
                _signal("s2", "identity_claim", "identity", "Region-C", value="id-c"),
                _signal("s3", "temporal_marker", "temporal", "Region-C", value="tm-c"),
            ],
            true_region="Region-C",
            difficulty="easy",
            notes="aligned evidence should attribute correctly",
        ),
        EvaluationCase(
            case_id="case_noisy_signals",
            signals=[
                _signal("s1", "real_ip_country", "infrastructure", "Region-D", value="ip-d", trust_label="UNKNOWN"),
                _signal("s2", "x_mailer", "identity", None, value="unknown-client"),
                _signal("s3", "timezone_offset", "temporal", None, value="+0400"),
                _signal("s4", "hop_count", "infrastructure", None, value=12),
            ],
            true_region="Region-D",
            difficulty="medium",
            notes="noisy signal mix should keep confidence low",
        ),
        EvaluationCase(
            case_id="case_adversarial_spoofed",
            signals=[
                _signal("s1", "real_ip_country", "infrastructure", "Region-E", value="ip-e"),
                _signal("s2", "dkim_domain", "identity", None, value="spoofed.example", validation_flags=("MALFORMED",)),
                _signal("s3", "timezone_offset", "temporal", None, value="-0300"),
                _signal("s4", "isp_country", "infrastructure", "Region-F", value="asn-f"),
            ],
            true_region=None,
            difficulty="hard",
            notes="adversarial spoofing and contradictions should abstain",
        ),
    ]


def evaluate_default_dataset(engine: Optional[InferenceEngine] = None) -> Dict[str, Any]:
    evaluator = AttributionEvaluator(engine=engine)
    report = evaluator.evaluate(build_default_dataset())
    return report.to_dict()


def main() -> None:
    report = evaluate_default_dataset()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
