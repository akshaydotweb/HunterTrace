#!/usr/bin/env python3
"""
Comparative evaluation for baseline vs correlation-enhanced attribution.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from huntertrace.atlas.provenance import derive_provenance
    from huntertrace.analysis.correlation import apply_correlation_adjustment
    from huntertrace.attribution.adversarial_testing import (
        ALL_ATTACK_TYPES,
        generate_adversarial_case,
    )
    from huntertrace.attribution.config_loader import load_runtime_config
    from huntertrace.attribution.evaluation import EvaluationCase, build_default_dataset
    from huntertrace.attribution.scoring import InferenceEngine, NormalizedSignal
except ModuleNotFoundError:  # pragma: no cover
    from correlation import apply_correlation_adjustment  # type: ignore
    from adversarial_testing import ALL_ATTACK_TYPES, generate_adversarial_case  # type: ignore
    from config_loader import load_runtime_config  # type: ignore
    from evaluation import EvaluationCase, build_default_dataset  # type: ignore
    from scoring import InferenceEngine, NormalizedSignal  # type: ignore

    class _FallbackProv:
        value = "sender_controlled"

    def derive_provenance(*_args, **_kwargs):  # type: ignore
        return None, _FallbackProv(), 0.2


_EPS = 1e-12


def _normalize_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _as_signal(signal: Any) -> NormalizedSignal:
    if isinstance(signal, NormalizedSignal):
        return signal
    if not isinstance(signal, Mapping):
        raise TypeError(f"Unsupported signal type: {type(signal)!r}")
    source_hint = str(signal.get("source") or signal.get("source_field") or "")
    source_header = signal.get("source_header")
    provenance_class = signal.get("provenance_class")
    trust_weight_base = signal.get("trust_weight_base")
    if not provenance_class or trust_weight_base is None:
        header, provenance, derived_weight = derive_provenance(
            signal_name=str(signal.get("name", "")),
            source_hint=source_hint,
            hop_index=signal.get("hop_index") if isinstance(signal.get("hop_index"), int) else None,
        )
        if not source_header:
            source_header = header
        if not provenance_class:
            provenance_class = provenance.value
        if trust_weight_base is None:
            trust_weight_base = derived_weight
    return NormalizedSignal(
        signal_id=str(signal.get("signal_id", "")),
        name=str(signal.get("name", "")),
        group=str(signal.get("group", "identity")),
        value=signal.get("value"),
        candidate_region=_normalize_text(signal.get("candidate_region")),
        source=str(signal.get("source", "comparative_eval")),
        source_header=source_header,
        trust_label=str(signal.get("trust_label", "UNKNOWN")),
        validation_flags=tuple(signal.get("validation_flags", ()) or ()),
        anomaly_detail=_normalize_text(signal.get("anomaly_detail")),
        excluded_reason=_normalize_text(signal.get("excluded_reason")),
        provenance_class=str(provenance_class or "sender_controlled"),
        trust_weight_base=float(trust_weight_base) if trust_weight_base is not None else 0.2,
        confidence=float(signal.get("confidence", 1.0)),
    )


def _as_case(raw: EvaluationCase | Mapping[str, Any]) -> EvaluationCase:
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


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    verdict: str
    predicted_region: Optional[str]
    confidence: float
    true_region: Optional[str]
    is_correct: bool
    is_false_attribution: bool
    is_inconclusive: bool
    limitations: Tuple[str, ...]
    changed_by_correlation: bool = False
    confidence_dropped: bool = False
    switched_to_inconclusive: bool = False


class ComparativeEvaluator:
    def __init__(
        self,
        *,
        config_path: str = "config/scoring.yaml",
        overrides: Optional[Sequence[str]] = None,
    ):
        self.runtime = load_runtime_config(config_path, overrides=overrides)
        self.engine = InferenceEngine(config=self.runtime.scoring)
        self.confidence_threshold = float(self.runtime.inference.get("confidence_threshold", 0.35))
        self.tie_epsilon = float(self.runtime.inference.get("tie_epsilon", 1e-9))
        self.min_supporting = int(self.runtime.inference.get("min_supporting_signals", 2))
        self.min_contributing_groups = int(self.runtime.inference.get("min_contributing_groups", 2))
        self.min_winning_groups = int(self.runtime.inference.get("min_distinct_supporting_groups", 2))

    def _evaluate_case(self, case: EvaluationCase, *, use_correlation: bool) -> CaseResult:
        signals: Sequence[NormalizedSignal] = case.signals
        confidence_penalty = 0.0
        anonymization_confidence = 0.0
        reasoning: List[str] = []

        if use_correlation:
            adjustment = apply_correlation_adjustment(case.signals, [])
            signals = adjustment.adjusted_signals
            confidence_penalty = float(adjustment.confidence_penalty)
            anonymization_confidence = float(adjustment.anonymization.confidence)
            reasoning.extend(list(adjustment.reasoning))

        candidates = sorted({
            _normalize_text(s.candidate_region)
            for s in signals
            if _normalize_text(s.candidate_region) is not None
        })
        if not candidates:
            return CaseResult(
                case_id=case.case_id,
                verdict="inconclusive",
                predicted_region=None,
                confidence=0.0,
                true_region=case.true_region,
                is_correct=False,
                is_false_attribution=False,
                is_inconclusive=True,
                limitations=("No candidate regions available.",),
            )

        evaluations = [self.engine._evaluate_candidate(candidate, signals, []) for candidate in candidates]
        evaluations.sort(
            key=lambda item: (-float(item.confidence), -float(item.weighted_score), str(item.candidate))
        )
        best = evaluations[0]

        raw_confidence = float(best.confidence)
        confidence = raw_confidence * (1.0 - confidence_penalty)
        confidence = round(max(0.0, confidence), 12)

        ties = [
            item for item in evaluations
            if abs(float(item.confidence) - raw_confidence) <= self.tie_epsilon
        ]

        support_rows = list(best.supporting_signals)
        support_groups = {row.group for row in support_rows}
        contributing_groups = {
            s.group
            for s in signals
            if s.candidate_region is not None
            and self.engine._resolve_base_weight(s) > 0
            and self.engine._resolve_validation_multiplier(s) > 0
            and (not s.excluded_reason)
        }

        verdict = "attributed"
        predicted = str(best.candidate)
        limitations: List[str] = []

        if len(ties) > 1:
            verdict = "inconclusive"
            predicted = None
            limitations.append("Tie between top candidates.")
        if confidence < self.confidence_threshold:
            verdict = "inconclusive"
            predicted = None
            limitations.append("Confidence below threshold.")
        if len(support_rows) < self.min_supporting:
            verdict = "inconclusive"
            predicted = None
            limitations.append("Insufficient supporting signals.")
        if len(contributing_groups) < self.min_contributing_groups:
            verdict = "inconclusive"
            predicted = None
            limitations.append("Insufficient contributing groups.")
        if len(support_groups) < self.min_winning_groups:
            verdict = "inconclusive"
            predicted = None
            limitations.append("Insufficient distinct winning groups.")
        if use_correlation and anonymization_confidence >= 0.70:
            verdict = "inconclusive"
            predicted = None
            limitations.append("High anonymization confidence.")

        limitations.extend(reasoning)

        is_inconclusive = verdict == "inconclusive"
        is_correct = (
            (not is_inconclusive)
            and (case.true_region is not None)
            and (_normalize_text(predicted) == _normalize_text(case.true_region))
        )
        is_false_attribution = (
            (not is_inconclusive)
            and (case.true_region is not None)
            and (_normalize_text(predicted) != _normalize_text(case.true_region))
        )

        return CaseResult(
            case_id=case.case_id,
            verdict=verdict,
            predicted_region=_normalize_text(predicted),
            confidence=confidence,
            true_region=case.true_region,
            is_correct=is_correct,
            is_false_attribution=is_false_attribution,
            is_inconclusive=is_inconclusive,
            limitations=tuple(limitations),
        )

    def _metrics(self, outcomes: Sequence[CaseResult]) -> Dict[str, float]:
        known_truth = [o for o in outcomes if o.true_region is not None]
        attributed = [o for o in outcomes if not o.is_inconclusive]
        incorrect = [o for o in attributed if o.is_false_attribution]
        correct = [o for o in attributed if o.is_correct]

        accuracy = (
            sum(1 for o in known_truth if o.is_correct) / len(known_truth)
            if known_truth
            else 0.0
        )
        false_attribution_rate = (
            len(incorrect) / len(attributed)
            if attributed
            else 0.0
        )
        abstention_rate = (
            sum(1 for o in outcomes if o.is_inconclusive) / len(outcomes)
            if outcomes
            else 0.0
        )

        return {
            "accuracy": round(accuracy, 12),
            "false_attribution_rate": round(false_attribution_rate, 12),
            "abstention_rate": round(abstention_rate, 12),
            "avg_confidence_correct": round(_mean([o.confidence for o in correct]), 12),
            "avg_confidence_incorrect": round(_mean([o.confidence for o in incorrect]), 12),
            "avg_confidence_all": round(_mean([o.confidence for o in outcomes]), 12),
        }

    def _expand_cases(
        self,
        dataset: Optional[Sequence[EvaluationCase | Mapping[str, Any]]] = None,
        *,
        include_adversarial: bool = True,
    ) -> List[EvaluationCase]:
        base_cases = [_as_case(item) for item in (dataset or build_default_dataset())]
        all_cases: List[EvaluationCase] = list(base_cases)

        if include_adversarial:
            for case in base_cases:
                for attack_type in ALL_ATTACK_TYPES:
                    all_cases.append(generate_adversarial_case(case, attack_type))

        all_cases.sort(key=lambda item: item.case_id)
        return all_cases

    def compare(
        self,
        dataset: Optional[Sequence[EvaluationCase | Mapping[str, Any]]] = None,
        *,
        include_adversarial: bool = True,
    ) -> Dict[str, Any]:
        cases = self._expand_cases(dataset, include_adversarial=include_adversarial)

        baseline_rows = [self._evaluate_case(case, use_correlation=False) for case in cases]
        correlation_rows = [self._evaluate_case(case, use_correlation=True) for case in cases]

        baseline_by_id = {row.case_id: row for row in baseline_rows}
        correlation_by_id = {row.case_id: row for row in correlation_rows}

        changed_outcome_cases: List[Dict[str, Any]] = []
        confidence_dropped_cases: List[Dict[str, Any]] = []
        switched_to_inconclusive_cases: List[Dict[str, Any]] = []
        improved_cases: List[Dict[str, Any]] = []
        regressions: List[Dict[str, Any]] = []

        for case in cases:
            baseline = baseline_by_id[case.case_id]
            correlation = correlation_by_id[case.case_id]

            changed = (
                baseline.verdict != correlation.verdict
                or baseline.predicted_region != correlation.predicted_region
            )
            dropped = correlation.confidence + _EPS < baseline.confidence
            switched = (
                baseline.verdict != "inconclusive"
                and correlation.verdict == "inconclusive"
            )

            row = {
                "case_id": case.case_id,
                "difficulty": case.difficulty,
                "true_region": case.true_region,
                "baseline_verdict": baseline.verdict,
                "correlation_verdict": correlation.verdict,
                "baseline_region": baseline.predicted_region,
                "correlation_region": correlation.predicted_region,
                "baseline_confidence": baseline.confidence,
                "correlation_confidence": correlation.confidence,
            }

            if changed:
                changed_outcome_cases.append(row)
            if dropped:
                confidence_dropped_cases.append(row)
            if switched:
                switched_to_inconclusive_cases.append(row)

            improved = False
            if baseline.is_false_attribution and not correlation.is_false_attribution:
                improved = True
            elif baseline.is_inconclusive and correlation.is_correct:
                improved = True
            elif baseline.is_false_attribution and correlation.is_inconclusive:
                improved = True

            regressed = False
            if baseline.is_correct and correlation.is_false_attribution:
                regressed = True
            elif baseline.is_correct and correlation.is_inconclusive:
                regressed = True
            elif baseline.is_inconclusive and correlation.is_false_attribution:
                regressed = True
            elif baseline.is_false_attribution and correlation.is_false_attribution and correlation.confidence > baseline.confidence + _EPS:
                regressed = True

            if improved:
                improved_cases.append({**row, "reason": "safer_or_more_correct_outcome"})
            if regressed:
                regressions.append({**row, "reason": "lost_correctness_or_higher_risk"})

        baseline_metrics = self._metrics(baseline_rows)
        correlation_metrics = self._metrics(correlation_rows)

        delta = {
            "false_attribution_reduction": round(
                baseline_metrics["false_attribution_rate"] - correlation_metrics["false_attribution_rate"], 12
            ),
            "abstention_shift": round(
                correlation_metrics["abstention_rate"] - baseline_metrics["abstention_rate"], 12
            ),
            "confidence_delta": round(
                correlation_metrics["avg_confidence_all"] - baseline_metrics["avg_confidence_all"], 12
            ),
            "changed_outcome_count": float(len(changed_outcome_cases)),
            "confidence_dropped_count": float(len(confidence_dropped_cases)),
            "switched_to_inconclusive_count": float(len(switched_to_inconclusive_cases)),
            "dataset_size": float(len(cases)),
        }

        changed_outcome_cases.sort(key=lambda row: row["case_id"])
        confidence_dropped_cases.sort(key=lambda row: row["case_id"])
        switched_to_inconclusive_cases.sort(key=lambda row: row["case_id"])
        improved_cases.sort(key=lambda row: row["case_id"])
        regressions.sort(key=lambda row: row["case_id"])

        return {
            "baseline": baseline_metrics,
            "correlation": correlation_metrics,
            "delta": delta,
            "changed_outcome_cases": changed_outcome_cases,
            "confidence_dropped_cases": confidence_dropped_cases,
            "switched_to_inconclusive_cases": switched_to_inconclusive_cases,
            "improved_cases": improved_cases,
            "regressions": regressions,
        }


def _load_dataset(path: Optional[str]) -> Optional[List[Mapping[str, Any]]]:
    if not path:
        return None
    raw = json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw
    if isinstance(raw, Mapping) and isinstance(raw.get("cases"), list):
        return list(raw["cases"])
    raise ValueError("Dataset must be list or object with 'cases'.")


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="comparative_evaluation",
        description="Run baseline vs correlation-enabled attribution evaluation.",
    )
    parser.add_argument("--dataset", help="Optional dataset JSON path.")
    parser.add_argument("--config", default="config/scoring.yaml")
    parser.add_argument("--set", action="append", default=[], help="Config override key.path=value")
    parser.add_argument("--no-adversarial", action="store_true", help="Disable adversarial expansion.")
    parser.add_argument("--output", help="Optional output JSON path.")
    args = parser.parse_args(argv)

    dataset = _load_dataset(args.dataset)
    evaluator = ComparativeEvaluator(config_path=args.config, overrides=args.set)
    report = evaluator.compare(
        dataset=dataset,
        include_adversarial=not args.no_adversarial,
    )

    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload, encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
