#!/usr/bin/env python3
"""
huntertrace/attribution/adversarial_testing.py
==============================================
Phase 6B adversarial robustness testing for attribution scoring.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from huntertrace.attribution.evaluation import (
        AttributionEvaluator,
        CaseOutcome,
        EvaluationCase,
        build_default_dataset,
    )
    from huntertrace.attribution.scoring import NormalizedSignal
except ModuleNotFoundError:  # pragma: no cover - direct-script fallback
    from evaluation import (  # type: ignore
        AttributionEvaluator,
        CaseOutcome,
        EvaluationCase,
        build_default_dataset,
    )
    from scoring import NormalizedSignal  # type: ignore


ATTACK_SPOOFED_INFRASTRUCTURE = "spoofed_infrastructure"
ATTACK_MIXED_SIGNALS = "mixed_signals"
ATTACK_NOISE_INJECTION = "noise_injection"
ATTACK_SIGNAL_REMOVAL = "signal_removal"
ATTACK_TEMPORAL_EVASION = "temporal_evasion"

ALL_ATTACK_TYPES: Tuple[str, ...] = (
    ATTACK_SPOOFED_INFRASTRUCTURE,
    ATTACK_MIXED_SIGNALS,
    ATTACK_NOISE_INJECTION,
    ATTACK_SIGNAL_REMOVAL,
    ATTACK_TEMPORAL_EVASION,
)


def _normalize_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _as_case(case: EvaluationCase | Mapping[str, Any]) -> EvaluationCase:
    if isinstance(case, EvaluationCase):
        return case
    return EvaluationCase(
        case_id=str(case["case_id"]),
        signals=[
            signal if isinstance(signal, NormalizedSignal) else NormalizedSignal(
                signal_id=str(signal.get("signal_id", "")),
                name=str(signal.get("name", "")),
                group=str(signal.get("group", "identity")),
                value=signal.get("value"),
                candidate_region=_normalize_text(signal.get("candidate_region")),
                source=str(signal.get("source", "adversarial")),
                trust_label=str(signal.get("trust_label", "UNKNOWN")),
                validation_flags=tuple(signal.get("validation_flags", ()) or ()),
                anomaly_detail=_normalize_text(signal.get("anomaly_detail")),
                excluded_reason=_normalize_text(signal.get("excluded_reason")),
            )
            for signal in list(case.get("signals", []))
        ],
        true_region=_normalize_text(case.get("true_region")),
        difficulty=str(case.get("difficulty", "medium")),
        notes=str(case.get("notes", "")),
    )


def _candidate_regions(signals: Sequence[NormalizedSignal]) -> List[str]:
    regions: List[str] = []
    for signal in signals:
        region = _normalize_text(signal.candidate_region)
        if region and region not in regions:
            regions.append(region)
    return regions


def _dominant_region(base_case: EvaluationCase) -> str:
    regions = _candidate_regions(base_case.signals)
    if regions:
        return regions[0]
    if base_case.true_region:
        return base_case.true_region
    return "Region-Base"


def _decoy_region(base_case: EvaluationCase) -> str:
    base = _dominant_region(base_case)
    return f"{base}-Decoy"


def _signal_weight(signal: NormalizedSignal) -> float:
    trust = {
        "TRUSTED": 1.0,
        "PARTIALLY_TRUSTED": 0.75,
        "UNTRUSTED": 0.4,
        "UNKNOWN": 0.6,
    }.get(str(signal.trust_label), 0.6)
    val_mult = 1.0
    for flag in signal.validation_flags:
        flag_value = str(flag)
        if flag_value == "MALFORMED":
            val_mult = min(val_mult, 0.0)
        elif flag_value == "MISSING":
            val_mult = min(val_mult, 0.0)
        elif flag_value == "SUSPICIOUS":
            val_mult = min(val_mult, 0.6)
    return trust * val_mult


def _with_case_meta(
    base_case: EvaluationCase,
    signals: List[NormalizedSignal],
    attack_type: str,
    attack_note: str,
) -> EvaluationCase:
    return EvaluationCase(
        case_id=f"{base_case.case_id}__{attack_type}",
        signals=signals,
        true_region=base_case.true_region,
        difficulty=base_case.difficulty,
        notes=f"{base_case.notes} | attack={attack_type} | {attack_note}",
    )


def _spoofed_infrastructure_case(base_case: EvaluationCase) -> EvaluationCase:
    decoy = _decoy_region(base_case)
    updated: List[NormalizedSignal] = []
    for signal in base_case.signals:
        if signal.group == "infrastructure" and signal.candidate_region is not None:
            updated.append(replace(signal, candidate_region=decoy, value=f"forged-{signal.value}"))
        else:
            updated.append(signal)
    updated.append(
        NormalizedSignal(
            signal_id=f"{base_case.case_id}-adv-hop-mismatch",
            name="hop_mismatch",
            group="infrastructure",
            value="received-hop-order-mismatch",
            candidate_region=None,
            source="adversarial.spoofed_infrastructure",
            trust_label="UNTRUSTED",
            validation_flags=("SUSPICIOUS",),
            anomaly_detail="Mismatched Received chain order",
        )
    )
    updated.append(
        NormalizedSignal(
            signal_id=f"{base_case.case_id}-adv-forged-header",
            name="forged_header",
            group="identity",
            value="x-originating-ip: forged",
            candidate_region=None,
            source="adversarial.spoofed_infrastructure",
            trust_label="UNTRUSTED",
            validation_flags=("MALFORMED",),
            anomaly_detail="Forged header artifact",
        )
    )
    return _with_case_meta(
        base_case,
        updated,
        ATTACK_SPOOFED_INFRASTRUCTURE,
        "fake IP regions + mismatched hops + forged headers",
    )


def _mixed_signals_case(base_case: EvaluationCase) -> EvaluationCase:
    regions = _candidate_regions(base_case.signals)
    region_a = regions[0] if regions else _dominant_region(base_case)
    region_b = regions[1] if len(regions) > 1 else _decoy_region(base_case)

    candidate_indices = [idx for idx, s in enumerate(base_case.signals) if s.candidate_region is not None]
    updated = list(base_case.signals)
    half = len(candidate_indices) // 2
    for order, idx in enumerate(candidate_indices):
        region = region_a if order < half else region_b
        updated[idx] = replace(updated[idx], candidate_region=region)

    if not candidate_indices:
        updated.append(
            NormalizedSignal(
                signal_id=f"{base_case.case_id}-adv-mix-a",
                name="mixed_anchor_a",
                group="infrastructure",
                value="mix-a",
                candidate_region=region_a,
                source="adversarial.mixed_signals",
                trust_label="PARTIALLY_TRUSTED",
                validation_flags=("CLEAN",),
            )
        )
        updated.append(
            NormalizedSignal(
                signal_id=f"{base_case.case_id}-adv-mix-b",
                name="mixed_anchor_b",
                group="identity",
                value="mix-b",
                candidate_region=region_b,
                source="adversarial.mixed_signals",
                trust_label="PARTIALLY_TRUSTED",
                validation_flags=("CLEAN",),
            )
        )

    return _with_case_meta(
        base_case,
        updated,
        ATTACK_MIXED_SIGNALS,
        "50/50 region split",
    )


def _noise_injection_case(base_case: EvaluationCase) -> EvaluationCase:
    updated = list(base_case.signals)
    noise = [
        NormalizedSignal(
            signal_id=f"{base_case.case_id}-adv-noise-1",
            name="x_noise_blob",
            group="identity",
            value="garbled\x00header",
            candidate_region=None,
            source="adversarial.noise_injection",
            trust_label="UNKNOWN",
            validation_flags=("MALFORMED",),
            anomaly_detail="Corrupted identity header",
        ),
        NormalizedSignal(
            signal_id=f"{base_case.case_id}-adv-noise-2",
            name="body_entropy",
            group="temporal",
            value="irrelevant-stat",
            candidate_region=None,
            source="adversarial.noise_injection",
            trust_label="UNKNOWN",
            validation_flags=("SUSPICIOUS",),
            anomaly_detail="Irrelevant noisy feature",
        ),
        NormalizedSignal(
            signal_id=f"{base_case.case_id}-adv-noise-3",
            name="checksum_corruption",
            group="infrastructure",
            value="crc-mismatch",
            candidate_region=None,
            source="adversarial.noise_injection",
            trust_label="UNTRUSTED",
            validation_flags=("MALFORMED",),
            anomaly_detail="Corrupted signal payload",
        ),
    ]
    updated.extend(noise)
    return _with_case_meta(
        base_case,
        updated,
        ATTACK_NOISE_INJECTION,
        "irrelevant + malformed signal injection",
    )


def _signal_removal_case(base_case: EvaluationCase) -> EvaluationCase:
    candidate_signals = [
        s for s in base_case.signals
        if s.candidate_region is not None and (not s.excluded_reason)
    ]
    ranked = sorted(
        candidate_signals,
        key=lambda signal: (_signal_weight(signal), signal.group, signal.name),
        reverse=True,
    )
    remove_ids = {signal.signal_id for signal in ranked[:2]}
    updated = [s for s in base_case.signals if s.signal_id not in remove_ids]

    if not updated:
        updated = [
            NormalizedSignal(
                signal_id=f"{base_case.case_id}-adv-signal-removed-anchor",
                name="signal_removed_anchor",
                group="identity",
                value="anchor",
                candidate_region=None,
                source="adversarial.signal_removal",
                trust_label="UNKNOWN",
                validation_flags=("SUSPICIOUS",),
                anomaly_detail="Strongest signals removed",
            )
        ]
    else:
        updated.append(
            NormalizedSignal(
                signal_id=f"{base_case.case_id}-adv-signal-removed-note",
                name="signal_removal_marker",
                group="infrastructure",
                value="strongest-signals-removed",
                candidate_region=None,
                source="adversarial.signal_removal",
                trust_label="UNTRUSTED",
                validation_flags=("SUSPICIOUS",),
                anomaly_detail="Strong attribution anchors removed",
            )
        )

    return _with_case_meta(
        base_case,
        updated,
        ATTACK_SIGNAL_REMOVAL,
        "strongest candidate-bearing signals removed",
    )


def _temporal_evasion_case(base_case: EvaluationCase) -> EvaluationCase:
    decoy = _decoy_region(base_case)
    updated = list(base_case.signals)
    updated.extend(
        [
            NormalizedSignal(
                signal_id=f"{base_case.case_id}-adv-tz-conflict",
                name="timezone_offset",
                group="temporal",
                value="+1400",
                candidate_region=None,
                source="adversarial.temporal_evasion",
                trust_label="UNTRUSTED",
                validation_flags=("SUSPICIOUS",),
                anomaly_detail="Conflicting timezone artifact",
            ),
            NormalizedSignal(
                signal_id=f"{base_case.case_id}-adv-sendhour-conflict",
                name="send_hour_utc",
                group="temporal",
                value=29,
                candidate_region=None,
                source="adversarial.temporal_evasion",
                trust_label="UNTRUSTED",
                validation_flags=("MALFORMED",),
                anomaly_detail="Unrealistic send hour",
            ),
            NormalizedSignal(
                signal_id=f"{base_case.case_id}-adv-temporal-decoy",
                name="temporal_marker_decoy",
                group="temporal",
                value="timestamp-skew",
                candidate_region=decoy,
                source="adversarial.temporal_evasion",
                trust_label="UNTRUSTED",
                validation_flags=("SUSPICIOUS",),
                anomaly_detail="Timestamp spoofing decoy",
            ),
        ]
    )
    return _with_case_meta(
        base_case,
        updated,
        ATTACK_TEMPORAL_EVASION,
        "timezone/send-hour conflicts + unrealistic timestamps",
    )


def generate_adversarial_case(
    base_case: EvaluationCase | Mapping[str, Any],
    attack_type: str,
) -> EvaluationCase:
    """
    Attack simulation API.

    Returns a deterministic adversarial case derived from `base_case`.
    """
    case = _as_case(base_case)
    if attack_type == ATTACK_SPOOFED_INFRASTRUCTURE:
        return _spoofed_infrastructure_case(case)
    if attack_type == ATTACK_MIXED_SIGNALS:
        return _mixed_signals_case(case)
    if attack_type == ATTACK_NOISE_INJECTION:
        return _noise_injection_case(case)
    if attack_type == ATTACK_SIGNAL_REMOVAL:
        return _signal_removal_case(case)
    if attack_type == ATTACK_TEMPORAL_EVASION:
        return _temporal_evasion_case(case)
    raise ValueError(f"Unknown attack_type: {attack_type}")


@dataclass(frozen=True)
class AttackEvaluationRow:
    case_id: str
    attack_type: str
    baseline_region: Optional[str]
    attacked_region: Optional[str]
    baseline_verdict: str
    attacked_verdict: str
    baseline_confidence: float
    attacked_confidence: float
    true_region: Optional[str]
    confidence_increase: bool
    high_confidence_incorrect: bool
    incorrect_attribution: bool
    safe_output: bool
    baseline_notes: str
    attacked_notes: str


@dataclass
class AdversarialReport:
    robustness_score: float
    attack_success_rate: float
    confidence_shift: float
    abstention_increase: float
    failures: List[Dict[str, Any]]
    total_attacks: int
    safe_outputs: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AdversarialTester:
    """Apply adversarial attacks to evaluation cases and summarize robustness."""

    def __init__(
        self,
        evaluator: Optional[AttributionEvaluator] = None,
        *,
        high_confidence_threshold: float = 0.6,
        confidence_epsilon: float = 1e-12,
    ):
        self.evaluator = evaluator or AttributionEvaluator()
        self.high_confidence_threshold = float(high_confidence_threshold)
        self.confidence_epsilon = float(confidence_epsilon)

    def run(
        self,
        dataset: Optional[Sequence[EvaluationCase | Mapping[str, Any]]] = None,
        attack_types: Sequence[str] = ALL_ATTACK_TYPES,
    ) -> AdversarialReport:
        base_cases = [_as_case(case) for case in (dataset or build_default_dataset())]
        rows: List[AttackEvaluationRow] = []

        for base_case in base_cases:
            baseline_outcome = self.evaluator._evaluate_case(base_case)
            for attack_type in attack_types:
                attacked_case = generate_adversarial_case(base_case, attack_type)
                attacked_outcome = self.evaluator._evaluate_case(attacked_case)
                rows.append(self._make_row(base_case, attack_type, baseline_outcome, attacked_outcome))

        return self._build_report(rows)

    def _make_row(
        self,
        base_case: EvaluationCase,
        attack_type: str,
        baseline: CaseOutcome,
        attacked: CaseOutcome,
    ) -> AttackEvaluationRow:
        confidence_increase = attacked.confidence > (baseline.confidence + self.confidence_epsilon)
        incorrect_attribution = (
            (not attacked.is_inconclusive)
            and (base_case.true_region is not None)
            and (_normalize_text(attacked.predicted_region) != _normalize_text(base_case.true_region))
        )
        high_confidence_incorrect = (
            incorrect_attribution and attacked.confidence >= self.high_confidence_threshold
        )

        safe_output = (
            (not confidence_increase)
            and (not high_confidence_incorrect)
            and (
                attacked.is_inconclusive
                or (
                    base_case.true_region is not None
                    and _normalize_text(attacked.predicted_region) == _normalize_text(base_case.true_region)
                )
            )
        )

        return AttackEvaluationRow(
            case_id=base_case.case_id,
            attack_type=attack_type,
            baseline_region=_normalize_text(baseline.predicted_region),
            attacked_region=_normalize_text(attacked.predicted_region),
            baseline_verdict=baseline.verdict,
            attacked_verdict=attacked.verdict,
            baseline_confidence=round(baseline.confidence, 12),
            attacked_confidence=round(attacked.confidence, 12),
            true_region=_normalize_text(base_case.true_region),
            confidence_increase=confidence_increase,
            high_confidence_incorrect=high_confidence_incorrect,
            incorrect_attribution=incorrect_attribution,
            safe_output=safe_output,
            baseline_notes=base_case.notes,
            attacked_notes=f"{base_case.notes} | attack={attack_type}",
        )

    def _build_report(self, rows: Sequence[AttackEvaluationRow]) -> AdversarialReport:
        total = len(rows)
        safe = sum(1 for row in rows if row.safe_output)

        truth_rows = [row for row in rows if row.true_region is not None]
        incorrect = [row for row in truth_rows if row.incorrect_attribution]
        attack_success_rate = (len(incorrect) / len(truth_rows)) if truth_rows else 0.0

        confidence_shift = _mean([
            row.attacked_confidence - row.baseline_confidence
            for row in rows
        ])

        baseline_abstention_rate = (
            sum(1 for row in rows if row.baseline_verdict == "inconclusive") / total
            if total else 0.0
        )
        attacked_abstention_rate = (
            sum(1 for row in rows if row.attacked_verdict == "inconclusive") / total
            if total else 0.0
        )
        abstention_increase = attacked_abstention_rate - baseline_abstention_rate

        failures: List[Dict[str, Any]] = []
        for row in rows:
            reasons: List[str] = []
            if row.confidence_increase:
                reasons.append("confidence_increase_under_attack")
            if row.high_confidence_incorrect:
                reasons.append("high_confidence_incorrect_attribution")
            if reasons:
                failures.append(
                    {
                        "case_id": row.case_id,
                        "attack_type": row.attack_type,
                        "true_region": row.true_region,
                        "baseline_region": row.baseline_region,
                        "attacked_region": row.attacked_region,
                        "baseline_verdict": row.baseline_verdict,
                        "attacked_verdict": row.attacked_verdict,
                        "baseline_confidence": row.baseline_confidence,
                        "attacked_confidence": row.attacked_confidence,
                        "reasons": reasons,
                    }
                )

        return AdversarialReport(
            robustness_score=round((safe / total) if total else 0.0, 12),
            attack_success_rate=round(attack_success_rate, 12),
            confidence_shift=round(confidence_shift, 12),
            abstention_increase=round(abstention_increase, 12),
            failures=failures,
            total_attacks=total,
            safe_outputs=safe,
        )


def run_adversarial_evaluation(
    dataset: Optional[Sequence[EvaluationCase | Mapping[str, Any]]] = None,
    attack_types: Sequence[str] = ALL_ATTACK_TYPES,
) -> Dict[str, Any]:
    tester = AdversarialTester()
    report = tester.run(dataset=dataset, attack_types=attack_types)
    return report.to_dict()


def main() -> None:
    report = run_adversarial_evaluation()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

