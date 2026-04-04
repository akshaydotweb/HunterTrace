"""Correlation engine for HunterTrace Atlas normalized signals."""

from __future__ import annotations

from typing import Iterable, List, Sequence

from huntertrace.analysis.models import (
    Contradiction,
    CorrelationConfig,
    CorrelationResult,
    Relationship,
    Signal,
)
from huntertrace.analysis.rules import (
    build_derived_relationships,
    detect_anonymization,
    detect_cross_conflicts,
    evaluate_infrastructure,
    evaluate_quality,
    evaluate_structure,
    evaluate_temporal,
    group_signals,
)
from huntertrace.analysis.utils import (
    clamp01,
    normalize_signals,
    severity_penalty,
    sort_contradictions,
    sort_relationships,
)


class AtlasCorrelationEngine:
    """Deterministic, explainable signal correlation engine."""

    @staticmethod
    def correlate(signals: Sequence[Signal | dict | object], config: CorrelationConfig | None = None) -> CorrelationResult:
        cfg = config or CorrelationConfig()
        normalized = normalize_signals(signals)
        groups = group_signals(normalized)

        temporal_eval = evaluate_temporal(groups["temporal"], cfg)
        structure_eval = evaluate_structure(groups["structure"], normalized, cfg)
        infrastructure_eval = evaluate_infrastructure(groups["infrastructure"], cfg)
        quality_score = evaluate_quality(normalized)

        group_scores = {
            "temporal": round(temporal_eval.score, 4),
            "infrastructure": round(infrastructure_eval.score, 4),
            "structure": round(structure_eval.score, 4),
            "quality": round(quality_score, 4),
        }

        contradictions: List[Contradiction] = []
        contradictions.extend(temporal_eval.contradictions)
        contradictions.extend(structure_eval.contradictions)
        contradictions.extend(infrastructure_eval.contradictions)

        cross_eval = detect_cross_conflicts(groups=groups, group_scores=group_scores, contradictions=contradictions)
        contradictions.extend(cross_eval.contradictions)

        anonymization = detect_anonymization(
            groups=groups,
            signals=normalized,
            contradictions=contradictions,
            config=cfg,
        )

        relationships: List[Relationship] = []
        relationships.extend(temporal_eval.relationships)
        relationships.extend(structure_eval.relationships)
        relationships.extend(infrastructure_eval.relationships)
        relationships.extend(cross_eval.relationships)
        relationships.extend(build_derived_relationships(normalized))
        relationships.extend(_conflict_edges_from_contradictions(contradictions))

        contradictions = _dedupe_contradictions(contradictions)
        relationships = _dedupe_relationships(relationships)

        base_score = (
            (0.35 * group_scores["temporal"])
            + (0.30 * group_scores["structure"])
            + (0.20 * group_scores["infrastructure"])
            + (0.15 * group_scores["quality"])
        )
        contradiction_penalty = sum(severity_penalty(item.severity) for item in contradictions)
        consistency_score = round(clamp01(base_score - contradiction_penalty), 4)

        limitations = _build_limitations(
            contradictions=contradictions,
            quality_score=group_scores["quality"],
            anonymization_detected=anonymization.detected,
        )

        return CorrelationResult(
            consistency_score=consistency_score,
            contradictions=sort_contradictions(contradictions),
            relationships=sort_relationships(relationships),
            anonymization=anonymization,
            group_scores=group_scores,
            limitations=limitations,
        )


def _conflict_edges_from_contradictions(contradictions: Iterable[Contradiction]) -> List[Relationship]:
    relationships: List[Relationship] = []
    for contradiction in contradictions:
        signals = list(contradiction.signals)
        if len(signals) < 2:
            continue
        root = signals[0]
        for target in signals[1:]:
            relationships.append(
                Relationship(
                    type="conflicts",
                    source_signal=root,
                    target_signal=target,
                    rationale=f"Contradiction: {contradiction.reason}",
                )
            )
    return relationships


def _dedupe_contradictions(items: Sequence[Contradiction]) -> List[Contradiction]:
    seen = set()
    output: List[Contradiction] = []
    for item in items:
        key = (item.type, tuple(item.signals), item.reason, item.severity)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _dedupe_relationships(items: Sequence[Relationship]) -> List[Relationship]:
    seen = set()
    output: List[Relationship] = []
    for item in items:
        key = (item.type, item.source_signal, item.target_signal, item.rationale)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _build_limitations(
    *,
    contradictions: Sequence[Contradiction],
    quality_score: float,
    anonymization_detected: bool,
) -> List[str]:
    limitations: List[str] = []
    if any(item.type == "temporal" for item in contradictions):
        limitations.append("Temporal inconsistencies detected")
    if any(item.type == "structure" for item in contradictions):
        limitations.append("Structural anomalies present")
    if quality_score < 0.5:
        limitations.append("Low signal quality")
    if anonymization_detected:
        limitations.append("Possible anonymization patterns detected")
    return limitations

