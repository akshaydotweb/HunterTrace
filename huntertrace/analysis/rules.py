"""Deterministic correlation rule implementations for Atlas."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from statistics import mean
from typing import Dict, Iterable, List, Sequence, Tuple

from huntertrace.analysis.models import (
    AnonymizationResult,
    Contradiction,
    CorrelationConfig,
    Relationship,
    Signal,
)
from huntertrace.analysis.utils import (
    anomaly_tokens,
    base_domain,
    clamp01,
    host_related,
    is_private_ip,
    normalize_to_list,
    parse_datetime,
    parse_hop_index,
    sort_signals,
)

_HOST_TOKEN_RE = re.compile(r"^[A-Za-z0-9.-]+$")


@dataclass
class DomainEvaluation:
    """Container for domain-specific scoring and explainability artifacts."""

    score: float
    contradictions: List[Contradiction] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    metadata: Dict[str, float] = field(default_factory=dict)


def group_signals(signals: Sequence[Signal]) -> Dict[str, List[Signal]]:
    """Group normalized signals into temporal/infrastructure/structure/quality domains."""

    grouped: Dict[str, List[Signal]] = {
        "temporal": [],
        "infrastructure": [],
        "structure": [],
        "quality": [],
    }

    for signal in sort_signals(signals):
        name = signal.name.lower()
        if name.startswith("hop_timestamp") or name.startswith("temporal."):
            grouped["temporal"].append(signal)
        if name in {"hop_from_ip", "hop_from_host", "hop_by_host"} or name.startswith(
            "infrastructure."
        ):
            grouped["infrastructure"].append(signal)
        if name in {"anomaly_types", "chain_anomaly_count", "hop_count"} or name.startswith(
            "structure."
        ):
            grouped["structure"].append(signal)
        if "completeness" in name or "reliability" in name or name.startswith("quality."):
            grouped["quality"].append(signal)

        if name == "anomaly_types":
            tokens = {item.upper() for item in normalize_to_list(signal.value)}
            if tokens.intersection({"INVALID_TIMESTAMP", "TEMPORAL_ANOMALY"}):
                grouped["temporal"].append(signal)
            if tokens.intersection({"BROKEN_CHAIN", "POSSIBLE_INJECTION", "MALFORMED_HEADER"}):
                grouped["structure"].append(signal)

    for key, items in grouped.items():
        grouped[key] = sort_signals(items)
    return grouped


def evaluate_temporal(signals: Sequence[Signal], config: CorrelationConfig) -> DomainEvaluation:
    """Evaluate timestamp ordering and delta plausibility."""

    timestamps = [
        signal
        for signal in sort_signals(signals)
        if signal.name in {"hop_timestamp_utc", "temporal.timestamp"}
    ]

    contradictions: List[Contradiction] = []
    relationships: List[Relationship] = []
    score = 1.0

    for idx in range(len(timestamps) - 1):
        left = timestamps[idx]
        right = timestamps[idx + 1]
        left_ts = parse_datetime(left.value)
        right_ts = parse_datetime(right.value)

        if left_ts is None or right_ts is None:
            contradictions.append(
                Contradiction(
                    type="temporal",
                    signals=[left.signal_id, right.signal_id],
                    reason="Unparseable timestamp value prevents strict temporal ordering.",
                    severity="medium",
                )
            )
            relationships.append(
                Relationship(
                    type="conflicts",
                    source_signal=left.signal_id,
                    target_signal=right.signal_id,
                    rationale="Timestamp parsing failed for at least one adjacent hop.",
                )
            )
            score -= 0.10
            continue

        delta = (right_ts - left_ts).total_seconds()
        if delta < 0:
            contradictions.append(
                Contradiction(
                    type="temporal",
                    signals=[left.signal_id, right.signal_id],
                    reason="Negative inter-hop timestamp delta indicates impossible ordering.",
                    severity="high",
                )
            )
            relationships.append(
                Relationship(
                    type="conflicts",
                    source_signal=left.signal_id,
                    target_signal=right.signal_id,
                    rationale="Later hop has an earlier timestamp than the preceding hop.",
                )
            )
            score -= 0.20
        elif delta == 0:
            contradictions.append(
                Contradiction(
                    type="temporal",
                    signals=[left.signal_id, right.signal_id],
                    reason="Identical adjacent hop timestamps indicate temporal anomaly.",
                    severity="medium",
                )
            )
            relationships.append(
                Relationship(
                    type="conflicts",
                    source_signal=left.signal_id,
                    target_signal=right.signal_id,
                    rationale="Adjacent hops share the exact same timestamp.",
                )
            )
            score -= 0.10
        elif delta > config.temporal_large_delta_minutes * 60:
            severity = "medium" if delta > config.temporal_large_delta_minutes * 120 else "low"
            contradictions.append(
                Contradiction(
                    type="temporal",
                    signals=[left.signal_id, right.signal_id],
                    reason=(
                        "Large inter-hop timestamp gap exceeds configured threshold "
                        f"({config.temporal_large_delta_minutes} minutes)."
                    ),
                    severity=severity,
                )
            )
            relationships.append(
                Relationship(
                    type="conflicts",
                    source_signal=left.signal_id,
                    target_signal=right.signal_id,
                    rationale="Inter-hop delay exceeds expected relay progression window.",
                )
            )
            score -= 0.10 if severity == "medium" else 0.05
        else:
            relationships.append(
                Relationship(
                    type="supports",
                    source_signal=left.signal_id,
                    target_signal=right.signal_id,
                    rationale="Adjacent hop timestamps increase monotonically.",
                )
            )

    tokens = {token.upper() for token in anomaly_tokens(signals)}
    if "INVALID_TIMESTAMP" in tokens and not any(
        "impossible ordering" in item.reason.lower() for item in contradictions
    ):
        contradictions.append(
            Contradiction(
                type="temporal",
                signals=[signal.signal_id for signal in signals if signal.name == "anomaly_types"],
                reason="Signal layer flagged INVALID_TIMESTAMP anomaly.",
                severity="high",
            )
        )
        score -= 0.15
    if "TEMPORAL_ANOMALY" in tokens and not any(
        "temporal anomaly" in item.reason.lower() for item in contradictions
    ):
        contradictions.append(
            Contradiction(
                type="temporal",
                signals=[signal.signal_id for signal in signals if signal.name == "anomaly_types"],
                reason="Signal layer flagged TEMPORAL_ANOMALY.",
                severity="medium",
            )
        )
        score -= 0.10

    return DomainEvaluation(score=clamp01(score), contradictions=contradictions, relationships=relationships)


def evaluate_structure(
    structure_signals: Sequence[Signal], all_signals: Sequence[Signal], config: CorrelationConfig
) -> DomainEvaluation:
    """Evaluate hop-chain integrity and structural anomaly signals."""

    del config  # Reserved for future structure-specific threshold tuning.

    contradictions: List[Contradiction] = []
    relationships: List[Relationship] = []
    score = 1.0

    tokens = {token.upper() for token in anomaly_tokens(structure_signals)}
    anomaly_signal_ids = [signal.signal_id for signal in structure_signals if signal.name == "anomaly_types"]

    if "BROKEN_CHAIN" in tokens:
        contradictions.append(
            Contradiction(
                type="structure",
                signals=anomaly_signal_ids,
                reason="BROKEN_CHAIN detected from upstream structural validation.",
                severity="high",
            )
        )
        score -= 0.30
    if "POSSIBLE_INJECTION" in tokens:
        contradictions.append(
            Contradiction(
                type="structure",
                signals=anomaly_signal_ids,
                reason="POSSIBLE_INJECTION indicates duplicate/repeated suspicious hop patterns.",
                severity="high",
            )
        )
        score -= 0.25
    if "MALFORMED_HEADER" in tokens:
        contradictions.append(
            Contradiction(
                type="structure",
                signals=anomaly_signal_ids,
                reason="MALFORMED_HEADER anomaly token present in structural evidence.",
                severity="medium",
            )
        )
        score -= 0.10

    hosts_by_signal = [
        signal
        for signal in all_signals
        if signal.name in {"hop_from_host", "hop_by_host", "structure.chain_integrity"}
    ]
    for signal in hosts_by_signal:
        if signal.name in {"hop_from_host", "hop_by_host"} and not _is_host_token_valid(signal.value):
            contradictions.append(
                Contradiction(
                    type="structure",
                    signals=[signal.signal_id],
                    reason="Host token format is malformed for structural continuity checks.",
                    severity="medium",
                )
            )
            score -= 0.10

    by_signals = sorted(
        [signal for signal in all_signals if signal.name == "hop_by_host"],
        key=lambda item: parse_hop_index(item.source),
    )
    from_signals = sorted(
        [signal for signal in all_signals if signal.name == "hop_from_host"],
        key=lambda item: parse_hop_index(item.source),
    )
    by_map = {parse_hop_index(signal.source): signal for signal in by_signals}
    from_map = {parse_hop_index(signal.source): signal for signal in from_signals}

    for index in sorted(by_map.keys()):
        current = by_map[index]
        nxt = from_map.get(index + 1)
        if nxt is None:
            continue
        if host_related(str(current.value), str(nxt.value)):
            relationships.append(
                Relationship(
                    type="supports",
                    source_signal=current.signal_id,
                    target_signal=nxt.signal_id,
                    rationale="Adjacent by/from host continuity relationship is plausible.",
                )
            )
        else:
            contradictions.append(
                Contradiction(
                    type="structure",
                    signals=[current.signal_id, nxt.signal_id],
                    reason="Adjacent by/from hosts are not structurally continuous.",
                    severity="high",
                )
            )
            relationships.append(
                Relationship(
                    type="conflicts",
                    source_signal=current.signal_id,
                    target_signal=nxt.signal_id,
                    rationale="Adjacent by/from hosts show continuity break.",
                )
            )
            score -= 0.20

    return DomainEvaluation(score=clamp01(score), contradictions=contradictions, relationships=relationships)


def evaluate_infrastructure(
    signals: Sequence[Signal], config: CorrelationConfig
) -> DomainEvaluation:
    """Evaluate infrastructure coherence across hosts and IP literals."""

    contradictions: List[Contradiction] = []
    relationships: List[Relationship] = []
    score = 1.0

    host_signals = [
        signal
        for signal in signals
        if signal.name in {"hop_from_host", "hop_by_host", "infrastructure.domain"}
    ]
    ip_signals = [signal for signal in signals if signal.name in {"hop_from_ip", "infrastructure.ip"}]
    from_domain_signals = [signal for signal in host_signals if signal.name in {"hop_from_host", "infrastructure.domain"}]

    domain_counts: Dict[str, int] = {}
    domain_to_signals: Dict[str, List[Signal]] = {}
    for signal in from_domain_signals:
        domain = base_domain(str(signal.value))
        if not domain or domain.count(".") == 0:
            continue
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
        domain_to_signals.setdefault(domain, []).append(signal)

    if domain_counts:
        top_domain, top_count = sorted(domain_counts.items(), key=lambda item: (-item[1], item[0]))[0]
        if (
            top_count >= config.relay_repetition_strong_hops
            and len(from_domain_signals) >= config.relay_repetition_strong_hops
            and (top_count / max(1, len(from_domain_signals))) >= 0.8
        ):
            contradictions.append(
                Contradiction(
                    type="infrastructure",
                    signals=[item.signal_id for item in domain_to_signals[top_domain]],
                    reason="Repeated relay-like domain family appears across many hops.",
                    severity="medium",
                )
            )
            score -= 0.10
        elif top_count >= 2:
            items = sorted(domain_to_signals[top_domain], key=lambda sig: sig.signal_id)
            for idx in range(len(items) - 1):
                relationships.append(
                    Relationship(
                        type="supports",
                        source_signal=items[idx].signal_id,
                        target_signal=items[idx + 1].signal_id,
                        rationale="Signals share a consistent domain family across hops.",
                    )
                )

    ordered_from_hosts = sorted(
        [signal for signal in host_signals if signal.name == "hop_from_host"],
        key=lambda item: parse_hop_index(item.source),
    )
    domain_changes = 0
    transition_pairs: List[Tuple[Signal, Signal]] = []
    for idx in range(len(ordered_from_hosts) - 1):
        left = base_domain(str(ordered_from_hosts[idx].value))
        right = base_domain(str(ordered_from_hosts[idx + 1].value))
        if left and right and left != right:
            domain_changes += 1
            transition_pairs.append((ordered_from_hosts[idx], ordered_from_hosts[idx + 1]))

    if len(ordered_from_hosts) > 1:
        change_ratio = domain_changes / (len(ordered_from_hosts) - 1)
        if change_ratio >= 0.8 and domain_changes >= 2:
            contradictions.append(
                Contradiction(
                    type="infrastructure",
                    signals=[signal.signal_id for signal in ordered_from_hosts],
                    reason="Frequent abrupt domain-family transitions across adjacent hops.",
                    severity="medium",
                )
            )
            for left_sig, right_sig in transition_pairs:
                relationships.append(
                    Relationship(
                        type="conflicts",
                        source_signal=left_sig.signal_id,
                        target_signal=right_sig.signal_id,
                        rationale="Abrupt adjacent domain-family transition observed.",
                    )
                )
            score -= 0.10
        elif change_ratio >= 0.5 and domain_changes >= 2:
            contradictions.append(
                Contradiction(
                    type="infrastructure",
                    signals=[signal.signal_id for signal in ordered_from_hosts],
                    reason="Multiple adjacent domain-family transitions reduce infrastructure consistency.",
                    severity="low",
                )
            )
            for left_sig, right_sig in transition_pairs:
                relationships.append(
                    Relationship(
                        type="conflicts",
                        source_signal=left_sig.signal_id,
                        target_signal=right_sig.signal_id,
                        rationale="Abrupt adjacent domain-family transition observed.",
                    )
                )
            score -= 0.05

    if ip_signals:
        indexed_ips: List[Tuple[int, Signal]] = [
            (parse_hop_index(signal.source), signal) for signal in ip_signals
        ]
        indexed_ips.sort(key=lambda item: (item[0], item[1].signal_id))
        private_count = sum(1 for _, signal in indexed_ips if is_private_ip(str(signal.value)))
        public_count = sum(1 for _, signal in indexed_ips if not is_private_ip(str(signal.value)))
        min_index = min(index for index, _ in indexed_ips)
        max_index = max(index for index, _ in indexed_ips)
        private_middle = any(
            is_private_ip(str(signal.value)) and index not in {min_index, max_index}
            for index, signal in indexed_ips
        )

        if (
            private_count >= 1
            and public_count >= 1
            and len(indexed_ips) >= config.mixed_private_public_min_ips
            and private_middle
        ):
            contradictions.append(
                Contradiction(
                    type="infrastructure",
                    signals=[signal.signal_id for _, signal in indexed_ips],
                    reason="Private IP appears in middle of mixed public/private relay path.",
                    severity="medium",
                )
            )
            score -= 0.10

    return DomainEvaluation(score=clamp01(score), contradictions=contradictions, relationships=relationships)


def evaluate_quality(signals: Sequence[Signal]) -> float:
    """Derive deterministic quality score from completeness/reliability signals."""

    completeness_candidates = [
        float(signal.value)
        for signal in signals
        if signal.name in {"chain_completeness_score", "quality.completeness"}
        and _is_numeric(signal.value)
    ]
    completeness = mean(completeness_candidates) if completeness_candidates else 0.5

    reliability_candidates = [
        float(signal.value)
        for signal in signals
        if signal.name in {"quality.reliability"}
        and _is_numeric(signal.value)
    ]
    if not reliability_candidates:
        confidence_values = [signal.confidence for signal in signals]
        reliability = mean(confidence_values) if confidence_values else 0.5
    else:
        reliability = mean(reliability_candidates)

    anomaly_counts = [
        int(float(signal.value))
        for signal in signals
        if signal.name in {"chain_anomaly_count", "structure.anomaly_count"}
        and _is_numeric(signal.value)
    ]
    anomaly_penalty = min(0.20, 0.03 * sum(anomaly_counts))

    score = (0.7 * completeness) + (0.3 * reliability) - anomaly_penalty
    return clamp01(score)


def detect_cross_conflicts(
    groups: Dict[str, List[Signal]],
    group_scores: Dict[str, float],
    contradictions: Sequence[Contradiction],
) -> DomainEvaluation:
    """Detect contradictions emerging only when domains are considered jointly."""

    del groups  # currently unused but retained for future explainability expansion.

    output = DomainEvaluation(score=1.0)
    temporal_conflict = any(item.type == "temporal" for item in contradictions)
    structure_conflict = any(item.type == "structure" for item in contradictions)

    if group_scores.get("structure", 0.0) >= 0.80 and temporal_conflict:
        output.contradictions.append(
            Contradiction(
                type="cross",
                signals=["group:structure", "group:temporal"],
                reason="Structure appears coherent while temporal evidence indicates impossible ordering.",
                severity="high",
            )
        )
        output.relationships.append(
            Relationship(
                type="conflicts",
                source_signal="group:structure",
                target_signal="group:temporal",
                rationale="Cross-domain mismatch between structure and time progression.",
            )
        )

    if group_scores.get("quality", 0.0) >= 0.80 and len(contradictions) >= 2:
        output.contradictions.append(
            Contradiction(
                type="cross",
                signals=["group:quality", "group:structure"],
                reason="High completeness/quality coexists with multiple detected anomalies.",
                severity="medium",
            )
        )
        output.relationships.append(
            Relationship(
                type="conflicts",
                source_signal="group:quality",
                target_signal="group:structure",
                rationale="Quality and anomaly findings are in tension.",
            )
        )

    if group_scores.get("temporal", 0.0) < 0.50 and not structure_conflict and group_scores.get(
        "structure", 0.0
    ) >= 0.75:
        output.contradictions.append(
            Contradiction(
                type="cross",
                signals=["group:temporal", "group:structure"],
                reason="Temporal score is weak despite structurally plausible chain.",
                severity="high",
            )
        )
        output.relationships.append(
            Relationship(
                type="conflicts",
                source_signal="group:temporal",
                target_signal="group:structure",
                rationale="Temporal inconsistency weakens otherwise plausible chain structure.",
            )
        )

    return output


def detect_anonymization(
    groups: Dict[str, List[Signal]],
    signals: Sequence[Signal],
    contradictions: Sequence[Contradiction],
    config: CorrelationConfig,
) -> AnonymizationResult:
    """Detect anonymization-like patterns with deterministic multi-indicator rules."""

    strong: List[str] = []
    weak: List[str] = []

    structure_contradictions = [
        item
        for item in contradictions
        if item.type == "structure"
        and ("BROKEN_CHAIN" in item.reason or "POSSIBLE_INJECTION" in item.reason or item.severity == "high")
    ]
    if len(structure_contradictions) >= 2:
        strong.append("multiple_structure_anomalies")

    hop_count = _extract_hop_count(signals)
    if hop_count >= 2 and any(item.type == "temporal" for item in contradictions):
        strong.append("temporal_contradictions_with_multiple_hops")

    domain_family_counts = _domain_family_counts(groups.get("infrastructure", []))
    if domain_family_counts:
        max_repeat = max(domain_family_counts.values())
        if max_repeat >= config.relay_repetition_strong_hops:
            strong.append("repeated_relay_like_domain_patterns")

    if hop_count >= config.anonymization_min_hops_weak:
        weak.append("high_hop_count")

    completeness = _extract_completeness(signals)
    anomaly_count = _extract_anomaly_count(signals)
    if completeness < 0.55 and anomaly_count >= 2:
        weak.append("low_completeness_with_multiple_anomalies")

    ip_signals = [signal for signal in groups.get("infrastructure", []) if signal.name == "hop_from_ip"]
    if _has_mixed_private_public_ips(ip_signals):
        weak.append("mixed_private_and_public_relay_ips")

    indicators = sorted(set(strong)) + sorted(set(item for item in weak if item not in strong))

    if strong:
        confidence = clamp01(0.75 + 0.08 * (len(set(strong)) - 1) + 0.03 * len(set(weak)))
        return AnonymizationResult(
            detected=True,
            confidence=round(confidence, 4),
            indicators=indicators,
            strength="high",
        )

    if len(set(weak)) >= 2:
        confidence = clamp01(0.55 + 0.06 * (len(set(weak)) - 2))
        return AnonymizationResult(
            detected=True,
            confidence=round(confidence, 4),
            indicators=indicators,
            strength="medium",
        )

    if len(set(weak)) == 1:
        return AnonymizationResult(
            detected=False,
            confidence=0.35,
            indicators=indicators,
            strength="low",
        )

    return AnonymizationResult(detected=False, confidence=0.15, indicators=[], strength="low")


def build_derived_relationships(signals: Sequence[Signal]) -> List[Relationship]:
    """Build derived_from relationships for signals sharing the same evidence source."""

    by_source: Dict[str, List[Signal]] = {}
    for signal in sort_signals(signals):
        by_source.setdefault(signal.source, []).append(signal)

    relationships: List[Relationship] = []
    for source, items in sorted(by_source.items(), key=lambda pair: pair[0]):
        ordered = sorted(items, key=lambda signal: signal.signal_id)
        for idx in range(len(ordered) - 1):
            relationships.append(
                Relationship(
                    type="derived_from",
                    source_signal=ordered[idx].signal_id,
                    target_signal=ordered[idx + 1].signal_id,
                    rationale=f"Both signals originate from source {source}.",
                )
            )
    return relationships


def _is_numeric(value) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def _is_host_token_valid(value) -> bool:
    if value is None:
        return False
    token = str(value).strip()
    if not token:
        return False
    if token.count("..") > 0:
        return False
    if token in {"???", "!!!!"}:
        return False
    return bool(_HOST_TOKEN_RE.fullmatch(token))


def _extract_hop_count(signals: Sequence[Signal]) -> int:
    candidates = [
        int(float(signal.value))
        for signal in signals
        if signal.name == "hop_count" and _is_numeric(signal.value)
    ]
    if candidates:
        return max(candidates)
    hop_indexes = [parse_hop_index(signal.source) for signal in signals if parse_hop_index(signal.source) < 10**9]
    if hop_indexes:
        return max(hop_indexes) + 1
    return 0


def _extract_completeness(signals: Sequence[Signal]) -> float:
    candidates = [
        float(signal.value)
        for signal in signals
        if signal.name in {"chain_completeness_score", "quality.completeness"} and _is_numeric(signal.value)
    ]
    return clamp01(mean(candidates)) if candidates else 0.5


def _extract_anomaly_count(signals: Sequence[Signal]) -> int:
    counts = [
        int(float(signal.value))
        for signal in signals
        if signal.name in {"chain_anomaly_count", "structure.anomaly_count"} and _is_numeric(signal.value)
    ]
    if counts:
        return max(counts)
    anomalies = [
        normalize_to_list(signal.value)
        for signal in signals
        if signal.name in {"anomaly_types", "structure.anomaly"}
    ]
    flattened = [item for group in anomalies for item in group]
    return len(set(flattened))


def _domain_family_counts(signals: Sequence[Signal]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for signal in signals:
        if signal.name not in {"hop_from_host", "infrastructure.domain"}:
            continue
        domain = base_domain(str(signal.value))
        if domain and "." in domain:
            counts[domain] = counts.get(domain, 0) + 1
    return counts


def _has_mixed_private_public_ips(ip_signals: Sequence[Signal]) -> bool:
    if not ip_signals:
        return False
    private = [signal for signal in ip_signals if is_private_ip(str(signal.value))]
    public = [signal for signal in ip_signals if not is_private_ip(str(signal.value))]
    return bool(private and public)
