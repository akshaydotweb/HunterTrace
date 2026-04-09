#!/usr/bin/env python3
"""
Correlation-Based Origin Inference (probabilistic, non-deanonymizing).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from huntertrace.attribution.scoring import NormalizedSignal
from huntertrace.atlas.provenance import derive_provenance, trust_weight_for


_VPN_PATTERN = re.compile(
    r"(?<![a-z0-9])(vpn|proxy|tor|relay|exit|datacenter|hosting|residential)(?![a-z0-9])",
    re.IGNORECASE,
)
_TZ_PATTERN = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(value)))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _as_signal(raw: Any, index: int = 0) -> NormalizedSignal:
    if isinstance(raw, NormalizedSignal):
        return raw
    if isinstance(raw, Mapping):
        source_hint = str(raw.get("source") or raw.get("source_field") or "")
        hop_index = raw.get("hop_index") or raw.get("hop_position")
        source_header = raw.get("source_header")
        provenance_class = raw.get("provenance_class")
        trust_weight_base = raw.get("trust_weight_base")
        if not provenance_class:
            source_header, provenance, derived_weight = derive_provenance(
                signal_name=str(raw.get("name", "")),
                source_hint=source_hint,
                hop_index=hop_index if isinstance(hop_index, int) else None,
            )
            provenance_class = provenance.value
            trust_weight_base = derived_weight
        if trust_weight_base is None:
            trust_weight_base = trust_weight_for(
                derive_provenance(
                    signal_name=str(raw.get("name", "")),
                    source_hint=source_hint,
                    hop_index=hop_index if isinstance(hop_index, int) else None,
                )[1]
            )
        return NormalizedSignal(
            signal_id=str(raw.get("signal_id", f"signal-{index}")),
            name=str(raw.get("name", "unknown_signal")),
            group=str(raw.get("group", "identity")),
            value=raw.get("value"),
            candidate_region=(str(raw["candidate_region"]).strip() if raw.get("candidate_region") is not None else None),
            source=str(raw.get("source", "correlation")),
            source_header=source_header,
            trust_label=str(raw.get("trust_label", "UNKNOWN")),
            validation_flags=tuple(raw.get("validation_flags", ()) or ()),
            anomaly_detail=(str(raw["anomaly_detail"]).strip() if raw.get("anomaly_detail") else None),
            excluded_reason=(str(raw["excluded_reason"]).strip() if raw.get("excluded_reason") else None),
            provenance_class=str(provenance_class),
            trust_weight_base=float(trust_weight_base) if trust_weight_base is not None else 1.0,
            confidence=float(raw.get("confidence", 1.0)),
        )
    source_hint = getattr(raw, "source", "correlation")
    hop_index = getattr(raw, "hop_index", None)
    source_header = getattr(raw, "source_header", None)
    provenance_class = getattr(raw, "provenance_class", None)
    trust_weight_base = getattr(raw, "trust_weight_base", None)
    if not provenance_class:
        source_header, provenance, derived_weight = derive_provenance(
            signal_name=getattr(raw, "name", ""),
            source_hint=str(source_hint or ""),
            hop_index=hop_index if isinstance(hop_index, int) else None,
        )
        provenance_class = provenance.value
        trust_weight_base = derived_weight
    return NormalizedSignal(
        signal_id=f"signal-{index}",
        name=getattr(raw, "name", "unknown_signal"),
        group=getattr(raw, "group", "identity"),
        value=getattr(raw, "value", None),
        candidate_region=getattr(raw, "candidate_region", None),
        source=getattr(raw, "source", "correlation"),
        source_header=source_header,
        trust_label=getattr(raw, "trust_label", "UNKNOWN"),
        validation_flags=tuple(getattr(raw, "validation_flags", ()) or ()),
        anomaly_detail=getattr(raw, "anomaly_detail", None),
        excluded_reason=getattr(raw, "excluded_reason", None),
        provenance_class=str(provenance_class),
        trust_weight_base=float(trust_weight_base) if trust_weight_base is not None else 1.0,
        confidence=float(getattr(raw, "confidence", 1.0)),
    )


def _parse_timestamp(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        return parsedate_to_datetime(text)
    except Exception:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return None


def _parse_timezone_offset(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    text = str(raw).strip()
    match = _TZ_PATTERN.match(text)
    if not match:
        return None
    sign, hours, mins = match.groups()
    return f"{sign}{int(hours):02d}{int(mins):02d}"


def _trust_to_score(label: str) -> float:
    return {
        "TRUSTED": 1.0,
        "PARTIALLY_TRUSTED": 0.8,
        "UNKNOWN": 0.6,
        "UNTRUSTED": 0.4,
    }.get(str(label or "UNKNOWN"), 0.6)


def _signal_weight_score(signal: NormalizedSignal) -> float:
    trust_score = _trust_to_score(signal.trust_label)
    trust_weight = float(getattr(signal, "trust_weight_base", 1.0))
    confidence = float(getattr(signal, "confidence", 1.0))
    return trust_score * trust_weight * confidence


def _score_to_trust(score: float) -> str:
    if score >= 0.95:
        return "TRUSTED"
    if score >= 0.75:
        return "PARTIALLY_TRUSTED"
    if score >= 0.50:
        return "UNKNOWN"
    return "UNTRUSTED"


@dataclass(frozen=True)
class AnonymizationProfile:
    anonymization_detected: bool
    confidence: float
    indicators: Tuple[str, ...]


@dataclass(frozen=True)
class CorrelationResult:
    path_consistency_score: float
    suspicious_transitions: Tuple[Dict[str, Any], ...]
    likely_injection_points: Tuple[int, ...]


@dataclass(frozen=True)
class TemporalProfile:
    send_hour_distribution: Dict[int, int]
    timezone_offsets: Tuple[str, ...]
    consistency_score: float
    anomaly_score: float
    notes: Tuple[str, ...]


@dataclass(frozen=True)
class OriginHypothesis:
    adjusted_candidate_scores: Dict[str, float]
    confidence_shift: float
    reasoning: Tuple[str, ...]


@dataclass(frozen=True)
class CorrelationAdjustment:
    adjusted_signals: Tuple[NormalizedSignal, ...]
    anonymization: AnonymizationProfile
    correlation: CorrelationResult
    temporal: TemporalProfile
    origin_hypothesis: OriginHypothesis
    correlation_weight_multiplier: float
    confidence_penalty: float
    downgraded_signal_ids: Tuple[str, ...]
    boosted_signal_ids: Tuple[str, ...]
    reasoning: Tuple[str, ...]


def detect_anonymization(signals: Sequence[NormalizedSignal | Mapping[str, Any] | Any]) -> AnonymizationProfile:
    normalized = [_as_signal(s, idx) for idx, s in enumerate(signals)]
    indicators: List[str] = []
    weak_indicators: List[str] = []
    strong_indicators: List[str] = []
    score = 0.0

    vpn_like_hits = sum(
        1
        for signal in normalized
        if _VPN_PATTERN.search(signal.name or "")
        or _VPN_PATTERN.search(signal.source or "")
        or _VPN_PATTERN.search(str(signal.value or ""))
    )
    if vpn_like_hits > 0:
        weak_indicators.append("vpn_proxy_tor_pattern_detected")
        score += min(0.35, 0.10 + 0.08 * vpn_like_hits)

    candidate_regions = sorted({s.candidate_region for s in normalized if s.candidate_region})
    if len(candidate_regions) > 1:
        weak_indicators.append("candidate_region_mismatch")
        score += 0.22

    hop_count_values = [
        int(_safe_float(s.value, 0))
        for s in normalized
        if s.name == "hop_count" and _safe_float(s.value, 0) > 0
    ]
    if hop_count_values and max(hop_count_values) >= 4:
        weak_indicators.append("rapid_or_deep_relay_transitions")
        score += 0.16

    infra_regions = {s.candidate_region for s in normalized if s.group == "infrastructure" and s.candidate_region}
    temporal_regions = {s.candidate_region for s in normalized if s.group == "temporal" and s.candidate_region}
    if infra_regions and temporal_regions and infra_regions.isdisjoint(temporal_regions):
        strong_indicators.append("timezone_infrastructure_inconsistency")
        score += 0.28

    webmail_signals = [
        s for s in normalized
        if (s.name == "webmail_detected" and str(s.value).lower() in {"1", "true", "yes"})
    ]
    external_relay_signals = [
        s for s in normalized
        if ("relay" in (s.name or "").lower())
        or ("relay" in (s.source or "").lower())
        or ("external" in str(s.value or "").lower() and "relay" in str(s.value or "").lower())
    ]
    if webmail_signals and external_relay_signals:
        strong_indicators.append("webmail_external_relay_combo")
        score += 0.24
    elif webmail_signals or external_relay_signals:
        weak_indicators.append("relay_or_webmail_obfuscation_pattern")
        score += 0.12

    rapid_transition_signals = [
        s for s in normalized
        if ("rapid_transition" in str(s.name or "").lower())
        or ("time_reversal" in str(s.name or "").lower())
        or ("hop_mismatch" in str(s.name or "").lower())
        or ("rapid_transition" in str(s.anomaly_detail or "").lower())
        or ("time_reversal" in str(s.anomaly_detail or "").lower())
    ]
    if len(rapid_transition_signals) >= 1:
        strong_indicators.append("rapid_hop_transition_pattern")
        score += 0.20

    inconsistent_hop_pattern = False
    if hop_count_values:
        infra_candidate_values = [
            s.candidate_region for s in normalized
            if s.group == "infrastructure" and s.candidate_region is not None
        ]
        if len(infra_candidate_values) > 1 and len(set(infra_candidate_values)) > 1:
            inconsistent_hop_pattern = True
        if max(hop_count_values) >= 5 and len(infra_candidate_values) >= 2:
            inconsistent_hop_pattern = True
    if inconsistent_hop_pattern:
        strong_indicators.append("multiple_hops_inconsistent_patterns")
        score += 0.20

    confidence = round(_clamp(score), 12)
    indicators = sorted(set(weak_indicators + strong_indicators))
    # Sensitivity rule: trigger on confidence threshold, any strong indicator,
    # or at least two weak indicators.
    anonymization_detected = (
        confidence >= 0.18
        or bool(strong_indicators)
        or len(set(weak_indicators)) >= 2
    )
    return AnonymizationProfile(
        anonymization_detected=anonymization_detected,
        confidence=confidence,
        indicators=tuple(indicators),
    )


def correlate_hops(received_chain: Sequence[Mapping[str, Any] | Any]) -> CorrelationResult:
    suspicious: List[Dict[str, Any]] = []
    likely_injection_points: List[int] = []

    chain_rows: List[Dict[str, Any]] = []
    for idx, hop in enumerate(received_chain):
        if isinstance(hop, Mapping):
            row = dict(hop)
        else:
            row = {
                "position": getattr(hop, "position", idx),
                "ip": getattr(hop, "ip", None) or getattr(hop, "ip_v4", None) or getattr(hop, "ip_v6", None),
                "timestamp_raw": getattr(hop, "timestamp_raw", None),
                "by_hostname": getattr(hop, "by_hostname", None),
                "from_hostname": getattr(hop, "from_hostname", None),
                "parsing_confidence": getattr(hop, "parsing_confidence", 1.0),
            }
        row.setdefault("position", idx)
        chain_rows.append(row)

    parsed_times: List[Tuple[int, Optional[datetime]]] = []
    for row in chain_rows:
        parsed_times.append((int(_safe_float(row.get("position"), 0)), _parse_timestamp(row.get("timestamp_raw"))))

    for index in range(1, len(parsed_times)):
        current_pos, current_time = parsed_times[index]
        prev_pos, prev_time = parsed_times[index - 1]
        if current_time is None or prev_time is None:
            continue
        delta_seconds = (current_time - prev_time).total_seconds()
        if delta_seconds < 0:
            suspicious.append(
                {
                    "type": "time_reversal",
                    "from_position": prev_pos,
                    "to_position": current_pos,
                    "delta_seconds": round(delta_seconds, 3),
                }
            )
            likely_injection_points.append(current_pos)
        elif delta_seconds > 1800:
            suspicious.append(
                {
                    "type": "large_hop_gap",
                    "from_position": prev_pos,
                    "to_position": current_pos,
                    "delta_seconds": round(delta_seconds, 3),
                }
            )
            likely_injection_points.append(current_pos)
        elif delta_seconds < 2:
            suspicious.append(
                {
                    "type": "rapid_transition",
                    "from_position": prev_pos,
                    "to_position": current_pos,
                    "delta_seconds": round(delta_seconds, 3),
                }
            )

    infra_seen: Dict[str, int] = {}
    for row in chain_rows:
        by_host = str(row.get("by_hostname") or "").strip().lower()
        from_host = str(row.get("from_hostname") or "").strip().lower()
        ip_value = str(row.get("ip") or row.get("ip_v4") or row.get("ip_v6") or "").strip().lower()
        key = "|".join(part for part in (by_host, from_host, ip_value) if part)
        if not key:
            continue
        if key in infra_seen:
            suspicious.append(
                {
                    "type": "repeated_infrastructure",
                    "first_position": infra_seen[key],
                    "repeat_position": int(_safe_float(row.get("position"), 0)),
                }
            )
            likely_injection_points.append(int(_safe_float(row.get("position"), 0)))
        else:
            infra_seen[key] = int(_safe_float(row.get("position"), 0))

        parse_conf = _safe_float(row.get("parsing_confidence"), 1.0)
        if parse_conf < 0.6:
            likely_injection_points.append(int(_safe_float(row.get("position"), 0)))
            suspicious.append(
                {
                    "type": "low_parse_confidence_hop",
                    "position": int(_safe_float(row.get("position"), 0)),
                    "parsing_confidence": round(parse_conf, 6),
                }
            )

    unique_points = tuple(sorted(set(likely_injection_points)))
    penalty = min(0.9, 0.12 * len(suspicious) + 0.08 * len(unique_points))
    consistency = round(_clamp(1.0 - penalty), 12)

    return CorrelationResult(
        path_consistency_score=consistency,
        suspicious_transitions=tuple(suspicious),
        likely_injection_points=unique_points,
    )


def temporal_profile(signals: Sequence[NormalizedSignal | Mapping[str, Any] | Any]) -> TemporalProfile:
    normalized = [_as_signal(s, idx) for idx, s in enumerate(signals)]

    hour_counts: Dict[int, int] = {}
    timezones: List[str] = []
    notes: List[str] = []
    anomaly_score = 0.0

    for signal in normalized:
        if signal.name == "send_hour_utc":
            value = _safe_float(signal.value, -1)
            hour = int(value)
            if 0 <= hour <= 23:
                hour_counts[hour] = hour_counts.get(hour, 0) + 1
            else:
                anomaly_score += 0.25
                notes.append("invalid_send_hour_detected")

        if signal.name == "timezone_offset":
            offset = _parse_timezone_offset(signal.value)
            if offset is None:
                anomaly_score += 0.18
                notes.append("invalid_timezone_offset_detected")
            else:
                timezones.append(offset)

    unique_offsets = sorted(set(timezones))
    if len(unique_offsets) > 2:
        anomaly_score += 0.15
        notes.append("high_timezone_variance")

    if hour_counts:
        total = sum(hour_counts.values())
        dominant = max(hour_counts.values())
        hour_consistency = dominant / total if total else 0.0
    else:
        hour_consistency = 0.5
        notes.append("missing_send_hour_signal")

    if unique_offsets:
        tz_consistency = 1.0 / len(unique_offsets)
    else:
        tz_consistency = 0.5
        notes.append("missing_timezone_signal")

    consistency_score = _clamp((0.55 * hour_consistency) + (0.45 * tz_consistency) - anomaly_score)
    anomaly_score = _clamp(anomaly_score)

    return TemporalProfile(
        send_hour_distribution=dict(sorted(hour_counts.items())),
        timezone_offsets=tuple(unique_offsets),
        consistency_score=round(consistency_score, 12),
        anomaly_score=round(anomaly_score, 12),
        notes=tuple(sorted(set(notes))),
    )


def infer_pre_anonymization_region(
    signals: Sequence[NormalizedSignal | Mapping[str, Any] | Any],
    correlation: CorrelationResult,
    temporal: TemporalProfile,
) -> OriginHypothesis:
    normalized = [_as_signal(s, idx) for idx, s in enumerate(signals)]
    anonymization = detect_anonymization(normalized)

    candidates = sorted({s.candidate_region for s in normalized if s.candidate_region})
    if not candidates:
        return OriginHypothesis(
            adjusted_candidate_scores={},
            confidence_shift=0.0,
            reasoning=("No upstream candidate regions available.",),
        )

    base_scores: Dict[str, float] = {candidate: 0.0 for candidate in candidates}
    adjusted_scores: Dict[str, float] = {candidate: 0.0 for candidate in candidates}

    corr_multiplier = 0.75 + (0.50 * correlation.path_consistency_score)
    temporal_multiplier = 0.85 + (0.45 * temporal.consistency_score)
    infra_downgrade = 1.0 - (0.65 * anonymization.confidence) if anonymization.anonymization_detected else 1.0
    infra_downgrade = _clamp(infra_downgrade, 0.25, 1.0)

    for signal in normalized:
        if not signal.candidate_region or signal.candidate_region not in base_scores:
            continue
        if signal.excluded_reason:
            continue

        base_weight = _signal_weight_score(signal)
        base_scores[signal.candidate_region] += base_weight

        adjusted_weight = base_weight
        if signal.group == "infrastructure":
            adjusted_weight *= infra_downgrade * corr_multiplier
        elif signal.group == "temporal":
            adjusted_weight *= temporal_multiplier
        else:
            adjusted_weight *= 1.0 + (0.10 * (1.0 - anonymization.confidence))

        adjusted_scores[signal.candidate_region] += adjusted_weight

    best_base = max(base_scores.values()) if base_scores else 0.0
    best_adjusted = max(adjusted_scores.values()) if adjusted_scores else 0.0
    if best_base > 0:
        confidence_shift = round((best_adjusted - best_base) / best_base, 12)
    else:
        confidence_shift = 0.0

    reasoning = [
        f"Correlation multiplier applied: {corr_multiplier:.6f}",
        f"Temporal multiplier applied: {temporal_multiplier:.6f}",
        f"Infrastructure downgrade multiplier: {infra_downgrade:.6f}",
        f"Anonymization confidence: {anonymization.confidence:.6f}",
    ]

    return OriginHypothesis(
        adjusted_candidate_scores={k: round(v, 12) for k, v in sorted(adjusted_scores.items())},
        confidence_shift=confidence_shift,
        reasoning=tuple(reasoning),
    )


def apply_correlation_adjustment(
    signals: Sequence[NormalizedSignal | Mapping[str, Any] | Any],
    received_chain: Optional[Sequence[Mapping[str, Any] | Any]] = None,
) -> CorrelationAdjustment:
    normalized = tuple(_as_signal(s, idx) for idx, s in enumerate(signals))
    correlation = correlate_hops(received_chain or [])
    temporal = temporal_profile(normalized)
    anonymization = detect_anonymization(normalized)
    hypothesis = infer_pre_anonymization_region(normalized, correlation, temporal)

    adjusted: List[NormalizedSignal] = []
    downgraded_ids: List[str] = []
    boosted_ids: List[str] = []
    reasoning: List[str] = []

    correlation_weight_multiplier = round(
        _clamp((0.70 + (0.30 * correlation.path_consistency_score)) * (1.0 - (0.35 * anonymization.confidence)), 0.35, 1.15),
        12,
    )

    for signal in normalized:
        if signal.excluded_reason:
            adjusted.append(signal)
            continue

        if signal.candidate_region is None:
            adjusted.append(signal)
            continue

        multiplier = 1.0
        local_reasons: List[str] = []

        if signal.group == "infrastructure":
            multiplier *= correlation_weight_multiplier
            if anonymization.anonymization_detected:
                anonym_drop = _clamp(1.0 - (0.65 * anonymization.confidence), 0.25, 1.0)
                multiplier *= anonym_drop
                local_reasons.append(f"infrastructure_downgrade={anonym_drop:.6f}")

        if signal.group == "temporal":
            temporal_boost = _clamp(0.85 + (0.35 * temporal.consistency_score), 0.80, 1.20)
            multiplier *= temporal_boost
            if temporal_boost > 1.0:
                local_reasons.append(f"temporal_boost={temporal_boost:.6f}")

        if signal.group == "identity" and anonymization.anonymization_detected:
            identity_adj = _clamp(0.95 + (0.10 * (1.0 - anonymization.confidence)), 0.90, 1.05)
            multiplier *= identity_adj

        old_score = _signal_weight_score(signal)
        new_score = _clamp(old_score * multiplier, 0.2, 1.0)
        new_label = _score_to_trust(new_score)

        new_flags = list(signal.validation_flags)
        if multiplier < 0.80 and "SUSPICIOUS" not in new_flags and "MALFORMED" not in new_flags:
            new_flags.append("SUSPICIOUS")

        detail_suffix = "; ".join(local_reasons) if local_reasons else None
        anomaly_detail = signal.anomaly_detail
        if detail_suffix:
            anomaly_detail = f"{anomaly_detail}; {detail_suffix}" if anomaly_detail else detail_suffix

        adjusted_signal = replace(
            signal,
            trust_label=new_label,
            validation_flags=tuple(new_flags),
            anomaly_detail=anomaly_detail,
        )
        adjusted.append(adjusted_signal)

        if new_score + 1e-12 < old_score:
            downgraded_ids.append(signal.signal_id)
        elif new_score > old_score + 1e-12:
            boosted_ids.append(signal.signal_id)

    confidence_penalty = round(
        _clamp(0.55 * anonymization.confidence + 0.25 * (1.0 - correlation.path_consistency_score), 0.0, 0.85),
        12,
    )

    if anonymization.anonymization_detected:
        reasoning.append(
            f"Anonymization suspected (confidence={anonymization.confidence:.6f}) from indicators: "
            + ", ".join(anonymization.indicators)
        )
    if downgraded_ids:
        reasoning.append(f"Downgraded {len(downgraded_ids)} candidate-bearing signals due to anonymization correlation.")
    if boosted_ids:
        reasoning.append(f"Boosted {len(boosted_ids)} temporal-consistent signals.")

    reasoning.extend(list(hypothesis.reasoning))
    if correlation.suspicious_transitions:
        reasoning.append(f"{len(correlation.suspicious_transitions)} suspicious hop transitions influenced weighting.")

    return CorrelationAdjustment(
        adjusted_signals=tuple(adjusted),
        anonymization=anonymization,
        correlation=correlation,
        temporal=temporal,
        origin_hypothesis=hypothesis,
        correlation_weight_multiplier=correlation_weight_multiplier,
        confidence_penalty=confidence_penalty,
        downgraded_signal_ids=tuple(sorted(set(downgraded_ids))),
        boosted_signal_ids=tuple(sorted(set(boosted_ids))),
        reasoning=tuple(reasoning),
    )
