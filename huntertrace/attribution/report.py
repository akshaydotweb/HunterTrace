#!/usr/bin/env python3
"""
Deterministic attribution reporting utilities for production CLI workflows.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from huntertrace.analysis.correlation import apply_correlation_adjustment
from huntertrace.atlas.provenance import derive_provenance, extract_hop_index
from huntertrace.attribution.config_loader import RuntimeConfig
from huntertrace.attribution.dkim import DKIMVerificationSummary, verify_message
from huntertrace.attribution.scoring import (
    AttributionResult,
    InferenceEngine,
    NormalizedSignal,
)


@dataclass(frozen=True)
class InferencePolicy:
    confidence_threshold: float = 0.35
    tie_epsilon: float = 1e-9
    min_supporting_signals: int = 2
    min_contributing_groups: int = 2
    min_distinct_supporting_groups: int = 2

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "InferencePolicy":
        return cls(
            confidence_threshold=float(value.get("confidence_threshold", 0.35)),
            tie_epsilon=float(value.get("tie_epsilon", 1e-9)),
            min_supporting_signals=int(value.get("min_supporting_signals", 2)),
            min_contributing_groups=int(value.get("min_contributing_groups", 2)),
            min_distinct_supporting_groups=int(value.get("min_distinct_supporting_groups", 2)),
        )


@dataclass(frozen=True)
class AnalysisInput:
    evidence_id: str
    input_type: str
    source: str
    signals: Tuple[NormalizedSignal, ...]
    anomalies: Tuple[Dict[str, Any], ...]
    received_chain: Tuple[Dict[str, Any], ...] = ()
    authentication: Dict[str, Any] = None


def _clean_text(value: Any, *, max_len: int = 512) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    safe = "".join(ch for ch in text if ch.isprintable())
    return safe[:max_len] if safe else None


def _normalize_region(value: Any) -> Optional[str]:
    return _clean_text(value, max_len=128)


def _to_flag_list(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            text = _clean_text(item, max_len=64)
            if text:
                out.append(text.split(".")[-1])
        return tuple(out)
    text = _clean_text(value, max_len=64)
    return (text.split(".")[-1],) if text else ()


def _to_signal(raw: Mapping[str, Any], index: int, source: str) -> NormalizedSignal:
    signal_id = _clean_text(raw.get("signal_id"), max_len=128) or f"signal-{index}"
    name = _clean_text(raw.get("name"), max_len=128) or "unknown_signal"
    group = _clean_text(raw.get("group"), max_len=64) or "identity"
    trust_label = _clean_text(raw.get("trust_label") or raw.get("trust_tier"), max_len=64) or "UNKNOWN"
    candidate_region = _extract_upstream_region(raw)

    anomaly_detail = _clean_text(raw.get("anomaly_detail"), max_len=256)
    excluded_reason = _clean_text(raw.get("excluded_reason"), max_len=256)

    value = raw.get("value")
    if isinstance(value, (dict, list)):
        value = json.loads(json.dumps(value, sort_keys=True))

    source_hint = _clean_text(raw.get("source_field") or raw.get("source"), max_len=256)
    hop_index = raw.get("hop_position")
    if not isinstance(hop_index, int):
        hop_index = extract_hop_index(source_hint)

    source_header = _clean_text(raw.get("source_header"), max_len=64)
    provenance_class = _clean_text(raw.get("provenance_class"), max_len=64)
    trust_weight_base = raw.get("trust_weight_base")
    if not provenance_class or trust_weight_base is None:
        header, provenance, derived_weight = derive_provenance(
            signal_name=name,
            source_hint=source_hint,
            hop_index=hop_index if isinstance(hop_index, int) else None,
        )
        if not source_header:
            source_header = header
        if not provenance_class:
            provenance_class = provenance.value
        if trust_weight_base is None:
            trust_weight_base = derived_weight

    return NormalizedSignal(
        signal_id=signal_id,
        name=name,
        group=group,
        value=value,
        candidate_region=candidate_region,
        source=_clean_text(raw.get("source"), max_len=128) or source,
        source_header=source_header,
        trust_label=trust_label.split(".")[-1],
        validation_flags=_to_flag_list(raw.get("validation_flags")),
        anomaly_detail=anomaly_detail,
        excluded_reason=excluded_reason,
        provenance_class=str(provenance_class or "sender_controlled"),
        trust_weight_base=float(trust_weight_base) if trust_weight_base is not None else 0.2,
        confidence=float(raw.get("confidence", 1.0)),
    )


def _safe_anomaly_entry(entry: Any) -> Dict[str, Any]:
    if isinstance(entry, Mapping):
        output: Dict[str, Any] = {}
        for key in sorted(entry.keys()):
            key_text = _clean_text(key, max_len=128)
            if not key_text:
                continue
            value = entry[key]
            if isinstance(value, (str, int, float, bool)) or value is None:
                output[key_text] = value
            else:
                output[key_text] = _clean_text(value, max_len=256)
        return output
    text = _clean_text(entry, max_len=256)
    return {"detail": text} if text else {"detail": "unknown_anomaly"}


def _hash_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_json_input(path: Path) -> AnalysisInput:
    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, list):
        signal_rows = data
        anomalies = []
        received_chain = []
        evidence_id = _hash_json({"signals": data, "source": str(path)})
    elif isinstance(data, Mapping):
        signal_rows = data.get("signals")
        if signal_rows is None and isinstance(data.get("validated_bundle"), Mapping):
            signal_rows = data["validated_bundle"].get("signals", [])
        if signal_rows is None and isinstance(data.get("bundle"), Mapping):
            signal_rows = data["bundle"].get("signals", [])
        if signal_rows is None:
            signal_rows = data.get("normalized_signals", [])
        if not isinstance(signal_rows, list):
            signal_rows = []

        anomalies_raw = data.get("anomalies", [])
        anomalies = anomalies_raw if isinstance(anomalies_raw, list) else []
        chain_raw = data.get("received_chain", [])
        received_chain = chain_raw if isinstance(chain_raw, list) else []
        evidence_id = (
            _clean_text(data.get("evidence_id"), max_len=128)
            or _hash_json({"signals": signal_rows, "anomalies": anomalies, "source": str(path)})
        )
    else:
        raise ValueError("JSON input must be an object or list.")

    signals = [
        _to_signal(row, idx, source="json_input")
        for idx, row in enumerate(signal_rows)
        if isinstance(row, Mapping)
    ]
    signals = list(_ensure_candidate_regions(signals))
    anomaly_rows = [_safe_anomaly_entry(item) for item in anomalies]

    return AnalysisInput(
        evidence_id=evidence_id,
        input_type="json",
        source=str(path),
        signals=tuple(signals),
        anomalies=tuple(anomaly_rows),
        received_chain=tuple(
            dict(row) for row in received_chain if isinstance(row, Mapping)
        ),
        authentication={},
    )


_RE_TZ = re.compile(r"([+-]\d{2}:?\d{2})")
_RE_IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b")
_RE_DKIM = re.compile(r"(?:^|;)\s*d\s*=\s*([^\s;]+)", re.IGNORECASE)
_RE_RECEIVED_BY = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)
_RE_RECEIVED_FROM = re.compile(r"\bfrom\s+([^\s;]+)", re.IGNORECASE)
_RE_RECEIVED_TS = re.compile(r";\s*(.+)$")
_RE_DOMAIN = re.compile(r"([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", re.IGNORECASE)


def _extract_upstream_region(raw: Mapping[str, Any]) -> Optional[str]:
    direct = _normalize_region(raw.get("candidate_region"))
    if direct:
        return direct

    for key in (
        "region",
        "region_label",
        "region_cluster",
        "candidate_label",
        "candidate_region_label",
    ):
        value = _normalize_region(raw.get(key))
        if value:
            return value

    enrichment = raw.get("enrichment")
    if isinstance(enrichment, Mapping):
        for key in (
            "candidate_region",
            "region",
            "region_label",
            "region_cluster",
            "candidate_label",
        ):
            value = _normalize_region(enrichment.get(key))
            if value:
                return value
    return None


def _extract_domain_token(value: Any) -> Optional[str]:
    text = _clean_text(value, max_len=256)
    if not text:
        return None
    if _RE_IPV4.search(text):
        return None
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    match = _RE_DOMAIN.search(text.lower())
    return match.group(1) if match else None


def _derive_cluster_candidate(signals: Sequence[NormalizedSignal]) -> Optional[str]:
    token_counts: Dict[str, int] = {}
    for signal in signals:
        token = _extract_domain_token(signal.value)
        if token:
            token_counts[token] = token_counts.get(token, 0) + 1
    eligible = sorted(
        (
            (token, count)
            for token, count in token_counts.items()
            if count >= 2
        ),
        key=lambda row: (-row[1], row[0]),
    )
    if not eligible:
        return None
    top_token = eligible[0][0]
    return f"CLUSTER:{top_token}"


def _fallback_candidate_trust(label: str) -> str:
    normalized = str(label or "UNKNOWN").upper()
    if normalized in {"UNKNOWN", "UNTRUSTED"}:
        return normalized
    return "UNKNOWN"


def _ensure_candidate_regions(signals: Sequence[NormalizedSignal]) -> Tuple[NormalizedSignal, ...]:
    if any(_normalize_region(signal.candidate_region) for signal in signals):
        return tuple(signals)

    cluster_label = _derive_cluster_candidate(signals)
    adjusted: List[NormalizedSignal] = []
    if cluster_label:
        for signal in signals:
            token = _extract_domain_token(signal.value)
            if token and (cluster_label == f"CLUSTER:{token}"):
                adjusted.append(
                    NormalizedSignal(
                        signal_id=signal.signal_id,
                        name=signal.name,
                        group=signal.group,
                        value=signal.value,
                        candidate_region=cluster_label,
                        source=signal.source,
                        source_header=signal.source_header,
                        trust_label=_fallback_candidate_trust(signal.trust_label),
                        validation_flags=signal.validation_flags,
                        anomaly_detail=signal.anomaly_detail,
                        excluded_reason=signal.excluded_reason,
                        provenance_class=signal.provenance_class,
                        trust_weight_base=signal.trust_weight_base,
                        confidence=signal.confidence,
                    )
                )
            else:
                adjusted.append(signal)
        if any(_normalize_region(signal.candidate_region) for signal in adjusted):
            return tuple(adjusted)

    # Last-resort weak candidate to avoid an empty candidate set.
    for signal in signals:
        adjusted.append(
            NormalizedSignal(
                signal_id=signal.signal_id,
                name=signal.name,
                group=signal.group,
                value=signal.value,
                candidate_region="UNKNOWN",
                source=signal.source,
                source_header=signal.source_header,
                trust_label=_fallback_candidate_trust(signal.trust_label),
                validation_flags=signal.validation_flags,
                anomaly_detail=signal.anomaly_detail,
                excluded_reason=signal.excluded_reason,
                provenance_class=signal.provenance_class,
                trust_weight_base=signal.trust_weight_base,
                confidence=signal.confidence,
            )
        )
    return tuple(adjusted)


def _dkim_to_signals(
    summary: DKIMVerificationSummary,
    candidate_region: Optional[str],
    start_index: int,
) -> Tuple[List[NormalizedSignal], List[Dict[str, Any]], int]:
    signals: List[NormalizedSignal] = []
    anomalies: List[Dict[str, Any]] = []
    index = start_index

    if not summary.dkim_present:
        return signals, anomalies, index

    if summary.domain:
        header, provenance, trust_weight = derive_provenance(
            signal_name="dkim_domain",
            source_hint="DKIM-Signature",
        )
        signals.append(
            NormalizedSignal(
                signal_id=f"eml-{index}",
                name="dkim_domain",
                group="authentication",
                value=summary.domain,
                candidate_region=candidate_region,
                source="eml.dkim.domain",
                source_header=header,
                trust_label="TRUSTED" if summary.dkim_valid else "PARTIALLY_TRUSTED",
                validation_flags=("CLEAN",) if summary.dkim_valid else ("SUSPICIOUS",),
                anomaly_detail=None if summary.dkim_valid else summary.failure_reason,
                provenance_class=provenance.value,
                trust_weight_base=trust_weight,
                confidence=1.0,
            )
        )
        index += 1

    header, provenance, trust_weight = derive_provenance(
        signal_name="dkim_valid",
        source_hint="DKIM-Signature",
    )
    signals.append(
        NormalizedSignal(
            signal_id=f"eml-{index}",
            name="dkim_valid",
            group="authentication",
            value=summary.dkim_valid,
            candidate_region=candidate_region,
            source="eml.dkim.verify",
            source_header=header,
            trust_label="TRUSTED" if summary.dkim_valid else "PARTIALLY_TRUSTED",
            validation_flags=("CLEAN",) if summary.dkim_valid else ("SUSPICIOUS",),
            anomaly_detail=None if summary.dkim_valid else summary.failure_reason,
            provenance_class=provenance.value,
            trust_weight_base=trust_weight,
            confidence=1.0,
        )
    )
    index += 1

    if not summary.dkim_valid:
        anomalies.append(
            {
                "type": "authentication",
                "protocol": "dkim",
                "detail": summary.failure_reason or "dkim_verification_failed",
                "domain": summary.domain,
                "selector": summary.selector,
                "signed_headers": list(summary.signed_headers),
                "canonicalization": summary.canonicalization,
            }
        )

    return signals, anomalies, index


def _load_eml_input(path: Path) -> AnalysisInput:
    raw_bytes = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    evidence_id = hashlib.sha256(raw_bytes).hexdigest()
    source = str(path)

    signals: List[NormalizedSignal] = []
    anomalies: List[Dict[str, Any]] = []
    received_chain: List[Dict[str, Any]] = []
    idx = 0

    injected_region = (
        _normalize_region(message.get("X-HunterTrace-Candidate-Region"))
        or _normalize_region(message.get("X-HunterTrace-Region"))
        or _normalize_region(message.get("X-HunterTrace-Region-Cluster"))
        or _normalize_region(message.get("X-Region-Cluster"))
    )
    dkim_summary = verify_message(raw_bytes)

    date_value = _clean_text(message.get("Date"), max_len=256)
    if date_value:
        tz_match = _RE_TZ.search(date_value)
        header, provenance, trust_weight = derive_provenance(
            signal_name="timezone_offset",
            source_hint="Date",
        )
        signals.append(
            NormalizedSignal(
                signal_id=f"eml-{idx}",
                name="timezone_offset",
                group="temporal",
                value=tz_match.group(1) if tz_match else date_value,
                candidate_region=injected_region,
                source="eml.header.date",
                source_header=header,
                trust_label="UNKNOWN",
                validation_flags=("CLEAN",) if tz_match else ("SUSPICIOUS",),
                anomaly_detail=None if tz_match else "No timezone token found in Date header",
                provenance_class=provenance.value,
                trust_weight_base=trust_weight,
                confidence=1.0,
            )
        )
        idx += 1

    message_id = _clean_text(message.get("Message-ID"), max_len=256)
    if message_id and "@" in message_id:
        domain = message_id.rsplit("@", 1)[-1].strip(" >")
        header, provenance, trust_weight = derive_provenance(
            signal_name="message_id_domain",
            source_hint="Message-ID",
        )
        signals.append(
            NormalizedSignal(
                signal_id=f"eml-{idx}",
                name="message_id_domain",
                group="identity",
                value=domain,
                candidate_region=injected_region,
                source="eml.header.message-id",
                source_header=header,
                trust_label="UNKNOWN",
                validation_flags=("CLEAN",),
                provenance_class=provenance.value,
                trust_weight_base=trust_weight,
                confidence=1.0,
            )
        )
        idx += 1

    dkim_signals, dkim_anomalies, idx = _dkim_to_signals(dkim_summary, injected_region, idx)
    signals.extend(dkim_signals)
    anomalies.extend(dkim_anomalies)

    received_headers = message.get_all("Received", []) or []
    for hop_index, hop in enumerate(received_headers):
        hop_text = _clean_text(hop, max_len=4096) or ""
        by_host_match = _RE_RECEIVED_BY.search(hop_text)
        from_host_match = _RE_RECEIVED_FROM.search(hop_text)
        ts_match = _RE_RECEIVED_TS.search(hop_text)
        received_chain.append(
            {
                "position": hop_index,
                "raw_text": hop_text,
                "by_hostname": by_host_match.group(1) if by_host_match else None,
                "from_hostname": from_host_match.group(1) if from_host_match else None,
                "timestamp_raw": ts_match.group(1).strip() if ts_match else None,
                "parsing_confidence": 1.0 if hop_text else 0.5,
            }
        )
        ips = sorted(set(_RE_IPV4.findall(hop_text)))
        if not ips:
            continue
        for ip in ips:
            header, provenance, trust_weight = derive_provenance(
                signal_name="first_hop_ip" if hop_index == 0 else "all_ips",
                source_hint=f"Received[{hop_index}]",
                hop_index=hop_index,
                hop_count=len(received_headers),
            )
            signals.append(
                NormalizedSignal(
                    signal_id=f"eml-{idx}",
                    name="all_ips" if hop_index > 0 else "first_hop_ip",
                    group="infrastructure",
                    value=ip,
                    candidate_region=injected_region,
                    source=f"eml.header.received[{hop_index}]",
                    source_header=header,
                    trust_label="PARTIALLY_TRUSTED",
                    validation_flags=("CLEAN",),
                    provenance_class=provenance.value,
                    trust_weight_base=trust_weight,
                    confidence=1.0,
                )
            )
            idx += 1

    if not signals:
        anomalies.append(
            {
                "type": "input_parsing",
                "detail": "No usable signals could be extracted from .eml input.",
            }
        )
    signals = list(_ensure_candidate_regions(signals))

    return AnalysisInput(
        evidence_id=evidence_id,
        input_type="eml",
        source=source,
        signals=tuple(signals),
        anomalies=tuple(anomalies),
        received_chain=tuple(received_chain),
        authentication={"dkim": dkim_summary.to_dict()},
    )


def load_analysis_input(path: str) -> AnalysisInput:
    input_path = Path(path).expanduser().resolve()
    suffix = input_path.suffix.lower()
    if suffix == ".eml":
        return _load_eml_input(input_path)
    if suffix == ".json":
        return _load_json_input(input_path)
    raise ValueError("Unsupported input type. Use .eml or .json.")


def _contributing_groups(engine: InferenceEngine, signals: Sequence[NormalizedSignal]) -> List[str]:
    groups = {
        s.group
        for s in signals
        if s.candidate_region is not None
        and engine._resolve_base_weight(s) > 0
        and engine._resolve_validation_multiplier(s) > 0
        and (not s.excluded_reason)
    }
    return sorted(groups)


def _signals_rejected(engine: InferenceEngine, signals: Sequence[NormalizedSignal]) -> List[Dict[str, Any]]:
    rejected: List[Dict[str, Any]] = []
    for signal in signals:
        reason: Optional[str] = None
        if signal.candidate_region is None:
            reason = "non_attributable"
        elif signal.excluded_reason:
            reason = signal.excluded_reason
        elif engine._resolve_base_weight(signal) <= 0:
            reason = "non_positive_weight"
        elif engine._resolve_validation_multiplier(signal) <= 0:
            reason = "validation_excluded"

        if reason:
            rejected.append(
                {
                    "signal_id": signal.signal_id,
                    "name": signal.name,
                    "group": signal.group,
                    "reason": reason,
                }
            )

    rejected.sort(key=lambda row: (row["name"], row["signal_id"]))
    return rejected


def _build_explanation(
    verdict: str,
    region: Optional[str],
    confidence: float,
    top_supporting: Sequence[Mapping[str, Any]],
    top_conflicting: Sequence[Mapping[str, Any]],
    limitations: Sequence[str],
) -> str:
    supporting_names = ", ".join(row["name"] for row in top_supporting if row.get("name")) or "none"
    conflicting_names = ", ".join(row["name"] for row in top_conflicting if row.get("name")) or "none"
    limitation_blob = " ".join(str(item) for item in limitations).lower()
    anonymization_detected = "anonymization indicators detected" in limitation_blob
    conflict_detected = bool(top_conflicting)

    if verdict == "inconclusive":
        if conflict_detected:
            return (
                f"Conflicting signals ({conflicting_names}) outweighed consistent evidence ({supporting_names}); "
                f"the result is inconclusive at confidence {confidence:.6f}."
            )
        if anonymization_detected:
            return (
                f"Anonymization indicators reduced confidence, so HunterTrace stayed inconclusive "
                f"at {confidence:.6f}."
            )
        return (
            f"Signal consistency was insufficient for safe attribution; the result is inconclusive "
            f"at confidence {confidence:.6f}."
        )

    if anonymization_detected:
        return (
            f"Signals supported {region}, but anonymization indicators reduced confidence to "
            f"{confidence:.6f}."
        )
    return (
        f"Signals were consistent, so attribution to {region} is reported with cautious confidence "
        f"{confidence:.6f}."
    )


class AttributionRunner:
    def __init__(self, runtime: RuntimeConfig, use_correlation: bool = True):
        self.runtime = runtime
        self.use_correlation = bool(use_correlation)
        self.engine = InferenceEngine(config=runtime.scoring)
        self.policy = InferencePolicy.from_mapping(runtime.inference)
        self._cache: Dict[str, Dict[str, Any]] = {}

    def analyze(self, payload: AnalysisInput) -> Dict[str, Any]:
        assert all(
            s.candidate_region is None or isinstance(s.candidate_region, str)
            for s in payload.signals
        )

        cache_key = _hash_json(
            {
                "evidence_id": payload.evidence_id,
                "signals": [asdict(s) for s in payload.signals],
                "anomalies": list(payload.anomalies),
                "received_chain": list(payload.received_chain),
                "use_correlation": self.use_correlation,
                "scoring_config": {
                    "group_weights": dict(self.runtime.scoring.group_weights),
                    "signal_weights": dict(self.runtime.scoring.signal_weights),
                    "trust_multipliers": dict(self.runtime.scoring.trust_multipliers),
                    "validation_multipliers": dict(self.runtime.scoring.validation_multipliers),
                    "conflict_multipliers": dict(self.runtime.scoring.conflict_multipliers),
                    "evidence_penalties": dict(self.runtime.scoring.evidence_penalties),
                    "confidence_cap": float(self.runtime.scoring.confidence_cap),
                },
                "policy": asdict(self.policy),
            }
        )
        if cache_key in self._cache:
            return json.loads(json.dumps(self._cache[cache_key], sort_keys=True))

        result = self._run(payload)
        self._cache[cache_key] = result
        return json.loads(json.dumps(result, sort_keys=True))

    def _run(self, payload: AnalysisInput) -> Dict[str, Any]:
        if self.use_correlation:
            correlation_adjustment = apply_correlation_adjustment(
                payload.signals,
                payload.received_chain,
            )
            scoring_signals = correlation_adjustment.adjusted_signals
            confidence_penalty = float(correlation_adjustment.confidence_penalty)
            correlation_trace = {
                "enabled": True,
                "anonymization_detected": bool(correlation_adjustment.anonymization.anonymization_detected),
                "key_indicators": list(correlation_adjustment.anonymization.indicators),
                "confidence_impact": correlation_adjustment.confidence_penalty,
                "anonymization": asdict(correlation_adjustment.anonymization),
                "hop_correlation": asdict(correlation_adjustment.correlation),
                "temporal_profile": asdict(correlation_adjustment.temporal),
                "origin_hypothesis": asdict(correlation_adjustment.origin_hypothesis),
                "correlation_weight_multiplier": correlation_adjustment.correlation_weight_multiplier,
                "confidence_penalty": correlation_adjustment.confidence_penalty,
                "downgraded_signal_ids": list(correlation_adjustment.downgraded_signal_ids),
                "boosted_signal_ids": list(correlation_adjustment.boosted_signal_ids),
            }
            correlation_reasoning = list(correlation_adjustment.reasoning)
            anonymization_detected = correlation_adjustment.anonymization.anonymization_detected
            anonymization_confidence = float(correlation_adjustment.anonymization.confidence)
            anonymization_indicators = list(correlation_adjustment.anonymization.indicators)
            downgraded_signal_ids = list(correlation_adjustment.downgraded_signal_ids)
            boosted_signal_ids = list(correlation_adjustment.boosted_signal_ids)
        else:
            scoring_signals = payload.signals
            confidence_penalty = 0.0
            correlation_trace = {
                "enabled": False,
                "anonymization_detected": False,
                "key_indicators": [],
                "confidence_impact": 0.0,
                "reason": "Correlation preprocessing disabled via CLI flag.",
            }
            correlation_reasoning = []
            anonymization_detected = False
            anonymization_confidence = 0.0
            anonymization_indicators = []
            downgraded_signal_ids = []
            boosted_signal_ids = []

        rejected = _signals_rejected(self.engine, scoring_signals)
        candidates = sorted({
            _normalize_region(signal.candidate_region)
            for signal in scoring_signals
            if _normalize_region(signal.candidate_region) is not None
        })

        if not candidates:
            limitations = ["No candidate regions provided by upstream signals."]
            if rejected:
                limitations.append(f"{len(rejected)} signals were non-attributable or excluded.")
            limitations.extend(correlation_reasoning)
            result = {
                "region": None,
                "confidence": 0.0,
                "verdict": "inconclusive",
                "signals_used": [],
                "signals_rejected": rejected,
                "anomalies": list(payload.anomalies) + [
                    {
                        "type": "correlation_inference",
                        "correlation_enabled": self.use_correlation,
                        "anonymization_detected": anonymization_detected,
                        "anonymization_confidence": anonymization_confidence,
                        "indicators": anonymization_indicators,
                    }
                ],
                "limitations": limitations,
                "authentication": payload.authentication or {},
            }
            result["explanation"] = _build_explanation(
                verdict="inconclusive",
                region=None,
                confidence=0.0,
                top_supporting=[],
                top_conflicting=[],
                limitations=limitations,
            )
            return {
                "result": result,
                "trace": {
                    "evidence_id": payload.evidence_id,
                    "candidates": [],
                    "correlation": correlation_trace,
                },
            }

        evaluations = [self.engine._evaluate_candidate(candidate, scoring_signals, payload.anomalies) for candidate in candidates]
        evaluations.sort(
            key=lambda item: (
                -float(item.confidence),
                -float(item.weighted_score),
                str(item.candidate),
            )
        )
        best = evaluations[0]

        raw_best_confidence = float(best.confidence)
        best_confidence = round(
            max(0.0, raw_best_confidence * (1.0 - confidence_penalty)),
            12,
        )
        ties = [
            item for item in evaluations
            if abs(float(item.confidence) - raw_best_confidence) <= self.policy.tie_epsilon
        ]

        supporting = list(best.supporting_signals)
        conflicting = list(best.conflicting_signals)
        supporting_groups = sorted({entry.group for entry in supporting})
        overall_groups = _contributing_groups(self.engine, scoring_signals)

        limitations: List[str] = []
        verdict = "attributed"
        region: Optional[str] = str(best.candidate)

        if len(ties) > 1:
            verdict = "inconclusive"
            region = None
            limitations.append("Tie between top candidate scores.")
        if best_confidence < self.policy.confidence_threshold:
            verdict = "inconclusive"
            region = None
            limitations.append(
                f"Confidence {best_confidence:.12f} below threshold {self.policy.confidence_threshold:.12f}."
            )
        if len(supporting) < self.policy.min_supporting_signals:
            verdict = "inconclusive"
            region = None
            limitations.append(
                f"Supporting signals {len(supporting)} below minimum {self.policy.min_supporting_signals}."
            )
        if len(overall_groups) < self.policy.min_contributing_groups:
            verdict = "inconclusive"
            region = None
            limitations.append(
                f"Contributing groups {len(overall_groups)} below minimum {self.policy.min_contributing_groups}."
            )
        if len(supporting_groups) < self.policy.min_distinct_supporting_groups:
            verdict = "inconclusive"
            region = None
            limitations.append(
                "Distinct supporting groups "
                f"{len(supporting_groups)} below minimum {self.policy.min_distinct_supporting_groups}."
            )
        if rejected:
            limitations.append(
                f"{len(rejected)} non-attributable or excluded signals reduced evidence quality."
            )
        if anonymization_detected:
            limitations.append(
                "Anonymization indicators detected: "
                + ", ".join(anonymization_indicators)
            )
            limitations.append(
                f"Correlation confidence penalty applied: {confidence_penalty:.6f}."
            )
        if anonymization_confidence >= 0.70:
            verdict = "inconclusive"
            region = None
            limitations.append(
                f"High anonymization confidence ({anonymization_confidence:.6f}) forces abstention."
            )
        limitations.extend(correlation_reasoning)

        support_rows = [asdict(entry) for entry in supporting]
        conflict_rows = [asdict(entry) for entry in conflicting]
        support_rows.sort(key=lambda row: (-float(row.get("effective_weight", 0.0)), row["signal_id"]))
        conflict_rows.sort(key=lambda row: (-float(row.get("penalty", 0.0)), row["signal_id"]))

        anomalies = [dict(item) for item in payload.anomalies]
        anomalies.append(
            {
                "type": "correlation_inference",
                "correlation_enabled": self.use_correlation,
                "anonymization_detected": anonymization_detected,
                "anonymization_confidence": anonymization_confidence,
                "indicators": anonymization_indicators,
                "downgraded_signal_ids": downgraded_signal_ids,
                "boosted_signal_ids": boosted_signal_ids,
            }
        )
        if float(best.penalty_score) > 0:
            anomalies.append(
                {
                    "type": "scoring_conflict",
                    "candidate": str(best.candidate),
                    "penalty_score": float(best.penalty_score),
                    "conflicting_signals": len(conflicting),
                }
            )
        anomalies.sort(key=lambda row: json.dumps(row, sort_keys=True, default=str))

        result = {
            "region": region,
            "confidence": best_confidence,
            "verdict": verdict,
            "signals_used": support_rows + conflict_rows,
            "signals_rejected": rejected,
            "anomalies": anomalies,
            "limitations": limitations,
            "authentication": payload.authentication or {},
        }
        result["explanation"] = _build_explanation(
            verdict=verdict,
            region=region,
            confidence=float(result["confidence"]),
            top_supporting=support_rows[:3],
            top_conflicting=conflict_rows[:3],
            limitations=limitations,
        )

        trace = {
            "evidence_id": payload.evidence_id,
            "source": payload.source,
            "input_type": payload.input_type,
            "signal_count": len(payload.signals),
            "candidate_count": len(candidates),
            "candidates": [
                {
                    "candidate": str(item.candidate),
                    "supporting_score": float(item.supporting_score),
                    "penalty_score": float(item.penalty_score),
                    "weighted_score": float(item.weighted_score),
                    "max_possible_score": float(item.max_possible_score),
                    "confidence": float(item.confidence),
                    "confidence_post_correlation_penalty": round(
                        float(item.confidence) * (1.0 - confidence_penalty),
                        12,
                    ),
                    "supporting_count": len(item.supporting_signals),
                    "conflicting_count": len(item.conflicting_signals),
                    "supporting_groups": list(item.supporting_groups),
                }
                for item in evaluations
            ],
            "winner": region,
            "verdict": verdict,
            "abstention_reasons": limitations if verdict == "inconclusive" else [],
            "correlation": correlation_trace,
            "authentication": payload.authentication or {},
        }

        return {"result": result, "trace": trace}


def parse_input_path(input_path: str) -> List[str]:
    path = Path(input_path).expanduser().resolve()
    if path.is_dir():
        files = sorted(
            [
                file
                for file in path.iterdir()
                if file.is_file() and file.suffix.lower() in {".eml", ".json"}
            ],
            key=lambda value: value.name,
        )
        return [str(file) for file in files]
    return [str(path)]


def evaluate_inputs(
    input_path: str,
    runtime: RuntimeConfig,
    use_correlation: bool = True,
) -> Dict[str, Any]:
    runner = AttributionRunner(runtime, use_correlation=use_correlation)
    item_paths = parse_input_path(input_path)
    reports: List[Dict[str, Any]] = []
    for path in item_paths:
        try:
            item = load_analysis_input(path)
            evaluated = runner.analyze(item)
            reports.append(
                {
                    "evidence_id": item.evidence_id,
                    "source": item.source,
                    "result": evaluated["result"],
                    "trace": evaluated["trace"],
                }
            )
        except Exception as exc:
            evidence_id = _hash_json({"source": path, "error": str(exc)})
            fallback = AttributionResult(
                region=None,
                confidence=0.0,
                signals_used=[],
                signals_rejected=[],
                anomalies=[],
                limitations=[f"Analysis error: {type(exc).__name__}: {exc}"],
                verdict="inconclusive",
            )
            reports.append(
                {
                    "evidence_id": evidence_id,
                    "source": path,
                    "result": {
                        "region": fallback.region,
                        "confidence": fallback.confidence,
                        "verdict": fallback.verdict,
                        "signals_used": fallback.signals_used,
                        "signals_rejected": fallback.signals_rejected,
                        "anomalies": fallback.anomalies,
                        "limitations": fallback.limitations,
                        "explanation": "Inconclusive attribution due to processing error.",
                    },
                    "trace": {
                        "evidence_id": evidence_id,
                        "source": path,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                }
            )

    summary = {
        "total_inputs": len(reports),
        "attributed": sum(1 for row in reports if row["result"]["verdict"] == "attributed"),
        "inconclusive": sum(1 for row in reports if row["result"]["verdict"] == "inconclusive"),
    }

    return {
        "summary": summary,
        "reports": reports,
    }
