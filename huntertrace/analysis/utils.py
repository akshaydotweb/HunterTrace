"""Utilities for deterministic correlation analysis."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from huntertrace.analysis.models import Contradiction, Relationship, Signal

_HOP_INDEX_RE = re.compile(r"\[(\d+)\]")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_COMMON_PREFIXES = {"smtp", "mail", "mx", "relay"}


def clamp01(value: float) -> float:
    """Clamp a numeric value into [0, 1]."""

    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def severity_penalty(severity: str) -> float:
    """Return deterministic penalty for contradiction severity."""

    mapping = {"low": 0.05, "medium": 0.10, "high": 0.20}
    return mapping.get((severity or "").lower(), 0.0)


def parse_hop_index(source: str) -> int:
    """Extract hop index from a signal source token (e.g., Received[3])."""

    if not source:
        return 10**9
    match = _HOP_INDEX_RE.search(source)
    if match:
        return int(match.group(1))
    digits = re.findall(r"\d+", source)
    if digits:
        return int(digits[0])
    return 10**9


def canonicalize_hostname(host: Optional[str]) -> Optional[str]:
    """Normalize hostname for structural/infrastructure relationship checks."""

    if not host:
        return None

    token = str(host).strip().lower().strip("[]<>() \t\r\n")
    token = token.rstrip(".")
    if not token:
        return None
    if _IPV4_RE.fullmatch(token):
        return token

    labels = [label for label in token.split(".") if label]
    while labels and labels[0] in _COMMON_PREFIXES:
        labels.pop(0)
    if not labels:
        return token
    return ".".join(labels)


def base_domain(host: Optional[str]) -> Optional[str]:
    """Extract coarse base domain from host token."""

    canon = canonicalize_hostname(host)
    if not canon:
        return None
    if _IPV4_RE.fullmatch(canon) or ":" in canon:
        return canon

    labels = canon.split(".")
    if len(labels) < 2:
        return canon
    return ".".join(labels[-2:])


def host_related(left: Optional[str], right: Optional[str]) -> bool:
    """Evaluate whether two hosts are reasonably related."""

    lval = canonicalize_hostname(left)
    rval = canonicalize_hostname(right)
    if not lval or not rval:
        return False
    if lval == rval:
        return True
    if lval.endswith("." + rval) or rval.endswith("." + lval):
        return True
    lbase = base_domain(lval)
    rbase = base_domain(rval)
    return bool(lbase and rbase and lbase == rbase)


def is_private_ip(value: Optional[str]) -> bool:
    """Return True if the provided token is a private IP literal."""

    if not value:
        return False
    token = str(value).strip()
    try:
        parsed = ipaddress.ip_address(token)
        return bool(parsed.is_private)
    except ValueError:
        return False


def parse_datetime(value: Any) -> Optional[datetime]:
    """Parse ISO 8601 timestamp values used by the signal layer."""

    if value is None:
        return None
    token = str(value).strip()
    if not token:
        return None
    try:
        if token.endswith("Z"):
            token = token[:-1] + "+00:00"
        return datetime.fromisoformat(token)
    except ValueError:
        return None


def normalize_to_list(value: Any) -> List[str]:
    """Normalize arbitrary value into a deterministic list of string tokens."""

    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def anomaly_tokens(signals: Sequence[Signal]) -> List[str]:
    """Extract uppercase anomaly tokens from signal values/validation flags."""

    tokens: List[str] = []
    for signal in signals:
        if signal.name in {"anomaly_types", "structure.anomaly", "temporal.anomaly_flag"}:
            tokens.extend(item.upper() for item in normalize_to_list(signal.value))
        for flag in signal.validation_flags:
            tokens.append(str(flag).upper())
    return sorted(set(tokens))


def sort_signals(signals: Iterable[Signal]) -> List[Signal]:
    """Return deterministically sorted signals."""

    return sorted(
        signals,
        key=lambda item: (
            parse_hop_index(item.source),
            item.source,
            item.name,
            repr(item.value),
            item.signal_id,
        ),
    )


def normalize_signals(signals: Sequence[Any]) -> List[Signal]:
    """Normalize mixed signal payloads into deterministic Signal objects."""

    extracted: List[Dict[str, Any]] = []

    for item in signals:
        if isinstance(item, Signal):
            extracted.append(
                {
                    "name": item.name,
                    "value": item.value,
                    "source": item.source,
                    "validation_flags": list(item.validation_flags),
                    "confidence": item.confidence,
                    "evidence": item.evidence,
                    "signal_id": item.signal_id,
                }
            )
            continue

        if isinstance(item, dict):
            getter = item.get
        else:
            getter = lambda key, default=None: getattr(item, key, default)

        confidence = getter("confidence", None)
        if confidence is None:
            confidence = getter("confidence_initial", 0.5)
        evidence = getter("evidence", None)
        if evidence in (None, ""):
            evidence = getter("raw_reference", "")
        validation_flags = getter("validation_flags", []) or []
        normalized_flags = [str(getattr(flag, "value", flag)) for flag in validation_flags]

        extracted.append(
            {
                "name": str(getter("name", "unknown")),
                "value": getter("value", None),
                "source": str(getter("source", "unknown")),
                "validation_flags": normalized_flags,
                "confidence": float(confidence),
                "evidence": str(evidence),
                "signal_id": getter("signal_id", None),
            }
        )

    extracted = sorted(
        extracted,
        key=lambda row: (
            parse_hop_index(str(row["source"])),
            str(row["source"]),
            str(row["name"]),
            repr(row["value"]),
            str(row["evidence"]),
        ),
    )

    dedupe_counts: Dict[Tuple[str, str, str], int] = {}
    normalized: List[Signal] = []
    for row in extracted:
        dedupe_key = (str(row["source"]), str(row["name"]), repr(row["value"]))
        count = dedupe_counts.get(dedupe_key, 0) + 1
        dedupe_counts[dedupe_key] = count
        signal_id = row["signal_id"] or f"{row['source']}::{row['name']}::{count}"
        normalized.append(
            Signal(
                signal_id=str(signal_id),
                name=str(row["name"]),
                value=row["value"],
                source=str(row["source"]),
                validation_flags=tuple(sorted(set(row["validation_flags"]))),
                confidence=clamp01(float(row["confidence"])),
                evidence=str(row["evidence"]),
            )
        )

    return sort_signals(normalized)


def sort_contradictions(items: Iterable[Contradiction]) -> List[Contradiction]:
    """Sort contradictions in deterministic order."""

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(
        items,
        key=lambda item: (
            severity_rank.get(item.severity, 3),
            item.type,
            item.reason,
            tuple(item.signals),
        ),
    )


def sort_relationships(items: Iterable[Relationship]) -> List[Relationship]:
    """Sort relationships in deterministic order."""

    rank = {"conflicts": 0, "supports": 1, "derived_from": 2}
    return sorted(
        items,
        key=lambda item: (
            rank.get(item.type, 3),
            item.source_signal,
            item.target_signal,
            item.rationale,
        ),
    )

