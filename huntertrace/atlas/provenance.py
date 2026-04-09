#!/usr/bin/env python3
"""
huntertrace/atlas/provenance.py
================================
Header provenance classification utilities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class ProvenanceClass(str, Enum):
    sender_controlled = "sender_controlled"
    sender_mua_generated = "sender_mua_generated"
    sending_mta_generated = "sending_mta_generated"
    intermediary_relay_generated = "intermediary_relay_generated"
    recipient_mta_generated = "recipient_mta_generated"
    cryptographic = "cryptographic"


TRUST_WEIGHT_BASE = {
    ProvenanceClass.cryptographic: 1.0,
    ProvenanceClass.recipient_mta_generated: 0.9,
    ProvenanceClass.intermediary_relay_generated: 0.7,
    ProvenanceClass.sending_mta_generated: 0.6,
    ProvenanceClass.sender_mua_generated: 0.4,
    ProvenanceClass.sender_controlled: 0.2,
}

PROVENANCE_RANK = {
    ProvenanceClass.sender_controlled: 0,
    ProvenanceClass.sender_mua_generated: 1,
    ProvenanceClass.sending_mta_generated: 2,
    ProvenanceClass.intermediary_relay_generated: 3,
    ProvenanceClass.recipient_mta_generated: 4,
    ProvenanceClass.cryptographic: 5,
}

_HEADER_TOKEN_RE = re.compile(r"([a-z0-9-]+)", re.IGNORECASE)
_RECEIVED_INDEX_RE = re.compile(r"received\[(\d+)\]", re.IGNORECASE)
_EML_RECEIVED_RE = re.compile(r"eml\.header\.received\[(\d+)\]", re.IGNORECASE)


@dataclass(frozen=True)
class HopContext:
    hop_index: Optional[int] = None
    hop_count: Optional[int] = None


def trust_weight_for(provenance: ProvenanceClass) -> float:
    return float(TRUST_WEIGHT_BASE.get(provenance, 0.2))


def infer_header_name(signal_name: Optional[str], source_hint: Optional[str]) -> Optional[str]:
    if source_hint:
        lowered = source_hint.lower()
        if "authentication-results" in lowered:
            return "Authentication-Results"
        if "received-spf" in lowered:
            return "Received-SPF"
        if "dkim-signature" in lowered or "dkim" in lowered:
            return "DKIM-Signature"
        if "arc-" in lowered:
            return "ARC-*"
        if "message-id" in lowered:
            return "Message-ID"
        if "mime-version" in lowered:
            return "MIME-Version"
        if "user-agent" in lowered:
            return "User-Agent"
        if "subject" in lowered:
            return "Subject"
        if "from" in lowered:
            return "From"
        if "date" in lowered:
            return "Date"
        if "received" in lowered:
            return "Received"
        match = _HEADER_TOKEN_RE.search(source_hint)
        if match:
            return match.group(1)

    if not signal_name:
        return None
    name = signal_name.lower()
    if name in {"timezone_offset", "send_hour_utc", "send_hour_local"}:
        return "Date"
    if name in {"message_id_domain", "message_id"}:
        return "Message-ID"
    if name in {"dkim_domain", "dkim_valid", "dkim_status", "dkim_failure_reason"}:
        return "DKIM-Signature"
    if name in {"spf_client_ip", "spf_result", "spf_aligned"}:
        return "Authentication-Results"
    if name in {"dmarc_result", "dmarc_status", "dmarc_policy"}:
        return "Authentication-Results"
    if name in {"dkim_aligned"}:
        return "Authentication-Results"
    if name in {"first_hop_ip", "all_ips", "hop_count", "webmail_detected"}:
        return "Received"
    return None


def extract_hop_index(source_hint: Optional[str]) -> Optional[int]:
    if not source_hint:
        return None
    match = _RECEIVED_INDEX_RE.search(source_hint)
    if match:
        return int(match.group(1))
    match = _EML_RECEIVED_RE.search(source_hint)
    if match:
        return int(match.group(1))
    return None


def classify_header(header_name: Optional[str], hop_context: Optional[HopContext] = None) -> ProvenanceClass:
    if not header_name:
        return ProvenanceClass.sender_controlled
    name = header_name.strip().lower()

    if name in {"date", "subject", "from"}:
        return ProvenanceClass.sender_controlled
    if name in {"message-id", "mime-version", "user-agent"}:
        return ProvenanceClass.sender_mua_generated
    if name == "dkim-signature" or name.startswith("arc-") or name == "arc-*":
        return ProvenanceClass.cryptographic
    if name in {"received-spf", "authentication-results"}:
        return ProvenanceClass.recipient_mta_generated
    if name == "received":
        hop_index = hop_context.hop_index if hop_context else None
        if hop_index is not None and hop_index == 0:
            return ProvenanceClass.sending_mta_generated
        return ProvenanceClass.intermediary_relay_generated

    return ProvenanceClass.sender_controlled


def derive_provenance(
    *,
    signal_name: Optional[str],
    source_hint: Optional[str],
    hop_index: Optional[int] = None,
    hop_count: Optional[int] = None,
) -> Tuple[Optional[str], ProvenanceClass, float]:
    header_name = infer_header_name(signal_name, source_hint)
    provenance = classify_header(header_name, HopContext(hop_index=hop_index, hop_count=hop_count))
    return header_name, provenance, trust_weight_for(provenance)
