from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Optional


@dataclass
class ParsedEmail:
    raw_email: str
    headers: list[tuple[str, str]]
    body_text: Optional[str]
    body_html: Optional[str]
    message_id: Optional[str]
    date_raw: Optional[str]
    date_parsed_utc: Optional[datetime]


@dataclass
class Hop:
    raw: str
    from_host: Optional[str]
    by_host: Optional[str]
    ip: Optional[str]
    timestamp: Optional[datetime]


@dataclass
class Signals:
    first_hop_ip: Optional[str]
    all_ips: list[str]
    hop_count: int
    timezone_offset: Optional[str]
    send_hour_utc: Optional[int]
    spf_client_ip: Optional[str]
    dkim_domain: Optional[str]
    message_id_domain: Optional[str]
    webmail_detected: bool


@dataclass
class ValidatedSignals:
    signals: Signals
    trust_scores: dict[str, float]
    anomalies: list[str]
    rejected_signals: list[str]


@dataclass
class AttributionResult:
    region: Optional[str]
    confidence: float
    evidence: list[str]
    limitations: list[str]
    anomalies: list[str]
    verdict: Literal["high", "moderate", "low", "inconclusive"]