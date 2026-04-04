"""Typed models for HunterTrace Atlas header parsing and hop reconstruction."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class ValidationFlag(str, Enum):
    """Standard validation flags for hop-level parsing and chain validation."""

    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    TEMPORAL_ANOMALY = "TEMPORAL_ANOMALY"
    BROKEN_CHAIN = "BROKEN_CHAIN"
    POSSIBLE_INJECTION = "POSSIBLE_INJECTION"
    MALFORMED_HEADER = "MALFORMED_HEADER"
    MISSING_FIELDS = "MISSING_FIELDS"


@dataclass
class Hop:
    """Structured representation of one visible SMTP hop from a Received header."""

    index: int
    from_host: Optional[str]
    from_ip: Optional[str]
    by_host: Optional[str]
    protocol: Optional[str]
    timestamp: Optional[datetime]
    raw_header: str
    parse_confidence: float
    validation_flags: List[ValidationFlag] = field(default_factory=list)


@dataclass
class HopChain:
    """Ordered and validated list of hops reconstructed from Received headers."""

    hops: List[Hop]
    anomalies: List[str]
    completeness_score: float
