"""Parser for individual Received header values."""

from __future__ import annotations

import re
from typing import Optional

from huntertrace.parsing.models import Hop, ValidationFlag
from huntertrace.parsing.utils import (
    extract_ip,
    normalize_whitespace,
    parse_rfc_datetime_to_utc,
    validate_hostname,
)

_FROM_RE = re.compile(r"\bfrom\s+([^\s\(;]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s\(;]+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+([A-Za-z0-9_-]+)", re.IGNORECASE)


class ReceivedParser:
    """Extract best-effort fields from one normalized Received header."""

    @staticmethod
    def parse_received(raw_received: str, index: int) -> Hop:
        """Parse one Received header into a Hop model with defensive fallbacks."""

        normalized = normalize_whitespace(raw_received)
        flags = []

        from_host = ReceivedParser._extract_host(_FROM_RE, normalized)
        by_host = ReceivedParser._extract_host(_BY_RE, normalized)
        protocol = ReceivedParser._extract_protocol(normalized)
        from_ip = ReceivedParser._extract_from_ip(normalized)
        timestamp = ReceivedParser._extract_timestamp(normalized)

        extraction_hits = sum(
            [
                1 if from_host else 0,
                1 if from_ip else 0,
                1 if by_host else 0,
                1 if protocol else 0,
                1 if timestamp else 0,
            ]
        )

        parse_confidence = min(1.0, extraction_hits / 5.0)

        malformed_host = False
        if from_host and not validate_hostname(from_host):
            malformed_host = True
            flags.append(ValidationFlag.MALFORMED_HEADER)
        if by_host and not validate_hostname(by_host):
            malformed_host = True
            flags.append(ValidationFlag.MALFORMED_HEADER)
        if malformed_host:
            parse_confidence = max(0.0, parse_confidence - 0.2)

        if extraction_hits <= 1:
            flags.append(ValidationFlag.MALFORMED_HEADER)
        if not from_host or not by_host:
            flags.append(ValidationFlag.MISSING_FIELDS)
        if timestamp is None:
            flags.append(ValidationFlag.INVALID_TIMESTAMP)

        return Hop(
            index=index,
            from_host=from_host,
            from_ip=from_ip,
            by_host=by_host,
            protocol=protocol,
            timestamp=timestamp,
            raw_header=raw_received,
            parse_confidence=parse_confidence,
            validation_flags=flags,
        )

    @staticmethod
    def _extract_host(pattern: re.Pattern[str], text: str) -> Optional[str]:
        match = pattern.search(text)
        if not match:
            return None
        host = match.group(1).strip("<>()[]")
        return host or None

    @staticmethod
    def _extract_protocol(text: str) -> Optional[str]:
        match = _WITH_RE.search(text)
        if not match:
            return None
        return match.group(1).upper()

    @staticmethod
    def _extract_from_ip(text: str) -> Optional[str]:
        from_clause_match = _FROM_RE.search(text)
        segment = text
        if from_clause_match:
            start = from_clause_match.start()
            end = text.find(" by ", start)
            if end > start:
                segment = text[start:end]
        return extract_ip(segment)

    @staticmethod
    def _extract_timestamp(text: str):
        if ";" not in text:
            return None
        # RFC style dates are after final semicolon in most Received lines.
        date_part = text.rsplit(";", 1)[-1].strip()
        return parse_rfc_datetime_to_utc(date_part)
