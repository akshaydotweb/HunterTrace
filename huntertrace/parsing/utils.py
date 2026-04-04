"""Utility helpers for RFC-style header parsing and normalization."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_BRACKET_RE = re.compile(r"\[([0-9A-Fa-f:]+)\]")
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9-]{1,63}$")
_IPV6_TOKEN_RE = re.compile(r"^[0-9A-Fa-f:]+$")
_PROVIDER_BASE_DOMAINS = {
    "gmail.com",
    "google.com",
    "outlook.com",
    "office365.com",
    "live.com",
    "hotmail.com",
    "yahoo.com",
}


def normalize_whitespace(value: str) -> str:
    """Collapse linear whitespace while preserving token order."""

    return re.sub(r"\s+", " ", value or "").strip()


def parse_rfc_datetime_to_utc(value: str) -> Optional[datetime]:
    """Parse RFC-style date-time strings into timezone-aware UTC datetimes."""

    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except Exception:
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_ip(value: str) -> Optional[str]:
    """Extract first IP address (IPv4 preferred, then bracketed IPv6) from text."""

    if not value:
        return None

    ipv4 = _IPV4_RE.search(value)
    if ipv4:
        return ipv4.group(0)

    ipv6 = _IPV6_BRACKET_RE.search(value)
    if ipv6:
        return ipv6.group(1)

    if ":" in value:
        parts = re.findall(r"[0-9A-Fa-f:]{2,}", value)
        for part in parts:
            if part.count(":") >= 2:
                return part

    return None


def hostname_approx_equal(left: Optional[str], right: Optional[str]) -> bool:
    """Approximate host continuity match between adjacent hops."""

    if not left or not right:
        return False

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
    if lbase and rbase and lbase == rbase and lbase in _PROVIDER_BASE_DOMAINS:
        return True

    return False


def canonicalize_hostname(host: Optional[str]) -> Optional[str]:
    """Normalize host token for continuity checks."""

    if not host:
        return None
    cleaned = host.strip().lower().strip("[]<>() \t\r\n")
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]
    if not cleaned:
        return None

    labels = cleaned.split(".")
    while labels and labels[0] in {"smtp", "mail", "mx", "relay"}:
        labels.pop(0)
    if not labels:
        return cleaned
    return ".".join(labels)


def base_domain(host: Optional[str]) -> Optional[str]:
    """Return coarse base domain for provider continuity comparison."""

    if not host:
        return None
    token = host.strip(".")
    if not token or "." not in token:
        return token
    labels = token.split(".")
    if len(labels) < 2:
        return token
    return ".".join(labels[-2:])


def validate_hostname(host: Optional[str]) -> bool:
    """
    Validate host token for basic domain/IP sanity.

    Accepts:
    - domain-style hostnames with non-empty labels
    - IPv4 literals
    - IPv6-like tokens
    """

    if not host:
        return False

    token = host.strip().strip("[]<>()")
    if not token:
        return False

    if _IPV4_RE.fullmatch(token):
        return True

    if ":" in token and _IPV6_TOKEN_RE.fullmatch(token) and token.count(":") >= 2:
        return True

    if "." not in token:
        return False

    labels = token.split(".")
    if any(label == "" for label in labels):
        return False
    if len(token) > 253:
        return False

    for label in labels:
        if not _DOMAIN_LABEL_RE.fullmatch(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False

    return True
