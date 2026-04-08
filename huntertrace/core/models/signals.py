#!/usr/bin/env python3
"""
huntertrace/core/signals.py
=============================
Layer 2 — Signal Construction.

Single public entry point:

    signals = build_signals(extracted)   # List[ForensicSignal]

Responsibilities
----------------
- Accept an ExtractedEmail (Layer 1 output)
- Construct discrete, named ForensicSignal objects from raw header fields
- Return the complete list; emit nothing else

Hard constraints (Phase 1 architecture spec, Layer 2 scope)
-----------------------------------------------------------
  NO INFERENCE   — values are never mapped to countries, regions, or verdicts
  NO TRUST       — every signal is constructed with TrustTier.UNTRUSTED;
                   trust assignment from config/trust_model.yaml is Layer 2b
                   (TrustAssigner), not performed here
  NO VALIDATION  — anomaly detection is Layer 3's responsibility
  NO ENRICHMENT  — GeoIP / WHOIS / ASN lookups are Layer 4's responsibility
  NO SCORING     — likelihood ratios and Bayesian weights are Layer 5's resp.
  NO MUTATION    — the ExtractedEmail and its ReceivedHops are never modified;
                   all collections produced here are new objects

Signal catalogue (this module)
-------------------------------
  first_hop_ip        INFRASTRUCTURE      Received[0].ip_v4 or ip_v6
  all_ips             INFRASTRUCTURE      All IPs across all hops (list)
  hop_count           BEHAVIORAL          Number of Received: headers
  timezone_offset     GEOGRAPHIC_INDIRECT Raw tz offset from Date: header
  send_hour_utc       BEHAVIORAL          Hour-of-day in UTC from Date:
  dkim_domain         AUTHENTICATION      d= tag from first DKIM-Signature
  message_id_domain   INFRASTRUCTURE      Substring after "@" in Message-ID
  spf_client_ip       INFRASTRUCTURE      client-ip= from Received-SPF
  webmail_detected    INFRASTRUCTURE      Bool — known webmail in chain

Extraction methods used
-----------------------
  - Direct field access on ReceivedHop / ExtractedEmail attributes
  - re.search() for structured sub-field extraction (tz, hour, DKIM, SPF)
  - str.partition() for domain extraction
  - No external libraries beyond stdlib re, uuid, datetime

No external dependencies.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from huntertrace.core.models.extracted import ExtractedEmail, ReceivedHop

# Placeholder classes if signal types are not available
# This is a pre-existing issue in the codebase where signal type definitions are missing
class ForensicSignal:
    """Placeholder for ForensicSignal when actual definition is unavailable."""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class SignalClass:
    """Placeholder for SignalClass enum."""
    INFRASTRUCTURE = "INFRASTRUCTURE"
    BEHAVIORAL = "BEHAVIORAL"
    GEOGRAPHIC_INDIRECT = "GEOGRAPHIC_INDIRECT"
    AUTHENTICATION = "AUTHENTICATION"

class TrustTier:
    """Placeholder for TrustTier enum."""
    TRUSTED = "TRUSTED"
    PARTIALLY_TRUSTED = "PARTIALLY_TRUSTED"
    UNTRUSTED = "UNTRUSTED"

class ValidationFlag:
    """Placeholder for ValidationFlag."""
    pass

class SourceType:
    """Placeholder for SourceType."""
    pass

class EnrichmentUncertainty:
    """Placeholder for EnrichmentUncertainty."""
    pass

class EnrichmentData:
    """Placeholder for EnrichmentData."""
    pass

class EnrichmentResult:
    """Placeholder for EnrichmentResult."""
    pass

class SignalBundle:
    """Placeholder for SignalBundle."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE-LEVEL CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Trust tier applied to every signal constructed here.
# Per architecture spec: trust assignment is config-driven (trust_model.yaml)
# and is applied by TrustAssigner (Layer 2b).  Until that pass runs, every
# signal carries UNTRUSTED as a conservative safe default.
_DEFAULT_TRUST: TrustTier = TrustTier.UNTRUSTED
_DEFAULT_TRUST_RATIONALE: str = (
    "Default — trust not yet assigned from config/trust_model.yaml. "
    "TrustAssigner (Layer 2b) must run before this signal is used for inference."
)

# Known webmail provider substrings matched case-insensitively against
# ReceivedHop.by_hostname and from_hostname.
# Presence → webmail_detected = True.
# This is a detection heuristic only; it implies nothing about trust or location.
_WEBMAIL_PROVIDER_SUBSTRINGS: tuple = (
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.",        # yahoo.co.in, yahoo.co.uk, etc.
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "protonmail.com",
    "proton.me",
    "mail.ru",
    "yandex.ru",
    "yandex.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "zoho.com",
    "aol.com",
    "gmx.com",
    "gmx.net",
    "web.de",
    "tutanota.com",
    "fastmail.com",
    "rediffmail.com",
    "naver.com",
    "163.com",
    "126.com",
    "qq.com",
)

# RFC 2822 timezone offset at the end of a Date: header or ISO 8601 string.
# Matches "+0530", "-0800", "+05:30", "-08:00".
# Group 1: full matched offset string including sign.
_RE_TZ_OFFSET: re.Pattern = re.compile(
    r"([+-]\d{2}:?\d{2})\s*$"
)

# Hour and minute from ISO 8601 datetime: "2026-02-20T19:51:57+05:30"
# Group 1: hour ("19"), Group 2: minute ("51")
_RE_ISO_HOUR: re.Pattern = re.compile(
    r"T(\d{2}):(\d{2}):\d{2}"
)

# UTC offset from ISO 8601 string: trailing "+HH:MM" or "-HH:MM" or "Z"
_RE_ISO_TZ: re.Pattern = re.compile(
    r"([+-])(\d{2}):(\d{2})$|Z$"
)

# d= tag in a DKIM-Signature header.
# Tag-list items are separated by ";"; the d= tag value ends at ";" or EOL.
_RE_DKIM_D_TAG: re.Pattern = re.compile(
    r"(?:^|;)\s*d\s*=\s*([^\s;]+)",
    re.IGNORECASE,
)

# client-ip= parameter in a Received-SPF: header (RFC 7208 §9.1).
_RE_SPF_CLIENT_IP: re.Pattern = re.compile(
    r"client-ip\s*=\s*([^\s;,)]+)",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
#  INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _make_signal(
    *,
    evidence_id:       str,
    name:              str,
    value,
    signal_class:      SignalClass,
    source_field:      str,
    extraction_method: str,
    hop_position:      Optional[int] = None,
    constructed_at:    str,
) -> ForensicSignal:
    """
    Sole constructor for ForensicSignals within this module.

    All signals pass through here so field population is uniform and the
    correct defaults are applied to all downstream annotation fields.
    """
    return ForensicSignal(
        signal_id              = str(uuid.uuid4()),
        evidence_id            = evidence_id,
        name                   = name,
        value                  = value,
        signal_class           = signal_class,
        source_field           = source_field,
        extraction_method      = extraction_method,
        hop_position           = hop_position,
        constructed_at         = constructed_at,
        trust_tier             = _DEFAULT_TRUST,
        trust_rationale        = _DEFAULT_TRUST_RATIONALE,
        # Layer 3 populates:
        validation_flags       = [],    # new list per signal — never shared
        anomaly_detail         = None,
        # Layer 4 populates:
        enrichment             = None,
        # Layer 5 populates — all None until inference:
        bayesian_weight        = None,
        reliability_multiplier = None,
        effective_lr           = None,
        posterior_delta        = None,
        contributed_to         = None,
        excluded_reason        = None,
    )


def _utc_now_iso() -> str:
    """Return current UTC time as an ISO 8601 string with Z suffix."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _extract_timezone_offset(date_raw: str) -> Optional[str]:
    """
    Extract the raw timezone offset string from a Date: header value.

    Returns the matched string exactly as it appears (e.g. "+0530",
    "-08:00") with no normalisation.  Returns None when no offset
    pattern is found.
    """
    if not date_raw:
        return None
    m = _RE_TZ_OFFSET.search(date_raw.strip())
    return m.group(1) if m else None


def _extract_send_hour_utc(date_raw: str) -> Optional[int]:
    """
    Extract the UTC hour-of-day (0–23) from a Date: header value.

    Parameters
    ----------
    date_raw : str
        Verbatim Date: header value or the ISO 8601 string produced by
        email.utils.parsedate_to_datetime().isoformat() stored in
        ExtractedEmail.date_raw by the extraction layer.

    Returns
    -------
    int (0–23) or None on any parse failure.  No exceptions are raised.

    Algorithm
    ---------
    1. Match the local hour from the ISO 8601 "THH:" pattern.
    2. Match the UTC offset (±HH:MM or Z) from the trailing portion.
    3. Compute UTC hour = (local_hour × 60 − offset_minutes) // 60 mod 24.

    Limitations (deliberate)
    ------------------------
    - RFC 2822 strings without a preceding ISO 8601 parse (step by
      Layer 1) return None; extracting hours from raw RFC 2822 strings
      would duplicate extraction-layer logic.
    - DST is not resolved; the offset in the header is taken as-is.
    """
    if not date_raw:
        return None

    hour_match = _RE_ISO_HOUR.search(date_raw)
    if not hour_match:
        return None
    local_hour   = int(hour_match.group(1))
    local_minute = int(hour_match.group(2))
    local_total_minutes = local_hour * 60 + local_minute

    tz_match = _RE_ISO_TZ.search(date_raw)
    if not tz_match:
        # No trailing offset — treat as UTC
        return local_hour % 24

    full_match = tz_match.group(0)
    if full_match == "Z":
        return local_hour % 24

    sign_str = tz_match.group(1)         # "+" or "-"
    tz_h     = int(tz_match.group(2))
    tz_m     = int(tz_match.group(3))
    offset_minutes = tz_h * 60 + tz_m

    if sign_str == "+":
        # local = UTC + offset  →  UTC = local − offset
        utc_minutes = local_total_minutes - offset_minutes
    else:
        # local = UTC − offset  →  UTC = local + offset
        utc_minutes = local_total_minutes + offset_minutes

    return (utc_minutes // 60) % 24


def _extract_dkim_domain(dkim_signature_raws: List[str]) -> Optional[str]:
    """
    Return the d= tag value from the first DKIM-Signature header that
    contains one.  Returns None when no d= tag is found.

    No validation of the domain string is performed.
    Trailing dots (as sometimes appear in FQDN notation) are stripped.
    """
    for raw in dkim_signature_raws:
        m = _RE_DKIM_D_TAG.search(raw)
        if m:
            return m.group(1).strip().rstrip(".")
    return None


def _extract_message_id_domain(message_id: str) -> Optional[str]:
    """
    Return the domain portion of a Message-ID header value.

    RFC 2822 §3.6.4 form: "<local-part@domain>"
    Returns everything after the first "@", with trailing ">" and
    whitespace stripped.  Returns None when "@" is absent.
    """
    if not message_id or "@" not in message_id:
        return None
    domain = message_id.partition("@")[2].strip().rstrip(">").strip()
    return domain if domain else None


def _extract_spf_client_ip(received_spf_raw: Optional[str]) -> Optional[str]:
    """
    Return the client-ip= value from a Received-SPF: header.

    Returns the raw IP string with no validation.
    Returns None when the header is absent or the pattern is not matched.
    """
    if not received_spf_raw:
        return None
    m = _RE_SPF_CLIENT_IP.search(received_spf_raw)
    return m.group(1).strip() if m else None


def _collect_all_ips(received_chain: List[ReceivedHop]) -> List[str]:
    """
    Collect all IP addresses from all hops in chronological order.

    For each hop: ip_v4 first, then ip_v6 (when both are present).
    Duplicates are preserved — deduplication is not this layer's
    responsibility.  Returns an empty list when the chain is empty.
    """
    ips: List[str] = []
    for hop in received_chain:
        if hop.ip_v4:
            ips.append(hop.ip_v4)
        if hop.ip_v6:
            ips.append(hop.ip_v6)
    return ips


def _detect_webmail(received_chain: List[ReceivedHop]) -> bool:
    """
    Return True when any hop's by_hostname or from_hostname contains a
    known webmail provider substring (case-insensitive).
    """
    for hop in received_chain:
        candidates: List[str] = []
        if hop.by_hostname:
            candidates.append(hop.by_hostname.lower())
        if hop.from_hostname:
            candidates.append(hop.from_hostname.lower())
        for hostname in candidates:
            for provider in _WEBMAIL_PROVIDER_SUBSTRINGS:
                if provider in hostname:
                    return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def build_signals(extracted: ExtractedEmail) -> List[ForensicSignal]:
    """
    Construct all ForensicSignals from one ExtractedEmail.

    Parameters
    ----------
    extracted : ExtractedEmail
        Layer 1 output.  This object and all objects it references are
        never mutated.

    Returns
    -------
    List[ForensicSignal]
        One entry per emitted signal.  A signal is omitted (not emitted
        as None) when its source field is absent or the extraction
        pattern produces no match.

    Signal emission order
    ---------------------
    1. first_hop_ip         — conditional on chain[0] having an IP
    2. all_ips              — always emitted (may have empty list value)
    3. hop_count            — always emitted
    4. timezone_offset      — conditional on Date: containing an offset
    5. send_hour_utc        — conditional on ISO hour + offset parseable
    6. dkim_domain          — conditional on DKIM-Signature d= present
    7. message_id_domain    — conditional on Message-ID containing "@"
    8. spf_client_ip        — conditional on Received-SPF client-ip= present
    9. webmail_detected     — always emitted (True or False)

    All signals share a single constructed_at timestamp captured once
    at the start of the call.
    """
    signals: List[ForensicSignal] = []
    eid = extracted.evidence_id
    ts  = _utc_now_iso()

    # ── 1. first_hop_ip ──────────────────────────────────────────────────────
    # Oldest hop (position=0) — closest to the sender.
    # Prefers ip_v4; falls back to ip_v6.
    first_hop: Optional[ReceivedHop] = (
        extracted.received_chain[0] if extracted.received_chain else None
    )
    if first_hop is not None:
        first_ip = first_hop.ip_v4 or first_hop.ip_v6
        if first_ip:
            ip_attr = "ip_v4" if first_hop.ip_v4 else "ip_v6"
            signals.append(_make_signal(
                evidence_id       = eid,
                name              = "first_hop_ip",
                value             = first_ip,
                signal_class      = SignalClass.INFRASTRUCTURE,
                source_field      = f"Received[0].{ip_attr}",
                extraction_method = (
                    "Direct field access on ReceivedHop.ip_v4 "
                    "(fallback ip_v6) at received_chain[0]"
                ),
                hop_position      = 0,
                constructed_at    = ts,
            ))

    # ── 2. all_ips ───────────────────────────────────────────────────────────
    # Every IP across the full Received: chain.
    # Always emitted — an empty list signals the absence of IP data.
    all_ips = _collect_all_ips(extracted.received_chain)
    signals.append(_make_signal(
        evidence_id       = eid,
        name              = "all_ips",
        value             = all_ips,
        signal_class      = SignalClass.INFRASTRUCTURE,
        source_field      = "Received: chain (all hops)",
        extraction_method = (
            "Collect ReceivedHop.ip_v4 then ip_v6 for each hop "
            "in chronological order; duplicates preserved"
        ),
        hop_position      = None,
        constructed_at    = ts,
    ))

    # ── 3. hop_count ─────────────────────────────────────────────────────────
    # Raw count of Received: headers as recorded by the extraction layer.
    # May exceed len(received_chain) when some headers could not be parsed.
    signals.append(_make_signal(
        evidence_id       = eid,
        name              = "hop_count",
        value             = extracted.hop_count,
        signal_class      = SignalClass.BEHAVIORAL,
        source_field      = "Received: header count",
        extraction_method = "Direct field access on ExtractedEmail.hop_count",
        hop_position      = None,
        constructed_at    = ts,
    ))

    # ── 4. timezone_offset ───────────────────────────────────────────────────
    # Raw UTC offset string from the Date: header.
    # Value preserved exactly as matched — no normalisation ("+05:30"
    # and "+0530" may both appear depending on the MUA).
    tz_offset = _extract_timezone_offset(extracted.date_raw or "")
    if tz_offset is not None:
        signals.append(_make_signal(
            evidence_id       = eid,
            name              = "timezone_offset",
            value             = tz_offset,
            signal_class      = SignalClass.GEOGRAPHIC_INDIRECT,
            source_field      = "Date: header",
            extraction_method = (
                r"re.search(r'([+-]\d{2}:?\d{2})\s*$') on "
                "ExtractedEmail.date_raw"
            ),
            hop_position      = None,
            constructed_at    = ts,
        ))

    # ── 5. send_hour_utc ─────────────────────────────────────────────────────
    # Hour-of-day (0–23) in UTC.
    # Omitted (not emitted as None) when date_raw cannot be parsed.
    send_hour = _extract_send_hour_utc(extracted.date_raw or "")
    if send_hour is not None:
        signals.append(_make_signal(
            evidence_id       = eid,
            name              = "send_hour_utc",
            value             = send_hour,
            signal_class      = SignalClass.BEHAVIORAL,
            source_field      = "Date: header",
            extraction_method = (
                "Extract local hour+minute via regex on ISO 8601 T-component; "
                "extract UTC offset via trailing ±HH:MM or Z; "
                "UTC hour = (local_hour_min + local_min − offset_min) // 60 mod 24"
            ),
            hop_position      = None,
            constructed_at    = ts,
        ))

    # ── 6. dkim_domain ───────────────────────────────────────────────────────
    # d= tag from the first DKIM-Signature header containing one.
    dkim_domain = _extract_dkim_domain(extracted.dkim_signature_raws)
    if dkim_domain is not None:
        signals.append(_make_signal(
            evidence_id       = eid,
            name              = "dkim_domain",
            value             = dkim_domain,
            signal_class      = SignalClass.AUTHENTICATION,
            source_field      = "DKIM-Signature: header",
            extraction_method = (
                r"re.search(r'(?:^|;)\s*d\s*=\s*([^\s;]+)', IGNORECASE) "
                "on first DKIM-Signature header; trailing dot stripped"
            ),
            hop_position      = None,
            constructed_at    = ts,
        ))

    # ── 7. message_id_domain ─────────────────────────────────────────────────
    # Domain portion of the Message-ID (everything after "@").
    mid_domain = _extract_message_id_domain(extracted.message_id)
    if mid_domain is not None:
        signals.append(_make_signal(
            evidence_id       = eid,
            name              = "message_id_domain",
            value             = mid_domain,
            signal_class      = SignalClass.INFRASTRUCTURE,
            source_field      = "Message-ID: header",
            extraction_method = (
                "str.partition('@')[2]; "
                "strip trailing '>' and whitespace"
            ),
            hop_position      = None,
            constructed_at    = ts,
        ))

    # ── 8. spf_client_ip ─────────────────────────────────────────────────────
    # client-ip= value from Received-SPF: (RFC 7208 §9.1).
    spf_ip = _extract_spf_client_ip(extracted.received_spf_raw)
    if spf_ip is not None:
        signals.append(_make_signal(
            evidence_id       = eid,
            name              = "spf_client_ip",
            value             = spf_ip,
            signal_class      = SignalClass.INFRASTRUCTURE,
            source_field      = "Received-SPF: header",
            extraction_method = (
                r"re.search(r'client-ip\s*=\s*([^\s;,)]+)', IGNORECASE) "
                "on ExtractedEmail.received_spf_raw"
            ),
            hop_position      = None,
            constructed_at    = ts,
        ))

    # ── 9. webmail_detected ───────────────────────────────────────────────────
    # Always emitted so the scoring layer can distinguish
    # "confirmed no webmail" from "signal absent".
    webmail = _detect_webmail(extracted.received_chain)
    signals.append(_make_signal(
        evidence_id       = eid,
        name              = "webmail_detected",
        value             = webmail,
        signal_class      = SignalClass.INFRASTRUCTURE,
        source_field      = "Received: chain (by_hostname, from_hostname)",
        extraction_method = (
            "Case-insensitive substring match of each hop's by_hostname "
            "and from_hostname against known webmail provider list"
        ),
        hop_position      = None,
        constructed_at    = ts,
    ))

    # ── 10. Authentication signals (Phase 8+) ──────────────────────────────────
    # Extracted from authentication validation (SPF, DKIM, DMARC, ARC).
    # Only emitted if authentication validation is performed; otherwise omitted.
    #
    # Note: These signals require the authentication.py module to be called
    # from the enrichment/scoring pipeline, not directly from this signal
    # construction layer. This preserves Layer 2's "no inference" constraint.
    # Authentication evaluation happens downstream and these signals are
    # injected into the signals list after this function returns.

    return signals
