#!/usr/bin/env python3
"""
huntertrace/core/models/extracted.py
======================================
Layer 1 — Extraction data models.

ExtractedEmail is the output of RFC 5322 parsing.  Every field is a
verbatim, unparsed value taken directly from the email source.

CRITICAL design constraints:
  - ALL string fields carry the RAW header value, not an interpreted one.
    date_raw is the literal "Date:" header string.
    from_header is the literal "From:" header string.
    No normalisation, no decoding, no timezone parsing happens here.
  - Parsing happens in Layer 2 (Signal Construction).
  - This model is NOT frozen because the extraction layer may need to
    populate fields incrementally during multi-pass parsing, but NO field
    may be modified after Layer 1 hands the object to Layer 2.
  - IPv4 and IPv6 addresses are stored as extracted strings, not as
    ipaddress objects, to avoid any implicit validation at the model level.
    Validation is Layer 3's responsibility.
  - x_headers preserves ALL X-* headers without pre-filtering.
    Pre-filtering would destroy evidence.

No external dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 1 — EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ReceivedHop:
    """
    One hop in the email's Received: chain.

    Position 0 is the OLDEST hop (closest to the sender).
    The final hop (highest position index) is written by the receiving
    MTA under analyst/victim control and is the most trusted.

    All string fields are raw extracted values — not normalised, not
    validated, not parsed beyond what is needed to identify the field.

    Fields
    ------
    position : int
        Zero-based index in the chronological hop sequence.
        0 = first relay (sender-side), N-1 = final MTA (receiver-side).

    raw_text : str
        Verbatim text of the Received: header.  Never modified.
        This is the forensic reference value for this hop.

    ip_v4 : Optional[str]
        IPv4 address extracted from this hop, if present.
        Raw string, e.g. "203.0.113.42".  Private-range filtering
        is performed at extraction time; this field will be None for
        RFC 1918 / loopback addresses.

    ip_v6 : Optional[str]
        IPv6 address extracted from this hop, if present.
        Raw string, e.g. "2001:db8::1".

    by_hostname : Optional[str]
        Value of the "by" clause in the Received: header.
        Identifies the MTA that received this message.

    from_hostname : Optional[str]
        Value of the "from" clause in the Received: header.
        Identifies the sending host as claimed in this header.
        UNTRUSTED for all hops except the final MTA.

    timestamp_raw : Optional[str]
        Raw timestamp string from this hop's Received: header.
        Example: "Thu, 20 Feb 2026 19:51:57 +0530"
        Parsed in Layer 2 only.

    protocol : Optional[str]
        Mail transfer protocol observed at this hop.
        Example: "ESMTPS", "SMTP", "HTTP".

    tls : bool
        True if TLS/encryption was indicated in this hop's header.

    parsing_confidence : float
        0.0–1.0 estimate of how reliably this hop was parsed.
        Set by the extraction layer based on header conformance.
        Not a trust score — trust assignment is Layer 2's responsibility.
    """

    position:           int
    raw_text:           str

    # ── Extracted addresses ───────────────────────────────────────────────────
    ip_v4:              Optional[str]
    ip_v6:              Optional[str]

    # ── Routing metadata ─────────────────────────────────────────────────────
    by_hostname:        Optional[str]
    from_hostname:      Optional[str]
    timestamp_raw:      Optional[str]
    protocol:           Optional[str]
    tls:                bool

    # ── Parsing quality ───────────────────────────────────────────────────────
    parsing_confidence: float         # 0.0–1.0; NOT a trust score


@dataclass
class ExtractedEmail:
    """
    Structured output of RFC 5322 parsing (Layer 1).

    Every field is a raw extracted value.  No field contains an
    interpreted, normalised, or inferred value.  The only transformation
    permitted in this model is structural (e.g. splitting a list of
    Received: headers into a list of ReceivedHop objects).

    Fields
    ------
    evidence_id : str
        Foreign key to EvidenceEnvelope.evidence_id.
        Maintains chain of custody from raw bytes to this artifact.

    extraction_timestamp : str
        ISO 8601 UTC timestamp at which extraction was completed.

    received_chain : List[ReceivedHop]
        Chronologically ordered list of Received: hops.
        Index 0 = oldest (sender-side).
        Index -1 = newest (final MTA, most trusted).

    from_header : str
        Verbatim value of the "From:" header.
        UNTRUSTED — set entirely by the sender.

    to_header : str
        Verbatim value of the "To:" header.

    subject_raw : str
        Verbatim value of the "Subject:" header.
        May contain RFC 2047 encoded-words (e.g. =?UTF-8?B?...?=).
        UNTRUSTED.

    date_raw : Optional[str]
        Verbatim value of the "Date:" header.
        NOT parsed here.  Timezone extraction happens in Layer 2.
        UNTRUSTED (sender-controlled).

    message_id : str
        Verbatim value of the "Message-ID:" header.

    reply_to_raw : Optional[str]
        Verbatim value of the "Reply-To:" header, if present.
        UNTRUSTED.

    content_type_raw : Optional[str]
        Verbatim value of the primary "Content-Type:" header.
        Used in Layer 2 to extract charset signal.

    auth_results_raw : Optional[str]
        Verbatim value of the "Authentication-Results:" header.
        Contains SPF/DKIM/DMARC evaluation results as written by
        the receiving MTA.  PARTIALLY_TRUSTED.

    received_spf_raw : Optional[str]
        Verbatim value of the "Received-SPF:" header.

    dkim_signature_raws : List[str]
        All verbatim "DKIM-Signature:" header values found.
        Multiple signatures are possible (e.g. Gmail adds its own).

    raw_bytes : Optional[bytes]
        Original RFC 5322 message bytes. Used for cryptographic
        authentication (e.g. DKIM/ARC) verification.

    x_headers : Dict[str, List[str]]
        All "X-*" extended headers found in the email.
        Key: normalised header name (lowercase, hyphens preserved).
        Value: list of all values for that header name (some appear
               multiple times).
        Complete — nothing is pre-filtered.
        All values are UNTRUSTED by default.

    arc_headers : Dict[str, List[str]]
        All "ARC-*" headers found in the email.
        Key: normalised header name (lowercase, hyphens preserved).
        Value: list of all values for that header name.
        These are UNTRUSTED by default until ARC validation succeeds.

    unique_ipv4 : List[str]
        Deduplicated list of all public IPv4 addresses found across
        the entire email (Received: chain + X-* headers).
        Private ranges (RFC 1918, loopback, APIPA) excluded.
        Order: first appearance in the Received: chain.

    unique_ipv6 : List[str]
        Deduplicated list of all public IPv6 addresses found.
        Link-local, loopback, ULA, and documentation prefixes excluded.

    charset_raw : Optional[str]
        Raw charset string extracted from Content-Type or from an
        encoded-word in the Subject header.
        Example: "windows-1251", "utf-8", "iso-8859-5"
        Not normalised here — normalisation is Layer 2's responsibility.

    hop_count : int
        Total number of Received: headers found.
        May differ from len(received_chain) if any headers were
        unparseable and omitted with a parsing warning.

    parse_warnings : List[str]
        Non-fatal issues encountered during extraction.
        Example: "Received header #3 could not be parsed — omitted"
        Does NOT prevent downstream processing.

    has_body : bool
        True if a message body was present and accessible.
        Body content is NOT included in this model — only metadata
        derived from the body structure (content_type_raw) is kept.
    """

    # ── Chain of custody ──────────────────────────────────────────────────────
    evidence_id:          str
    extraction_timestamp: str           # ISO 8601 UTC

    # ── Received: chain ───────────────────────────────────────────────────────
    received_chain:       List[ReceivedHop] = field(default_factory=list)

    # ── Standard headers (raw) ────────────────────────────────────────────────
    from_header:          str           = ""
    to_header:            str           = ""
    subject_raw:          str           = ""
    date_raw:             Optional[str] = None
    message_id:           str           = ""
    reply_to_raw:         Optional[str] = None

    # ── Content metadata (raw) ────────────────────────────────────────────────
    content_type_raw:     Optional[str] = None
    charset_raw:          Optional[str] = None
    has_body:             bool          = False

    # ── Authentication headers (raw) ──────────────────────────────────────────
    auth_results_raw:     Optional[str] = None
    received_spf_raw:     Optional[str] = None
    dkim_signature_raws:  List[str]     = field(default_factory=list)
    raw_bytes:            Optional[bytes] = None

    # ── Extended headers (complete) ───────────────────────────────────────────
    x_headers:            Dict[str, List[str]] = field(default_factory=dict)
    arc_headers:          Dict[str, List[str]] = field(default_factory=dict)

    # ── Deduplicated address lists ────────────────────────────────────────────
    unique_ipv4:          List[str] = field(default_factory=list)
    unique_ipv6:          List[str] = field(default_factory=list)

    # ── Extraction metadata ───────────────────────────────────────────────────
    hop_count:            int       = 0
    parse_warnings:       List[str] = field(default_factory=list)

