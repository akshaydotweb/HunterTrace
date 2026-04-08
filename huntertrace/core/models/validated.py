#!/usr/bin/env python3
"""
huntertrace/forensics/validation.py
=====================================
Layer 3 — Validation.

Single public entry point:

    bundle = validate(signals)   # ValidatedSignalBundle

Responsibilities
----------------
- Assign trust_tier and trust_rationale to every ForensicSignal
- Detect structural and semantic anomalies in the signal set
- Annotate signals with ValidationFlag values and anomaly_detail
- Produce ChainIntegrityReport and AnomalyFinding records
- Return a ValidatedSignalBundle with the same signal count as input

Hard constraints (Phase 1 architecture spec, Layer 3 scope)
-----------------------------------------------------------
  NO REMOVAL     — every signal in is every signal out; only annotated
  NO INFERENCE   — no geographic conclusions, no posterior updates
  NO ENRICHMENT  — no external API calls
  NO SCORING     — no likelihood ratios or Bayesian weights
  NO HARDCODING  — trust assignment rules are table-driven within this
                   module; no signal value is mapped to a country

Trust assignment policy (per Phase 1 trust_model.yaml design)
--------------------------------------------------------------
  TRUSTED
    • webmail_detected (provider wrote the header, not the sender)
    • first_hop_ip when it originates from the final-MTA hop
      (not applicable here — hop position used as proxy)

  PARTIALLY_TRUSTED
    • first_hop_ip            (relay-written; attacker may control relay)
    • all_ips                 (relay-written; mix of trust levels)
    • hop_count               (derived from relay headers)
    • dkim_domain             (cryptographic but domain ≠ identity)
    • message_id_domain       (relay-written Message-ID field)
    • spf_client_ip           (SPF infrastructure, partially verifiable)

  UNTRUSTED
    • timezone_offset         (Date: header — sender-controlled)
    • send_hour_utc           (derived from Date: header)
    • everything unrecognised (safe conservative default)

Anomaly detection catalogue
----------------------------
  A1  MISSING chain       — hop_count signal value == 0
  A2  MALFORMED IP        — all_ips / first_hop_ip contain non-IP strings
  A3  MALFORMED timezone  — timezone_offset outside valid UTC range
  A4  EXCESSIVE hops      — hop_count > EXCESSIVE_HOP_THRESHOLD
  A5  MISSING auth        — neither dkim_domain nor spf_client_ip present
  A6  IMPOSSIBLE timezone — offset minutes component not 0/15/30/45

Validation flags applied
------------------------
  CLEAN        — no anomalies found for this signal
  MISSING      — expected signal is absent (emitted as finding; no signal to flag)
  MALFORMED    — signal value fails basic structural check
  SUSPICIOUS   — signal value is structurally valid but statistically unusual

No external dependencies beyond stdlib.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from huntertrace.core.models.signals import (
    ForensicSignal,
    SignalClass,
    TrustTier,
    ValidationFlag,
)
from huntertrace.core.models.validated import (
    AnomalyFinding,
    AnomalyType,
    ChainIntegrityReport,
    ChainVerdict,
    Severity,
    ValidatedSignalBundle,
    ValidationProvenance,
)

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

_MODULE = "huntertrace.forensics.validation"
_VERSION = "1.0"

# Hop count above which EXCESSIVE_HOPS anomaly is raised.
# Legitimate email rarely exceeds 8 hops; 10 is a generous threshold.
_EXCESSIVE_HOP_THRESHOLD: int = 10

# Valid UTC offset hours: -12 to +14 (IANA tz database extremes).
_TZ_HOUR_MIN: int = -12
_TZ_HOUR_MAX: int = 14

# Valid minute components for UTC offsets (IANA catalogue).
_VALID_TZ_MINUTES: frozenset = frozenset({0, 15, 30, 45})

# Regex: IPv4 address — four decimal octets 0–255.
_RE_IPV4: re.Pattern = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$"
)

# Regex: IPv6 address — minimal structural check (contains colons, hex only).
_RE_IPV6: re.Pattern = re.compile(
    r"^[0-9a-fA-F:]{2,39}$"
)

# Regex: timezone offset as extracted by Layer 2 — "+HHMM" or "+HH:MM".
_RE_TZ_OFFSET: re.Pattern = re.compile(
    r"^([+-])(\d{2}):?(\d{2})$"
)

# ── Trust tier assignment table ───────────────────────────────────────────────
# Maps signal name → (TrustTier, rationale string).
# Signals absent from this table receive UNTRUSTED as the safe default.
_TRUST_TABLE: Dict[str, Tuple[TrustTier, str]] = {
    # Infrastructure signals — written by relay MTAs, not the sender.
    "first_hop_ip": (
        TrustTier.PARTIALLY_TRUSTED,
        "IP extracted from oldest Received: hop — written by a relay MTA; "
        "attacker may control that relay.",
    ),
    "all_ips": (
        TrustTier.PARTIALLY_TRUSTED,
        "IPs extracted from Received: chain — relay-written; mix of trust "
        "levels across hops; treated conservatively as PARTIALLY_TRUSTED.",
    ),
    "hop_count": (
        TrustTier.PARTIALLY_TRUSTED,
        "Count of Received: headers — relay-written; an attacker can inject "
        "additional headers to inflate the count.",
    ),
    # Authentication signals — cryptographically constrained but domain ≠ identity.
    "dkim_domain": (
        TrustTier.PARTIALLY_TRUSTED,
        "DKIM d= tag — cryptographic binding to signing domain, but the "
        "domain may be a newly-registered lookalike; DKIM pass ≠ legitimacy.",
    ),
    # Infrastructure derived from relay-written Message-ID.
    "message_id_domain": (
        TrustTier.PARTIALLY_TRUSTED,
        "Domain extracted from Message-ID — typically written by the sending "
        "MTA, not the user; can be forged in standards-non-conformant clients.",
    ),
    # SPF infrastructure — verifiable but limited.
    "spf_client_ip": (
        TrustTier.PARTIALLY_TRUSTED,
        "client-ip from Received-SPF — written by the receiving MTA from "
        "the SMTP envelope; reliable if the receiving MTA is trusted.",
    ),
    # Webmail provider detection — hostname written by the provider's MTA.
    "webmail_detected": (
        TrustTier.PARTIALLY_TRUSTED,
        "Webmail provider detected from relay hostname — hostname written by "
        "the provider's MTA infrastructure, not the sender; reliable indicator "
        "of routing path but not of sender identity.",
    ),
    # Sender-controlled temporal signals — Date: header is UNTRUSTED.
    "timezone_offset": (
        TrustTier.UNTRUSTED,
        "Extracted from Date: header — set by the sender's MUA; "
        "trivially spoofable; attacker may set any timezone.",
    ),
    "send_hour_utc": (
        TrustTier.UNTRUSTED,
        "Derived from Date: header — set by the sender's MUA; "
        "trivially spoofable; hour reflects attacker-controlled clock.",
    ),
}

# ── Severity ordering for overall_anomaly_severity computation ────────────────
_SEVERITY_ORDER: Dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW:           1,
    Severity.MEDIUM:        2,
    Severity.HIGH:          3,
    Severity.CRITICAL:      4,
}


# ─────────────────────────────────────────────────────────────────────────────
#  INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _new_finding_id() -> str:
    return str(uuid.uuid4())


def _is_valid_ip(value: str) -> bool:
    """Return True if value is a syntactically valid IPv4 or IPv6 address."""
    s = str(value).strip()
    return bool(_RE_IPV4.match(s) or _RE_IPV6.match(s))


def _parse_tz_offset(raw: str) -> Optional[Tuple[int, int, str]]:
    """
    Parse a timezone offset string into (hours, minutes, sign).

    Accepts "+0530", "-0800", "+05:30", "-00:00".
    Returns None when the string does not match the expected pattern.
    """
    m = _RE_TZ_OFFSET.match(str(raw).strip())
    if not m:
        return None
    sign   = m.group(1)
    hours  = int(m.group(2))
    mins   = int(m.group(3))
    return hours, mins, sign


def _highest_severity(severities: List[Severity]) -> Optional[Severity]:
    """Return the highest Severity from a list, or None if the list is empty."""
    if not severities:
        return None
    return max(severities, key=lambda s: _SEVERITY_ORDER[s])


def _annotate(
    signal: ForensicSignal,
    flag:   ValidationFlag,
    detail: str,
) -> None:
    """Append a ValidationFlag and set anomaly_detail on a signal in-place."""
    if flag not in signal.validation_flags:
        signal.validation_flags.append(flag)
    # Use the most severe detail string; append if detail already exists.
    if signal.anomaly_detail is None:
        signal.anomaly_detail = detail
    else:
        signal.anomaly_detail = f"{signal.anomaly_detail}; {detail}"


def _mark_clean(signal: ForensicSignal) -> None:
    """Mark a signal CLEAN if it has not already received any other flag."""
    if not signal.validation_flags:
        signal.validation_flags.append(ValidationFlag.CLEAN)


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1 — TRUST ASSIGNMENT
# ─────────────────────────────────────────────────────────────────────────────

def _assign_trust(signals: List[ForensicSignal]) -> None:
    """
    Assign trust_tier and trust_rationale to every signal in-place.

    Uses _TRUST_TABLE for known signal names; falls back to UNTRUSTED
    for any unrecognised name.  No signal value is inspected here —
    trust is a property of the signal source, not its content.
    """
    for sig in signals:
        if sig.name in _TRUST_TABLE:
            tier, rationale = _TRUST_TABLE[sig.name]
        else:
            tier = TrustTier.UNTRUSTED
            rationale = (
                f"Signal '{sig.name}' is not in the trust assignment table; "
                "UNTRUSTED applied as the safe conservative default."
            )
        sig.trust_tier      = tier
        sig.trust_rationale = rationale


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2 — ANOMALY DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def _check_missing_chain(
    by_name: Dict[str, ForensicSignal],
) -> List[AnomalyFinding]:
    """
    A1 — Detect missing or empty Received: chain.

    hop_count == 0 means no Received: headers were found.  This prevents
    any IP-based attribution and is anomalous for legitimate email.
    """
    findings: List[AnomalyFinding] = []
    hc_sig = by_name.get("hop_count")

    if hc_sig is None:
        # hop_count signal was never constructed — chain completely absent.
        findings.append(AnomalyFinding(
            finding_id             = _new_finding_id(),
            anomaly_type           = AnomalyType.HOP_INJECTION,
            severity               = Severity.HIGH,
            affected_signal_ids    = [],
            affected_hop_positions = [],
            detail                 = (
                "hop_count signal is absent — Received: chain could not be "
                "parsed at all.  IP-based attribution is unavailable."
            ),
            evidence               = "hop_count signal not present in signal list",
            mitre_technique        = "T1036",
            validator_module       = _MODULE,
        ))
        return findings

    hop_value = hc_sig.value
    if isinstance(hop_value, int) and hop_value == 0:
        _annotate(hc_sig, ValidationFlag.ANOMALY,
                  "hop_count == 0: no Received: headers found")
        findings.append(AnomalyFinding(
            finding_id             = _new_finding_id(),
            anomaly_type           = AnomalyType.HOP_INJECTION,
            severity               = Severity.HIGH,
            affected_signal_ids    = [hc_sig.signal_id],
            affected_hop_positions = [],
            detail                 = (
                "hop_count is 0 — no Received: headers present in this email. "
                "Either the headers were stripped or the email was injected "
                "directly into a mailbox without relay."
            ),
            evidence               = f"hop_count = {hop_value}",
            mitre_technique        = "T1036",
            validator_module       = _MODULE,
        ))

    return findings


def _check_ip_format(
    by_name: Dict[str, ForensicSignal],
) -> List[AnomalyFinding]:
    """
    A2 — Detect malformed IP address values.

    Checks first_hop_ip (scalar) and all_ips (list) for syntactic
    validity.  Does not validate routability or address space — that
    is enrichment's concern.
    """
    findings: List[AnomalyFinding] = []

    # first_hop_ip — scalar
    fh = by_name.get("first_hop_ip")
    if fh is not None and fh.value is not None:
        if not _is_valid_ip(str(fh.value)):
            _annotate(fh, ValidationFlag.IMPOSSIBLE,
                      f"first_hop_ip value '{fh.value}' is not a valid IP address")
            findings.append(AnomalyFinding(
                finding_id             = _new_finding_id(),
                anomaly_type           = AnomalyType.HOP_INJECTION,
                severity               = Severity.HIGH,
                affected_signal_ids    = [fh.signal_id],
                affected_hop_positions = [fh.hop_position]
                                         if fh.hop_position is not None else [],
                detail                 = (
                    f"first_hop_ip value '{fh.value}' failed IPv4/IPv6 "
                    "format validation.  This may indicate a malformed or "
                    "injected Received: header."
                ),
                evidence               = f"first_hop_ip = '{fh.value}'",
                mitre_technique        = "T1036.005",
                validator_module       = _MODULE,
            ))

    # all_ips — list; check each element
    ai = by_name.get("all_ips")
    if ai is not None and isinstance(ai.value, list):
        bad_ips = [ip for ip in ai.value if not _is_valid_ip(str(ip))]
        if bad_ips:
            _annotate(ai, ValidationFlag.IMPOSSIBLE,
                      f"all_ips contains malformed addresses: {bad_ips}")
            findings.append(AnomalyFinding(
                finding_id             = _new_finding_id(),
                anomaly_type           = AnomalyType.HOP_INJECTION,
                severity               = Severity.MEDIUM,
                affected_signal_ids    = [ai.signal_id],
                affected_hop_positions = [],
                detail                 = (
                    f"{len(bad_ips)} address(es) in all_ips failed "
                    f"IPv4/IPv6 format validation: {bad_ips}"
                ),
                evidence               = f"malformed values: {bad_ips}",
                mitre_technique        = "T1036.005",
                validator_module       = _MODULE,
            ))

    return findings


def _check_timezone(
    by_name: Dict[str, ForensicSignal],
) -> List[AnomalyFinding]:
    """
    A3 & A6 — Detect malformed or impossible timezone offset values.

    A3: offset does not match the expected ±HH:MM / ±HHMM format.
    A6: offset hours outside ±12–14 range, or minute component not in
        {0, 15, 30, 45} (the only minute values used by real timezones).
    """
    findings: List[AnomalyFinding] = []
    tz_sig = by_name.get("timezone_offset")
    if tz_sig is None or tz_sig.value is None:
        return findings

    raw = str(tz_sig.value)
    parsed = _parse_tz_offset(raw)

    if parsed is None:
        # A3 — cannot parse at all
        _annotate(tz_sig, ValidationFlag.IMPOSSIBLE,
                  f"timezone_offset '{raw}' does not match ±HH:MM / ±HHMM pattern")
        findings.append(AnomalyFinding(
            finding_id             = _new_finding_id(),
            anomaly_type           = AnomalyType.IMPOSSIBLE_TIMEZONE,
            severity               = Severity.MEDIUM,
            affected_signal_ids    = [tz_sig.signal_id],
            affected_hop_positions = [],
            detail                 = (
                f"timezone_offset value '{raw}' does not conform to "
                "RFC 2822 ±HHMM or ISO 8601 ±HH:MM format."
            ),
            evidence               = f"timezone_offset = '{raw}'",
            mitre_technique        = "T1036",
            validator_module       = _MODULE,
        ))
        return findings

    hours, mins, sign = parsed
    sign_mult = 1 if sign == "+" else -1
    effective_hours = sign_mult * hours

    # A3 — hours outside valid IANA range
    if effective_hours < _TZ_HOUR_MIN or effective_hours > _TZ_HOUR_MAX:
        _annotate(tz_sig, ValidationFlag.IMPOSSIBLE,
                  f"timezone_offset '{raw}' has hour component {effective_hours} "
                  f"outside valid UTC range [{_TZ_HOUR_MIN}, {_TZ_HOUR_MAX}]")
        findings.append(AnomalyFinding(
            finding_id             = _new_finding_id(),
            anomaly_type           = AnomalyType.IMPOSSIBLE_TIMEZONE,
            severity               = Severity.HIGH,
            affected_signal_ids    = [tz_sig.signal_id],
            affected_hop_positions = [],
            detail                 = (
                f"timezone_offset '{raw}' has hour component {effective_hours}h "
                f"which is outside the valid IANA range "
                f"[{_TZ_HOUR_MIN}h, +{_TZ_HOUR_MAX}h].  "
                "No real timezone uses this offset."
            ),
            evidence               = f"timezone_offset = '{raw}'",
            mitre_technique        = "T1036",
            validator_module       = _MODULE,
        ))

    # A6 — minute component not in IANA catalogue
    elif mins not in _VALID_TZ_MINUTES:
        _annotate(tz_sig, ValidationFlag.ANOMALY,
                  f"timezone_offset '{raw}' has minute component {mins} "
                  f"not in valid set {sorted(_VALID_TZ_MINUTES)}")
        findings.append(AnomalyFinding(
            finding_id             = _new_finding_id(),
            anomaly_type           = AnomalyType.IMPOSSIBLE_TIMEZONE,
            severity               = Severity.MEDIUM,
            affected_signal_ids    = [tz_sig.signal_id],
            affected_hop_positions = [],
            detail                 = (
                f"timezone_offset '{raw}' has minute component {mins} which "
                f"is not in the set of valid IANA timezone minute values "
                f"{sorted(_VALID_TZ_MINUTES)}.  This offset does not correspond "
                "to any real timezone."
            ),
            evidence               = f"timezone_offset = '{raw}', minutes = {mins}",
            mitre_technique        = "T1036",
            validator_module       = _MODULE,
        ))

    return findings


def _check_excessive_hops(
    by_name: Dict[str, ForensicSignal],
) -> List[AnomalyFinding]:
    """
    A4 — Detect an unusually high hop count.

    Legitimate email rarely traverses more than _EXCESSIVE_HOP_THRESHOLD
    relays.  A high count may indicate deliberate obfuscation by routing
    through many intermediary relays (T1090.003).
    """
    findings: List[AnomalyFinding] = []
    hc_sig = by_name.get("hop_count")
    if hc_sig is None or not isinstance(hc_sig.value, int):
        return findings

    if hc_sig.value > _EXCESSIVE_HOP_THRESHOLD:
        _annotate(hc_sig, ValidationFlag.ANOMALY,
                  f"hop_count {hc_sig.value} exceeds threshold {_EXCESSIVE_HOP_THRESHOLD}")
        findings.append(AnomalyFinding(
            finding_id             = _new_finding_id(),
            anomaly_type           = AnomalyType.EXCESSIVE_HOPS,
            severity               = Severity.MEDIUM,
            affected_signal_ids    = [hc_sig.signal_id],
            affected_hop_positions = [],
            detail                 = (
                f"hop_count is {hc_sig.value}, which exceeds the threshold of "
                f"{_EXCESSIVE_HOP_THRESHOLD}.  Legitimate email rarely traverses "
                "this many relays.  This may indicate deliberate relay-chaining "
                "to obscure the true origin."
            ),
            evidence               = f"hop_count = {hc_sig.value}",
            mitre_technique        = "T1090.003",
            validator_module       = _MODULE,
        ))

    return findings


def _check_missing_authentication(
    by_name: Dict[str, ForensicSignal],
) -> List[AnomalyFinding]:
    """
    A5 — Detect complete absence of authentication signals.

    When neither dkim_domain nor spf_client_ip is present, there is
    no cryptographic or SPF-based corroboration of the sender's
    infrastructure.  This is a weak signal on its own (many legitimate
    senders lack authentication) but warrants recording.
    """
    findings: List[AnomalyFinding] = []
    has_dkim = by_name.get("dkim_domain") is not None
    has_spf  = by_name.get("spf_client_ip") is not None

    if not has_dkim and not has_spf:
        findings.append(AnomalyFinding(
            finding_id             = _new_finding_id(),
            anomaly_type           = AnomalyType.MISSING_AUTHENTICATION,
            severity               = Severity.LOW,
            affected_signal_ids    = [],
            affected_hop_positions = [],
            detail                 = (
                "Neither dkim_domain nor spf_client_ip signals were constructed "
                "from this email.  This means no DKIM signature and no "
                "Received-SPF client-ip were found.  Authentication-based "
                "corroboration of sender infrastructure is unavailable."
            ),
            evidence               = "dkim_domain absent; spf_client_ip absent",
            mitre_technique        = None,
            validator_module       = _MODULE,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3 — CLEAN FLAG PASS
# ─────────────────────────────────────────────────────────────────────────────

def _apply_clean_flags(signals: List[ForensicSignal]) -> None:
    """
    Mark every signal that received no anomaly flags as CLEAN.

    Runs after all anomaly detectors have had a chance to annotate.
    A signal is CLEAN if and only if validation_flags is still empty.
    """
    for sig in signals:
        _mark_clean(sig)


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4 — CHAIN INTEGRITY REPORT
# ─────────────────────────────────────────────────────────────────────────────

def _build_chain_integrity(
    by_name:      Dict[str, ForensicSignal],
    findings:     List[AnomalyFinding],
) -> ChainIntegrityReport:
    """
    Build a ChainIntegrityReport from signals and findings produced so far.

    Counts are derived from the signal values available; forgery_score
    is a simple weighted sum of anomaly severities normalised to [0, 1].
    """
    hc_sig  = by_name.get("hop_count")
    total   = hc_sig.value if (hc_sig and isinstance(hc_sig.value, int)) else 0
    # All parsed hops are represented in all_ips; count non-empty entries.
    ai_sig  = by_name.get("all_ips")
    parsed  = len(ai_sig.value) if (ai_sig and isinstance(ai_sig.value, list)) else 0

    # Trust tier counts: count signals in each tier and use as a proxy for hops.
    # (Actual per-hop trust requires hop objects; we use the signal-level proxy.)
    trusted   = sum(1 for s in by_name.values()
                    if s.trust_tier == TrustTier.TRUSTED)
    partial   = sum(1 for s in by_name.values()
                    if s.trust_tier == TrustTier.PARTIALLY_TRUSTED)
    untrusted = sum(1 for s in by_name.values()
                    if s.trust_tier == TrustTier.UNTRUSTED)

    # Count specific anomaly types from findings.
    ts_regressions    = sum(1 for f in findings
                            if f.anomaly_type == AnomalyType.TIMESTAMP_REGRESSION)
    injection_count   = sum(1 for f in findings
                            if f.anomaly_type == AnomalyType.HOP_INJECTION)
    private_ip_count  = sum(1 for f in findings
                            if f.anomaly_type == AnomalyType.PRIVATE_IP_IN_CHAIN)

    # Forgery score: weighted sum of finding severities, capped at 1.0.
    _SEVERITY_WEIGHTS: Dict[Severity, float] = {
        Severity.CRITICAL:      0.40,
        Severity.HIGH:          0.25,
        Severity.MEDIUM:        0.15,
        Severity.LOW:           0.05,
        Severity.INFORMATIONAL: 0.00,
    }
    raw_score = sum(_SEVERITY_WEIGHTS.get(f.severity, 0.0) for f in findings)
    forgery_score = min(1.0, raw_score)

    # Chain verdict from forgery score.
    if forgery_score >= 0.60:
        verdict = ChainVerdict.FORGED
    elif forgery_score >= 0.20:
        verdict = ChainVerdict.SUSPICIOUS
    else:
        verdict = ChainVerdict.CLEAN

    return ChainIntegrityReport(
        total_hops              = total,
        parsed_hops             = parsed,
        trusted_hops            = trusted,
        partially_trusted_hops  = partial,
        untrusted_hops          = untrusted,
        timestamp_regressions   = ts_regressions,
        injection_indicators    = injection_count,
        private_ips_found       = private_ip_count,
        max_hop_gap_seconds     = None,   # requires hop timestamps — not available here
        forgery_score           = round(forgery_score, 4),
        verdict                 = verdict,
        finding_ids             = [f.finding_id for f in findings],
    )


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def validate(signals: List[ForensicSignal]) -> ValidatedSignalBundle:
    """
    Validate a list of ForensicSignals and return a ValidatedSignalBundle.

    Parameters
    ----------
    signals : List[ForensicSignal]
        Layer 2 output.  All signals are annotated in-place; the same
        objects are returned in the bundle (not copies).

    Returns
    -------
    ValidatedSignalBundle
        - Same signal count as input (INVARIANT: no signals removed)
        - trust_tier and trust_rationale set on every signal
        - validation_flags and anomaly_detail set on every signal
        - anomalies list with one AnomalyFinding per detected issue
        - chain_integrity always present
        - provenance always present

    Processing order
    ----------------
    1. Build name → signal index for O(1) lookup
    2. Assign trust tiers (all signals)
    3. Run anomaly detectors (produce findings + annotate signals)
    4. Apply CLEAN flag to signals with no anomaly annotations
    5. Build ChainIntegrityReport
    6. Compute overall_anomaly_severity and signals_flagged
    7. Construct and return ValidatedSignalBundle
    """
    ts = _utc_now_iso()

    # Derive evidence_id from the first signal (all share the same one).
    evidence_id = signals[0].evidence_id if signals else "unknown"

    # ── Step 1: name lookup index ─────────────────────────────────────────────
    # When multiple signals share a name (e.g. extended signal sets), take
    # the first occurrence for anomaly checks; all occurrences are annotated.
    by_name: Dict[str, ForensicSignal] = {}
    for sig in signals:
        if sig.name not in by_name:
            by_name[sig.name] = sig

    # ── Step 2: trust assignment ──────────────────────────────────────────────
    _assign_trust(signals)

    # ── Step 3: anomaly detection ─────────────────────────────────────────────
    all_findings: List[AnomalyFinding] = []
    notes:        List[str]            = []

    all_findings.extend(_check_missing_chain(by_name))
    all_findings.extend(_check_ip_format(by_name))
    all_findings.extend(_check_timezone(by_name))
    all_findings.extend(_check_excessive_hops(by_name))
    all_findings.extend(_check_missing_authentication(by_name))

    # ── Step 4: clean flag pass ───────────────────────────────────────────────
    _apply_clean_flags(signals)

    # ── Step 5: chain integrity report ────────────────────────────────────────
    chain = _build_chain_integrity(by_name, all_findings)

    # ── Step 6: aggregate summaries ───────────────────────────────────────────
    overall_severity = _highest_severity(
        [f.severity for f in all_findings]
    )
    signals_flagged = sum(
        1 for s in signals
        if any(f != ValidationFlag.CLEAN for f in s.validation_flags)
    )

    # ── Step 7: assemble bundle ───────────────────────────────────────────────
    return ValidatedSignalBundle(
        evidence_id              = evidence_id,
        validated_at             = ts,
        chain_integrity          = chain,
        provenance               = ValidationProvenance(
                                       validator_versions={_MODULE: _VERSION}
                                   ),
        signals                  = signals,
        anomalies                = all_findings,
        overall_anomaly_severity = overall_severity,
        signals_flagged          = signals_flagged,
        validation_notes         = notes,
    )