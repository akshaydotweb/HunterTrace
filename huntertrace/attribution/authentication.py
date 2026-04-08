#!/usr/bin/env python3
"""
huntertrace/attribution/authentication.py
==========================================
Email authentication layer: SPF, DKIM, DMARC, ARC validation and alignment.

Standards-compliant implementation that performs real validation instead of
relying solely on Authentication-Results headers.

Architecture
------------
1. extract_auth_fields()      — Extract raw fields from ExtractedEmail
2. validate_spf()             — SPF validation via DNS TXT lookup
3. check_spf_alignment()      — Align SPF domain with From domain
4. check_dkim_alignment()     — Align DKIM d= with From domain
5. evaluate_dmarc()           — Compute DMARC pass/fail from SPF + DKIM
6. validate_arc()             — Basic ARC chain integrity check
7. build_auth_signals()       — Create ForensicSignal objects

No external dependencies beyond stdlib + dnspython (already required).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Sequence, Tuple
import os

# ─────────────────────────────────────────────────────────────────────────────
#  EXTERNAL IMPORTS (for signal creation)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from huntertrace.core.models.signal import ForensicSignal, SignalClass, TrustTier
except ImportError:
    ForensicSignal = None  # type: ignore[assignment]
    SignalClass = None  # type: ignore[assignment]
    TrustTier = None  # type: ignore[assignment]


# ─────────────────────────────────────────────────────────────────────────────
#  DATACLASSES
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SPFEvaluation:
    """Result of SPF validation against connecting IP."""

    result: str  # pass, fail, softfail, neutral, none
    domain: str  # envelope sender domain
    connecting_ip: str
    mechanisms_checked: Tuple[str, ...] = ()
    explanation: str = ""


@dataclass(frozen=True)
class DKIMAlignmentResult:
    """Result of DKIM domain alignment check."""

    dkim_domain: Optional[str]
    from_domain: str
    aligned: bool
    mode: str  # strict or relaxed
    explanation: str = ""


@dataclass(frozen=True)
class SPFAlignmentResult:
    """Result of SPF domain alignment check."""

    spf_domain: str
    from_domain: str
    aligned: bool
    mode: str  # strict or relaxed
    explanation: str = ""


@dataclass(frozen=True)
class DMARCPolicy:
    """Parsed DMARC policy record."""

    policy: str  # none, quarantine, reject
    aspf: str = "r"  # strict or relaxed (r=relaxed)
    adkim: str = "r"
    subdomain_policy: Optional[str] = None
    reporting_email: Optional[str] = None
    percentage: int = 100
    raw_record: str = ""


@dataclass(frozen=True)
class DMARCEvaluation:
    """Result of DMARC evaluation."""

    result: str  # pass or fail
    policy: Optional[DMARCPolicy]
    spf_pass: bool
    spf_aligned: bool
    dkim_pass: bool
    dkim_aligned: bool
    explanation: str = ""


@dataclass(frozen=True)
class ARCValidation:
    """Result of ARC chain validation."""

    valid: bool
    chain_count: int = 0
    latest_result: Optional[str] = None  # pass, fail, neutral, none
    explanation: str = ""


@dataclass(frozen=True)
class AuthenticationResult:
    """Complete authentication evaluation for an email."""

    spf: SPFEvaluation
    spf_aligned: SPFAlignmentResult
    dkim_present: bool
    dkim_valid: bool
    dkim_domain: Optional[str]
    dkim_aligned: Optional[DKIMAlignmentResult]
    dmarc: DMARCEvaluation
    arc: ARCValidation

    # Forensic summary
    verdict: str  # pass, fail, suspicious
    explanation: str


@dataclass(frozen=True)
class AuthenticationFields:
    """Extracted authentication-relevant fields from email."""

    from_domain: str
    return_path_domain: str
    connecting_ip: str
    dkim_domain: Optional[str]
    received_chain: List[ReceivedHop]
    arc_headers: Dict[str, str]  # i -> full ARC-* header value
    auth_results_hints: Optional[str]


@dataclass
class AuthenticationConfig:
    """Configuration for authentication validation."""

    spf_alignment_mode: str = "relaxed"  # strict or relaxed
    dkim_alignment_mode: str = "relaxed"
    dmarc_alignment_mode: str = "relaxed"
    cache_path: Optional[str] = None
    max_spf_recursion: int = 10
    follow_spf_includes: bool = True


# ─────────────────────────────────────────────────────────────────────────────
#  RESOLVER PROTOCOL & CACHE
# ─────────────────────────────────────────────────────────────────────────────


class TXTResolver(Protocol):
    """Protocol for DNS TXT record resolution."""

    def resolve_txt(self, name: str) -> List[str]:
        """Return TXT records for a DNS name."""


class AuthenticationCache:
    """Persistent cache for DNS lookups and validation results."""

    def __init__(self, cache_path: Optional[str] = None):
        default_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        self.cache_path = (
            Path(cache_path) if cache_path
            else default_root / "huntertrace" / "auth_cache.json"
        )
        self._data: Optional[Dict] = None

    def get(self, category: str, key: str) -> Optional[object]:
        """Get cached value."""
        data = self._load()
        return data.get(category, {}).get(key)

    def set(self, category: str, key: str, value: object) -> None:
        """Set cached value with deterministic serialization."""
        data = self._load()
        if category not in data:
            data[category] = {}
        # Serialize value deterministically
        data[category][str(key)] = self._serialize_value(value)
        self._persist(data)

    def _serialize_value(self, value: object) -> object:
        """Serialize value for deterministic JSON storage."""
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        if isinstance(value, (list, tuple)):
            return [self._serialize_value(v) for v in value]
        if isinstance(value, dict):
            return {str(k): self._serialize_value(v) for k, v in sorted(value.items())}
        # For other types, try to convert to string
        return str(value)

    def _load(self) -> Dict:
        if self._data is not None:
            return self._data
        if not self.cache_path.exists():
            self._data = {}
            return self._data
        try:
            content = self.cache_path.read_text(encoding="utf-8")
            loaded = json.loads(content)
            if isinstance(loaded, dict):
                self._data = loaded
            else:
                self._data = {}
        except Exception:
            self._data = {}
        return self._data

    def _persist(self) -> None:
        """Persist cache to disk with deterministic JSON formatting."""
        if self._data is None:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        # Use deterministic JSON serialization (sorted keys, consistent formatting)
        content = json.dumps(self._data, sort_keys=True, indent=2, ensure_ascii=True)
        self.cache_path.write_text(content, encoding="utf-8")

    def clear(self) -> None:
        """Clear all cached data."""
        self._data = {}
        if self.cache_path.exists():
            self.cache_path.unlink()


# ─────────────────────────────────────────────────────────────────────────────
#  FIELD EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────


def extract_auth_fields(extracted: ExtractedEmail) -> AuthenticationFields:
    """
    Extract authentication-relevant fields from ExtractedEmail.

    Normalizes domains and identifies the first untrusted hop (connecting IP).
    """
    # Extract From domain
    from_domain = _extract_from_domain(extracted.from_header)

    # Extract Return-Path domain (envelope sender)
    return_path_domain = _extract_return_path_domain(
        extracted.received_spf_raw,
        extracted.auth_results_raw
    )

    # Extract DKIM domain
    dkim_domain = _extract_dkim_domain(extracted.dkim_signature_raws)

    # Get connecting IP (first hop = sender-side = position 0)
    connecting_ip = ""
    if extracted.received_chain:
        first_hop = extracted.received_chain[0]
        connecting_ip = first_hop.ip_v4 or first_hop.ip_v6 or ""

    # Extract ARC headers (if present)
    arc_headers = _extract_arc_headers(extracted.x_headers)

    return AuthenticationFields(
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        connecting_ip=connecting_ip,
        dkim_domain=dkim_domain,
        received_chain=extracted.received_chain,
        arc_headers=arc_headers,
        auth_results_hints=extracted.auth_results_raw,
    )


def _extract_from_domain(from_header: str) -> str:
    """Extract and normalize domain from From header."""
    if not from_header:
        return ""

    # RFC 5322 form: "Name <email@domain>" or just "email@domain"
    match = re.search(r"[a-zA-Z0-9.+-]+@([a-zA-Z0-9.-]+)", from_header)
    if match:
        domain = match.group(1).strip().rstrip(".")
        return domain.lower()
    return ""


def _extract_return_path_domain(
    received_spf_raw: Optional[str],
    auth_results_raw: Optional[str]
) -> str:
    """Extract Return-Path domain from SPF or Authentication-Results headers."""
    # Try Received-SPF first: "envelope-from=user@domain.com"
    if received_spf_raw:
        match = re.search(
            r"envelope-from=([a-zA-Z0-9.+-]+@[a-zA-Z0-9.-]+)",
            received_spf_raw,
            re.IGNORECASE
        )
        if match:
            domain = match.group(1).split("@")[1].strip().rstrip(".")
            return domain.lower()

    # Try Authentication-Results
    if auth_results_raw:
        match = re.search(
            r"from\s*=\s*([a-zA-Z0-9.+-]+@[a-zA-Z0-9.-]+)",
            auth_results_raw,
            re.IGNORECASE
        )
        if match:
            domain = match.group(1).split("@")[1].strip().rstrip(".")
            return domain.lower()

    return ""


def _extract_dkim_domain(dkim_signature_raws: List[str]) -> Optional[str]:
    """Extract d= tag from first DKIM-Signature header."""
    for raw in dkim_signature_raws:
        match = re.search(r"(?:^|;)\s*d\s*=\s*([^\s;]+)", raw, re.IGNORECASE)
        if match:
            domain = match.group(1).strip().rstrip(".")
            return domain.lower()
    return None


def _extract_arc_headers(x_headers: Dict[str, List[str]]) -> Dict[str, str]:
    """Extract ARC-* headers by instance number."""
    arc_headers: Dict[str, str] = {}

    # ARC headers come as x_headers with keys like "arc-seal", "arc-message-signature"
    for key, values in x_headers.items():
        if key.lower().startswith("arc-"):
            for value in values:
                # Parse i= parameter to get instance number
                match = re.search(r"i\s*=\s*(\d+)", value, re.IGNORECASE)
                if match:
                    instance = match.group(1)
                    arc_headers[instance] = value

    return arc_headers


# ─────────────────────────────────────────────────────────────────────────────
#  DOMAIN NORMALIZATION & ORGANIZATIONAL DOMAIN EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────


def normalize_domain(domain: str) -> str:
    """Normalize domain: lowercase, strip trailing dot."""
    if not domain:
        return ""
    return domain.strip().rstrip(".").lower()


def get_organizational_domain(domain: str) -> str:
    """
    Extract organizational domain (base domain) from a FQDN.

    Examples:
        mail.example.com → example.com
        example.co.uk → example.co.uk
        example.com → example.com
    """
    domain = normalize_domain(domain)
    if not domain:
        return ""

    # List of known multi-part TLDs
    multi_part_tlds = {
        "co.uk", "co.jp", "co.in", "co.nz", "com.au", "com.br", "gov.uk",
        "ac.uk", "org.uk", "co.kr", "com.hk", "co.il", "com.mx", "co.za",
    }

    parts = domain.split(".")

    # Check if last two parts match a known multi-part TLD
    if len(parts) >= 2:
        potential_tld = ".".join(parts[-2:]).lower()
        if potential_tld in multi_part_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])

    # Default: last two parts
    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return domain


# ─────────────────────────────────────────────────────────────────────────────
#  STUB FUNCTIONS (Implemented in subsequent phases)
# ─────────────────────────────────────────────────────────────────────────────


def validate_spf(
    fields: AuthenticationFields,
    resolver: Optional[TXTResolver] = None,
    config: Optional[AuthenticationConfig] = None,
) -> SPFEvaluation:
    """Validate SPF against connecting IP using phase 3 implementation."""
    config = config or AuthenticationConfig()

    if not fields.connecting_ip or not fields.return_path_domain:
        return SPFEvaluation(
            result="none",
            domain=fields.return_path_domain or "",
            connecting_ip=fields.connecting_ip or "",
            mechanisms_checked=(),
            explanation="missing_ip_or_domain"
        )

    validator = SPFValidator(resolver=resolver, max_recursion=config.max_spf_recursion)
    result, mechanisms, explanation = validator.validate(
        fields.connecting_ip,
        fields.return_path_domain
    )

    return SPFEvaluation(
        result=result,
        domain=fields.return_path_domain,
        connecting_ip=fields.connecting_ip,
        mechanisms_checked=tuple(mechanisms),
        explanation=explanation
    )


def check_spf_alignment(
    spf: SPFEvaluation,
    from_domain: str,
    mode: str = "relaxed"
) -> SPFAlignmentResult:
    """
    Check SPF alignment with From domain.

    Alignment types:
        strict: spf_domain == from_domain
        relaxed: organizational_domain(spf_domain) == organizational_domain(from_domain)
    """
    spf_domain = spf.domain

    if not spf_domain or not from_domain:
        return SPFAlignmentResult(
            spf_domain=spf_domain or "",
            from_domain=from_domain,
            aligned=False,
            mode=mode,
            explanation="missing_domain"
        )

    spf_domain_norm = normalize_domain(spf_domain)
    from_domain_norm = normalize_domain(from_domain)

    if mode.lower() == "strict":
        aligned = spf_domain_norm == from_domain_norm
        explanation = (
            f"SPF domain {spf_domain_norm} {'matches' if aligned else 'does not match'} "
            f"From domain {from_domain_norm} (strict)")
    else:  # relaxed (default)
        spf_org = get_organizational_domain(spf_domain_norm)
        from_org = get_organizational_domain(from_domain_norm)
        aligned = spf_org == from_org
        explanation = (
            f"SPF organizational domain {spf_org} "
            f"{'matches' if aligned else 'does not match'} "
            f"From organizational domain {from_org} (relaxed)"
        )

    return SPFAlignmentResult(
        spf_domain=spf_domain_norm,
        from_domain=from_domain_norm,
        aligned=aligned,
        mode=mode,
        explanation=explanation
    )


def check_dkim_alignment(
    dkim_domain: Optional[str],
    from_domain: str,
    mode: str = "relaxed"
) -> Optional[DKIMAlignmentResult]:
    """
    Check DKIM alignment with From domain.

    Alignment types:
        strict: dkim_domain == from_domain
        relaxed: organizational_domain(dkim_domain) == organizational_domain(from_domain)
    """
    if not dkim_domain or not from_domain:
        return None

    dkim_domain_norm = normalize_domain(dkim_domain)
    from_domain_norm = normalize_domain(from_domain)

    if mode.lower() == "strict":
        aligned = dkim_domain_norm == from_domain_norm
        explanation = (
            f"DKIM domain {dkim_domain_norm} {'matches' if aligned else 'does not match'} "
            f"From domain {from_domain_norm} (strict)"
        )
    else:  # relaxed (default)
        dkim_org = get_organizational_domain(dkim_domain_norm)
        from_org = get_organizational_domain(from_domain_norm)
        aligned = dkim_org == from_org
        explanation = (
            f"DKIM organizational domain {dkim_org} "
            f"{'matches' if aligned else 'does not match'} "
            f"From organizational domain {from_org} (relaxed)"
        )

    return DKIMAlignmentResult(
        dkim_domain=dkim_domain_norm,
        from_domain=from_domain_norm,
        aligned=aligned,
        mode=mode,
        explanation=explanation
    )


def evaluate_dmarc(
    spf: SPFEvaluation,
    spf_aligned: SPFAlignmentResult,
    dkim_valid: bool,
    dkim_aligned: Optional[DKIMAlignmentResult],
    fields: AuthenticationFields,
    resolver: Optional[TXTResolver] = None,
) -> DMARCEvaluation:
    """Evaluate DMARC policy using phase 6 implementation."""
    dkim_pass = dkim_valid
    dkim_aligned_bool = dkim_aligned.aligned if dkim_aligned else False

    validator = DMARCValidator(resolver=resolver)
    return validator.evaluate(
        spf_pass=(spf.result == "pass"),
        spf_aligned=spf_aligned.aligned,
        dkim_pass=dkim_pass,
        dkim_aligned=dkim_aligned_bool,
        dmarc_domain=fields.from_domain,
    )


def validate_arc(
    raw_message: bytes,
    fields: AuthenticationFields,
) -> ARCValidation:
    """Validate ARC chain using phase 7 implementation."""
    validator = ARCValidator()
    valid, chain_count, explanation = validator.validate(fields.arc_headers)

    latest_result = None
    if valid:
        latest_result = validator.extract_arc_result(fields.arc_headers)

    return ARCValidation(
        valid=valid,
        chain_count=chain_count,
        latest_result=latest_result,
        explanation=explanation
    )


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ORCHESTRATION (Phase 8+ integration point)
# ─────────────────────────────────────────────────────────────────────────────


def evaluate_email_authentication(
    extracted: ExtractedEmail,
    dkim_valid: bool,
    resolver: Optional[TXTResolver] = None,
    config: Optional[AuthenticationConfig] = None,
) -> AuthenticationResult:
    """
    Comprehensive email authentication evaluation.

    Takes extracted email and DKIM verification result, performs full validation
    including SPF, DKIM alignment, DMARC policy check, and ARC handling.

    Arguments:
        extracted: ExtractedEmail from Layer 1
        dkim_valid: result from existing DKIM verifier
        resolver: optional DNS resolver (for testing)
        config: optional configuration

    Returns:
        AuthenticationResult with complete evaluation
    """
    config = config or AuthenticationConfig()

    # 1. Extract fields
    fields = extract_auth_fields(extracted)

    # 2. Validate SPF
    spf = validate_spf(fields, resolver=resolver, config=config)

    # 3. Check SPF alignment
    spf_aligned = check_spf_alignment(
        spf,
        fields.from_domain,
        mode=config.spf_alignment_mode
    )

    # 4. Check DKIM alignment
    dkim_aligned = check_dkim_alignment(
        fields.dkim_domain,
        fields.from_domain,
        mode=config.dkim_alignment_mode
    ) if dkim_valid else None

    # 5. Evaluate DMARC
    dmarc = evaluate_dmarc(
        spf,
        spf_aligned,
        dkim_valid,
        dkim_aligned,
        fields,
        resolver=resolver
    )

    # 6. Validate ARC
    arc = validate_arc(extracted.raw_bytes if hasattr(extracted, 'raw_bytes') else b"", fields)

    # 7. Determine verdict
    verdict, summary = _determine_verdict(
        dmarc=dmarc,
        arc=arc,
        spf_aligned=spf_aligned.aligned,
        dkim_aligned=dkim_aligned.aligned if dkim_aligned else False
    )

    return AuthenticationResult(
        spf=spf,
        spf_aligned=spf_aligned,
        dkim_present=len(extracted.dkim_signature_raws) > 0,
        dkim_valid=dkim_valid,
        dkim_domain=fields.dkim_domain,
        dkim_aligned=dkim_aligned,
        dmarc=dmarc,
        arc=arc,
        verdict=verdict,
        explanation=summary
    )


def _determine_verdict(
    dmarc: DMARCEvaluation,
    arc: ARCValidation,
    spf_aligned: bool,
    dkim_aligned: bool,
) -> Tuple[str, str]:
    """Determine overall verdict and summary explanation."""
    if dmarc.result == "pass":
        return "pass", "Message passed DMARC authentication"

    if dmarc.result == "fail" and arc.valid:
        return "forwarded", (
            f"Message failed DMARC but ARC chain is valid; "
            f"message was likely forwarded by a trusted relay"
        )

    if dmarc.result == "fail" and not arc.valid:
        # Distinguish between alignment failures vs outright failures
        if not spf_aligned and not dkim_aligned:
            return "fail", (
                f"Message failed DMARC: neither SPF nor DKIM were aligned with From domain. "
                f"This may indicate spoofing."
            )
        return "suspicious", f"Message failed DMARC: {dmarc.explanation}"

    return "unknown", "Could not determine authentication verdict"


# ─────────────────────────────────────────────────────────────────────────────
#  SIGNAL CREATION (for Layer 2b integration)
# ─────────────────────────────────────────────────────────────────────────────


def build_authentication_signals(
    auth_result: AuthenticationResult,
    evidence_id: str,
) -> List[object]:
    """
    Build ForensicSignal objects from authentication evaluation result.

    For use in Layer 2b (signal enrichment layer) to inject authentication
    signals into the signal stream alongside infrastructure/behavioral signals.

    Returns empty list if signal classes not available (import failed).
    """
    if ForensicSignal is None or SignalClass is None or TrustTier is None:
        return []

    signals = []

    _utc_now_iso = lambda: __import__(
        'datetime'
    ).datetime.now(
        __import__('datetime').timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

    ts = _utc_now_iso()

    # Helper to create signal
    def _make_auth_signal(name: str, value, explanation: str) -> ForensicSignal:
        return ForensicSignal(
            signal_id=str(__import__('uuid').uuid4()),
            evidence_id=evidence_id,
            name=name,
            value=value,
            signal_class=SignalClass.AUTHENTICATION,
            source_field="Authentication evaluation",
            extraction_method=f"RFC 7208/7489/8617 standards-compliant validation",
            hop_position=None,
            constructed_at=ts,
            trust_tier=TrustTier.UNTRUSTED,
            trust_rationale="Authentication signals are derived from header values and DNS lookups; trust assessment depends on upstream validation",
            validation_flags=[],
            anomaly_detail=None,
            enrichment=None,
            bayesian_weight=None,
            reliability_multiplier=None,
            effective_lr=None,
            posterior_delta=None,
            contributed_to=None,
            excluded_reason=None,
        )

    # SPF signals
    signals.append(_make_auth_signal(
        "spf_result",
        auth_result.spf.result,
        auth_result.spf.explanation
    ))
    signals.append(_make_auth_signal(
        "spf_aligned",
        auth_result.spf_aligned.aligned,
        auth_result.spf_aligned.explanation
    ))

    # DKIM signals (only if DKIM present)
    if auth_result.dkim_present:
        signals.append(_make_auth_signal(
            "dkim_valid",
            auth_result.dkim_valid,
            f"DKIM signature present and {'valid' if auth_result.dkim_valid else 'invalid'}"
        ))
        if auth_result.dkim_aligned is not None:
            signals.append(_make_auth_signal(
                "dkim_aligned",
                auth_result.dkim_aligned.aligned,
                auth_result.dkim_aligned.explanation
            ))

    # DMARC signals
    signals.append(_make_auth_signal(
        "dmarc_result",
        auth_result.dmarc.result,
        auth_result.dmarc.explanation
    ))
    if auth_result.dmarc.policy:
        signals.append(_make_auth_signal(
            "dmarc_policy",
            auth_result.dmarc.policy.policy,
            f"DMARC policy: {auth_result.dmarc.policy.policy}"
        ))

    # ARC signals (only if ARC present)
    if auth_result.arc.chain_count > 0:
        signals.append(_make_auth_signal(
            "arc_valid",
            auth_result.arc.valid,
            f"ARC chain with {auth_result.arc.chain_count} instance(s): {auth_result.arc.explanation}"
        ))

    return signals
