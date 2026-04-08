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
import os
import re
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

# ─────────────────────────────────────────────────────────────────────────────
#  EXTERNAL IMPORTS
# ─────────────────────────────────────────────────────────────────────────────

from huntertrace.core.models.extracted import ExtractedEmail, ReceivedHop
from huntertrace.attribution.spf_validator import SPFValidator
from huntertrace.attribution.dmarc_validator import DMARCValidator
from huntertrace.attribution.arc_validator import ARCValidator
from huntertrace.attribution.authentication_types import (
    SPFEvaluation,
    DKIMAlignmentResult,
    SPFAlignmentResult,
    DMARCPolicy,
    DMARCEvaluation,
    ARCValidation,
    AuthenticationResult,
    AuthenticationFields,
    AuthenticationConfig,
)
try:
    # Try to import from signals module directly to avoid circular imports
    from huntertrace.core.models.signals import ForensicSignal, SignalClass, TrustTier
except (ImportError, ModuleNotFoundError):
    ForensicSignal = None  # type: ignore[assignment]
    SignalClass = None  # type: ignore[assignment]
    TrustTier = None  # type: ignore[assignment]


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION & HELPERS
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
    dkim_domains = _extract_dkim_domains(extracted.dkim_signature_raws)

    # Get connecting IP (first hop = sender-side = position 0)
    connecting_ip = ""
    if extracted.received_chain:
        first_hop = extracted.received_chain[0]
        connecting_ip = first_hop.ip_v4 or first_hop.ip_v6 or ""

    # Extract ARC headers (if present)
    arc_source = getattr(extracted, "arc_headers", None) or extracted.x_headers
    arc_headers = _extract_arc_headers(arc_source)

    return AuthenticationFields(
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        connecting_ip=connecting_ip,
        dkim_domain=dkim_domain,
        dkim_domains=dkim_domains,
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


def _extract_dkim_domains(dkim_signature_raws: List[str]) -> Tuple[str, ...]:
    """Extract all d= tags from DKIM-Signature headers."""
    domains: List[str] = []
    for raw in dkim_signature_raws:
        match = re.search(r"(?:^|;)\s*d\s*=\s*([^\s;]+)", raw, re.IGNORECASE)
        if match:
            domain = match.group(1).strip().rstrip(".")
            domains.append(domain.lower())
    return tuple(domains)


def _format_arc_header_name(key: str) -> str:
    normalized = key.strip().lower()
    if not normalized.startswith("arc-"):
        return key.strip()
    parts = normalized.split("-")
    return "ARC-" + "-".join(part.capitalize() for part in parts[1:])


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
                    header_name = _format_arc_header_name(key)
                    header_value = value
                    if not value.lower().startswith("arc-"):
                        header_value = f"{header_name}: {value}"
                    if instance in arc_headers:
                        arc_headers[instance] = arc_headers[instance] + "\n" + header_value
                    else:
                        arc_headers[instance] = header_value

    return arc_headers


def _normalize_dkim_summary(dkim_summary: Optional[object]) -> Optional[Mapping[str, Any]]:
    if dkim_summary is None:
        return None
    if isinstance(dkim_summary, Mapping):
        return dkim_summary
    if hasattr(dkim_summary, "to_dict"):
        return dkim_summary.to_dict()  # type: ignore[no-any-return]
    return None


def _select_dkim_alignment(
    domains: Sequence[str],
    from_domain: str,
    mode: str,
) -> Optional[DKIMAlignmentResult]:
    if not from_domain:
        return None
    first_unaligned: Optional[DKIMAlignmentResult] = None
    for domain in domains:
        alignment = check_dkim_alignment(domain, from_domain, mode=mode)
        if alignment is None:
            continue
        if alignment.aligned:
            return alignment
        if first_unaligned is None:
            first_unaligned = alignment
    return first_unaligned


def _classify_dkim(
    signatures: Sequence[Mapping[str, Any]],
    dkim_present: bool,
    from_domain: str,
    mode: str,
    fallback_domains: Sequence[str],
) -> Tuple[str, Optional[str], Optional[DKIMAlignmentResult], Optional[str]]:
    valid_domains = [
        str(sig.get("domain"))
        for sig in signatures
        if sig.get("dkim_valid") is True and sig.get("domain")
    ]
    if valid_domains:
        alignment = _select_dkim_alignment(valid_domains, from_domain, mode)
        selected_domain = alignment.dkim_domain if alignment else valid_domains[0]
        if alignment and alignment.aligned:
            return "pass_aligned", None, alignment, selected_domain
        return "pass_unaligned", None, alignment, selected_domain

    if not dkim_present:
        return "none", None, None, None

    reasons = [
        str(sig.get("failure_reason"))
        for sig in signatures
        if sig.get("failure_reason")
    ]
    if "body_hash_mismatch" in reasons:
        return "fail_modified", "body_hash_mismatch", None, None

    missing_key_reasons = {"missing_key", "invalid_key_record", "invalid_key"}
    if reasons and all(reason in missing_key_reasons for reason in reasons):
        return "none", "missing_key", None, None

    if reasons:
        return "fail_invalid", reasons[0], None, None

    fallback_domain = fallback_domains[0] if fallback_domains else None
    return "fail_invalid", None, None, fallback_domain


def _classify_dmarc_status(
    spf: SPFEvaluation,
    spf_aligned: SPFAlignmentResult,
    dkim_status: str,
    dkim_aligned: Optional[DKIMAlignmentResult],
    dmarc: DMARCEvaluation,
    arc: ARCValidation,
) -> str:
    spf_pass = spf.result == "pass"
    dkim_pass = dkim_status in {"pass_aligned", "pass_unaligned"}
    dkim_aligned_bool = dkim_aligned.aligned if dkim_aligned else False

    if dmarc.result == "pass":
        return "pass_strong"

    if arc.valid and arc.latest_result == "pass":
        return "fail_forwarded"

    if spf_pass or dkim_pass:
        return "pass_weak"

    if (not spf_pass or not spf_aligned.aligned) and (not dkim_pass or not dkim_aligned_bool):
        return "fail_spoofed"

    return "fail_spoofed"


def _arc_is_partial_or_absent(arc: ARCValidation) -> bool:
    if arc.chain_count == 0:
        return True
    return arc.failure_reason in {"no_arc_headers", "missing_arc_chain_components"}


def _score_authentication(
    dmarc: DMARCEvaluation,
    arc: ARCValidation,
    spf: SPFEvaluation,
    spf_aligned: bool,
    dkim_status: str,
    dkim_aligned: bool,
) -> Tuple[float, str]:
    """Compute a conservative auth score using multiple signals."""
    spf_pass = spf.result == "pass"
    strong_auth = dkim_status == "pass_aligned" or (spf_pass and spf_aligned)
    weak_auth = (
        dkim_status == "pass_unaligned"
        or spf_pass
        or (dkim_status == "fail_modified" and spf_pass)
    )
    forwarded = dmarc.dmarc_status == "fail_forwarded" and arc.valid and arc.latest_result == "pass"
    spoof_indicators = (
        dmarc.dmarc_status == "fail_spoofed"
        or (dkim_status == "fail_invalid" and not spf_pass and arc.chain_count == 0)
    )

    if spoof_indicators and not strong_auth:
        return -0.7, "Multiple authentication failures indicate likely spoofing"
    if strong_auth:
        return 0.6, "Aligned SPF or DKIM passed; strong authentication signal"
    if forwarded:
        return 0.0, "Forwarded path detected; authentication score left neutral"
    if weak_auth:
        return 0.2, "Partial authentication pass without alignment; weak positive signal"
    return 0.0, "Insufficient authentication signal strength for scoring"


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
    latest_result = validator.extract_arc_result(fields.arc_headers)
    failure_reason = None if valid else explanation

    return ARCValidation(
        valid=valid,
        chain_count=chain_count,
        latest_result=latest_result,
        explanation=explanation,
        failure_reason=failure_reason,
        forwarded=False,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ORCHESTRATION (Phase 8+ integration point)
# ─────────────────────────────────────────────────────────────────────────────


def evaluate_email_authentication(
    extracted: ExtractedEmail,
    dkim_valid: bool,
    dkim_summary: Optional[Mapping[str, Any]] = None,
    resolver: Optional[TXTResolver] = None,
    arc_resolver: Optional[TXTResolver] = None,
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

    # 4. Check DKIM alignment with multi-signature support
    summary = _normalize_dkim_summary(dkim_summary)
    summary_signatures: Tuple[Mapping[str, Any], ...] = ()
    if summary and isinstance(summary.get("signatures"), list):
        summary_signatures = tuple(
            sig for sig in summary.get("signatures", [])
            if isinstance(sig, Mapping)
        )
    dkim_present = bool(summary_signatures) or bool(extracted.dkim_signature_raws)
    dkim_status, dkim_failure_reason, dkim_aligned, selected_domain = _classify_dkim(
        signatures=summary_signatures,
        dkim_present=dkim_present,
        from_domain=fields.from_domain,
        mode=config.dkim_alignment_mode,
        fallback_domains=fields.dkim_domains,
    )
    dkim_valid_effective = bool(summary.get("dkim_valid")) if summary else bool(dkim_valid)
    if dkim_status in {"pass_aligned", "pass_unaligned"}:
        dkim_valid_effective = True
    if dkim_status in {"fail_modified", "fail_invalid"}:
        dkim_valid_effective = False

    # 5. Evaluate DMARC
    dmarc = evaluate_dmarc(
        spf,
        spf_aligned,
        dkim_valid_effective,
        dkim_aligned,
        fields,
        resolver=resolver
    )

    # 6. Validate ARC
    arc = validate_arc(extracted.raw_bytes if hasattr(extracted, "raw_bytes") else b"", fields)

    dmarc_status = _classify_dmarc_status(
        spf=spf,
        spf_aligned=spf_aligned,
        dkim_status=dkim_status,
        dkim_aligned=dkim_aligned,
        dmarc=dmarc,
        arc=arc,
    )
    dmarc = replace(dmarc, dmarc_status=dmarc_status)

    # 7. Determine verdict
    verdict, summary, forwarded = _determine_verdict(
        dmarc=dmarc,
        arc=arc,
        spf=spf,
        spf_aligned=spf_aligned.aligned,
        dkim_status=dkim_status,
        dkim_aligned=dkim_aligned.aligned if dkim_aligned else False
    )
    auth_score, auth_score_explanation = _score_authentication(
        dmarc=dmarc,
        arc=arc,
        spf=spf,
        spf_aligned=spf_aligned.aligned,
        dkim_status=dkim_status,
        dkim_aligned=dkim_aligned.aligned if dkim_aligned else False,
    )

    if forwarded:
        arc = ARCValidation(
            valid=arc.valid,
            chain_count=arc.chain_count,
            latest_result=arc.latest_result,
            explanation=arc.explanation,
            failure_reason=arc.failure_reason,
            forwarded=True,
        )

    return AuthenticationResult(
        spf=spf,
        spf_aligned=spf_aligned,
        dkim_present=dkim_present,
        dkim_valid=dkim_valid_effective,
        dkim_status=dkim_status,
        dkim_failure_reason=dkim_failure_reason,
        dkim_domain=selected_domain or fields.dkim_domain,
        dkim_aligned=dkim_aligned,
        dmarc=dmarc,
        dmarc_status=dmarc_status,
        arc=arc,
        verdict=verdict,
        explanation=summary,
        auth_score=auth_score,
        auth_score_explanation=auth_score_explanation,
    )


def _determine_verdict(
    dmarc: DMARCEvaluation,
    arc: ARCValidation,
    spf: SPFEvaluation,
    spf_aligned: bool,
    dkim_status: str,
    dkim_aligned: bool,
) -> Tuple[str, str, bool]:
    """Determine overall verdict and summary explanation."""
    spf_pass = spf.result == "pass"
    arc_claims_pass = arc.latest_result == "pass"

    if dkim_status == "pass_aligned":
        return "pass", "DKIM aligned signature passed; trusted regardless of SPF", False

    if spf_pass and spf_aligned and dkim_status in {"none", "pass_unaligned", "fail_modified"}:
        return "pass", "SPF passed and aligned; DKIM not required for acceptance", False

    if dmarc.dmarc_status == "fail_forwarded" and arc.valid and arc.latest_result == "pass":
        return "forwarded", (
            "DMARC failed but ARC chain is valid and upstream auth passed; "
            "message classified as forwarded"
        ), True

    if dkim_status == "fail_modified" and spf_pass:
        return "pass", (
            "DKIM failed due to body modification (mailing list/footer); SPF passed, "
            "not treated as spoof"
        ), False

    if not arc.valid and arc_claims_pass and not _arc_is_partial_or_absent(arc):
        return "suspicious", (
            "ARC chain invalid but claims upstream pass; possible header injection"
        ), False

    if dmarc.dmarc_status == "pass_weak":
        return "suspicious", (
            "SPF or DKIM passed without alignment; DMARC failed but weak authentication present"
        ), False

    if (not spf_pass or not spf_aligned) and dkim_status == "fail_invalid" and arc.chain_count == 0:
        return "fail", (
            "SPF failed and DKIM signature invalid with no ARC chain; spoofing likely"
        ), False

    if dmarc.result == "fail":
        return "suspicious", f"Message failed DMARC: {dmarc.explanation}", False

    return "pass", "Message passed authentication checks", False


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
        signals.append(_make_auth_signal(
            "dkim_status",
            auth_result.dkim_status,
            f"DKIM status: {auth_result.dkim_status}"
        ))
        if auth_result.dkim_failure_reason:
            signals.append(_make_auth_signal(
                "dkim_failure_reason",
                auth_result.dkim_failure_reason,
                f"DKIM failure reason: {auth_result.dkim_failure_reason}"
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
    signals.append(_make_auth_signal(
        "dmarc_status",
        auth_result.dmarc_status,
        f"DMARC status: {auth_result.dmarc_status}"
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
        if auth_result.arc.forwarded:
            signals.append(_make_auth_signal(
                "arc_forwarded",
                True,
                "ARC chain valid with upstream pass; message classified as forwarded"
            ))

    signals.append(_make_auth_signal(
        "auth_verdict",
        auth_result.verdict,
        auth_result.explanation
    ))

    signals.append(_make_auth_signal(
        "auth_score",
        auth_result.auth_score,
        auth_result.auth_score_explanation
    ))

    return signals
