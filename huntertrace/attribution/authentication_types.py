#!/usr/bin/env python3
"""
huntertrace/attribution/authentication_types.py
==============================================
Shared dataclasses for email authentication layer.

These are defined separately to avoid circular imports between
authentication.py and dmarc_validator.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from huntertrace.core.models.extracted import ReceivedHop


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
    dmarc_status: str = ""


@dataclass(frozen=True)
class ARCValidation:
    """Result of ARC chain validation."""

    valid: bool
    chain_count: int = 0
    latest_result: Optional[str] = None  # pass, fail, neutral, none
    explanation: str = ""
    failure_reason: Optional[str] = None
    failed_instance: Optional[int] = None
    upstream_auth_results: Tuple[Dict[str, str], ...] = ()
    upstream_summary: str = ""
    forwarded: bool = False


@dataclass(frozen=True)
class AuthenticationResult:
    """Complete authentication evaluation for an email."""

    spf: SPFEvaluation
    spf_aligned: SPFAlignmentResult
    dkim_present: bool
    dkim_valid: bool
    dkim_status: str
    dkim_failure_reason: Optional[str]
    dkim_domain: Optional[str]
    dkim_aligned: Optional[DKIMAlignmentResult]
    dmarc: DMARCEvaluation
    dmarc_status: str
    arc: ARCValidation

    # Forensic summary
    verdict: str  # pass, fail, suspicious
    explanation: str
    auth_score: float
    auth_score_explanation: str


@dataclass(frozen=True)
class AuthenticationFields:
    """Extracted authentication-relevant fields from email."""

    from_domain: str
    return_path_domain: str
    connecting_ip: str
    dkim_domain: Optional[str]
    received_chain: List[ReceivedHop]
    dkim_domains: Tuple[str, ...] = ()
    auth_results_raw: Optional[str] = None
    received_spf_raw: Optional[str] = None
    date_raw: Optional[str] = None
    arc_headers: Dict[str, str] = None  # type: ignore
    auth_results_hints: Optional[str] = None

    def __post_init__(self):
        if self.arc_headers is None:
            object.__setattr__(self, 'arc_headers', {})
        if self.auth_results_hints is None:
            object.__setattr__(self, 'auth_results_hints', None)


@dataclass
class AuthenticationConfig:
    """Configuration for authentication validation."""

    spf_alignment_mode: str = "relaxed"  # strict or relaxed
    dkim_alignment_mode: str = "relaxed"
    dmarc_alignment_mode: str = "relaxed"
    cache_path: Optional[str] = None
    max_spf_recursion: int = 10
    follow_spf_includes: bool = True
