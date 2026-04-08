#!/usr/bin/env python3
"""
huntertrace/attribution/dmarc_validator.py
===========================================
DMARC (Domain-based Message Authentication, Reporting, and Conformance) evaluator.

Fetches DMARC policy records and evaluates message alignment.

Standards: RFC 7489 (DMARC)
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Tuple

from huntertrace.attribution.authentication import DMARCPolicy, DMARCEvaluation


class TXTResolver(Protocol):
    """Protocol for DNS TXT record resolution."""

    def resolve_txt(self, name: str) -> List[str]:
        """Return TXT records for a DNS name."""


class DMARCCache:
    """Cache for DMARC policy lookups."""

    def __init__(self, cache_path: Optional[str] = None):
        default_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        self.cache_path = (
            Path(cache_path) if cache_path
            else default_root / "huntertrace" / "dmarc_cache.json"
        )
        self._data: Optional[Dict[str, str]] = None

    def get(self, domain: str) -> Optional[str]:
        """Get cached DMARC policy."""
        data = self._load()
        return data.get(domain)

    def set(self, domain: str, policy: str) -> None:
        """Cache DMARC policy."""
        data = self._load()
        data[domain] = policy
        self._save(data)

    def _load(self) -> Dict[str, str]:
        if self._data is not None:
            return self._data
        if not self.cache_path.exists():
            self._data = {}
            return self._data
        try:
            content = self.cache_path.read_text(encoding="utf-8")
            self._data = json.loads(content)
            if not isinstance(self._data, dict):
                self._data = {}
        except Exception:
            self._data = {}
        return self._data

    def _save(self, data: Dict[str, str]) -> None:
        """Save cache with deterministic JSON."""
        self._data = data
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True)
        self.cache_path.write_text(content, encoding="utf-8")


class DMARCValidator:
    """DMARC policy validator."""

    def __init__(self, resolver: Optional[TXTResolver] = None, cache_path: Optional[str] = None):
        self.resolver = resolver
        self.cache = DMARCCache(cache_path=cache_path)

    def evaluate(
        self,
        spf_pass: bool,
        spf_aligned: bool,
        dkim_pass: bool,
        dkim_aligned: bool,
        dmarc_domain: str,
    ) -> DMARCEvaluation:
        """
        Evaluate DMARC pass/fail based on SPF and DKIM alignment.

        DMARC passes when:
            (spf_pass AND spf_aligned) OR (dkim_pass AND dkim_aligned)

        Otherwise it fails.
        """
        policy = None
        explanation = ""

        # Fetch DMARC policy if we have a resolver
        if self.resolver:
            policy = self._fetch_dmarc_policy(dmarc_domain)

        # Determine DMARC result
        dmarc_pass = (spf_pass and spf_aligned) or (dkim_pass and dkim_aligned)

        if dmarc_pass:
            explanation = self._explain_pass(spf_pass, spf_aligned, dkim_pass, dkim_aligned)
            result = "pass"
        else:
            explanation = self._explain_fail(spf_pass, spf_aligned, dkim_pass, dkim_aligned)
            result = "fail"

        # Get policy from record if available
        policy_value = policy.policy if policy else "none"

        return DMARCEvaluation(
            result=result,
            policy=policy,
            spf_pass=spf_pass,
            spf_aligned=spf_aligned,
            dkim_pass=dkim_pass,
            dkim_aligned=dkim_aligned,
            explanation=explanation,
        )

    def _fetch_dmarc_policy(self, domain: str) -> Optional[DMARCPolicy]:
        """Fetch and parse DMARC policy from _dmarc.domain TXT record."""
        if not domain or not self.resolver:
            return None

        domain_norm = domain.strip().rstrip(".").lower()

        # Check cache first
        cached = self.cache.get(domain_norm)
        if cached is not None:
            if cached == "":  # Empty string means no DMARC policy
                return None
            return self._parse_dmarc_policy(cached)

        dmarc_domain = f"_dmarc.{domain_norm}"

        try:
            records = self.resolver.resolve_txt(dmarc_domain)
            for record in records:
                if record.startswith("v=DMARC1"):
                    # Cache the result
                    self.cache.set(domain_norm, record)
                    return self._parse_dmarc_policy(record)
        except Exception:
            pass

        # Cache negative result
        self.cache.set(domain_norm, "")
        return None

    def _parse_dmarc_policy(self, record: str) -> DMARCPolicy:
        """Parse DMARC policy record."""
        tags = self._parse_dmarc_tags(record)

        policy = tags.get("p", "none")
        aspf = tags.get("aspf", "r")  # r = relaxed (default)
        adkim = tags.get("adkim", "r")
        subdomain_policy = tags.get("sp")
        reporting_email = tags.get("rua")

        try:
            percentage = int(tags.get("pct", "100"))
        except ValueError:
            percentage = 100

        return DMARCPolicy(
            policy=policy,
            aspf=aspf,
            adkim=adkim,
            subdomain_policy=subdomain_policy,
            reporting_email=reporting_email,
            percentage=percentage,
            raw_record=record,
        )

    def _parse_dmarc_tags(self, record: str) -> dict:
        """Parse DMARC policy tags."""
        tags = {}
        pattern = re.compile(r"(?:^|;)\s*([a-z]+)\s*=\s*([^;]*)", re.IGNORECASE)

        for match in pattern.finditer(record):
            key = match.group(1).strip().lower()
            value = match.group(2).strip()
            tags[key] = value

        return tags

    def _explain_pass(
        self,
        spf_pass: bool,
        spf_aligned: bool,
        dkim_pass: bool,
        dkim_aligned: bool,
    ) -> str:
        """Generate explanation for DMARC pass."""
        reasons = []

        if spf_pass and spf_aligned:
            reasons.append("SPF passed and aligned")

        if dkim_pass and dkim_aligned:
            reasons.append("DKIM passed and aligned")

        return "DMARC passed: " + "; ".join(reasons)

    def _explain_fail(
        self,
        spf_pass: bool,
        spf_aligned: bool,
        dkim_pass: bool,
        dkim_aligned: bool,
    ) -> str:
        """Generate explanation for DMARC fail."""
        reasons = []

        if not spf_pass:
            reasons.append("SPF failed")
        elif not spf_aligned:
            reasons.append("SPF not aligned")

        if not dkim_pass:
            reasons.append("DKIM failed")
        elif not dkim_aligned:
            reasons.append("DKIM not aligned")

        return "DMARC failed: " + "; ".join(reasons)


def evaluate_dmarc_simple(
    spf_pass: bool,
    spf_aligned: bool,
    dkim_pass: bool,
    dkim_aligned: bool,
) -> str:
    """Simple DMARC evaluation (just result, no policy lookup)."""
    if (spf_pass and spf_aligned) or (dkim_pass and dkim_aligned):
        return "pass"
    return "fail"
