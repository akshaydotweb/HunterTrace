#!/usr/bin/env python3
"""
huntertrace/attribution/arc_validator.py
=========================================
ARC (Authenticated Received Chain) validator for forwarded mail handling.

Performs basic ARC chain integrity checks. Full cryptographic validation
is beyond this scope; we focus on structural integrity to identify forwarded mail.

Standards: RFC 8617 (ARC)
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple


class ARCValidator:
    """ARC chain validator."""

    def validate(self, arc_headers: Dict[str, str]) -> Tuple[bool, int, str]:
        """
        Validate ARC chain integrity.

        Arguments:
            arc_headers: Dict[instance_number] -> full ARC header value

        Returns:
            (valid, chain_count, explanation)
        """
        if not arc_headers:
            return False, 0, "no_arc_headers"

        # Verify we have all required headers for each instance
        instances = set()
        seal_count = 0
        msg_sig_count = 0
        auth_results_count = 0

        for instance, header in arc_headers.items():
            instances.add(instance)

            if "ARC-Seal:" in header:
                seal_count += 1
            if "ARC-Message-Signature:" in header:
                msg_sig_count += 1
            if "ARC-Authentication-Results:" in header:
                auth_results_count += 1

        chain_count = len(instances)

        # Verify sequential instance numbering
        if instances:
            instance_nums = sorted([int(i) for i in instances if i.isdigit()])
            if instance_nums != list(range(1, len(instance_nums) + 1)):
                return False, chain_count, "non_sequential_instance_numbers"

        # Verify we have matching counts (should be 1:1:1 or 1:1 for seal)
        if not (seal_count > 0 and msg_sig_count > 0 and auth_results_count > 0):
            return False, chain_count, "missing_arc_chain_components"

        # Basic validation passed
        explanation = f"ARC chain valid with {chain_count} instance(s)"
        return True, chain_count, explanation

    def extract_arc_result(self, arc_headers: Dict[str, str]) -> Optional[str]:
        """Extract the most recent ARC-Authentication-Results."""
        if not arc_headers:
            return None

        # Get highest instance number
        instances = [int(i) for i in arc_headers.keys() if i.isdigit()]
        if not instances:
            return None

        latest_instance = str(max(instances))

        # Find ARC-Authentication-Results for this instance
        for instance, header in arc_headers.items():
            if instance == latest_instance and "ARC-Authentication-Results:" in header:
                header_lower = header.lower()
                if re.search(r"\b(dkim|spf|dmarc)=pass\b", header_lower):
                    return "pass"
                if re.search(r"\b(dkim|spf|dmarc)=fail\b", header_lower):
                    return "fail"
                if re.search(r"\b(dkim|spf|dmarc)=neutral\b", header_lower):
                    return "neutral"
                if re.search(r"\b(dkim|spf|dmarc)=none\b", header_lower):
                    return "none"
                match = re.search(r";\s*(pass|fail|neutral|none)\b", header_lower)
                if match:
                    return match.group(1)

        return None


def validate_arc_simple(arc_headers: Dict[str, str]) -> bool:
    """Simple ARC validation - just check if valid chain exists."""
    validator = ARCValidator()
    valid, _, _ = validator.validate(arc_headers)
    return valid
