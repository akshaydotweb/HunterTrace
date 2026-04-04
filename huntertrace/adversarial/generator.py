"""Deterministic adversarial sample generation engine."""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from huntertrace.adversarial.models import AdversarialSample, AttackSeverity, AttackType, MutationTrace


class DeterministicRNG:
    """Deterministic pseudo-random number generator using LCG (Linear Congruential Generator)."""

    def __init__(self, seed: int):
        """Initialize with seed."""
        self.seed = seed
        self.state = seed
        # LCG parameters (using same as glibc)
        self.a = 1103515245
        self.c = 12345
        self.m = 2**31

    def next(self) -> float:
        """Return next random number in [0.0, 1.0)."""
        self.state = (self.a * self.state + self.c) % self.m
        return self.state / self.m

    def choice(self, items: List[str]) -> str:
        """Deterministically choose from list."""
        if not items:
            return ""
        idx = int(self.next() * len(items))
        return items[idx % len(items)]

    def randint(self, a: int, b: int) -> int:
        """Deterministically generate int in [a, b]."""
        return a + int(self.next() * (b - a + 1))


class AdversarialGenerator:
    """Generate deterministic adversarial email variants."""

    # Common provider patterns for relay_mimicry attack
    COMMON_PROVIDERS = [
        "gmail.com",
        "outlook.com",
        "yahoo.com",
        "protonmail.com",
        "mail.ru",
        "163.com",
    ]

    # Common infrastructure prefixes
    INFRA_PREFIXES = ["mta", "mail", "smtp", "relay", "gateway"]

    @staticmethod
    def generate_variants(
        email_content: str,
        original_path: str,
        attack_types: Optional[List[str]] = None,
        severity: Optional[str] = None,
        seed: int = 42,
    ) -> List[AdversarialSample]:
        """
        Generate adversarial variants of an email.

        Args:
            email_content: Original email content (headers + body)
            original_path: Path to original email
            attack_types: Which attacks to generate (default: all)
            severity: Severity level (low/medium/high) affecting mutation intensity
            seed: Random seed for determinism

        Returns:
            List of AdversarialSample objects representing mutations
        """
        if attack_types is None:
            attack_types = [t.value for t in AttackType]
        if severity is None:
            severity = AttackSeverity.MEDIUM.value

        samples = []
        variant_seed = seed

        for attack_type in attack_types:
            try:
                modified_content, mutation_trace = AdversarialGenerator._apply_attack(
                    email_content=email_content,
                    attack_type=attack_type,
                    severity=severity,
                    seed=variant_seed,
                )

                if modified_content and mutation_trace.parser_valid:
                    sample = AdversarialSample(
                        original_path=original_path,
                        modified_content=modified_content,
                        attack_type=attack_type,
                        severity=severity,
                        seed=variant_seed,
                        mutation_trace=mutation_trace,
                    )
                    samples.append(sample)
            except Exception:
                # Skip if generation fails
                continue

            variant_seed += 1

        return samples

    @staticmethod
    def _apply_attack(
        email_content: str,
        attack_type: str,
        severity: str,
        seed: int,
    ) -> Tuple[str, MutationTrace]:
        """
        Apply adversarial attack to email content.

        Returns:
            (modified_email_content, mutation_trace)
        """
        rng = DeterministicRNG(seed)

        if attack_type == AttackType.HEADER_INJECTION.value:
            return AdversarialGenerator._header_injection(email_content, severity, rng)
        elif attack_type == AttackType.TIMESTAMP_SPOOFING.value:
            return AdversarialGenerator._timestamp_spoofing(email_content, severity, rng)
        elif attack_type == AttackType.HOP_CHAIN_BREAK.value:
            return AdversarialGenerator._hop_chain_break(email_content, severity, rng)
        elif attack_type == AttackType.RELAY_MIMICRY.value:
            return AdversarialGenerator._relay_mimicry(email_content, severity, rng)
        elif attack_type == AttackType.INFRASTRUCTURE_CONFLICT.value:
            return AdversarialGenerator._infrastructure_conflict(email_content, severity, rng)
        elif attack_type == AttackType.HEADER_OBFUSCATION.value:
            return AdversarialGenerator._header_obfuscation(email_content, severity, rng)
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

    @staticmethod
    def _header_injection(
        email_content: str, severity: str, rng: DeterministicRNG
    ) -> Tuple[str, MutationTrace]:
        """Inject or duplicate fake Received headers."""
        lines = email_content.split("\n")
        received_headers = []
        header_end_idx = 0

        # Find all Received headers
        for i, line in enumerate(lines):
            if line.startswith("Received:"):
                received_headers.append(i)
                header_end_idx = i

        mutations = []
        if not received_headers:
            # Create synthetic Received header at start
            fake_header = "Received: from unknown (unknown [127.0.0.1]) by localhost with SMTP"
            lines.insert(0, fake_header)
            mutations.append(("start", "Injected synthetic Received header"))
            header_end_idx = 0

        # Duplicate headers based on severity
        mutation_count = {"low": 1, "medium": 2, "high": 3}.get(severity, 1)

        for _ in range(mutation_count):
            if received_headers:
                source_idx = rng.choice(received_headers)
                if isinstance(source_idx, str):
                    source_idx = received_headers[0]
                duplicate = lines[source_idx] + f" (injected-{rng.randint(1000, 9999)})"
                insert_pos = header_end_idx + 1 + _
                lines.insert(insert_pos, duplicate)
                mutations.append(
                    (f"position_{insert_pos}", f"Duplicated Received header #{_ + 1}")
                )

        modified_content = "\n".join(lines)
        parser_valid = _validate_email_format(modified_content)

        trace = MutationTrace(
            attack_type=AttackType.HEADER_INJECTION.value,
            severity=severity,
            mutations=mutations,
            mutation_count=len(mutations),
            parser_valid=parser_valid,
            description="Injected or duplicated Received headers to confuse hop analysis",
        )

        return modified_content, trace

    @staticmethod
    def _timestamp_spoofing(
        email_content: str, severity: str, rng: DeterministicRNG
    ) -> Tuple[str, MutationTrace]:
        """Create identical or non-monotonic timestamps."""
        lines = email_content.split("\n")
        mutations = []

        # Find Date header
        date_idx = None
        for i, line in enumerate(lines):
            if line.startswith("Date:"):
                date_idx = i
                break

        # Find Received headers with timestamps
        timestamp_indices = []
        for i, line in enumerate(lines):
            if line.startswith("Received:") and ";" in line:
                timestamp_indices.append(i)

        if not timestamp_indices:
            return email_content, MutationTrace(
                attack_type=AttackType.TIMESTAMP_SPOOFING.value,
                severity=severity,
                mutations=[],
                mutation_count=0,
                parser_valid=False,
                description="No timestamps found",
            )

        # Apply timestamp spoofing
        if severity == "low":
            # Identical timestamps
            patterns_to_spoof = [timestamp_indices[0]]
        elif severity == "medium":
            # Mix of identical and non-monotonic
            patterns_to_spoof = timestamp_indices[: len(timestamp_indices) // 2]
        else:  # high
            # All timestamps get spoofed
            patterns_to_spoof = timestamp_indices

        # Use first timestamp as reference
        ref_line = lines[timestamp_indices[0]]
        ref_time = _extract_timestamp(ref_line)

        for idx in patterns_to_spoof:
            if ref_time:
                # Replace timestamp with reference time
                new_line = lines[idx].replace(
                    _extract_timestamp(lines[idx]) or "", ref_time
                )
                lines[idx] = new_line
                mutations.append((f"header_{idx}", f"Synchronized timestamp to {ref_time}"))

        modified_content = "\n".join(lines)
        parser_valid = _validate_email_format(modified_content)

        trace = MutationTrace(
            attack_type=AttackType.TIMESTAMP_SPOOFING.value,
            severity=severity,
            mutations=mutations,
            mutation_count=len(mutations),
            parser_valid=parser_valid,
            description="Applied non-monotonic or identical timestamps to break temporal analysis",
        )

        return modified_content, trace

    @staticmethod
    def _hop_chain_break(
        email_content: str, severity: str, rng: DeterministicRNG
    ) -> Tuple[str, MutationTrace]:
        """Remove intermediate hops from chain."""
        lines = email_content.split("\n")
        mutations = []

        # Find Received headers
        received_indices = []
        for i, line in enumerate(lines):
            if line.startswith("Received:"):
                received_indices.append(i)

        if len(received_indices) < 2:
            return email_content, MutationTrace(
                attack_type=AttackType.HOP_CHAIN_BREAK.value,
                severity=severity,
                mutations=[],
                mutation_count=0,
                parser_valid=False,
                description="Insufficient hops to break",
            )

        # Remove hops based on severity
        removal_count = {"low": 1, "medium": 2, "high": 4}.get(severity, 1)
        removal_count = min(removal_count, len(received_indices) - 1)

        # Remove from middle (preserve first and last for parser validation)
        indices_to_remove = received_indices[1 : 1 + removal_count]
        indices_to_remove.sort(reverse=True)  # Remove from end to start to preserve indices

        for idx in indices_to_remove:
            lines.pop(idx)
            mutations.append((f"hop_{idx}", "Removed intermediate Received header"))

        modified_content = "\n".join(lines)
        parser_valid = _validate_email_format(modified_content)

        trace = MutationTrace(
            attack_type=AttackType.HOP_CHAIN_BREAK.value,
            severity=severity,
            mutations=mutations,
            mutation_count=len(mutations),
            parser_valid=parser_valid,
            description="Broke hop chain by removing intermediate headers",
        )

        return modified_content, trace

    @staticmethod
    def _relay_mimicry(
        email_content: str, severity: str, rng: DeterministicRNG
    ) -> Tuple[str, MutationTrace]:
        """Replace hosts with common provider patterns."""
        lines = email_content.split("\n")
        mutations = []

        received_indices = []
        for i, line in enumerate(lines):
            if line.startswith("Received:"):
                received_indices.append(i)

        mutation_count = {"low": 1, "medium": 2, "high": 4}.get(severity, 1)
        mutation_count = min(mutation_count, len(received_indices))

        for i in range(mutation_count):
            idx = received_indices[i] if i < len(received_indices) else received_indices[0]
            old_line = lines[idx]

            # Replace domain patterns with common providers
            replaced_provider = rng.choice(AdversarialGenerator.COMMON_PROVIDERS)
            new_line = old_line

            # Replace any domain-like patterns
            new_line = re.sub(r"\b[a-z0-9-]+\.(com|org|net|io)\b", replaced_provider, new_line)

            if new_line != old_line:
                lines[idx] = new_line
                mutations.append(
                    (f"relay_{idx}", f"Mimicked provider: {replaced_provider}")
                )

        modified_content = "\n".join(lines)
        parser_valid = _validate_email_format(modified_content)

        trace = MutationTrace(
            attack_type=AttackType.RELAY_MIMICRY.value,
            severity=severity,
            mutations=mutations,
            mutation_count=len(mutations),
            parser_valid=parser_valid,
            description="Replaced relay hosts with common provider patterns",
        )

        return modified_content, trace

    @staticmethod
    def _infrastructure_conflict(
        email_content: str, severity: str, rng: DeterministicRNG
    ) -> Tuple[str, MutationTrace]:
        """Inject conflicting IP/host patterns."""
        lines = email_content.split("\n")
        mutations = []

        # Find Received headers
        received_indices = []
        for i, line in enumerate(lines):
            if line.startswith("Received:"):
                received_indices.append(i)

        for idx in received_indices:
            if rng.next() < {"low": 0.3, "medium": 0.6, "high": 0.9}.get(severity, 0.6):
                old_line = lines[idx]

                # Inject conflicting infrastructure
                prefix = rng.choice(AdversarialGenerator.INFRA_PREFIXES)
                conflicting_host = f"{prefix}-{rng.randint(1, 100)}.internal.test"
                conflicting_ip = f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 255)}"

                new_line = old_line + f" (conflicting-host={conflicting_host}; conflicting-ip={conflicting_ip})"
                lines[idx] = new_line
                mutations.append(
                    (f"infra_{idx}", f"Injected conflicting infra: {conflicting_host}")
                )

        modified_content = "\n".join(lines)
        parser_valid = _validate_email_format(modified_content)

        trace = MutationTrace(
            attack_type=AttackType.INFRASTRUCTURE_CONFLICT.value,
            severity=severity,
            mutations=mutations,
            mutation_count=len(mutations),
            parser_valid=parser_valid,
            description="Injected conflicting infrastructure signals",
        )

        return modified_content, trace

    @staticmethod
    def _header_obfuscation(
        email_content: str, severity: str, rng: DeterministicRNG
    ) -> Tuple[str, MutationTrace]:
        """Malformed but parseable header variations."""
        lines = email_content.split("\n")
        mutations = []

        # Find any headers and apply obfuscation
        mutation_count = {"low": 1, "medium": 2, "high": 4}.get(severity, 1)

        for _ in range(mutation_count):
            # Find a random header line
            header_lines = [i for i, line in enumerate(lines) if ":" in line and i > 0]
            if not header_lines:
                break

            idx = rng.choice([str(h) for h in header_lines])
            try:
                idx = int(idx)
            except:
                idx = header_lines[0]

            old_line = lines[idx]

            # Apply obfuscation: add whitespace, extra characters, etc.
            obfuscation_type = rng.randint(0, 2)
            if obfuscation_type == 0:
                # Add extra spaces
                new_line = old_line.replace(": ", ":  ")
            elif obfuscation_type == 1:
                # Add comment-like text
                new_line = old_line + " (obfuscated)"
            else:
                # Line wrapping
                new_line = old_line + "\n  continuation"

            lines[idx] = new_line
            mutations.append((f"header_{idx}", f"Applied obfuscation type {obfuscation_type}"))

        modified_content = "\n".join(lines)
        parser_valid = _validate_email_format(modified_content)

        trace = MutationTrace(
            attack_type=AttackType.HEADER_OBFUSCATION.value,
            severity=severity,
            mutations=mutations,
            mutation_count=len(mutations),
            parser_valid=parser_valid,
            description="Applied malformed but parseable header variations",
        )

        return modified_content, trace


def _extract_timestamp(header_line: str) -> Optional[str]:
    """Extract RFC 2822 timestamp from Received header."""
    # Simple regex to find timestamp pattern (simplified)
    match = re.search(r"(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})", header_line)
    if match:
        return match.group(1)
    return None


def _validate_email_format(email_content: str) -> bool:
    """Check if email maintains basic parseable format."""
    try:
        if not email_content:
            return False

        lines = email_content.split("\n")

        # Must have at least minimal headers
        required_headers = ["From:", "To:", "Date:", "Subject:", "Received:"]
        has_headers = any(
            line.startswith(h)
            for line in lines
            for h in required_headers
        )

        return has_headers
    except Exception:
        return False
