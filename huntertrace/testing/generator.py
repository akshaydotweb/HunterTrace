"""Synthetic .eml sample generation for testing.

Generates deterministic, scenario-specific test emails with controlled
characteristics for validating the pipeline across different anomaly types.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Optional


@dataclass
class SyntheticSample:
    """Generated test sample with metadata."""

    content: str  # Full .eml email
    category: str  # Scenario type
    expected_behavior: dict  # {should_abstain, has_anomaly, anonymization}
    metadata: dict  # {seed, timestamp, hops, ...}

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class SyntheticGenerator:
    """Generates scenario-specific .eml samples deterministically."""

    # IPs for different regions
    REGION_IPS = {
        "us": ["192.0.2.1", "198.51.100.1", "203.0.113.1"],
        "eu": ["2001:db8::1", "192.0.2.50", "198.51.100.50"],
        "asia": ["192.0.2.100", "198.51.100.100", "203.0.113.100"],
        "private": ["10.0.0.1", "172.16.0.1", "192.168.1.1"],
    }

    # Hostnames for different scenarios
    HOSTNAMES = {
        "enterprise": ["mail.example.com", "smtp.corporate.net", "relay.acme.org"],
        "relay": ["mail1.isp.net", "mail2.isp.net", "mx.provider.com"],
        "spoofed": ["fake-bank.com", "spoofed-host.net", "impersonator.org"],
        "generic": ["mail-server.test", "relay-host.test", "gateway.test"],
    }

    PROTOCOLS = ["SMTP", "ESMTP", "SMTPS"]
    TIMEZONES = ["+0000", "-0500", "+0100", "+0800", "-0800"]

    @staticmethod
    def generate(scenario_type: str, seed: int) -> SyntheticSample:
        """Generate a single synthetic sample.

        Args:
            scenario_type: One of the defined scenario types
            seed: Random seed for deterministic generation

        Returns:
            SyntheticSample with generated .eml content
        """
        rng = random.Random(seed)
        generated_at = datetime.now(timezone.utc).isoformat()

        if scenario_type == "clean_enterprise":
            return SyntheticGenerator._generate_clean_enterprise(rng, seed, generated_at)
        elif scenario_type == "multi_hop_relay":
            return SyntheticGenerator._generate_multi_hop_relay(rng, seed, generated_at)
        elif scenario_type == "forwarded_chain":
            return SyntheticGenerator._generate_forwarded_chain(rng, seed, generated_at)
        elif scenario_type == "spoofed_headers":
            return SyntheticGenerator._generate_spoofed_headers(rng, seed, generated_at)
        elif scenario_type == "broken_chain":
            return SyntheticGenerator._generate_broken_chain(rng, seed, generated_at)
        elif scenario_type == "timestamp_spoof":
            return SyntheticGenerator._generate_timestamp_spoof(rng, seed, generated_at)
        elif scenario_type == "anonymized_like":
            return SyntheticGenerator._generate_anonymized_like(rng, seed, generated_at)
        elif scenario_type == "malformed_headers":
            return SyntheticGenerator._generate_malformed_headers(rng, seed, generated_at)
        elif scenario_type == "geo_hop":
            return SyntheticGenerator._generate_geo_hop(rng, seed, generated_at)
        elif scenario_type == "vpn_tor_like":
            return SyntheticGenerator._generate_vpn_tor_like(rng, seed, generated_at)
        else:
            raise ValueError(f"Unknown scenario type: {scenario_type}")

    @staticmethod
    def generate_batch(
        scenario_type: str, count: int, seed: int = 42
    ) -> list[SyntheticSample]:
        """Generate multiple samples of the same type.

        Args:
            scenario_type: Scenario type to generate
            count: Number of samples to generate
            seed: Starting seed (incremented for each sample)

        Returns:
            List of SyntheticSample objects
        """
        return [
            SyntheticGenerator.generate(scenario_type, seed + i) for i in range(count)
        ]

    # Generator helper methods for each scenario type

    @staticmethod
    def _generate_clean_enterprise(
        rng: random.Random, seed: int, generated_at: str
    ) -> SyntheticSample:
        """Generate clean enterprise email (no anomalies)."""
        hops = []
        base_time = datetime(2026, 4, 4, 10, 0, 0, tzinfo=timezone.utc)

        # Generate 2-3 clean hops
        num_hops = rng.randint(2, 3)
        for i in range(num_hops):
            timestamp = (base_time - timedelta(minutes=i * 5)).strftime(
                "%a, %d %b %Y %H:%M:%S %z"
            )
            ip = rng.choice(SyntheticGenerator.REGION_IPS["us"])
            hostname = rng.choice(SyntheticGenerator.HOSTNAMES["enterprise"])
            by_hostname = rng.choice(SyntheticGenerator.HOSTNAMES["enterprise"])
            protocol = rng.choice(SyntheticGenerator.PROTOCOLS)

            hop = (
                f"Received: from {hostname} ({hostname} [{ip}])\n"
                f"    by {by_hostname} with {protocol}\n"
                f"    ; {timestamp}"
            )
            hops.append(hop)

        received_headers = "\n".join(hops)
        content = SyntheticGenerator._build_eml(received_headers, "Clean Email", rng=rng)

        return SyntheticSample(
            content=content,
            category="clean_enterprise",
            expected_behavior={
                "should_abstain": False,
                "has_anomaly": False,
                "anonymization": False,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": num_hops,
                "scenario": "clean_enterprise",
            },
        )

    @staticmethod
    def _generate_multi_hop_relay(
        rng: random.Random, seed: int, generated_at: str
    ) -> SyntheticSample:
        """Generate email with multiple relay hops."""
        hops = []
        base_time = datetime(2026, 4, 4, 10, 0, 0, tzinfo=timezone.utc)

        # Generate 4-6 relay hops (all consistent)
        num_hops = rng.randint(4, 6)
        for i in range(num_hops):
            timestamp = (base_time - timedelta(minutes=i * 3)).strftime(
                "%a, %d %b %Y %H:%M:%S %z"
            )
            ip = rng.choice(SyntheticGenerator.REGION_IPS["us"])
            hostname = rng.choice(SyntheticGenerator.HOSTNAMES["relay"])
            by_hostname = rng.choice(SyntheticGenerator.HOSTNAMES["relay"])
            protocol = rng.choice(SyntheticGenerator.PROTOCOLS)

            hop = (
                f"Received: from {hostname} ({hostname} [{ip}])\n"
                f"    by {by_hostname} with {protocol}\n"
                f"    ; {timestamp}"
            )
            hops.append(hop)

        received_headers = "\n".join(hops)
        content = SyntheticGenerator._build_eml(received_headers, "Relay Email")

        return SyntheticSample(
            content=content,
            category="multi_hop_relay",
            expected_behavior={
                "should_abstain": False,
                "has_anomaly": False,
                "anonymization": False,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": num_hops,
                "scenario": "multi_hop_relay",
            },
        )

    @staticmethod
    def _generate_forwarded_chain(
        rng: random.Random, seed: int, generated_at: str
    ) -> SyntheticSample:
        """Generate email forwarded multiple times."""
        hops = []
        base_time = datetime(2026, 4, 4, 10, 0, 0, tzinfo=timezone.utc)

        # Generate forwarding chain
        num_hops = rng.randint(3, 5)
        for i in range(num_hops):
            timestamp = (base_time - timedelta(hours=i)).strftime(
                "%a, %d %b %Y %H:%M:%S %z"
            )
            ip = rng.choice(SyntheticGenerator.REGION_IPS["eu"])
            hostname = f"forwarded-{i}.example.com"
            by_hostname = f"mx-{i}.example.com"
            protocol = "ESMTP"

            hop = (
                f"Received: from {hostname} ({hostname} [{ip}])\n"
                f"    by {by_hostname} with {protocol}\n"
                f"    ; {timestamp}"
            )
            hops.append(hop)

        received_headers = "\n".join(hops)
        content = SyntheticGenerator._build_eml(
            received_headers, "Forwarded Email", has_forwarded_header=True
        )

        return SyntheticSample(
            content=content,
            category="forwarded_chain",
            expected_behavior={
                "should_abstain": False,
                "has_anomaly": False,
                "anonymization": False,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": num_hops,
                "scenario": "forwarded_chain",
            },
        )

    @staticmethod
    def _generate_spoofed_headers(
        rng: random.Random, seed: int, generated_at: str
    ) -> SyntheticSample:
        """Generate email with spoofed headers."""
        hops = []
        base_time = datetime(2026, 4, 4, 10, 0, 0, tzinfo=timezone.utc)

        # Generate spoofing scenario - mismatch in headers
        num_hops = rng.randint(2, 3)
        for i in range(num_hops):
            timestamp = (base_time - timedelta(minutes=i * 5)).strftime(
                "%a, %d %b %Y %H:%M:%S %z"
            )
            ip = rng.choice(SyntheticGenerator.REGION_IPS["us"])
            # Spoofed hostname
            hostname = rng.choice(SyntheticGenerator.HOSTNAMES["spoofed"])
            by_hostname = "real-server.example.com"
            protocol = rng.choice(SyntheticGenerator.PROTOCOLS)

            hop = (
                f"Received: from {hostname} ({hostname} [{ip}])\n"
                f"    by {by_hostname} with {protocol}\n"
                f"    ; {timestamp}"
            )
            hops.append(hop)

        received_headers = "\n".join(hops)
        content = SyntheticGenerator._build_eml(received_headers, "Spoofed Email")

        return SyntheticSample(
            content=content,
            category="spoofed_headers",
            expected_behavior={
                "should_abstain": False,
                "has_anomaly": True,
                "anonymization": False,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": num_hops,
                "scenario": "spoofed_headers",
                "anomaly_type": "spoofing",
            },
        )

    @staticmethod
    def _generate_broken_chain(
        rng: random.Random, seed: int, generated_at: str
    ) -> SyntheticSample:
        """Generate email with broken/incomplete chain."""
        hops = []
        base_time = datetime(2026, 4, 4, 10, 0, 0, tzinfo=timezone.utc)

        # Generate incomplete chain (missing middle hops)
        num_hops = rng.randint(2, 3)
        for i in range(num_hops):
            timestamp = (base_time - timedelta(minutes=i * 10)).strftime(
                "%a, %d %b %Y %H:%M:%S %z"
            )
            ip = rng.choice(SyntheticGenerator.REGION_IPS["us"])
            hostname = f"relay-{i}.test.com"
            by_hostname = f"mx-{i}.test.com"

            # Intentionally incomplete header
            hop = f"Received: from {hostname} [{ip}]\n    by {by_hostname}\n    ; {timestamp}"
            hops.append(hop)

        received_headers = "\n".join(hops)
        content = SyntheticGenerator._build_eml(received_headers, "Broken Chain Email")

        return SyntheticSample(
            content=content,
            category="broken_chain",
            expected_behavior={
                "should_abstain": True,
                "has_anomaly": True,
                "anonymization": False,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": num_hops,
                "scenario": "broken_chain",
                "anomaly_type": "missing_fields",
            },
        )

    @staticmethod
    def _generate_timestamp_spoof(
        rng: random.Random, seed: int, generated_at: str
    ) -> SyntheticSample:
        """Generate email with out-of-order timestamps."""
        hops = []
        base_time = datetime(2026, 4, 4, 10, 0, 0, tzinfo=timezone.utc)

        # Generate hops with reversed/out-of-order timestamps
        timestamps = [
            base_time,
            base_time - timedelta(hours=1),  # Going backwards
            base_time + timedelta(minutes=30),  # Jump forward
            base_time - timedelta(minutes=10),  # Backwards again
        ]

        for i, ts in enumerate(timestamps[:rng.randint(2, 3)]):
            timestamp_str = ts.strftime("%a, %d %b %Y %H:%M:%S %z")
            ip = rng.choice(SyntheticGenerator.REGION_IPS["us"])
            hostname = f"mail-{i}.time-spoofed.com"
            by_hostname = f"mx-{i}.time-spoofed.com"
            protocol = rng.choice(SyntheticGenerator.PROTOCOLS)

            hop = (
                f"Received: from {hostname} ({hostname} [{ip}])\n"
                f"    by {by_hostname} with {protocol}\n"
                f"    ; {timestamp_str}"
            )
            hops.append(hop)

        received_headers = "\n".join(hops)
        content = SyntheticGenerator._build_eml(received_headers, "Timestamp Spoofed Email")

        return SyntheticSample(
            content=content,
            category="timestamp_spoof",
            expected_behavior={
                "should_abstain": False,
                "has_anomaly": True,
                "anonymization": False,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": len(timestamps[:rng.randint(2, 3)]),
                "scenario": "timestamp_spoof",
                "anomaly_type": "temporal",
            },
        )

    @staticmethod
    def _generate_anonymized_like(
        rng: random.Random, seed: int, generated_at: str
    ) -> SyntheticSample:
        """Generate email with anonymization indicators (private IPs)."""
        hops = []
        base_time = datetime(2026, 4, 4, 10, 0, 0, tzinfo=timezone.utc)

        # Generate hops with private IP addresses
        num_hops = rng.randint(3, 5)
        for i in range(num_hops):
            timestamp = (base_time - timedelta(minutes=i * 5)).strftime(
                "%a, %d %b %Y %H:%M:%S %z"
            )
            ip = rng.choice(SyntheticGenerator.REGION_IPS["private"])
            hostname = f"anon-{i}.internal"
            by_hostname = f"internal-{i}.local"
            protocol = rng.choice(SyntheticGenerator.PROTOCOLS)

            hop = (
                f"Received: from {hostname} ({hostname} [{ip}])\n"
                f"    by {by_hostname} with {protocol}\n"
                f"    ; {timestamp}"
            )
            hops.append(hop)

        received_headers = "\n".join(hops)
        content = SyntheticGenerator._build_eml(received_headers, "Anonymized Email")

        return SyntheticSample(
            content=content,
            category="anonymized_like",
            expected_behavior={
                "should_abstain": False,
                "has_anomaly": False,
                "anonymization": True,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": num_hops,
                "scenario": "anonymized_like",
                "anonymization_indicators": "private_ips",
            },
        )

    @staticmethod
    def _generate_malformed_headers(
        rng: random.Random, seed: int, generated_at: str
    ) -> SyntheticSample:
        """Generate email with malformed/invalid headers."""
        # Create intentionally malformed headers
        malformed_hops = [
            "Received: invalid header format without proper fields",
            "Received-From: wrong-format@test.com",
            "Received: from server1 by server2",  # Missing timestamp and IP
        ]

        received_headers = "\n".join(rng.sample(malformed_hops, rng.randint(1, 2)))
        content = SyntheticGenerator._build_eml(received_headers, "Malformed Email")

        return SyntheticSample(
            content=content,
            category="malformed_headers",
            expected_behavior={
                "should_abstain": True,
                "has_anomaly": True,
                "anonymization": False,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": 0,
                "scenario": "malformed_headers",
                "anomaly_type": "malformed",
            },
        )

    @staticmethod
    def _generate_geo_hop(rng: random.Random, seed: int, generated_at: str) -> SyntheticSample:
        """Generate email with hops from multiple geographic regions."""
        hops = []
        base_time = datetime(2026, 4, 4, 10, 0, 0, tzinfo=timezone.utc)
        regions = ["us", "eu", "asia", "us"]  # Multi-region hop chain

        for i, region in enumerate(regions):
            timestamp = (base_time - timedelta(minutes=i * 5)).strftime(
                "%a, %d %b %Y %H:%M:%S %z"
            )
            ip = rng.choice(SyntheticGenerator.REGION_IPS[region])
            hostname = f"mail-{region}-{i}.test.com"
            by_hostname = f"mx-{region}-{i}.test.com"
            protocol = rng.choice(SyntheticGenerator.PROTOCOLS)

            hop = (
                f"Received: from {hostname} ({hostname} [{ip}])\n"
                f"    by {by_hostname} with {protocol}\n"
                f"    ; {timestamp}"
            )
            hops.append(hop)

        received_headers = "\n".join(hops)
        content = SyntheticGenerator._build_eml(received_headers, "Geo-Hop Email")

        return SyntheticSample(
            content=content,
            category="geo_hop",
            expected_behavior={
                "should_abstain": False,
                "has_anomaly": False,
                "anonymization": False,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": len(regions),
                "scenario": "geo_hop",
                "regions": regions,
            },
        )

    @staticmethod
    def _generate_vpn_tor_like(
        rng: random.Random, seed: int, generated_at: str
    ) -> SyntheticSample:
        """Generate email with VPN/Tor-like characteristics."""
        hops = []
        base_time = datetime(2026, 4, 4, 10, 0, 0, tzinfo=timezone.utc)

        # Mix of known VPN provider names and unusual hostnames
        vpn_providers = ["nordvpn.net", "expressvpn.com", "surfshark.net", "protonvpn.com"]

        num_hops = rng.randint(2, 4)
        for i in range(num_hops):
            timestamp = (base_time - timedelta(minutes=i * 5)).strftime(
                "%a, %d %b %Y %H:%M:%S %z"
            )
            # Mix of public and VPN provider IPs
            if i % 2 == 0:
                ip = rng.choice(SyntheticGenerator.REGION_IPS["us"])
                hostname = rng.choice(vpn_providers)
            else:
                ip = f"198.51.100.{rng.randint(1, 254)}"
                hostname = f"proxy-{i}.{rng.choice(vpn_providers)}"

            by_hostname = f"mail-{i}.test.com"
            protocol = rng.choice(SyntheticGenerator.PROTOCOLS)

            hop = (
                f"Received: from {hostname} ({hostname} [{ip}])\n"
                f"    by {by_hostname} with {protocol}\n"
                f"    ; {timestamp}"
            )
            hops.append(hop)

        received_headers = "\n".join(hops)
        content = SyntheticGenerator._build_eml(received_headers, "VPN/Tor-like Email")

        return SyntheticSample(
            content=content,
            category="vpn_tor_like",
            expected_behavior={
                "should_abstain": False,
                "has_anomaly": False,
                "anonymization": False,
            },
            metadata={
                "seed": seed,
                "generated_at": generated_at,
                "hops": num_hops,
                "scenario": "vpn_tor_like",
                "anonymization_indicators": "vpn_providers",
            },
        )

    @staticmethod
    def _build_eml(
        received_headers: str,
        subject: str = "Test Email",
        has_forwarded_header: bool = False,
        rng: Optional[random.Random] = None,
    ) -> str:
        """Build a complete RFC 5322 email from received headers.

        Args:
            received_headers: Received header chain
            subject: Email subject
            has_forwarded_header: Whether to include Forwarded header
            rng: Random generator for deterministic IDs

        Returns:
            Complete EML content
        """
        if rng is None:
            rng = random.Random()

        # Use seeded random for deterministic IDs
        msg_id = f"{rng.randint(10000000, 99999999):08d}"

        sender = f"sender{msg_id}@example.com"
        recipient = f"recipient{msg_id}@example.com"
        timestamp = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z")

        eml = f"""From: {sender}
To: {recipient}
Subject: {subject}
Date: {timestamp}
Message-ID: <{msg_id}@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
{received_headers}

This is a synthetic test email generated for testing purposes.
"""

        if has_forwarded_header:
            eml += "\n---------- Forwarded message ---------\n"
            eml += f"From: original@example.com\n"
            eml += "To: forwarded@example.com\n"
            eml += f"Date: {timestamp}\n"
            eml += "Subject: Original message\n\n"
            eml += "Original message content.\n"

        return eml
