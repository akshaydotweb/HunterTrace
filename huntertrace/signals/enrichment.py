"""Signal enrichment module - adds geographic and categorical information to signals."""

from __future__ import annotations

from typing import Optional

from huntertrace.analysis.models import Signal


class SignalEnricher:
    """Enrich signals with candidate_region and group information."""

    # IP ranges to region mapping (CIDR-like patterns for common providers)
    IP_REGION_MAP = {
        # Google
        "172.217.": "us-west",
        "172.218.": "us-west",
        "142.251.": "us-west",
        "209.85.": "us-west",
        # Microsoft/Outlook
        "40.107.": "us-east",
        "52.101.": "us-east",
        "40.74.": "us-east",
        # Amazon AWS US
        "79.125.": "us-east-1",  # US East
        "54.": "us-west",  # AWS multi-region
        # Amazon AWS EU
        "195.154.": "eu-central",
        "176.32.": "eu-west",
        # European ISPs
        "195.": "eu-central",
        "203.": "eu-west",
        # Asia Pacific
        "60.48.": "asia-southeast",
        "210.": "asia-east",
        "203.215.": "asia-southeast",
        # Internal networks
        "10.": "internal",
        "172.16.": "internal",
        "172.17.": "internal",
        "172.18.": "internal",
        "172.19.": "internal",
        "172.20.": "internal",
        "172.21.": "internal",
        "172.22.": "internal",
        "172.23.": "internal",
        "172.24.": "internal",
        "172.25.": "internal",
        "172.26.": "internal",
        "172.27.": "internal",
        "172.28.": "internal",
        "172.29.": "internal",
        "172.30.": "internal",
        "172.31.": "internal",
        "192.0.": "internal",
        "192.168.": "internal",
        "127.": "local",
    }

    # Domain patterns to region mapping
    DOMAIN_REGION_MAP = {
        # Google/Alphabet
        "google.com": "us-west",
        "gmail.com": "us-west",
        "googlemail.com": "us-west",
        # Microsoft
        "outlook.com": "us-east",
        "office365.com": "us-east",
        "microsoft.com": "us-east",
        # AWS regions
        "amazonaws.com": "us-east-1",
        "us-west": "us-west",
        "us-east": "us-east",
        "eu-central": "eu-central",
        "eu-west": "eu-west",
        "ap-southeast": "asia-southeast",
        # European
        ".de": "eu-central",
        ".eu": "eu-central",
        ".uk": "eu-west",
        ".fr": "eu-west",
        # Asia-Pacific
        ".sg": "asia-southeast",
        ".jp": "asia-east",
        ".cn": "asia-east",
        ".au": "asia-southeast",
        # Hosting
        "aws": "us-east-1",
        "heroku": "us-west",
        "digitalocean": "us-east",
    }

    @staticmethod
    def enrich_signal(signal) -> Signal:
        """Enrich a single signal with candidate_region and group."""
        candidate_region = SignalEnricher._extract_region(signal)
        group = SignalEnricher._extract_group(signal)

        return Signal(
            signal_id=signal.signal_id if hasattr(signal, "signal_id") else f"{signal.source}::{signal.name}",
            name=signal.name,
            value=signal.value,
            source=signal.source,
            validation_flags=getattr(signal, "validation_flags", ()),
            confidence=getattr(signal, "confidence_initial", 0.5),
            evidence=getattr(signal, "evidence", ""),
            candidate_region=candidate_region,
            group=group,
        )

    @staticmethod
    def _extract_region(signal) -> Optional[str]:
        """Extract region from signal using multiple heuristics."""
        value_str = str(signal.value).lower()
        name = signal.name.lower()

        # 1. IP-based enrichment
        if "ip" in name or "address" in name:
            for ip_prefix, region in SignalEnricher.IP_REGION_MAP.items():
                if value_str.startswith(ip_prefix):
                    return region

        # 2. Hostname/domain enrichment
        if "host" in name or "domain" in name or "." in value_str:
            # Check for internal/private indicators first
            if any(x in value_str for x in ["internal", "localhost", "local", ".local", "private"]):
                return "internal"

            for domain_pattern, region in SignalEnricher.DOMAIN_REGION_MAP.items():
                if domain_pattern in value_str:
                    return region

        # 3. Timezone-based enrichment
        if "timezone" in name or "date" in name or "timestamp" in name:
            if any(tz in value_str for tz in ["PST", "PDT", "us-west", "california"]):
                return "us-west"
            elif any(tz in value_str for tz in ["EST", "EDT", "us-east", "newyork"]):
                return "us-east"
            elif any(tz in value_str for tz in ["GMT", "UTC", "CET", "eu-", "europe"]):
                return "eu-central"
            elif any(tz in value_str for tz in ["SGT", "JST", "asia", "singapore", "tokyo"]):
                return "asia-southeast"

        # 4. Protocol/version hints
        if "protocol" in name:
            if "esmtps" in value_str:
                return "us-east"  # Common in enterprise
            elif "smtp" in value_str:
                return "us-west"  # Generic

        # 5. Default fallback
        if ".com" in value_str or ".net" in value_str or ".org" in value_str:
            return "us-west"  # US-centric inference

        return None

    @staticmethod
    def _extract_group(signal) -> Optional[str]:
        """Extract signal group from signal name."""
        name = signal.name.lower()

        if any(x in name for x in ["timestamp", "date", "time", "utc", "timezone"]):
            return "temporal"
        elif any(x in name for x in ["from", "by", "host", "ip", "protocol", "via"]):
            return "infrastructure"
        elif any(x in name for x in ["anomaly", "chain", "completeness", "count", "flag"]):
            return "structure"
        else:
            return "quality"

    @staticmethod
    def enrich_signals(signals: list) -> list:
        """Enrich multiple signals."""
        return [SignalEnricher.enrich_signal(sig) for sig in signals]
