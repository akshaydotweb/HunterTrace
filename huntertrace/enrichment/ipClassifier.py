#!/usr/bin/env python3
"""
IP CLASSIFICATION MODULE — VPN / DATACENTER / RESIDENTIAL DETECTION
=====================================================================

Stage 2 of the HunterTrace pipeline. Takes a list of IPs extracted from
the Received: chain and classifies each one into a category that determines
how much we should trust it as a potential attacker origin.

CLASSIFICATION TAXONOMY
-----------------------
  TOR_EXIT          — Tor exit node. Confirmed from Tor Project's published
                      exit-address list. 95% confidence minimum.

  VPN_PROVIDER      — Matches a known commercial VPN ASN or IP prefix.
                      Confidence 80–90% depending on ASN match quality.

  DATACENTER        — AWS, Azure, GCP, DigitalOcean, Hetzner etc.
                      Could be a VPN backend or attacker-rented server.

  RESIDENTIAL_PROXY — Looks residential but flagged by AbuseIPDB as a known
                      RESIP (residential proxy). High abuse score on a home ISP.

  RESIDENTIAL       — Home ISP (Comcast, Jio, BT etc.) with no abuse history.
                      Highest-value category for attacker attribution.

  ATTACKER_ORIGIN   — AbuseIPDB score > 75. Highly likely criminal IP.

  SUSPICIOUS        — AbuseIPDB score 25–75.

  UNKNOWN           — No useful signals found.

DESIGN DECISIONS
----------------
  1. Tor check runs first — Tor exit nodes are the highest-confidence
     unforgeable signal.

  2. VPN ASN check runs second — We maintain a curated table of ASNs
     that belong exclusively to commercial VPN providers. This is
     more reliable than IP prefix matching because prefixes change
     but ASN assignments are stable.

  3. AbuseIPDB fills the gap — For IPs not matched by ASN or Tor,
     the abuse score provides evidence-based classification.

  4. Hosting type keywords (from hostingKeywordsIntegration.py) are
     used to distinguish DATACENTER from RESIDENTIAL when WHOIS org
     name is available.

  5. Residential proxy detection: an IP on a home ISP with an abuse
     score > 40 is treated as RESIDENTIAL_PROXY, not plain RESIDENTIAL.
     This catches "proxy farms" that sell access to compromised home IPs.

PIPELINE POSITION
-----------------
  Feeds into:
    - Stage 3A (ProxyChainTracer) — classifies the chain layer by layer
    - Real IP Extractor — non-VPN/non-Tor IPs become real-IP candidates
    - Geolocation Enrichment — attacker IP is prioritised for geolocation

API KEYS (from .env or environment):
  ABUSEIPDB_API_KEY — Required for abuse-score classification.
                      Get a free key at https://www.abuseipdb.com/
  SHODAN_API_KEY    — Optional. Used for port/service fingerprinting.

USAGE:
    from huntertrace.enrichment.ip_classifier import IPClassifier, classify_ip_list

    # Single IP
    result = IPClassifier().classify("203.0.113.42")
    print(result.classification, result.confidence)

    # Batch (returns dict keyed by IP)
    results = classify_ip_list(["203.0.113.42", "45.33.32.156"])
"""

import os
import re
import time
import ipaddress
import requests
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set
from enum import Enum
from datetime import datetime


# ============================================================================
# ENUMS & DATA STRUCTURES
# ============================================================================

class IPCategory(Enum):
    """Ordered from most-likely-attacker to least-useful for attribution."""
    RESIDENTIAL       = "RESIDENTIAL"           # Home ISP — best attribution target
    RESIDENTIAL_PROXY = "RESIDENTIAL_PROXY"     # Compromised home IP used as proxy
    ATTACKER_ORIGIN   = "ATTACKER_ORIGIN"       # High-abuse score, not a VPN/Tor
    SUSPICIOUS        = "SUSPICIOUS"            # Moderate abuse score
    DATACENTER        = "DATACENTER"            # Cloud/hosting — could be VPN backend
    VPN_PROVIDER      = "VPN_PROVIDER"          # Commercial VPN exit node
    TOR_EXIT          = "TOR_EXIT"              # Tor anonymity network exit
    UNKNOWN           = "UNKNOWN"               # No useful signals


@dataclass
class IPClassificationResult:
    """Full classification result for one IP address."""
    ip:                  str
    category:            IPCategory
    classification:      str               # human-readable label (= category.value)
    confidence:          float             # 0.0 – 1.0
    evidence:            List[str]         # ordered list, most important first
    country:             Optional[str]
    asn:                 Optional[str]
    provider:            Optional[str]     # ISP / hosting org name
    threat_score:        int               # 0 – 100 from AbuseIPDB
    abuse_reports:       int               # lifetime report count from AbuseIPDB
    is_vpn:              bool
    is_tor:              bool
    is_proxy:            bool
    is_residential:      bool
    is_datacenter:       bool
    techniques_applied:  List[str]         # which checks ran
    timestamp_analyzed:  str

    def __str__(self):
        return (
            f"[{self.classification}] {self.ip}  "
            f"conf={self.confidence:.0%}  "
            f"abuse={self.threat_score}/100  "
            f"country={self.country or '?'}"
        )


# ============================================================================
# KNOWN VPN ASNs
# The most reliable VPN detection signal. ASNs are assigned by RIRs and
# don't change — a NordVPN ASN today will still be NordVPN next year.
# An IP-prefix list would require constant maintenance; ASNs do not.
# ============================================================================

VPN_ASNS: Dict[str, str] = {
    # NordVPN
    "AS51908":  "NordVPN",
    "AS200651": "NordVPN",
    "AS62209":  "NordVPN",

    # ExpressVPN
    "AS41387":  "ExpressVPN",
    "AS6739":   "ExpressVPN",

    # Surfshark
    "AS68127":  "Surfshark",
    "AS200557": "Surfshark",

    # ProtonVPN
    "AS32542":  "ProtonVPN",
    "AS62597":  "ProtonVPN",

    # CyberGhost
    "AS43350":  "CyberGhost",
    "AS35540":  "CyberGhost",

    # Private Internet Access (PIA)
    "AS48693":  "Private Internet Access",
    "AS397431": "Private Internet Access",

    # HideMyAss (now Avast)
    "AS49335":  "HideMyAss",

    # Mullvad — known for strong privacy focus
    "AS39351":  "Mullvad",

    # IPVanish
    "AS46562":  "IPVanish",

    # Windscribe
    "AS36352":  "Windscribe",

    # TorGuard
    "AS40021":  "TorGuard",

    # AirVPN
    "AS136753": "AirVPN",

    # IVPN
    "AS198093": "IVPN",

    # VyprVPN
    "AS25820":  "VyprVPN (Golden Frog)",

    # Astrill VPN
    "AS14061":  "Datacenter/Hosting (DigitalOcean — check WHOIS)",
    "AS16509":  "Datacenter/Hosting (AWS — check WHOIS)",
    "AS15169":  "Datacenter/Hosting (Google — check WHOIS)",
    "AS8075":   "Datacenter/Hosting (Microsoft Azure — check WHOIS)",
    "AS20473":  "Datacenter/Hosting (Vultr — check WHOIS)",
    "AS24940":  "Datacenter/Hosting (Hetzner — check WHOIS)",
    "AS16276":  "Datacenter/Hosting (OVH — check WHOIS)",
}

# ASNs that are ALWAYS datacenter (cloud/hosting), never residential
DATACENTER_ASNS: Set[str] = {
    "AS16509",   # Amazon AWS
    "AS14618",   # Amazon AWS (region 2)
    "AS15169",   # Google Cloud
    "AS8075",    # Microsoft Azure
    "AS20940",   # Akamai
    "AS14061",   # DigitalOcean
    "AS20473",   # Vultr
    "AS24940",   # Hetzner
    "AS16276",   # OVH
    "AS35540",   # Leaseweb
    "AS12876",   # Scaleway
    "AS24785",   # Kinsta
    "AS396982",  # Google Cloud (GCP)
    "AS13335",   # Cloudflare
    "AS32934",   # Facebook (Meta infra)
    "AS2906",    # Netflix CDN
}

# Keywords in WHOIS org name that indicate datacenter/hosting
DATACENTER_KEYWORDS = frozenset([
    "amazon", "aws", "google", "azure", "microsoft", "digitalocean",
    "linode", "vultr", "hetzner", "ovh", "leaseweb", "scaleway",
    "rackspace", "softlayer", "ionos", "1&1", "cloudflare", "akamai",
    "fastly", "data center", "datacenter", "colocation", "colo",
    "hosting", "cloud", "vps", "dedicated server", "server farm",
    "internet exchange", "cdn", "content delivery",
    # Russian/Eastern European hosters often used by attackers
    "selectel", "timeweb", "beget", "firstvds", "fastvps",
    # Chinese cloud
    "aliyun", "alibaba", "tencent", "huawei cloud", "qcloud",
])

# Keywords in WHOIS org name that indicate residential ISP
RESIDENTIAL_KEYWORDS = frozenset([
    "comcast", "xfinity", "verizon", "at&t", "att", "cox",
    "charter", "spectrum", "centurylink", "lumen", "frontier",
    "windstream", "mediacom",
    # UK
    "bt", "btinternet", "virgin media", "talktalk", "sky",
    "plusnet", "vodafone uk", "o2 uk", "ee limited",
    # Europe
    "orange", "sfr", "bouygues", "deutsche telekom", "telekom",
    "swisscom", "telecom italia", "telia", "telenor",
    # India
    "jio", "airtel", "bsnl", "mtnl", "act fibernet", "hathway",
    # Russia
    "rostelecom", "beeline", "megafon", "mts",
    # Other Asia-Pacific
    "ntt", "kddi", "softbank", "kt corp", "telstra", "optus",
    "singtel", "starhub", "maxis",
    # Generic residential signals
    "broadband", "cable", "dsl", "fiber",
])

# Private/reserved ranges that are never attacker IPs
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip: str) -> bool:
    """Return True if IP is RFC1918 / loopback / link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return True


def _classify_org_by_keyword(org: str) -> Optional[str]:
    """
    Scan WHOIS org string against known keyword lists.
    Returns 'DATACENTER', 'RESIDENTIAL', or None if no match.
    """
    if not org:
        return None
    org_lower = org.lower()

    if any(kw in org_lower for kw in DATACENTER_KEYWORDS):
        return "DATACENTER"
    if any(kw in org_lower for kw in RESIDENTIAL_KEYWORDS):
        return "RESIDENTIAL"
    return None


# ============================================================================
# TOR EXIT NODE LIST  (cached in memory, refreshed every hour)
# ============================================================================

class _TorExitCache:
    """Singleton cache for Tor exit node list. Refreshes once per hour."""
    _ips: Set[str] = set()
    _last_fetch: float = 0.0
    _TTL: float = 3600.0  # 1 hour

    @classmethod
    def contains(cls, ip: str) -> bool:
        now = time.time()
        if not cls._ips or (now - cls._last_fetch) > cls._TTL:
            cls._refresh()
        return ip in cls._ips

    @classmethod
    def _refresh(cls):
        try:
            resp = requests.get(
                "https://check.torproject.org/exit-addresses",
                timeout=8
            )
            cls._ips = {
                line.split()[1]
                for line in resp.text.splitlines()
                if line.startswith("ExitAddress")
            }
            cls._last_fetch = time.time()
        except Exception:
            pass   # Keep stale cache rather than crash


# ============================================================================
# AbuseIPDB WRAPPER
# ============================================================================

class _AbuseIPDB:
    """Thin wrapper around AbuseIPDB v2 check endpoint."""

    _BASE = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: Optional[str]):
        self._key = api_key

    def check(self, ip: str) -> Optional[Dict]:
        """
        Returns dict with keys:
          abuse_score (int 0–100), total_reports (int),
          country (str 2-letter code), asn (str), isp (str)
        or None if the API call fails / no key configured.
        """
        if not self._key:
            return None
        try:
            resp = requests.get(
                self._BASE,
                headers={"Key": self._key, "Accept": "application/json"},
                params={
                    "ipAddress":    ip,
                    "maxAgeInDays": 90,
                    "verbose":      "",
                },
                timeout=10,
            )
            data = resp.json().get("data", {})
            if not data:
                return None
            return {
                "abuse_score":   data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country":       data.get("countryCode"),
                "asn":           data.get("asn"),
                "isp":           data.get("isp"),
                "domain":        data.get("domain"),
                "is_tor":        data.get("isTor", False),
                "usage_type":    data.get("usageType", ""),
            }
        except Exception:
            return None


# ============================================================================
# CORE CLASSIFIER
# ============================================================================

class IPClassifier:
    """
    Classifies a single IP using a layered decision tree:

      1. Private IP guard — skip immediately
      2. Tor exit list    — highest confidence unforgeable signal
      3. ASN-based VPN    — stable ASN → VPN provider mapping
      4. AbuseIPDB        — abuse score, usage_type, country, ASN
      5. WHOIS org keyword — datacenter vs. residential from org name
      6. Residential proxy — home ISP IP with elevated abuse score
      7. Fallback          — UNKNOWN

    Each layer annotates the evidence list so the analyst can see
    exactly why the classification was reached.
    """

    def __init__(self, verbose: bool = False):
        self.verbose   = verbose
        self._abuse    = _AbuseIPDB(os.getenv("ABUSEIPDB_API_KEY"))
        self._tor      = _TorExitCache

    def classify(
        self,
        ip: str,
        whois_org: Optional[str] = None,
        asn:       Optional[str] = None,
    ) -> IPClassificationResult:
        """
        Classify a single IP address.

        Args:
            ip:        The IPv4 or IPv6 address to classify.
            whois_org: Optional pre-fetched WHOIS organisation name.
                       If supplied, saves a round-trip to AbuseIPDB.
            asn:       Optional pre-fetched ASN string (e.g. "AS14061").

        Returns:
            IPClassificationResult with full evidence chain.
        """
        techniques: List[str] = []
        evidence:   List[str] = []

        # ── defaults ────────────────────────────────────────────────────────
        category      = IPCategory.UNKNOWN
        confidence    = 0.30
        country       = None
        asn_found     = asn
        provider      = whois_org
        threat_score  = 0
        abuse_reports = 0
        is_vpn  = is_tor = is_proxy = is_residential = is_datacenter = False

        # ── 0. Guard: private / reserved addresses ───────────────────────────
        if _is_private(ip):
            return self._build_result(
                ip, IPCategory.UNKNOWN, 0.0,
                ["Private/reserved address — not a routable attacker IP"],
                None, asn_found, provider, 0, 0,
                False, False, False, False, False,
                ["private-guard"], techniques
            )

        # ── 1. Tor exit list ─────────────────────────────────────────────────
        techniques.append("tor-exit-list")
        if self._tor.contains(ip):
            is_tor = True
            category   = IPCategory.TOR_EXIT
            confidence = 0.97
            evidence.append("Confirmed Tor exit node (Tor Project exit-address list)")
            # Still fetch abuse data for threat score enrichment
            abuse_data = self._abuse.check(ip)
            if abuse_data:
                threat_score  = abuse_data.get("abuse_score", 0)
                abuse_reports = abuse_data.get("total_reports", 0)
                country       = abuse_data.get("country")
                asn_found     = asn_found or abuse_data.get("asn")
                provider      = provider  or abuse_data.get("isp")
            return self._build_result(
                ip, category, confidence, evidence, country, asn_found,
                provider, threat_score, abuse_reports,
                is_vpn, is_tor, is_proxy, is_residential, is_datacenter,
                techniques, []
            )

        # ── 2. ASN-based VPN detection ───────────────────────────────────────
        techniques.append("asn-vpn-lookup")
        # First try the caller-supplied ASN, then we'll also try AbuseIPDB's
        if asn_found and asn_found in VPN_ASNS:
            vpn_name = VPN_ASNS[asn_found]
            if "Datacenter" not in vpn_name:          # skip the datacenter entries
                is_vpn   = True
                category = IPCategory.VPN_PROVIDER
                confidence = 0.88
                provider   = vpn_name
                evidence.append(f"ASN {asn_found} belongs to {vpn_name} (VPN provider)")

        # ── 3. AbuseIPDB ─────────────────────────────────────────────────────
        techniques.append("abuseipdb-api")
        abuse_data = self._abuse.check(ip)

        if abuse_data:
            threat_score  = abuse_data.get("abuse_score", 0)
            abuse_reports = abuse_data.get("total_reports", 0)
            country       = abuse_data.get("country")
            isp           = abuse_data.get("isp", "")
            usage_type    = abuse_data.get("usage_type", "")
            is_tor_api    = abuse_data.get("is_tor", False)
            ab_asn        = abuse_data.get("asn", "")

            # If we didn't already have an ASN, use the one from AbuseIPDB
            if not asn_found:
                asn_found = ab_asn
            if not provider:
                provider = isp

            # Cross-check ASN against VPN table now that we have it from API
            if not is_vpn and asn_found and asn_found in VPN_ASNS:
                vpn_name = VPN_ASNS[asn_found]
                if "Datacenter" not in vpn_name:
                    is_vpn     = True
                    category   = IPCategory.VPN_PROVIDER
                    confidence = 0.88
                    provider   = vpn_name
                    evidence.append(f"ASN {asn_found} confirmed as {vpn_name}")

            # Tor flag from API
            if is_tor_api and not is_tor:
                is_tor     = True
                category   = IPCategory.TOR_EXIT
                confidence = 0.95
                evidence.append("AbuseIPDB flags this IP as a Tor exit node")

            # Usage type gives us datacenter vs residential signal
            if usage_type:
                techniques.append("abuseipdb-usage-type")
                ut_lower = usage_type.lower()
                if any(kw in ut_lower for kw in ("data center", "hosting", "colocation", "cloud")):
                    is_datacenter = True
                    evidence.append(f"AbuseIPDB usage_type = '{usage_type}'")
                elif any(kw in ut_lower for kw in ("residential", "home", "isp", "broadband")):
                    is_residential = True
                    evidence.append(f"AbuseIPDB usage_type = '{usage_type}'")

            if abuse_reports > 0:
                evidence.append(f"{abuse_reports} abuse reports on AbuseIPDB (score {threat_score}/100)")

        # ── 4. WHOIS org keyword fallback ─────────────────────────────────────
        techniques.append("whois-keyword")
        org_classification = _classify_org_by_keyword(whois_org or provider or "")
        if org_classification == "DATACENTER" and not is_tor and not is_vpn:
            is_datacenter = True
            evidence.append(f"WHOIS org '{whois_org or provider}' matches datacenter keywords")
        elif org_classification == "RESIDENTIAL" and not is_tor and not is_vpn:
            is_residential = True
            evidence.append(f"WHOIS org '{whois_org or provider}' matches residential ISP keywords")

        # Also check ASN against known datacenter set
        if asn_found and asn_found in DATACENTER_ASNS and not is_vpn and not is_tor:
            is_datacenter = True
            evidence.append(f"ASN {asn_found} is a known cloud/datacenter provider")

        # ── 5. Derive category from collected signals ─────────────────────────
        if category == IPCategory.UNKNOWN:        # not already set by Tor/VPN checks
            if threat_score > 75:
                category   = IPCategory.ATTACKER_ORIGIN
                confidence = 0.85
                evidence.insert(0, f"High AbuseIPDB score: {threat_score}/100")

            elif is_residential and threat_score > 40:
                # Home ISP IP with elevated abuse score → residential proxy farm
                is_proxy   = True
                category   = IPCategory.RESIDENTIAL_PROXY
                confidence = 0.75
                evidence.insert(0, "Residential ISP IP with elevated abuse score → likely residential proxy")

            elif is_residential:
                category   = IPCategory.RESIDENTIAL
                confidence = 0.80
                evidence.insert(0, "Residential ISP — high-value attribution target")

            elif threat_score > 25:
                category   = IPCategory.SUSPICIOUS
                confidence = 0.60
                evidence.insert(0, f"Moderate AbuseIPDB score: {threat_score}/100")

            elif is_datacenter:
                category   = IPCategory.DATACENTER
                confidence = 0.75
                evidence.insert(0, "Cloud / hosting provider IP (could be VPN backend or attacker server)")

            else:
                category   = IPCategory.UNKNOWN
                confidence = 0.30

        return self._build_result(
            ip, category, min(confidence, 1.0), evidence, country, asn_found,
            provider, threat_score, abuse_reports,
            is_vpn, is_tor, is_proxy, is_residential, is_datacenter,
            techniques, []
        )

    def _build_result(
        self,
        ip, category, confidence, evidence, country, asn, provider,
        threat_score, abuse_reports,
        is_vpn, is_tor, is_proxy, is_residential, is_datacenter,
        techniques, extra_techniques
    ) -> IPClassificationResult:
        return IPClassificationResult(
            ip                 = ip,
            category           = category,
            classification     = category.value,
            confidence         = confidence,
            evidence           = evidence,
            country            = country,
            asn                = asn,
            provider           = provider,
            threat_score       = threat_score,
            abuse_reports      = abuse_reports,
            is_vpn             = is_vpn,
            is_tor             = is_tor,
            is_proxy           = is_proxy,
            is_residential     = is_residential,
            is_datacenter      = is_datacenter,
            techniques_applied = techniques + extra_techniques,
            timestamp_analyzed = datetime.now().isoformat(),
        )


# ============================================================================
# BATCH CLASSIFIER
# ============================================================================

class IPClassifierBatch:
    """
    Classify a list of IPs, applying rate-limiting between API calls
    so we don't exhaust AbuseIPDB's free-tier quota (1000 req/day).
    """

    def __init__(self, verbose: bool = False, rate_limit_sec: float = 0.5):
        self._clf   = IPClassifier(verbose=verbose)
        self._delay = rate_limit_sec
        self._verbose = verbose

    def classify_all(
        self,
        ips: List[str],
        whois_orgs: Optional[Dict[str, str]] = None,
        asns:       Optional[Dict[str, str]] = None,
    ) -> Dict[str, IPClassificationResult]:
        """
        Args:
            ips:        List of IP addresses.
            whois_orgs: Optional dict mapping IP → WHOIS org name.
            asns:       Optional dict mapping IP → ASN string.

        Returns:
            Dict mapping each IP to its classification result.
        """
        results: Dict[str, IPClassificationResult] = {}
        whois_orgs = whois_orgs or {}
        asns       = asns or {}

        for i, ip in enumerate(ips):
            if self._verbose:
                print(f"  [{i+1}/{len(ips)}] Classifying {ip} …")

            result = self._clf.classify(
                ip,
                whois_org=whois_orgs.get(ip),
                asn=asns.get(ip),
            )
            results[ip] = result

            if self._verbose:
                print(f"    → {result}")

            # Rate-limit between API calls (skip delay on last item)
            if i < len(ips) - 1:
                time.sleep(self._delay)

        return results


# ============================================================================
# CONVENIENCE FUNCTION (drop-in for hunterTrace.py pipeline)
# ============================================================================

def classify_ip_list(
    ips: List[str],
    whois_orgs: Optional[Dict[str, str]] = None,
    asns:       Optional[Dict[str, str]] = None,
    verbose:    bool = False,
) -> Dict[str, IPClassificationResult]:
    """
    One-liner entry point for the pipeline.

    Example:
        results = classify_ip_list(
            ["203.0.113.42", "45.33.32.156"],
            verbose=True
        )
        for ip, r in results.items():
            print(ip, r.classification, f"{r.confidence:.0%}")
    """
    return IPClassifierBatch(verbose=verbose).classify_all(ips, whois_orgs, asns)


def classify_ip(ip: str, whois_org: str = None, asn: str = None) -> IPClassificationResult:
    """Single-IP convenience wrapper. Identical to IPClassifier().classify()."""
    return IPClassifier().classify(ip, whois_org=whois_org, asn=asn)


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    import sys, json

    if len(sys.argv) < 2:
        print("Usage: python ipClassifier.py <ip> [ip2] [ip3] ...")
        print("\nSet ABUSEIPDB_API_KEY env var for full classification.")
        sys.exit(0)

    targets = sys.argv[1:]
    results = classify_ip_list(targets, verbose=True)

    print("\n" + "=" * 70)
    print("CLASSIFICATION RESULTS")
    print("=" * 70)
    for ip, r in results.items():
        print(f"\n  IP: {r.ip}")
        print(f"  Category:     {r.classification}")
        print(f"  Confidence:   {r.confidence:.0%}")
        print(f"  Threat Score: {r.threat_score}/100  ({r.abuse_reports} reports)")
        print(f"  Country:      {r.country or 'N/A'}")
        print(f"  ASN:          {r.asn or 'N/A'}")
        print(f"  Provider:     {r.provider or 'N/A'}")
        print(f"  Flags:        VPN={r.is_vpn} Tor={r.is_tor} Proxy={r.is_proxy} Residential={r.is_residential} DC={r.is_datacenter}")
        print(f"  Evidence:")
        for ev in r.evidence[:5]:
            print(f"    • {ev}")
        print(f"  Techniques:   {', '.join(r.techniques_applied)}")
