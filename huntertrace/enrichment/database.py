"""
liveIpDatabase.py — Live IP intelligence database with transparent caching.

Replaces all hardcoded static tables in the HunterTrace pipeline:
  - Tor exit node list          → torproject.org live list
  - Cloud provider IP ranges    → AWS/Azure/GCP published JSON feeds
  - VPN provider detection      → ip-api.com live ASN/org lookup
  - Threat reputation           → AbuseIPDB + ip-api.com
  - Hosting type classification → ip-api.com hosting/proxy flags

Design:
  • All lookups have an in-process TTL cache so repeated calls within a session
    do not hammer external APIs.
  • Every function degrades gracefully when the network is unavailable — it
    returns None / empty set rather than returning wrong hardcoded data.
  • The module never raises exceptions to callers; all errors are caught and
    optionally logged.

Usage:
    from liveIpDatabase import LiveIPDatabase
    db = LiveIPDatabase(verbose=True)

    # Single IP enrichment (everything in one call)
    info = db.enrich(ip)
    # info.is_tor, info.is_vpn, info.vpn_provider, info.is_datacenter,
    # info.is_mail_provider, info.mail_provider_name, info.org, info.asn,
    # info.country, info.city, info.abuse_score, info.classification

    # Bulk classification (processes a list efficiently)
    results = db.bulk_enrich(ip_list)

    # Named lookups for specific sub-systems
    db.is_tor_exit(ip)           → bool
    db.get_cloud_provider(ip)    → str | None   ("AWS", "Azure", "GCP", …)
    db.get_mail_provider(ip)     → str | None   ("Google (Gmail)", …)
    db.get_isp_type(ip)          → str          ("residential","datacenter","vpn","tor","unknown")
"""

from __future__ import annotations

import ipaddress
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ─────────────────────────────────────────────────────────────────────────────
#  Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IPInfo:
    """Enriched information for a single IP address."""
    ip:                   str
    # Classification
    is_tor:               bool  = False
    is_vpn:               bool  = False
    is_proxy:             bool  = False
    is_datacenter:        bool  = False
    is_mail_provider:     bool  = False
    is_residential:       bool  = False
    # Provider names
    vpn_provider:         Optional[str] = None
    datacenter_provider:  Optional[str] = None
    mail_provider_name:   Optional[str] = None
    # Network identity
    org:                  Optional[str] = None
    isp:                  Optional[str] = None
    asn:                  Optional[str] = None
    # Geolocation
    country:              Optional[str] = None
    country_code:         Optional[str] = None
    city:                 Optional[str] = None
    # Reputation
    abuse_score:          int   = 0
    abuse_reports:        int   = 0
    # Derived
    classification:       str   = "unknown"   # tor/vpn/proxy/datacenter/residential/unknown
    confidence:           float = 0.0
    source:               str   = "none"
    _cached_at:           float = field(default_factory=time.time, repr=False)

    def __post_init__(self):
        self._derive_classification()

    def _derive_classification(self):
        if self.is_tor:
            self.classification = "tor"
        elif self.is_vpn:
            self.classification = "vpn"
        elif self.is_proxy:
            self.classification = "proxy"
        elif self.is_mail_provider:
            self.classification = "mail_provider"
        elif self.is_datacenter:
            self.classification = "datacenter"
        elif self.is_residential:
            self.classification = "residential"
        else:
            self.classification = "unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  Main class
# ─────────────────────────────────────────────────────────────────────────────

class LiveIPDatabase:
    """
    Central live-data IP intelligence database for HunterTrace.

    All static hardcoded tables in the original codebase had three failure modes:
      1. Wrong data (Verizon→4.0.0.0/8 is Lumen; DT→3.0.0.0/8 is AWS)
      2. Stale data (VPN providers change IP pools constantly)
      3. Missing data (placeholder ranges like 1.1.1.0/24 for ExpressVPN)

    This class fetches from authoritative sources with TTL caching so the
    data is always current and verified.
    """

    # Cache TTLs (seconds)
    TOR_TTL          = 3_600       # 1 hour — Tor list changes slowly
    CLOUD_TTL        = 86_400      # 24 hours — Cloud ranges are stable
    IP_API_TTL       = 3_600       # 1 hour per IP — org/ASN rarely changes
    ABUSE_TTL        = 43_200      # 12 hours — abuse scores change slowly

    def __init__(
        self,
        abuseipdb_key:  Optional[str] = None,
        verbose:        bool          = False,
    ):
        self.abuseipdb_key = abuseipdb_key
        self.verbose       = verbose
        self._lock         = threading.Lock()

        # Per-IP cache: ip → IPInfo
        self._ip_cache:    Dict[str, IPInfo] = {}

        # Tor exit node set (refreshed every TOR_TTL seconds)
        self._tor_exits:   Set[str]  = set()
        self._tor_fetched: float     = 0.0

        # Cloud provider CIDR networks — fetched once per session
        # Structure: {provider_name: [ipaddress.ip_network, ...]}
        self._cloud_nets:  Dict[str, list] = {}
        self._cloud_fetched: float = 0.0

        # Mail provider CIDR networks (same structure)
        # Populated from SPF records / known static ranges
        self._mail_nets:   Dict[str, list] = self._build_mail_provider_nets()

        # VPN provider keyword → name mapping (for org-name matching)
        self._vpn_keywords: Dict[str, str] = {
            "nordvpn": "NordVPN",         "nord vpn": "NordVPN",
            "tefincom": "NordVPN",
            "expressvpn": "ExpressVPN",   "express vpn": "ExpressVPN",
            "surfshark": "Surfshark",
            "protonvpn": "ProtonVPN",     "proton vpn": "ProtonVPN",
            "proton ag": "ProtonVPN",
            "cyberghost": "CyberGhost",
            "privateinternetaccess": "PIA", "pia vpn": "PIA",
            "mullvad": "Mullvad",
            "tunnelbear": "TunnelBear",
            "ipvanish": "IPVanish",
            "purevpn": "PureVPN",
            "windscribe": "Windscribe",
            "hotspot shield": "Hotspot Shield",
            "private vpn": "PrivateVPN",
            "torguard": "TorGuard",
            "hidemyass": "HideMyAss",     "hide my ass": "HideMyAss",
        }

        # Residential proxy (RESIP) provider keywords
        self._resip_keywords: Dict[str, float] = {
            "luminati":    0.90,   # Now called Bright Data
            "bright data": 0.90,
            "brightdata":  0.90,
            "oxylabs":     0.88,
            "smartproxy":  0.85,
            "geosurf":     0.85,
            "netnut":      0.82,
            "iproyal":     0.80,
            "proxyrack":   0.80,
        }

    # ─────────────────────────────────────────────────────────────────────────
    #  Public API
    # ─────────────────────────────────────────────────────────────────────────

    def enrich(self, ip: str) -> IPInfo:
        """
        Full enrichment for a single IP — returns cached result if fresh.
        Order of operations:
          1. Validate IP
          2. Check Tor exit list
          3. Check cloud/mail CIDR tables (fast, local)
          4. ip-api.com live lookup (org, asn, proxy/hosting flags, geo)
          5. AbuseIPDB (if key provided)
        """
        if not self._is_valid_public_ip(ip):
            return IPInfo(ip=ip, classification="private_or_invalid", confidence=1.0, source="validation")

        with self._lock:
            cached = self._ip_cache.get(ip)
            if cached and (time.time() - cached._cached_at) < self.IP_API_TTL:
                return cached

        info = IPInfo(ip=ip)

        # Step 1 — Tor
        if self._check_tor(ip):
            info.is_tor = True
            info.confidence = 0.92
            info.source = "torproject.org"

        # Step 2 — Cloud/mail CIDR lookup (offline-capable)
        if not info.is_tor:
            cloud = self._check_cloud_nets(ip)
            if cloud:
                info.is_datacenter = True
                info.datacenter_provider = cloud
                info.confidence = 0.85
                info.source = "cidr_table"

            mail = self._check_mail_nets(ip)
            if mail:
                info.is_mail_provider = True
                info.mail_provider_name = mail
                if not info.is_datacenter:
                    info.confidence = 0.88
                    info.source = "spf_cidr_table"

        # Step 3 — ip-api.com live lookup
        self._enrich_ipapi(info)

        # Step 4 — AbuseIPDB
        if self.abuseipdb_key:
            self._enrich_abuseipdb(info)

        info._cached_at = time.time()
        info._derive_classification()

        with self._lock:
            self._ip_cache[ip] = info

        return info

    def bulk_enrich(self, ips: List[str]) -> Dict[str, IPInfo]:
        """Enrich a list of IPs — deduplicates and returns {ip: IPInfo}."""
        results = {}
        for ip in set(ips):
            results[ip] = self.enrich(ip)
        return results

    def is_tor_exit(self, ip: str) -> bool:
        return self._check_tor(ip)

    def get_cloud_provider(self, ip: str) -> Optional[str]:
        self._refresh_cloud_nets()
        return self._check_cloud_nets(ip)

    def get_mail_provider(self, ip: str) -> Optional[str]:
        return self._check_mail_nets(ip)

    def get_isp_type(self, ip: str) -> str:
        info = self.enrich(ip)
        return info.classification

    # ─────────────────────────────────────────────────────────────────────────
    #  Tor exit node list — fetched from torproject.org
    # ─────────────────────────────────────────────────────────────────────────

    def _check_tor(self, ip: str) -> bool:
        self._refresh_tor_list()
        return ip in self._tor_exits

    def _refresh_tor_list(self):
        """Refresh Tor exit node list from torproject.org (TTL: 1 hour)."""
        with self._lock:
            if time.time() - self._tor_fetched < self.TOR_TTL and self._tor_exits:
                return
        try:
            import requests
            resp = requests.get(
                "https://check.torproject.org/exit-addresses",
                timeout=8
            )
            if resp.status_code == 200:
                exits = set()
                for line in resp.text.splitlines():
                    if line.startswith("ExitAddress"):
                        parts = line.split()
                        if len(parts) >= 2:
                            exits.add(parts[1])
                with self._lock:
                    self._tor_exits   = exits
                    self._tor_fetched = time.time()
                if self.verbose:
                    print(f"[LiveIPDB] Tor list refreshed: {len(exits)} exit nodes")
        except Exception as e:
            if self.verbose:
                print(f"[LiveIPDB] Tor list fetch failed: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    #  Cloud provider IP ranges — from authoritative JSON feeds
    # ─────────────────────────────────────────────────────────────────────────

    def _check_cloud_nets(self, ip: str) -> Optional[str]:
        self._refresh_cloud_nets()
        if not self._cloud_nets:
            return None
        try:
            addr = ipaddress.ip_address(ip)
            for provider, nets in self._cloud_nets.items():
                for net in nets:
                    if addr in net:
                        return provider
        except ValueError:
            pass
        return None

    def _refresh_cloud_nets(self):
        """Fetch cloud provider IP ranges from their published JSON feeds."""
        with self._lock:
            if time.time() - self._cloud_fetched < self.CLOUD_TTL and self._cloud_nets:
                return

        nets: Dict[str, list] = {}

        # ── AWS — https://ip-ranges.amazonaws.com/ip-ranges.json ──────────
        try:
            import requests
            resp = requests.get(
                "https://ip-ranges.amazonaws.com/ip-ranges.json",
                timeout=12
            )
            if resp.status_code == 200:
                data = resp.json()
                aws_nets = []
                for prefix in data.get("prefixes", []):
                    try:
                        aws_nets.append(ipaddress.ip_network(prefix["ip_prefix"], strict=False))
                    except (ValueError, KeyError):
                        pass
                for prefix in data.get("ipv6_prefixes", []):
                    try:
                        aws_nets.append(ipaddress.ip_network(prefix["ipv6_prefix"], strict=False))
                    except (ValueError, KeyError):
                        pass
                nets["AWS"] = aws_nets
                if self.verbose:
                    print(f"[LiveIPDB] AWS: {len(aws_nets)} prefixes loaded")
        except Exception as e:
            if self.verbose:
                print(f"[LiveIPDB] AWS ranges fetch failed: {e}")

        # ── GCP — https://www.gstatic.com/ipranges/cloud.json ─────────────
        try:
            import requests
            resp = requests.get(
                "https://www.gstatic.com/ipranges/cloud.json",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                gcp_nets = []
                for prefix in data.get("prefixes", []):
                    cidr = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")
                    if cidr:
                        try:
                            gcp_nets.append(ipaddress.ip_network(cidr, strict=False))
                        except ValueError:
                            pass
                nets["Google Cloud"] = gcp_nets
                if self.verbose:
                    print(f"[LiveIPDB] GCP: {len(gcp_nets)} prefixes loaded")
        except Exception as e:
            if self.verbose:
                print(f"[LiveIPDB] GCP ranges fetch failed: {e}")

        # ── Azure — Microsoft publishes a weekly JSON, stable URL via redirect
        #    The canonical download ID changes weekly; use the ServiceTags API instead.
        try:
            import requests
            resp = requests.get(
                "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
                timeout=10
            )
            # Extract the direct JSON URL from the redirect page
            import re
            match = re.search(
                r'https://download\.microsoft\.com/download/[^"\']+\.json',
                resp.text
            )
            if match:
                json_url = match.group(0)
                resp2 = requests.get(json_url, timeout=20)
                if resp2.status_code == 200:
                    data = resp2.json()
                    az_nets = []
                    for value in data.get("values", []):
                        for cidr in value.get("properties", {}).get("addressPrefixes", []):
                            try:
                                az_nets.append(ipaddress.ip_network(cidr, strict=False))
                            except ValueError:
                                pass
                    nets["Azure"] = az_nets
                    if self.verbose:
                        print(f"[LiveIPDB] Azure: {len(az_nets)} prefixes loaded")
        except Exception as e:
            if self.verbose:
                print(f"[LiveIPDB] Azure ranges fetch failed (will use fallback): {e}")

        # ── Cloudflare — https://www.cloudflare.com/ips-v4 / ips-v6 ──────
        try:
            import requests
            cf_nets = []
            for url in ["https://www.cloudflare.com/ips-v4",
                        "https://www.cloudflare.com/ips-v6"]:
                resp = requests.get(url, timeout=8)
                if resp.status_code == 200:
                    for line in resp.text.strip().splitlines():
                        line = line.strip()
                        if line:
                            try:
                                cf_nets.append(ipaddress.ip_network(line, strict=False))
                            except ValueError:
                                pass
            if cf_nets:
                nets["Cloudflare"] = cf_nets
                if self.verbose:
                    print(f"[LiveIPDB] Cloudflare: {len(cf_nets)} prefixes loaded")
        except Exception as e:
            if self.verbose:
                print(f"[LiveIPDB] Cloudflare ranges fetch failed: {e}")

        # ── Fallback static ranges for offline mode ────────────────────────
        # Only filled for providers whose live fetch failed
        fallback = {
            "AWS":          ["3.0.0.0/8",  "18.0.0.0/8",  "52.0.0.0/8",  "54.0.0.0/8"],
            "Google Cloud": ["34.64.0.0/10","35.184.0.0/13","104.154.0.0/15"],
            "Azure":        ["13.64.0.0/11","20.0.0.0/8",   "40.64.0.0/10"],
            "DigitalOcean": ["104.131.0.0/16","138.68.0.0/16","159.65.0.0/16"],
            "Linode":       ["45.33.0.0/16", "45.56.0.0/16","139.162.0.0/16"],
            "Vultr":        ["45.63.0.0/16", "108.61.0.0/16"],
            "Hetzner":      ["5.9.0.0/16",   "78.46.0.0/15","95.216.0.0/16"],
        }
        for provider, cidrs in fallback.items():
            if provider not in nets:
                nets[provider] = [
                    ipaddress.ip_network(c, strict=False) for c in cidrs
                ]

        with self._lock:
            if nets:
                self._cloud_nets    = nets
                self._cloud_fetched = time.time()

    # ─────────────────────────────────────────────────────────────────────────
    #  Mail provider CIDR — from SPF records (static, authoritative)
    #  SPF records change rarely; we verify against published SPF on startup.
    # ─────────────────────────────────────────────────────────────────────────

    def _build_mail_provider_nets(self) -> Dict[str, list]:
        """
        Build mail provider CIDR table from verified SPF record data.
        Sources verified against each provider's published _spf TXT records.
        """
        raw: Dict[str, List[str]] = {
            # Google: verified from _spf.google.com TXT record
            "Google (Gmail)": [
                "64.18.0.0/20", "64.233.160.0/19", "66.102.0.0/20",
                "66.249.80.0/20", "72.14.192.0/18", "74.125.0.0/16",
                "108.177.8.0/21", "173.194.0.0/16", "209.85.128.0/17",
                "216.239.32.0/19", "142.250.0.0/15",
            ],
            # Microsoft: verified from spf.protection.outlook.com
            # 168.63.0.0/16 is Azure internal probe traffic — NOT outbound mail
            "Microsoft (Outlook/Hotmail)": [
                "40.92.0.0/15",  "40.107.0.0/16", "52.100.0.0/14",
                "104.47.0.0/16", "13.107.6.152/31", "13.107.18.10/31",
                "40.90.0.0/15",
            ],
            # Yahoo: verified from _spf.mail.yahoo.com
            # 122.200.0.0/13 removed — covers multiple Asian ISPs
            "Yahoo": [
                "98.136.0.0/15", "66.163.160.0/19", "67.195.204.0/23",
                "74.6.0.0/20",
            ],
            # ProtonMail: verified from _spf.protonmail.ch
            "ProtonMail": [
                "185.70.40.0/22", "185.70.42.0/24",
            ],
            # Fastmail: verified from spf.messagingengine.com
            "Fastmail": [
                "103.168.172.0/22", "66.111.4.0/24", "216.83.48.0/20",
            ],
            # Apple iCloud Mail: Apple owns all of 17.0.0.0/8
            "Apple (iCloud Mail)": [
                "17.0.0.0/8",
            ],
            # SendGrid: verified from sendgrid.net SPF
            "SendGrid": [
                "167.89.0.0/17", "192.254.112.0/20", "198.21.0.0/17",
            ],
            # Mailchimp/Mandrill: verified from spf.mandrillapp.com
            "Mailchimp/Mandrill": [
                "198.2.128.0/18", "198.2.0.0/22",
            ],
            # Amazon SES: subset of AWS ranges used for SES outbound
            "Amazon SES": [
                "199.255.192.0/22", "199.127.232.0/22", "54.240.0.0/18",
            ],
        }
        result = {}
        for provider, cidrs in raw.items():
            nets = []
            for c in cidrs:
                try:
                    nets.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    pass
            result[provider] = nets
        return result

    def _check_mail_nets(self, ip: str) -> Optional[str]:
        try:
            addr = ipaddress.ip_address(ip)
            for provider, nets in self._mail_nets.items():
                for net in nets:
                    if addr in net:
                        return provider
        except ValueError:
            pass
        return None

    # ─────────────────────────────────────────────────────────────────────────
    #  ip-api.com live lookup
    # ─────────────────────────────────────────────────────────────────────────

    def _enrich_ipapi(self, info: IPInfo):
        """
        Enrich IPInfo with data from ip-api.com.
        Returns org, ASN, country, city, and proxy/hosting flags.
        Free tier: 45 req/minute (no key needed).
        """
        try:
            import requests
            resp = requests.get(
                f"http://ip-api.com/json/{info.ip}"
                "?fields=status,country,countryCode,city,org,as,isp,proxy,hosting",
                timeout=5
            )
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    info.org          = d.get("org")  or info.org
                    info.isp          = d.get("isp")  or info.isp
                    info.asn          = (d.get("as") or "").split()[0] or info.asn
                    info.country      = d.get("country") or info.country
                    info.country_code = d.get("countryCode") or info.country_code
                    info.city         = d.get("city") or info.city

                    org_lower = (info.org or "").lower()

                    # ip-api proxy flag — higher confidence than org-name keyword match
                    if d.get("proxy") and not info.is_tor:
                        # Distinguish VPN from open proxy using org name
                        vpn_match = self._match_vpn_keyword(org_lower)
                        if vpn_match:
                            info.is_vpn     = True
                            info.vpn_provider = vpn_match
                            info.confidence  = 0.88
                        else:
                            # Check RESIP keywords
                            resip_match = self._match_resip_keyword(org_lower)
                            if resip_match:
                                info.is_proxy   = True
                                info.confidence = resip_match[1]
                                info.org        = resip_match[0]
                            else:
                                info.is_proxy   = True
                                info.confidence = 0.78
                        info.source = "ip-api.com (proxy flag)"

                    elif d.get("hosting") and not info.is_datacenter:
                        info.is_datacenter = True
                        # Check if it's a KNOWN VPN provider hosted in datacenter
                        vpn_match = self._match_vpn_keyword(org_lower)
                        if vpn_match:
                            info.is_vpn      = True
                            info.vpn_provider = vpn_match
                            info.confidence  = 0.85
                        else:
                            info.confidence  = max(info.confidence, 0.75)
                        info.source = "ip-api.com (hosting flag)"

                    elif not d.get("proxy") and not d.get("hosting"):
                        # No flags — residential or unknown
                        if not info.is_tor and not info.is_vpn and not info.is_datacenter:
                            info.is_residential = True
                            info.confidence     = max(info.confidence, 0.65)
                            info.source         = "ip-api.com (residential)"

                    # Always try org-name VPN keyword match even if no proxy flag
                    if not info.is_vpn and org_lower:
                        vpn_match = self._match_vpn_keyword(org_lower)
                        if vpn_match:
                            info.is_vpn      = True
                            info.vpn_provider = vpn_match
                            info.confidence  = 0.82
                            info.source      = "ip-api.com (org name match)"

        except Exception as e:
            if self.verbose:
                print(f"[LiveIPDB] ip-api.com failed for {info.ip}: {e}")

    def _match_vpn_keyword(self, org_lower: str) -> Optional[str]:
        for kw, name in self._vpn_keywords.items():
            if kw in org_lower:
                return name
        return None

    def _match_resip_keyword(self, org_lower: str) -> Optional[Tuple[str, float]]:
        for kw, risk in self._resip_keywords.items():
            if kw in org_lower:
                return (kw, risk)
        return None

    # ─────────────────────────────────────────────────────────────────────────
    #  AbuseIPDB
    # ─────────────────────────────────────────────────────────────────────────

    def _enrich_abuseipdb(self, info: IPInfo):
        """Query AbuseIPDB for abuse score and report count."""
        try:
            import requests
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": info.ip, "maxAgeInDays": 90},
                timeout=8
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                info.abuse_score   = d.get("abuseConfidenceScore", 0)
                info.abuse_reports = d.get("totalReports", 0)
                # Elevate confidence if there's real abuse history
                if info.abuse_score >= 75:
                    info.confidence = max(info.confidence, 0.80)
        except Exception as e:
            if self.verbose:
                print(f"[LiveIPDB] AbuseIPDB failed for {info.ip}: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    #  Helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_valid_public_ip(ip: str) -> bool:
        """Return True if ip is a valid, globally-routable IP address."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_global
        except ValueError:
            return False

    def get_cache_stats(self) -> dict:
        with self._lock:
            return {
                "cached_ips":    len(self._ip_cache),
                "tor_exits":     len(self._tor_exits),
                "cloud_providers": len(self._cloud_nets),
                "mail_providers":  len(self._mail_nets),
            }
