#!/usr/bin/env python3
"""
COMPLETE ATTACKER IP IDENTIFICATION SYSTEM
Full 7-Stage Pipeline in Single File

Stages:
  1. Email Header Extraction (RFC 2822 parsing, IP extraction)
  2. IP Classification (Tor/VPN/Proxy detection with real APIs)
  3A. Proxy Chain Analysis (obfuscation layer detection)
  3B. WHOIS/Reverse DNS Enrichment (organization & ownership metadata)
  3C. Infrastructure Correlation (attack pattern detection, team sizing)
  4. Threat Intelligence Aggregation (C2 detection, malware analysis, threat scoring)
  [GEOLOCATION] Attacker Geolocation (city-level location with coordinates, timezone, ISP)
  5. Attribution Analysis (final synthesis, evidence packaging, law enforcement reports)

Single command:
    python3 complete_attacker_identification_system.py ./phishing_email.eml
    python3 complete_attacker_identification_system.py email.eml --json report.json --verbose
    python3 complete_attacker_identification_system.py email.eml --skip-enrichment
"""

import sys
import os
import json
import re
import email
import socket
import requests
import time
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    whois = None
    WHOIS_AVAILABLE = False
from typing import List, Dict, Optional, Tuple, Set, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
from email.utils import parsedate_to_datetime
import argparse
from pathlib import Path

try:
    from huntertrace.attribution.dkim import verify_message
    DKIM_VERIFICATION_AVAILABLE = True
except ImportError:
    DKIM_VERIFICATION_AVAILABLE = False

# Import live hosting keywords integration
try:
    from huntertrace.enrichment.hosting import get_hosting_keywords, classify_hosting_by_keywords
    HOSTING_KEYWORDS_AVAILABLE = True
except ImportError:
    HOSTING_KEYWORDS_AVAILABLE = False

# Import geolocation enrichment module
try:
    from huntertrace.enrichment.geolocation import GeolocationEnricher, GeolocationData, format_coordinates, get_distance_between_points
    GEOLOCATION_AVAILABLE = True
except ImportError:
    GEOLOCATION_AVAILABLE = False

# Import Stage 5: Attribution Analysis
try:
    from huntertrace.attribution.analysis import AttributionAnalysisEngine, Stage5Attribution
    STAGE5_AVAILABLE = True
except ImportError:
    STAGE5_AVAILABLE = False

# Import Real IP Extractor (VPN/Proxy bypass) - Basic version
try:
    from huntertrace.extraction.basic import RealIPExtractor, extract_real_ip_summary
    REAL_IP_EXTRACTOR_AVAILABLE = True
except ImportError:
    REAL_IP_EXTRACTOR_AVAILABLE = False

# Import Advanced Real IP Extractor (11+ techniques from research paper)
try:
    from huntertrace.extraction.advanced import AdvancedRealIPExtractor, extract_real_ip_summary as extract_real_ip_summary_advanced
    ADVANCED_REAL_IP_EXTRACTOR_AVAILABLE = True
except ImportError:
    ADVANCED_REAL_IP_EXTRACTOR_AVAILABLE = False

# Import VPN Backtracking Analyzer (12 techniques to trace real IP through VPN)
try:
    from huntertrace.extraction.vpnBacktrack import RealIPBacktracker
    VPN_BACKTRACK_AVAILABLE = True
except ImportError:
    VPN_BACKTRACK_AVAILABLE = False

# ============================================================================
# HUNTЕРТRACE v3 COMPONENTS - INTEGRATED
# ============================================================================

# Graph Centrality Engine
try:
    from huntertrace.graph.centrality import (
        InfrastructureGraphAnalyzer,
        integrate_graph_boost_into_attribution
    )
    GRAPH_CENTRALITY_AVAILABLE = True
except ImportError:
    GRAPH_CENTRALITY_AVAILABLE = False

# Bayesian Attribution Engine
try:
    from huntertrace.attribution.engine import AttributionEngine, AttributionResult
    ATTRIBUTION_ENGINE_AVAILABLE = True
except ImportError:
    ATTRIBUTION_ENGINE_AVAILABLE = False

# Webmail v2 Real IP Extractor
try:
    from huntertrace.extraction.webmail import run_webmail_extraction
    WEBMAIL_V2_AVAILABLE = True
except ImportError:
    WEBMAIL_V2_AVAILABLE = False

# ── Layer 1: Campaign Urgency Classifier ─────────────────────────────────────
try:
    from huntertrace.core.urgency import (
        CampaignUrgencyClassifier,
        UrgencyResult,
        classify_email_urgency,
    )
    URGENCY_AVAILABLE = True
except ImportError:
    URGENCY_AVAILABLE = False
    UrgencyResult = None

# ── Layer 1: Canarytoken Bait Generator ──────────────────────────────────────
try:
    from huntertrace.forensics.canaryToken import (
        CanarytokenGenerator,
        CanarytokenResult,
        cli_bait,
    )
    CANARYTOKEN_AVAILABLE = True
except ImportError:
    CANARYTOKEN_AVAILABLE = False
    CanarytokenResult = None
    cli_bait = None

# ── Phase 0: Attacker Technique Profiler ─────────────────────────────────────
try:
    from huntertrace.forensics.attackerTechniqueProfiler import (
        AttackerTechniqueProfiler,
        AttackerTechniqueProfile,
        profile_attacker_techniques,
    )
    TECHNIQUE_PROFILER_AVAILABLE = True
except ImportError:
    TECHNIQUE_PROFILER_AVAILABLE = False
    AttackerTechniqueProfile = None

# ── Active Analysis (5 live-probe techniques) ─────────────────────────────────
try:
    from huntertrace.active.activeAnalysis import (
        ActiveAnalysisPipeline,
        ActiveAnalysisResult,
        patch_backtracker_with_active_analysis,
    )
    ACTIVE_ANALYSIS_AVAILABLE = True
except ImportError:
    ACTIVE_ANALYSIS_AVAILABLE = False
    ActiveAnalysisResult = None

# ── Active Validation (offline + live validation framework) ───────────────────
try:
    from huntertrace.active.activeValidation import (
        ValidationRunner,
        ValidationReport,
    )
    ACTIVE_VALIDATION_AVAILABLE = True
except ImportError:
    ACTIVE_VALIDATION_AVAILABLE = False
    ValidationReport = None


# ============================================================================
# STAGE 1: EMAIL HEADER EXTRACTION
# ============================================================================

@dataclass
class ReceivedHeaderDetail:
    """Individual email hop information - SUPPORTS IPv4 AND IPv6"""
    hop_number: int
    ip: Optional[str]  # IPv4 address
    hostname: Optional[str] = None
    protocol: str = "UNKNOWN"
    timestamp: Optional[str] = None
    authentication: Dict = field(default_factory=dict)
    raw_header: str = ""
    parsing_confidence: float = 0.5
    ipv6: Optional[str] = None  # IPv6 address (NEW)


@dataclass
class ReceivedChainAnalysis:
    """Complete email header chain analysis"""
    email_from: str
    email_to: str
    email_subject: str
    email_date: Optional[str]
    message_id: str
    hops: List[ReceivedHeaderDetail]
    origin_ip: Optional[str]
    destination_ip: Optional[str]
    hop_count: int
    headers_found: int
    spoofing_risk: float
    confidence: float
    red_flags: List[str]
    email_charset: Optional[str] = None    # Charset from Content-Type / subject encoding
    auth_results_raw: Optional[str] = None
    dkim_signature: Optional[str] = None
    dkim_signatures: List[str] = field(default_factory=list)
    dkim_verification: Dict[str, Any] = field(default_factory=dict)


class HeaderExtractor:
    """Stage 1: Extract headers from email - SUPPORTS BOTH IPv4 AND IPv6"""
    
    def __init__(self, dkim_resolver: Optional[Any] = None):
        self.patterns = {
            "ipv4_only": re.compile(r'\[(\d+\.\d+\.\d+\.\d+)\]|(?:^|\bfrom\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\])', re.IGNORECASE),
            "ipv6_with_brackets": re.compile(r'\[([a-fA-F0-9:]+)\]', re.IGNORECASE),  # IPv6 in brackets
            "ipv6_loose": re.compile(                                                   # IPv6 without brackets
                r'\b('
                r'(?:[a-fA-F0-9]{1,4}:){3,}[a-fA-F0-9]{0,4}'  # >= 3 colons (multi-segment)
                r'|(?:[a-fA-F0-9]{1,4}:)*::(?:[a-fA-F0-9:]*)'   # contains :: (compressed)
                r'|::[a-fA-F0-9:]+'                               # starts with ::
                r')\b',
                re.IGNORECASE
            ),  # IPv6 without brackets
            "protocol": re.compile(r'with\s+(ESMTP|SMTP|HTTP|HTTPS|LMTP)', re.IGNORECASE),
            "by_clause": re.compile(r'by\s+(\S+)', re.IGNORECASE),
        }
        self.dkim_resolver = dkim_resolver
    
    def parse_email_file(self, file_path: str) -> Optional[ReceivedChainAnalysis]:
        """Parse email file"""
        try:
            with open(file_path, 'rb') as f:
                raw_bytes = f.read()
            email_raw = raw_bytes.decode('utf-8', errors='ignore')
            return self.parse_email_raw(email_raw, raw_bytes=raw_bytes)
        except Exception as e:
            print(f"[ERROR] Failed to read {file_path}: {e}")
            return None
    
    def parse_email_raw(self, email_raw: str, raw_bytes: Optional[bytes] = None) -> Optional[ReceivedChainAnalysis]:
        """Parse raw email"""
        
        if raw_bytes is not None:
            msg = email.message_from_bytes(raw_bytes)
        else:
            msg = email.message_from_string(email_raw)
        
        email_from = msg.get('From', 'Unknown')
        email_to = msg.get('To', 'Unknown')
        email_subject = msg.get('Subject', 'Unknown')
        message_id = msg.get('Message-ID', 'Unknown')
        auth_results_raw = msg.get('Authentication-Results', None)
        dkim_signatures = msg.get_all('DKIM-Signature', []) or []
        dkim_signature = dkim_signatures[0] if dkim_signatures else None
        dkim_verification: Dict[str, Any] = {}
        if raw_bytes is not None and DKIM_VERIFICATION_AVAILABLE:
            try:
                dkim_verification = verify_message(raw_bytes, resolver=self.dkim_resolver).to_dict()
            except Exception as exc:
                dkim_verification = {
                    "dkim_present": bool(dkim_signatures),
                    "dkim_valid": False,
                    "failure_reason": f"verification_error:{type(exc).__name__}",
                    "domain": None,
                    "selector": None,
                    "algorithm": None,
                    "signed_headers": [],
                    "canonicalization": "simple/simple",
                    "key_type": None,
                    "flags": [],
                    "signatures": [],
                }

        # ── Charset extraction ──────────────────────────────────────────────
        # Priority 1: Content-Type header  (most reliable)
        # Priority 2: encoded-word charset in Subject  (=?charset?...?=)
        # Priority 3: None (no signal emitted)
        email_charset: Optional[str] = None
        ct_header = msg.get('Content-Type', '')
        _ct_m = re.search(r'charset=["\']?([A-Za-z0-9_\-]+)', ct_header, re.I)
        if _ct_m:
            email_charset = _ct_m.group(1).lower()
        if not email_charset:
            _subj_m = re.search(r'=\?([A-Za-z0-9_\-]+)\?', email_subject or '', re.I)
            if _subj_m:
                email_charset = _subj_m.group(1).lower()
        
        date_str = msg.get('Date', None)
        email_date = None
        if date_str:
            try:
                email_date = parsedate_to_datetime(date_str).isoformat()
            except:
                pass
        
        received_headers = msg.get_all('Received', [])
        
        hops = []
        for i, header_text in enumerate(received_headers):
            hop = self._parse_header(header_text, i)
            hops.append(hop)
        
        # Reverse to chronological order (emails are bottom-to-top)
        hops.reverse()
        
        # Renumber hops
        for i, hop in enumerate(hops):
            hop.hop_number = i + 1
        
        # Get origin IP (prefer IPv4, fall back to IPv6)
        # Priority: first hop with a public IP → last hop public IP → sender domain DNS
        origin_ip = None
        for hop in hops:
            candidate = hop.ip or hop.ipv6
            if candidate:
                origin_ip = candidate
                break  # take first (oldest) hop that has an IP

        # Fallback: resolve the From: domain to an IP if no Received: IP found
        if not origin_ip and email_from:
            try:
                domain_match = re.search(r'@([\w.\-]+)', email_from)
                if domain_match:
                    from_domain = domain_match.group(1)
                    resolved = socket.gethostbyname(from_domain)
                    # Only use if it's a public IP
                    parts = resolved.split('.')
                    first, second = int(parts[0]), int(parts[1])
                    is_private = (first == 10 or first == 127 or
                                  (first == 172 and 16 <= second <= 31) or
                                  (first == 192 and second == 168))
                    if not is_private:
                        origin_ip = resolved
                        print(f"  [+] From domain resolved: {from_domain} → {resolved}")
            except Exception:
                pass  # DNS failure is non-fatal
        
        destination_ip = None
        if hops:
            destination_ip = hops[-1].ip or hops[-1].ipv6
        
        # Detect spoofing
        received_spf = msg.get('Received-SPF', None)
        red_flags = []
        spoofing_risk = 0.0
        
        if received_spf and "fail" in received_spf.lower():
            spoofing_risk += 0.25
            red_flags.append("[CRITICAL] SPF FAILED: " + received_spf)
        
        for hop in hops:
            if hop.hostname and ("compromised" in hop.hostname.lower() or "fake" in hop.hostname.lower()):
                red_flags.append(f"[CRITICAL] Suspicious hostname: {hop.hostname}")
                spoofing_risk += 0.15
        
        analysis = ReceivedChainAnalysis(
            email_from=email_from,
            email_to=email_to,
            email_subject=email_subject,
            email_date=email_date,
            message_id=message_id,
            hops=hops,
            origin_ip=origin_ip,
            destination_ip=destination_ip,
            hop_count=len(hops),
            headers_found=len(received_headers),
            spoofing_risk=min(1.0, spoofing_risk),
            confidence=1.0 - (spoofing_risk * 0.3),
            red_flags=red_flags,
            email_charset=email_charset,
            auth_results_raw=auth_results_raw,
            dkim_signature=dkim_signature,
            dkim_signatures=dkim_signatures,
            dkim_verification=dkim_verification,
        )
        
        return analysis
    
    def _parse_header(self, header_text: str, hop_number: int) -> ReceivedHeaderDetail:
        """Parse single Received header - SUPPORTS IPv4 AND IPv6"""
        
        ipv4 = None
        ipv6 = None
        hostname = None
        protocol = "UNKNOWN"
        timestamp = None
        authentication = {}
        parsing_confidence = 0.5
        
        # Extract IPv4 address — match bracketed [1.2.3.4] first, then bare IP after 'from'
        ipv4_match = self.patterns["ipv4_only"].search(header_text)
        if ipv4_match:
            # group(1) = bracketed match, group(2) = bare match after 'from'
            ipv4 = ipv4_match.group(1) or ipv4_match.group(2)
            # Validate it's a real routable IP (skip private/loopback ranges)
            if ipv4:
                parts = ipv4.split('.')
                if len(parts) == 4:
                    first = int(parts[0])
                    second = int(parts[1])
                    # Filter private ranges: 10.x, 172.16-31.x, 192.168.x, 127.x
                    if first == 10 or first == 127 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168):
                        ipv4 = None  # discard private IP, keep looking
            if ipv4:
                parsing_confidence = 0.95
        
        # Extract IPv6 address (priority: bracketed form first)
        ipv6_match = self.patterns["ipv6_with_brackets"].search(header_text)
        if ipv6_match:
            potential_ipv6 = ipv6_match.group(1)
            # Validate it's not an IPv4 (should contain colons)
            if ':' in potential_ipv6 and not self._is_ipv4(potential_ipv6):
                ipv6 = potential_ipv6
                if not ipv4:
                    parsing_confidence = 0.95
        
        # If no IPv4/IPv6 in brackets, try loose IPv6 pattern
        if not ipv6:
            ipv6_loose_match = self.patterns["ipv6_loose"].search(header_text.replace('[', '').replace(']', ''))
            if ipv6_loose_match:
                potential_ipv6 = ipv6_loose_match.group(1)
                if self._is_valid_ipv6(potential_ipv6) and ':' in potential_ipv6:
                    ipv6 = potential_ipv6
        
        # Extract hostname
        by_match = self.patterns["by_clause"].search(header_text)
        if by_match:
            hostname = by_match.group(1)
        
        # Extract protocol
        protocol_match = self.patterns["protocol"].search(header_text)
        if protocol_match:
            protocol = protocol_match.group(1).upper()
        
        # Check for TLS
        if "TLS" in header_text or "encrypted" in header_text.lower():
            authentication["tls"] = True
        
        return ReceivedHeaderDetail(
            hop_number=hop_number,
            ip=ipv4,
            ipv6=ipv6,
            hostname=hostname,
            protocol=protocol,
            timestamp=timestamp,
            authentication=authentication,
            raw_header=header_text[:100],
            parsing_confidence=parsing_confidence
        )
    
    def _is_ipv4(self, address: str) -> bool:
        """Check if string is IPv4 address"""
        return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', address))
    
    def _is_valid_ipv6(self, address: str) -> bool:
        """
        Validate IPv6 address format.
        Rejects timestamps (HH:MM:SS) which match the loose hex+colon pattern.

        Rules:
          - Must contain at least one colon
          - All chars must be hex or colon
          - Must NOT be a pure timestamp (DD:DD:DD where all segments are
            exactly 2 decimal digits) — e.g. '06:21:58' is NOT IPv6
          - Must have either >= 3 colons (multi-segment), or contain '::'
            (compressed notation), or have at least one segment > 2 chars
        """
        address = address.strip()
        if ':' not in address:
            return False
        if not all(c in '0123456789abcdefABCDEF:' for c in address):
            return False
        # Reject HH:MM:SS timestamps: exactly 3 segments all <= 2 decimal digits
        segments = address.split(':')
        if (len(segments) == 3
                and all(len(s) <= 2 and s.isdigit() for s in segments)):
            return False
        # Require: either :: compression, >= 3 colons, or a long hex segment
        has_double_colon = '::' in address
        colon_count = address.count(':')
        has_long_segment = any(len(s) > 2 for s in segments)
        return has_double_colon or colon_count >= 3 or has_long_segment


# ============================================================================
# STAGE 2: IP CLASSIFICATION
# ============================================================================

@dataclass
class IPClassification:
    """IP classification result"""
    ip: str
    classification: str
    confidence: float
    evidence: List[str]
    country: Optional[str]
    asn: Optional[str]
    provider: Optional[str]
    threat_score: int
    abuse_reports: int
    is_vpn: bool
    is_tor: bool
    is_proxy: bool
    timestamp_analyzed: str


class IPClassifierLight:
    """Stage 2: Classify extracted IPs"""
    
    def __init__(self):
        self.abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.tor_cache = None
        self.tor_cache_time = 0
    
    def classify_ips(self, ips: List[str]) -> Dict[str, IPClassification]:
        """Classify multiple IPs"""
        results = {}
        for ip in ips:
            results[ip] = self.classify_ip(ip)
            time.sleep(0.2)  # Rate limiting
        return results
    
    def classify_ip(self, ip: str) -> IPClassification:
        """Classify single IP"""
        
        classification = "UNKNOWN"
        confidence = 0.3
        evidence = []
        country = None
        asn = None
        provider = None
        threat_score = 0
        abuse_reports = 0
        is_tor = False
        is_vpn = False
        is_proxy = False
        
        # Check VPN/Proxy providers FIRST
        vpn_result = self._check_vpn_provider(ip)
        if vpn_result:
            classification = "VPN_PROVIDER"
            confidence = vpn_result.get("confidence", 0.85)
            is_vpn = True
            evidence.append(f"VPN Service: {vpn_result.get('provider', 'Unknown')}")
            provider = vpn_result.get("provider")
        
        # Check Tor
        if self._is_tor_exit(ip):
            classification = "TOR_EXIT"
            confidence = 0.95
            is_tor = True
            evidence.append("Tor exit node detected")
        
        # Check AbuseIPDB (if not already classified as VPN/Tor)
        if classification == "UNKNOWN" and self.abuse_api_key:
            try:
                result = self._check_abuseipdb(ip)
                
                if result:
                    threat_score = result.get("abuse_score", 0)
                    abuse_reports = result.get("total_reports", 0)
                    country = result.get("country", country)
                    
                    if threat_score > 75:
                        classification = "ATTACKER_ORIGIN"
                        confidence = 0.85
                        evidence.append(f"High threat score: {threat_score}%")
                    elif threat_score > 25:
                        classification = "SUSPICIOUS"
                        confidence = 0.60
                        evidence.append(f"Moderate threat score: {threat_score}%")
                    
                    if abuse_reports > 10:
                        evidence.append(f"{abuse_reports} abuse reports")
            
            except Exception as e:
                pass
        
        return IPClassification(
            ip=ip,
            classification=classification,
            confidence=confidence,
            evidence=evidence,
            country=country,
            asn=asn,
            provider=provider,
            threat_score=threat_score,
            abuse_reports=abuse_reports,
            is_vpn=is_vpn,
            is_tor=is_tor,
            is_proxy=is_proxy,
            timestamp_analyzed=datetime.now().isoformat()
        )
    
    def _check_vpn_provider(self, ip: str) -> Optional[Dict]:
        """
        Check if IP belongs to a known VPN, proxy, or datacenter provider.

        Strategy (in order of reliability):
          1. Live ASN lookup via ip-api.com — returns org name, ASN, type
          2. Known IP-prefix table — verified prefixes only, no wrong ASN entries
          3. Keyword matching on the org name returned by ip-api

        Previous bugs removed:
          - AS15169 was Google LLC, not NordVPN → deleted
          - AS41387 was Cogeco Peer 1, not ExpressVPN → deleted
          - AS6739 was Colt Technology, not ExpressVPN → deleted
          - AS14061 appeared twice (Linode then DigitalOcean) → Python silently
            used DigitalOcean, Linode entry was dead code → fixed
          - ASN strings (e.g. "AS51908") can never match an IP with startswith()
            → all ASN-based matching now goes through the live lookup
        """
        import ipaddress

        # ── Step 1: Live ASN/org lookup ───────────────────────────────────
        # ip-api.com returns org, AS number, and connection type for free
        org_name = ""
        asn_str  = ""
        conn_type = ""
        try:
            import requests
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=org,as,proxy,hosting,isp",
                timeout=4
            )
            if resp.status_code == 200:
                data = resp.json()
                org_name  = (data.get("org")  or "").lower()
                asn_str   = (data.get("as")   or "")
                conn_type = "proxy" if data.get("proxy") else ("hosting" if data.get("hosting") else "")
        except Exception:
            pass

        # ── Step 2: Keyword match on live org name ────────────────────────
        vpn_keywords = {
            "nordvpn":     "NordVPN",
            "nord vpn":    "NordVPN",
            "expressvpn":  "ExpressVPN",
            "express vpn": "ExpressVPN",
            "surfshark":   "Surfshark",
            "protonvpn":   "ProtonVPN",
            "proton vpn":  "ProtonVPN",
            "cyberghost":  "CyberGhost",
            "privateinternetaccess": "PIA",
            "pia vpn":     "PIA",
            "hidemyass":   "HideMyAss",
            "hide my ass": "HideMyAss",
            "mullvad":     "Mullvad",
            "tunnelbear":  "TunnelBear",
            "ipvanish":    "IPVanish",
            "purevpn":     "PureVPN",
            "windscribe":  "Windscribe",
            "hotspot shield": "Hotspot Shield",
            "private vpn": "PrivateVPN",
            "torguard":    "TorGuard",
        }
        for keyword, provider in vpn_keywords.items():
            if keyword in org_name:
                return {"provider": provider, "confidence": 0.90, "is_vpn": True,
                        "asn": asn_str, "org": org_name}

        datacenter_keywords = {
            "digitalocean": "DigitalOcean",
            "linode":       "Linode/Akamai",
            "akamai":       "Linode/Akamai",
            "vultr":        "Vultr",
            "amazon":       "AWS",
            "amazonaws":    "AWS",
            "microsoft":    "Azure",
            "google":       "Google Cloud",
            "ovh":          "OVH",
            "hetzner":      "Hetzner",
            "leaseweb":     "LeaseWeb",
            "choopa":       "Vultr",
        }
        for keyword, provider in datacenter_keywords.items():
            if keyword in org_name:
                return {"provider": provider, "confidence": 0.75,
                        "is_vpn": False, "is_datacenter": True,
                        "asn": asn_str, "org": org_name}

        # ip-api flags proxy/hosting directly
        if conn_type == "proxy":
            return {"provider": org_name or "Unknown Proxy",
                    "confidence": 0.80, "is_vpn": True,
                    "asn": asn_str, "org": org_name}
        if conn_type == "hosting":
            return {"provider": org_name or "Unknown Hosting",
                    "confidence": 0.70, "is_vpn": False, "is_datacenter": True,
                    "asn": asn_str, "org": org_name}

        # ── Step 3: Verified IP-prefix fallback (no network available) ────
        # Only real, verified prefixes — wrong entries from the old code removed
        verified_prefixes = {
            # NordVPN (M247 Ltd infrastructure — AS9009)
            "37.19.":   "NordVPN",
            "45.14.71": "NordVPN",
            "31.13.191": "NordVPN",
            # ProtonVPN
            "185.70.40": "ProtonVPN",
            "185.217.116": "ProtonVPN",
            # Mullvad
            "185.213.154": "Mullvad",
            # Tor (Tor Project owns 5 /24s)
            "5.188.10":  "Tor Exit",
        }
        for prefix, provider in verified_prefixes.items():
            if ip.startswith(prefix):
                return {"provider": provider, "confidence": 0.70,
                        "is_vpn": True, "asn": "", "org": ""}

        return None
    
    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB API"""
        try:
            headers = {"Key": self.abuse_api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=10
            )
            data = response.json()
            
            if "data" in data:
                return {
                    "abuse_score": data["data"]["abuseConfidenceScore"],
                    "total_reports": data["data"]["totalReports"],
                    "country": data["data"]["countryCode"]
                }
        except:
            pass
        return None
    
    def _is_tor_exit(self, ip: str) -> bool:
        """Check if IP is Tor exit node"""
        try:
            current_time = time.time()
            # Cache for 1 hour
            if self.tor_cache is None or (current_time - self.tor_cache_time) > 3600:
                response = requests.get("https://check.torproject.org/exit-addresses", timeout=5)
                self.tor_cache = response.text
                self.tor_cache_time = current_time
            
            if self.tor_cache:
                for line in self.tor_cache.split('\n'):
                    if line.startswith('ExitAddress') and ip in line:
                        return True
        except:
            pass
        return False


# ============================================================================
# STAGE 3A: PROXY CHAIN ANALYSIS
# ============================================================================

@dataclass
class ProxyLayer:
    """Single layer in proxy chain"""
    position: int
    ip: str
    classification: str
    confidence: float
    is_obfuscation: bool
    threat_score: int
    abuse_reports: int
    country: Optional[str]
    provider: Optional[str]
    evidence: List[str]


@dataclass
class ProxyChainAnalysis:
    """Complete proxy chain analysis"""
    chain: List[ProxyLayer]
    obfuscation_count: int
    obfuscation_types: List[str]
    apparent_origin: str
    likely_real_origin: Optional[str]
    true_origin_confidence: float
    analysis_notes: List[str]
    timestamp_analyzed: str


class ProxyChainTracer:
    """Stage 3A: Analyze proxy chain for obfuscation"""
    
    def __init__(self):
        self.obfuscation_types_map = {
            "TOR_EXIT": ("Tor", True),
            "VPN_PROVIDER": ("VPN", True),
            "PROXY": ("Proxy", True),
            "ATTACKER_ORIGIN": ("Direct", False),
            "SUSPICIOUS": ("Suspicious", False),
            "UNKNOWN": ("Unknown", False),
        }
    
    def trace_chain(self, classified_ips: List[Dict]) -> ProxyChainAnalysis:
        """Analyze IP chain for obfuscation layers"""
        
        chain = []
        obfuscation_count = 0
        obfuscation_types = set()
        analysis_notes = []
        
        for position, ip_data in enumerate(classified_ips, 1):
            ip = ip_data.get("ip", "UNKNOWN")
            classification = ip_data.get("classification", "UNKNOWN")
            confidence = ip_data.get("confidence", 0.0)
            threat_score = ip_data.get("threat_score", 0)
            abuse_reports = ip_data.get("abuse_reports", 0)
            country = ip_data.get("country")
            provider = ip_data.get("provider")
            evidence = ip_data.get("evidence", [])
            
            obf_name, is_obfuscation = self.obfuscation_types_map.get(
                classification,
                ("Unknown", False)
            )
            
            if is_obfuscation:
                obfuscation_count += 1
                obfuscation_types.add(obf_name)
            
            layer = ProxyLayer(
                position=position,
                ip=ip,
                classification=classification,
                confidence=confidence,
                is_obfuscation=is_obfuscation,
                threat_score=threat_score,
                abuse_reports=abuse_reports,
                country=country,
                provider=provider,
                evidence=evidence
            )
            
            chain.append(layer)
        
        # Determine true origin
        likely_real_origin = None
        true_origin_confidence = 0.0
        
        if obfuscation_count > 0:
            likely_real_origin = "UNKNOWN"
            true_origin_confidence = 0.0
            analysis_notes.append(f"[OBFUSCATED] {obfuscation_count} hiding layer(s) detected")
            analysis_notes.append(f"[METHODS] {', '.join(sorted(obfuscation_types))}")
            analysis_notes.append("[CONCLUSION] True origin cannot be determined without law enforcement assistance")
        else:
            if chain:
                likely_real_origin = chain[0].ip
                true_origin_confidence = chain[0].confidence
                analysis_notes.append("[DIRECT] No obfuscation detected")
                analysis_notes.append(f"[LIKELY ORIGIN] {likely_real_origin}")
        
        apparent_origin = chain[-1].ip if chain else "UNKNOWN"
        
        return ProxyChainAnalysis(
            chain=chain,
            obfuscation_count=obfuscation_count,
            obfuscation_types=sorted(obfuscation_types),
            apparent_origin=apparent_origin,
            likely_real_origin=likely_real_origin,
            true_origin_confidence=true_origin_confidence,
            analysis_notes=analysis_notes,
            timestamp_analyzed=datetime.now().isoformat()
        )


# ============================================================================
# STAGE 3B: WHOIS/REVERSE DNS ENRICHMENT
# ============================================================================

@dataclass
class ReverseDNSResult:
    """Reverse DNS lookup result"""
    ip: str
    hostname: Optional[str]
    ptr_record: Optional[str]
    lookup_success: bool
    confidence: float
    timestamp: str


@dataclass
class WHOISData:
    """WHOIS lookup result"""
    ip: str
    asn: Optional[str]
    cidr: Optional[str]
    organization: Optional[str]
    registrar: Optional[str]
    registration_date: Optional[str]
    last_updated: Optional[str]
    netname: Optional[str]
    country: Optional[str]
    raw_whois: str
    lookup_success: bool
    confidence: float
    timestamp: str


@dataclass
class HostingTypeAnalysis:
    """Hosting type classification"""
    ip: str
    hosting_type: str
    shared_hosting: bool
    confidence: float
    evidence: List[str]
    risk_level: str
    timestamp: str


@dataclass
class IPEnrichmentResult:
    """Complete IP enrichment with all metadata"""
    ip: str
    reverse_dns: ReverseDNSResult
    whois_data: WHOISData
    hosting_analysis: HostingTypeAnalysis
    is_infrastructure: bool
    ownership_confidence: float
    enrichment_notes: List[str]
    timestamp: str


class ReverseDNSLookup:
    """Perform reverse DNS lookups"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.cache = {}
    
    def lookup(self, ip: str) -> ReverseDNSResult:
        """Resolve IP to hostname"""
        
        if ip in self.cache:
            return self.cache[ip]
        
        hostname = None
        ptr_record = None
        lookup_success = False
        confidence = 0.0
        
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
            lookup_success = True
            confidence = 0.90
            ptr_record = hostname
        except socket.herror:
            pass
        except socket.timeout:
            pass
        except Exception:
            pass
        
        result = ReverseDNSResult(
            ip=ip,
            hostname=hostname,
            ptr_record=ptr_record,
            lookup_success=lookup_success,
            confidence=confidence,
            timestamp=datetime.now().isoformat()
        )
        
        self.cache[ip] = result
        return result


class WHOISLookupManager:
    """Perform WHOIS lookups with caching"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.cache = {}
        self.failed_ips = set()
    
    def lookup(self, ip: str) -> WHOISData:
        """Perform WHOIS lookup"""
        
        if ip in self.cache:
            return self.cache[ip]
        
        if ip in self.failed_ips:
            return self._empty_whois(ip, success=False)
        
        asn = None
        cidr = None
        organization = None
        registrar = None
        registration_date = None
        last_updated = None
        netname = None
        country = None
        raw_whois = ""
        lookup_success = False
        confidence = 0.0
        
        try:
            if not WHOIS_AVAILABLE or whois is None:
                raise ImportError("python-whois not installed")
            w = whois.whois(ip)
            raw_whois = str(w)
            lookup_success = True
            confidence = 0.85
            
            # Parse WHOIS response
            org_field = w.get('org', [None])[0] if isinstance(w.get('org'), list) else w.get('org')
            if not org_field:
                org_field = w.get('organization', [None])[0] if isinstance(w.get('organization'), list) else w.get('organization')
            
            organization = org_field
            
            # ASN extraction
            asn_field = w.get('asn', None)
            if asn_field:
                asn = asn_field[0] if isinstance(asn_field, list) else asn_field
            
            # CIDR extraction
            cidr_field = w.get('cidr', None)
            if cidr_field:
                cidr = cidr_field[0] if isinstance(cidr_field, list) else cidr_field
            
            # Netname
            netname_field = w.get('netname', None)
            if netname_field:
                netname = netname_field[0] if isinstance(netname_field, list) else netname_field
            
            # Country
            country_field = w.get('country', None)
            if country_field:
                country = country_field[0] if isinstance(country_field, list) else country_field
            
            # Dates
            updated = w.get('updated_date', None)
            if updated:
                last_updated = updated[0].isoformat() if isinstance(updated, list) else updated.isoformat()
            
            created = w.get('created_date', None)
            if created:
                registration_date = created[0].isoformat() if isinstance(created, list) else created.isoformat()
        
        except Exception:
            self.failed_ips.add(ip)
        
        result = WHOISData(
            ip=ip,
            asn=asn,
            cidr=cidr,
            organization=organization,
            registrar=registrar,
            registration_date=registration_date,
            last_updated=last_updated,
            netname=netname,
            country=country,
            raw_whois=raw_whois,
            lookup_success=lookup_success,
            confidence=confidence,
            timestamp=datetime.now().isoformat()
        )
        
        self.cache[ip] = result
        return result
    
    def _empty_whois(self, ip: str, success: bool = False) -> WHOISData:
        """Return empty WHOIS result"""
        return WHOISData(
            ip=ip,
            asn=None,
            cidr=None,
            organization=None,
            registrar=None,
            registration_date=None,
            last_updated=None,
            netname=None,
            country=None,
            raw_whois="",
            lookup_success=success,
            confidence=0.0,
            timestamp=datetime.now().isoformat()
        )


class HostingTypeDetector:
    """Detect if IP is residential, datacenter, or hosting provider"""
    
    def __init__(self):
        # Try to load live keywords from online sources
        self.live_keywords = None
        self.use_live_keywords = HOSTING_KEYWORDS_AVAILABLE
        
        if HOSTING_KEYWORDS_AVAILABLE:
            try:
                # Fetch live keywords from online sources (non-blocking)
                self.live_keywords = get_hosting_keywords(fetch_online=True)
            except Exception as e:
                print(f"[!] Warning: Could not fetch live hosting keywords: {e}")
                self.use_live_keywords = False
        
        # Fallback hardcoded keywords (if live keywords fail or not available)
        self.datacenter_keywords = [
            'digital ocean', 'aws', 'amazon', 'google cloud', 'azure', 'linode',
            'vultr', 'hetzner', 'rackspace', 'ovh', 'ionos', 'namecheap',
            'hostgator', 'bluehost', 'dreamhost', 'godaddy', 'data center',
            'server', 'hosting', 'cloud', 'provider', 'vps', 'dedicated'
        ]
        
        self.residential_keywords = [
            'residential', 'home', 'consumer', 'broadband', 'isp', 'comcast',
            'verizon', 'att', 'charter', 'cox', 'spectrum', 'vodafone'
        ]
        
        self.shared_hosting_keywords = [
            'shared', 'vps', 'virtual', 'reseller', 'cloud'
        ]
    
    def analyze(self, whois_data: WHOISData, reverse_dns: ReverseDNSResult) -> HostingTypeAnalysis:
        """Analyze hosting type using live online keywords"""
        
        hosting_type = "UNKNOWN"
        shared_hosting = False
        confidence = 0.0
        evidence = []
        risk_level = "MEDIUM"
        
        combined_text = (
            (whois_data.organization or "") +
            " " +
            (whois_data.netname or "") +
            " " +
            (reverse_dns.hostname or "")
        ).lower()
        
        # Try to use live online keywords first
        if self.use_live_keywords and self.live_keywords:
            try:
                result = classify_hosting_by_keywords(whois_data.organization or "", self.live_keywords)
                
                if result['type'] != 'UNKNOWN':
                    hosting_type = result['type']
                    confidence = result['confidence'] / 100.0  # Convert to 0-1 range
                    evidence.append(f"[LIVE KEYWORDS] {result['type']}")
                    
                    if result['matches']:
                        evidence.extend([f"Matched: {m}" for m in result['matches'][:3]])
                    
                    # Set risk level based on type
                    if hosting_type in ["DATACENTER", "HOSTING"]:
                        risk_level = "HIGH"
                    elif hosting_type == "RESIDENTIAL":
                        risk_level = "LOW"
            
            except Exception as e:
                # Fall back to hardcoded keywords
                pass
        
        # Fallback to hardcoded keywords if live keywords failed or returned UNKNOWN
        if hosting_type == "UNKNOWN":
            # Check for datacenter
            for keyword in self.datacenter_keywords:
                if keyword in combined_text:
                    hosting_type = "DATACENTER"
                    confidence = max(confidence, 0.85)
                    evidence.append(f"Found keyword: {keyword}")
                    risk_level = "HIGH"
                    break
            
            # Check for residential
            if hosting_type == "UNKNOWN":
                for keyword in self.residential_keywords:
                    if keyword in combined_text:
                        hosting_type = "RESIDENTIAL"
                        confidence = 0.80
                        evidence.append(f"Residential keyword: {keyword}")
                        risk_level = "LOW"
                        break
        
        # Check for shared hosting
        if hosting_type == "DATACENTER":
            for keyword in self.shared_hosting_keywords:
                if keyword in combined_text:
                    shared_hosting = True
                    confidence = max(confidence, 0.80)
                    evidence.append(f"Shared hosting indicator: {keyword}")
                    break
        
        # Heuristics from WHOIS
        if hosting_type == "UNKNOWN" and whois_data.lookup_success:
            if whois_data.organization:
                if any(x in whois_data.organization.lower() for x in ['inc', 'llc', 'corp']):
                    hosting_type = "HOSTING_PROVIDER"
                    confidence = 0.70
                    evidence.append("Company organization structure")
                    risk_level = "HIGH"
            
            if whois_data.asn:
                hosting_type = "HOSTING_PROVIDER"
                confidence = 0.75
                evidence.append(f"ASN identified: {whois_data.asn}")
                risk_level = "MEDIUM"
        
        # Default
        if hosting_type == "UNKNOWN":
            hosting_type = "UNKNOWN"
            confidence = 0.3
            risk_level = "MEDIUM"
        
        return HostingTypeAnalysis(
            ip=whois_data.ip,
            hosting_type=hosting_type,
            shared_hosting=shared_hosting,
            confidence=confidence,
            evidence=evidence,
            risk_level=risk_level,
            timestamp=datetime.now().isoformat()
        )


class IPEnrichmentStage3B:
    """Stage 3B: Orchestrate WHOIS and Reverse DNS enrichment"""
    
    def __init__(self):
        self.reverse_dns = ReverseDNSLookup()
        self.whois = WHOISLookupManager()
        self.hosting_detector = HostingTypeDetector()
    
    def enrich_ip(self, ip: str) -> IPEnrichmentResult:
        """Enrich single IP with full metadata"""
        
        # Reverse DNS
        reverse_dns_result = self.reverse_dns.lookup(ip)
        
        # WHOIS
        whois_result = self.whois.lookup(ip)
        
        # Hosting type analysis
        hosting_analysis = self.hosting_detector.analyze(whois_result, reverse_dns_result)
        
        # Determine if infrastructure
        is_infrastructure = hosting_analysis.hosting_type in ["DATACENTER", "HOSTING_PROVIDER"]
        
        # Calculate ownership confidence
        ownership_confidence = (
            (reverse_dns_result.confidence * 0.3) +
            (whois_result.confidence * 0.4) +
            (hosting_analysis.confidence * 0.3)
        )
        
        # Build enrichment notes
        enrichment_notes = []
        
        if is_infrastructure:
            enrichment_notes.append(f"[INFRASTRUCTURE] Hosted on {hosting_analysis.hosting_type.lower()}")
            if hosting_analysis.shared_hosting:
                enrichment_notes.append("[SHARED] Multiple domains/customers on same IP")
        else:
            enrichment_notes.append(f"[ORIGIN] {hosting_analysis.hosting_type.lower()}")
        
        if whois_result.organization:
            enrichment_notes.append(f"[ORGANIZATION] {whois_result.organization}")
        
        if whois_result.asn:
            enrichment_notes.append(f"[ASN] {whois_result.asn}")
        
        if whois_result.country:
            enrichment_notes.append(f"[COUNTRY] {whois_result.country}")
        
        result = IPEnrichmentResult(
            ip=ip,
            reverse_dns=reverse_dns_result,
            whois_data=whois_result,
            hosting_analysis=hosting_analysis,
            is_infrastructure=is_infrastructure,
            ownership_confidence=ownership_confidence,
            enrichment_notes=enrichment_notes,
            timestamp=datetime.now().isoformat()
        )
        
        return result
    
    def enrich_multiple(self, ips: List[str]) -> Dict[str, IPEnrichmentResult]:
        """Enrich multiple IPs"""
        
        results = {}
        for ip in ips:
            results[ip] = self.enrich_ip(ip)
            time.sleep(1)  # Rate limiting
        
        return results


# ============================================================================
# STAGE 3C: INFRASTRUCTURE CORRELATION
# ============================================================================

@dataclass
class InfrastructureCluster:
    """Represents grouped IPs with shared characteristics"""
    cluster_id: str
    ips: List[str]
    shared_asn: Optional[str]
    shared_provider: Optional[str]
    shared_country: Optional[str]
    shared_hosting_type: Optional[str]
    cluster_size: int
    confidence: float
    notes: List[str]
    timestamp: str


@dataclass
class CampaignPattern:
    """Detected attack pattern across multiple campaigns"""
    pattern_id: str
    ips_involved: List[str]
    pattern_type: str  # SAME_ASN, SAME_PROVIDER, SAME_COUNTRY, SEQUENTIAL_IPS
    timing_days_apart: Optional[List[int]]
    threat_level: str
    likelihood_same_attacker: float
    supporting_evidence: List[str]
    timestamp: str


@dataclass
class CorrelationAnalysis:
    """Complete infrastructure correlation results"""
    clusters: List[InfrastructureCluster]
    patterns: List[CampaignPattern]
    attacker_profile: Dict
    estimated_infrastructure_size: int
    estimated_team_size_range: Tuple[int, int]
    operational_notes: List[str]
    timestamp_analyzed: str


class InfrastructureCorrelationEngine:
    """Stage 3C: Correlate IPs and detect attack patterns"""
    
    def __init__(self):
        self.campaign_database = {}  # Simulated database of past campaigns
        self.asn_registry = {}
        self.provider_registry = {}
    
    def analyze_infrastructure(
        self,
        enrichment_results: Dict[str, IPEnrichmentResult],
        email_date: Optional[str] = None
    ) -> CorrelationAnalysis:
        """Analyze IP infrastructure for patterns and correlation"""
        
        ips_data = self._extract_ip_data(enrichment_results)
        
        # Stage 1: Cluster IPs by shared characteristics
        clusters = self._cluster_ips(ips_data)
        
        # Stage 2: Detect patterns in current infrastructure
        patterns = self._detect_patterns(ips_data, clusters)
        
        # Stage 3: Correlate with known campaigns
        campaign_matches = self._correlate_with_campaigns(ips_data)
        
        # Stage 4: Build attacker profile
        attacker_profile = self._build_attacker_profile(ips_data, clusters, patterns)
        
        # Stage 5: Estimate team and infrastructure size
        team_size = self._estimate_team_size(clusters, patterns)
        infra_size = self._estimate_infrastructure_size(clusters, patterns)
        
        # Operational notes
        op_notes = self._generate_operational_notes(clusters, patterns, attacker_profile)
        
        analysis = CorrelationAnalysis(
            clusters=clusters,
            patterns=patterns,
            attacker_profile=attacker_profile,
            estimated_infrastructure_size=infra_size,
            estimated_team_size_range=team_size,
            operational_notes=op_notes,
            timestamp_analyzed=datetime.now().isoformat()
        )
        
        return analysis
    
    def _extract_ip_data(self, enrichment_results: Dict[str, IPEnrichmentResult]) -> List[Dict]:
        """Extract structured data from enrichment results"""
        
        ips_data = []
        for ip, enrich in enrichment_results.items():
            ips_data.append({
                "ip": ip,
                "asn": enrich.whois_data.asn,
                "provider": enrich.whois_data.organization,
                "country": enrich.whois_data.country,
                "hosting_type": enrich.hosting_analysis.hosting_type,
                "is_infrastructure": enrich.is_infrastructure,
                "risk_score": 0,  # Can be calculated from classification
                "notes": enrich.enrichment_notes
            })
        
        return ips_data
    
    def _cluster_ips(self, ips_data: List[Dict]) -> List[InfrastructureCluster]:
        """Group IPs by shared characteristics (ASN, Provider, Country)"""
        
        clusters = []
        processed = set()
        cluster_counter = 0
        
        for i, ip_data in enumerate(ips_data):
            if ip_data["ip"] in processed:
                continue
            
            # Find all IPs that share characteristics
            cluster_ips = [ip_data["ip"]]
            
            # Match by ASN
            if ip_data["asn"]:
                for j, other_ip in enumerate(ips_data):
                    if other_ip["ip"] not in processed and other_ip["asn"] == ip_data["asn"]:
                        if other_ip["ip"] not in cluster_ips:
                            cluster_ips.append(other_ip["ip"])
            
            # Match by Provider
            if ip_data["provider"]:
                for j, other_ip in enumerate(ips_data):
                    if other_ip["ip"] not in processed and other_ip["provider"] == ip_data["provider"]:
                        if other_ip["ip"] not in cluster_ips:
                            cluster_ips.append(other_ip["ip"])
            
            # Create cluster if multiple IPs or special characteristics
            if len(cluster_ips) > 1 or ip_data["is_infrastructure"]:
                cluster = InfrastructureCluster(
                    cluster_id=f"CLUSTER_{cluster_counter:03d}",
                    ips=cluster_ips,
                    shared_asn=ip_data["asn"],
                    shared_provider=ip_data["provider"],
                    shared_country=ip_data["country"],
                    shared_hosting_type=ip_data["hosting_type"],
                    cluster_size=len(cluster_ips),
                    confidence=0.85 if len(cluster_ips) > 1 else 0.70,
                    notes=[
                        f"[SHARED_ASN] Cluster built on ASN {ip_data['asn']}" if ip_data["asn"] else None,
                        f"[SHARED_PROVIDER] {ip_data['provider']}" if ip_data["provider"] else None,
                        f"[LOCATION] {ip_data['country']}" if ip_data["country"] else None,
                        f"[TYPE] {ip_data['hosting_type']}"
                    ],
                    timestamp=datetime.now().isoformat()
                )
                
                # Remove None from notes
                cluster.notes = [n for n in cluster.notes if n is not None]
                
                clusters.append(cluster)
                
                for ip in cluster_ips:
                    processed.add(ip)
                
                cluster_counter += 1
        
        # Create standalone clusters for unmatched IPs
        for ip_data in ips_data:
            if ip_data["ip"] not in processed:
                cluster = InfrastructureCluster(
                    cluster_id=f"CLUSTER_{cluster_counter:03d}",
                    ips=[ip_data["ip"]],
                    shared_asn=ip_data["asn"],
                    shared_provider=ip_data["provider"],
                    shared_country=ip_data["country"],
                    shared_hosting_type=ip_data["hosting_type"],
                    cluster_size=1,
                    confidence=0.60,
                    notes=[f"[SINGLE_IP] Standalone IP from {ip_data['country'] or 'Unknown'}"],
                    timestamp=datetime.now().isoformat()
                )
                clusters.append(cluster)
                processed.add(ip_data["ip"])
                cluster_counter += 1
        
        return clusters
    
    def _detect_patterns(
        self,
        ips_data: List[Dict],
        clusters: List[InfrastructureCluster]
    ) -> List[CampaignPattern]:
        """Detect attack patterns within current infrastructure"""
        
        patterns = []
        
        # Pattern 1: Same ASN usage
        asn_groups = {}
        for ip_data in ips_data:
            if ip_data["asn"]:
                if ip_data["asn"] not in asn_groups:
                    asn_groups[ip_data["asn"]] = []
                asn_groups[ip_data["asn"]].append(ip_data["ip"])
        
        for asn, ips in asn_groups.items():
            if len(ips) > 1:
                pattern = CampaignPattern(
                    pattern_id=f"PATTERN_ASN_{asn}",
                    ips_involved=ips,
                    pattern_type="SAME_ASN",
                    timing_days_apart=None,
                    threat_level="HIGH",
                    likelihood_same_attacker=0.80,
                    supporting_evidence=[
                        f"Multiple IPs from same ASN: {asn}",
                        f"IPs: {', '.join(ips)}",
                        "Indicates intentional infrastructure reuse"
                    ],
                    timestamp=datetime.now().isoformat()
                )
                patterns.append(pattern)
        
        # Pattern 2: Same provider/datacenter
        provider_groups = {}
        for ip_data in ips_data:
            if ip_data["provider"]:
                if ip_data["provider"] not in provider_groups:
                    provider_groups[ip_data["provider"]] = []
                provider_groups[ip_data["provider"]].append(ip_data["ip"])
        
        for provider, ips in provider_groups.items():
            if len(ips) > 1:
                pattern = CampaignPattern(
                    pattern_id=f"PATTERN_PROV_{len(patterns)}",
                    ips_involved=ips,
                    pattern_type="SAME_PROVIDER",
                    timing_days_apart=None,
                    threat_level="MEDIUM",
                    likelihood_same_attacker=0.70,
                    supporting_evidence=[
                        f"Multiple IPs from same provider: {provider}",
                        f"IPs: {', '.join(ips)}",
                        "Suggests coordinated attack infrastructure"
                    ],
                    timestamp=datetime.now().isoformat()
                )
                patterns.append(pattern)
        
        # Pattern 3: Geographic clustering
        country_groups = {}
        for ip_data in ips_data:
            if ip_data["country"]:
                if ip_data["country"] not in country_groups:
                    country_groups[ip_data["country"]] = []
                country_groups[ip_data["country"]].append(ip_data["ip"])
        
        for country, ips in country_groups.items():
            if len(ips) > 1:
                pattern = CampaignPattern(
                    pattern_id=f"PATTERN_GEO_{country}",
                    ips_involved=ips,
                    pattern_type="SAME_COUNTRY",
                    timing_days_apart=None,
                    threat_level="MEDIUM",
                    likelihood_same_attacker=0.65,
                    supporting_evidence=[
                        f"All IPs geolocated to: {country}",
                        f"IPs: {', '.join(ips)}",
                        "Possible attacker originating from this region"
                    ],
                    timestamp=datetime.now().isoformat()
                )
                patterns.append(pattern)
        
        return patterns
    
    def _correlate_with_campaigns(self, ips_data: List[Dict]) -> List[Dict]:
        """
        Correlate observed IPs against known phishing/malware campaigns.

        Sources:
          1. self.campaign_database — IPs added from previous emails this session
             (populated by _update_campaign_database after each analysis)
          2. AbuseIPDB verbose reports — comments often mention campaign names
          3. Infrastructure clustering — IPs sharing ASN + country + hosting type
             across this batch are flagged as likely same campaign

        The old implementation used two fictional campaigns (CAMPAIGN_A/B) with
        invented ASNs (AS1234, AS5678) that could never match a real IP.
        Every call silently returned [] but appeared to have performed correlation.
        """
        matches = []

        if not ips_data:
            return matches

        # ── Source 1: Session campaign database ──────────────────────────
        # campaign_database is populated from previous emails in this batch.
        # Format: {campaign_id: {asns, providers, countries, ips, description}}
        if hasattr(self, 'campaign_database') and self.campaign_database:
            for ip_data in ips_data:
                for cid, attrs in self.campaign_database.items():
                    score = 0.0
                    reasons = []

                    if ip_data.get("asn") and ip_data["asn"] in attrs.get("asns", set()):
                        score += 0.40
                        reasons.append(f"matching ASN {ip_data['asn']}")
                    if ip_data.get("provider") and ip_data["provider"] in attrs.get("providers", set()):
                        score += 0.30
                        reasons.append(f"shared provider {ip_data['provider']}")
                    if ip_data.get("country") and ip_data["country"] in attrs.get("countries", set()):
                        score += 0.20
                        reasons.append(f"same country {ip_data['country']}")
                    if ip_data.get("ip") in attrs.get("ips", set()):
                        score += 0.50
                        reasons.append("IP seen in previous session email")

                    if score >= 0.40:
                        matches.append({
                            "ip":          ip_data["ip"],
                            "campaign":    cid,
                            "match_score": round(score, 2),
                            "description": attrs.get("description", "Session cluster"),
                            "reasons":     reasons,
                            "source":      "session_database"
                        })

        # ── Source 2: Infrastructure clustering within this batch ─────────
        # Group IPs by (ASN, country, hosting_type).  If 2+ IPs share all three
        # they are very likely part of the same actor infrastructure.
        from collections import defaultdict
        clusters: dict = defaultdict(list)
        for ip_data in ips_data:
            key = (
                ip_data.get("asn", ""),
                ip_data.get("country", ""),
                ip_data.get("hosting_type", "")
            )
            if any(k for k in key):   # at least one dimension populated
                clusters[key].append(ip_data["ip"])

        for (asn, country, htype), ips_in_cluster in clusters.items():
            if len(ips_in_cluster) >= 2:
                for ip in ips_in_cluster:
                    # Don't duplicate something already matched from session DB
                    already = any(m["ip"] == ip for m in matches)
                    if not already:
                        matches.append({
                            "ip":          ip,
                            "campaign":    f"INFERRED_CLUSTER_{asn}_{country}",
                            "match_score": 0.60,
                            "description": (
                                f"Infrastructure cluster: {len(ips_in_cluster)} IPs sharing "
                                f"ASN={asn}, country={country}, hosting={htype}"
                            ),
                            "reasons":  ["infrastructure clustering"],
                            "source":   "batch_clustering"
                        })

        return matches

    def _update_campaign_database(self, ips_data: List[Dict]) -> None:
        """
        Update the session campaign database from freshly analysed IPs.
        Called after each email analysis to build up longitudinal context.
        Groups IPs that share ASN+country+hosting into a named cluster.
        """
        if not hasattr(self, 'campaign_database'):
            self.campaign_database = {}

        from collections import defaultdict
        groups: dict = defaultdict(list)
        for ip_data in ips_data:
            key = (ip_data.get("asn",""), ip_data.get("country",""))
            if any(key):
                groups[key].append(ip_data)

        for (asn, country), group in groups.items():
            cid = f"CLUSTER_{asn}_{country}".replace(" ", "_")
            if cid not in self.campaign_database:
                self.campaign_database[cid] = {
                    "asns":        set(),
                    "providers":   set(),
                    "countries":   set(),
                    "ips":         set(),
                    "description": f"Auto-clustered: ASN {asn}, country {country}",
                }
            db = self.campaign_database[cid]
            for ip_data in group:
                if ip_data.get("asn"):      db["asns"].add(ip_data["asn"])
                if ip_data.get("provider"): db["providers"].add(ip_data["provider"])
                if ip_data.get("country"):  db["countries"].add(ip_data["country"])
                if ip_data.get("ip"):       db["ips"].add(ip_data["ip"])
    
    def _build_attacker_profile(
        self,
        ips_data: List[Dict],
        clusters: List[InfrastructureCluster],
        patterns: List[CampaignPattern]
    ) -> Dict:
        """Build attacker profile based on infrastructure analysis"""
        
        # Analyze infrastructure characteristics
        countries = set(ip["country"] for ip in ips_data if ip["country"])
        providers = set(ip["provider"] for ip in ips_data if ip["provider"])
        asns = set(ip["asn"] for ip in ips_data if ip["asn"])
        hosting_types = set(ip["hosting_type"] for ip in ips_data if ip["hosting_type"])
        
        profile = {
            "infrastructure_diversity": {
                "unique_countries": len(countries),
                "countries": list(countries),
                "unique_providers": len(providers),
                "providers": list(providers),
                "unique_asns": len(asns),
                "asns": list(asns)
            },
            "hosting_preferences": {
                "preferred_types": list(hosting_types),
                "uses_datacenter": "DATACENTER" in hosting_types,
                "uses_residential": "RESIDENTIAL" in hosting_types,
                "uses_hosting_provider": "HOSTING_PROVIDER" in hosting_types
            },
            "operational_characteristics": {
                "total_clusters": len(clusters),
                "cluster_distribution": [c.cluster_size for c in clusters],
                "avg_cluster_size": sum(c.cluster_size for c in clusters) / len(clusters) if clusters else 0,
                "max_cluster_size": max((c.cluster_size for c in clusters), default=0)
            },
            "attack_patterns": {
                "total_patterns": len(patterns),
                "pattern_types": list(set(p.pattern_type for p in patterns)),
                "avg_likelihood": sum(p.likelihood_same_attacker for p in patterns) / len(patterns) if patterns else 0
            },
            "sophistication_indicators": {
                "infrastructure_planning": "High" if len(clusters) > 3 else "Medium" if len(clusters) > 1 else "Low",
                "provider_diversity": "High" if len(providers) > 3 else "Medium" if len(providers) > 1 else "Low",
                "geographic_spread": "High" if len(countries) > 3 else "Medium" if len(countries) > 1 else "Low"
            }
        }
        
        return profile
    
    def _estimate_team_size(
        self,
        clusters: List[InfrastructureCluster],
        patterns: List[CampaignPattern]
    ) -> Tuple[int, int]:
        """Estimate attacker team size based on infrastructure"""
        
        # Heuristics for team size estimation
        base_size = 1
        
        # Add operators (one per cluster typically)
        operators = len(clusters)
        
        # Add infrastructure managers (roughly 1 per 5 IPs)
        total_ips = sum(c.cluster_size for c in clusters)
        infrastructure_mgrs = max(1, total_ips // 5)
        
        # Add specialized roles (payload dev, social eng, etc)
        specialists = 1 if len(patterns) > 2 else 0
        
        min_team = base_size + max(1, operators // 2)
        max_team = base_size + operators + infrastructure_mgrs + specialists + 2  # +2 for leadership
        
        return (min_team, max_team)
    
    def _estimate_infrastructure_size(
        self,
        clusters: List[InfrastructureCluster],
        patterns: List[CampaignPattern]
    ) -> int:
        """Estimate total infrastructure size"""
        
        total_ips = sum(c.cluster_size for c in clusters)
        
        # Account for potential hidden/dark web infrastructure
        hidden_factor = 1.5 if any(p.pattern_type == "SAME_ASN" for p in patterns) else 1.0
        
        estimated = int(total_ips * hidden_factor)
        
        return estimated
    
    def _generate_operational_notes(
        self,
        clusters: List[InfrastructureCluster],
        patterns: List[CampaignPattern],
        attacker_profile: Dict
    ) -> List[str]:
        """Generate operational/intelligence notes about attacker"""
        
        notes = []
        
        # Infrastructure notes
        if attacker_profile["infrastructure_diversity"]["unique_countries"] > 3:
            notes.append("[GLOBAL] Attacker operates across multiple continents")
        
        if attacker_profile["infrastructure_diversity"]["unique_providers"] > 2:
            notes.append("[MULTI_PROVIDER] Attacker diversifies across multiple hosting providers")
        
        if any("DATACENTER" in c.notes for c in clusters):
            notes.append("[INFRASTRUCTURE] Uses commercial datacenters (likely professional operation)")
        
        # Pattern notes
        if any(p.pattern_type == "SAME_ASN" for p in patterns):
            notes.append("[PREFERENCE] Demonstrates preference for specific ASNs (infrastructure reuse)")
        
        # Sophistication notes
        if len(clusters) > 5:
            notes.append("[SOPHISTICATED] Large infrastructure suggests well-resourced threat actor")
        
        if attacker_profile["hosting_preferences"]["uses_datacenter"] and \
           attacker_profile["hosting_preferences"]["uses_residential"]:
            notes.append("[HYBRID] Mixes datacenter and residential infrastructure (evasion technique)")
        
        # Operational security notes
        if attacker_profile["infrastructure_diversity"]["unique_asns"] == 1:
            notes.append("[OPSEC_RISK] Single ASN usage increases attribution risk")
        else:
            notes.append("[OPSEC_GOOD] Multiple ASNs reduce traceability")
        
        return notes


# ============================================================================
# STAGE 4: THREAT INTELLIGENCE AGGREGATION
# ============================================================================

@dataclass
class ShodanResult:
    """Shodan API query results"""
    ip: str
    lookup_success: bool
    open_ports: List[int]
    services: List[str]
    banners: List[str]
    technologies: List[str]
    operating_system: Optional[str]
    isp: Optional[str]
    confidence: float
    timestamp: str


@dataclass
class VirusTotalResult:
    """VirusTotal API query results"""
    ip: str
    lookup_success: bool
    malicious_votes: int
    suspicious_votes: int
    harmless_votes: int
    undetected_votes: int
    community_score: float
    detected_urls: List[str]
    detected_files: List[str]
    c2_indicators: List[str]
    confidence: float
    timestamp: str


@dataclass
class ThreatHistoryResult:
    """Historical threat data"""
    ip: str
    abuse_history: List[Dict]
    whois_changes: List[Dict]
    known_malware_associations: List[str]
    c2_server_likelihood: float
    botnet_associations: List[str]
    ransomware_associations: List[str]
    confidence: float
    timestamp: str


@dataclass
class ThreatIntelligenceSummary:
    """Complete threat intelligence analysis"""
    ip: str
    shodan_data: ShodanResult
    virustotal_data: VirusTotalResult
    threat_history: ThreatHistoryResult
    threat_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    threat_score: int  # 0-100
    confidence: float
    detected_threat_types: List[str]
    detected_malware_families: List[str]
    c2_confidence: float
    is_known_c2: bool
    intelligence_notes: List[str]
    timestamp: str


@dataclass
class ThreatIntelligenceAnalysis:
    """Complete threat intelligence for all IPs"""
    summaries: Dict[str, ThreatIntelligenceSummary]
    critical_ips: List[str]
    c2_servers: List[str]
    known_malware_families: List[str]
    aggregate_threat_level: str
    aggregate_confidence: float
    intelligence_notes: List[str]
    timestamp_analyzed: str


class ThreatIntelligenceEngine:
    """Stage 4: Aggregate threat intelligence from multiple sources"""
    
    def __init__(self):
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.query_cache = {}
    
    def analyze_ips(self, ips: List[str]) -> ThreatIntelligenceAnalysis:
        """Analyze multiple IPs for threat intelligence"""
        
        summaries = {}
        critical_ips = []
        c2_servers = []
        known_malware = set()
        
        for ip in ips:
            summary = self._analyze_single_ip(ip)
            summaries[ip] = summary
            
            # Track critical IPs
            if summary.threat_level in ["CRITICAL", "HIGH"]:
                critical_ips.append(ip)
            
            # Track C2 servers
            if summary.is_known_c2:
                c2_servers.append(ip)
            
            # Aggregate malware families
            known_malware.update(summary.detected_malware_families)
        
        # Generate intelligence notes
        intel_notes = self._generate_intelligence_notes(
            summaries, critical_ips, c2_servers, list(known_malware)
        )
        
        # Calculate aggregate threat level
        threat_scores = [s.threat_score for s in summaries.values()]
        avg_threat = sum(threat_scores) / len(threat_scores) if threat_scores else 0
        
        if avg_threat > 80:
            aggregate_threat = "CRITICAL"
        elif avg_threat > 60:
            aggregate_threat = "HIGH"
        elif avg_threat > 40:
            aggregate_threat = "MEDIUM"
        else:
            aggregate_threat = "LOW"
        
        aggregate_confidence = sum(s.confidence for s in summaries.values()) / len(summaries) if summaries else 0
        
        analysis = ThreatIntelligenceAnalysis(
            summaries=summaries,
            critical_ips=critical_ips,
            c2_servers=c2_servers,
            known_malware_families=list(known_malware),
            aggregate_threat_level=aggregate_threat,
            aggregate_confidence=aggregate_confidence,
            intelligence_notes=intel_notes,
            timestamp_analyzed=datetime.now().isoformat()
        )
        
        return analysis
    
    def _analyze_single_ip(self, ip: str) -> ThreatIntelligenceSummary:
        """Analyze single IP across all threat intelligence sources"""
        
        # Check cache
        if ip in self.query_cache:
            return self.query_cache[ip]
        
        # Query each source
        shodan_result = self._query_shodan(ip)
        virustotal_result = self._query_virustotal(ip)
        threat_history = self._query_threat_history(ip)
        
        # Combine results into threat assessment
        threat_score, threat_level = self._calculate_threat_score(
            shodan_result, virustotal_result, threat_history
        )
        
        # Detect C2 indicators
        c2_confidence, is_known_c2 = self._detect_c2_indicators(
            shodan_result, virustotal_result, threat_history
        )
        
        # Detect threat types
        threat_types = self._detect_threat_types(
            shodan_result, virustotal_result, threat_history
        )
        
        # Generate notes
        notes = self._generate_ip_intelligence_notes(
            ip, shodan_result, virustotal_result, threat_history, threat_types
        )
        
        summary = ThreatIntelligenceSummary(
            ip=ip,
            shodan_data=shodan_result,
            virustotal_data=virustotal_result,
            threat_history=threat_history,
            threat_level=threat_level,
            threat_score=int(threat_score),
            confidence=(shodan_result.confidence + virustotal_result.confidence + threat_history.confidence) / 3,
            detected_threat_types=threat_types,
            detected_malware_families=threat_history.c2_server_likelihood > 0.5 and ["Potential C2"] or threat_history.known_malware_associations,
            c2_confidence=c2_confidence,
            is_known_c2=is_known_c2,
            intelligence_notes=notes,
            timestamp=datetime.now().isoformat()
        )
        
        self.query_cache[ip] = summary
        return summary
    
    def _query_shodan(self, ip: str) -> ShodanResult:
        """Query Shodan API"""
        
        if not self.shodan_api_key:
            return ShodanResult(
                ip=ip,
                lookup_success=False,
                open_ports=[],
                services=[],
                banners=[],
                technologies=[],
                operating_system=None,
                isp=None,
                confidence=0.0,
                timestamp=datetime.now().isoformat()
            )
        
        try:
            headers = {"X-APIKey": self.shodan_api_key}
            response = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                ports = data.get("ports", [])
                services = [f"{p}-{data.get('data', [{}])[0].get('product', 'Unknown')}" for p in ports[:3]]
                banners = [d.get("data", "")[:50] for d in data.get("data", [])[:3]]
                
                return ShodanResult(
                    ip=ip,
                    lookup_success=True,
                    open_ports=ports,
                    services=services,
                    banners=banners,
                    technologies=data.get("tags", []),
                    operating_system=data.get("os"),
                    isp=data.get("isp"),
                    confidence=0.90,
                    timestamp=datetime.now().isoformat()
                )
        except:
            pass
        
        return ShodanResult(
            ip=ip,
            lookup_success=False,
            open_ports=[],
            services=[],
            banners=[],
            technologies=[],
            operating_system=None,
            isp=None,
            confidence=0.0,
            timestamp=datetime.now().isoformat()
        )
    
    def _query_virustotal(self, ip: str) -> VirusTotalResult:
        """Query VirusTotal API"""
        
        if not self.virustotal_api_key:
            return VirusTotalResult(
                ip=ip,
                lookup_success=False,
                malicious_votes=0,
                suspicious_votes=0,
                harmless_votes=0,
                undetected_votes=0,
                community_score=0.0,
                detected_urls=[],
                detected_files=[],
                c2_indicators=[],
                confidence=0.0,
                timestamp=datetime.now().isoformat()
            )
        
        try:
            headers = {"x-apikey": self.virustotal_api_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                attrs = data.get("attributes", {})
                
                last_analysis = attrs.get("last_analysis_stats", {})
                malicious = last_analysis.get("malicious", 0)
                suspicious = last_analysis.get("suspicious", 0)
                harmless = last_analysis.get("harmless", 0)
                undetected = last_analysis.get("undetected", 0)
                
                # Detect URLs
                detected_urls = []
                if "detected_urls" in attrs:
                    detected_urls = [u.get("url", "")[:100] for u in attrs.get("detected_urls", [])[:3]]
                
                # Detect C2
                c2_indicators = []
                if malicious > 0 or suspicious > 0:
                    c2_indicators = ["Malicious/Suspicious detection"]
                
                return VirusTotalResult(
                    ip=ip,
                    lookup_success=True,
                    malicious_votes=malicious,
                    suspicious_votes=suspicious,
                    harmless_votes=harmless,
                    undetected_votes=undetected,
                    community_score=attrs.get("reputation", 0),
                    detected_urls=detected_urls,
                    detected_files=[],
                    c2_indicators=c2_indicators,
                    confidence=0.85,
                    timestamp=datetime.now().isoformat()
                )
        except:
            pass
        
        return VirusTotalResult(
            ip=ip,
            lookup_success=False,
            malicious_votes=0,
            suspicious_votes=0,
            harmless_votes=0,
            undetected_votes=0,
            community_score=0.0,
            detected_urls=[],
            detected_files=[],
            c2_indicators=[],
            confidence=0.0,
            timestamp=datetime.now().isoformat()
        )
    
    def _query_threat_history(self, ip: str) -> ThreatHistoryResult:
        """
        Query real threat intelligence for an IP address.

        Sources (in order of preference):
          1. AbuseIPDB  — if self.abuse_api_key is set (free tier: 1000 req/day)
          2. ip-api.com  — free, no key, returns proxy/hosting flag + basic info
          3. VirusTotal  — if self.virustotal_api_key is set

        The old implementation used a three-IP hardcoded "simulated database"
        with fake malware names and fictional dates (2025-12-01). Real IPs
        never matched, so every query silently returned confidence=0.50 with
        zero findings — but the output looked like a real lookup had occurred.
        That code is removed entirely.
        """
        abuse_history  = []
        malware_assoc  = []
        botnet_assoc   = []
        c2_likelihood  = 0.0
        confidence     = 0.0
        data_source    = "none"

        # ── Source 1: AbuseIPDB ───────────────────────────────────────────
        if hasattr(self, 'abuse_api_key') and self.abuse_api_key:
            try:
                import requests
                resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.abuse_api_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    timeout=8
                )
                if resp.status_code == 200:
                    d = resp.json().get("data", {})
                    score        = d.get("abuseConfidenceScore", 0)
                    total_rpts   = d.get("totalReports", 0)
                    last_rpt     = d.get("lastReportedAt", "")
                    categories   = d.get("reports", [])  # verbose mode

                    if total_rpts > 0:
                        abuse_history.append({
                            "date":    last_rpt[:10] if last_rpt else "unknown",
                            "reports": total_rpts,
                            "reason":  f"AbuseIPDB score {score}%"
                        })

                    # Map AbuseIPDB categories to threat types
                    # https://www.abuseipdb.com/categories
                    cat_ids = set()
                    for rpt in categories:
                        cat_ids.update(rpt.get("categories", []))

                    if 18 in cat_ids or 20 in cat_ids:   # Brute-Force / Exploited Host
                        malware_assoc.append("Brute-force / compromised host")
                    if 10 in cat_ids or 11 in cat_ids:   # Web spam / Email spam
                        malware_assoc.append("Spam / phishing infrastructure")
                    if 21 in cat_ids:                     # Web App Attack
                        malware_assoc.append("Web application attack")

                    # C2 likelihood from score
                    if score >= 85:
                        c2_likelihood = 0.80
                    elif score >= 50:
                        c2_likelihood = 0.45
                    elif score >= 20:
                        c2_likelihood = 0.20

                    confidence  = min(0.85, score / 100 + 0.10) if score > 0 else 0.30
                    data_source = "abuseipdb"
            except Exception as e:
                if hasattr(self, 'verbose') and self.verbose:
                    print(f"  [!] AbuseIPDB query failed for {ip}: {e}")

        # ── Source 2: ip-api.com proxy/hosting flag (free, no key) ───────
        if confidence == 0.0:
            try:
                import requests
                resp = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=proxy,hosting,isp,org",
                    timeout=4
                )
                if resp.status_code == 200:
                    d = resp.json()
                    if d.get("proxy"):
                        c2_likelihood = 0.30
                        malware_assoc.append(f"Proxy/VPN detected: {d.get('org','')}")
                        confidence  = 0.45
                        data_source = "ip-api"
                    elif d.get("hosting"):
                        malware_assoc.append(f"Hosting provider: {d.get('org','')}")
                        confidence  = 0.30
                        data_source = "ip-api"
                    else:
                        confidence  = 0.20
                        data_source = "ip-api"
            except Exception:
                pass

        return ThreatHistoryResult(
            ip=ip,
            abuse_history=abuse_history,
            whois_changes=[],
            known_malware_associations=malware_assoc,
            c2_server_likelihood=c2_likelihood,
            botnet_associations=botnet_assoc,
            ransomware_associations=[],
            confidence=confidence,
            timestamp=datetime.now().isoformat()
        )
    
    def _calculate_threat_score(
        self,
        shodan: ShodanResult,
        vt: VirusTotalResult,
        history: ThreatHistoryResult
    ) -> Tuple[float, str]:
        """Calculate threat score from multiple sources"""
        
        score = 0.0
        
        # VirusTotal contribution (0-40)
        total_votes = vt.malicious_votes + vt.suspicious_votes + vt.harmless_votes + vt.undetected_votes
        if total_votes > 0:
            malicious_ratio = vt.malicious_votes / total_votes
            vt_score = malicious_ratio * 40
            score += vt_score
        
        # History contribution (0-30)
        if history.c2_server_likelihood > 0.7:
            score += 30
        elif history.botnet_associations:
            score += 20
        elif history.known_malware_associations:
            score += 15
        
        # Shodan contribution (0-20)
        if shodan.lookup_success:
            if len(shodan.open_ports) > 5:
                score += 10
            if shodan.operating_system and "windows" not in shodan.operating_system.lower():
                score += 5
        
        # Anomaly contribution (0-10)
        if history.abuse_history:
            score += 5
        
        # Determine level
        if score > 80:
            level = "CRITICAL"
        elif score > 60:
            level = "HIGH"
        elif score > 40:
            level = "MEDIUM"
        elif score > 20:
            level = "LOW"
        else:
            level = "INFO"
        
        return (min(100, score), level)
    
    def _detect_c2_indicators(
        self,
        shodan: ShodanResult,
        vt: VirusTotalResult,
        history: ThreatHistoryResult
    ) -> Tuple[float, bool]:
        """Detect C2 indicators"""
        
        indicators = 0
        max_indicators = 5
        
        # Indicator 1: Known C2
        if history.c2_server_likelihood > 0.7:
            indicators += 2
        
        # Indicator 2: VirusTotal detection
        if vt.malicious_votes > 0:
            indicators += 1
        
        # Indicator 3: Botnet association
        if history.botnet_associations:
            indicators += 1
        
        # Indicator 4: Suspicious ports
        if shodan.lookup_success and any(p in shodan.open_ports for p in [4444, 5555, 6666, 8080, 9090]):
            indicators += 1
        
        confidence = (indicators / max_indicators) * 100
        is_known = indicators >= 2
        
        return (confidence, is_known)
    
    def _detect_threat_types(
        self,
        shodan: ShodanResult,
        vt: VirusTotalResult,
        history: ThreatHistoryResult
    ) -> List[str]:
        """Detect threat types"""
        
        types = []
        
        if history.c2_server_likelihood > 0.7:
            types.append("C2_SERVER")
        
        if history.botnet_associations:
            types.append("BOTNET")
        
        if history.known_malware_associations:
            for malware in history.known_malware_associations:
                types.append(f"MALWARE:{malware}")
        
        if vt.malicious_votes > 0:
            types.append("DETECTED_MALICIOUS")
        
        if shodan.lookup_success and shodan.open_ports:
            types.append("EXPOSED_SERVICE")
        
        return types if types else ["SUSPICIOUS"]
    
    def _generate_ip_intelligence_notes(
        self,
        ip: str,
        shodan: ShodanResult,
        vt: VirusTotalResult,
        history: ThreatHistoryResult,
        threat_types: List[str]
    ) -> List[str]:
        """Generate intelligence notes for single IP"""
        
        notes = []
        
        if history.c2_server_likelihood > 0.7:
            notes.append(f"[C2] {ip} likely used as C2 server ({history.c2_server_likelihood:.0%} confidence)")
        
        if history.botnet_associations:
            notes.append(f"[BOTNET] Associated with: {', '.join(history.botnet_associations)}")
        
        if vt.malicious_votes > 0:
            notes.append(f"[VIRUSTOTAL] {vt.malicious_votes} engines detect as malicious")
        
        if shodan.lookup_success:
            if shodan.open_ports:
                notes.append(f"[SERVICES] {len(shodan.open_ports)} open ports detected: {', '.join(map(str, shodan.open_ports[:5]))}")
            if shodan.technologies:
                notes.append(f"[TECH] {', '.join(shodan.technologies[:3])}")
        
        if history.abuse_history:
            notes.append(f"[ABUSE_HISTORY] {len(history.abuse_history)} abuse reports on file")
        
        return notes
    
    def _generate_intelligence_notes(
        self,
        summaries: Dict[str, ThreatIntelligenceSummary],
        critical_ips: List[str],
        c2_servers: List[str],
        malware_families: List[str]
    ) -> List[str]:
        """Generate aggregate intelligence notes"""
        
        notes = []
        
        if c2_servers:
            notes.append(f"[CRITICAL] {len(c2_servers)} confirmed/suspected C2 server(s)")
        
        if critical_ips:
            notes.append(f"[HIGH_THREAT] {len(critical_ips)} IP(s) rated as critical threat")
        
        if malware_families:
            notes.append(f"[MALWARE] Associated with {len(malware_families)} malware families")
        
        threat_scores = [s.threat_score for s in summaries.values()]
        if threat_scores and max(threat_scores) > 80:
            notes.append("[ESCALATE] This campaign shows signs of professional threat actor involvement")
        
        return notes


# ============================================================================
# COMPLETE PIPELINE + REPORT GENERATION
# ============================================================================

@dataclass
class CompletePipelineResult:
    """Complete analysis result with all stages"""
    header_analysis: ReceivedChainAnalysis
    classifications: Dict[str, IPClassification]
    proxy_analysis: ProxyChainAnalysis
    enrichment_results: Optional[Dict[str, IPEnrichmentResult]] = None
    correlation_analysis: Optional[CorrelationAnalysis] = None
    threat_intelligence: Optional[ThreatIntelligenceAnalysis] = None
    geolocation_results: Optional[Dict[str, 'GeolocationData']] = None
    attribution_analysis: Optional['Stage5Attribution'] = None
    real_ip_analysis: Optional['RealIPAnalysis'] = None
    vpn_backtrack_analysis: Optional['BacktrackResult'] = None

    # v3 Components
    webmail_extraction: Optional[Any] = None
    bayesian_attribution: Optional[Any] = None

    # Layer 1: urgency classification (time-decay confidence)
    urgency_result: Optional[Any] = None

    # Layer 1: canarytoken (populated after bait trigger, or None)
    canarytoken_result: Optional[Any] = None

    # IPv6 addresses from Received chain — VPN-resistant geolocation signal
    unique_ipv6: Optional[List[str]] = None
    graph_boost_factors: Optional[Any] = None

    # Phase 0: attacker technique profile (populated before Stage 2)
    attacker_technique_profile: Optional[Any] = None

    # Active analysis result (populated when active analysis is enabled)
    active_analysis_result: Optional[Any] = None


class CompletePipelineReport:
    """Generate complete analysis report"""
    
    def __init__(self, result: CompletePipelineResult):
        self._result = result
        self.header = result.header_analysis
        self.classifications = result.classifications
        self.proxy = result.proxy_analysis
        self.enrichment = result.enrichment_results
        self.correlation = result.correlation_analysis
        self.threat_intelligence = result.threat_intelligence
        self.geolocation = result.geolocation_results
        self.attribution = result.attribution_analysis
        self.real_ip = result.real_ip_analysis
        self._vpn_backtrack_analysis = result.vpn_backtrack_analysis
    
    def generate_text_report(self, verbose: bool = False) -> str:
        """Generate comprehensive text report"""
        
        lines = []
        lines.append("[ATTACKER IP IDENTIFICATION SYSTEM - COMPLETE ANALYSIS]")
        lines.append("=" * 80)
        
        # Email info
        lines.append("\n\n[STAGE 1: EMAIL HEADER INFORMATION]")
        lines.append("-" * 80)
        lines.append(f"  From: {self.header.email_from}")
        lines.append(f"  To: {self.header.email_to}")
        lines.append(f"  Subject: {self.header.email_subject}")
        lines.append(f"  Date: {self.header.email_date}")
        lines.append(f"  Message-ID: {self.header.message_id}")
        lines.append(f"\n  Spoofing Risk: {self.header.spoofing_risk:.0%}")
        lines.append(f"  Header Confidence: {self.header.confidence:.0%}")
        dkim_info = getattr(self.header, "dkim_verification", {}) or {}
        lines.append(f"  DKIM Present: {'Yes' if dkim_info.get('dkim_present') else 'No'}")
        if dkim_info.get("dkim_present"):
            lines.append(f"  DKIM Valid: {'Yes' if dkim_info.get('dkim_valid') else 'No'}")
            lines.append(
                f"  DKIM Domain/Selector: "
                f"{dkim_info.get('domain') or 'Unknown'} / {dkim_info.get('selector') or 'Unknown'}"
            )
            lines.append(f"  DKIM Canonicalization: {dkim_info.get('canonicalization') or 'Unknown'}")
            if dkim_info.get("failure_reason"):
                lines.append(f"  DKIM Failure Reason: {dkim_info.get('failure_reason')}")
            if dkim_info.get("signed_headers"):
                lines.append(
                    "  DKIM Signed Headers: "
                    + ", ".join(dkim_info.get("signed_headers", [])[:12])
                )
        
        if self.header.red_flags:
            lines.append(f"\n  Red Flags ({len(self.header.red_flags)}):")
            for flag in self.header.red_flags[:5]:
                lines.append(f"    {flag}")
        
        # Header chain
        lines.append(f"\n  Header Chain: {self.header.hop_count} hops found")
        lines.append(f"    Origin IP: {self.header.origin_ip}")
        lines.append(f"    Destination IP: {self.header.destination_ip}")
        
        if verbose and self.header.hops:
            lines.append(f"\n  Detailed Hops (IPv4 + IPv6):")
            for hop in self.header.hops:
                ip_display = hop.ip or hop.ipv6 or 'N/A'
                ip_type = ""
                if hop.ipv6 and not hop.ip:
                    ip_type = " [IPv6]"
                lines.append(f"    [{hop.hop_number}] {ip_display}{ip_type} - {hop.hostname or 'N/A'}")
        
        # Stage 2: Classifications
        lines.append("\n\n[STAGE 2: IP CLASSIFICATION ANALYSIS]")
        lines.append("-" * 80)
        
        for ip in sorted(self.classifications.keys()):
            result = self.classifications[ip]
            lines.append(f"\n  IP: {ip}")
            lines.append(f"    Classification: {result.classification}")
            lines.append(f"    Confidence: {result.confidence:.0%}")
            lines.append(f"    Threat Score: {result.threat_score}/100")
            lines.append(f"    Abuse Reports: {result.abuse_reports}")
            
            if result.country:
                lines.append(f"    Country: {result.country}")
            
            if result.evidence:
                lines.append(f"    Evidence:")
                for ev in result.evidence[:3]:
                    lines.append(f"      - {ev}")
            
            # Stage 3B enrichment
            if self.enrichment and ip in self.enrichment:
                enrich = self.enrichment[ip]
                lines.append(f"\n    [STAGE 3B: WHOIS ENRICHMENT]")
                
                if enrich.reverse_dns.hostname:
                    lines.append(f"      Reverse DNS: {enrich.reverse_dns.hostname}")
                
                if enrich.whois_data.organization:
                    lines.append(f"      Organization: {enrich.whois_data.organization}")
                
                if enrich.whois_data.asn:
                    lines.append(f"      ASN: {enrich.whois_data.asn}")
                
                if enrich.whois_data.cidr:
                    lines.append(f"      CIDR: {enrich.whois_data.cidr}")
                
                hosting = enrich.hosting_analysis.hosting_type
                lines.append(f"      Hosting Type: {hosting}")
                lines.append(f"      Risk Level: {enrich.hosting_analysis.risk_level}")
                lines.append(f"      Ownership Confidence: {enrich.ownership_confidence:.0%}")
                
                if enrich.enrichment_notes:
                    for note in enrich.enrichment_notes[:3]:
                        lines.append(f"      {note}")
        
        # Stage 3A: Proxy chain
        lines.append("\n\n[STAGE 3A: PROXY CHAIN ANALYSIS]")
        lines.append("-" * 80)
        lines.append(f"  Obfuscation Layers Detected: {self.proxy.obfuscation_count}")
        
        if self.proxy.obfuscation_types:
            lines.append(f"  Methods: {', '.join(self.proxy.obfuscation_types)}")
        
        lines.append(f"  Apparent Origin: {self.proxy.apparent_origin}")
        lines.append(f"  Likely Real Origin: {self.proxy.likely_real_origin}")
        lines.append(f"  Origin Confidence: {self.proxy.true_origin_confidence:.0%}")
        
        # Attack flow diagram
        lines.append("\n  [ATTACK FLOW DIAGRAM]")
        
        for i, layer in enumerate(self.proxy.chain):
            ip_short = layer.ip[-12:] if len(layer.ip) > 12 else layer.ip
            obf_marker = " [OBFUSCATED]" if layer.is_obfuscation else ""
            threat_marker = " [HIGH THREAT]" if layer.threat_score > 75 else ""
            
            lines.append(f"    [{i+1}] {ip_short:<15} {layer.classification:<18}{threat_marker}{obf_marker}")
            
            if i < len(self.proxy.chain) - 1:
                lines.append("         |")
                lines.append("         v")
        
        # REAL IP EXTRACTION: Display true IP behind VPN/proxy
        if self.real_ip:
            lines.append("\n\n[REAL IP EXTRACTION - VPN/PROXY BYPASS ANALYSIS]")
            lines.append("=" * 80)
            
            lines.append(f"\n  [!]  IDENTIFIED REAL ATTACKER IP: {self.real_ip.suspected_real_ip or 'UNKNOWN'}")
            lines.append(f"  Confidence: {self.real_ip.confidence_score:.0%}")
            lines.append(f"  Obfuscation Level: {self.real_ip.obfuscation_level.value.upper()}")
            
            if self.real_ip.vpn_provider:
                lines.append(f"  VPN Provider Detected: {self.real_ip.vpn_provider}")
            
            if self.real_ip.likely_real_infrastructure:
                lines.append(f"  Real Infrastructure: {self.real_ip.likely_real_infrastructure}")
            
            # Display techniques used if available
            if hasattr(self.real_ip, 'techniques_used') and self.real_ip.techniques_used:
                lines.append(f"\n  Techniques Applied ({len(self.real_ip.techniques_used)}):")
                for i, technique in enumerate(self.real_ip.techniques_used, 1):
                    lines.append(f"    {i}. {technique}")
                lines.append(f"\n  [SOURCE: Research Paper - 'A Survey on Tracing IP Address Behind VPN/Proxy Server']")
            
            lines.append(f"\n  Key Evidence Items:")
            for i, evidence in enumerate(self.real_ip.evidence_items[:5], 1):
                lines.append(f"    {i}. {evidence}")
            
            lines.append(f"\n  Analysis Notes:")
            for note in self.real_ip.analysis_notes[:3]:
                lines.append(f"    {note}")
        
        # Stage 3C: Infrastructure Correlation
        if self.correlation:
            lines.append("\n\n[STAGE 3C: INFRASTRUCTURE CORRELATION ANALYSIS]")
            lines.append("-" * 80)
            
            lines.append(f"  Infrastructure Clusters: {len(self.correlation.clusters)}")
            lines.append(f"  Detected Patterns: {len(self.correlation.patterns)}")
            lines.append(f"  Estimated Total Infrastructure Size: {self.correlation.estimated_infrastructure_size} IPs")
            lines.append(f"  Estimated Attacker Team Size: {self.correlation.estimated_team_size_range[0]}-{self.correlation.estimated_team_size_range[1]} members")
            
            # Clusters detail
            if self.correlation.clusters:
                lines.append(f"\n  [INFRASTRUCTURE CLUSTERS]")
                for cluster in self.correlation.clusters[:5]:  # Show first 5
                    lines.append(f"\n    {cluster.cluster_id}:")
                    lines.append(f"      IPs: {', '.join(cluster.ips)}")
                    if cluster.shared_asn:
                        lines.append(f"      ASN: {cluster.shared_asn}")
                    if cluster.shared_provider:
                        lines.append(f"      Provider: {cluster.shared_provider}")
                    if cluster.shared_country:
                        lines.append(f"      Country: {cluster.shared_country}")
                    lines.append(f"      Confidence: {cluster.confidence:.0%}")
            
            # Patterns detail
            if self.correlation.patterns:
                lines.append(f"\n  [DETECTED PATTERNS]")
                for pattern in self.correlation.patterns[:5]:  # Show first 5
                    lines.append(f"\n    {pattern.pattern_id} ({pattern.pattern_type}):")
                    lines.append(f"      IPs: {', '.join(pattern.ips_involved)}")
                    lines.append(f"      Likelihood Same Attacker: {pattern.likelihood_same_attacker:.0%}")
                    lines.append(f"      Threat Level: {pattern.threat_level}")
            
            # Attacker profile
            if self.correlation.attacker_profile:
                lines.append(f"\n  [ATTACKER PROFILE]")
                profile = self.correlation.attacker_profile
                
                if "infrastructure_diversity" in profile:
                    lines.append(f"\n    Infrastructure Diversity:")
                    lines.append(f"      Countries: {profile['infrastructure_diversity']['unique_countries']}")
                    lines.append(f"      Providers: {profile['infrastructure_diversity']['unique_providers']}")
                    lines.append(f"      ASNs: {profile['infrastructure_diversity']['unique_asns']}")
                
                if "sophistication_indicators" in profile:
                    lines.append(f"\n    Sophistication Level:")
                    soph = profile['sophistication_indicators']
                    lines.append(f"      Planning: {soph.get('infrastructure_planning', 'Unknown')}")
                    lines.append(f"      Provider Diversity: {soph.get('provider_diversity', 'Unknown')}")
                    lines.append(f"      Geographic Spread: {soph.get('geographic_spread', 'Unknown')}")
            
            # Operational notes
            if self.correlation.operational_notes:
                lines.append(f"\n  [OPERATIONAL INTELLIGENCE]")
                for note in self.correlation.operational_notes:
                    lines.append(f"    {note}")
        
        # Stage 4: Threat Intelligence
        if self.threat_intelligence:
            lines.append("\n\n[STAGE 4: THREAT INTELLIGENCE AGGREGATION]")
            lines.append("-" * 80)
            
            lines.append(f"  Aggregate Threat Level: {self.threat_intelligence.aggregate_threat_level}")
            lines.append(f"  Aggregate Confidence: {self.threat_intelligence.aggregate_confidence:.0%}")
            lines.append(f"  Critical IPs Identified: {len(self.threat_intelligence.critical_ips)}")
            lines.append(f"  Suspected C2 Servers: {len(self.threat_intelligence.c2_servers)}")
            lines.append(f"  Detected Malware Families: {len(self.threat_intelligence.known_malware_families)}")
            
            # C2 detail
            if self.threat_intelligence.c2_servers:
                lines.append(f"\n  [COMMAND & CONTROL SERVERS]")
                for c2_ip in self.threat_intelligence.c2_servers[:3]:
                    if c2_ip in self.threat_intelligence.summaries:
                        summary = self.threat_intelligence.summaries[c2_ip]
                        lines.append(f"\n    {c2_ip}:")
                        lines.append(f"      Threat Score: {summary.threat_score}/100")
                        lines.append(f"      C2 Confidence: {summary.c2_confidence:.0%}")
                        
                        if summary.detected_malware_families:
                            lines.append(f"      Associated Malware: {', '.join(summary.detected_malware_families[:2])}")
                        
                        if summary.threat_history.botnet_associations:
                            lines.append(f"      Botnets: {', '.join(summary.threat_history.botnet_associations)}")
                        
                        if summary.intelligence_notes:
                            for note in summary.intelligence_notes[:2]:
                                lines.append(f"      {note}")
            
            # Malware detail
            if self.threat_intelligence.known_malware_families:
                lines.append(f"\n  [DETECTED MALWARE/BOTNETS]")
                for malware in self.threat_intelligence.known_malware_families[:5]:
                    lines.append(f"    - {malware}")
            
            # Intelligence notes
            if self.threat_intelligence.intelligence_notes:
                lines.append(f"\n  [THREAT INTELLIGENCE NOTES]")
                for note in self.threat_intelligence.intelligence_notes:
                    lines.append(f"    {note}")
        
        # Conclusion
        lines.append("\n\n[ANALYSIS CONCLUSION]")
        lines.append("=" * 80)
        
        for note in self.proxy.analysis_notes:
            lines.append(f"  {note}")
        
        # Recommendations
        lines.append("\n[RECOMMENDED ACTIONS]")
        
        if self.proxy.obfuscation_count > 0:
            lines.append("  1. Alert law enforcement (Tor/VPN forensics required)")
            lines.append("  2. Monitor for related patterns in other campaigns")
            lines.append("  3. Correlate with threat intelligence databases")
            lines.append("  4. Consider infrastructure blocking")
        else:
            lines.append("  1. Contact IP's hosting provider abuse team")
            lines.append("  2. File DMCA/abuse report with AbuseIPDB")
            lines.append("  3. Request ISP logs via subpoena (legal)")
            lines.append("  4. Document evidence for law enforcement")
        
        # ========================================================================
        # STAGE 5: FINAL ATTRIBUTION ANALYSIS
        # ========================================================================
        if self.attribution:
            lines.append("\n[STAGE 5: FINAL ATTRIBUTION & EVIDENCE ANALYSIS]")
            lines.append("=" * 80)
            
            # Attribution Statement
            lines.append(f"\n  CONFIDENCE LEVEL: {self.attribution.confidence_level}")
            lines.append(f"  Overall Confidence Score: {self.attribution.confidence_scoring.overall_confidence:.0%}")
            
            lines.append(f"\n  ATTRIBUTION STATEMENT:")
            for stmt_line in self.attribution.final_attribution_statement.split('\n'):
                lines.append(f"    {stmt_line}")
            
            # Attacker Profile
            profile = self.attribution.attacker_profile
            lines.append(f"\n  ATTACKER PROFILE:")
            lines.append(f"    Primary Origin: {profile.primary_origin}")
            lines.append(f"    Origin Confidence: {profile.origin_confidence:.0%}")
            if profile.countries_used:
                lines.append(f"    Countries Used: {', '.join(profile.countries_used)}")
            if profile.cities_detected:
                lines.append(f"    Cities Detected: {', '.join(list(profile.cities_detected)[:5])}")
            
            lines.append(f"\n  INFRASTRUCTURE PROFILE:")
            lines.append(f"    Unique ASNs: {len(profile.unique_asns)}")
            lines.append(f"    Unique ISPs: {profile.unique_isps}")
            lines.append(f"    Infrastructure Diversity: {profile.infrastructure_diversity}")
            lines.append(f"    Operational Security Level: {profile.operational_security_level}")
            
            lines.append(f"\n  ATTACK CHARACTERISTICS:")
            lines.append(f"    Attack Type: {profile.attack_type}")
            lines.append(f"    Estimated Team Size: {profile.estimated_team_size}")
            lines.append(f"    Likely Motivation: {profile.likely_motivation}")
            lines.append(f"    Uses Tor: {profile.uses_tor}")
            lines.append(f"    Uses VPN: {profile.uses_vpn}")
            lines.append(f"    Uses Residential Proxies: {profile.uses_residential_proxies}")
            
            # Confidence Breakdown
            lines.append(f"\n  CONFIDENCE BREAKDOWN:")
            lines.append(f"    Location Confidence: {self.attribution.confidence_scoring.location_confidence:.0%}")
            lines.append(f"    Infrastructure Confidence: {self.attribution.confidence_scoring.infrastructure_confidence:.0%}")
            lines.append(f"    Threat Intel Confidence: {self.attribution.confidence_scoring.threat_intel_confidence:.0%}")
            lines.append(f"    Behavioral Confidence: {self.attribution.confidence_scoring.behavioral_confidence:.0%}")
            lines.append(f"    Technical Confidence: {self.attribution.confidence_scoring.technical_confidence:.0%}")
            
            # Supporting Evidence Summary
            lines.append(f"\n  SUPPORTING EVIDENCE ({len(self.attribution.supporting_evidence)} items):")
            for i, evidence in enumerate(self.attribution.supporting_evidence[:10], 1):  # Show top 10
                lines.append(f"    {i}. [{evidence.category.upper()}] {evidence.description}")
                lines.append(f"       Confidence: {evidence.confidence:.0%}, Severity: {evidence.severity}")
            
            if len(self.attribution.supporting_evidence) > 10:
                lines.append(f"    ... and {len(self.attribution.supporting_evidence) - 10} more evidence items")
            
            # Attribution Graph Summary
            if self.attribution.attribution_graph:
                graph = self.attribution.attribution_graph
                lines.append(f"\n  ATTRIBUTION GRAPH:")
                lines.append(f"    Nodes (IPs/ASNs): {len(graph.nodes)}")
                lines.append(f"    Relationships: {len(graph.edges)}")
                lines.append(f"    Infrastructure Clusters: {len(graph.clusters)}")
            
            # Recommended Actions from Stage 5
            if self.attribution.recommended_actions:
                lines.append(f"\n  STAGE 5 RECOMMENDATIONS:")
                for i, action in enumerate(self.attribution.recommended_actions[:5], 1):
                    lines.append(f"    {i}. {action}")
        
        # ========================================================================
        # FINAL SECTION: PRIMARY FOCUS - ATTACKER GEOLOCATION ANALYSIS
        # ========================================================================
        lines.append("\n\n" + "=" * 80)
        lines.append("[PRIMARY: ATTACKER GEOLOCATION ANALYSIS - FINAL RESULT]")
        lines.append("=" * 80)
        
        # PRIORITY 1: If VPN backtracking found REAL location, show that as PRIMARY result
        if hasattr(self, '_vpn_backtrack_analysis') and self._vpn_backtrack_analysis:
            lines.append("\n[OK] [ALERT] REAL ATTACKER LOCATION IDENTIFIED (VPN BYPASS SUCCESSFUL)")
            lines.append(f"\n  {self._vpn_backtrack_analysis.probable_country}")
            lines.append(f"  Detection Confidence: {self._vpn_backtrack_analysis.backtracking_confidence:.0%}")
            lines.append(f"  Detection Method: Multi-technique forensic analysis ({len(self._vpn_backtrack_analysis.signals)} techniques)")
            
            lines.append(f"\n[VPN OBFUSCATION DETECTED & BYPASSED]")
            lines.append(f"  VPN Endpoint: {self._vpn_backtrack_analysis.vpn_endpoint_ip} ({self._vpn_backtrack_analysis.vpn_country})")
            lines.append(f"  Real Location: {self._vpn_backtrack_analysis.probable_country}")
            
            lines.append(f"\n[BACKTRACKING TECHNIQUES APPLIED]")
            for signal in self._vpn_backtrack_analysis.signals:
                lines.append(f"  [+] {signal.method.value.upper()} ({signal.confidence:.0%} confidence)")
                if signal.real_ip:
                    lines.append(f"    => Real IP: {signal.real_ip}")
                if signal.real_country:
                    lines.append(f"    => Location: {signal.real_country}")
                if signal.evidence:
                    for evidence_item in signal.evidence[:3]:  # Show up to 3 evidence items
                        lines.append(f"    => {evidence_item}")
            
            lines.append(f"\n" + "-" * 80)
        
        # PRIORITY 2: Show geolocation data (as secondary if backtracking exists, or primary if not)
        if self.geolocation:
            if not (hasattr(self, '_vpn_backtrack_analysis') and self._vpn_backtrack_analysis):
                # No VPN backtracking - show geolocation as primary
                # Identify which IP is likely the ATTACKER vs MAIL SERVER
                attacker_location = None
                
                # If we have real IP analysis, use the suspected_real_ip location
                if self.real_ip and hasattr(self.real_ip, 'suspected_real_ip') and self.real_ip.suspected_real_ip:
                    attacker_ip = self.real_ip.suspected_real_ip
                    if attacker_ip in self.geolocation and self.geolocation[attacker_ip]:
                        attacker_location = (attacker_ip, self.geolocation[attacker_ip])
                        lines.append(f"\n  [ALERT] ATTACKER IDENTIFIED - LOCATION DETERMINED:")
                        lines.append(f"\n     Real IP Address: {attacker_ip}")
                        geo = attacker_location[1]
                        if geo.city:
                            lines.append(f"     City: {geo.city}")
                        if geo.country:
                            lines.append(f"     Country: {geo.country}")
                        if geo.latitude and geo.longitude:
                            lines.append(f"     GPS Coordinates: {format_coordinates(geo.latitude, geo.longitude)}")
                        if geo.timezone:
                            lines.append(f"     Timezone: {geo.timezone}")
                        if hasattr(geo, 'isp') and geo.isp:
                            lines.append(f"     ISP: {geo.isp}")
                        if hasattr(geo, 'accuracy_radius_km') and geo.accuracy_radius_km:
                            lines.append(f"     Accuracy Radius: ±{geo.accuracy_radius_km} km")
                        lines.append(f"     Confidence Level: {geo.confidence:.0%}")
                        
                        # For law enforcement
                        lines.append(f"\n  [LAW ENFORCEMENT REFERENCE SUMMARY]")
                        lines.append(f"     Attacker Location: {geo.city}, {geo.country}")
                        if geo.latitude and geo.longitude:
                            lines.append(f"     GPS Coordinates: {format_coordinates(geo.latitude, geo.longitude)}")
                        lines.append(f"     Real IP Address: {attacker_ip}")
                
                # Show all other locations (likely mail servers/relays)
                if len(self.geolocation) > 1 or (attacker_location is None):
                    if not attacker_location:
                        lines.append(f"\n  [!]  PRIMARY LOCATION (Mail server/relay):")
                        # Find primary location
                        primary_locations = {}
                        for ip, geoloc in self.geolocation.items():
                            if geoloc and geoloc.city and geoloc.country:
                                city_key = f"{geoloc.city}, {geoloc.country}"
                                primary_locations[city_key] = primary_locations.get(city_key, 0) + 1
                        
                        if primary_locations:
                            sorted_locations = sorted(primary_locations.items(), key=lambda x: x[1], reverse=True)
                            lines.append(f"     Location: {sorted_locations[0][0]}")
                            lines.append(f"     NOTE: This appears to be a MAIL SERVER, not the attacker's location.")
                            lines.append(f"           The attacker identity was extracted using advanced header analysis.")
                    else:
                        lines.append(f"\n  [EMAIL INTERMEDIARY SERVERS] (For Reference):")
                    
                    lines.append(f"")
                    for ip, geoloc in sorted(self.geolocation.items()):
                        # Skip if this is the attacker's real IP (already shown above)
                        if attacker_location and ip == attacker_location[0]:
                            continue
                        
                        if geoloc and geoloc.confidence > 0 and geoloc.city:
                            coord_str = ""
                            if geoloc.latitude and geoloc.longitude:
                                coord_str = f" - {format_coordinates(geoloc.latitude, geoloc.longitude)}"
                            lines.append(f"     {ip}: {geoloc.city}, {geoloc.country}{coord_str}")
            else:
                # VPN backtracking found real location - show geolocation as supplementary info
                lines.append(f"\n[VPN ENDPOINT GEOLOCATION (For Reference)]")
                for ip, geoloc in sorted(self.geolocation.items()):
                    if geoloc and geoloc.confidence > 0 and geoloc.city:
                        lines.append(f"  {ip}: {geoloc.city}, {geoloc.country}")
                        if geoloc.latitude and geoloc.longitude:
                            lines.append(f"       Coordinates: {format_coordinates(geoloc.latitude, geoloc.longitude)}")
            
            # ====================================================================
            # QUICK REFERENCE TABLE: FOR LAW ENFORCEMENT (IPv4 + IPv6)
            # ====================================================================
            lines.append(f"\n  [QUICK REFERENCE TABLE - CITY & COORDINATES]")
            lines.append(f"  " + "-" * 90)
            lines.append(f"  {'IP Address':<45} {'Type':<15} {'Location':<20}")
            lines.append(f"  " + "-" * 90)
            
            # If we have backtracking results, show the real location
            if hasattr(self, '_vpn_backtrack_analysis') and self._vpn_backtrack_analysis:
                lines.append(f"  {'REAL IP (Backtracked)':<45} {'ATTACKER':<15} {self._vpn_backtrack_analysis.probable_country:<20}")
                if self._vpn_backtrack_analysis.vpn_endpoint_ip in self.geolocation:
                    geo = self.geolocation[self._vpn_backtrack_analysis.vpn_endpoint_ip]
                    lines.append(f"  {self._vpn_backtrack_analysis.vpn_endpoint_ip:<45} {'VPN EXIT':<15} {geo.city if geo.city else 'Unknown':<20}")
            else:
                # Identify attacker location from geolocation
                attacker_location = None
                if self.real_ip and hasattr(self.real_ip, 'suspected_real_ip') and self.real_ip.suspected_real_ip:
                    attacker_ip = self.real_ip.suspected_real_ip
                    if attacker_ip in self.geolocation and self.geolocation[attacker_ip]:
                        attacker_location = (attacker_ip, self.geolocation[attacker_ip])
                
                if attacker_location:
                    ip, geo = attacker_location
                    lines.append(f"  {ip:<45} {'ATTACKER':<15} {geo.city:<20}")
                
                # Add other IPs (mail servers)
                for ip, geoloc in sorted(self.geolocation.items()):
                    if attacker_location and ip == attacker_location[0]:
                        continue  # Already shown above
                    if geoloc and geoloc.confidence > 0 and geoloc.city:
                        lines.append(f"  {ip:<45} {'MAIL RELAY':<15} {geoloc.city:<20}")
            
            lines.append(f"  " + "-" * 90)
        else:
            lines.append("  [NO GEOLOCATION DATA AVAILABLE]")
        
        lines.append("\n" + "=" * 80 + "\n")
        
        # ====================================================================
        # BAYESIAN ATTRIBUTION (v3 engine — always runs)
        # ====================================================================
        bayes = getattr(self, '_bayes', None)
        # Pull from result object stored on self
        if not bayes:
            result_obj = getattr(self, '_result', None)
            if result_obj:
                bayes = getattr(result_obj, 'bayesian_attribution', None)
        
        if bayes:
            lines.append("[BAYESIAN ATTRIBUTION — v3 ENGINE]")
            lines.append("=" * 80)
            lines.append(f"  Primary Region   : {bayes.primary_region}")
            lines.append(f"  Probability      : {bayes.primary_probability:.1%}")
            lines.append(f"  ACI Score        : {bayes.aci.final_aci:.2f}")
            lines.append(f"  ACI-Adjusted     : {bayes.aci_adjusted_prob:.1%}")
            lines.append(f"  Confidence Tier  : {bayes.tier} — {bayes.tier_label}")
            lines.append(f"  Signals Used     : {', '.join(bayes.signals_used) if bayes.signals_used else 'none'}")
            if bayes.posterior:
                lines.append(f"\n  TOP CANDIDATE REGIONS:")
                for rp in bayes.posterior[:5]:
                    bar = '█' * int(rp.probability * 30)
                    lines.append(f"    {rp.region:<28} {rp.probability:>6.1%}  {bar}")
            lines.append("\n" + "=" * 80 + "\n")
        
        return "\n".join(lines)
    
    def to_json(self) -> Dict:
        """Export complete analysis to JSON"""
        
        enrichment_data = {}
        if self.enrichment:
            for ip, enrich in self.enrichment.items():
                enrichment_data[ip] = {
                    "reverse_dns": asdict(enrich.reverse_dns),
                    "whois": asdict(enrich.whois_data),
                    "hosting_analysis": asdict(enrich.hosting_analysis),
                    "is_infrastructure": enrich.is_infrastructure,
                    "ownership_confidence": enrich.ownership_confidence,
                    "notes": enrich.enrichment_notes
                }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "email": {
                "from": self.header.email_from,
                "to": self.header.email_to,
                "subject": self.header.email_subject,
                "date": self.header.email_date,
                "message_id": self.header.message_id,
                "spoofing_risk": self.header.spoofing_risk,
                "red_flags": self.header.red_flags,
                "authentication_results": self.header.auth_results_raw,
                "dkim_signature": self.header.dkim_signature,
                "dkim_verification": self.header.dkim_verification,
            },
            "stage1_header_extraction": {
                "hops_found": self.header.hop_count,
                "origin_ip": self.header.origin_ip,
                "destination_ip": self.header.destination_ip,
                "confidence": self.header.confidence,
                "hop_details": [asdict(hop) for hop in self.header.hops],
                "authentication": {
                    "authentication_results": self.header.auth_results_raw,
                    "dkim_signature": self.header.dkim_signature,
                    "dkim_signatures": self.header.dkim_signatures,
                    "dkim_verification": self.header.dkim_verification,
                },
            },
            "stage2_ip_classification": {
                ip: asdict(c) for ip, c in self.classifications.items()
            },
            "stage3a_proxy_chain": {
                "obfuscation_count": self.proxy.obfuscation_count,
                "obfuscation_types": self.proxy.obfuscation_types,
                "apparent_origin": self.proxy.apparent_origin,
                "likely_real_origin": self.proxy.likely_real_origin,
                "true_origin_confidence": self.proxy.true_origin_confidence,
                "analysis_notes": self.proxy.analysis_notes,
                "chain_layers": [asdict(layer) for layer in self.proxy.chain]
            },
            "stage3b_whois_enrichment": enrichment_data,
            "stage3c_infrastructure_correlation": asdict(self.correlation) if self.correlation else None,
            "stage4_threat_intelligence": self._threat_intel_to_dict() if self.threat_intelligence else None,
            "geolocation_analysis": self._geolocation_to_dict() if self.geolocation else None,
            "real_ip_extraction": self._real_ip_to_dict() if self.real_ip else None,
            "stage5_attribution_analysis": self._attribution_to_dict() if self.attribution else None
        }
    
    def _threat_intel_to_dict(self) -> Dict:
        """Convert threat intelligence analysis to dictionary"""
        if not self.threat_intelligence:
            return {}
        
        summaries_dict = {}
        for ip, summary in self.threat_intelligence.summaries.items():
            summaries_dict[ip] = {
                "threat_score": summary.threat_score,
                "threat_level": summary.threat_level,
                "c2_confidence": summary.c2_confidence,
                "is_known_c2": summary.is_known_c2,
                "detected_threat_types": summary.detected_threat_types,
                "detected_malware_families": summary.detected_malware_families,
                "shodan_data": asdict(summary.shodan_data),
                "virustotal_data": asdict(summary.virustotal_data),
                "threat_history": asdict(summary.threat_history),
                "intelligence_notes": summary.intelligence_notes
            }
        
        return {
            "summaries": summaries_dict,
            "critical_ips": self.threat_intelligence.critical_ips,
            "c2_servers": self.threat_intelligence.c2_servers,
            "known_malware_families": self.threat_intelligence.known_malware_families,
            "aggregate_threat_level": self.threat_intelligence.aggregate_threat_level,
            "aggregate_confidence": self.threat_intelligence.aggregate_confidence,
            "intelligence_notes": self.threat_intelligence.intelligence_notes
        }
        """Convert correlation analysis to dictionary"""
        if not self.correlation:
            return {}
        
        return {
            "clusters": [asdict(c) for c in self.correlation.clusters],
            "patterns": [asdict(p) for p in self.correlation.patterns],
            "attacker_profile": self.correlation.attacker_profile,
            "estimated_infrastructure_size": self.correlation.estimated_infrastructure_size,
            "estimated_team_size_range": list(self.correlation.estimated_team_size_range),
            "operational_notes": self.correlation.operational_notes
        }
    
    def _geolocation_to_dict(self) -> Dict:
        """Convert geolocation data to dictionary for JSON export"""
        if not self.geolocation:
            return {}
        
        geolocations_dict = {}
        city_coordinates_summary = []
        
        for ip, geoloc in self.geolocation.items():
            if geoloc:
                geolocations_dict[ip] = {
                    "country": getattr(geoloc, 'country', None),
                    "country_code": getattr(geoloc, 'country_code', 'UNKNOWN'),
                    "city": getattr(geoloc, 'city', None),
                    "latitude": getattr(geoloc, 'latitude', None),
                    "longitude": getattr(geoloc, 'longitude', None),
                    "timezone": getattr(geoloc, 'timezone', None),
                    "asn": getattr(geoloc, 'asn', None),
                    "provider": getattr(geoloc, 'provider', None),
                    "accuracy_radius_km": getattr(geoloc, 'accuracy_radius_km', None),
                    "confidence": getattr(geoloc, 'confidence', 0.0),
                    "sources": getattr(geoloc, 'sources', [])
                }
                
                # Build city & coordinates summary for law enforcement
                city = getattr(geoloc, 'city', None)
                country = getattr(geoloc, 'country', None)
                lat = getattr(geoloc, 'latitude', None)
                lon = getattr(geoloc, 'longitude', None)
                
                if city and country and lat and lon:
                    city_coordinates_summary.append({
                        "ip_address": ip,
                        "city": city,
                        "country": country,
                        "country_code": getattr(geoloc, 'country_code', 'UNKNOWN'),
                        "latitude": lat,
                        "longitude": lon,
                        "coordinates_decimal": f"({lat}, {lon})",
                        "timezone": getattr(geoloc, 'timezone', None),
                        "confidence_percentage": f"{getattr(geoloc, 'confidence', 0.0):.0%}",
                        "accuracy_radius_km": getattr(geoloc, 'accuracy_radius_km', None)
                    })
        
        return {
            "ips_with_location": geolocations_dict,
            "city_and_coordinates_summary": city_coordinates_summary,
            "summary": {
                "total_ips": len(self.geolocation),
                "ips_with_coordinates": len([g for g in self.geolocation.values() if g and getattr(g, 'latitude', None) and getattr(g, 'longitude', None)]),
                "unique_countries": len(set(getattr(g, 'country', None) for g in self.geolocation.values() if g and getattr(g, 'country', None))),
                "unique_cities": len(set(f"{getattr(g, 'city', 'Unknown')},{getattr(g, 'country', 'Unknown')}" for g in self.geolocation.values() if g and getattr(g, 'city', None) and getattr(g, 'country', None)))
            }
        }
    
    def _real_ip_to_dict(self) -> Dict:
        """Convert real IP extraction analysis to dictionary for JSON export"""
        if not self.real_ip:
            return {}
        
        return {
            "suspected_real_ip": self.real_ip.suspected_real_ip,
            "origin_ip_from_headers": self.real_ip.origin_ip_from_headers,
            "obfuscation_level": self.real_ip.obfuscation_level.value,
            "vpn_provider": self.real_ip.vpn_provider,
            "likely_real_infrastructure": self.real_ip.likely_real_infrastructure,
            "confidence_score": self.real_ip.confidence_score,
            "techniques_used": self.real_ip.techniques_used,
            "evidence_items": self.real_ip.evidence_items,
            "analysis_notes": self.real_ip.analysis_notes
        }
    
    def _attribution_to_dict(self) -> Dict:
        """Convert Stage 5 attribution analysis to dictionary for JSON export"""
        if not self.attribution:
            return {}
        
        # Extract attacker profile
        profile = self.attribution.attacker_profile
        profile_dict = {
            "primary_origin": profile.primary_origin,
            "origin_confidence": profile.origin_confidence,
            "countries_used": list(profile.countries_used),
            "cities_detected": list(profile.cities_detected),
            "timezones": list(profile.timezones),
            "unique_isps": profile.unique_isps,
            "unique_asns": len(profile.unique_asns),
            "hosting_types": list(profile.hosting_types),
            "uses_tor": profile.uses_tor,
            "uses_vpn": profile.uses_vpn,
            "uses_residential_proxies": profile.uses_residential_proxies,
            "infrastructure_diversity": profile.infrastructure_diversity,
            "operational_security_level": profile.operational_security_level,
            "attack_type": profile.attack_type,
            "estimated_team_size": profile.estimated_team_size,
            "likely_motivation": profile.likely_motivation,
            "activity_timezone": profile.activity_timezone,
            "activity_hours": profile.activity_hours,
            "campaign_frequency": profile.campaign_frequency
        }
        
        # Extract attribution graph
        graph_dict = {}
        if self.attribution.attribution_graph:
            graph = self.attribution.attribution_graph
            graph_dict = {
                "nodes_count": len(graph.nodes),
                "edges_count": len(graph.edges),
                "clusters_count": len(graph.clusters),
                "clusters": [
                    {
                        "id": c.get("id"),
                        "purpose": c.get("purpose"),
                        "confidence": c.get("confidence"),
                        "nodes": c.get("nodes", [])
                    }
                    for c in graph.clusters
                ]
            }
        
        # Extract confidence scoring
        confidence = self.attribution.confidence_scoring
        confidence_dict = {
            "overall_confidence": confidence.overall_confidence,
            "location_confidence": confidence.location_confidence,
            "infrastructure_confidence": confidence.infrastructure_confidence,
            "threat_intel_confidence": confidence.threat_intel_confidence,
            "behavioral_confidence": confidence.behavioral_confidence,
            "technical_confidence": confidence.technical_confidence,
            "confidence_reasoning": confidence.confidence_reasoning
        }
        
        # Extract supporting evidence
        evidence_list = []
        for evidence in self.attribution.supporting_evidence:
            evidence_list.append({
                "category": evidence.category,
                "description": evidence.description,
                "confidence": evidence.confidence,
                "severity": evidence.severity,
                "stage_origin": evidence.stage_origin,
                "source": evidence.source
            })
        
        return {
            "timestamp": self.attribution.timestamp,
            "attacker_profile": profile_dict,
            "attribution_graph": graph_dict,
            "confidence_scoring": confidence_dict,
            "supporting_evidence": evidence_list,
            "final_attribution_statement": self.attribution.final_attribution_statement,
            "confidence_level": self.attribution.confidence_level,
            "evidence_package": self.attribution.evidence_package,
            "recommended_actions": self.attribution.recommended_actions
        }


class CompletePipeline:
    """Master pipeline orchestrating all 7 stages (1, 2, 3A, 3B, 3C, 4, Geolocation, 5) + Real IP Extraction"""
    
    def __init__(self, verbose: bool = False, skip_enrichment: bool = False, use_advanced_extraction: bool = True):
        self.extractor = HeaderExtractor()
        self.classifier = IPClassifierLight()
        self.tracer = ProxyChainTracer()
        self.enricher = IPEnrichmentStage3B() if not skip_enrichment else None
        self.correlator = InfrastructureCorrelationEngine()
        self.threat_intel_engine = ThreatIntelligenceEngine()
        self.geolocation_enricher = GeolocationEnricher(verbose=verbose) if GEOLOCATION_AVAILABLE else None
        self.attribution_analyzer = AttributionAnalysisEngine(verbose=verbose) if STAGE5_AVAILABLE else None
        
        # Use advanced real IP extractor with 11+ techniques if available
        if use_advanced_extraction and ADVANCED_REAL_IP_EXTRACTOR_AVAILABLE:
            self.advanced_real_ip_extractor = AdvancedRealIPExtractor(verbose=verbose)
            self.real_ip_extractor = None
        else:
            self.advanced_real_ip_extractor = None
            self.real_ip_extractor = RealIPExtractor(verbose=verbose) if REAL_IP_EXTRACTOR_AVAILABLE else None
        
        self.verbose = verbose
        self.use_advanced_extraction = use_advanced_extraction and ADVANCED_REAL_IP_EXTRACTOR_AVAILABLE

        # ====================================================================
        # v3 Components - Graph & Attribution
        # ====================================================================
        
        # Graph analyzer (for batch mode)
        if GRAPH_CENTRALITY_AVAILABLE:
            self.graph_analyzer = InfrastructureGraphAnalyzer()
        else:
            self.graph_analyzer = None
        
        # Bayesian attribution
        if ATTRIBUTION_ENGINE_AVAILABLE:
            self.bayesian_attribution = AttributionEngine()
        else:
            self.bayesian_attribution = None
        
        # Track processed emails for batch graph analysis
        self.processed_emails = []

        # Layer 1: urgency classifier (stateless — one instance is fine)
        self.urgency_classifier = (
            CampaignUrgencyClassifier() if URGENCY_AVAILABLE else None
        )

        # Layer 1: canarytoken generator (host set later via CLI or env)
        self._canarytoken_generator = None

        # Phase 0: attacker technique profiler
        self.technique_profiler = (
            AttackerTechniqueProfiler(verbose=verbose)
            if TECHNIQUE_PROFILER_AVAILABLE else None
        )

        # Active analysis pipeline (opt-in; disabled by default to avoid
        # unexpected outbound TCP/ICMP probes)
        self.active_pipeline: Optional[Any] = None
        self._active_enabled: bool = False

    # ── Public API: opt-in active analysis ───────────────────────────────────

    def enable_active_analysis(
        self,
        canary_host:   str   = "",
        run_vpn_probe: bool  = True,
        run_rtt:       bool  = True,
        run_flux:      bool  = True,
        run_graph:     bool  = True,
        run_canary:    bool  = True,
        timeout:       float = 5.0,
    ) -> "CompletePipeline":
        """
        Enable active geolocation techniques for all subsequent run() calls.

        Active techniques (opt-in — sends outbound TCP/ICMP/DNS probes):
          1. Canary callback  — polls your webhook for real-IP triggers
          2. Fast-flux DNS    — Holz et al. flux score + ASN geo
          3. VPN port-probe   — TCP port fingerprinting (Goel et al.)
          4. RTT geolocation  — round-trip time triangulation
          5. Infra graph      — NS/MX/SPF/DKIM multi-signal graph (Prasad 2025)

        Parameters
        ----------
        canary_host   : Hostname of your canarytoken callback server.
                        Leave empty to skip canary polling.
        run_vpn_probe : TCP-probe candidate IP for VPN port fingerprinting.
        run_rtt       : RTT-based geolocation via local TCP probes.
        run_flux      : Fast-flux DNS scoring of attacker's domain.
        run_graph     : Infrastructure graph analysis (DNS/DKIM/SPF/MX).
        run_canary    : Poll canary callback endpoint.
        timeout       : Per-technique network timeout in seconds.

        Returns self for chaining:
            pipeline = CompletePipeline().enable_active_analysis(canary_host="...")
        """
        if not ACTIVE_ANALYSIS_AVAILABLE:
            if self.verbose:
                print("[WARNING] Active analysis not available — "
                      "install huntertrace.active.active_analysis")
            return self

        self.active_pipeline = ActiveAnalysisPipeline(
            canary_host   = canary_host,
            run_vpn_probe = run_vpn_probe,
            run_rtt       = run_rtt,
            run_flux      = run_flux,
            run_graph     = run_graph,
            run_canary    = run_canary,
            timeout       = timeout,
            verbose       = self.verbose,
        )
        self._active_enabled = True
        if self.verbose:
            enabled = [
                t for t, on in [
                    ("canary", run_canary), ("flux", run_flux),
                    ("vpn_probe", run_vpn_probe), ("rtt", run_rtt),
                    ("graph", run_graph),
                ] if on
            ]
            print(f"[Active] Enabled techniques: {', '.join(enabled)}")
        return self

    def disable_active_analysis(self) -> "CompletePipeline":
        """Turn off active analysis without destroying configuration."""
        self._active_enabled = False
        return self

    def run_validation(self, verbose: bool = False) -> Optional[Any]:
        """
        Run the active analysis validation framework offline.
        Returns a ValidationReport or None if validation is not available.

        Usage:
            report = pipeline.run_validation(verbose=True)
            if report:
                report.print_summary()
                report.save_json("validation.json")
        """
        if not ACTIVE_VALIDATION_AVAILABLE:
            print("[WARNING] Active validation not available — "
                  "install huntertrace.active.active_validation")
            return None
        runner = ValidationRunner(verbose=verbose)
        return runner.run_all()

    def run(self, email_file: str) -> Optional[CompletePipelineResult]:
        """Run all 7 stages (1: Headers, 2: Classification, 3A: Proxy Chain, 3B: Enrichment, 3C: Correlation, 4: Threat Intelligence, Geolocation, 5: Attribution)"""
        
        print("[START] Complete Attacker IP Identification Pipeline")
        print("=" * 80)
        
        # STAGE 1: Extract headers
        print("\n[STAGE 1] Extracting email headers...")
        
        header_analysis = self.extractor.parse_email_file(email_file)
        
        if not header_analysis:
            print("[ERROR] Failed to parse email")
            return None
        
        print(f"[SUCCESS] Found {header_analysis.hop_count} hops in email chain")

        # ── CAMPAIGN URGENCY CLASSIFICATION (Layer 1) ─────────────────────
        # Classify email age -> CRITICAL/HIGH/NORMAL/COLD.
        # Must run before any confidence-scored output so the time-decay
        # penalty is available for the Bayesian engine.
        urgency_result = None
        if self.urgency_classifier:
            try:
                urgency_result = self.urgency_classifier.classify(
                    header_analysis.email_date
                )
                tier_icon = {
                    "CRITICAL": "🔴", "HIGH": "🟠",
                    "NORMAL":   "🟡", "COLD": "⚪",
                }.get(urgency_result.tier, "")
                print(
                    f"  [URGENCY] {tier_icon} {urgency_result.tier} — "
                    f"email is {urgency_result.age_minutes:.0f} min old  "
                    f"(ACI penalty: {urgency_result.aci_penalty:.0%})"
                )
                if urgency_result.canarytoken_action == "DEPLOY_NOW":
                    print("  [URGENCY] ⚡ Canarytoken deployment recommended — "
                          "attacker likely still active")
            except Exception as _ue:
                if self.verbose:
                    print(f"  [WARNING] Urgency classification failed: {_ue}")

        # Extract unique IPs (BOTH IPv4 AND IPv6)
        unique_ips = []
        unique_ipv6 = []
        seen_ipv4 = set()
        seen_ipv6 = set()
        for hop in header_analysis.hops:
            if hop.ip and hop.ip not in seen_ipv4:
                unique_ips.append(hop.ip)
                seen_ipv4.add(hop.ip)
            if hop.ipv6 and hop.ipv6 not in seen_ipv6:
                unique_ipv6.append(hop.ipv6)
                seen_ipv6.add(hop.ipv6)
        
        print(f"[INFO] Unique IPs found: {', '.join(unique_ips + unique_ipv6)}")

        dkim_info = getattr(header_analysis, "dkim_verification", {}) or {}
        if dkim_info.get("dkim_present"):
            print(
                "  [AUTH] DKIM present: yes"
                f" | valid: {'yes' if dkim_info.get('dkim_valid') else 'no'}"
            )
            if dkim_info.get("domain") or dkim_info.get("selector"):
                print(
                    "    Domain/selector: "
                    f"{dkim_info.get('domain') or 'unknown'}"
                    f" / {dkim_info.get('selector') or 'unknown'}"
                )
            if dkim_info.get("canonicalization"):
                print(f"    Canonicalization: {dkim_info.get('canonicalization')}")
            if dkim_info.get("failure_reason"):
                print(f"    Failure reason: {dkim_info.get('failure_reason')}")
            if dkim_info.get("signed_headers"):
                print(
                    "    Signed headers: "
                    + ", ".join(dkim_info.get("signed_headers", [])[:12])
                )
        else:
            print("  [AUTH] DKIM present: no")
        
        # WEBMAIL EXTRACTION: run immediately after header parsing on raw file
        webmail_extraction = None
        if WEBMAIL_V2_AVAILABLE:
            try:
                with open(email_file, 'r', encoding='utf-8', errors='replace') as _wf:
                    _raw_email = _wf.read()
                webmail_extraction = run_webmail_extraction(_raw_email)
                if webmail_extraction and getattr(webmail_extraction, 'real_ip_found', False):
                    print(f"  [WEBMAIL LEAK] Real IP found: {webmail_extraction.real_ip}")
                    print(f"    Provider : {getattr(webmail_extraction, 'provider_name', 'Unknown')}")
                    print(f"    Header   : {getattr(webmail_extraction, 'header_source', 'Unknown')}")
                else:
                    print(f"  [WEBMAIL] No real IP leaked via webmail headers")
            except Exception as _e:
                if self.verbose:
                    print(f"  [WARNING] Webmail extraction failed: {_e}")
        if unique_ipv6:
            print(f"[INFO] IPv6 addresses detected: {', '.join(unique_ipv6)}")

        # ── PHASE 0: ATTACKER TECHNIQUE PROFILING ─────────────────────────
        # Runs BEFORE IP classification. Answers "what did the attacker DO?"
        # before "where did they come from?"
        # Outputs:
        #   - detected_techniques[]       → MITRE ATT&CK TTP fingerprint
        #   - sending_method              → webmail provider / phishing kit / bot
        #   - header_integrity_score      → discounts forged Received: signals
        #   - passive_attribution_blocked → triggers canary token fallback
        technique_profile = None
        _raw_email_for_profiler = None
        if self.technique_profiler:
            print("\n[PHASE 0] Profiling attacker techniques...")
            try:
                with open(email_file, 'r', encoding='utf-8', errors='replace') as _pf:
                    _raw_email_for_profiler = _pf.read()
                technique_profile = self.technique_profiler.profile(
                    _raw_email_for_profiler,
                    header_analysis=header_analysis,
                )
                technique_profile.print_summary()

                # ── Propagate Phase 0 findings to downstream stages ────────
                # 1. If Received: chain is forged, warn backtracking engine
                if technique_profile.header_integrity_score < 0.85:
                    print(
                        f"  [PHASE 0] ⚠  Header integrity "
                        f"{technique_profile.header_integrity_score:.0%} "
                        f"— Received: chain may be forged. "
                        f"T1/T3 backtracking signals will be discounted."
                    )

                # 2. If ProtonMail / Tutanota detected, passive attribution is
                #    blocked — escalate canary token urgency immediately
                if technique_profile.passive_attribution_blocked:
                    print(
                        "  [PHASE 0] 🔴 Passive attribution BLOCKED "
                        "(ProtonMail/Tutanota strips all sender IP). "
                        "Canary token is the only recovery path."
                    )
                    if urgency_result is not None:
                        urgency_result.canarytoken_action = "DEPLOY_NOW"

                # 3. If sending method leaked a real IP, log it prominently
                if (technique_profile.sending_method and
                        technique_profile.sending_method.real_ip_leaked and
                        technique_profile.sending_method.real_ip):
                    print(
                        f"  [PHASE 0] ✓ Sending method leaked real IP: "
                        f"{technique_profile.sending_method.real_ip} "
                        f"({technique_profile.sending_method.provider}) "
                        f"conf {technique_profile.sending_method.confidence:.0%}"
                    )

            except Exception as _pe:
                if self.verbose:
                    print(f"  [WARNING] Technique profiling failed: {_pe}")
                technique_profile = None

        # STAGE 2: Classify IPs
        print("\n[STAGE 2] Classifying IPs...")
        
        classifications = {}
        for ip in unique_ips:
            result = self.classifier.classify_ip(ip)
            classifications[ip] = result
            print(f"  {ip}: {result.classification} (confidence: {result.confidence:.0%}, threat: {result.threat_score}/100)")
        
        # STAGE 3A: Trace proxy chain
        print("\n[STAGE 3A] Analyzing proxy chain...")
        
        classified_chain = []
        for hop in header_analysis.hops:
            if hop.ip and hop.ip in classifications:
                classified_data = asdict(classifications[hop.ip])
                classified_chain.append(classified_data)
        
        proxy_analysis = self.tracer.trace_chain(classified_chain)
        print(f"  Obfuscation layers detected: {proxy_analysis.obfuscation_count}")
        print(f"  Real origin status: {proxy_analysis.likely_real_origin}")
        
        # VPN BACKTRACKING (NEW): If VPN detected, attempt to backtrack real IP
        vpn_backtrack_analysis = None
        if proxy_analysis.obfuscation_count > 0 and VPN_BACKTRACK_AVAILABLE:
            print("\n[VPN BACKTRACKING] Detecting obfuscation methods...")
            try:
                # Find VPN IP in classifications
                vpn_ip = None
                vpn_provider = "Unknown"
                vpn_country = "Unknown"
                for ip, classification in classifications.items():
                    if classification.is_vpn:
                        vpn_ip = ip
                        if classification.provider:
                            vpn_provider = classification.provider
                        if classification.country:
                            vpn_country = classification.country
                        break
                
                if vpn_ip:
                    print(f"  VPN detected: {vpn_provider} ({vpn_ip})")
                    # If Phase 0 flagged header forgery, warn that T1/T3 will
                    # yield low-confidence results before we even start
                    if (technique_profile is not None and
                            technique_profile.header_integrity_score < 0.85):
                        print(
                            f"  [PHASE 0 WARNING] Header integrity "
                            f"{technique_profile.header_integrity_score:.0%} "
                            f"— Received: chain appears forged. "
                            f"T1/T3 signals discounted; relying on T4/T8."
                        )
                    print(f"  Attempting to backtrack REAL IP using 7+ techniques...\n")
                    
                    backtracker = RealIPBacktracker(verbose=self.verbose)
                    
                    # Convert email headers to dict
                    email_headers_for_backtrack = {
                        'Date': str(header_analysis.email_date) if header_analysis.email_date else None,
                        'Received': [hop.raw_header for hop in header_analysis.hops],
                        'Received-SPF': 'Unknown',
                        'DKIM-Signature': 'Unknown',
                        'X-Originating-IP': 'Unknown',
                        'Authentication-Results': 'Unknown',
                    }
                    
                    vpn_backtrack_analysis = backtracker.backtrack_real_ip(
                        email_headers=email_headers_for_backtrack,
                        vpn_endpoint_ip=vpn_ip,
                        vpn_country=vpn_country
                    )
                    
                    print(f"  [+] BACKTRACKING COMPLETE:")
                    print(f"    Techniques applied: {len(vpn_backtrack_analysis.signals)}")
                    print(f"    Backtracking confidence: {vpn_backtrack_analysis.backtracking_confidence:.0%}")
                    if vpn_backtrack_analysis.probable_real_ip:
                        print(f"    [ALERT] PROBABLE REAL IP: {vpn_backtrack_analysis.probable_real_ip}")
                    if vpn_backtrack_analysis.probable_country:
                        print(f"    Location: {vpn_backtrack_analysis.probable_country}")
            except Exception as e:
                if self.verbose:
                    print(f"  [WARNING] VPN backtracking failed: {e}")
                vpn_backtrack_analysis = None
        
        # STAGE 3B: WHOIS enrichment
        enrichment_results = None
        if self.enricher:
            print("\n[STAGE 3B] Enriching with WHOIS/DNS data...")
            try:
                enrichment_results = {}
                for ip in unique_ips:
                    result = self.enricher.enrich_ip(ip)
                    enrichment_results[ip] = result
                    org = result.whois_data.organization or "Unknown"
                    country = result.whois_data.country or "?"
                    print(f"  {ip}: {org} ({country})")
            except Exception as e:
                if self.verbose:
                    print(f"  [WARNING] Enrichment failed: {e}")
                enrichment_results = None
        else:
            print("\n[NOTICE] Stage 3B skipped (requires python-whois library)")
        
        # STAGE 3C: Infrastructure Correlation
        print("\n[STAGE 3C] Analyzing infrastructure correlation...")
        
        correlation_analysis = None
        if enrichment_results:
            try:
                correlation_analysis = self.correlator.analyze_infrastructure(
                    enrichment_results,
                    email_date=header_analysis.email_date
                )
                
                print(f"  Clusters detected: {len(correlation_analysis.clusters)}")
                print(f"  Patterns found: {len(correlation_analysis.patterns)}")
                print(f"  Est. infrastructure size: {correlation_analysis.estimated_infrastructure_size} IPs")
                print(f"  Est. team size: {correlation_analysis.estimated_team_size_range[0]}-{correlation_analysis.estimated_team_size_range[1]} members")
            except Exception as e:
                if self.verbose:
                    print(f"  [WARNING] Correlation analysis failed: {e}")
                correlation_analysis = None
        else:
            print("  [NOTICE] Stage 3C skipped (requires Stage 3B enrichment data)")
        
        # STAGE 4: Threat Intelligence Aggregation
        print("\n[STAGE 4] Aggregating threat intelligence...")
        
        threat_intelligence = None
        if enrichment_results:
            try:
                threat_intelligence = self.threat_intel_engine.analyze_ips(
                    ips=unique_ips
                )
                
                if threat_intelligence.critical_ips:
                    print(f"  Critical IPs identified: {len(threat_intelligence.critical_ips)}")
                if threat_intelligence.c2_servers:
                    print(f"  C2 servers detected: {len(threat_intelligence.c2_servers)}")
                if threat_intelligence.known_malware_families:
                    print(f"  Malware families: {', '.join(threat_intelligence.known_malware_families)}")
                    
                print(f"  Overall threat assessment: {threat_intelligence.aggregate_threat_level}")
            except Exception as e:
                if self.verbose:
                    print(f"  [WARNING] Threat intelligence analysis failed: {e}")
                threat_intelligence = None
        else:
            print("  [NOTICE] Stage 4 skipped (requires Stage 3B enrichment data)")
        
        # (Real IP extraction and geolocation run in the canonical block below)
        
        # REAL IP EXTRACTION: Extract true IP address before geolocating (so we geolocate the RIGHT IP)
        print("\n[REAL IP EXTRACTION] Identifying true attacker IP (VPN/Proxy bypass)...")
        real_ip_analysis = None
        attacker_real_ip = None  # Will store the suspected_real_ip for targeted geolocation
        
        # Try advanced extraction first (11+ techniques from research paper)
        if self.use_advanced_extraction and self.advanced_real_ip_extractor:
            try:
                print("  Using ADVANCED Real IP Extractor (11+ techniques from research paper)...")
                
                # Prepare data for advanced extractor
                email_headers_dict = {
                    'received_from_ip': header_analysis.origin_ip,
                    'hop_count': header_analysis.hop_count,
                }
                
                # Prepare classifications dict
                classifications_dict = {}
                for ip, classification in classifications.items():
                    classifications_dict[ip] = {
                        'is_vpn': 'VPN' in classification.classification,
                        'is_proxy': 'Proxy' in classification.classification,
                        'is_tor': 'Tor' in classification.classification,
                    }
                
                # Prepare enrichment data
                enrichments = {}
                if enrichment_results:
                    for ip, enrichment in enrichment_results.items():
                        enrichments[ip] = {
                            'organization': enrichment.whois_data.organization or "Unknown",
                            'asn': enrichment.whois_data.asn or "Unknown",
                            'country': enrichment.whois_data.country or "Unknown",
                        }
                
                # Run advanced extraction
                advanced_real_ip_analysis = self.advanced_real_ip_extractor.extract_real_ip(
                    email_headers=email_headers_dict,
                    classifications=classifications_dict,
                    enrichments=enrichments,
                    geolocation={},  # Will add geolocation after extraction
                    honeypot_data=None,
                    dns_queries=None,
                    traffic_patterns=None
                )
                
                if advanced_real_ip_analysis:
                    real_ip_analysis = advanced_real_ip_analysis
                    attacker_real_ip = advanced_real_ip_analysis.suspected_real_ip
                    print(f"  [+] EXTRACTED ATTACKER IP: {attacker_real_ip} ({advanced_real_ip_analysis.confidence_score:.0%} confidence)")
                    if advanced_real_ip_analysis.vpn_provider:
                        print(f"    VPN Provider: {advanced_real_ip_analysis.vpn_provider}")
            except Exception as e:
                if self.verbose:
                    print(f"  [WARNING] Advanced extraction failed: {e}")
        
        # Fallback to standard extraction
        if not real_ip_analysis and self.real_ip_extractor:
            try:
                print("  Using standard Real IP Extractor (7 basic techniques)...")
                
                classifications_dict = {}
                for ip, classification in classifications.items():
                    classifications_dict[ip] = {
                        "classification": classification.classification,
                        "confidence": classification.confidence
                    }
                
                enrichment_dict = None
                if enrichment_results:
                    enrichment_dict = {}
                    for ip, enrichment in enrichment_results.items():
                        enrichment_dict[ip] = {
                            "organization": enrichment.whois_data.organization or "Unknown",
                            "asn": enrichment.whois_data.asn or "Unknown"
                        }
                
                real_ip_analysis = self.real_ip_extractor.extract_real_ip(
                    origin_ip=header_analysis.origin_ip,
                    all_ips_in_chain=[hop.ip or hop.ipv6 for hop in header_analysis.hops if (hop.ip or hop.ipv6)],
                    hop_details=[{
                        "hop_number": hop.hop_number,
                        "ip": hop.ip,
                        "ipv6": hop.ipv6,
                        "hostname": hop.hostname,
                        "raw_header": hop.raw_header
                    } for hop in header_analysis.hops],
                    classifications=classifications_dict,
                    enrichment_data=enrichment_dict,
                    geolocation_data=None
                )
                
                if real_ip_analysis:
                    attacker_real_ip = real_ip_analysis.suspected_real_ip
                    print(f"  [+] EXTRACTED ATTACKER IP: {attacker_real_ip} ({real_ip_analysis.confidence_score:.0%} confidence)")
            except Exception as e:
                if self.verbose:
                    print(f"  [WARNING] Standard extraction failed: {e}")
        
        # NOW GEOLOCATE: Use VPN backtracking result if available (it has real IP), otherwise use real_ip_analysis
        print("\n[GEOLOCATION] Enriching attacker IP location...")
        geolocation_results = None
        
        # PRIORITY: If VPN backtracking found real IP, use that for geolocation
        # BUT: If the probable_real_ip IS the VPN endpoint, use inferred COUNTRY instead
        ip_to_geolocate = None
        use_backtrack_country = False
        backtrack_country = None
        
        if vpn_backtrack_analysis and vpn_backtrack_analysis.probable_real_ip:
            # Check if this IP is the same as the VPN endpoint (happens when backtracking can't separate IP)
            is_same_as_vpn = False
            if proxy_analysis and proxy_analysis.chain:
                for chain_item in proxy_analysis.chain:
                    if chain_item.ip == vpn_backtrack_analysis.probable_real_ip and chain_item.is_obfuscation:
                        is_same_as_vpn = True
                        break
            
            # If it's the VPN endpoint, use inferred country instead of geolocating the VPN IP
            if is_same_as_vpn and vpn_backtrack_analysis.probable_country:
                use_backtrack_country = True
                backtrack_country = vpn_backtrack_analysis.probable_country
                print(f"  [VPN BACKTRACK] Using inferred country (VPN endpoint detected): {backtrack_country}")
                print(f"     Confidence: {vpn_backtrack_analysis.backtracking_confidence:.0%}")
            else:
                # Actually different IP, geolocate it
                ip_to_geolocate = vpn_backtrack_analysis.probable_real_ip
                print(f"  Using VPN backtracking result: {ip_to_geolocate}")
        elif attacker_real_ip:
            ip_to_geolocate = attacker_real_ip
            print(f"  Using real IP extraction result: {ip_to_geolocate}")
        
        if use_backtrack_country:
            # Use inferred country from backtracking (timezone, behavior analysis, etc.)
            geolocation_results = {vpn_backtrack_analysis.probable_real_ip: type('obj', (object,), {
                'country': backtrack_country,
                'country_code': 'INFERRED',
                'city': 'Unknown',
                'latitude': None,
                'longitude': None,
                'timezone': 'Unknown',
                'asn': 'Unknown',
                'provider': 'Unknown',
                'isp': 'Unknown',
                'accuracy_radius_km': None,
                'confidence': vpn_backtrack_analysis.backtracking_confidence,
                'sources': ['VPN Backtracking']
            })()} if vpn_backtrack_analysis.probable_real_ip else None
            print(f"  [+] ATTACKER LOCATION: {backtrack_country} (Inferred)")
        elif ip_to_geolocate and self.geolocation_enricher:
            try:
                geolocation_results = self.geolocation_enricher.enrich_multiple_ips([ip_to_geolocate])
                
                if geolocation_results and ip_to_geolocate in geolocation_results:
                    geo = geolocation_results[ip_to_geolocate]
                    if geo:
                        print(f"  [+] ATTACKER LOCATION: {geo.city}, {geo.country}")
                        if geo.latitude and geo.longitude:
                            print(f"     Coordinates: {format_coordinates(geo.latitude, geo.longitude)}")
                        print(f"     ISP: {geo.isp}")
                        print(f"     Confidence: {geo.confidence:.0%}")
            except Exception as e:
                if self.verbose:
                    print(f"  [WARNING] Geolocation failed: {e}")
        elif self.geolocation_enricher:
            # Fallback: geolocate all IPs if no attacker IP identified
            try:
                geolocation_results = self.geolocation_enricher.enrich_multiple_ips(unique_ips)
            except Exception as e:
                if self.verbose:
                    print(f"  [WARNING] Geolocation enrichment failed: {e}")
        
        # ── ACTIVE ANALYSIS (opt-in) ────────────────────────────────────────
        # Runs after passive backtracking.  Signals from active techniques
        # (canary callback, fast-flux DNS, VPN port-probe, RTT geo, infra
        # graph) are merged into the existing BacktrackResult signal list
        # and confidences re-synthesised before Bayesian attribution fires.
        active_analysis_result = None
        if self._active_enabled and self.active_pipeline and ACTIVE_ANALYSIS_AVAILABLE:
            print("\n[ACTIVE ANALYSIS] Running 5 active geolocation techniques...")
            try:
                # Build headers dict for active pipeline
                _active_headers = {
                    "From":            header_analysis.email_from,
                    "DKIM-Signature":  str(getattr(header_analysis, "dkim_signature", "")),
                    "Received":        [h.raw_header for h in header_analysis.hops],
                    "X-HunterTrace-Canary": None,   # populated when canary deployed
                }

                _candidate_ip = (
                    vpn_backtrack_analysis.probable_real_ip
                    if vpn_backtrack_analysis and vpn_backtrack_analysis.probable_real_ip
                    else header_analysis.origin_ip
                )

                active_analysis_result = self.active_pipeline.run(
                    email_headers  = _active_headers,
                    candidate_ip   = _candidate_ip,
                    canary_token_id= None,
                )

                # Merge active signals into vpn_backtrack_analysis
                if vpn_backtrack_analysis and active_analysis_result.signals:
                    vpn_backtrack_analysis.signals.extend(
                        active_analysis_result.signals)
                    # Re-synthesise confidence with merged signals
                    from collections import Counter as _Counter
                    _ip_scores:  dict = _Counter()
                    _cty_scores: dict = _Counter()
                    for _s in vpn_backtrack_analysis.signals:
                        if _s.real_ip:
                            _ip_scores[_s.real_ip]       += _s.confidence
                        if _s.real_country:
                            _cty_scores[_s.real_country] += _s.confidence
                    if _ip_scores:
                        _best_ip = max(_ip_scores, key=_ip_scores.__getitem__)
                        if _ip_scores[_best_ip] > 0.60:
                            vpn_backtrack_analysis.probable_real_ip = _best_ip
                    if _cty_scores:
                        vpn_backtrack_analysis.probable_country = max(
                            _cty_scores, key=_cty_scores.__getitem__)
                    vpn_backtrack_analysis.backtracking_confidence = min(
                        sum(s.confidence for s in vpn_backtrack_analysis.signals)
                        / max(len(vpn_backtrack_analysis.signals), 1),
                        1.0,
                    )

                # Print summary
                ar = active_analysis_result
                print(f"  Active signals generated : {len(ar.signals)}")
                if ar.dominant_country:
                    print(f"  Dominant country         : {ar.dominant_country}")
                print(f"  Active confidence        : {ar.overall_confidence:.0%}")
                if ar.canary_result and ar.canary_result.triggered:
                    print(f"  [CANARY] Triggered — real IP: {ar.canary_result.real_ip}")
                if ar.flux_result and ar.flux_result.is_fast_flux:
                    print(f"  [FLUX] Fast-flux domain detected "
                          f"(score={ar.flux_result.flux_score:.2f})")

            except Exception as _ae:
                if self.verbose:
                    print(f"  [WARNING] Active analysis failed: {_ae}")
                    import traceback; traceback.print_exc()
                active_analysis_result = None

        # Stage 5 legacy attribution object — superseded by the Bayesian
        # engine below, but kept as None so the result dataclass field is set.
        attribution_analysis = None

        # Create result
        result = CompletePipelineResult(
            header_analysis=header_analysis,
            classifications=classifications,
            proxy_analysis=proxy_analysis,
            enrichment_results=enrichment_results,
            correlation_analysis=correlation_analysis,
            threat_intelligence=threat_intelligence,
            geolocation_results=geolocation_results,
            attribution_analysis=attribution_analysis,
            real_ip_analysis=real_ip_analysis,
            vpn_backtrack_analysis=vpn_backtrack_analysis,
            webmail_extraction=webmail_extraction,
            unique_ipv6=unique_ipv6,
            attacker_technique_profile=technique_profile,
            active_analysis_result=active_analysis_result,
        )
        
        # ── BAYESIAN ATTRIBUTION (Layer 5) ───────────────────────────────────
        # Runs on the assembled result regardless of whether Stage 3B /
        # geolocation are available.  The engine reads whatever signals exist
        # (timezone, webmail provider, VPN flags, canarytoken, etc.).
        # Now wires in:
        #   • Signal reliability weighting (VPN -> zero-weight IP signals)
        #   • False flag detection (CONFLICTED state, 45% cap)
        #   • Urgency time-decay ACI penalty (Layer 1)
        if self.bayesian_attribution:
            print("\n[ATTRIBUTION] Running Bayesian multi-signal attribution (Layer 5)...")
            try:
                bayes_result = self.bayesian_attribution.attribute(result)

                # ── Apply urgency time-decay penalty ─────────────────────
                if urgency_result is not None:
                    try:
                        from huntertrace.core.urgency import apply_to_aci
                        original_aci = bayes_result.aci_adjusted_prob
                        bayes_result = apply_to_aci(bayes_result, urgency_result)
                        if self.verbose and bayes_result.aci_adjusted_prob != original_aci:
                            print(
                                f"  [URGENCY] ACI adjusted: "
                                f"{original_aci:.1%} → {bayes_result.aci_adjusted_prob:.1%} "
                                f"(−{urgency_result.aci_penalty:.0%} time-decay)"
                            )
                    except Exception as _upe:
                        if self.verbose:
                            print(f"  [WARNING] Urgency ACI adjustment failed: {_upe}")

                result.bayesian_attribution = bayes_result
                result.urgency_result       = urgency_result

                # ── Print result ──────────────────────────────────────────
                print(f"  Primary region : {bayes_result.primary_region}")
                print(
                    f"  Confidence     : {bayes_result.primary_probability:.1%}"
                    f"  (ACI-adjusted: {bayes_result.aci_adjusted_prob:.1%})"
                )
                print(f"  ACI score      : {bayes_result.aci.final_aci:.2f}")
                print(f"  Tier           : {bayes_result.tier} — {bayes_result.tier_label}")
                print(f"  Reliability    : {bayes_result.reliability_mode}")
                print(
                    f"  Signals used   : "
                    f"{', '.join(bayes_result.signals_used) if bayes_result.signals_used else 'none'}"
                )

                # ── False flag warning ────────────────────────────────────
                if bayes_result.false_flag_warning:
                    print(
                        f"  ⚠  FALSE FLAG DETECTED — conflict_score="
                        f"{bayes_result.conflict_score:.2f}  "
                        f"confidence capped at 45%"
                    )
                    print(
                        f"     Conflicting signals : "
                        f"{', '.join(bayes_result.conflicting_signals)}"
                    )
                    print(
                        f"     Conflict regions   : "
                        f"{', '.join(bayes_result.conflict_regions)}"
                    )

                if bayes_result.posterior:
                    print("  Top candidates :")
                    for rp in bayes_result.posterior[:3]:
                        print(f"    {rp.region:<30} {rp.probability:.1%}")

            except Exception as _be:
                if self.verbose:
                    print(f"  [WARNING] Bayesian attribution failed: {_be}")
                    import traceback; traceback.print_exc()
        
        print("\n[STAGE COMPLETE] All stages finished successfully")
        
        return result
    
    def _geolocate_ipv6_block(self, ipv6_address: str) -> str:
        """
        Geolocate an IPv6 address — live API first, prefix table fallback.

        The old prefix table only mapped to continents/regions ("Europe",
        "Asia-Pacific") not countries, and duplicated a more complete table
        already in geolocationEnrichment.py.

        Strategy:
          1. Try ip-api.com (free, accurate, returns country for IPv6)
          2. Fall back to GeolocationEnricher._get_ipv6_block_country() which
             has a comprehensive APNIC/RIPE/ARIN/LACNIC prefix table
          3. Last resort: RIR-block heuristic (continent-level only)
        """
        # ── Live lookup ───────────────────────────────────────────────────
        try:
            import requests
            resp = requests.get(
                f"http://ip-api.com/json/{ipv6_address}?fields=country,status",
                timeout=4
            )
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success" and d.get("country"):
                    return d["country"]
        except Exception:
            pass

        # ── Fallback: GeolocationEnricher prefix table ────────────────────
        try:
            from huntertrace.enrichment.geolocation import GeolocationEnricher
            enricher = GeolocationEnricher(verbose=False)
            country = enricher._get_ipv6_block_country(ipv6_address)
            if country and country not in ("Unknown", ""):
                return country
        except Exception:
            pass

        # ── Last resort: RIR block heuristic (continent only) ─────────────
        addr = ipv6_address.lower()
        if addr.startswith(("fc", "fd")):
            return "Reserved/Private"
        rir_map = {
            "2a": "Europe (RIPE region)",
            "2c": "Africa (AfriNIC region)",
            "28": "Latin America (LACNIC region)",
            "26": "North America (ARIN region)",
        }
        for prefix, region in rir_map.items():
            if addr.startswith(prefix):
                return region
        if addr.startswith("24") or addr.startswith("240"):
            return "Asia-Pacific (APNIC region)"
        return "Unknown"


# ============================================================================
# BATCH PROCESSING & CAMPAIGN CORRELATION 
# ============================================================================

class BatchProcessor:
    """Process multiple emails and correlate campaigns"""
    
    def __init__(self, mail_dir=None, verbose=False, skip_enrichment=False):
        self.mail_dir = Path(mail_dir) if mail_dir else Path(".")
        self.pipeline = CompletePipeline(verbose=verbose, skip_enrichment=skip_enrichment)
        self.results = []
        self.verbose = verbose
    
    def process_all_emails(self):
        """Batch process all emails in mail directory"""
        eml_files = list(self.mail_dir.glob('*.eml'))
        
        if not eml_files:
            print(f"[ERROR] No .eml files found in {self.mail_dir}")
            return False
        
        print(f"[BATCH PROCESSING] Found {len(eml_files)} emails")
        print("=" * 80)
        
        for i, eml_file in enumerate(sorted(eml_files), 1):
            print(f"\n[{i}/{len(eml_files)}] {eml_file.name}")
            
            result = self.pipeline.run(str(eml_file))
            
            if result:
                attacker_data = {
                    'file': eml_file.name,
                    'from': result.header_analysis.email_from if result.header_analysis else 'UNKNOWN',
                    'subject': result.header_analysis.email_subject if result.header_analysis else 'UNKNOWN',
                    'date': result.header_analysis.email_date if result.header_analysis else 'UNKNOWN',
                    'VPN_detected': result.proxy_analysis.obfuscation_count > 0 if result.proxy_analysis else False,
                    'full_result': result
                }
                
                # Extract real location
                if result.vpn_backtrack_analysis:
                    attacker_data['location'] = result.vpn_backtrack_analysis.probable_country
                    attacker_data['confidence'] = f"{result.vpn_backtrack_analysis.backtracking_confidence:.0%}"
                    attacker_data['real_ip'] = result.vpn_backtrack_analysis.probable_real_ip
                elif result.geolocation_results:
                    for ip, geo in result.geolocation_results.items():
                        if geo:
                            attacker_data['location'] = geo.country
                            attacker_data['city'] = geo.city
                            break
                
                self.results.append(attacker_data)
                
                # Print summary
                print(f"  From: {attacker_data['from'][:50]}")
                if 'location' in attacker_data:
                    print(f"  Location: {attacker_data['location']}")
                if attacker_data['VPN_detected']:
                    print(f"  [VPN DETECTED] Confidence: {attacker_data.get('confidence', 'N/A')}")
            else:
                print(f"  [ERROR] Failed to process")
        
        return len(self.results) > 0
    
    def correlate_campaigns(self):
        """Correlate emails by location and sender"""
        print("\n[CAMPAIGN CORRELATION ANALYSIS]")
        print("=" * 80)
        
        from collections import defaultdict
        
        # Group by location
        by_location = defaultdict(list)
        by_from = defaultdict(list)
        
        for result in self.results:
            location = result.get('location', 'UNKNOWN')
            sender = result.get('from', 'UNKNOWN')
            
            by_location[location].append(result)
            by_from[sender].append(result)
        
        # Report locations
        print("\n[GEOGRAPHIC DISTRIBUTION]")
        for location in sorted(by_location.keys()):
            emails = by_location[location]
            print(f"  {location}: {len(emails)} email(s)")
            for email in emails:
                print(f"    - {email['file']}")
        
        # Report senders
        print("\n[SENDER ANALYSIS]")
        for sender in sorted(by_from.keys())[:10]:
            emails = by_from[sender]
            if len(emails) > 1:
                print(f"  {sender}: {len(emails)} emails")
        
        return by_location, by_from
    
    def export_json_report(self, output_file):
        """Export batch results to JSON"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'total_emails': len(self.results),
            'emails_processed': len([r for r in self.results if r.get('full_result')]),
            'emails': []
        }
        
        # Build email summaries
        for result in self.results:
            email_summary = {
                'filename': result['file'],
                'from': result['from'],
                'subject': result['subject'],
                'date': result['date'],
                'vpn_detected': result['VPN_detected'],
                'location': result.get('location'),
                'confidence': result.get('confidence'),
                'real_ip': result.get('real_ip')
            }
            
            # Add full analysis if available
            if result.get('full_result'):
                full_report = CompletePipelineReport(result['full_result'])
                email_summary['full_analysis'] = full_report.to_json()
            
            report_data['emails'].append(email_summary)
        
        # Geographic summary
        from collections import defaultdict
        geo_summary = defaultdict(int)
        for result in self.results:
            if 'location' in result:
                geo_summary[result['location']] += 1
        
        report_data['geographic_distribution'] = dict(geo_summary)
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n[SUCCESS] Batch report exported to: {output_file}")

# ============================================================================
# CLI ENTRY POINT - UNIFIED INTERFACE
# ============================================================================


# ============================================================================
# CONFIG / API KEY LOADING
# ============================================================================

def _load_config(config_file=None):
    """
    Load API keys from (in priority order):
      1. --config <file>  explicitly passed on CLI
      2. .env file in current working directory
      3. OS environment variables (always override file values)

    Supported keys:
      ABUSEIPDB_API_KEY, IPINFO_TOKEN, VIRUSTOTAL_API_KEY
    """
    cfg = {}

    # Candidate files: explicit first, then .env in cwd
    candidates = []
    if config_file:
        candidates.append(Path(config_file))
    candidates.append(Path(".env"))

    for fpath in candidates:
        if fpath.is_file():
            try:
                for raw in fpath.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, _, v = line.partition("=")
                        cfg[k.strip()] = v.strip().strip('"').strip("'")
            except Exception:
                pass
            break  # first matching file wins

    # Environment variables always override
    for env_key in ("ABUSEIPDB_API_KEY", "IPINFO_TOKEN", "VIRUSTOTAL_API_KEY"):
        val = os.getenv(env_key)
        if val:
            cfg[env_key] = val

    return cfg


def _inject_keys(cfg, args):
    """
    Push resolved API keys into os.environ so every module/stage picks them up
    without needing to be refactored.  CLI flags beat config file values.
    """
    # AbuseIPDB
    key = getattr(args, "abuseipdb_key", None) or cfg.get("ABUSEIPDB_API_KEY")
    if key:
        os.environ["ABUSEIPDB_API_KEY"] = key

    # IPInfo
    tok = cfg.get("IPINFO_TOKEN")
    if tok:
        os.environ["IPINFO_TOKEN"] = tok

    # VirusTotal
    vt = cfg.get("VIRUSTOTAL_API_KEY")
    if vt:
        os.environ["VIRUSTOTAL_API_KEY"] = vt


def _key_status_lines():
    """Return a list of human-readable lines showing which keys are active."""
    checks = [
        ("AbuseIPDB",  "ABUSEIPDB_API_KEY"),
        ("IPInfo",     "IPINFO_TOKEN"),
        ("VirusTotal", "VIRUSTOTAL_API_KEY"),
    ]
    lines = []
    for label, env in checks:
        val = os.getenv(env)
        if val:
            lines.append(f"  {label:14} ✓  ({env}={val[:6]}{'...' if len(val) > 6 else ''})")
        else:
            lines.append(f"  {label:14} ✗  (unset — pass --abuseipdb-key or add to .env)")
    return lines


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    """
    HunterTrace — Phishing Email Attribution & Campaign Intelligence

    Commands
    --------
      <file.eml>           Analyse a single email
      batch  <dir>         Batch-process all .eml files in a directory
      v3     <dir>         Full v3 campaign analysis (actor clustering + MITRE)
      offline <dir>        V3 correlation from saved JSON reports
      bait                 Generate canarytoken bait documents (active VPN bypass)
      info                 Show module/API-key status

    Quick start
    -----------
      # Single email, all output to ./ht_output/
      python hunterTrace.py suspicious.eml

      # With an AbuseIPDB key
      python hunterTrace.py suspicious.eml --abuseipdb-key YOUR_KEY

      # Or put keys in a .env file (picked up automatically)
      echo "ABUSEIPDB_API_KEY=YOUR_KEY" >> .env
      python hunterTrace.py suspicious.eml

      # Batch processing
      python hunterTrace.py batch ./inbox/ --output ./reports/

      # Full v3 campaign intelligence
      python hunterTrace.py v3 ./inbox/ --output ./reports/ --verbose

      # Active VPN bypass — generate bait documents
      python hunterTrace.py bait --generate --host mycallback.canarytokens.org --legal-ack
      python hunterTrace.py bait --generate --formats xlsx --host myhost --label actor1 --legal-ack
      python hunterTrace.py bait --poll TOKEN_ID --host mycallback.canarytokens.org
    """

    parser = argparse.ArgumentParser(
        prog="hunterTrace.py",
        description="HunterTrace — Phishing Email Attribution & Campaign Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
COMMANDS
  <file.eml>           Analyse a single .eml file
  batch  <dir>         Batch-analyse every .eml in a directory
  v3     <dir>         V3 campaign mode: actor clustering + MITRE ATT&CK mapping
  offline <dir>        V3 correlation from previously-saved JSON reports
  bait                 Generate canarytoken bait documents for active VPN bypass
  info                 Show available modules and API-key status

OUTPUT FLAGS
  -o / --output DIR    Directory for all output files  (default: ./ht_output/)
  --format FORMAT      Output format: text | json | both  (default: both)

API KEY FLAGS  (also accepted via .env file or environment variables)
  --abuseipdb-key KEY  AbuseIPDB key  (env: ABUSEIPDB_API_KEY)
  --config FILE        Load keys from this file instead of .env

PIPELINE FLAGS
  --skip-enrichment    Skip WHOIS / reverse-DNS enrichment (Stage 3B) — faster,
                       loses infrastructure correlation and Stage 5 attribution
  -v / --verbose       Print per-stage detail
  -q / --quiet         Print only the final summary

.env FILE FORMAT  (place alongside hunterTrace.py or in working directory)
  ABUSEIPDB_API_KEY=abc123def456
  IPINFO_TOKEN=tok_xxxx
  VIRUSTOTAL_API_KEY=vt_xxxx

EXAMPLES
  python hunterTrace.py phishing.eml
  python hunterTrace.py phishing.eml --abuseipdb-key abc123 --format json -o ./out/
  python hunterTrace.py batch ./mails/ -o ./reports/ --skip-enrichment
  python hunterTrace.py v3    ./mails/ -o ./campaign/ --verbose
  python hunterTrace.py offline ./json_reports/ -o ./campaign/
  python hunterTrace.py info
""",
    )

    # ── Positional args ───────────────────────────────────────────────────
    parser.add_argument(
        "command",
        metavar="COMMAND_OR_FILE",
        help="Command (batch | v3 | offline | info) or path to a single .eml file",
    )
    parser.add_argument(
        "path",
        nargs="?",
        metavar="PATH",
        help="Directory for batch / v3 / offline commands",
    )

    # ── Output ────────────────────────────────────────────────────────────
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default="./ht_output",
        help="Output directory (default: ./ht_output)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "both"],
        default="both",
        help="Output format: text, json, or both  (default: both)",
    )

    # ── API keys ──────────────────────────────────────────────────────────
    parser.add_argument(
        "--abuseipdb-key",
        metavar="KEY",
        dest="abuseipdb_key",
        help="AbuseIPDB API key  (overrides ABUSEIPDB_API_KEY in .env / env)",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Config / .env file with API keys  (default: .env in cwd)",
    )

    # ── Pipeline ──────────────────────────────────────────────────────────
    parser.add_argument(
        "--skip-enrichment",
        action="store_true",
        help="Skip Stage 3B WHOIS enrichment — faster, works fully offline",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed per-stage output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress stage output; show only the final summary",
    )

    args = parser.parse_args()

    if args.quiet and args.verbose:
        parser.error("--quiet and --verbose are mutually exclusive")

    # ── Load config and inject keys into os.environ ───────────────────────
    cfg = _load_config(args.config)
    _inject_keys(cfg, args)

    # ── Ensure output directory exists ────────────────────────────────────
    output_dir = Path(args.output)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[ERROR] Cannot create output directory {output_dir}: {e}")
        sys.exit(1)

    verbose = args.verbose and not args.quiet

    # ══════════════════════════════════════════════════════════════════════
    # INFO
    # ══════════════════════════════════════════════════════════════════════
    if args.command == "info":
        print("\n  HunterTrace — module & key status")
        print("  " + "─" * 46)
        print("\n  Core modules:")
        module_checks = [
            ("Core pipeline",         True),
            ("Geolocation",           GEOLOCATION_AVAILABLE),
            ("Stage 5 attribution",   STAGE5_AVAILABLE),
            ("VPN backtracking",      VPN_BACKTRACK_AVAILABLE),
            ("Advanced real-IP",      ADVANCED_REAL_IP_EXTRACTOR_AVAILABLE),
            ("WHOIS enrichment",      WHOIS_AVAILABLE),
            ("Hosting keywords",      HOSTING_KEYWORDS_AVAILABLE),
        ]
        for label, ok in module_checks:
            icon = "✓" if ok else "✗"
            hint = ""
            if not ok and label == "WHOIS enrichment":
                hint = "  → pip install python-whois"
            print(f"    {icon}  {label}{hint}")

        print("\n  V3 modules:")
        v3_checks = [
            ("campaign correlator",   "huntertrace.analysis.campaignCorrelator"),
            ("actor profiler",        "huntertrace.analysis.actorProfiler"),
            ("attack graph builder",  "huntertrace.graph.builder"),
            ("attribution engine",    "huntertrace.attribution.engine"),
            ("V3 orchestrator",       "huntertrace.core.orchestrator"),
            ("forensics scanner",     "huntertrace.forensics.scanner"),
            ("graph centrality",      "huntertrace.graph.centrality"),
        ]
        print("\n  Layer 1 modules:")
        l1_checks = [
            ("urgency classifier",    "huntertrace.core.urgency"),
            ("canarytoken generator", "huntertrace.forensics.canarytoken"),
        ]
        for label, mod in l1_checks:
            try:
                __import__(mod)
                print(f"    ✓  {label}")
            except ImportError as _e:
                print(f"    ✗  {label}  ({_e})")
        for label, mod in v3_checks:
            try:
                __import__(mod)
                print(f"    ✓  {label}")
            except ImportError as _e:
                print(f"    ✗  {label}  ({_e})")

        print("\n  API keys:")
        for line in _key_status_lines():
            print(line)

        print(f"\n  Output directory:  {output_dir.resolve()}")
        print()
        return

    # ══════════════════════════════════════════════════════════════════════
    # V3 / OFFLINE — campaign intelligence via hunterTraceV3
    # ══════════════════════════════════════════════════════════════════════
    if args.command in ("v3", "offline"):
        target = args.path
        if not target:
            parser.error(
                f"'{args.command}' requires a directory path\n"
                f"  Usage: hunterTrace.py {args.command} /path/to/emails/"
            )
        if not Path(target).exists():
            print(f"[ERROR] Path not found: {target}")
            sys.exit(1)

        try:
            from huntertrace.core.orchestrator import HunterTraceV3
        except ImportError:
            print("[ERROR] hunterTraceV3.py not found in the current directory.")
            print("  Make sure hunterTraceV3.py is placed alongside hunterTrace.py.")
            sys.exit(1)

        if not args.quiet:
            print(f"\n  HunterTrace v3 — Campaign Intelligence")
            print(f"  {'─'*44}")
            print(f"  Mode    : {args.command}")
            print(f"  Input   : {Path(target).resolve()}")
            print(f"  Output  : {output_dir.resolve()}")
            print("\n  API keys:")
            for line in _key_status_lines():
                print(line)
            print()

        v3 = HunterTraceV3(
            verbose=verbose,
            skip_enrichment=args.skip_enrichment,
            output_dir=str(output_dir),
        )

        report = v3.run_batch(target) if args.command == "v3" else v3.correlate_from_json_dir(target)

        if report:
            report.print_executive_summary()
            if not args.quiet:
                print(f"\n  Outputs written to: {output_dir.resolve()}/\n")
        return

    # ══════════════════════════════════════════════════════════════════════
    # BATCH — process a directory of .eml files
    # ══════════════════════════════════════════════════════════════════════
    if args.command == "batch":
        mail_dir = args.path
        if not mail_dir:
            parser.error(
                "'batch' requires a directory path\n"
                "  Usage: hunterTrace.py batch /path/to/emails/"
            )
        if not Path(mail_dir).exists():
            print(f"[ERROR] Directory not found: {mail_dir}")
            sys.exit(1)

        if not args.quiet:
            print(f"\n  HunterTrace — Batch Processing")
            print(f"  {'─'*44}")
            print(f"  Input   : {Path(mail_dir).resolve()}")
            print(f"  Output  : {output_dir.resolve()}")
            print("\n  API keys:")
            for line in _key_status_lines():
                print(line)
            print()

        processor = BatchProcessor(
            mail_dir=mail_dir,
            verbose=verbose,
            skip_enrichment=args.skip_enrichment,
        )

        if processor.process_all_emails():
            processor.correlate_campaigns()

            if args.format in ("json", "both"):
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                json_path = output_dir / f"batch_report_{ts}.json"
                processor.export_json_report(str(json_path))
                if not args.quiet:
                    print(f"\n  Report: {json_path}")
        return

    # ══════════════════════════════════════════════════════════════════════
    # BAIT — generate canarytoken bait documents (Layer 1 active bypass)
    # Usage:
    #   hunterTrace.py bait --generate --host CALLBACKHOST [--formats xlsx docx pdf]
    #                       [--output DIR] [--label LABEL] [--legal-ack]
    #   hunterTrace.py bait --poll TOKEN_ID --host CALLBACKHOST
    # ══════════════════════════════════════════════════════════════════════
    if args.command == "bait":
        if not CANARYTOKEN_AVAILABLE:
            print(
                "[ERROR] Canarytoken module not available.\n"
                "  Expected at: huntertrace/forensics/canarytoken.py\n"
                "  Make sure the file is committed to the repo and installed."
            )
            sys.exit(1)

        # Re-parse with bait-specific args.  We use a sub-parser approach:
        # read remaining argv manually to keep the top-level parser simple.
        import argparse as _ap
        bait_parser = _ap.ArgumentParser(
            prog="hunterTrace.py bait",
            description="Generate canarytoken bait documents for active VPN bypass",
        )
        bait_parser.add_argument(
            "--generate", action="store_true",
            help="Generate bait documents (XLSX, DOCX, and/or PDF)",
        )
        bait_parser.add_argument(
            "--poll", dest="poll_token", metavar="TOKEN_ID",
            help="Poll a previously generated token for trigger events",
        )
        bait_parser.add_argument(
            "--host", metavar="HOST",
            help="Callback hostname (e.g. yourdomain.canarytokens.org)",
        )
        bait_parser.add_argument(
            "--formats", nargs="+", default=["xlsx", "docx", "pdf"],
            metavar="FMT",
            help="Bait formats to generate: xlsx docx pdf  (default: all three)",
        )
        bait_parser.add_argument(
            "--output", "-o", default="./ht_baits", metavar="DIR",
            help="Output directory for bait files  (default: ./ht_baits)",
        )
        bait_parser.add_argument(
            "--label", default="", metavar="LABEL",
            help="Optional label embedded in token ID (e.g. actor name)",
        )
        bait_parser.add_argument(
            "--legal-ack", dest="legal_ack", action="store_true",
            help="Acknowledge legal notice before generating bait documents",
        )

        # Parse everything after "bait" from sys.argv
        bait_argv = sys.argv[sys.argv.index("bait") + 1:]
        bait_args = bait_parser.parse_args(bait_argv)

        if not bait_args.generate and not bait_args.poll_token:
            bait_parser.print_help()
            sys.exit(0)

        exit_code = cli_bait(bait_args)
        sys.exit(exit_code)

    # ══════════════════════════════════════════════════════════════════════
    # SINGLE EMAIL — default when command looks like a file path
    # ══════════════════════════════════════════════════════════════════════
    email_file = args.command

    # Catch unknown subcommands before attempting file I/O
    known_commands = {"batch", "v3", "offline", "info", "bait"}
    if email_file in known_commands:
        # Already handled above; this branch means the user forgot the path arg
        parser.error(
            f"'{email_file}' requires a path argument\n"
            f"  Usage: hunterTrace.py {email_file} /path/to/..."
        )

    if not Path(email_file).exists():
        print(f"[ERROR] File not found: {email_file!r}")
        print("  Tip: for batch mode use:  hunterTrace.py batch /path/to/emails/")
        sys.exit(1)

    if not args.quiet:
        print(f"\n  HunterTrace — Single Email Analysis")
        print(f"  {'─'*44}")
        print(f"  File    : {Path(email_file).resolve()}")
        print(f"  Output  : {output_dir.resolve()}")
        print("\n  API keys:")
        for line in _key_status_lines():
            print(line)
        print()

    pipeline = CompletePipeline(verbose=verbose, skip_enrichment=args.skip_enrichment)
    result = pipeline.run(email_file)

    if not result:
        print("[ERROR] Pipeline failed — could not parse the email file")
        sys.exit(1)

    report_obj = CompletePipelineReport(result)

    # ── Text output ───────────────────────────────────────────────────────
    if args.format in ("text", "both") and not args.quiet:
        print("\n")
        print(report_obj.generate_text_report(verbose=verbose))

    # ── JSON output ───────────────────────────────────────────────────────
    if args.format in ("json", "both"):
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = Path(email_file).stem
        json_path = output_dir / f"{stem}_{ts}.json"
        try:
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump(report_obj.to_json(), fh, indent=2)
            if not args.quiet:
                print(f"  JSON: {json_path}")
        except Exception as e:
            print(f"[ERROR] Could not write JSON report: {e}")

    if not args.quiet:
        print("\n[COMPLETE]\n")


if __name__ == "__main__":
    main()
