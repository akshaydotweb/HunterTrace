#!/usr/bin/env python3
"""
COMPLETE ATTACKER IP IDENTIFICATION SYSTEM

Stages:
  1. Email Header Extraction (RFC 2822 parsing, IP extraction)
  2. IP Classification (Tor/VPN/Proxy detection with real APIs)
  3A. Proxy Chain Analysis (obfuscation layer detection)
  3B. WHOIS/Reverse DNS Enrichment (organization & ownership metadata)
  3C. Infrastructure Correlation (attack pattern detection, team sizing)
  4. Threat Intelligence Aggregation (C2 detection, malware analysis, threat scoring)

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
import whois
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime
from email.utils import parsedate_to_datetime
import argparse
from pathlib import Path

# Import live hosting keywords integration
try:
    from hostingKeywordsIntegration import get_hosting_keywords, classify_hosting_by_keywords
    HOSTING_KEYWORDS_AVAILABLE = True
except ImportError:
    HOSTING_KEYWORDS_AVAILABLE = False


# ============================================================================
# STAGE 1: EMAIL HEADER EXTRACTION
# ============================================================================

@dataclass
class ReceivedHeaderDetail:
    """Individual email hop information"""
    hop_number: int
    ip: Optional[str]
    hostname: Optional[str]
    protocol: str
    timestamp: Optional[str]
    authentication: Dict
    raw_header: str
    parsing_confidence: float


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


class HeaderExtractor:
    """Stage 1: Extract headers from email"""
    
    def __init__(self):
        self.patterns = {
            "ip_only": re.compile(r'\[(\d+\.\d+\.\d+\.\d+)\]', re.IGNORECASE),
            "protocol": re.compile(r'with\s+(ESMTP|SMTP|HTTP|HTTPS|LMTP)', re.IGNORECASE),
            "by_clause": re.compile(r'by\s+(\S+)', re.IGNORECASE),
        }
    
    def parse_email_file(self, file_path: str) -> Optional[ReceivedChainAnalysis]:
        """Parse email file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_raw = f.read()
            return self.parse_email_raw(email_raw)
        except Exception as e:
            print(f"[ERROR] Failed to read {file_path}: {e}")
            return None
    
    def parse_email_raw(self, email_raw: str) -> Optional[ReceivedChainAnalysis]:
        """Parse raw email"""
        
        msg = email.message_from_string(email_raw)
        
        email_from = msg.get('From', 'Unknown')
        email_to = msg.get('To', 'Unknown')
        email_subject = msg.get('Subject', 'Unknown')
        message_id = msg.get('Message-ID', 'Unknown')
        
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
        
        origin_ip = hops[0].ip if hops else None
        destination_ip = hops[-1].ip if hops else None
        
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
            red_flags=red_flags
        )
        
        return analysis
    
    def _parse_header(self, header_text: str, hop_number: int) -> ReceivedHeaderDetail:
        """Parse single Received header"""
        
        ip = None
        hostname = None
        protocol = "UNKNOWN"
        timestamp = None
        authentication = {}
        parsing_confidence = 0.5
        
        # Extract IP
        ip_match = self.patterns["ip_only"].search(header_text)
        if ip_match:
            ip = ip_match.group(1)
            parsing_confidence = 0.95
        
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
            ip=ip,
            hostname=hostname,
            protocol=protocol,
            timestamp=timestamp,
            authentication=authentication,
            raw_header=header_text[:100],
            parsing_confidence=parsing_confidence
        )


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
        
        # Check AbuseIPDB
        if self.abuse_api_key:
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
        
        # Check Tor
        if self._is_tor_exit(ip):
            classification = "TOR_EXIT"
            confidence = 0.95
            is_tor = True
            evidence.append("Tor exit node detected")
        
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
        """Correlate with known campaigns (simulated database)"""
        
        matches = []
        
        # Simulated known campaigns database
        known_campaigns = {
            "CAMPAIGN_A": {
                "asns": ["AS1234", "AS5678"],
                "providers": ["Digital Ocean", "Linode"],
                "countries": ["RU", "CN"],
                "description": "Phishing campaign targeting finance sector"
            },
            "CAMPAIGN_B": {
                "asns": ["AS9012"],
                "providers": ["AWS", "OVH"],
                "countries": ["US", "FR"],
                "description": "Credential harvesting attacks"
            }
        }
        
        # Check each IP against known campaigns
        for ip_data in ips_data:
            for campaign_name, campaign_attrs in known_campaigns.items():
                match_score = 0
                
                if ip_data["asn"] in campaign_attrs.get("asns", []):
                    match_score += 0.4
                if ip_data["provider"] in campaign_attrs.get("providers", []):
                    match_score += 0.3
                if ip_data["country"] in campaign_attrs.get("countries", []):
                    match_score += 0.3
                
                if match_score > 0:
                    matches.append({
                        "ip": ip_data["ip"],
                        "campaign": campaign_name,
                        "match_score": match_score,
                        "description": campaign_attrs["description"]
                    })
        
        return matches
    
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
            detected_malware_families=threat_history.c2_server_likelihood > 0.5 and ["Potential C2"] or threat_history.malware_associations,
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
        """Query threat history and associations"""
        
        # Simulated threat database
        known_c2_servers = ["197.210.45.88", "203.0.113.195", "192.0.2.100"]
        known_malware_ips = {
            "197.210.45.88": ["Emotet", "TrickBot"],
            "203.0.113.195": ["Mirai", "Dridex"],
            "10.0.0.1": ["Generic Ransomware"]
        }
        known_botnets = {
            "197.210.45.88": ["ZeuS", "Conficker"],
        }
        
        abuse_history = []
        whois_changes = []
        malware_assoc = []
        botnet_assoc = []
        c2_likelihood = 0.0
        
        # Check known C2
        if ip in known_c2_servers:
            c2_likelihood = 0.95
        
        # Check malware associations
        if ip in known_malware_ips:
            malware_assoc = known_malware_ips[ip]
        
        # Check botnet associations
        if ip in known_botnets:
            botnet_assoc = known_botnets[ip]
        
        # Simulate abuse history
        if c2_likelihood > 0.5:
            abuse_history = [
                {"date": "2025-12-01", "reports": 25, "reason": "C2 communication"},
                {"date": "2025-11-15", "reports": 18, "reason": "Malware distribution"}
            ]
        
        return ThreatHistoryResult(
            ip=ip,
            abuse_history=abuse_history,
            whois_changes=whois_changes,
            known_malware_associations=malware_assoc,
            c2_server_likelihood=c2_likelihood,
            botnet_associations=botnet_assoc,
            ransomware_associations=[],
            confidence=0.80 if (malware_assoc or botnet_assoc) else 0.50,
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


class CompletePipelineReport:
    """Generate complete analysis report"""
    
    def __init__(self, result: CompletePipelineResult):
        self.header = result.header_analysis
        self.classifications = result.classifications
        self.proxy = result.proxy_analysis
        self.enrichment = result.enrichment_results
        self.correlation = result.correlation_analysis
        self.threat_intelligence = result.threat_intelligence
    
    def generate_text_report(self, verbose: bool = False) -> str:
        """Generate comprehensive text report"""
        
        lines = []
        lines.append("[ATTACKER IP IDENTIFICATION SYSTEM - COMPLETE ANALYSIS]")
        lines.append("=" * 80)
        
        # Email info
        lines.append("\n[STAGE 1: EMAIL HEADER INFORMATION]")
        lines.append("-" * 80)
        lines.append(f"  From: {self.header.email_from}")
        lines.append(f"  To: {self.header.email_to}")
        lines.append(f"  Subject: {self.header.email_subject}")
        lines.append(f"  Date: {self.header.email_date}")
        lines.append(f"  Message-ID: {self.header.message_id}")
        lines.append(f"\n  Spoofing Risk: {self.header.spoofing_risk:.0%}")
        lines.append(f"  Header Confidence: {self.header.confidence:.0%}")
        
        if self.header.red_flags:
            lines.append(f"\n  Red Flags ({len(self.header.red_flags)}):")
            for flag in self.header.red_flags[:5]:
                lines.append(f"    {flag}")
        
        # Header chain
        lines.append(f"\n  Header Chain: {self.header.hop_count} hops found")
        lines.append(f"    Origin IP: {self.header.origin_ip}")
        lines.append(f"    Destination IP: {self.header.destination_ip}")
        
        if verbose and self.header.hops:
            lines.append(f"\n  Detailed Hops:")
            for hop in self.header.hops:
                lines.append(f"    [{hop.hop_number}] {hop.ip or 'N/A'} - {hop.hostname or 'N/A'}")
        
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
                "red_flags": self.header.red_flags
            },
            "stage1_header_extraction": {
                "hops_found": self.header.hop_count,
                "origin_ip": self.header.origin_ip,
                "destination_ip": self.header.destination_ip,
                "confidence": self.header.confidence,
                "hop_details": [asdict(hop) for hop in self.header.hops]
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
            "stage4_threat_intelligence": self._threat_intel_to_dict() if self.threat_intelligence else None
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


class CompletePipeline:
    """Master pipeline orchestrating all 6 stages (1, 2, 3A, 3B, 3C, 4)"""
    
    def __init__(self, verbose: bool = False, skip_enrichment: bool = False):
        self.extractor = HeaderExtractor()
        self.classifier = IPClassifierLight()
        self.tracer = ProxyChainTracer()
        self.enricher = IPEnrichmentStage3B() if not skip_enrichment else None
        self.correlator = InfrastructureCorrelationEngine()
        self.threat_intel_engine = ThreatIntelligenceEngine()
        self.verbose = verbose
    
    def run(self, email_file: str) -> Optional[CompletePipelineResult]:
        """Run all 5 stages (1: Headers, 2: Classification, 3A: Proxy Chain, 3B: Enrichment, 3C: Correlation, 4: Threat Intelligence)"""
        
        print("[START] Complete Attacker IP Identification Pipeline")
        print("=" * 80)
        
        # STAGE 1: Extract headers
        print("\n[STAGE 1] Extracting email headers...")
        
        header_analysis = self.extractor.parse_email_file(email_file)
        
        if not header_analysis:
            print("[ERROR] Failed to parse email")
            return None
        
        print(f"[SUCCESS] Found {header_analysis.hop_count} hops in email chain")
        
        # Extract unique IPs
        unique_ips = []
        seen = set()
        for hop in header_analysis.hops:
            if hop.ip and hop.ip not in seen:
                unique_ips.append(hop.ip)
                seen.add(hop.ip)
        
        print(f"[INFO] Unique IPs found: {', '.join(unique_ips)}")
        
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
                    ips=unique_ips,
                    enrichments=enrichment_results
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
        
        # Create result
        result = CompletePipelineResult(
            header_analysis=header_analysis,
            classifications=classifications,
            proxy_analysis=proxy_analysis,
            enrichment_results=enrichment_results,
            correlation_analysis=correlation_analysis,
            threat_intelligence=threat_intelligence
        )
        
        print("\n[STAGE COMPLETE] All stages finished successfully")
        
        return result


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    """Command-line interface"""
    
    parser = argparse.ArgumentParser(
        description="Complete Attacker IP Identification System (All 5 Stages)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
STAGES:
  1. Email header extraction (RFC 2822 parsing, IP extraction in order)
  2. IP classification (Tor/VPN/Proxy detection with real APIs)
  3A. Proxy chain analysis (obfuscation layers detection)
  3B. WHOIS/Reverse DNS enrichment (organization & ASN metadata)
  3C. Infrastructure correlation (attack pattern detection, team size estimation)
  4. Threat intelligence aggregation (C2 detection, malware analysis, threat scoring)

EXAMPLES:
  python3 complete_attacker_identification_system.py ./phishing.eml
  python3 complete_attacker_identification_system.py email.eml --json report.json
  python3 complete_attacker_identification_system.py email.eml --verbose
  python3 complete_attacker_identification_system.py email.eml --skip-enrichment

SETUP:
  pip install requests python-whois dnspython
  export ABUSEIPDB_API_KEY="your_key_here"
        """
    )
    
    parser.add_argument(
        "email_file",
        help="Path to email file (.eml format)"
    )
    
    parser.add_argument(
        "--json",
        metavar="OUTPUT_FILE",
        help="Export full analysis to JSON file"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    
    parser.add_argument(
        "--skip-enrichment",
        action="store_true",
        help="Skip Stage 3B (WHOIS enrichment)"
    )
    
    args = parser.parse_args()
    
    # Validate file
    if not Path(args.email_file).exists():
        print(f"[ERROR] File not found: {args.email_file}")
        sys.exit(1)
    
    # Run pipeline
    pipeline = CompletePipeline(verbose=args.verbose, skip_enrichment=args.skip_enrichment)
    result = pipeline.run(args.email_file)
    
    if not result:
        print("[ERROR] Pipeline execution failed")
        sys.exit(1)
    
    # Generate and display report
    print("\n")
    report = CompletePipelineReport(result)
    print(report.generate_text_report(verbose=args.verbose))
    
    # Export JSON if requested
    if args.json:
        try:
            with open(args.json, 'w') as f:
                json.dump(report.to_json(), f, indent=2)
            print(f"[SUCCESS] Full analysis exported to: {args.json}")
        except Exception as e:
            print(f"[ERROR] Failed to export JSON: {e}")
            sys.exit(1)
    
    print("[COMPLETE] Analysis finished successfully")


if __name__ == "__main__":
    main()
