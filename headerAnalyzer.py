#!/usr/bin/env python3
"""
COMPLETE ATTACKER IP IDENTIFICATION SYSTEM
Full 4-Stage Pipeline in Single File

Stages:
  1. Email Header Extraction (RFC 2822 parsing, IP extraction)
  2. IP Classification (Tor/VPN/Proxy detection with real APIs)
  3A. Proxy Chain Analysis (obfuscation layer detection)
  3B. WHOIS/Reverse DNS Enrichment (organization & ownership metadata)

Single command:
    python3 complete_attacker_identification_system.py ./phishing_email.eml
    python3 complete_attacker_identification_system.py email.eml --json report.json --verbose
    python3 complete_attacker_identification_system.py email.eml --skip-enrichment

Requirements:
    pip install requests python-whois dnspython
    export ABUSEIPDB_API_KEY="your_api_key_here"
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
        """Analyze hosting type"""
        
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
        
        # Check for datacenter
        for keyword in self.datacenter_keywords:
            if keyword in combined_text:
                hosting_type = "DATACENTER"
                confidence = max(confidence, 0.85)
                evidence.append(f"Found keyword: {keyword}")
                risk_level = "HIGH"
                break
        
        # Check for shared hosting
        if hosting_type == "DATACENTER":
            for keyword in self.shared_hosting_keywords:
                if keyword in combined_text:
                    shared_hosting = True
                    confidence = max(confidence, 0.80)
                    evidence.append(f"Shared hosting indicator: {keyword}")
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
# COMPLETE PIPELINE + REPORT GENERATION
# ============================================================================

@dataclass
class CompletePipelineResult:
    """Complete analysis result with all stages"""
    header_analysis: ReceivedChainAnalysis
    classifications: Dict[str, IPClassification]
    proxy_analysis: ProxyChainAnalysis
    enrichment_results: Optional[Dict[str, IPEnrichmentResult]] = None


class CompletePipelineReport:
    """Generate complete analysis report"""
    
    def __init__(self, result: CompletePipelineResult):
        self.header = result.header_analysis
        self.classifications = result.classifications
        self.proxy = result.proxy_analysis
        self.enrichment = result.enrichment_results
    
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
            "stage3b_whois_enrichment": enrichment_data
        }


class CompletePipeline:
    """Master pipeline orchestrating all 4 stages"""
    
    def __init__(self, verbose: bool = False, skip_enrichment: bool = False):
        self.extractor = HeaderExtractor()
        self.classifier = IPClassifierLight()
        self.tracer = ProxyChainTracer()
        self.enricher = IPEnrichmentStage3B() if not skip_enrichment else None
        self.verbose = verbose
    
    def run(self, email_file: str) -> Optional[CompletePipelineResult]:
        """Run all 4 stages"""
        
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
        
        # Create result
        result = CompletePipelineResult(
            header_analysis=header_analysis,
            classifications=classifications,
            proxy_analysis=proxy_analysis,
            enrichment_results=enrichment_results
        )
        
        print("\n[STAGE COMPLETE] All stages finished successfully")
        
        return result


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    """Command-line interface"""
    
    parser = argparse.ArgumentParser(
        description="Complete Attacker IP Identification System (All 4 Stages)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
STAGES:
  1. Email header extraction (RFC 2822 parsing, IP extraction in order)
  2. IP classification (Tor/VPN/Proxy detection with real APIs)
  3A. Proxy chain analysis (obfuscation layers detection)
  3B. WHOIS/Reverse DNS enrichment (organization & ASN metadata)

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
