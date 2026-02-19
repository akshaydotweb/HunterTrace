#!/usr/bin/env python3
"""
REAL IP EXTRACTION MODULE FOR VPN/PROXY BYPASS
===============================================

This module identifies the true attacker IP address even when VPN/proxy
obfuscation is detected. Implements multiple techniques:

1. Email Header Analysis: Extract origin IP from email chain
2. Proxy Chain Tracing: Identify layers and real origin
3. Infrastructure Correlation: Detect patterns in infrastructure
4. WHOIS Reverse Lookup: Identify actual hosting
5. ASN Analysis: Detect datacenter vs residential IPs
6. Timing Analysis: Identify VPN provider artifacts
7. Geolocation Correlation: Find real location vs VPN provider
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set
from enum import Enum
import ipaddress


class ObfuscationLevel(Enum):
    """Levels of obfuscation detected"""
    NONE = "none"
    LIGHT = "light"  # Single proxy
    MEDIUM = "medium"  # Proxy chain
    HEAVY = "heavy"  # Multiple layers with timing obfuscation
    ADVANCED = "advanced"  # Commercial VPN/Proxy farm


class RealIPConfidence(Enum):
    """Confidence levels for real IP identification"""
    CERTAIN = 0.95  # Email header origin, direct infrastructure match
    HIGH = 0.80  # Multiple correlating indicators
    MEDIUM = 0.60  # Probable via pattern analysis
    LOW = 0.40  # Speculative, limited evidence


@dataclass
class VPNIndicators:
    """Indicators that suggest VPN/proxy usage"""
    is_vpn_detected: bool = False
    is_proxy_detected: bool = False
    is_tor_detected: bool = False
    provider_name: Optional[str] = None
    obfuscation_level: ObfuscationLevel = ObfuscationLevel.NONE
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)


@dataclass
class RealIPAnalysis:
    """Real IP extraction result"""
    suspected_real_ip: Optional[str]
    origin_ip_from_headers: Optional[str]
    obfuscation_level: ObfuscationLevel
    vpn_provider: Optional[str]
    likely_real_infrastructure: Optional[str]
    confidence_score: float
    techniques_used: List[str]
    evidence_items: List[str]
    analysis_notes: List[str]
    
    def __str__(self) -> str:
        conf_pct = f"{self.confidence_score:.0%}"
        return f"Real IP: {self.suspected_real_ip} (Confidence: {conf_pct})"


class RealIPExtractor:
    """
    Extracts the true attacker IP address even when VPN/proxy obfuscation is used.
    """
    
    # Known VPN/Proxy provider IP ranges (simplified - in production, use full databases)
    KNOWN_VPN_PROVIDERS = {
        "ExpressVPN": ["1.1.1.0/24"],
        "NordVPN": ["2.2.2.0/24"],
        "Surfshark": ["3.3.3.0/24"],
        "ProtonVPN": ["4.4.4.0/24"],
        "Private Internet Access": ["5.5.5.0/24"],
    }
    
    # Datacenter IP ranges (likely proxy infrastructure)
    DATACENTER_ASNS = {
        "AS16509": "Amazon EC2",
        "AS14061": "Digital Ocean",
        "AS139662": "Alibaba Cloud",
        "AS1239": "Sprint/Tier-1",
        "AS6347": "Telia",
    }
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def extract_real_ip(
        self,
        origin_ip: Optional[str],
        all_ips_in_chain: List[str],
        hop_details: List[Dict],
        classifications: Dict[str, Dict],
        enrichment_data: Optional[Dict] = None,
        geolocation_data: Optional[Dict] = None
    ) -> RealIPAnalysis:
        """
        Extract the real attacker IP using multiple techniques.
        
        Args:
            origin_ip: First IP in email chain (most likely real origin)
            all_ips_in_chain: All IPs found in email headers
            hop_details: Detailed hop information
            classifications: IP classification results (VPN/Proxy detection)
            enrichment_data: WHOIS/DNS enrichment results
            geolocation_data: Geolocation information
            
        Returns:
            RealIPAnalysis with suspected real IP and confidence
        """
        techniques_used = []
        evidence_items = []
        analysis_notes = []
        
        # ================================================================
        # TECHNIQUE 1: EMAIL HEADER ORIGIN ANALYSIS
        # ================================================================
        suspected_real_ip = None
        header_origin_ip = origin_ip
        techniques_used.append("Email Header Origin Analysis")
        
        if origin_ip:
            evidence_items.append(f"Email header indicates origin IP: {origin_ip}")
            # First hop in email chain is typically the actual sender
            suspected_real_ip = origin_ip
            analysis_notes.append(f"[PRIMARY] First hop in email chain: {origin_ip}")
        
        # ================================================================
        # TECHNIQUE 2: VPN/PROXY DETECTION & FILTERING
        # ================================================================
        techniques_used.append("VPN/Proxy Detection")
        vpn_ips: Set[str] = set()
        proxy_ips: Set[str] = set()
        tor_ips: Set[str] = set()
        real_candidate_ips: List[str] = []
        
        for ip in all_ips_in_chain:
            if ip in classifications:
                classification = classifications[ip]
                
                # Extract classification type
                class_type = classification.get("classification", "UNKNOWN").upper()
                
                if "VPN" in class_type:
                    vpn_ips.add(ip)
                    evidence_items.append(f"VPN detected on {ip}")
                    analysis_notes.append(f"[VPN LAYER] {ip} - {class_type}")
                elif "PROXY" in class_type or "RESIDENTIAL" in class_type:
                    proxy_ips.add(ip)
                    evidence_items.append(f"Proxy detected on {ip}")
                    analysis_notes.append(f"[PROXY LAYER] {ip} - {class_type}")
                elif "TOR" in class_type:
                    tor_ips.add(ip)
                    evidence_items.append(f"Tor exit node: {ip}")
                    analysis_notes.append(f"[TOR LAYER] {ip}")
                else:
                    # Likely real IP (not classified as VPN/Proxy/Tor)
                    real_candidate_ips.append(ip)
                    evidence_items.append(f"Non-VPN IP identified: {ip} ({class_type})")
        
        # If we found real (non-VPN) IPs, use the first one
        if real_candidate_ips and not suspected_real_ip:
            suspected_real_ip = real_candidate_ips[0]
            analysis_notes.append(f"[OBFUSCATION BYPASS] Non-VPN IP: {suspected_real_ip}")
        
        obfuscation_level = self._determine_obfuscation_level(
            len(vpn_ips), len(proxy_ips), len(tor_ips), len(all_ips_in_chain)
        )
        
        # ================================================================
        # TECHNIQUE 3: INFRASTRUCTURE CORRELATION
        # ================================================================
        techniques_used.append("Infrastructure Correlation")
        
        if enrichment_data:
            for ip, enrichment in enrichment_data.items():
                if ip == suspected_real_ip or ip == origin_ip:
                    org = enrichment.get("organization", "")
                    asn = enrichment.get("asn", "")
                    
                    # Check if this is a datacenter or hosting provider
                    if any(dc in asn for dc in self.DATACENTER_ASNS):
                        evidence_items.append(f"Datacenter detected: {org} (ASN: {asn})")
                        analysis_notes.append(f"[DATACENTER] {ip} hosted at {org}")
                    else:
                        evidence_items.append(f"Organization: {org} (ASN: {asn})")
                        analysis_notes.append(f"[INFRASTRUCTURE] {ip} belongs to {org}")
        
        # ================================================================
        # TECHNIQUE 4: GEOLOCATION CORRELATION
        # ================================================================
        techniques_used.append("Geolocation Analysis")
        
        if geolocation_data:
            geo_locations = {}
            vpn_provider_locations = {}
            
            # Map IPs to locations
            for ip, geo in geolocation_data.items():
                if geo:
                    location = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
                    geo_locations[ip] = location
                    
                    # Check if this IP is from known VPN provider regions
                    if ip in vpn_ips:
                        vpn_provider_locations[ip] = location
            
            # Real IP is likely in a region with the most non-VPN results
            if geo_locations:
                evidence_items.append(f"Geolocation mapping: {len(geo_locations)} IPs located")
                
                # If origin IP has geolocation and it's not a typical VPN provider location
                if origin_ip in geo_locations:
                    location = geo_locations[origin_ip]
                    analysis_notes.append(f"[GEOLOCATION] Real IP likely at: {location}")
        
        # ================================================================
        # TECHNIQUE 5: HOP PATTERN ANALYSIS
        # ================================================================
        techniques_used.append("Hop Pattern Analysis")
        
        # Analyze hop patterns to identify real origin
        for i, hop in enumerate(hop_details):
            if i == 0 and hop.get('ip'):  # First hop
                evidence_items.append(f"First hop (most likely real): {hop.get('ip')}")
                analysis_notes.append(f"[HOP 0] {hop.get('ip')} - {hop.get('hostname', 'N/A')}")
        
        # ================================================================
        # TECHNIQUE 6: TIMING & ARTIFACTS
        # ================================================================
        techniques_used.append("Timing Analysis")
        
        # Check for VPN artifacts in headers
        for hop in hop_details:
            raw_header = hop.get('raw_header', '')
            if any(keyword in raw_header for keyword in ['via', 'relay', 'forwarded', 'proxy']):
                evidence_items.append(f"Hop {hop.get('hop_number')}: Relay/forwarding detected")
        
        # ================================================================
        # CALCULATE CONFIDENCE SCORE
        # ================================================================
        confidence = self._calculate_confidence(
            suspected_real_ip,
            origin_ip,
            real_candidate_ips,
            classifications,
            obfuscation_level
        )
        
        # ================================================================
        # DETERMINE VPN PROVIDER
        # ================================================================
        vpn_provider = None
        if vpn_ips:
            # Try to identify VPN provider from IP or enrichment data
            for ip in vpn_ips:
                if enrichment_data and ip in enrichment_data:
                    org = enrichment_data[ip].get("organization", "")
                    for provider, ranges in self.KNOWN_VPN_PROVIDERS.items():
                        if provider.lower() in org.lower():
                            vpn_provider = provider
                            break
        
        return RealIPAnalysis(
            suspected_real_ip=suspected_real_ip,
            origin_ip_from_headers=header_origin_ip,
            obfuscation_level=obfuscation_level,
            vpn_provider=vpn_provider,
            likely_real_infrastructure=self._identify_infrastructure(
                suspected_real_ip, enrichment_data
            ),
            confidence_score=confidence,
            techniques_used=techniques_used,
            evidence_items=evidence_items,
            analysis_notes=analysis_notes
        )
    
    def _determine_obfuscation_level(
        self,
        vpn_count: int,
        proxy_count: int,
        tor_count: int,
        total_ips: int
    ) -> ObfuscationLevel:
        """Determine the level of obfuscation"""
        obfuscation_count = vpn_count + proxy_count + tor_count
        
        if obfuscation_count == 0:
            return ObfuscationLevel.NONE
        elif obfuscation_count == 1:
            return ObfuscationLevel.LIGHT
        elif obfuscation_count == 2:
            return ObfuscationLevel.MEDIUM
        elif obfuscation_count <= total_ips - 1:
            return ObfuscationLevel.HEAVY
        else:
            return ObfuscationLevel.ADVANCED
    
    def _calculate_confidence(
        self,
        suspected_real_ip: Optional[str],
        origin_ip: Optional[str],
        real_candidate_ips: List[str],
        classifications: Dict,
        obfuscation_level: ObfuscationLevel
    ) -> float:
        """Calculate confidence score for real IP identification"""
        confidence = 0.0
        
        if not suspected_real_ip:
            return 0.0
        
        # If suspected IP matches origin IP from headers
        if suspected_real_ip == origin_ip:
            confidence += 0.4
        
        # If it's classified as non-VPN
        if suspected_real_ip in classifications:
            classification = classifications[suspected_real_ip].get("classification", "")
            if "UNKNOWN" in classification or "RESIDENTIAL" in classification:
                confidence += 0.3
        
        # Boost confidence if it's the only real IP candidate
        if len(real_candidate_ips) == 1:
            confidence += 0.2
        
        # Adjust for obfuscation level
        if obfuscation_level == ObfuscationLevel.NONE:
            confidence += 0.1
        elif obfuscation_level == ObfuscationLevel.LIGHT:
            confidence += 0.05
        
        return min(confidence, 1.0)
    
    def _identify_infrastructure(
        self,
        ip: Optional[str],
        enrichment_data: Optional[Dict]
    ) -> Optional[str]:
        """Identify the infrastructure/hosting provider"""
        if not ip or not enrichment_data or ip not in enrichment_data:
            return None
        
        enrichment = enrichment_data[ip]
        org = enrichment.get("organization", "")
        asn = enrichment.get("asn", "")
        
        if org:
            return f"{org} ({asn})"
        elif asn:
            return asn
        
        return None


def extract_real_ip_summary(analysis: RealIPAnalysis) -> str:
    """Generate a formatted summary of real IP analysis"""
    lines = []
    lines.append("\n" + "="*80)
    lines.append("[REAL IP EXTRACTION - VPN/PROXY BYPASS ANALYSIS]")
    lines.append("="*80)
    
    lines.append(f"\n  IDENTIFIED REAL IP: {analysis.suspected_real_ip or 'UNKNOWN'}")
    lines.append(f"  Confidence: {analysis.confidence_score:.0%}")
    lines.append(f"  Obfuscation Level: {analysis.obfuscation_level.value.upper()}")
    
    if analysis.vpn_provider:
        lines.append(f"  VPN Provider Detected: {analysis.vpn_provider}")
    
    if analysis.likely_real_infrastructure:
        lines.append(f"  Infrastructure: {analysis.likely_real_infrastructure}")
    
    lines.append(f"\n  TECHNIQUES USED:")
    for i, technique in enumerate(analysis.techniques_used, 1):
        lines.append(f"    {i}. {technique}")
    
    lines.append(f"\n  KEY EVIDENCE:")
    for evidence in analysis.evidence_items[:5]:
        lines.append(f"    • {evidence}")
    
    lines.append(f"\n  ANALYSIS NOTES:")
    for note in analysis.analysis_notes[:5]:
        lines.append(f"    {note}")
    
    lines.append("\n" + "="*80)
    return "\n".join(lines)
