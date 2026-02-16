#!/usr/bin/env python3
"""
Complete Attacker IP Identification System - Full Pipeline
Stage 1: Extract headers → Stage 2: Classify IPs → Stage 3: Trace Proxy Chain

Single command flow:
    python3 complete_pipeline.py ./phishing_email.eml
    python3 complete_pipeline.py email.eml --json full_analysis.json
    python3 complete_pipeline.py email.eml --verbose
"""

import sys
import os
import json
import re
import email
import requests
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from email.utils import parsedate_to_datetime
import argparse
from pathlib import Path


# ============================================================================
# STAGE 1: HEADER EXTRACTION
# ============================================================================

@dataclass
class ReceivedHeaderDetail:
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
        
        hops.reverse()
        
        for i, hop in enumerate(hops):
            hop.hop_number = i + 1
        
        origin_ip = hops[0].ip if hops else None
        destination_ip = hops[-1].ip if hops else None
        
        received_spf = msg.get('Received-SPF', None)
        red_flags = []
        spoofing_risk = 0.0
        
        if received_spf and "fail" in received_spf.lower():
            spoofing_risk += 0.25
            red_flags.append(f"[CRITICAL] SPF FAILED")
        
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
        """Parse single header"""
        
        ip = None
        hostname = None
        protocol = "UNKNOWN"
        timestamp = None
        authentication = {}
        parsing_confidence = 0.5
        
        ip_match = self.patterns["ip_only"].search(header_text)
        if ip_match:
            ip = ip_match.group(1)
            parsing_confidence = 0.95
        
        by_match = self.patterns["by_clause"].search(header_text)
        if by_match:
            hostname = by_match.group(1)
        
        protocol_match = self.patterns["protocol"].search(header_text)
        if protocol_match:
            protocol = protocol_match.group(1).upper()
        
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
        self.tor_exits = None
    
    def classify_ips(self, ips: List[str]) -> Dict[str, IPClassification]:
        """Classify multiple IPs"""
        results = {}
        for ip in ips:
            results[ip] = self.classify_ip(ip)
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
        """Query AbuseIPDB"""
        try:
            headers = {"Key": self.abuse_api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
            response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
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
        """Check if Tor exit"""
        try:
            response = requests.get("https://check.torproject.org/exit-addresses", timeout=5)
            for line in response.text.split('\n'):
                if line.startswith('ExitAddress') and ip in line:
                    return True
        except:
            pass
        return False


# ============================================================================
# STAGE 3: PROXY CHAIN ANALYSIS
# ============================================================================

@dataclass
class ProxyLayer:
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
    chain: List[ProxyLayer]
    obfuscation_count: int
    obfuscation_types: List[str]
    apparent_origin: str
    likely_real_origin: Optional[str]
    true_origin_confidence: float
    analysis_notes: List[str]
    timestamp_analyzed: str

class ProxyChainTracer:
    """Stage 3: Analyze proxy chain"""
    
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
        """Analyze IP chain"""
        
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
            analysis_notes.append("[CONCLUSION] True origin cannot be determined")
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
# REPORT GENERATOR
# ============================================================================

class CompletePipelineReport:
    """Generate complete analysis report"""
    
    def __init__(self, header_analysis, classifications, proxy_analysis):
        self.header = header_analysis
        self.classifications = classifications
        self.proxy = proxy_analysis
    
    def generate_text_report(self, verbose: bool = False) -> str:
        """Generate text report"""
        
        lines = []
        lines.append("[COMPLETE PHISHING EMAIL ANALYSIS REPORT]")
        lines.append("=" * 70)
        
        # Email info
        lines.append("\n[EMAIL INFORMATION]")
        lines.append(f"  From: {self.header.email_from}")
        lines.append(f"  To: {self.header.email_to}")
        lines.append(f"  Subject: {self.header.email_subject}")
        lines.append(f"  Date: {self.header.email_date}")
        lines.append(f"  Spoofing Risk: {self.header.spoofing_risk:.0%}")
        
        if self.header.red_flags:
            lines.append(f"  Red Flags:")
            for flag in self.header.red_flags[:3]:  # Show first 3
                lines.append(f"    - {flag}")
        
        # Header chain
        lines.append("\n[HEADER CHAIN ANALYSIS]")
        lines.append(f"  Total Hops: {self.header.hop_count}")
        lines.append(f"  Origin IP: {self.header.origin_ip}")
        lines.append(f"  Destination IP: {self.header.destination_ip}")
        
        if verbose:
            lines.append(f"  Hops:")
            for hop in self.header.hops:
                lines.append(f"    {hop.hop_number}. {hop.ip} ({hop.hostname})")
        
        # IP Classifications
        lines.append("\n[IP CLASSIFICATIONS (STAGE 2)]")
        
        for ip in sorted(self.classifications.keys()):
            result = self.classifications[ip]
            lines.append(f"\n  IP: {ip}")
            lines.append(f"    Classification: {result.classification}")
            lines.append(f"    Confidence: {result.confidence:.0%}")
            lines.append(f"    Threat Score: {result.threat_score}/100")
            
            if result.evidence:
                lines.append(f"    Evidence: {'; '.join(result.evidence[:2])}")
        
        # Proxy chain
        lines.append("\n[PROXY CHAIN ANALYSIS (STAGE 3)]")
        lines.append(f"  Obfuscation Layers: {self.proxy.obfuscation_count}")
        
        if self.proxy.obfuscation_types:
            lines.append(f"  Methods: {', '.join(self.proxy.obfuscation_types)}")
        
        lines.append(f"  Apparent Origin: {self.proxy.apparent_origin}")
        lines.append(f"  Likely Real Origin: {self.proxy.likely_real_origin}")
        lines.append(f"  Origin Confidence: {self.proxy.true_origin_confidence:.0%}")
        
        # Flow diagram
        lines.append("\n[ATTACK FLOW]")
        
        for i, layer in enumerate(self.proxy.chain):
            ip_short = layer.ip[-10:] if len(layer.ip) > 10 else layer.ip
            obf_marker = " [OBFUSCATED]" if layer.is_obfuscation else ""
            threat_marker = " [HIGH THREAT]" if layer.threat_score > 75 else ""
            
            lines.append(f"  [{i+1}] {ip_short:<12} {layer.classification:<20}{threat_marker}{obf_marker}")
            
            if i < len(self.proxy.chain) - 1:
                lines.append("       |")
                lines.append("       v")
        
        # Conclusion
        lines.append("\n[CONCLUSION]")
        lines.append("=" * 70)
        
        for note in self.proxy.analysis_notes:
            lines.append(f"  {note}")
        
        lines.append("\n[RECOMMENDED ACTIONS]")
        
        if self.proxy.obfuscation_count > 0:
            lines.append("  1. Alert law enforcement (Tor/VPN forensics)")
            lines.append("  2. Monitor for pattern changes")
            lines.append("  3. Correlate with other campaigns")
        else:
            lines.append("  1. Contact hosting provider")
            lines.append("  2. File abuse report")
            lines.append("  3. Request ISP logs via subpoena")
        
        lines.append("\n" + "=" * 70 + "\n")
        
        return "\n".join(lines)
    
    def to_json(self) -> Dict:
        """Export to JSON"""
        
        return {
            "email": {
                "from": self.header.email_from,
                "to": self.header.email_to,
                "subject": self.header.email_subject,
                "date": self.header.email_date,
                "spoofing_risk": self.header.spoofing_risk,
                "red_flags": self.header.red_flags
            },
            "stage1_header_chain": {
                "hops": self.header.hop_count,
                "origin_ip": self.header.origin_ip,
                "destination_ip": self.header.destination_ip
            },
            "stage2_ip_classifications": {
                ip: asdict(c) for ip, c in self.classifications.items()
            },
            "stage3_proxy_chain": {
                "obfuscation_count": self.proxy.obfuscation_count,
                "obfuscation_types": self.proxy.obfuscation_types,
                "apparent_origin": self.proxy.apparent_origin,
                "likely_real_origin": self.proxy.likely_real_origin,
                "true_origin_confidence": self.proxy.true_origin_confidence,
                "analysis_notes": self.proxy.analysis_notes,
                "chain": [asdict(layer) for layer in self.proxy.chain]
            }
        }


# ============================================================================
# MASTER PIPELINE
# ============================================================================

class CompletePipeline:
    """Master pipeline: Stage 1 → Stage 2 → Stage 3"""
    
    def __init__(self, verbose: bool = False):
        self.extractor = HeaderExtractor()
        self.classifier = IPClassifierLight()
        self.tracer = ProxyChainTracer()
        self.verbose = verbose
    
    def run(self, email_file: str) -> Optional[CompletePipelineReport]:
        """Run complete pipeline"""
        
        print("[START] Complete Phishing Analysis Pipeline")
        print("=" * 70)
        
        # STAGE 1: Extract headers
        print("\n[STAGE 1] Extracting email headers...")
        
        header_analysis = self.extractor.parse_email_file(email_file)
        
        if not header_analysis:
            print("[ERROR] Failed to parse email")
            return None
        
        print(f"[SUCCESS] Found {header_analysis.hop_count} hops")
        
        # Extract unique IPs
        unique_ips = []
        seen = set()
        for hop in header_analysis.hops:
            if hop.ip and hop.ip not in seen:
                unique_ips.append(hop.ip)
                seen.add(hop.ip)
        
        print(f"[INFO] Unique IPs: {', '.join(unique_ips)}")
        
        # STAGE 2: Classify IPs
        print("\n[STAGE 2] Classifying IPs...")
        
        classifications = {}
        for ip in unique_ips:
            result = self.classifier.classify_ip(ip)
            classifications[ip] = result
            print(f"  {ip}: {result.classification} ({result.confidence:.0%})")
        
        # STAGE 3: Trace proxy chain
        print("\n[STAGE 3] Tracing proxy chain...")
        
        # Build classified IPs list in chain order
        classified_chain = []
        for hop in header_analysis.hops:
            if hop.ip and hop.ip in classifications:
                classified_data = asdict(classifications[hop.ip])
                classified_chain.append(classified_data)
        
        proxy_analysis = self.tracer.trace_chain(classified_chain)
        print(f"  Obfuscation layers: {proxy_analysis.obfuscation_count}")
        print(f"  Real origin: {proxy_analysis.likely_real_origin}")
        
        # Generate report
        print("\n[GENERATING REPORT]")
        
        report = CompletePipelineReport(header_analysis, classifications, proxy_analysis)
        
        return report


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="Complete Attacker IP Identification Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 complete_pipeline.py ./phishing_email.eml
  python3 complete_pipeline.py email.eml --json full_report.json
  python3 complete_pipeline.py email.eml --verbose
  python3 complete_pipeline.py email.eml --json report.json --verbose
        """
    )
    
    parser.add_argument(
        "email_file",
        help="Path to email file (.eml format)"
    )
    
    parser.add_argument(
        "--json",
        metavar="OUTPUT_FILE",
        help="Export full report to JSON"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    
    args = parser.parse_args()
    
    # Validate file
    if not Path(args.email_file).exists():
        print(f"[ERROR] File not found: {args.email_file}")
        sys.exit(1)
    
    # Run pipeline
    pipeline = CompletePipeline(verbose=args.verbose)
    report = pipeline.run(args.email_file)
    
    if not report:
        print("[ERROR] Pipeline failed")
        sys.exit(1)
    
    # Display report
    print("\n")
    print(report.generate_text_report(verbose=args.verbose))
    
    # Export JSON if requested
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(report.to_json(), f, indent=2)
        print(f"[SUCCESS] Full report exported to: {args.json}")
    
    print("[COMPLETE] Analysis finished")


if __name__ == "__main__":
    main()