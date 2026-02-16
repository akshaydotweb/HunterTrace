#!/usr/bin/env python3
"""
Full Phishing Email Analysis Pipeline
Stage 1: Extract IPs from email headers
Stage 2: Classify extracted IPs using real APIs

Usage:
    python3 phishing_analyzer.py ./phishing_email.eml
    python3 phishing_analyzer.py email.eml --json full_report.json
"""

import sys
import os
import json
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import argparse


# ============================================================================
# IMPORT STAGE 1 (Header Analysis)
# ============================================================================

import email
from email.parser import Parser
from email.utils import parsedate_to_datetime

@dataclass
class ReceivedHeaderDetail:
    """One hop in the email chain"""
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

@dataclass
class IPClassification:
    """Classification result for one IP"""
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


# ============================================================================
# STAGE 1: HEADER EXTRACTION (Simplified)
# ============================================================================

class HeaderExtractor:
    """Extract IPs from email headers"""
    
    def __init__(self):
        import re
        self.patterns = {
            "ip_only": re.compile(r'\[(\d+\.\d+\.\d+\.\d+)\]', re.IGNORECASE),
            "protocol": re.compile(r'with\s+(ESMTP|SMTP|HTTP|HTTPS|LMTP)', re.IGNORECASE),
            "timestamp": re.compile(r';?\s*([A-Za-z]{3},?\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}[^;]*)', re.IGNORECASE),
            "by_clause": re.compile(r'by\s+(\S+)', re.IGNORECASE),
        }
    
    def parse_email_file(self, file_path: str) -> Optional[ReceivedChainAnalysis]:
        """Parse email file and extract headers"""
        
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
            red_flags.append(f"[CRITICAL] SPF FAILED: {received_spf}")
        
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
# STAGE 2: IP CLASSIFICATION (Simplified)
# ============================================================================

import requests
import time

class IPClassifierLight:
    """Lightweight IP classifier using real APIs"""
    
    def __init__(self):
        self.abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.cache = {}
    
    def classify_ip(self, ip: str) -> IPClassification:
        """Classify single IP"""
        
        print(f"[CLASSIFYING] {ip}")
        
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
        
        # Check AbuseIPDB if API key available
        if self.abuse_api_key:
            try:
                print(f"[CHECK] Querying AbuseIPDB...")
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
                print(f"[WARNING] AbuseIPDB error: {e}")
        
        # Check Tor
        print(f"[CHECK] Checking if Tor exit...")
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
            headers = {
                "Key": self.abuse_api_key,
                "Accept": "application/json"
            }
            
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            
            if "data" in data:
                return {
                    "abuse_score": data["data"]["abuseConfidenceScore"],
                    "total_reports": data["data"]["totalReports"],
                    "country": data["data"]["countryCode"]
                }
        
        except Exception as e:
            pass
        
        return None
    
    def _is_tor_exit(self, ip: str) -> bool:
        """Check if Tor exit (simplified)"""
        
        try:
            response = requests.get("https://check.torproject.org/exit-addresses", timeout=5)
            for line in response.text.split('\n'):
                if line.startswith('ExitAddress') and ip in line:
                    return True
        except:
            pass
        
        return False


# ============================================================================
# UNIFIED PIPELINE
# ============================================================================

class PhishingAnalyzerPipeline:
    """Complete phishing email analysis pipeline"""
    
    def __init__(self):
        self.extractor = HeaderExtractor()
        self.classifier = IPClassifierLight()
    
    def analyze(self, email_file: str) -> Dict:
        """
        Full analysis: Stage 1 + Stage 2
        
        Returns combined results
        """
        
        print("[START] Phishing Email Analysis Pipeline")
        print("=" * 70)
        
        # STAGE 1: Extract headers
        print("\n[STAGE 1] Extracting email headers...")
        
        header_analysis = self.extractor.parse_email_file(email_file)
        
        if not header_analysis:
            print("[ERROR] Failed to parse email")
            return None
        
        print(f"[SUCCESS] Found {header_analysis.hop_count} hops")
        print(f"[INFO] Origin IP: {header_analysis.origin_ip}")
        print(f"[INFO] Destination IP: {header_analysis.destination_ip}")
        
        # Extract unique IPs
        unique_ips = set()
        for hop in header_analysis.hops:
            if hop.ip:
                unique_ips.add(hop.ip)
        
        print(f"[INFO] Unique IPs found: {', '.join(sorted(unique_ips))}")
        
        # STAGE 2: Classify IPs
        print("\n[STAGE 2] Classifying extracted IPs...")
        
        classifications = {}
        for ip in sorted(unique_ips):
            result = self.classifier.classify_ip(ip)
            classifications[ip] = result
            print(f"[RESULT] {ip}: {result.classification} ({result.confidence:.0%})")
        
        # Combine results
        full_report = {
            "email_analysis": {
                "from": header_analysis.email_from,
                "to": header_analysis.email_to,
                "subject": header_analysis.email_subject,
                "date": header_analysis.email_date,
                "spoofing_risk": header_analysis.spoofing_risk,
                "confidence": header_analysis.confidence,
                "red_flags": header_analysis.red_flags
            },
            "header_chain": {
                "hops": len(header_analysis.hops),
                "origin_ip": header_analysis.origin_ip,
                "destination_ip": header_analysis.destination_ip,
                "hops_detail": [
                    {
                        "number": h.hop_number,
                        "ip": h.ip,
                        "hostname": h.hostname,
                        "protocol": h.protocol
                    }
                    for h in header_analysis.hops
                ]
            },
            "ip_classifications": {
                ip: asdict(c) for ip, c in classifications.items()
            }
        }
        
        return full_report


# ============================================================================
# OUTPUT FORMATTER
# ============================================================================

class ReportFormatter:
    """Format final report"""
    
    @staticmethod
    def print_report(report: Dict):
        """Print full report"""
        
        print("\n" + "=" * 70)
        print("FULL PHISHING ANALYSIS REPORT")
        print("=" * 70)
        
        email_info = report["email_analysis"]
        
        print("\n[EMAIL INFORMATION]")
        print(f"   From: {email_info['from']}")
        print(f"   To: {email_info['to']}")
        print(f"   Subject: {email_info['subject']}")
        print(f"   Date: {email_info['date']}")
        print(f"   Spoofing Risk: {email_info['spoofing_risk']:.0%}")
        print(f"   Confidence: {email_info['confidence']:.0%}")
        
        if email_info['red_flags']:
            print(f"\n   Red Flags:")
            for flag in email_info['red_flags']:
                print(f"      {flag}")
        
        header_chain = report["header_chain"]
        
        print(f"\n[HEADER CHAIN]")
        print(f"   Total Hops: {header_chain['hops']}")
        print(f"   Origin IP: {header_chain['origin_ip']}")
        print(f"   Destination IP: {header_chain['destination_ip']}")
        print(f"\n   Hops:")
        
        for hop in header_chain['hops_detail']:
            print(f"      {hop['number']}. {hop['ip']} ({hop['hostname']}) via {hop['protocol']}")
        
        classifications = report["ip_classifications"]
        
        print(f"\n[IP CLASSIFICATIONS]")
        
        for ip, result in sorted(classifications.items()):
            print(f"\n   IP: {ip}")
            print(f"      Classification: {result['classification']}")
            print(f"      Confidence: {result['confidence']:.0%}")
            print(f"      Threat Score: {result['threat_score']}/100")
            print(f"      Abuse Reports: {result['abuse_reports']}")
            print(f"      Country: {result['country'] or 'Unknown'}")
            
            if result['evidence']:
                print(f"      Evidence:")
                for evidence in result['evidence']:
                    print(f"         - {evidence}")
        
        print("\n" + "=" * 70 + "\n")
    
    @staticmethod
    def export_json(report: Dict, output_file: str):
        """Export to JSON"""
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[SUCCESS] Report exported to: {output_file}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="Full Phishing Email Analysis (Stage 1 + Stage 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 phishing_analyzer.py ./phishing_email.eml
  python3 phishing_analyzer.py email.eml --json report.json
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
    
    args = parser.parse_args()
    
    # Validate file
    if not Path(args.email_file).exists():
        print(f"[ERROR] File not found: {args.email_file}")
        sys.exit(1)
    
    # Run pipeline
    pipeline = PhishingAnalyzerPipeline()
    report = pipeline.analyze(args.email_file)
    
    if not report:
        print("[ERROR] Analysis failed")
        sys.exit(1)
    
    # Display report
    ReportFormatter.print_report(report)
    
    # Export JSON if requested
    if args.json:
        ReportFormatter.export_json(report, args.json)


if __name__ == "__main__":
    main()