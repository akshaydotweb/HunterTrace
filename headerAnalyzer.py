#!/usr/bin/env python3
"""
Stage 1: Attacker IP Identification System
Extract and analyze Received headers from phishing emails

Usage:
    python3 header_analyzer.py ./phishing_email.eml
    python3 eader_analyzer.py /path/to/email.eml
    python3 header_analyzer.py --help
"""

import sys
import re
import email
import json
from email.parser import Parser
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from email.utils import parsedate_to_datetime
import argparse
from pathlib import Path


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class ReceivedHeaderDetail:
    """One hop in the email chain"""
    hop_number: int                    # 1 = origin, last = destination
    ip: Optional[str]                  # 45.153.160.2
    hostname: Optional[str]            # attacker.ru (may be spoofed)
    protocol: str                      # SMTP, ESMTP, HTTP
    timestamp: Optional[str]           # ISO format datetime
    authentication: Dict               # SPF, DKIM, TLS info
    raw_header: str                    # First 100 chars for reference
    parsing_confidence: float          # 0.5-1.0 (how sure about this parse?)

@dataclass
class ReceivedChainAnalysis:
    """Complete email header chain analysis"""
    email_from: str                     # From: header (may be spoofed)
    email_to: str                       # To: header
    email_subject: str                  # Subject
    email_date: Optional[str]           # Date: header (ISO format)
    message_id: str                     # Message-ID (may be spoofed)
    
    hops: List[ReceivedHeaderDetail]    # All hops analyzed
    
    # Derived
    origin_ip: Optional[str]            # First hop (closest to attacker)
    destination_ip: Optional[str]       # Last hop (victim's server)
    hop_count: int                      # How many relays?
    
    # Quality checks
    headers_found: int                  # How many Received: headers?
    spoofing_risk: float                # 0-1 (likelihood headers spoofed?)
    confidence: float                   # Overall confidence in chain
    red_flags: List[str]                # Detected issues
    

# ============================================================================
# HEADER EXTRACTION ENGINE
# ============================================================================

class ReceivedHeaderParser:
    """Extract and parse Received headers from emails"""
    
    def __init__(self):
        """Initialize parser with regex patterns"""
        
        # Regex patterns for different email server formats
        self.patterns = {
            # Pattern 1: Standard SMTP format
            "standard_with_ip": re.compile(
                r'from\s+(\S+)\s+\(([^)]*)\s+\[(\d+\.\d+\.\d+\.\d+)\]\)',
                re.IGNORECASE
            ),
            
            # Pattern 2: Just IP in brackets
            "ip_only": re.compile(
                r'\[(\d+\.\d+\.\d+\.\d+)\]',
                re.IGNORECASE
            ),
            
            # Pattern 3: "by" clause
            "by_clause": re.compile(
                r'by\s+(\S+)',
                re.IGNORECASE
            ),
            
            # Pattern 4: Protocol
            "protocol": re.compile(
                r'with\s+(ESMTP|SMTP|HTTP|HTTPS|LMTP)',
                re.IGNORECASE
            ),
            
            # Pattern 5: TLS/Encryption
            "tls": re.compile(
                r'(TLS|STARTTLS|encrypted)',
                re.IGNORECASE
            ),
            
            # Pattern 6: Timestamp
            "timestamp": re.compile(
                r';?\s*([A-Za-z]{3},?\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}[^;]*)',
                re.IGNORECASE
            )
        }
    
    def parse_email_file(self, file_path: str) -> Optional[ReceivedChainAnalysis]:
        """
        Parse email file (.eml format)
        
        Args:
            file_path: Path to .eml file
        
        Returns: Complete chain analysis or None
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_raw = f.read()
            return self.parse_email_raw(email_raw)
        except FileNotFoundError:
            print(f"[ERROR] File not found: {file_path}")
            return None
        except Exception as e:
            print(f"[ERROR] Reading file: {e}")
            return None
    
    def parse_email_raw(self, email_raw: str) -> Optional[ReceivedChainAnalysis]:
        """
        Parse raw email (RFC 2822 format)
        
        Args:
            email_raw: Full email text
        
        Returns: Complete chain analysis
        """
        
        # Parse email
        msg = email.message_from_string(email_raw)
        
        # Extract basic headers
        email_from = msg.get('From', 'Unknown')
        email_to = msg.get('To', 'Unknown')
        email_subject = msg.get('Subject', 'Unknown')
        message_id = msg.get('Message-ID', 'Unknown')
        
        # Parse date
        date_str = msg.get('Date', None)
        email_date = None
        if date_str:
            try:
                email_date = parsedate_to_datetime(date_str).isoformat()
            except:
                pass
        
        # Extract ALL Received headers
        received_headers = msg.get_all('Received', [])
        
        # Parse each header
        hops = []
        for i, header_text in enumerate(received_headers):
            hop = self._parse_single_header(header_text, hop_number=i)
            hops.append(hop)
        
        # CRITICAL: Reverse the list (email headers are bottom-first)
        hops.reverse()
        
        # Update hop numbers
        for i, hop in enumerate(hops):
            hop.hop_number = i + 1
        
        # Extract IPs
        origin_ip = hops[0].ip if hops else None
        destination_ip = hops[-1].ip if hops else None
        
        # Get extra headers
        x_originating_ip = msg.get('X-Originating-IP', None)
        x_forwarded_for = msg.get('X-Forwarded-For', None)
        received_spf = msg.get('Received-SPF', None)
        
        # Calculate spoofing risk and red flags
        spoofing_risk, red_flags = self._calculate_spoofing_risk(
            hops, email_date, email_from, x_originating_ip, received_spf
        )
        
        # Create analysis
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
            spoofing_risk=spoofing_risk,
            confidence=1.0 - (spoofing_risk * 0.3),
            red_flags=red_flags
        )
        
        return analysis
    
    def _parse_single_header(self, header_text: str, hop_number: int) -> ReceivedHeaderDetail:
        """Parse one Received header"""
        
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
        hostname_match = self.patterns["standard_with_ip"].search(header_text)
        if hostname_match:
            hostname = hostname_match.group(1)
        else:
            by_match = self.patterns["by_clause"].search(header_text)
            if by_match:
                hostname = by_match.group(1)
        
        # Extract protocol
        protocol_match = self.patterns["protocol"].search(header_text)
        if protocol_match:
            protocol = protocol_match.group(1).upper()
        
        # Extract authentication
        if self.patterns["tls"].search(header_text):
            authentication["tls"] = True
        if "SPF" in header_text:
            authentication["spf"] = "found"
        if "DKIM" in header_text:
            authentication["dkim"] = "found"
        
        # Extract timestamp
        timestamp_match = self.patterns["timestamp"].search(header_text)
        if timestamp_match:
            try:
                ts = parsedate_to_datetime(timestamp_match.group(1))
                timestamp = ts.isoformat()
            except:
                pass
        
        return ReceivedHeaderDetail(
            hop_number=hop_number,
            ip=ip,
            hostname=hostname,
            protocol=protocol,
            timestamp=timestamp,
            authentication=authentication,
            raw_header=header_text[:100] + "..." if len(header_text) > 100 else header_text,
            parsing_confidence=parsing_confidence
        )
    
    def _calculate_spoofing_risk(self, hops: List[ReceivedHeaderDetail], 
                                 email_date: Optional[str],
                                 email_from: str,
                                 x_originating_ip: Optional[str],
                                 received_spf: Optional[str]) -> Tuple[float, List[str]]:
        """Detect spoofing indicators"""
        
        risk = 0.0
        red_flags = []
        
        if not hops:
            return 1.0, ["[CRITICAL] No Received headers found"]
        
        # CHECK 1: Timestamps out of order
        timestamps = []
        for hop in hops:
            if hop.timestamp:
                try:
                    timestamps.append(datetime.fromisoformat(hop.timestamp))
                except:
                    pass
        
        if len(timestamps) > 1:
            for i in range(1, len(timestamps)):
                if timestamps[i] < timestamps[i-1]:
                    risk += 0.2
                    red_flags.append(f"[WARNING] Timestamp anomaly: Hop {i} earlier than Hop {i-1}")
        
        # CHECK 2: SPF failure
        if received_spf and "fail" in received_spf.lower():
            risk += 0.25
            red_flags.append(f"[CRITICAL] SPF FAILED: {received_spf}")
        
        # CHECK 3: Missing IPs
        missing_count = sum(1 for h in hops if not h.ip)
        if missing_count > len(hops) * 0.5:
            risk += 0.2
            red_flags.append(f"[WARNING] {missing_count}/{len(hops)} hops missing IPs")
        
        # CHECK 4: All same IP
        unique_ips = set(h.ip for h in hops if h.ip)
        if len(unique_ips) == 1 and len(hops) > 2:
            risk += 0.15
            red_flags.append("[WARNING] All hops claim same IP")
        
        # CHECK 5: Hostname spoofing indicators
        for hop in hops:
            if hop.hostname and ("compromised" in hop.hostname.lower() or 
                                "fake" in hop.hostname.lower() or
                                "spoofed" in hop.hostname.lower()):
                risk += 0.15
                red_flags.append(f"[CRITICAL] Suspicious hostname: {hop.hostname}")
        
        # CHECK 6: X-Originating-IP mismatch
        if x_originating_ip and hops[0].ip:
            if x_originating_ip not in hops[0].ip:
                red_flags.append(f"[INFO] X-Originating-IP: {x_originating_ip}")
        
        return min(1.0, max(0.0, risk)), red_flags


# ============================================================================
# OUTPUT FORMATTER
# ============================================================================

class AnalysisFormatter:
    """Format analysis output beautifully"""
    
    @staticmethod
    def print_analysis(analysis: ReceivedChainAnalysis, email_file: str):
        """Print formatted analysis"""
        
        print("\n" + "="*70)
        print("PHISHING EMAIL HEADER ANALYSIS - STAGE 1")
        print("="*70)
        
        print(f"\nFILE: {email_file}")
        
        # Email metadata
        print(f"\n[EMAIL METADATA]")
        print(f"   From: {analysis.email_from}")
        print(f"   To: {analysis.email_to}")
        print(f"   Subject: {analysis.email_subject}")
        print(f"   Date: {analysis.email_date or 'Unknown'}")
        print(f"   Message-ID: {analysis.message_id}")
        
        # Header chain summary
        print(f"\n[RECEIVED HEADER CHAIN]")
        print(f"   Total hops: {analysis.hop_count}")
        print(f"   Headers found: {analysis.headers_found}")
        print(f"   Origin IP: {analysis.origin_ip or 'UNKNOWN'}")
        print(f"   Destination IP: {analysis.destination_ip or 'UNKNOWN'}")
        
        # Risk assessment
        print(f"\n[RISK ASSESSMENT]")
        print(f"   Spoofing risk: {analysis.spoofing_risk:.0%}")
        print(f"   Overall confidence: {analysis.confidence:.0%}")
        
        # Red flags
        if analysis.red_flags:
            print(f"\n[RED FLAGS DETECTED]")
            for flag in analysis.red_flags:
                print(f"   {flag}")
        else:
            print(f"\n[STATUS] No obvious red flags detected")
        
        # Hop-by-hop analysis
        print(f"\n[HOP-BY-HOP BREAKDOWN]")
        for hop in analysis.hops:
            AnalysisFormatter._print_hop(hop)
        
        # Summary
        print(f"\n[SUMMARY]")
        print(f"   Attacker's IP: {analysis.origin_ip}")
        print(f"   Confidence: {analysis.confidence:.0%}")
        
        if analysis.spoofing_risk > 0.6:
            risk_level = "HIGHLY SUSPICIOUS"
        elif analysis.spoofing_risk > 0.3:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "LIKELY LEGITIMATE"
        print(f"   Risk Level: {risk_level}")
        
        print("\n" + "="*70 + "\n")
    
    @staticmethod
    def _print_hop(hop: ReceivedHeaderDetail):
        """Print one hop nicely"""
        print(f"\n   HOP {hop.hop_number}:")
        print(f"   |- IP: {hop.ip or '(MISSING)'}")
        print(f"   |- Hostname: {hop.hostname or 'unknown'}")
        print(f"   |- Protocol: {hop.protocol}")
        print(f"   |- Timestamp: {hop.timestamp or 'unknown'}")
        if hop.authentication:
            print(f"   |- Auth: {hop.authentication}")
        print(f"   `- Confidence: {hop.parsing_confidence:.0%}")
    
    @staticmethod
    def export_json(analysis: ReceivedChainAnalysis, output_file: str):
        """Export analysis to JSON"""
        
        # Convert dataclasses to dicts
        hops_data = [asdict(hop) for hop in analysis.hops]
        
        data = {
            "email_from": analysis.email_from,
            "email_to": analysis.email_to,
            "email_subject": analysis.email_subject,
            "email_date": analysis.email_date,
            "message_id": analysis.message_id,
            "origin_ip": analysis.origin_ip,
            "destination_ip": analysis.destination_ip,
            "hop_count": analysis.hop_count,
            "spoofing_risk": analysis.spoofing_risk,
            "confidence": analysis.confidence,
            "red_flags": analysis.red_flags,
            "hops": hops_data
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[SUCCESS] Analysis exported to: {output_file}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="Stage 1: Extract and analyze received headers from phishing emails",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 email_header_analyzer.py ./phishing_email.eml
  python3 email_header_analyzer.py /path/to/email.eml
  python3 email_header_analyzer.py email.eml --json output.json
        """
    )
    
    parser.add_argument(
        "email_file",
        help="Path to email file (.eml format)"
    )
    
    parser.add_argument(
        "--json",
        metavar="OUTPUT_FILE",
        help="Export analysis to JSON file"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed parsing information"
    )
    
    args = parser.parse_args()
    
    # Check file exists
    if not Path(args.email_file).exists():
        print(f"[ERROR] File not found: {args.email_file}")
        sys.exit(1)
    
    # Parse email
    print(f"[INFO] Reading email file: {args.email_file}")
    parser_engine = ReceivedHeaderParser()
    analysis = parser_engine.parse_email_file(args.email_file)
    
    if not analysis:
        print("[ERROR] Failed to parse email")
        sys.exit(1)
    
    # Display analysis
    AnalysisFormatter.print_analysis(analysis, args.email_file)
    
    # Export JSON if requested
    if args.json:
        AnalysisFormatter.export_json(analysis, args.json)
    
    # Exit with status based on risk
    if analysis.spoofing_risk > 0.6:
        sys.exit(2)  # High risk
    elif analysis.spoofing_risk > 0.3:
        sys.exit(1)  # Medium risk
    else:
        sys.exit(0)  # Low risk


if __name__ == "__main__":
    main()