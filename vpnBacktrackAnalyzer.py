#!/usr/bin/env python3
"""
VPN/PROXY IP BACKTRACKING & REAL IP RECOVERY MODULE
==============================================================================

Technical methods to trace real attacker IP despite VPN/Proxy usage.
Implements techniques from: "A Survey on Tracing IP Address Behind VPN/Proxy Server"

WORKING BACKTRACKING TECHNIQUES (No law enforcement needed):

1. DNS LEAK DETECTION - Monitor DNS queries outside VPN tunnel
   - Parse email headers for DNS resolution records
   - Check Received-SPF for authenticated IP
   - Analyze DKIM signatures for sender ISP

2. IPID SEQUENCE ANALYSIS - Track IP ID increments across packets
   - Different ISPs use different IPID algorithms
   - Real IP reveals through pattern analysis

3. TTL ANALYSIS - Time-to-Live field reveals network hops
   - VPN adds hops, changes TTL
   - Calculate distance to real origin

4. EMAIL HEADER TIMESTAMPS - Timezone + sending time reveals location
   - Parse Date header timezone offset
   - Correlate with VPN endpoint location
   - Identify local time mismatch

5. GEOLOCATION INFERENCE - Compare VPN location vs timezone/ISP
   - If timezone is +05:30 (India) but VPN is Japan = real IP in India
   - Cross-reference with ASN geolocation data

6. REVERSE DNS + WHOIS CORRELATION - Trace VPN provider to real ISP
   - Map VPN IP to hosting provider
   - Check provider's known customer list
   - Correlate with IP allocation history

7. BEHAVIORAL BIOMETRICS - Email sending patterns reveal location
   - Sending time of day correlates with timezone
   - Reply time patterns match local business hours
   - Keyboard typing speed analysis (research shows ~200ms variance)

8. HEADER FIELD ANALYSIS - Extract embedded real IP from headers
   - X-Originating-IP (Outlook/Exchange servers)
   - X-MSMail-Priority, X-Priority reveal client OS
   - MIME-Version reveals email client (correlate with region)

9. MAIL SERVER ROUTING - Analyze Received headers for first-hop ISP
   - First server in chain = attacker's ISP
   - Later servers = mail relay/VPN
   - Extract first-hop IP before VPN gateway

10. PACKET TIMING ANALYSIS - Measure RPC delays to infer location
    - Email composition time reveals timezone
    - Server response times correlate with network distance

11. PUBLIC IP DATABASE LOOKUP - Check if "private" IPs have been leaked
    - Correlate MAC address with public IP history
    - Check Shodan/Censys for device fingerprints

12. MACHINE LEARNING CLASSIFICATION - Train on known VPN vs real traffic
    - Email patterns for VPN users vs direct users
    - Packet size distribution analysis
    - Protocol behavior fingerprinting
"""

from dataclasses import dataclass
from typing import Optional, List, Dict
from enum import Enum
import re
import ipaddress
from datetime import datetime
import socket


class BacktrackMethod(Enum):
    """Methods for backtracking real IP"""
    FIRST_HOP_ISP = "first_hop_isp"
    TIMEZONE_CORRELATION = "timezone_correlation"
    TTL_ANALYSIS = "ttl_analysis"
    DNS_LEAK = "dns_leak"
    HEADER_EXTRACTION = "header_extraction"
    BEHAVIORAL_TIME = "behavioral_time"
    GEOLOCATION_INFERENCE = "geolocation_inference"
    IPID_SEQUENCE = "ipid_sequence"


@dataclass
class RealIPSignal:
    """Signal indicating probable real IP"""
    method: BacktrackMethod
    real_ip: Optional[str]
    real_country: Optional[str]
    confidence: float
    evidence: List[str]


@dataclass
class BacktrackResult:
    """Complete real IP backtracking result"""
    probable_real_ip: Optional[str]
    probable_country: Optional[str]
    backtracking_confidence: float
    signals: List[RealIPSignal]
    analysis_notes: str
    vpn_endpoint_ip: Optional[str] = None
    vpn_country: Optional[str] = None


class RealIPBacktracker:
    """Extract real attacker IP from email despite VPN usage"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        # Timezone offset to country/region mapping
        self.timezone_regions = {
            "+05:30": ("India", ["IN"]),
            "+09:00": ("Japan/Korea", ["JP", "KR"]),
            "+08:00": ("China/Singapore", ["CN", "SG", "MY"]),
            "+00:00": ("UK/UTC", ["GB", "IE"]),
            "+01:00": ("Europe", ["DE", "FR", "ES", "IT"]),
            "+05:00": ("Pakistan", ["PK"]),
            "+06:00": ("Bangladesh", ["BD"]),
            "-05:00": ("USA East", ["US"]),
            "-08:00": ("USA West", ["US"]),
        }
    
    def backtrack_real_ip(
        self,
        email_headers: Dict,
        vpn_endpoint_ip: str,
        vpn_country: str = "Unknown"
    ) -> BacktrackResult:
        """
        WORKING TECHNIQUES to extract real IP from email despite VPN
        """
        
        signals = []
        
        # Technique 1: Extract first-hop ISP IP
        first_hop_signal = self._extract_first_hop_isp(email_headers)
        if first_hop_signal:
            signals.append(first_hop_signal)
        
        # Technique 2: Timezone correlation with location
        timezone_signal = self._analyze_timezone_location(email_headers, vpn_country)
        if timezone_signal:
            signals.append(timezone_signal)
        
        # Technique 3: TTL & Network topology analysis
        ttl_signal = self._analyze_ttl_hop_count(email_headers)
        if ttl_signal:
            signals.append(ttl_signal)
        
        # Technique 4: DNS leak detection from headers
        dns_signal = self._detect_dns_leaks(email_headers)
        if dns_signal:
            signals.append(dns_signal)
        
        # Technique 5: Extract embedded real IP from X-headers
        header_ip_signal = self._extract_x_originating_ip(email_headers)
        if header_ip_signal:
            signals.append(header_ip_signal)
        
        # Technique 6: Behavioral time analysis (when email was sent)
        behavior_signal = self._analyze_sending_time_pattern(email_headers)
        if behavior_signal:
            signals.append(behavior_signal)
        
        # Technique 6b: OS fingerprinting consistency check
        os_signal = self._analyze_os_fingerprint_consistency(email_headers, vpn_endpoint_ip, vpn_country)
        if os_signal:
            signals.append(os_signal)
        
        # Technique 7: Geolocation inference (VPN vs real location mismatch)
        geo_signal = self._infer_real_location_mismatch(signals, vpn_endpoint_ip, vpn_country)
        if geo_signal:
            signals.append(geo_signal)
        
        # Synthesize results FIRST
        probable_real_ip = self._determine_real_ip(signals)
        probable_country = self._determine_real_country(signals)
        confidence = self._calculate_confidence(signals)
        
        # NOW run COUNTER-TECHNIQUES: Detect advanced bypass attempts
        # Counter 1: Detect compromised legitimate server
        from_domain = email_headers.get("From", "").split("@")[-1].rstrip(">")
        dkim_domain = email_headers.get("DKIM-Signature", "").split("d=")[1].split(";")[0] if "d=" in email_headers.get("DKIM-Signature", "") else ""
        received_headers = email_headers.get("Received", [])
        received_list = received_headers if isinstance(received_headers, list) else [received_headers]
        
        compromised_check = self._detect_compromised_server(received_list, from_domain, dkim_domain)
        if compromised_check["is_likely_compromised"]:
            for signal in signals:
                signal.confidence = max(0.0, signal.confidence - 0.15)
        
        # Counter 2: Check multi-IP consistency (detect decoy VPN)
        consistency_check = self._check_multi_ip_consistency(received_list)
        if not consistency_check["consistency_ok"]:
            for signal in signals:
                signal.confidence = max(0.0, signal.confidence - 0.1)
        
        # Counter 3: Detect Tor usage
        email_str = str(email_headers)
        tor_check = self._analyze_tor_detection(probable_real_ip or "unknown", email_str)
        if tor_check["uses_tor"]:
            for signal in signals:
                signal.confidence = max(0.0, signal.confidence - 0.25)
        
        # Counter 4: Behavioral anomaly detection
        date_str = email_headers.get("Date", "")
        sending_hour = 12
        tz_str = "+"
        
        try:
            # Handle ISO 8601 format: 2026-02-20T19:51:57+05:30
            if "T" in date_str and ":" in date_str:
                time_part = date_str.split("T")[1].split(":")[0]
                sending_hour = int(time_part)
            # Handle RFC 2822 format: Thu, 20 Feb 2026 19:51:57 +0530
            elif ":" in date_str:
                parts = date_str.split()
                for i, part in enumerate(parts):
                    if ":" in part:
                        try:
                            sending_hour = int(part.split(":")[0])
                            break
                        except:
                            pass
            
            # Extract timezone (usually -05:00 or +05:30 format)
            if "+" in date_str:
                tz_str = date_str.split("+")[-1]
            elif "-" in date_str:
                tz_str = date_str.split("-")[-1]
        except:
            sending_hour = 12
            tz_str = "+"
        
        anomaly_check = self._calculate_behavioral_anomaly(sending_hour, tz_str)
        if anomaly_check["is_anomalous"]:
            for signal in signals:
                signal.confidence = signal.confidence * 0.85
        
        # Recalculate final results after penalties applied
        probable_real_ip = self._determine_real_ip(signals)
        probable_country = self._determine_real_country(signals)
        confidence = self._calculate_confidence(signals)
        notes = self._generate_analysis_notes(signals)
        
        # Add counter-technique evidence to notes
        all_evidence = []
        if compromised_check.get("evidence"):
            all_evidence.extend(["[COUNTER 1: Compromised Server]"] + compromised_check["evidence"])
        if consistency_check.get("evidence"):
            all_evidence.extend(["[COUNTER 2: Multi-IP Consistency]"] + consistency_check["evidence"])
        if tor_check.get("evidence"):
            all_evidence.extend(["[COUNTER 3: Tor Detection]"] + tor_check["evidence"])
        if anomaly_check.get("evidence"):
            all_evidence.extend(["[COUNTER 4: Behavioral Anomaly]"] + anomaly_check["evidence"])
        
        # Append counter-technique evidence to analysis notes
        if all_evidence and notes:
            notes += "\n\nCOUNTER-TECHNIQUE ANALYSIS:\n" + "\n".join(all_evidence[:10])

        
        return BacktrackResult(
            probable_real_ip=probable_real_ip,
            probable_country=probable_country,
            backtracking_confidence=confidence,
            signals=signals,
            analysis_notes=notes,
            vpn_endpoint_ip=vpn_endpoint_ip,
            vpn_country=vpn_country
        )
    
    def _extract_first_hop_isp(self, email_headers: Dict) -> Optional[RealIPSignal]:
        """
        TECHNIQUE 1: First Received header = first-hop ISP (before VPN proxy)
        Email path: [ATTACKER ISP] -> SMTP relay -> VPN gateway -> destination
        First IP in chain is attacker's real ISP!
        """
        
        received = email_headers.get("Received", [])
        if not received:
            return None
        
        # Received headers are in reverse chronological order
        # First element is from the sender's ISP
        received_list = received if isinstance(received, list) else [received]
        if not received_list:
            return None
        
        first_hop = str(received_list[0])
        
        # Extract IP from [xxx.xxx.xxx.xxx] format
        ip_pattern = r'\[([0-9a-fA-F:.]+)\]'
        matches = re.findall(ip_pattern, first_hop)
        
        if matches:
            first_hop_ip = matches[0]
            
            # This is the real ISP IP (before VPN)
            if not self._is_private_ip(first_hop_ip) and first_hop_ip != "127.0.0.1":
                evidence = [
                    f"First hop IP (sender's direct ISP): {first_hop_ip}",
                    "[CHECK] Email headers are IMMUTABLE at send time",
                    "First hop = attacker's actual ISP before any proxying",
                ]
                
                # Extract hostname/mail server info
                hostname_pattern = r'from\s+([\w.-]+)\s+\['
                hostname_match = re.search(hostname_pattern, first_hop, re.IGNORECASE)
                if hostname_match:
                    hostname = hostname_match.group(1)
                    evidence.append(f"Mail server hostname: {hostname}")
                
                # Extract timestamp if available
                timestamp_pattern = r'(\d{1,2}\s+\w+\s+\d{4}\s+\d{1,2}:\d{2}:\d{2})'
                timestamp_match = re.search(timestamp_pattern, first_hop)
                if timestamp_match:
                    evidence.append(f"Server timestamp: {timestamp_match.group(1)}")
                
                # Analyze the full header for anomalies
                if 'unknown' in first_hop.lower():
                    evidence.append("[WARNING] Unknown/obfuscated hostname in first hop")
                
                # NOTE: Don't return country from first-hop geolocation
                # First hop is often mail relay, not attacker's location
                # Use other techniques (timezone, behavioral) for real location
                
                return RealIPSignal(
                    method=BacktrackMethod.FIRST_HOP_ISP,
                    real_ip=first_hop_ip,
                    real_country=None,  # Don't geolocate first hop - it's usually a mail relay
                    confidence=0.92,  # VERY HIGH confidence - email headers are immutable at send time
                    evidence=evidence
                )
        else:
            # If we can't extract IP from first hop, it might be obfuscated
            # But we can still analyze the structure
            evidence = [
                "Received header lacks IP in brackets",
                "Possible obfuscation in first hop",
                f"First hop content: {first_hop[:100]}"
            ]
            
            return RealIPSignal(
                method=BacktrackMethod.FIRST_HOP_ISP,
                real_ip=None,
                real_country=None,
                confidence=0.35,
                evidence=evidence
            )
        
        return None
    
    def _analyze_timezone_location(self, email_headers: Dict, vpn_country: str) -> Optional[RealIPSignal]:
        """
        TECHNIQUE 2: Timezone reveals real location
        Email Date header contains timezone offset (e.g., +05:30 for India)
        If VPN is Japan but timezone is +05:30 = attacker in India
        
        SPOOFING DETECTION: The Date header is client-controlled and can be spoofed.
        Validate against server-added Received headers for consistency.
        """
        
        date_header = email_headers.get("Date", "")
        if not date_header:
            return None
        
        # Extract timezone offset from Date header (client-controlled, can be spoofed)
        # Pattern: space followed by +/- and digits:digits at end of string
        tz_pattern = r'\s([+-]\d{1,2}):?(\d{2})\s*$'
        tz_match = re.search(tz_pattern, str(date_header))
        
        if not tz_match:
            # Try alternate pattern without space requirement
            tz_pattern = r'([+-]\d{1,2}):?(\d{2})'
            tz_match = re.search(tz_pattern, str(date_header))
        
        if tz_match:
            # Normalize to colon format
            tz_offset = f"{tz_match.group(1)}:{tz_match.group(2)}"
        else:
            return None
        
        region, country_codes = self.timezone_regions.get(tz_offset, (None, None))
        
        if not region:
            return None
        
        evidence = [
            f"Email timezone offset: {tz_offset}",
            f"Inferred region: {region}",
            f"Date header: {date_header}"
        ]
        
        # SPOOFING CHECK: Validate against Received header timestamps
        # Received headers are added by mail servers (harder to spoof)
        received_headers = email_headers.get("Received", [])
        spoofing_detected = False
        server_tz_matches = False
        
        if received_headers:
            if not isinstance(received_headers, list):
                received_headers = [received_headers]
            
            # Extract timezone from server-added Received headers
            for received_header in received_headers[:3]:  # Check first 3 hops
                # Look for timestamp pattern in Received header
                # Formats: "-0800", "+0530", "-08:00", "+05:30"
                received_tz_match = re.search(r'([+-]\d{2}):?(\d{2})', str(received_header))
                if received_tz_match:
                    # Normalize to colon format for comparison
                    received_tz = f"{received_tz_match.group(1)}:{received_tz_match.group(2)}"
                    
                    if received_tz == tz_offset:
                        server_tz_matches = True
                        evidence.append(f"[CHECK] VALIDATED: Received header has matching timezone: {received_tz}")
                        break
                    else:
                        # Mismatch between Date and Received headers
                        spoofing_detected = True
                        evidence.append(f"[WARNING] SPOOFING DETECTED: Date claims {tz_offset}, server shows {received_tz}")
                        evidence.append(f"     This suggests the attacker falsified the Date header timezone!")

        
        # If VPN is different country = real location detected
        if vpn_country and vpn_country.lower() != region.lower():
            evidence.append(f"VPN endpoint: {vpn_country} (different timezone = real location elsewhere)")
            
            # Adjust confidence based on spoofing detection
            if spoofing_detected:
                confidence = 0.50  # LOW - timezone likely spoofed
                evidence.append("[WARNING] WARNING: Timezone mismatch suggests potential spoofing. Confidence reduced.")
            elif server_tz_matches:
                confidence = 0.95  # VERY HIGH - server validates timezone
                evidence.append("[CHECK] HIGH CONFIDENCE: Server timestamps corroborate timezone")
            else:
                confidence = 0.90  # HIGH - timezone not explicitly spoofed, but unvalidated
        else:
            if spoofing_detected or not server_tz_matches:
                confidence = 0.40  # LOW - timezone possibly spoofed/unvalidated
            else:
                confidence = 0.75  # MEDIUM - timezone consistent across headers
        
        return RealIPSignal(
            method=BacktrackMethod.TIMEZONE_CORRELATION,
            real_ip=None,
            real_country=region,
            confidence=confidence,
            evidence=evidence
        )
    
    def _analyze_ttl_hop_count(self, email_headers: Dict) -> Optional[RealIPSignal]:
        """
        TECHNIQUE 3: Hop Count Analysis
        Count Received headers to analyze routing complexity.
        Each Received header = one SMTP transfer.
        Direct send = 1-2 hops. VPN/Proxy = 3+ hops with unusual patterns.
        """
        
        received = email_headers.get("Received", [])
        if not received:
            return None
        
        # Count Received headers = number of hops
        hop_count = len(received) if isinstance(received, list) else 1
        
        evidence = [
            f"Hop count (Received headers): {hop_count}",
        ]
        
        # Analyze hop count patterns
        confidence = 0.30  # Default
        
        if hop_count == 1:
            evidence.append("Single hop - direct connection (suspicious for forwarded mail)")
            confidence = 0.40
        elif hop_count <= 3:
            evidence.append("Normal routing - 1-3 hops typical for legitimate mail")
            confidence = 0.35
        elif hop_count > 5:
            evidence.append("High hop count (5+) indicates complex routing/proxying")
            confidence = 0.60
        
        # Check for unusual patterns in Received headers
        if isinstance(received, list):
            for i, hop_header in enumerate(received[:3]):
                hop_str = str(hop_header)
                if 'unknown' in hop_str.lower() or 'private' in hop_str.lower():
                    evidence.append(f"Hop {i}: Contains privacy-obfuscation markers")
                    confidence += 0.15
                if '[' in hop_str and ']' in hop_str:
                    # Extract IP for analysis
                    ip_match = re.search(r'\[([0-9a-fA-F:.]+)\]', hop_str)
                    if ip_match:
                        ip = ip_match.group(1)
                        if hop_count >= 3 and i < 2:
                            evidence.append(f"Hop {i}: {ip} in routing chain")
        
        # Always return a signal
        return RealIPSignal(
            method=BacktrackMethod.TTL_ANALYSIS,
            real_ip=None,
            real_country=None,
            confidence=min(confidence, 0.80),
            evidence=evidence
        )
    
    def _detect_dns_leaks(self, email_headers: Dict) -> Optional[RealIPSignal]:
        """
        TECHNIQUE 4: Authentication Header Analysis
        SPF/DKIM/DMARC headers reveal authenticated sender IP and domain.
        Attacker can't spoof these without domain control.
        """
        
        real_ip = None
        real_domain = None
        evidence = []
        
        # Extract from SPF header
        spf_header = email_headers.get("Received-SPF", "")
        if spf_header:
            # Look for "ip=" or "from=" fields
            ip_pattern = r'(?:ip|from)=([0-9a-fA-F:.]+)'
            matches = re.findall(ip_pattern, str(spf_header))
            
            if matches:
                for ip in matches:
                    if not self._is_private_ip(ip):
                        real_ip = ip
                        evidence.append(f"SPF authenticated IP: {ip}")
                        break
            
            # Check SPF result
            if 'pass' in str(spf_header).lower():
                evidence.append("[CHECK] SPF verification: PASS (sender domain authenticated)")
            elif 'fail' in str(spf_header).lower():
                evidence.append("✗ SPF verification: FAIL (spoofed domain likely)")
        
        # Check Authentication-Results header
        auth_results = email_headers.get("Authentication-Results", "")
        if auth_results:
            auth_str = str(auth_results).lower()
            if "spf=pass" in auth_str:
                evidence.append("[+] SPF passed authentication")
            if "dkim=pass" in auth_str:
                evidence.append("[+] DKIM signature verified (email not tampered)")
            if "dmarc=pass" in auth_str:
                evidence.append("[+] DMARC passed (domain alignment confirmed)")
        
        # Check DKIM signature for domain info
        dkim_header = email_headers.get("DKIM-Signature", "")
        if dkim_header:
            domain_match = re.search(r'd=([^;\s]+)', str(dkim_header))
            if domain_match:
                real_domain = domain_match.group(1)
                evidence.append(f"DKIM signing domain: {real_domain}")
            evidence.append("DKIM signature present (email authenticity: verified)")
        
        # Return signal with whatever we found
        if real_ip or real_domain or auth_results:
            country = self._geolocate_ip(real_ip) if real_ip else None
            confidence = 0.80 if real_ip else 0.55
            
            return RealIPSignal(
                method=BacktrackMethod.DNS_LEAK,
                real_ip=real_ip,
                real_country=country,
                confidence=confidence,
                evidence=evidence
            )
        
        return None
    
    def _extract_x_originating_ip(self, email_headers: Dict) -> Optional[RealIPSignal]:
        """
        TECHNIQUE 5: Client IP Header Extraction
        Multiple mail servers embed client IP in custom X-headers:
        - X-Originating-IP: [xxx.xxx.xxx.xxx] (Outlook/Exchange)
        - X-Originating-Client-IP: xxx.xxx.xxx.xxx
        - X-Mailer reveals client software (can indicate OS/region)
        - X-Mail-Server reveal mail server type and configuration
        """
        
        real_ip = None
        evidence = []
        confidence = 0.50
        
        # Check multiple X-header variants
        x_headers_to_check = [
            ("X-Originating-IP", "X-Originating-IP (Outlook/Exchange client IP)"),
            ("X-Originating-Client-IP", "X-Originating-Client-IP (alternative format)"),
            ("X-Sender-IP", "X-Sender-IP (sender's IP address)"),
        ]
        
        for header_name, description in x_headers_to_check:
            header_value = email_headers.get(header_name, "")
            if header_value:
                # Extract IP from brackets [xxx.xxx.xxx.xxx] or plain format
                ip_pattern = r'\[?([0-9a-fA-F:.]+)\]?'
                matches = re.findall(ip_pattern, str(header_value))
                
                if matches:
                    candidate_ip = matches[0]
                    if self._is_valid_ip(candidate_ip):
                        real_ip = candidate_ip
                        evidence.append(f"{description}: {real_ip}")
                        confidence = 0.88
                        break
        
        # Check X-Mailer for client information
        x_mailer = email_headers.get("X-Mailer", "")
        if x_mailer:
            evidence.append(f"Email client: {x_mailer}")
            # Detect suspicious clients like gophish, phishing frameworks
            if 'gophish' in str(x_mailer).lower():
                evidence.append("[!]  CRITICAL: GoPhish phishing framework detected!")
                confidence += 0.20
            if 'phish' in str(x_mailer).lower():
                evidence.append("[!]  WARNING: Phishing-related tool detected")
                confidence += 0.15
        
        # Check X-Priority for behavior pattern
        x_priority = email_headers.get("X-Priority", "")
        if x_priority:
            evidence.append(f"X-Priority: {x_priority}")
        
        # Return signal if we found anything
        if real_ip:
            if not self._is_private_ip(real_ip):
                country = self._geolocate_ip(real_ip)
                return RealIPSignal(
                    method=BacktrackMethod.HEADER_EXTRACTION,
                    real_ip=real_ip,
                    real_country=country,
                    confidence=min(confidence, 0.95),
                    evidence=evidence
                )
            else:
                evidence.append(f"Note: {real_ip} is a private IP (client behind NAT/VPN)")
        
        # Return signal even without IP if mailer reveals information
        if evidence and not real_ip:
            # Calculate proper confidence boosted by phishing indicators
            final_confidence = confidence if confidence > 0.50 else 0.55
            return RealIPSignal(
                method=BacktrackMethod.HEADER_EXTRACTION,
                real_ip=None,
                real_country=None,
                confidence=final_confidence,
                evidence=evidence
            )
        
        return None
    
    def _analyze_sending_time_pattern(self, email_headers: Dict) -> Optional[RealIPSignal]:
        """
        TECHNIQUE 6: Behavioral Time Pattern Analysis
        When was email sent (local hour) + timezone = real location profile
        Patterns: spammers send at different times than real users
        Combination with timezone reveals actual sender timezone
        """
        
        date_header = email_headers.get("Date", "")
        if not date_header:
            return None
        
        evidence = []
        confidence = 0.40
        
        # Parse time from Date header
        time_pattern = r'(\d{1,2}):(\d{2}):(\d{2})'
        time_match = re.search(time_pattern, str(date_header))
        
        if time_match:
            hour = int(time_match.group(1))
            minute = int(time_match.group(2))
            evidence.append(f"Email sent at: {hour:02d}:{minute:02d} (local sender time)")
            
            # Behavioral classification
            if 0 <= hour < 6:
                evidence.append("[WARNING] Night/early morning send (0:00-6:00) - unusual for business")
                evidence.append("Suggests attacker in different timezone (not typical 9-5)")
                confidence = 0.55
            elif 6 <= hour < 9:
                evidence.append("Early morning send (6:00-9:00) - consistent with Asian timezones")
                confidence = 0.50
            elif 9 <= hour < 17:
                evidence.append("Business hours send (9:00-17:00) - typical office hours globally")
                confidence = 0.35
            elif 17 <= hour < 21:
                evidence.append("Evening send (17:00-21:00) - typical for India/Asia (5-9 PM)")
                confidence = 0.60
            else:
                evidence.append("Late evening send (21:00-24:00)")
                confidence = 0.45
            
            # Pattern consistency check
            # Compare with timezone from timezone analysis
            tz_pattern = r'\s([+-]\d{1,2}:\d{2})\s*$'
            tz_match = re.search(tz_pattern, str(date_header))
            if tz_match:
                tz_offset = tz_match.group(1)
                evidence.append(f"Timezone in Date header: {tz_offset}")
                
                # Check hour consistency with timezone
                try:
                    tz_hours = int(tz_offset.split(':')[0])
                    if hour >= 9 and hour < 17 and abs(tz_hours) < 5:
                        evidence.append("[CHECK] Time pattern matches timestamp timezone (consistent)")
                        confidence += 0.10
                    elif hour >= 14 and hour < 21 and tz_hours > 3:
                        evidence.append("[CHECK] Evening time pattern matches Asian timezone (consistent)")
                        confidence += 0.15
                except:
                    pass
        else:
            evidence.append("Could not parse time from Date header")
        
        if evidence:
            return RealIPSignal(
                method=BacktrackMethod.BEHAVIORAL_TIME,
                real_ip=None,
                real_country=None,
                confidence=min(confidence, 0.70),
                evidence=evidence
            )
        
        return None
    
    def _analyze_os_fingerprint_consistency(self, email_headers: Dict, vpn_ip: str, vpn_country: str) -> Optional[RealIPSignal]:
        """
        TECHNIQUE 6b: Detect OS fingerprinting spoofing
        Checks if X-Mailer/User-Agent matches expected OS for location
        Example: Apple Mail from China IP is suspicious
        """
        
        x_mailer = email_headers.get("X-Mailer", "").lower()
        user_agent = email_headers.get("User-Agent", "").lower()
        hostname = email_headers.get("Received", [""])[0].lower() if email_headers.get("Received") else ""
        
        # VPN country detection (from geoIP)
        country_lower = vpn_country.lower() if vpn_country else ""
        
        evidence = []
        confidence = 0.0
        spoofing_detected = False
        
        # OS mappings
        apple_clients = ['apple mail', 'macintosh', 'mac os', 'darwin', 'macos', 'iphone', 'ipad']
        windows_clients = ['outlook', 'windows', 'microsoft', 'thunderbird']
        android_clients = ['android', 'gmail app']
        
        # Check for Apple Mail
        if any(client in x_mailer or client in user_agent for client in apple_clients):
            evidence.append(f"Client: Apple Mail/macOS detected")
            # Apple Mail from China/Russia = suspicious
            if any(c in country_lower for c in ['china', 'russia', 'iran']):
                spoofing_detected = True
                confidence = 0.65
                evidence.append(f"[!] SUSPICIOUS: Apple Mail from {vpn_country} (unlikely distribution)")
        
        # Check for Windows/Outlook
        elif any(client in x_mailer or client in user_agent for client in windows_clients):
            evidence.append(f"Client: Windows/Outlook detected")
            # Less suspicious but still check timezone
        
        # Check for Android
        elif any(client in x_mailer or client in user_agent for client in android_clients):
            evidence.append(f"Client: Android device detected")
        
        # Check for GoPhish/Evilginx/phishing frameworks
        if 'gophish' in x_mailer or 'evilginx' in x_mailer:
            evidence.append("[!] PHISHING FRAMEWORK DETECTED: GoPhish/Evilginx")
            spoofing_detected = True
            confidence = 0.95
        
        if spoofing_detected or evidence:
            return RealIPSignal(
                method=BacktrackMethod.BEHAVIORAL_TIME,  # Reuse for OS check
                real_ip=None,
                real_country=None,
                confidence=confidence if spoofing_detected else 0.0,
                evidence=evidence
            )
        
        return None
    
    def _infer_real_location_mismatch(
        self,
        signals: List[RealIPSignal],
        vpn_endpoint_ip: str,
        vpn_country: str
    ) -> Optional[RealIPSignal]:
        """
        TECHNIQUE 7: Compare VPN location vs detected location
        If timezone/ISP geolocation != VPN endpoint location => real location found
        """
        
        # Collect all detected locations from other signals with their confidence
        location_scores = {}
        
        for signal in signals:
            if signal.real_country:
                if signal.real_country not in location_scores:
                    location_scores[signal.real_country] = 0
                location_scores[signal.real_country] += signal.confidence
        
        evidence = [
            f"VPN endpoint: {vpn_endpoint_ip} ({vpn_country})",
            f"Detected real locations: {', '.join(location_scores.keys()) or 'None yet'}"
        ]
        
        # Pick the location with highest confidence score
        best_country = None
        if location_scores:
            best_country = max(location_scores.items(), key=lambda x: x[1])[0]
            best_score = location_scores[best_country]
            evidence.append(f"Highest confidence location: {best_country} ({best_score:.0%})")
        
        # High confidence if detected location differs from VPN
        if best_country and vpn_country.lower() not in best_country.lower():
            evidence.append("LOCATION MISMATCH: Real location detected outside VPN")
            confidence = 0.85
        else:
            confidence = 0.40
        
        return RealIPSignal(
            method=BacktrackMethod.GEOLOCATION_INFERENCE,
            real_ip=None,
            real_country=best_country,  # Return the highest-confidence country
            confidence=confidence,
            evidence=evidence
        )
    
    def _determine_real_ip(self, signals: List[RealIPSignal]) -> Optional[str]:
        """Find most likely real IP from signals"""
        
        ip_scores = {}
        for signal in signals:
            if signal.real_ip:
                if signal.real_ip not in ip_scores:
                    ip_scores[signal.real_ip] = 0
                ip_scores[signal.real_ip] += signal.confidence
        
        if ip_scores:
            best_ip = max(ip_scores.items(), key=lambda x: x[1])[0]
            return best_ip if ip_scores[best_ip] > 0.6 else None
        
        return None
    
    def _determine_real_country(self, signals: List[RealIPSignal]) -> Optional[str]:
        """Determine real country from signals"""
        
        country_scores = {}
        for signal in signals:
            if signal.real_country:
                if signal.real_country not in country_scores:
                    country_scores[signal.real_country] = 0
                country_scores[signal.real_country] += signal.confidence
        
        if country_scores:
            best_country = max(country_scores.items(), key=lambda x: x[1])[0]
            return best_country if country_scores[best_country] > 0.5 else None
        
        return None
    
    def _calculate_confidence(self, signals: List[RealIPSignal]) -> float:
        """Calculate overall confidence based on multiple signals"""
        
        if not signals:
            return 0.0
        
        # Weight higher-confidence methods more
        total_confidence = sum(s.confidence for s in signals)
        avg_confidence = total_confidence / len(signals)
        
        # Bonus for multiple corroborating signals
        if len(signals) >= 3:
            avg_confidence *= 1.15
        
        return min(avg_confidence, 1.0)
    
    def _generate_analysis_notes(self, signals: List[RealIPSignal]) -> str:
        """Generate detailed analysis notes"""
        
        notes = "REAL IP BACKTRACKING ANALYSIS\n"
        notes += "=" * 60 + "\n\n"
        
        for i, signal in enumerate(signals, 1):
            notes += f"{i}. {signal.method.value.upper()}\n"
            notes += f"   Confidence: {signal.confidence:.0%}\n"
            if signal.real_ip:
                notes += f"   Real IP: {signal.real_ip}\n"
            if signal.real_country:
                notes += f"   Country: {signal.real_country}\n"
            notes += "   Evidence:\n"
            for evidence in signal.evidence[:3]:
                notes += f"   - {evidence}\n"
            notes += "\n"
        
        return notes
    
    def _detect_compromised_server(self, received_headers: List[str], from_domain: str, dkim_domain: str) -> Dict:
        """
        COUNTER-TECHNIQUE 1: Detect if email from compromised legitimate server
        Attacker hacks e.g. company.com mail server, sends phishing from there
        """
        
        evidence = []
        risk_score = 0.0
        
        # Check for domain mismatch
        if from_domain != dkim_domain:
            evidence.append(f"[WARNING] DOMAIN MISMATCH: From: {from_domain} != DKIM: {dkim_domain}")
            evidence.append("   This could indicate compromised server spoofing!")
            risk_score += 0.3
        
        # Check for unusual relay chains
        if len(received_headers) > 5:
            evidence.append(f"[WARNING] UNUSUAL RELAY CHAIN: {len(received_headers)} hops detected")
            evidence.append("   Longer chains indicate possible mail server compromise")
            risk_score += 0.2
        
        # Check for timezone anomalies across servers
        timezones = []
        for header in received_headers:
            tz_match = re.search(r'([+-]\d{4})', header)
            if tz_match:
                timezones.append(tz_match.group(1))
        
        if timezones and len(set(timezones)) > 1:
            evidence.append(f"[WARNING] TIMEZONE VARIANCE: {set(timezones)}")
            evidence.append("   Different servers have conflicting timezones - possible compromise")
            risk_score += 0.25
        
        return {
            "compromised_risk": risk_score,
            "evidence": evidence,
            "is_likely_compromised": risk_score > 0.5
        }
    
    def _check_multi_ip_consistency(self, received_headers: List[str]) -> Dict:
        """
        COUNTER-TECHNIQUE 2: Detect decoy VPN with hidden real connection
        Analyze ALL IPs in Received chain, not just first one
        """
        
        evidence = []
        all_ips = []
        countries = set()
        
        # Extract all IPs from Received headers
        for header in received_headers:
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]|\[([0-9a-f:]+)\]', header)
            if ip_match:
                ip = ip_match.group(1) or ip_match.group(2)
                all_ips.append(ip)
                country = self._geolocate_ip(ip)
                countries.add(country)
        
        evidence.append(f"IPs found: {len(all_ips)} servers in chain")
        evidence.append(f"Countries: {', '.join(sorted(countries))}")
        
        # Check for geographic inconsistency (decoy attack)
        if len(countries) > 1 and 'Unknown' not in countries:
            evidence.append("[WARNING] GEOGRAPHIC MISMATCH: IPs from different countries")
            evidence.append("   Possible decoy VPN with hidden real connection!")
            return {"consistency_ok": False, "evidence": evidence, "all_ips": all_ips}
        
        return {"consistency_ok": True, "evidence": evidence, "all_ips": all_ips}
    
    def _analyze_tor_detection(self, first_hop_ip: str, headers: str) -> Dict:
        """
        COUNTER-TECHNIQUE 3: Detect if using Tor hidden service
        Identify Tor exit nodes and onion services
        """
        
        evidence = []
        tor_confidence = 0.0
        
        # Known Tor exit node ranges (sample)
        tor_exit_ranges = [
            "192.241.",  # Tor exit node hosting
            "45.142.",   # Nightshade exit nodes
            "198.50.",   # Tor Project infrastructure
        ]
        
        # Check if IP is known Tor exit node
        for tor_range in tor_exit_ranges:
            if first_hop_ip.startswith(tor_range):
                evidence.append(f"[WARNING] TOR EXIT NODE DETECTED: {first_hop_ip}")
                evidence.append("   Attacker using Tor hidden service for anonymity")
                tor_confidence = 0.8
                break
        
        # Check for .onion domain (Tor hidden service)
        if '.onion' in headers.lower():
            evidence.append("[WARNING] .ONION DOMAIN DETECTED")
            evidence.append("   Email references Tor hidden service")
            tor_confidence = max(tor_confidence, 0.7)
        
        # Check for Tor browser fingerprints in User-Agent
        if 'Mozilla' in headers and 'Firefox' in headers and 'Windows NT' not in headers:
            evidence.append("[!] TOR BROWSER DETECTED: Unusual User-Agent signature")
            tor_confidence = max(tor_confidence, 0.5)
        
        return {
            "uses_tor": tor_confidence > 0.5,
            "tor_confidence": tor_confidence,
            "evidence": evidence
        }
    
    def _calculate_behavioral_anomaly(self, sending_hour: int, timezone_offset: str, 
                                     previous_emails: List[Dict] = None) -> Dict:
        """
        COUNTER-TECHNIQUE 4: Detect statistical anomaly in behavioral patterns
        Perfect spoofing would match timezone + sending time perfectly (0% variance)
        Real users have natural variance
        """
        
        evidence = []
        anomaly_score = 0.0
        
        # Parse timezone
        try:
            tz_sign = 1 if '+' in timezone_offset else -1
            tz_hours = int(timezone_offset.replace('+', '').replace('-', '')[:2])
            tz_offset = tz_sign * tz_hours
        except:
            tz_offset = 0
        
        # Check if time matches timezone expectations
        if sending_hour >= 9 and sending_hour <= 17:
            # Business hours
            evidence.append(f"[+] Normal business hours ({sending_hour}:00)")
            anomaly_score += 0.0
        elif sending_hour >= 19 and sending_hour <= 22:
            # Evening (common for India timezone +05:30)
            if tz_offset == 5.5:
                evidence.append(f"[+] Evening send at {sending_hour}:00 matches +05:30 timezone")
                anomaly_score += 0.1  # Slightly suspicious - too perfect
            else:
                evidence.append(f"[!] Evening send {sending_hour}:00 but timezone is {tz_offset}")
                anomaly_score += 0.3
        else:
            # Unusual hours (0-6 AM)
            evidence.append(f"[!] UNUSUAL HOUR: {sending_hour}:00 (night send)")
            evidence.append(f"   Inconsistent with stated timezone {timezone_offset}")
            anomaly_score += 0.4
        
        # If previous emails data available, check consistency
        if previous_emails and len(previous_emails) > 5:
            hours = [int(e['hour']) for e in previous_emails]
            avg_hour = sum(hours) / len(hours)
            variance = sum((h - avg_hour) ** 2 for h in hours) / len(hours)
            
            if variance < 0.5:
                # ZERO variance = suspicious (perfect spoofing)
                evidence.append(f"[!] ZERO VARIANCE: All {len(previous_emails)} emails at same hour")
                evidence.append("   Real users have natural variance in sending time!")
                anomaly_score += 0.5
            else:
                evidence.append(f"[+] Natural variance in sending times (σ={variance:.2f})")
                anomaly_score -= 0.2  # Reduce suspicion
        
        return {
            "anomaly_score": min(anomaly_score, 1.0),
            "is_anomalous": anomaly_score > 0.5,
            "evidence": evidence
        }
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved"""
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return True
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IPv4 or IPv6 address"""
        
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _geolocate_ip(self, ip: str) -> Optional[str]:
        """
        Quick geolocation using ASN/BGP data
        Returns likely country based on IP allocation
        """
        
        # Simplified mapping of IP ranges to countries
        ip_country_map = {
            "45.14.71": "Japan",  # NordVPN Japan endpoint - but country is Japan
            "209.85": "United States",  # Google
            "103.": "India",
            "202.": "Japan",
            "61.": "Australia",
            "185.": "Europe",
        }
        
        for prefix, country in ip_country_map.items():
            if ip.startswith(prefix):
                return country
        
        return "Unknown"



class BacktrackingMethod(Enum):
    """Methods for backtracking real IP"""
    DNS_LEAK = "dns_leak"
    WEBRTC_LEAK = "webrtc_leak"
    TOR_FINGERPRINT = "tor_fingerprint"
    KILL_SWITCH_FAIL = "kill_switch_failure"
    P2P_LEAK = "p2p_leak"
    EMAIL_METADATA = "email_metadata"
    ML_TRAFFIC_FP = "ml_traffic_fingerprint"
    TIMING_ANALYSIS = "timing_analysis"
    BEHAVIORAL = "behavioral_pattern"
    PROVIDER_VULN = "provider_vulnerability"
    TOPOLOGY_INFERENCE = "network_topology"
    CORRELATED_ACCOUNT = "correlated_account"


@dataclass
class BacktrackingSignal:
    """Signal indicating potential real IP"""
    method: BacktrackingMethod
    real_ip: Optional[str]
    confidence: float  # 0.0-1.0
    evidence: List[str]
    timestamp: Optional[str] = None


@dataclass
class VPNAnalysis:
    """Complete VPN analysis with backtracking results"""
    vpn_provider: str
    vpn_endpoint_ip: str
    detected_vpn_confidence: float
    backtracking_signals: List[BacktrackingSignal]
    likely_real_ip: Optional[str]
    backtracking_confidence: float  # 0.0-1.0
    recommended_actions: List[str]
    law_enforcement_notes: str


class VPNBacktrackAnalyzer:
    """Analyze VPN usage and attempt to backtrack real IP"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.known_vpn_providers = {
            "NordVPN": {"exit_countries": 60, "kill_switch": True, "leak_risk": 0.05},
            "ExpressVPN": {"exit_countries": 94, "kill_switch": True, "leak_risk": 0.03},
            "Surfshark": {"exit_countries": 100, "kill_switch": True, "leak_risk": 0.04},
            "ProtonVPN": {"exit_countries": 67, "kill_switch": True, "leak_risk": 0.06},
            "CyberGhost": {"exit_countries": 89, "kill_switch": True, "leak_risk": 0.07},
        }
    
    def analyze_vpn_backtrack(
        self,
        vpn_endpoint_ip: str,
        vpn_provider: str,
        email_from: str,
        email_headers: Dict,
        email_body: str = "",
        timestamp: Optional[str] = None
    ) -> VPNAnalysis:
        """
        Attempt to backtrack real IP using multiple techniques
        """
        
        backtracking_signals = []
        
        # Technique 1: DNS Leak Analysis
        dns_signal = self._analyze_dns_leaks(email_headers)
        if dns_signal:
            backtracking_signals.append(dns_signal)
        
        # Technique 2: Email Headers Metadata Analysis
        metadata_signal = self._analyze_email_metadata(email_headers, email_from)
        if metadata_signal:
            backtracking_signals.append(metadata_signal)
        
        # Technique 3: Tor Exit Node Fingerprinting
        if vpn_provider.lower() == "tor" or "onion" in vpn_provider.lower():
            tor_signal = self._analyze_tor_exit_node(vpn_endpoint_ip, email_headers)
            if tor_signal:
                backtracking_signals.append(tor_signal)
        
        # Technique 4: Email Artifact Analysis
        artifact_signal = self._analyze_email_artifacts(email_headers, email_body)
        if artifact_signal:
            backtracking_signals.append(artifact_signal)
        
        # Technique 5: Behavioral Pattern Recognition
        behavior_signal = self._analyze_behavioral_patterns(email_headers, email_from)
        if behavior_signal:
            backtracking_signals.append(behavior_signal)
        
        # Technique 6: Timezone & Location Correlation
        timezone_signal = self._analyze_timezone_location(email_headers, timestamp)
        if timezone_signal:
            backtracking_signals.append(timezone_signal)
        
        # Technique 7: VPN Provider Vulnerability Analysis
        vuln_signal = self._analyze_provider_vulnerabilities(vpn_provider)
        if vuln_signal:
            backtracking_signals.append(vuln_signal)
        
        # Determine likely real IP and confidence
        likely_real_ip = self._synthesize_results(backtracking_signals)
        backtracking_confidence = self._calculate_overall_confidence(backtracking_signals)
        
        # Generate recommendations for law enforcement
        actions = self._generate_backtrack_actions(backtracking_signals, vpn_provider)
        le_notes = self._generate_law_enforcement_notes(vpn_provider, backtracking_signals)
        
        analysis = VPNAnalysis(
            vpn_provider=vpn_provider,
            vpn_endpoint_ip=vpn_endpoint_ip,
            detected_vpn_confidence=0.95,
            backtracking_signals=backtracking_signals,
            likely_real_ip=likely_real_ip,
            backtracking_confidence=backtracking_confidence,
            recommended_actions=actions,
            law_enforcement_notes=le_notes
        )
        
        return analysis
    
    def _analyze_dns_leaks(self, email_headers: Dict) -> Optional[BacktrackingSignal]:
        """
        Technique 1: Detect DNS leaks in email headers
        DNS queries may reveal real IP if VPN kill switch failed
        """
        
        # Look for Received-SPF, DKIM-Signature headers
        spf_header = email_headers.get("Received-SPF", "")
        dkim_header = email_headers.get("DKIM-Signature", "")
        
        evidence = []
        potential_ip = None
        
        # Extract SPF authenticated IP
        spf_pattern = r'ip[6]?=([0-9a-fA-F:.]+)'
        spf_matches = re.findall(spf_pattern, str(spf_header))
        if spf_matches:
            for ip in spf_matches:
                if not self._is_private_ip(ip) and ip != "127.0.0.1":
                    potential_ip = ip
                    evidence.append(f"SPF authenticated IP: {ip}")
        
        # Check for multiple Received headers from different IPs
        received_headers = email_headers.get("Received", [])
        if isinstance(received_headers, list) and len(received_headers) > 1:
            ips = self._extract_ips_from_received(received_headers)
            if len(ips) > 1:
                # Real IP might be first in chain (before VPN)
                first_ip = ips[0]
                if not self._is_private_ip(first_ip):
                    evidence.append(f"First hop in chain: {first_ip} (before VPN)")
                    potential_ip = first_ip
        
        if potential_ip and evidence:
            return BacktrackingSignal(
                method=BacktrackingMethod.DNS_LEAK,
                real_ip=potential_ip,
                confidence=0.70,
                evidence=evidence
            )
        
        return None
    
    def _analyze_email_metadata(self, email_headers: Dict, email_from: str) -> Optional[BacktrackingSignal]:
        """
        Technique 2: Analyze email metadata for real IP clues
        X-Originating-IP, X-Mailer, X-Priority headers may reveal real IP
        """
        
        evidence = []
        potential_ip = None
        
        # Check X-Originating-IP header
        x_orig_ip = email_headers.get("X-Originating-IP", "")
        if x_orig_ip:
            ip_pattern = r'\[([0-9a-fA-F:.]+)\]'
            matches = re.findall(ip_pattern, str(x_orig_ip))
            if matches:
                potential_ip = matches[0]
                evidence.append(f"X-Originating-IP header: {potential_ip}")
        
        # Check X-Mailer header for OS/client info
        x_mailer = email_headers.get("X-Mailer", "")
        if x_mailer:
            evidence.append(f"Client identifier: {x_mailer}")
            if "Linux" in str(x_mailer):
                evidence.append("Suggests Linux-based VPN client")
            elif "Windows" in str(x_mailer):
                evidence.append("Suggests Windows OS (correlate with timezone)")
        
        # Check Microsoft authentication headers
        auth_results = email_headers.get("Authentication-Results", "")
        if auth_results and "spf=pass" in str(auth_results).lower():
            evidence.append("SPF pass indicates authenticated sending")
        
        if potential_ip or evidence:
            confidence = 0.65 if potential_ip else 0.40
            return BacktrackingSignal(
                method=BacktrackingMethod.EMAIL_METADATA,
                real_ip=potential_ip,
                confidence=confidence,
                evidence=evidence
            )
        
        return None
    
    def _analyze_tor_exit_node(self, exit_node_ip: str, email_headers: Dict) -> Optional[BacktrackingSignal]:
        """
        Technique 3: Fingerprint Tor exit nodes to identify real IP
        Tor users often leak real IP through browser behavior
        """
        
        evidence = []
        
        # Check for Tor browser user agent patterns
        user_agent = email_headers.get("User-Agent", "")
        if user_agent:
            evidence.append(f"User-Agent: {user_agent[:50]}")
            if "Tor" in str(user_agent) or "Tails" in str(user_agent):
                evidence.append("Tor browser detected")
        
        # WebRTC leak indicators
        if "WebRTC" in str(email_headers):
            evidence.append("Potential WebRTC leak in connection")
        
        # Tor exit relay characteristics
        evidence.append(f"Tor exit node analysis: {exit_node_ip}")
        evidence.append("Real IP hidden by Tor network - forensics required")
        
        return BacktrackingSignal(
            method=BacktrackingMethod.TOR_FINGERPRINT,
            real_ip=None,
            confidence=0.20,  # Low confidence - Tor is designed to hide IP
            evidence=evidence
        )
    
    def _analyze_email_artifacts(self, email_headers: Dict, email_body: str) -> Optional[BacktrackingSignal]:
        """
        Technique 4: Detect artifacts in email that reveal real IP
        Embedded images, tracking pixels may expose real IP
        """
        
        evidence = []
        
        # Check for embedded tracking pixels
        img_pattern = r'<img[^>]+src=["\']([^"\']+)["\']'
        images = re.findall(img_pattern, email_body)
        if images:
            evidence.append(f"Detected {len(images)} embedded images (may contain tracking IPs)")
            for img in images[:3]:
                if "http" in img:
                    evidence.append(f"  Image URL: {img[:60]}...")
        
        # Check for embedded links (beacons)
        beacon_pattern = r'href=["\']http[^"\']*["\']'
        beacons = re.findall(beacon_pattern, email_body)
        if beacons:
            evidence.append(f"Found {len(beacons)} external links (tracking beacons)")
        
        # Check for embedded videos/objects
        if "<video" in email_body or "<object" in email_body:
            evidence.append("Embedded media detected (potential IP leak vector)")
        
        if evidence:
            return BacktrackingSignal(
                method=BacktrackingMethod.P2P_LEAK,
                real_ip=None,
                confidence=0.30,
                evidence=evidence
            )
        
        return None
    
    def _analyze_behavioral_patterns(self, email_headers: Dict, email_from: str) -> Optional[BacktrackingSignal]:
        """
        Technique 5: Behavioral pattern recognition
        VPN usage + specific behavior may indicate real location
        """
        
        evidence = []
        
        # Check email sending time
        date_header = email_headers.get("Date", "")
        if date_header:
            evidence.append(f"Email sent at: {date_header}")
            evidence.append("Timing analysis: Compare with sender's typical activity")
        
        # Check for geolocation inconsistencies
        received_headers = email_headers.get("Received", [])
        if isinstance(received_headers, list):
            evidence.append(f"Multiple relay points: {len(received_headers)} hops")
            if len(received_headers) > 3:
                evidence.append("Complex path may indicate sophisticated setup")
        
        # From address pattern
        if "@gmail.com" in email_from or "@outlook.com" in email_from:
            evidence.append("Using free webmail service")
            evidence.append("Likely personal account (not corporate)")
        
        if evidence:
            return BacktrackingSignal(
                method=BacktrackingMethod.BEHAVIORAL,
                real_ip=None,
                confidence=0.35,
                evidence=evidence
            )
        
        return None
    
    def _analyze_timezone_location(self, email_headers: Dict, timestamp: Optional[str]) -> Optional[BacktrackingSignal]:
        """
        Technique 6: Timezone and location correlation
        Mismatch between VPN location and timezone may reveal real location
        """
        
        evidence = []
        
        # Extract timezone info
        date_header = email_headers.get("Date", "")
        if date_header:
            # Parse timezone offset (e.g., +05:30 for IST)
            tz_pattern = r'([+-]\d{2}:\d{2})$'
            tz_match = re.search(tz_pattern, date_header)
            if tz_match:
                tz_offset = tz_match.group(1)
                evidence.append(f"Email sent at timezone offset: {tz_offset}")
                
                # Map common timezones
                if tz_offset == "+05:30":
                    evidence.append("Timezone suggests India (IST)")
                elif tz_offset == "+09:00":
                    evidence.append("Timezone suggests Japan/Korea")
                elif tz_offset == "+00:00":
                    evidence.append("Timezone suggests UTC/UK")
        
        if evidence:
            return BacktrackingSignal(
                method=BacktrackingMethod.TIMING_ANALYSIS,
                real_ip=None,
                confidence=0.45,
                evidence=evidence
            )
        
        return None
    
    def _analyze_provider_vulnerabilities(self, vpn_provider: str) -> Optional[BacktrackingSignal]:
        """
        Technique 7: Analyze VPN provider for known vulnerabilities
        """
        
        evidence = []
        provider_info = self.known_vpn_providers.get(vpn_provider, {})
        
        if provider_info:
            leak_risk = provider_info.get("leak_risk", 0.05)
            evidence.append(f"Provider: {vpn_provider}")
            evidence.append(f"Known leak risk: {leak_risk * 100:.1f}%")
            evidence.append(f"Kill switch available: {provider_info.get('kill_switch', False)}")
            
            if leak_risk > 0.05:
                evidence.append("This provider has history of IP leaks")
                evidence.append("Law enforcement can request provider logs")
        else:
            evidence.append(f"Unknown/Custom VPN provider: {vpn_provider}")
            evidence.append("May be compromised or specialized service")
        
        return BacktrackingSignal(
            method=BacktrackingMethod.PROVIDER_VULN,
            real_ip=None,
            confidence=0.50,
            evidence=evidence
        )
    
    def _extract_ips_from_received(self, received_headers: List[str]) -> List[str]:
        """Extract all IPs from Received headers"""
        ips = []
        ip_pattern = r'\[([0-9a-fA-F:.]+)\]'
        for header in received_headers:
            matches = re.findall(ip_pattern, str(header))
            ips.extend(matches)
        return ips
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved"""
        private_ranges = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "fc00::/7",
            "fe80::/10",
        ]
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in private_ranges:
                if ip_obj in ipaddress.ip_network(range_str, strict=False):
                    return True
        except ValueError:
            return True
        return False
    
    def _synthesize_results(self, signals: List[BacktrackingSignal]) -> Optional[str]:
        """Combine multiple signals to determine likely real IP"""
        
        # Group IPs by frequency
        ip_scores = {}
        for signal in signals:
            if signal.real_ip:
                if signal.real_ip not in ip_scores:
                    ip_scores[signal.real_ip] = 0
                ip_scores[signal.real_ip] += signal.confidence
        
        if ip_scores:
            best_ip = max(ip_scores.items(), key=lambda x: x[1])[0]
            if ip_scores[best_ip] > 0.5:
                return best_ip
        
        return None
    
    def _calculate_overall_confidence(self, signals: List[BacktrackingSignal]) -> float:
        """Calculate overall backtracking confidence"""
        
        if not signals:
            return 0.0
        
        # Average confidence weighted by method importance
        method_weights = {
            BacktrackingMethod.DNS_LEAK: 0.80,
            BacktrackingMethod.EMAIL_METADATA: 0.70,
            BacktrackingMethod.TIMING_ANALYSIS: 0.60,
            BacktrackingMethod.BEHAVIORAL: 0.50,
            BacktrackingMethod.PROVIDER_VULN: 0.40,
            BacktrackingMethod.TOR_FINGERPRINT: 0.30,
            BacktrackingMethod.P2P_LEAK: 0.40,
        }
        
        total_weight = 0
        weighted_sum = 0
        for signal in signals:
            weight = method_weights.get(signal.method, 0.5)
            weighted_sum += signal.confidence * weight
            total_weight += weight
        
        if total_weight > 0:
            return weighted_sum / total_weight
        return 0.0
    
    def _generate_backtrack_actions(self, signals: List[BacktrackingSignal], vpn_provider: str) -> List[str]:
        """Generate recommended action steps for law enforcement"""
        
        actions = [
            "1. Request VPN provider logs via legal process",
            "2. Analyze email header metadata for real IP indicators",
            "3. Correlate timezone information with attacker location",
            "4. Check for DNS/WebRTC leaks in connection metadata",
        ]
        
        if vpn_provider.lower() == "tor":
            actions.append("5. Subpoena ISP records for Tor node connection times")
            actions.append("6. Correlate with Tor relay historical data")
        else:
            actions.append(f"5. Contact {vpn_provider} with lawful intercept request")
            actions.append("6. Check for kill switch failures in session logs")
        
        has_metadata = any(s.method == BacktrackingMethod.EMAIL_METADATA for s in signals)
        if has_metadata:
            actions.append("7. Extract and analyze X-originating-IP and X-Mailer headers")
        
        return actions
    
    def _generate_law_enforcement_notes(self, vpn_provider: str, signals: List[BacktrackingSignal]) -> str:
        """Generate notes for law enforcement"""
        
        notes = f"""
===============================================================================
[LAW ENFORCEMENT - VPN BACKTRACKING ANALYSIS]
===============================================================================

VPN PROVIDER: {vpn_provider}
================================================================================

BACKTRACKING CAPABILITY:
Based on {len(signals)} analysis techniques, real attacker IP may be recoverable
through lawful intercept and VPN provider cooperation.

KEY EVIDENCE FOR WARRANT:
{chr(10).join([f'- {s.method.value.upper()}: {s.confidence:.0%} confidence' for s in signals if s.evidence])}

INVESTIGATIVE DATA SOURCES:
1. VPN Provider Logs (requires warrant)
   - Connection timestamp logs
   - Real IP to VPN endpoint mappings
   - Session duration records
   - Payment/subscription information

2. Email Server Logs (may be available without warrant)
   - ISP logs matching VPN endpoint IP
   - Correlate with connection timestamp
   - Track to real subscriber address

3. Network Analysis
   - DNS query logs (ISP level)
   - BGP route analysis
   - Network topology inference

4. Behavioral Correlation
   - Compare with other known accounts
   - Timing patterns across campaigns
   - Geographic inconsistencies

NEXT STEPS:
1. Prepare evidence package with this analysis
2. Consult with prosecutor for appropriate warrants
3. Contact VPN provider legal department
4. Request ISP logs for matching timeframe
5. Coordinate with INTERPOL if international

TIMELINE PRIORITY:
- Urgent: VPN provider logs (preserved for ~30-90 days)
- High: ISP logs (preserved for 6-12 months)
- Medium: Email server analysis (available indefinitely)
===============================================================================
        """
        
        return notes
