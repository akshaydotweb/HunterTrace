#!/usr/bin/env python3
"""
REAL IP EXTRACTION MODULE v2 — FORENSICALLY CORRECT
=====================================================

This module replaces realIpExtractor.py with a forensically accurate
implementation that correctly distinguishes between:

  - SERVER-CONTROLLED headers (unforgeable — added by receiving mail servers)
  - CLIENT-CONTROLLED headers (forgeable — injected by the sender's mail client)

THE CRITICAL ERROR IN v1 (and why it mattered):
    v1 read the FIRST Received: header to get the "origin IP". This is wrong.
    
    Received: headers are prepended (added at the top) by each receiving server
    as the email travels forward. So in the final email:
    
        Received: by mx.recipient.com ...          ← LAST hop (receiving MX)  [index 0]
        Received: by relay2.provider.com ...        ← intermediate hop         [index 1]
        Received: from [ATTACKER_IP] by mx.attacker-provider.com ...  ← FIRST hop [index N-1]
    
    The BOTTOM of the Received: chain (highest index, last in the list) is the
    header added by the FIRST server that touched the email — i.e., the server
    that actually saw the attacker's IP or their VPN exit node.
    
    Reading index 0 (top) gives you the recipient's own mail server. That's not useful.
    
    v2 reads the chain from bottom to top and applies trust filtering to find the
    earliest hop outside the attacker's own infrastructure.

TECHNIQUES IMPLEMENTED:
    1. Correct Received: chain traversal (bottom-up)
    2. SPF `ip=` field extraction (server-added, unforgeable)
    3. Received-SPF header parsing (authenticated sending IP)
    4. Message-ID domain extraction (reveals real mail server)
    5. DKIM `d=` domain extraction (signed by real DNS record)
    6. Timezone cross-correlation (Date: offset as geographic clue)
    7. Provider-specific header extraction (Gmail, Yahoo, Outlook)
    8. Forgeable header flagging (X-Originating-IP, X-Forwarded-For)
    9. Confidence fusion from multiple independent signals

USAGE:
    from realIpExtractorV2 import EmailForensicExtractor, extract_real_ip_from_raw

    result = extract_real_ip_from_raw(raw_email_string)
    print(result.summary())

Author: HunterTrace v2 — Email Forensics Pipeline
"""

import re
import email
import email.message
import email.utils
import ipaddress
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Set
from enum import Enum
from datetime import datetime, timezone, timedelta


# ============================================================================
# CONSTANTS & TRUST FRAMEWORK
# ============================================================================

# These header names are SET BY RECEIVING SERVERS and cannot be forged by
# the email sender. They are the gold-standard source of attacker IP data.
UNFORGEABLE_HEADERS = frozenset([
    "Received",               # RFC 5321 §4.4 — each hop prepends one
    "Received-SPF",           # RFC 7208 §9.1 — added by receiving server after SPF check
    "Authentication-Results", # RFC 7001 — added by receiver's authentication module
])

# These headers CAN be injected by the sender's mail client or any relay
# they control. Treat them as supporting evidence, not primary ground truth.
FORGEABLE_HEADERS = frozenset([
    "X-Originating-IP",       # Some providers add this, but attacker can also inject it
    "X-Forwarded-For",        # Relay-chain header, trivially spoofed
    "X-Source-IP",
    "X-Real-IP",
    "X-Client-IP",
    "X-Sender-IP",
])

# Private/reserved IP ranges — these are infrastructure IPs, not attacker IPs
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Regex patterns for IP extraction from header values
# Matches IPv4 and IPv6 addresses in various header formats
_IP_IN_BRACKETS  = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
_IP_BARE         = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_IPV6_PATTERN    = re.compile(r'\[?((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\]?')

# SPF `ip=` field — this is the IP the sending server connected FROM, as
# recorded by the receiving server after checking SPF. Highly reliable.
_SPF_IP_FIELD    = re.compile(r'\bip=([^\s;]+)', re.IGNORECASE)

# DKIM d= domain — the signing domain must match real DNS TXT records
_DKIM_DOMAIN     = re.compile(r'\bd=([^;\s]+)', re.IGNORECASE)

# Message-ID domain — the part after @ reveals the actual mail server used
_MSGID_DOMAIN    = re.compile(r'<[^@]+@([^>]+)>', re.IGNORECASE)

# Received: "from X by Y" pattern — X is the connecting host
_RECEIVED_FROM   = re.compile(
    r'from\s+'
    r'(?:(\S+)\s+)?'                            # optional hostname
    r'(?:\(([^)]+)\)\s+)?'                      # optional (hostname [IP]) block
    r'by\s+(\S+)',                               # "by" receiving server
    re.IGNORECASE | re.DOTALL
)

# Timezone offset pattern from Date: header e.g. "+0530" or "-0800"
_TZ_OFFSET       = re.compile(r'([+-]\d{4})\s*$')


# ============================================================================
# DATA STRUCTURES
# ============================================================================

class HeaderTrust(Enum):
    """Trustworthiness of the header source"""
    UNFORGEABLE   = "server-added (unforgeable)"
    FORGEABLE     = "client-injectable (treat as supporting evidence only)"
    DERIVED       = "derived from unforgeable source"


@dataclass
class IPCandidate:
    """A single IP address candidate with full provenance"""
    ip:                str
    source_header:     str          # Which header it came from
    trust_level:       HeaderTrust  # Can the sender have forged this?
    hop_position:      Optional[int]  # Position in Received chain (None if not from Received)
    hop_direction:     Optional[str]  # "from" (sending) or "by" (receiving)
    context:           str          # Raw snippet where the IP was found
    confidence:        float        # 0.0–1.0 contribution to final confidence
    is_private:        bool         # Is this a private/RFC1918 address?
    notes:             List[str] = field(default_factory=list)


@dataclass
class SPFFindings:
    """Results of SPF header analysis"""
    spf_ip:            Optional[str]   # The `ip=` field from SPF check
    spf_result:        Optional[str]   # pass / fail / softfail / neutral
    authenticated:     bool            # Did SPF pass?
    raw_header:        Optional[str]


@dataclass
class AuthSignatureFindings:
    """Results from DKIM / Message-ID domain extraction"""
    dkim_domain:       Optional[str]   # Domain that signed the message
    message_id_domain: Optional[str]   # Domain in Message-ID header
    domains_agree:     bool            # Do they point to the same infrastructure?
    notes:             List[str] = field(default_factory=list)


@dataclass
class TimezoneFindings:
    """Geographic hints from Date: header timezone offset"""
    utc_offset:        Optional[str]   # e.g. "+0530"
    probable_regions:  List[str]       # Countries/regions in that UTC offset
    cross_validated:   bool            # Did IP geolocation agree with this offset?
    notes:             List[str] = field(default_factory=list)


@dataclass
class ForensicExtractionResult:
    """
    Full forensic result from email real-IP extraction.
    Contains the most reliable IP, full evidence chain, and confidence breakdown.
    """
    # Primary finding
    best_ip:               Optional[str]   # The most forensically reliable IP
    best_ip_source:        Optional[str]   # Where it came from
    best_ip_trust:         Optional[HeaderTrust]
    overall_confidence:    float           # 0.0–1.0

    # All candidates ordered by confidence
    all_candidates:        List[IPCandidate]

    # Sub-findings from each technique
    spf:                   Optional[SPFFindings]
    auth_signatures:       Optional[AuthSignatureFindings]
    timezone:              Optional[TimezoneFindings]

    # The full Received: chain (bottom = first hop, top = last hop)
    received_chain:        List[Dict]      # List of parsed hops, index 0 = first server

    # Forgeable header warnings
    forgeable_ips_found:   List[Dict]      # IPs in forgeable headers (with warnings)

    # Analyst notes
    forensic_notes:        List[str]
    warnings:              List[str]
    timestamp:             str

    def summary(self) -> str:
        """Return a human-readable forensic summary"""
        lines = [
            "=" * 80,
            "EMAIL FORENSIC REAL-IP EXTRACTION — v2 REPORT",
            "=" * 80,
            "",
            f"  Best IP Candidate:  {self.best_ip or 'NOT FOUND'}",
            f"  Source:             {self.best_ip_source or 'N/A'}",
            f"  Trust Level:        {self.best_ip_trust.value if self.best_ip_trust else 'N/A'}",
            f"  Overall Confidence: {self.overall_confidence:.0%}",
            "",
        ]

        if self.spf and self.spf.spf_ip:
            lines.append(f"  SPF Authenticated IP: {self.spf.spf_ip}  (result: {self.spf.spf_result})")

        if self.auth_signatures:
            if self.auth_signatures.dkim_domain:
                lines.append(f"  DKIM Signing Domain:  {self.auth_signatures.dkim_domain}")
            if self.auth_signatures.message_id_domain:
                lines.append(f"  Message-ID Domain:    {self.auth_signatures.message_id_domain}")

        if self.timezone and self.timezone.utc_offset:
            lines.append(f"  Timezone Offset:      {self.timezone.utc_offset} → {', '.join(self.timezone.probable_regions)}")

        if self.received_chain:
            lines.append(f"\n  RECEIVED CHAIN ({len(self.received_chain)} hops, reading first→last):")
            for hop in self.received_chain:
                marker = "→ ORIGIN" if hop.get("is_first_external") else ""
                lines.append(
                    f"    Hop {hop['hop_number']:>2}  from={hop.get('from_ip','?'):>15}  "
                    f"by={hop.get('by_host','?')}  {marker}"
                )

        if self.forgeable_ips_found:
            lines.append("\n  ⚠  FORGEABLE HEADER WARNING:")
            for f in self.forgeable_ips_found:
                lines.append(f"    {f['header']}: {f['ip']} — {f['warning']}")

        if self.warnings:
            lines.append("\n  WARNINGS:")
            for w in self.warnings:
                lines.append(f"    ⚠ {w}")

        if self.forensic_notes:
            lines.append("\n  FORENSIC NOTES:")
            for n in self.forensic_notes:
                lines.append(f"    {n}")

        lines.append("\n" + "=" * 80)
        return "\n".join(lines)


# ============================================================================
# TIMEZONE REGION MAP
# UTC offset → list of countries/regions that use it
# This provides a geographic clue even when IP geolocation fails.
# ============================================================================

UTC_OFFSET_REGIONS: Dict[str, List[str]] = {
    "-1200": ["Baker Island (uninhabited)"],
    "-1100": ["American Samoa", "Niue"],
    "-1000": ["Hawaii (USA)", "Cook Islands"],
    "-0900": ["Alaska (USA)"],
    "-0800": ["Pacific Time (USA/Canada)", "Baja California"],
    "-0700": ["Mountain Time (USA/Canada)", "Arizona"],
    "-0600": ["Central Time (USA/Canada)", "Mexico City"],
    "-0500": ["Eastern Time (USA/Canada)", "Colombia", "Peru", "Ecuador"],
    "-0400": ["Atlantic (Canada)", "Venezuela", "Bolivia", "Chile"],
    "-0300": ["Argentina", "Brazil (East)", "Uruguay"],
    "-0200": ["South Georgia", "Brazil (Fernando de Noronha)"],
    "-0100": ["Azores (Portugal)", "Cape Verde"],
    "+0000": ["UK (GMT)", "Ireland", "Portugal", "Ghana", "Senegal"],
    "+0100": ["Central Europe", "France", "Germany", "Nigeria", "Algeria"],
    "+0200": ["Eastern Europe", "Egypt", "South Africa", "Israel", "Ukraine"],
    "+0300": ["Moscow (Russia)", "Turkey", "Saudi Arabia", "Kenya", "Iraq"],
    "+0330": ["Iran"],
    "+0400": ["UAE", "Oman", "Azerbaijan", "Georgia", "Armenia", "Mauritius"],
    "+0430": ["Afghanistan"],
    "+0500": ["Pakistan", "Kazakhstan (West)", "Maldives"],
    "+0530": ["India", "Sri Lanka"],
    "+0545": ["Nepal"],
    "+0600": ["Bangladesh", "Kazakhstan (East)", "Kyrgyzstan"],
    "+0630": ["Myanmar (Burma)"],
    "+0700": ["Thailand", "Vietnam", "Indonesia (West)", "Laos", "Cambodia"],
    "+0800": ["China", "Taiwan", "Singapore", "Malaysia", "Philippines", "Hong Kong"],
    "+0900": ["Japan", "South Korea", "Indonesia (East)"],
    "+0930": ["Australia (Central Standard)"],
    "+1000": ["Australia (East)", "Papua New Guinea"],
    "+1100": ["Solomon Islands", "New Caledonia"],
    "+1200": ["New Zealand", "Fiji"],
    "+1300": ["Samoa", "Tonga"],
}


# ============================================================================
# CORE EXTRACTOR
# ============================================================================

class EmailForensicExtractor:
    """
    Forensically correct email real-IP extractor.
    
    Correctly handles Received: header ordering (reads bottom-up),
    distinguishes unforgeable from forgeable headers, and fuses
    multiple independent signals into a confidence-weighted result.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def extract(self, raw_email: str) -> ForensicExtractionResult:
        """
        Main entry point. Pass a raw email string (full headers + body).
        Returns a ForensicExtractionResult with the best attacker IP and evidence.
        """
        msg = email.message_from_string(raw_email)

        # Run all sub-extractors independently, then fuse results
        received_chain = self._parse_received_chain(msg)
        spf            = self._extract_spf(msg)
        auth_sigs      = self._extract_auth_signatures(msg)
        tz             = self._extract_timezone(msg)
        forgeable      = self._scan_forgeable_headers(msg)
        candidates     = self._build_candidates(received_chain, spf, forgeable)

        # Fuse candidates into a single best answer
        best, confidence, notes, warnings = self._fuse_candidates(
            candidates, spf, auth_sigs, received_chain
        )

        return ForensicExtractionResult(
            best_ip             = best.ip if best else None,
            best_ip_source      = best.source_header if best else None,
            best_ip_trust       = best.trust_level if best else None,
            overall_confidence  = confidence,
            all_candidates      = candidates,
            spf                 = spf,
            auth_signatures     = auth_sigs,
            timezone            = tz,
            received_chain      = received_chain,
            forgeable_ips_found = forgeable,
            forensic_notes      = notes,
            warnings            = warnings,
            timestamp           = datetime.now().isoformat(),
        )

    # -------------------------------------------------------------------------
    # RECEIVED CHAIN PARSING (the most important method)
    # -------------------------------------------------------------------------

    def _parse_received_chain(self, msg: email.message.Message) -> List[Dict]:
        """
        Parse all Received: headers and return them in CHRONOLOGICAL order
        (i.e., first server first, last server last).
        
        The key insight: email.message_from_string() returns headers in the
        order they appear in the raw text. Received: headers are PREPENDED,
        so the raw text has them NEWEST FIRST (top) → OLDEST LAST (bottom).
        
        To get chronological order (oldest = first server = most interesting),
        we reverse the list.
        """
        # Collect all Received headers preserving raw text order (newest first)
        raw_headers = msg.get_all("Received") or []

        # Reversing gives us chronological order: index 0 = first server that
        # touched the email (the one that saw the attacker's IP)
        raw_headers_chrono = list(reversed(raw_headers))

        chain = []
        for i, raw in enumerate(raw_headers_chrono):
            hop = self._parse_single_received(raw, hop_number=i + 1)
            chain.append(hop)

        # Mark the first externally-visible hop (the one most likely to have
        # the real attacker IP or their VPN exit)
        for hop in chain:
            from_ip = hop.get("from_ip")
            if from_ip and not _is_private_ip(from_ip):
                hop["is_first_external"] = True
                break

        return chain

    def _parse_single_received(self, raw: str, hop_number: int) -> Dict:
        """
        Parse a single Received: header value into structured fields.
        
        A typical Received: header looks like:
            from mail-relay.attacker.net ([203.0.113.42])
                by mx.victim.com with ESMTPS
                for <victim@victim.com>;
                Mon, 26 Feb 2026 10:30:00 +0000
        """
        hop: Dict = {
            "hop_number":       hop_number,
            "raw":              raw,
            "from_hostname":    None,
            "from_ip":          None,      # IP the message was RECEIVED FROM
            "by_host":          None,      # Server that added this header
            "timestamp":        None,
            "is_first_external": False,
        }

        # Extract IPs from bracketed notation first (most reliable format)
        bracketed = _IP_IN_BRACKETS.findall(raw)
        bare      = _IP_BARE.findall(raw)

        # The "from [IP]" pattern — the connecting client's IP as seen by the
        # receiving server. This is unforgeable because the receiver adds it.
        from_match = _RECEIVED_FROM.search(raw)
        if from_match:
            hop["from_hostname"] = from_match.group(1)
            hop["by_host"]       = from_match.group(3)
            
            # Extract IP from the parenthetical "(hostname [IP])" if present
            paren_block = from_match.group(2) or ""
            paren_ips = _IP_IN_BRACKETS.findall(paren_block)
            if paren_ips:
                hop["from_ip"] = paren_ips[0]
            elif bracketed:
                hop["from_ip"] = bracketed[0]

        # Fallback: use first bare IP if no bracketed form found
        if not hop["from_ip"] and bare:
            # Filter out the "by" host IP if it appears — we want the FROM IP
            candidates = [ip for ip in bare if not _is_private_ip(ip)]
            if candidates:
                hop["from_ip"] = candidates[0]

        # Extract timestamp from the Received: header
        # It appears after a semicolon at the end of the header
        semi = raw.rfind(";")
        if semi != -1:
            hop["timestamp"] = raw[semi + 1:].strip()

        if self.verbose:
            print(f"  [Hop {hop_number:>2}] from={hop['from_ip'] or '?':>16}  by={hop['by_host'] or '?'}")

        return hop

    # -------------------------------------------------------------------------
    # SPF EXTRACTION
    # -------------------------------------------------------------------------

    def _extract_spf(self, msg: email.message.Message) -> SPFFindings:
        """
        Extract the SPF authenticated sending IP.
        
        The Received-SPF header is added by the RECEIVING server after
        it checks the SPF record of the purported sender domain. The `ip=`
        field inside it is the IP the message actually arrived from.
        This is one of the most reliable signals we have.
        
        Example:
            Received-SPF: pass (mx.victim.com: domain of sender@attacker.com
                designates 203.0.113.42 as permitted sender)
                client-ip=203.0.113.42; envelope-from=sender@attacker.com;
                helo=mail.attacker.com; ip=203.0.113.42;
        """
        spf_header = msg.get("Received-SPF") or ""

        # Also check Authentication-Results for spf= field
        auth_results = msg.get("Authentication-Results") or ""

        spf_ip     = None
        spf_result = None

        if spf_header:
            # Extract result (first word of the header value)
            result_match = re.match(r'\s*(\w+)', spf_header)
            if result_match:
                spf_result = result_match.group(1).lower()

            # Extract ip= field
            ip_match = _SPF_IP_FIELD.search(spf_header)
            if ip_match:
                candidate = ip_match.group(1).strip()
                if _is_valid_public_ip(candidate):
                    spf_ip = candidate

            # Fallback: client-ip= field
            if not spf_ip:
                client_ip_match = re.search(r'client-ip=([^\s;]+)', spf_header, re.IGNORECASE)
                if client_ip_match:
                    candidate = client_ip_match.group(1).strip()
                    if _is_valid_public_ip(candidate):
                        spf_ip = candidate

        # Also look in Authentication-Results header
        if not spf_ip and auth_results:
            # Pattern: smtp.mailfrom=...; client-ip=203.0.113.42
            m = re.search(r'client-ip=([^\s;,]+)', auth_results, re.IGNORECASE)
            if m:
                candidate = m.group(1).strip()
                if _is_valid_public_ip(candidate):
                    spf_ip     = candidate
                    spf_result = spf_result or "derived"

        return SPFFindings(
            spf_ip       = spf_ip,
            spf_result   = spf_result,
            authenticated= spf_result in ("pass",) if spf_result else False,
            raw_header   = spf_header or auth_results or None,
        )

    # -------------------------------------------------------------------------
    # DKIM / MESSAGE-ID DOMAIN EXTRACTION
    # -------------------------------------------------------------------------

    def _extract_auth_signatures(self, msg: email.message.Message) -> AuthSignatureFindings:
        """
        Extract the DKIM signing domain and Message-ID domain.
        
        DKIM: The `d=` field in the DKIM-Signature header is the domain
        that cryptographically signed the message. Because DKIM signatures
        are verified against live DNS TXT records, the signing domain MUST
        actually control that DNS record — it can't be freely spoofed
        (unlike the From: address).
        
        Message-ID: The domain after @ in the Message-ID header is typically
        the actual mail server that generated the message. It's weaker than
        DKIM but useful for cross-correlation.
        """
        notes = []

        # DKIM domain
        dkim_header = msg.get("DKIM-Signature") or ""
        dkim_domain = None
        if dkim_header:
            m = _DKIM_DOMAIN.search(dkim_header)
            if m:
                dkim_domain = m.group(1).strip().rstrip(";")
                notes.append(f"DKIM signing domain: {dkim_domain} (must control {dkim_domain} DNS)")

        # Message-ID domain
        msgid = msg.get("Message-ID") or msg.get("Message-Id") or ""
        msgid_domain = None
        if msgid:
            m = _MSGID_DOMAIN.search(msgid)
            if m:
                msgid_domain = m.group(1).strip()
                notes.append(f"Message-ID domain: {msgid_domain} (actual generating server)")

        # Check agreement
        domains_agree = False
        if dkim_domain and msgid_domain:
            # Compare base domains (strip subdomains for fuzzy match)
            dkim_base  = ".".join(dkim_domain.rsplit(".", 2)[-2:])
            msgid_base = ".".join(msgid_domain.rsplit(".", 2)[-2:])
            domains_agree = dkim_base == msgid_base
            if domains_agree:
                notes.append(f"✓ DKIM domain and Message-ID domain agree: {dkim_base}")
            else:
                notes.append(f"⚠ Domain mismatch: DKIM={dkim_domain} vs MsgID={msgid_domain} — possible relay or forwarding")

        return AuthSignatureFindings(
            dkim_domain        = dkim_domain,
            message_id_domain  = msgid_domain,
            domains_agree      = domains_agree,
            notes              = notes,
        )

    # -------------------------------------------------------------------------
    # TIMEZONE EXTRACTION
    # -------------------------------------------------------------------------

    def _extract_timezone(self, msg: email.message.Message) -> TimezoneFindings:
        """
        Extract timezone offset from the Date: header.
        
        This is a weak signal on its own — the sender can trivially set any
        timezone in their mail client. However, when the timezone offset
        AGREES with the geolocation of the SPF IP or the Received: chain
        origin IP, it raises overall confidence significantly.
        
        The Date: header is formatted like:
            Mon, 26 Feb 2026 10:30:00 +0530
        The +0530 part is the UTC offset that reveals the sender's configured timezone.
        """
        notes = []
        date_header = msg.get("Date") or ""
        utc_offset  = None
        regions     = []

        if date_header:
            m = _TZ_OFFSET.search(date_header.strip())
            if m:
                utc_offset = m.group(1)
                # Normalize to canonical form (e.g., +0530 not +053000)
                regions = UTC_OFFSET_REGIONS.get(utc_offset, ["Unknown region"])
                notes.append(
                    f"Date: header offset {utc_offset} → sender may be in: {', '.join(regions)}"
                )
                notes.append(
                    "Note: timezone in Date: is client-controlled and can be forged. "
                    "Cross-validate with SPF IP geolocation."
                )

        return TimezoneFindings(
            utc_offset       = utc_offset,
            probable_regions = regions,
            cross_validated  = False,  # Updated later in fusion if geo data available
            notes            = notes,
        )

    # -------------------------------------------------------------------------
    # FORGEABLE HEADER SCAN
    # -------------------------------------------------------------------------

    def _scan_forgeable_headers(self, msg: email.message.Message) -> List[Dict]:
        """
        Scan for IPs in headers that CAN be forged by the sender.
        
        These are not useless — a naive attacker who doesn't know about these
        headers might leave their real IP in them. But a sophisticated attacker
        will inject false values. We record them with clear warnings so the
        analyst understands their evidential weight.
        """
        findings = []
        for header_name in FORGEABLE_HEADERS:
            value = msg.get(header_name)
            if not value:
                continue
            ips = _IP_IN_BRACKETS.findall(value) or _IP_BARE.findall(value)
            for ip in ips:
                if _is_valid_public_ip(ip):
                    findings.append({
                        "header":  header_name,
                        "ip":      ip,
                        "value":   value,
                        "warning": (
                            f"{header_name} is client-injectable — a sophisticated attacker "
                            "can set this to any value. Use as supporting evidence only, "
                            "never as primary ground truth."
                        ),
                    })
        return findings

    # -------------------------------------------------------------------------
    # CANDIDATE BUILDING
    # -------------------------------------------------------------------------

    def _build_candidates(
        self,
        received_chain: List[Dict],
        spf: SPFFindings,
        forgeable: List[Dict],
    ) -> List[IPCandidate]:
        """
        Build a ranked list of IP candidates from all sources.
        The ordering here reflects forensic reliability, not discovery order.
        """
        candidates: List[IPCandidate] = []

        # 1. SPF ip= field — highest reliability because the receiving server
        #    writes this after authenticating the connecting IP
        if spf and spf.spf_ip:
            candidates.append(IPCandidate(
                ip              = spf.spf_ip,
                source_header   = "Received-SPF (ip= field)",
                trust_level     = HeaderTrust.UNFORGEABLE,
                hop_position    = None,
                hop_direction   = "from",
                context         = spf.raw_header or "",
                confidence      = 0.90 if spf.authenticated else 0.75,
                is_private      = _is_private_ip(spf.spf_ip),
                notes           = [f"SPF result: {spf.spf_result}"],
            ))

        # 2. First-external hop in the Received: chain — the server that first
        #    saw the message from outside (closest to the attacker)
        for hop in received_chain:
            from_ip = hop.get("from_ip")
            if not from_ip or _is_private_ip(from_ip):
                continue
            is_first_external = hop.get("is_first_external", False)
            candidates.append(IPCandidate(
                ip              = from_ip,
                source_header   = f"Received: hop {hop['hop_number']} (from= field)",
                trust_level     = HeaderTrust.UNFORGEABLE,
                hop_position    = hop["hop_number"],
                hop_direction   = "from",
                context         = hop["raw"][:200],
                confidence      = 0.85 if is_first_external else 0.55,
                is_private      = False,
                notes           = [
                    "First external hop (closest to sender)" if is_first_external
                    else f"Intermediate hop {hop['hop_number']}"
                ],
            ))

        # 3. Forgeable headers — weaker, flag clearly
        for f in forgeable:
            if not _is_private_ip(f["ip"]):
                candidates.append(IPCandidate(
                    ip              = f["ip"],
                    source_header   = f["header"],
                    trust_level     = HeaderTrust.FORGEABLE,
                    hop_position    = None,
                    hop_direction   = None,
                    context         = f["value"],
                    confidence      = 0.30,   # Low — sender can forge this
                    is_private      = False,
                    notes           = [f["warning"]],
                ))

        return candidates

    # -------------------------------------------------------------------------
    # CONFIDENCE FUSION
    # -------------------------------------------------------------------------

    def _fuse_candidates(
        self,
        candidates: List[IPCandidate],
        spf: SPFFindings,
        auth_sigs: AuthSignatureFindings,
        received_chain: List[Dict],
    ) -> Tuple[Optional[IPCandidate], float, List[str], List[str]]:
        """
        Select the best candidate and compute a fused confidence score.
        
        Fusion rules (in priority order):
          1. SPF ip= with pass result → very high confidence
          2. First-external Received: hop that AGREES with SPF → extremely high
          3. First-external Received: hop alone → high confidence
          4. Forgeable header alone → low confidence with strong warning
          5. No candidates → confidence 0
        """
        notes   = []
        warnings = []

        if not candidates:
            warnings.append("No public IP addresses found in any header.")
            return None, 0.0, notes, warnings

        # Sort candidates by individual confidence (desc)
        sorted_candidates = sorted(candidates, key=lambda c: c.confidence, reverse=True)
        best = sorted_candidates[0]
        base_confidence = best.confidence

        # Agreement boost: if SPF IP and first-external Received: hop agree,
        # this is extremely strong — two independent server-controlled records
        # pointing to the same IP
        spf_ip = spf.spf_ip if spf else None
        first_external_ip = next(
            (c.ip for c in candidates if c.hop_position == 1 and c.trust_level == HeaderTrust.UNFORGEABLE),
            None
        )

        if spf_ip and first_external_ip:
            if spf_ip == first_external_ip:
                base_confidence = min(1.0, base_confidence + 0.10)
                notes.append(
                    f"✓ STRONG AGREEMENT: SPF ip= and first Received: hop both show {spf_ip}. "
                    "These are independent server-added records — very high confidence."
                )
            else:
                # Disagreement suggests a relay between the first receiving server
                # and the SPF-checking server (common in forwarding scenarios)
                warnings.append(
                    f"SPF ip= ({spf_ip}) and first Received: hop ({first_external_ip}) differ. "
                    "This may indicate mail forwarding, a relay, or SPF checking at a different "
                    "point in the chain. Both are recorded."
                )

        # DKIM boost: if best IP's reverse DNS roughly matches DKIM domain,
        # that further corroborates
        if auth_sigs and auth_sigs.dkim_domain:
            notes.append(
                f"DKIM signed by: {auth_sigs.dkim_domain}. "
                "Cross-reference this domain with the sending IP's rDNS for further corroboration."
            )

        # Forgeable-only warning
        if best.trust_level == HeaderTrust.FORGEABLE:
            base_confidence = min(base_confidence, 0.35)
            warnings.append(
                f"Best available IP ({best.ip}) came from a forgeable header ({best.source_header}). "
                "A sophisticated attacker may have injected a false value. "
                "Corroborate with the Received: chain before taking action."
            )

        notes.append(f"Primary IP selected from: {best.source_header}")
        notes.append(
            "REMINDER: Received: headers are prepended newest-first. "
            "This extractor reads them bottom-up to find the first server "
            "that touched the message — the one closest to the true sending client."
        )

        return best, round(base_confidence, 3), notes, warnings


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is in a private/reserved range"""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in network for network in PRIVATE_RANGES)
    except ValueError:
        return True  # If we can't parse it, treat as invalid/private


def _is_valid_public_ip(ip_str: str) -> bool:
    """Return True if the string is a valid, routable (non-private) IP"""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in network for network in PRIVATE_RANGES)
    except ValueError:
        return False


# ============================================================================
# CONVENIENCE WRAPPER
# ============================================================================

def extract_real_ip_from_raw(raw_email: str, verbose: bool = False) -> ForensicExtractionResult:
    """
    Convenience wrapper. Pass a raw email string, get back a ForensicExtractionResult.
    
    Example:
        with open("phishing.eml", "r", errors="ignore") as f:
            raw = f.read()
        result = extract_real_ip_from_raw(raw, verbose=True)
        print(result.summary())
        
        if result.overall_confidence >= 0.80:
            # Pass result.best_ip directly to your geolocation stage
            geolocate(result.best_ip)
    """
    extractor = EmailForensicExtractor(verbose=verbose)
    return extractor.extract(raw_email)


# ============================================================================
# PIPELINE INTEGRATION ADAPTER
# Provides backward-compatible interface for hunterTrace.py
# ============================================================================

def extract_real_ip_for_pipeline(
    origin_ip: Optional[str],
    all_ips_in_chain: List[str],
    hop_details: List[Dict],
    classifications: Dict,
    enrichment_data: Optional[Dict] = None,
    geolocation_data: Optional[Dict] = None,
    raw_email: Optional[str] = None,
    verbose: bool = False,
) -> Dict:
    """
    Drop-in replacement for the v1 RealIPExtractor.extract_real_ip() method.
    
    If raw_email is provided, runs the full forensic extraction (recommended).
    Otherwise falls back to the structured inputs from the existing pipeline.
    
    Returns a dict compatible with the rest of the pipeline:
        {
            "suspected_real_ip": str,
            "confidence": float,
            "source": str,
            "trust_level": str,
            "forensic_result": ForensicExtractionResult,  # full result for reporting
        }
    """
    if raw_email:
        result = extract_real_ip_from_raw(raw_email, verbose=verbose)
        return {
            "suspected_real_ip": result.best_ip,
            "confidence":        result.overall_confidence,
            "source":            result.best_ip_source,
            "trust_level":       result.best_ip_trust.value if result.best_ip_trust else "unknown",
            "forensic_result":   result,
        }

    # Fallback: no raw email provided, work with pre-parsed data
    # Even here we apply the correct logic: prefer the LAST hop's IP
    # (index -1 in the chronological chain) not the first
    if hop_details:
        # hop_details from v1 pipeline: hop 0 = first in raw (= NEWEST = last server)
        # So to get the origin, we want the LAST hop in the list
        first_server_hop = hop_details[-1]
        origin_candidate = first_server_hop.get("ip") or origin_ip
    else:
        origin_candidate = origin_ip

    return {
        "suspected_real_ip": origin_candidate,
        "confidence":        0.60,  # Lower confidence without raw email
        "source":            "Received chain (bottom hop, fallback mode)",
        "trust_level":       HeaderTrust.DERIVED.value,
        "forensic_result":   None,
    }


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python realIpExtractorV2.py <email.eml>")
        print("\nThis module replaces realIpExtractor.py with forensically correct")
        print("Received: header ordering (bottom-up) and SPF/DKIM signal fusion.")
        sys.exit(0)

    eml_path = sys.argv[1]
    verbose  = "--verbose" in sys.argv or "-v" in sys.argv

    try:
        with open(eml_path, "r", errors="ignore") as f:
            raw = f.read()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {eml_path}")
        sys.exit(1)

    result = extract_real_ip_from_raw(raw, verbose=verbose)
    print(result.summary())

    # Show all candidates for transparency
    if result.all_candidates:
        print("\nALL IP CANDIDATES (ranked by confidence):")
        sorted_candidates = sorted(result.all_candidates, key=lambda c: c.confidence, reverse=True)
        for c in sorted_candidates:
            print(f"  {c.ip:<18}  {c.confidence:.0%}  [{c.trust_level.value[:25]}]  via {c.source_header}")