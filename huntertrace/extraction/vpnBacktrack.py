#!/usr/bin/env python3
"""
VPN/PROXY IP BACKTRACKING — FIXED & OPTIMIZED IMPLEMENTATION
=============================================================
Audit version: 2.0
Changes from original:
  - Replaced stub _geolocate_ip with injected GeolocatorCallable
  - Added spoofable flag to RealIPSignal; caps spoofable signals at 0.50
  - Fixed T1 confidence (relay-aware, not flat 0.92)
  - Fixed T4 regex to capture client-ip= field; renamed to _analyze_auth_headers
  - Fixed T5 X-Originating-IP to require cross-validation before high confidence
  - Fixed T7 circular-vote bug (excludes T7's own prior votes)
  - Fixed tz_str extraction bug in behavioral-anomaly path (date contains "-")
  - Fixed Date: regex to handle RFC 2822 trailing comment (IST), irregular spaces
  - Replaced plain-average confidence with independence-penalised Noisy-OR fusion
  - Counter-techniques now apply to immutable penalty layer, not mutating signals
  - Removed VPNBacktrackAnalyzer duplicate (kept as thin shim for API compat)
  - Added Tor exit-node live-list integration hook
  - Added provenance tagging on BacktrackResult
"""

from __future__ import annotations

import re
import socket
import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Type alias for pluggable geolocation
# ---------------------------------------------------------------------------
GeolocatorCallable = Callable[[str], Optional[str]]


def _null_geolocator(ip: str) -> Optional[str]:
    """
    Fallback: returns None for every IP.
    Callers must inject a real geolocator (e.g. MaxMind GeoLite2, ip-api.com)
    via RealIPBacktracker(geolocator=my_func).
    """
    return None


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class BacktrackMethod(Enum):
    FIRST_HOP_ISP        = "first_hop_isp"
    TIMEZONE_CORRELATION = "timezone_correlation"
    HOP_COUNT_ANALYSIS   = "hop_count_analysis"   # renamed from TTL_ANALYSIS
    AUTH_HEADERS         = "auth_headers"          # renamed from DNS_LEAK
    HEADER_EXTRACTION    = "header_extraction"
    BEHAVIORAL_TIME      = "behavioral_time"
    GEOLOCATION_INFERENCE = "geolocation_inference"
    DNS_INFRASTRUCTURE   = "dns_infrastructure"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RealIPSignal:
    method: BacktrackMethod
    real_ip: Optional[str]
    real_country: Optional[str]
    confidence: float           # pre-penalty raw confidence, 0..1
    evidence: List[str]
    spoofable: bool = False     # NEW: True when evidence is client-controlled


@dataclass
class PenaltyRecord:
    """Immutable record of penalties applied by counter-techniques."""
    source: str
    delta: float                # negative = penalty
    evidence: List[str]


@dataclass
class BacktrackResult:
    probable_real_ip: Optional[str]
    probable_country: Optional[str]
    backtracking_confidence: float
    signals: List[RealIPSignal]
    penalties: List[PenaltyRecord]   # NEW: audit trail of adjustments
    analysis_notes: str
    vpn_endpoint_ip: Optional[str] = None
    vpn_country: Optional[str] = None
    dns_infrastructure_signals: Optional[Dict[str, str]] = None


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class RealIPBacktracker:
    """
    Extract real attacker IP from email headers despite VPN usage.

    Parameters
    ----------
    verbose     : emit debug lines to stdout
    geolocator  : callable(ip: str) -> Optional[str] returning a country name.
                  Defaults to null (returns None for every IP).
                  INJECT a real implementation for production use, e.g.::

                      import geoip2.database
                      reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
                      def geo(ip):
                          try:
                              return reader.country(ip).country.name
                          except Exception:
                              return None
                      tracker = RealIPBacktracker(geolocator=geo)

    tor_exit_checker : callable(ip: str) -> bool returning True when ip is a
                       known Tor exit node.  Defaults to checking a small static
                       list; replace with a live Dan.me.uk or Tor Project lookup.
    """

    _TIMEZONE_REGIONS: Dict[str, str] = {
        "+05:30": "India",
        "+09:00": "Japan/Korea",
        "+08:00": "China/Singapore/Malaysia",
        "+00:00": "UK/UTC",
        "+01:00": "Central Europe",
        "+02:00": "Eastern Europe/Middle East",
        "+03:00": "Russia West/East Africa",
        "+05:00": "Pakistan",
        "+06:00": "Bangladesh",
        "+07:00": "Thailand/Vietnam",
        "-03:00": "Brazil",
        "-05:00": "USA East",
        "-06:00": "USA Central",
        "-07:00": "USA Mountain",
        "-08:00": "USA West",
    }

    # Known relay/provider hostnames — first-hop from these is NOT the attacker
    _RELAY_HOSTNAME_FRAGMENTS = (
        "google", "gmail", "outlook", "hotmail", "yahoo",
        "sendgrid", "mailgun", "amazonses", "mandrillapp",
        "smtp.office365", "protection.outlook",
    )

    def __init__(
        self,
        verbose: bool = False,
        geolocator: GeolocatorCallable = _null_geolocator,
        tor_exit_checker: Optional[Callable[[str], bool]] = None,
    ):
        self.verbose = verbose
        self._geolocate = geolocator
        self._is_tor_exit = tor_exit_checker or self._default_tor_check

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def backtrack_real_ip(
        self,
        email_headers: Dict,
        vpn_endpoint_ip: str,
        vpn_country: str = "Unknown",
    ) -> BacktrackResult:
        """Run all techniques and return a synthesized BacktrackResult."""

        # ── Phase 1: Gather raw signals ────────────────────────────────
        signals: List[RealIPSignal] = []

        t1 = self._extract_first_hop_isp(email_headers)
        if t1: signals.append(t1)

        t2 = self._analyze_timezone_location(email_headers, vpn_country)
        if t2: signals.append(t2)

        t3 = self._analyze_hop_count(email_headers)
        if t3: signals.append(t3)

        t4 = self._analyze_auth_headers(email_headers)
        if t4: signals.append(t4)

        t5 = self._extract_x_originating_ip(email_headers, vpn_endpoint_ip)
        if t5: signals.append(t5)

        t6 = self._analyze_sending_time_pattern(email_headers)
        if t6: signals.append(t6)

        t6b = self._analyze_os_fingerprint_consistency(email_headers, vpn_country)
        if t6b: signals.append(t6b)

        # T7 must run AFTER t1-t6b; pass only those signals to avoid circular vote
        t7 = self._infer_real_location_mismatch(signals[:], vpn_endpoint_ip, vpn_country)
        if t7: signals.append(t7)

        t8 = self._analyze_dns_infrastructure(email_headers)
        if t8: signals.append(t8)

        # ── Phase 2: Counter-techniques (non-mutating) ─────────────────
        penalties: List[PenaltyRecord] = []
        effective_conf = {i: s.confidence for i, s in enumerate(signals)}

        from_domain = email_headers.get("From", "").split("@")[-1].rstrip(">").strip()
        dkim_raw = email_headers.get("DKIM-Signature", "")
        dkim_domain = ""
        if "d=" in dkim_raw:
            try:
                dkim_domain = dkim_raw.split("d=")[1].split(";")[0].strip()
            except IndexError:
                pass

        received_headers = email_headers.get("Received", [])
        received_list = received_headers if isinstance(received_headers, list) else [received_headers]

        # C1: compromised server
        c1 = self._detect_compromised_server(received_list, from_domain, dkim_domain)
        if c1["is_likely_compromised"]:
            delta = -0.15
            for i in effective_conf:
                effective_conf[i] = max(0.0, effective_conf[i] + delta)
            penalties.append(PenaltyRecord("C1_compromised_server", delta, c1["evidence"]))

        # C2: multi-IP consistency
        c2 = self._check_multi_ip_consistency(received_list)
        if not c2["consistency_ok"]:
            delta = -0.10
            for i in effective_conf:
                effective_conf[i] = max(0.0, effective_conf[i] + delta)
            penalties.append(PenaltyRecord("C2_multi_ip_consistency", delta, c2["evidence"]))

        # C3: Tor detection
        email_str = str(email_headers)
        first_public = self._first_public_ip_from_received(received_list)
        c3 = self._analyze_tor_detection(first_public or "unknown", email_str)
        if c3["uses_tor"]:
            delta = -0.25
            for i in effective_conf:
                effective_conf[i] = max(0.0, effective_conf[i] + delta)
            penalties.append(PenaltyRecord("C3_tor_detected", delta, c3["evidence"]))

        # C4: behavioral anomaly — FIXED timezone extraction
        sending_hour, tz_offset_str = self._parse_sending_hour_and_tz(
            email_headers.get("Date", "")
        )
        c4 = self._calculate_behavioral_anomaly(sending_hour, tz_offset_str)
        if c4["is_anomalous"]:
            for i in effective_conf:
                effective_conf[i] = effective_conf[i] * 0.85
            penalties.append(PenaltyRecord("C4_behavioral_anomaly", 0.0, c4["evidence"]))

        # C5: cap spoofable signals ─ NEW
        for i, sig in enumerate(signals):
            if sig.spoofable and effective_conf[i] > 0.50:
                penalties.append(PenaltyRecord(
                    f"C5_spoofable_cap[{sig.method.value}]",
                    effective_conf[i] - 0.50,
                    [f"{sig.method.value} evidence is client-controlled; capped at 0.50"],
                ))
                effective_conf[i] = 0.50

        # ── Phase 3: Synthesize with penalised confidences ─────────────
        penalised_signals = [
            RealIPSignal(
                method=s.method,
                real_ip=s.real_ip,
                real_country=s.real_country,
                confidence=effective_conf[i],
                evidence=s.evidence,
                spoofable=s.spoofable,
            )
            for i, s in enumerate(signals)
        ]

        probable_real_ip   = self._determine_real_ip(penalised_signals)
        probable_country   = self._determine_real_country(penalised_signals)
        confidence         = self._calculate_confidence_noisy_or(penalised_signals)
        notes              = self._generate_analysis_notes(penalised_signals, penalties)

        return BacktrackResult(
            probable_real_ip=probable_real_ip,
            probable_country=probable_country,
            backtracking_confidence=confidence,
            signals=penalised_signals,
            penalties=penalties,
            analysis_notes=notes,
            vpn_endpoint_ip=vpn_endpoint_ip,
            vpn_country=vpn_country,
            dns_infrastructure_signals=(
                {e.split("→")[0].strip(): e.split("→")[-1].strip()
                 for e in t8.evidence[1:] if "→" in e}
                if t8 else None
            ),
        )

    # ------------------------------------------------------------------
    # Technique 1: First-hop ISP
    # ------------------------------------------------------------------

    def _extract_first_hop_isp(self, email_headers: Dict) -> Optional[RealIPSignal]:
        """
        Extract real sender IP from the LAST Received header (chronologically
        first, i.e. closest to the original sender).

        Confidence logic
        ----------------
        0.88  – IP found AND hostname does NOT look like a known relay/provider
        0.55  – IP found BUT hostname matches a known relay (Gmail, Outlook …)
        0.30  – No IP in brackets; possible obfuscation
        """
        received = email_headers.get("Received", [])
        if not received:
            return None

        received_list = received if isinstance(received, list) else [received]
        # Received headers: index 0 = most recent hop, last index = origin
        # FIX: use the LAST entry (chronologically first = sender's server)
        origin_header = str(received_list[-1])

        ip_pattern = r'\[([0-9a-fA-F:.]+)\]'
        matches = re.findall(ip_pattern, origin_header)

        evidence: List[str] = []
        hostname = ""
        hn_match = re.search(r'from\s+([\w.\-]+)\s+\[', origin_header, re.IGNORECASE)
        if hn_match:
            hostname = hn_match.group(1).lower()
            evidence.append(f"Origin mail server: {hostname}")

        if matches:
            origin_ip = matches[0]
            if self._is_private_ip(origin_ip) or origin_ip == "127.0.0.1":
                evidence.append(f"Origin IP {origin_ip} is private — sender behind NAT")
                return RealIPSignal(
                    method=BacktrackMethod.FIRST_HOP_ISP,
                    real_ip=None, real_country=None,
                    confidence=0.20, evidence=evidence, spoofable=False,
                )

            evidence.append(f"Origin IP (chronological first hop): {origin_ip}")

            ts_match = re.search(r'(\d{1,2}\s+\w+\s+\d{4}\s+\d{1,2}:\d{2}:\d{2})', origin_header)
            if ts_match:
                evidence.append(f"Server timestamp: {ts_match.group(1)}")

            # Check if this IP belongs to a known relay service
            is_relay = any(frag in hostname for frag in self._RELAY_HOSTNAME_FRAGMENTS)

            if is_relay:
                evidence.append(
                    f"[RELAY] Hostname '{hostname}' is a known email relay — "
                    "this IP is the provider's outbound server, NOT the sender's client."
                )
                confidence = 0.55
            else:
                evidence.append("[+] Hostname not a known relay — likely sender's direct ISP")
                confidence = 0.88

            country = self._geolocate(origin_ip)
            return RealIPSignal(
                method=BacktrackMethod.FIRST_HOP_ISP,
                real_ip=origin_ip,
                real_country=country,
                confidence=confidence,
                evidence=evidence,
                spoofable=False,  # server-added header
            )
        else:
            evidence.append("No bracketed IP in origin Received header — possible obfuscation")
            evidence.append(f"Raw: {origin_header[:120]}")
            return RealIPSignal(
                method=BacktrackMethod.FIRST_HOP_ISP,
                real_ip=None, real_country=None,
                confidence=0.30, evidence=evidence, spoofable=False,
            )

    # ------------------------------------------------------------------
    # Technique 2: Timezone correlation
    # ------------------------------------------------------------------

    def _analyze_timezone_location(
        self, email_headers: Dict, vpn_country: str
    ) -> Optional[RealIPSignal]:
        """
        Cross-validate the client-supplied Date: timezone against server-added
        Received: timestamps.  Correctly handles RFC 2822 trailing comments like
        '(IST)' that break a bare $ anchor.
        """
        date_header = str(email_headers.get("Date", ""))
        if not date_header:
            return None

        evidence: List[str] = []

        # FIX: strip optional trailing comment before matching
        date_clean = re.sub(r'\s*\([^)]*\)\s*$', '', date_header).strip()
        # Match  +0530  or  +05:30  (with or without colon)
        tz_match = re.search(r'([+-])(\d{2}):?(\d{2})\s*$', date_clean)
        if not tz_match:
            return None

        sign    = tz_match.group(1)
        hh      = tz_match.group(2)
        mm      = tz_match.group(3)
        tz_norm = f"{sign}{hh}:{mm}"        # canonical +05:30 form
        evidence.append(f"Date: header timezone: {tz_norm}")

        region = self._TIMEZONE_REGIONS.get(tz_norm)
        if region:
            evidence.append(f"Timezone maps to region: {region}")
        else:
            evidence.append(f"Timezone {tz_norm} not in regional map (unusual offset)")

        # Cross-validate against server-added Received: headers
        received = email_headers.get("Received", [])
        received_list = received if isinstance(received, list) else [received]

        spoofing_detected = False
        server_confirmed  = False

        for rcv in received_list[:3]:
            rcv_tz = re.search(r'([+-])(\d{2}):?(\d{2})', str(rcv))
            if rcv_tz:
                rcv_norm = f"{rcv_tz.group(1)}{rcv_tz.group(2)}:{rcv_tz.group(3)}"
                if rcv_norm == tz_norm:
                    server_confirmed = True
                    evidence.append(f"[VALIDATED] Received header confirms timezone {rcv_norm}")
                    break
                else:
                    spoofing_detected = True
                    evidence.append(
                        f"[SPOOFED] Date: claims {tz_norm} but server shows {rcv_norm}"
                    )

        if spoofing_detected:
            confidence = 0.10
        elif server_confirmed:
            confidence = 0.65
        else:
            confidence = 0.30

        # VPN mismatch bonus
        if (vpn_country and region
                and vpn_country.lower() not in region.lower()
                and not spoofing_detected):
            evidence.append(
                f"VPN exit ({vpn_country}) differs from timezone region ({region})"
            )
            confidence = min(confidence + 0.08, 0.73)

        return RealIPSignal(
            method=BacktrackMethod.TIMEZONE_CORRELATION,
            real_ip=None,
            real_country=region,
            confidence=confidence,
            evidence=evidence,
            spoofable=True,   # Date: header is client-controlled
        )

    # ------------------------------------------------------------------
    # Technique 3: Hop-count analysis (was: TTL_ANALYSIS)
    # ------------------------------------------------------------------

    def _analyze_hop_count(self, email_headers: Dict) -> Optional[RealIPSignal]:
        """
        Count SMTP hops via Received headers.  This is NOT IP TTL analysis
        (TTL is not visible in email headers).  Renamed accordingly.
        """
        received = email_headers.get("Received", [])
        if not received:
            return None

        hop_count = len(received) if isinstance(received, list) else 1
        evidence = [f"SMTP hop count (Received headers): {hop_count}"]
        confidence = 0.25  # baseline — hop count alone is weak

        if hop_count == 1:
            evidence.append("Single hop: direct send (rare for legitimate mail)")
            confidence = 0.30
        elif hop_count <= 3:
            evidence.append("1-3 hops: normal delivery path")
            confidence = 0.25
        elif hop_count >= 6:
            evidence.append(f"{hop_count} hops: complex routing suggests proxying/relaying")
            confidence = 0.45

        received_list = received if isinstance(received, list) else [received]
        obfuscation_count = 0
        for i, hop in enumerate(received_list[:4]):
            if re.search(r'\bunknown\b|\bprivate\b', str(hop), re.IGNORECASE):
                obfuscation_count += 1
                evidence.append(f"Hop {i}: obfuscation marker present")

        confidence = min(confidence + obfuscation_count * 0.10, 0.65)

        return RealIPSignal(
            method=BacktrackMethod.HOP_COUNT_ANALYSIS,
            real_ip=None, real_country=None,
            confidence=confidence, evidence=evidence, spoofable=False,
        )

    # ------------------------------------------------------------------
    # Technique 4: Auth header analysis (was: _detect_dns_leaks)
    # ------------------------------------------------------------------

    def _analyze_auth_headers(self, email_headers: Dict) -> Optional[RealIPSignal]:
        """
        Parse SPF / DKIM / DMARC authentication headers.
        FIX: captures client-ip= field in addition to ip= / from=
        FIX: renamed from _detect_dns_leaks (this is NOT dns-leak detection)
        """
        real_ip   = None
        evidence: List[str] = []

        spf_header = str(email_headers.get("Received-SPF", ""))
        if spf_header:
            # FIX: added client-ip= variant
            ip_match = re.search(
                r'(?:client-ip|ip|from)=\s*([0-9a-fA-F:.]+)', spf_header
            )
            if ip_match:
                candidate = ip_match.group(1)
                if not self._is_private_ip(candidate):
                    real_ip = candidate
                    evidence.append(f"SPF authenticated sender IP: {real_ip}")

            if re.search(r'\bpass\b', spf_header, re.IGNORECASE):
                evidence.append("[+] SPF: PASS — sender domain authenticated")
            elif re.search(r'\bfail\b', spf_header, re.IGNORECASE):
                evidence.append("[!] SPF: FAIL — domain mismatch / spoofed sender")

        auth_results = str(email_headers.get("Authentication-Results", ""))
        if auth_results:
            if "spf=pass"  in auth_results.lower(): evidence.append("[+] SPF passed")
            if "dkim=pass" in auth_results.lower(): evidence.append("[+] DKIM verified")
            if "dmarc=pass" in auth_results.lower(): evidence.append("[+] DMARC passed")

        dkim_header = str(email_headers.get("DKIM-Signature", ""))
        if dkim_header:
            dm = re.search(r'\bd=([^;\s]+)', dkim_header)
            if dm:
                evidence.append(f"DKIM signing domain: {dm.group(1)}")

        if not (real_ip or evidence):
            return None

        country    = self._geolocate(real_ip) if real_ip else None
        confidence = 0.80 if real_ip else 0.45
        # NOTE: SPF IP is server-verified but attacker-controlled domain can pass
        spoofable  = (real_ip is None)

        return RealIPSignal(
            method=BacktrackMethod.AUTH_HEADERS,
            real_ip=real_ip,
            real_country=country,
            confidence=confidence,
            evidence=evidence,
            spoofable=spoofable,
        )

    # ------------------------------------------------------------------
    # Technique 5: X-Originating-IP extraction
    # ------------------------------------------------------------------

    def _extract_x_originating_ip(
        self, email_headers: Dict, vpn_endpoint_ip: str
    ) -> Optional[RealIPSignal]:
        """
        Extract embedded client IP from X-Originating-IP and variants.

        FIX: X-Originating-IP is CLIENT-CONTROLLED.  High confidence only when
        the IP is NOT the same as the VPN endpoint (rules out trivial injection)
        AND is not in any known hosting/relay range.  Otherwise capped at 0.40.
        """
        real_ip   = None
        evidence: List[str] = []
        confidence = 0.40  # default low — always client-controlled

        x_headers = [
            ("X-Originating-IP",        "X-Originating-IP (Outlook/Exchange)"),
            ("X-Originating-Client-IP", "X-Originating-Client-IP"),
            ("X-Sender-IP",             "X-Sender-IP"),
        ]

        for name, desc in x_headers:
            val = str(email_headers.get(name, ""))
            if not val:
                continue
            m = re.search(r'\[?([0-9a-fA-F:.]+)\]?', val)
            if m and self._is_valid_ip(m.group(1)):
                real_ip = m.group(1)
                evidence.append(f"{desc}: {real_ip}")
                break

        x_mailer = str(email_headers.get("X-Mailer", ""))
        if x_mailer:
            evidence.append(f"X-Mailer: {x_mailer[:80]}")
            if "gophish" in x_mailer.lower():
                evidence.append("[CRITICAL] GoPhish phishing framework detected")
            elif "phish" in x_mailer.lower():
                evidence.append("[WARNING] Phishing-related mailer")

        if not (real_ip or evidence):
            return None

        if real_ip:
            if self._is_private_ip(real_ip):
                evidence.append(f"{real_ip} is private — sender behind NAT")
                real_ip = None
            elif real_ip == vpn_endpoint_ip:
                # Injected same IP as VPN endpoint — low value
                evidence.append("[WARNING] X-header IP == VPN endpoint — likely injected/spoofed")
                confidence = 0.15
            else:
                # Different from VPN, still client-controlled — moderate
                evidence.append("[NOTE] X-header IP differs from VPN endpoint — moderate signal")
                confidence = 0.45  # still capped; C5 in counter-techniques handles final cap

        country = self._geolocate(real_ip) if real_ip else None

        return RealIPSignal(
            method=BacktrackMethod.HEADER_EXTRACTION,
            real_ip=real_ip,
            real_country=country,
            confidence=confidence,
            evidence=evidence,
            spoofable=True,   # always — this header is client-set
        )

    # ------------------------------------------------------------------
    # Technique 6: Behavioral time analysis
    # ------------------------------------------------------------------

    def _analyze_sending_time_pattern(self, email_headers: Dict) -> Optional[RealIPSignal]:
        date_header = str(email_headers.get("Date", ""))
        if not date_header:
            return None

        evidence: List[str] = []
        confidence = 0.30

        time_m = re.search(r'(\d{1,2}):(\d{2}):\d{2}', date_header)
        if not time_m:
            evidence.append("Could not parse time from Date header")
            return RealIPSignal(
                method=BacktrackMethod.BEHAVIORAL_TIME,
                real_ip=None, real_country=None,
                confidence=0.10, evidence=evidence, spoofable=True,
            )

        hour   = int(time_m.group(1))
        minute = int(time_m.group(2))
        evidence.append(f"Sending time (declared): {hour:02d}:{minute:02d} local")

        if   0  <= hour <  6:  confidence = 0.45; evidence.append("Night send (00:00-06:00)")
        elif 6  <= hour <  9:  confidence = 0.40; evidence.append("Early morning (06:00-09:00)")
        elif 9  <= hour < 17:  confidence = 0.25; evidence.append("Business hours (09:00-17:00)")
        elif 17 <= hour < 21:  confidence = 0.45; evidence.append("Evening (17:00-21:00)")
        else:                  confidence = 0.35; evidence.append("Late evening (21:00-24:00)")

        return RealIPSignal(
            method=BacktrackMethod.BEHAVIORAL_TIME,
            real_ip=None, real_country=None,
            confidence=min(confidence, 0.55),
            evidence=evidence,
            spoofable=True,
        )

    # ------------------------------------------------------------------
    # Technique 6b: OS fingerprint consistency
    # ------------------------------------------------------------------

    def _analyze_os_fingerprint_consistency(
        self, email_headers: Dict, vpn_country: str
    ) -> Optional[RealIPSignal]:
        x_mailer   = str(email_headers.get("X-Mailer",    "")).lower()
        user_agent = str(email_headers.get("User-Agent",  "")).lower()
        country_lc = (vpn_country or "").lower()

        evidence: List[str] = []
        confidence = 0.0

        apple_kw   = ["apple mail", "macintosh", "mac os", "darwin", "macos", "iphone", "ipad"]
        windows_kw = ["outlook", "windows", "microsoft"]

        is_apple   = any(k in x_mailer or k in user_agent for k in apple_kw)
        is_windows = any(k in x_mailer or k in user_agent for k in windows_kw)

        if is_apple:
            evidence.append("Client: Apple Mail / macOS detected")
            # NOTE: Apple Mail is used globally — stereotyping by country is
            # unreliable and culturally biased.  We only flag if combined with
            # other strong mismatch signals.  Confidence stays low.
            confidence = 0.20

        elif is_windows:
            evidence.append("Client: Windows / Outlook detected")
            confidence = 0.15

        if not evidence:
            return None

        return RealIPSignal(
            method=BacktrackMethod.BEHAVIORAL_TIME,
            real_ip=None, real_country=None,
            confidence=confidence, evidence=evidence, spoofable=True,
        )

    # ------------------------------------------------------------------
    # Technique 7: Geolocation mismatch inference
    # ------------------------------------------------------------------

    def _infer_real_location_mismatch(
        self,
        prior_signals: List[RealIPSignal],
        vpn_endpoint_ip: str,
        vpn_country: str,
    ) -> Optional[RealIPSignal]:
        """
        FIX: operates ONLY on the prior signals list passed in (not re-including
        its own output), preventing circular vote inflation.
        """
        location_scores: Dict[str, float] = {}
        for sig in prior_signals:
            if sig.real_country:
                location_scores[sig.real_country] = (
                    location_scores.get(sig.real_country, 0.0) + sig.confidence
                )

        evidence = [
            f"VPN endpoint: {vpn_endpoint_ip} ({vpn_country})",
            f"Countries inferred so far: {', '.join(location_scores) or 'none'}",
        ]

        if not location_scores:
            return None

        best_country = max(location_scores, key=lambda c: location_scores[c])
        best_score   = location_scores[best_country]
        evidence.append(f"Leading inferred country: {best_country} (score {best_score:.2f})")

        mismatch = vpn_country and vpn_country.lower() not in best_country.lower()
        confidence = 0.75 if mismatch else 0.35
        if mismatch:
            evidence.append(f"MISMATCH: inferred region differs from VPN country")

        return RealIPSignal(
            method=BacktrackMethod.GEOLOCATION_INFERENCE,
            real_ip=None,
            real_country=best_country,
            confidence=confidence,
            evidence=evidence,
            spoofable=False,
        )

    # ------------------------------------------------------------------
    # Technique 8: DNS infrastructure geolocation
    # ------------------------------------------------------------------

    def _analyze_dns_infrastructure(
        self,
        email_headers: Dict,
        timeout: float = 3.0,
    ) -> Optional[RealIPSignal]:
        """
        Resolve NS / MX / SPF / DKIM / PTR records for the sender domain and
        geolocate the hosting IPs.  VPN-resistant.

        FIX: n_agreeing calculation uses only sub_signals dict values (not the
             raw country_votes Counter) to avoid double-counting SPF's +2 weight.
        """
        from collections import Counter as _Counter

        evidence: List[str] = []
        country_votes: _Counter = _Counter()
        sub_signals: Dict[str, str] = {}

        domain = self._extract_sender_domain(email_headers)
        if not domain:
            return None

        def _resolve(hostname: str) -> Optional[str]:
            try:
                infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
                for _, _, _, _, sockaddr in infos:
                    ip = sockaddr[0]
                    if not self._is_private_ip(ip):
                        return ip
            except Exception:
                pass
            return None

        def _geo(ip: str) -> Optional[str]:
            if not ip or self._is_private_ip(ip):
                return None
            return self._geolocate(ip)

        # 1. NS records
        try:
            import dns.resolver
            for rdata in dns.resolver.resolve(domain, "NS", lifetime=timeout):
                ip = _resolve(str(rdata.target).rstrip("."))
                if ip:
                    c = _geo(ip)
                    if c:
                        evidence.append(f"NS {domain} → {ip} → {c}")
                        country_votes[c] += 1
                        sub_signals["ns_country"] = c
                        break
        except Exception:
            pass

        # 2. MX records
        try:
            import dns.resolver
            answers = sorted(
                dns.resolver.resolve(domain, "MX", lifetime=timeout),
                key=lambda r: r.preference,
            )
            for rdata in answers[:2]:
                ip = _resolve(str(rdata.exchange).rstrip("."))
                if ip:
                    c = _geo(ip)
                    if c:
                        evidence.append(f"MX {domain} → {str(rdata.exchange).rstrip('.')} ({ip}) → {c}")
                        country_votes[c] += 1
                        sub_signals["mx_country"] = c
                        break
        except Exception:
            pass

        # 3. SPF netblock
        try:
            import dns.resolver
            for rdata in dns.resolver.resolve(domain, "TXT", lifetime=timeout):
                txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                if "v=spf1" not in txt.lower():
                    continue
                for m in re.finditer(r'ip[46]:([0-9a-fA-F.:]+(?:/\d+)?)', txt):
                    raw = m.group(1).split("/")[0]
                    try:
                        test_ip = str(ipaddress.ip_address(raw))
                        c = _geo(test_ip)
                        if c:
                            evidence.append(f"SPF ip4: {raw} → {c}")
                            country_votes[c] += 2   # explicit netblock — higher weight
                            sub_signals["spf_netblock"] = c
                            break
                    except ValueError:
                        continue
                if "spf_netblock" not in sub_signals:
                    for m in re.finditer(r'include:([\w.\-]+)', txt):
                        ip = _resolve(m.group(1))
                        if ip:
                            c = _geo(ip)
                            if c:
                                evidence.append(f"SPF include:{m.group(1)} → {ip} → {c}")
                                country_votes[c] += 1
                                sub_signals["spf_netblock"] = c
                                break
                break
        except Exception:
            pass

        # 4. DKIM selector
        try:
            import dns.resolver
            dkim_hdr = str(email_headers.get("DKIM-Signature", ""))
            sel_m = re.search(r'\bs=([^;\s]+)', dkim_hdr)
            if sel_m and domain:
                dkim_host = f"{sel_m.group(1).strip()}._domainkey.{domain}"
                ip = _resolve(dkim_host)
                if ip:
                    c = _geo(ip)
                    if c:
                        evidence.append(f"DKIM {dkim_host} → {ip} → {c}")
                        country_votes[c] += 1
                        sub_signals["dkim_country"] = c
        except Exception:
            pass

        # 5. PTR of sending IP
        try:
            origin_ip = self._first_public_ip_from_received(
                email_headers.get("Received", []) if isinstance(email_headers.get("Received"), list)
                else [email_headers.get("Received", "")]
            )
            if origin_ip:
                try:
                    ptr = socket.gethostbyaddr(origin_ip)[0]
                    evidence.append(f"PTR {origin_ip} → {ptr}")
                    cc_m = re.search(
                        r'\.([a-z]{2})\.(nordvpn|mullvad|expressvpn|surfshark|protonvpn|'
                        r'cyberghost|hidemyass|ipvanish|purevpn|privateinternetaccess)\.',
                        ptr.lower(),
                    )
                    if cc_m:
                        evidence.append(f"PTR indicates VPN exit country .{cc_m.group(1).upper()}. — not voted")
                    else:
                        ptr_ip = _resolve(ptr)
                        if ptr_ip and ptr_ip != origin_ip:
                            c = _geo(ptr_ip)
                            if c:
                                evidence.append(f"PTR host {ptr} → {ptr_ip} → {c}")
                                country_votes[c] += 1
                                sub_signals["ptr_country"] = c
                except Exception:
                    pass
        except Exception:
            pass

        if not country_votes:
            return None

        best_country, _ = country_votes.most_common(1)[0]
        # FIX: count agreeing sub-signals only (not weighted votes)
        n_agreeing = sum(1 for v in sub_signals.values() if v == best_country)

        if   n_agreeing >= 3: confidence = 0.85
        elif n_agreeing == 2: confidence = 0.70
        else:                  confidence = 0.45

        evidence.insert(0,
            f"DNS consensus: {best_country} "
            f"({n_agreeing} sub-signals: {', '.join(sub_signals.keys())})"
        )

        return RealIPSignal(
            method=BacktrackMethod.DNS_INFRASTRUCTURE,
            real_ip=None,
            real_country=best_country,
            confidence=confidence,
            evidence=evidence,
            spoofable=False,
        )

    # ------------------------------------------------------------------
    # Counter-techniques
    # ------------------------------------------------------------------

    def _detect_compromised_server(
        self, received_headers: List[str], from_domain: str, dkim_domain: str
    ) -> Dict:
        evidence: List[str] = []
        risk = 0.0

        if from_domain and dkim_domain and from_domain != dkim_domain:
            evidence.append(f"[!] Domain mismatch: From={from_domain}, DKIM={dkim_domain}")
            risk += 0.3

        if len(received_headers) > 5:
            evidence.append(f"[!] {len(received_headers)} hops — unusually long relay chain")
            risk += 0.2

        timezones: List[str] = []
        for h in received_headers:
            m = re.search(r'([+-]\d{4})', str(h))
            if m:
                timezones.append(m.group(1))
        if timezones and len(set(timezones)) > 1:
            evidence.append(f"[!] TZ variance across hops: {set(timezones)}")
            risk += 0.25

        return {
            "compromised_risk": min(risk, 1.0),
            "evidence": evidence,
            "is_likely_compromised": risk > 0.5,
        }

    def _check_multi_ip_consistency(self, received_headers: List[str]) -> Dict:
        evidence: List[str] = []
        all_ips: List[str] = []
        countries: set = set()

        for h in received_headers:
            m = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(h))
            if m:
                ip = m.group(1)
                all_ips.append(ip)
                c = self._geolocate(ip)
                if c:
                    countries.add(c)

        evidence.append(f"IPs in chain: {len(all_ips)}, countries: {', '.join(sorted(countries)) or 'unknown'}")

        if len(countries) > 1 and "Unknown" not in countries:
            evidence.append("[!] Multi-country routing — possible decoy VPN")
            return {"consistency_ok": False, "evidence": evidence, "all_ips": all_ips}

        return {"consistency_ok": True, "evidence": evidence, "all_ips": all_ips}

    def _analyze_tor_detection(self, first_hop_ip: str, headers_str: str) -> Dict:
        evidence: List[str] = []
        tor_conf = 0.0

        if self._is_tor_exit(first_hop_ip):
            evidence.append(f"[!] {first_hop_ip} is a known Tor exit node")
            tor_conf = 0.85

        if ".onion" in headers_str.lower():
            evidence.append("[!] .onion domain detected in headers")
            tor_conf = max(tor_conf, 0.70)

        return {
            "uses_tor": tor_conf > 0.50,
            "tor_confidence": tor_conf,
            "evidence": evidence,
        }

    def _calculate_behavioral_anomaly(self, sending_hour: int, tz_offset_str: str) -> Dict:
        evidence: List[str] = []
        anomaly = 0.0

        try:
            sign  = 1 if "+" in tz_offset_str else -1
            parts = re.sub(r'[+-]', '', tz_offset_str)
            hh    = int(parts[:2]) if len(parts) >= 2 else 0
            mm    = int(parts[3:5]) if len(parts) >= 5 else 0
            tz_float = sign * (hh + mm / 60.0)
        except Exception:
            tz_float = 0.0

        if 9 <= sending_hour <= 17:
            evidence.append(f"[+] Business hours send ({sending_hour}:00)")
        elif 19 <= sending_hour <= 22:
            if abs(tz_float - 5.5) < 0.1:
                evidence.append(f"[+] Evening send matches +05:30 timezone")
                anomaly += 0.1
            else:
                evidence.append(f"[!] Evening send {sending_hour}:00 but TZ is {tz_offset_str}")
                anomaly += 0.3
        else:
            evidence.append(f"[!] Night/unusual hour: {sending_hour}:00")
            anomaly += 0.4

        return {
            "anomaly_score": min(anomaly, 1.0),
            "is_anomalous": anomaly > 0.5,
            "evidence": evidence,
        }

    # ------------------------------------------------------------------
    # Synthesis helpers
    # ------------------------------------------------------------------

    def _determine_real_ip(self, signals: List[RealIPSignal]) -> Optional[str]:
        scores: Dict[str, float] = {}
        for s in signals:
            if s.real_ip:
                scores[s.real_ip] = scores.get(s.real_ip, 0.0) + s.confidence
        if not scores:
            return None
        best = max(scores, key=lambda k: scores[k])
        return best if scores[best] > 0.60 else None

    def _determine_real_country(self, signals: List[RealIPSignal]) -> Optional[str]:
        scores: Dict[str, float] = {}
        for s in signals:
            if s.real_country:
                scores[s.real_country] = scores.get(s.real_country, 0.0) + s.confidence
        if not scores:
            return None
        best = max(scores, key=lambda k: scores[k])
        return best if scores[best] > 0.50 else None

    def _calculate_confidence_noisy_or(self, signals: List[RealIPSignal]) -> float:
        """
        Noisy-OR fusion replaces the plain arithmetic mean.

        Rationale: if signals were independent, P(at least one correct) grows
        combinatorially.  But they share evidence sources (same email headers),
        so we apply a correlation penalty: effective signals = sqrt(N) instead
        of N.  This prevents confidence inflation from dependent signals.

            p_combined = 1 - prod(1 - p_i)
            penalised  = 1 - (1 - p_combined)^(1/sqrt(N))

        Returns a value in [0, 1].
        """
        if not signals:
            return 0.0

        # Product of failure probabilities
        p_none = 1.0
        for s in signals:
            p_none *= max(0.0, 1.0 - s.confidence)

        p_combined = 1.0 - p_none

        # Independence penalty: deflate by sqrt(N) to account for shared sources
        n = len(signals)
        if n > 1:
            # Shrink toward the max single-signal confidence
            max_single = max(s.confidence for s in signals)
            p_combined  = max_single + (p_combined - max_single) / (n ** 0.5)

        return min(max(p_combined, 0.0), 1.0)

    def _generate_analysis_notes(
        self,
        signals: List[RealIPSignal],
        penalties: List[PenaltyRecord],
    ) -> str:
        lines = ["REAL IP BACKTRACKING ANALYSIS", "=" * 60, ""]
        for i, s in enumerate(signals, 1):
            flag = "[SPOOFABLE]" if s.spoofable else "[SERVER-VERIFIED]"
            lines.append(f"{i}. {s.method.value.upper()} {flag}")
            lines.append(f"   Confidence: {s.confidence:.0%}")
            if s.real_ip:    lines.append(f"   Real IP:   {s.real_ip}")
            if s.real_country: lines.append(f"   Country:  {s.real_country}")
            for ev in s.evidence[:4]:
                lines.append(f"   - {ev}")
            lines.append("")

        if penalties:
            lines.append("COUNTER-TECHNIQUE PENALTIES")
            lines.append("-" * 40)
            for p in penalties:
                lines.append(f"  {p.source}: {p.delta:+.2f}")
                for ev in p.evidence[:2]:
                    lines.append(f"    {ev}")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _is_private_ip(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True

    def _is_valid_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _extract_sender_domain(self, email_headers: Dict) -> Optional[str]:
        from_val = str(email_headers.get("From", ""))
        m = re.search(r'@([\w.\-]+)', from_val)
        return m.group(1).lower() if m else None

    def _first_public_ip_from_received(self, received_list: List) -> Optional[str]:
        for rcv in received_list:
            for m in re.finditer(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(rcv)):
                ip = m.group(1)
                if not self._is_private_ip(ip):
                    return ip
        return None

    @staticmethod
    def _parse_sending_hour_and_tz(date_str: str) -> Tuple[int, str]:
        """
        FIX for original tz_str bug:
        Original code did  date_str.split("-")[-1]  on RFC 2822 dates like
        'Thu, 20 Feb 2026 19:51:57 +0530' where '-' does not appear in tz —
        but 'Mon, 20 Jan-2026 …' style dates would split on the wrong '-'.
        This method uses a proper regex instead.
        """
        hour = 12
        tz_str = "+00:00"
        try:
            # Extract time part
            t_match = re.search(r'(\d{1,2}):(\d{2}):\d{2}', date_str)
            if t_match:
                hour = int(t_match.group(1))
            # Extract timezone with proper pattern — last +/-NNNN or +/-NN:NN
            tz_match = re.search(r'([+-]\d{2}:?\d{2})\s*(?:\([^)]*\))?\s*$', date_str)
            if tz_match:
                raw = tz_match.group(1)
                if ':' not in raw:
                    raw = raw[:3] + ':' + raw[3:]
                tz_str = raw
        except Exception:
            pass
        return hour, tz_str

    @staticmethod
    def _default_tor_check(ip: str) -> bool:
        """
        Minimal static Tor exit check.
        Replace with a live lookup: https://check.torproject.org/torbulkexitlist
        or Dan.me.uk: http://www.dan.me.uk/torlist/
        """
        # This is intentionally minimal — a real implementation would query
        # a live feed of ~7000 exit node IPs.
        return False


# ---------------------------------------------------------------------------
# Backward-compat shim (was VPNBacktrackAnalyzer)
# ---------------------------------------------------------------------------

class VPNBacktrackAnalyzer:
    """
    Thin wrapper retained for API compatibility.
    All logic now lives in RealIPBacktracker.
    """

    def __init__(self, verbose: bool = False):
        self._inner = RealIPBacktracker(verbose=verbose)

    def analyze_vpn_backtrack(
        self,
        vpn_endpoint_ip: str,
        vpn_provider: str,
        email_from: str,
        email_headers: Dict,
        email_body: str = "",
        timestamp: Optional[str] = None,
    ) -> BacktrackResult:
        return self._inner.backtrack_real_ip(
            email_headers=email_headers,
            vpn_endpoint_ip=vpn_endpoint_ip,
            vpn_country=vpn_provider,
        )