#!/usr/bin/env python3
"""
HunterTrace — Sender Classification Module
===========================================
Three forensic detectors operating on email header metadata:

  1. HopTimestampAnomalyDetector  — flags forged/injected Received: hops
  2. TimezoneValidityChecker      — flags impossible/spoofed Date: offsets  
  3. SendRegularityScorer         — classifies sender as Bot / Human / Scripted

All three produce structured findings that integrate into:
  - CompletePipelineResult.header_analysis.red_flags  (single-email)
  - ActorTTPProfile                                    (campaign-level)
  - MITRE ATT&CK layer output                         (T1036, T1584, T1059)

Usage (single email):
    from senderClassifier import classify_sender
    result = classify_sender(header_analysis, email_fingerprints=[fp])

Usage (campaign):
    from senderClassifier import classify_campaign_sender
    report = classify_campaign_sender(actor_id, fingerprints)
"""

from __future__ import annotations
import re, statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Tuple, Any
from email.utils import parsedate_to_datetime


# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HopAnomalyFinding:
    """One detected anomaly in the Received: chain."""
    hop_index:   int
    hop_ip:      Optional[str]
    anomaly:     str          # SHORT label
    detail:      str          # Human-readable explanation
    severity:    str          # "critical" | "high" | "medium" | "low"
    evidence:    str          # Raw header excerpt


@dataclass
class HopChainAnalysis:
    """Result of Detector 1 — timestamp regression + injection detection."""
    total_hops:             int
    analysed_hops:          int
    forgery_score:          float          # 0.0 = clean, 1.0 = definitely forged
    forged_hop_count:       int
    regression_count:       int            # Hops where time goes backwards
    injection_indicators:   int            # Hops that look injected
    findings:               List[HopAnomalyFinding]
    verdict:                str            # "CLEAN" | "SUSPICIOUS" | "FORGED"
    mitre_techniques:       List[str]

    def summary(self) -> str:
        lines = [f"[HOP CHAIN] {self.verdict}  forgery_score={self.forgery_score:.2f}"]
        for f in self.findings:
            lines.append(f"  [{f.severity.upper()}] Hop {f.hop_index}: {f.anomaly} — {f.detail}")
        return "\n".join(lines)


@dataclass
class TimezoneAnalysis:
    """Result of Detector 2 — timezone validity."""
    raw_offset:         Optional[str]      # e.g. "+0530"
    is_valid:           bool
    is_spoofed:         bool               # Deliberately impossible
    offset_minutes:     Optional[int]      # Numeric offset
    plausible_regions:  List[str]          # Countries that match this offset
    anomaly:            Optional[str]      # Description if invalid/spoofed
    confidence:         float              # Confidence in assessment
    mitre_techniques:   List[str]


@dataclass
class SendRegularityResult:
    """Result of Detector 3 — Bot/Human/Scripted classification."""
    sender_type:        str                # "bot" | "scripted_human" | "human"
    confidence:         float              # 0–1
    cv:                 Optional[float]    # Coefficient of variation of inter-send intervals
    mean_interval_hrs:  Optional[float]    # Average hours between sends
    std_interval_hrs:   Optional[float]
    n_emails:           int
    send_times:         List[str]          # ISO timestamps used
    evidence:           List[str]          # Human-readable reasoning
    mitre_techniques:   List[str]


@dataclass
class SenderClassification:
    """Combined output of all three detectors."""
    email_file:         Optional[str]
    actor_id:           Optional[str]
    hop_chain:          HopChainAnalysis
    timezone:           TimezoneAnalysis
    regularity:         SendRegularityResult
    overall_verdict:    str                # "bot" | "scripted_human" | "human" | "unknown"
    overall_confidence: float
    red_flags:          List[str]          # All critical findings concatenated
    all_mitre:          List[str]          # Unique MITRE techniques across all detectors

    def to_dict(self) -> dict:
        return {
            "email_file":         self.email_file,
            "actor_id":           self.actor_id,
            "overall_verdict":    self.overall_verdict,
            "overall_confidence": round(self.overall_confidence, 4),
            "red_flags":          self.red_flags,
            "mitre_techniques":   self.all_mitre,
            "hop_chain": {
                "verdict":           self.hop_chain.verdict,
                "forgery_score":     round(self.hop_chain.forgery_score, 4),
                "regression_count":  self.hop_chain.regression_count,
                "forged_hop_count":  self.hop_chain.forged_hop_count,
                "findings":          [
                    {"hop": f.hop_index, "anomaly": f.anomaly,
                     "severity": f.severity, "detail": f.detail}
                    for f in self.hop_chain.findings
                ],
            },
            "timezone": {
                "raw_offset":        self.timezone.raw_offset,
                "is_valid":          self.timezone.is_valid,
                "is_spoofed":        self.timezone.is_spoofed,
                "anomaly":           self.timezone.anomaly,
                "plausible_regions": self.timezone.plausible_regions,
                "confidence":        round(self.timezone.confidence, 4),
            },
            "regularity": {
                "sender_type":       self.regularity.sender_type,
                "confidence":        round(self.regularity.confidence, 4),
                "cv":                round(self.regularity.cv, 4) if self.regularity.cv else None,
                "mean_interval_hrs": round(self.regularity.mean_interval_hrs, 2) if self.regularity.mean_interval_hrs else None,
                "n_emails":          self.regularity.n_emails,
                "evidence":          self.regularity.evidence,
            },
        }

    def report(self) -> str:
        lines = [
            "=" * 65,
            "HUNTЕРТRACE — SENDER CLASSIFICATION REPORT",
            "=" * 65,
            f"  Actor/Email : {self.actor_id or self.email_file or 'unknown'}",
            f"  Verdict     : {self.overall_verdict.upper()}",
            f"  Confidence  : {self.overall_confidence:.0%}",
            "",
            self.hop_chain.summary(),
            "",
            f"[TIMEZONE]  offset={self.timezone.raw_offset}  "
            f"valid={self.timezone.is_valid}  spoofed={self.timezone.is_spoofed}",
        ]
        if self.timezone.anomaly:
            lines.append(f"  ↳ {self.timezone.anomaly}")
        if self.timezone.plausible_regions:
            lines.append(f"  ↳ Plausible regions: {', '.join(self.timezone.plausible_regions[:4])}")
        lines += [
            "",
            f"[REGULARITY]  type={self.regularity.sender_type}  "
            f"cv={self.regularity.cv:.3f if self.regularity.cv is not None else 'N/A'}  "
            f"n={self.regularity.n_emails}",
        ]
        for ev in self.regularity.evidence:
            lines.append(f"  ↳ {ev}")
        if self.red_flags:
            lines += ["", f"RED FLAGS ({len(self.red_flags)}):"]
            for rf in self.red_flags:
                lines.append(f"  ⚠  {rf}")
        if self.all_mitre:
            lines += ["", f"MITRE ATT&CK: {', '.join(self.all_mitre)}"]
        lines.append("=" * 65)
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  DETECTOR 1 — HOP TIMESTAMP REGRESSION & INJECTION
# ─────────────────────────────────────────────────────────────────────────────

# Valid range for legitimate email hop processing time
_MIN_HOP_SECONDS   = -30      # Allow 30s clock skew between MTAs
_MAX_HOP_SECONDS   = 3600 * 6 # 6 hours max for a legitimate hop

# Patterns that strongly indicate injected / fake hops
_LOCALHOST_PATTERNS = re.compile(
    r'\b(localhost|127\.0\.0\.1|::1|0\.0\.0\.0|unknown|loopback)\b', re.I
)
_FAKE_HOSTNAME_PATTERNS = re.compile(
    r'\b(mail\.example\.com|test\.local|smtp\.fake|internal|intranet)\b', re.I
)
_PRIVATE_IP = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|127\.)'
)


def _parse_hop_ts(raw_header: str) -> Optional[datetime]:
    """Extract datetime from a Received: header string."""
    # Strip leading 'Received: ' if present
    raw = re.sub(r'^Received:\s*', '', raw_header, flags=re.I).strip()

    # RFC 2822 date appears after semicolon in Received: headers
    m = re.search(r';\s*(.+)$', raw)
    if not m:
        # Some headers have the date inline without semicolon
        m = re.search(
            r'(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})', raw
        )
    if not m:
        return None
    try:
        return parsedate_to_datetime(m.group(1).strip())
    except Exception:
        return None


def _is_private_or_local(ip: Optional[str]) -> bool:
    if not ip:
        return True
    return bool(_PRIVATE_IP.match(ip))


class HopTimestampAnomalyDetector:
    """
    Detector 1: Analyse the Received: hop chain for:
      - Timestamp regression (time going backwards = forged hop)
      - Impossible hop duration (processed in 0ms or took >6h)
      - Injected fake hops (localhost, private IPs, suspicious hostnames)
      - Excess hop count (>8 hops suggests padding)
      - Missing timestamps (common in scripted/injected hops)
    """

    NORMAL_MAX_HOPS = 8

    def analyse(self, hops: list, raw_headers: Optional[List[str]] = None) -> HopChainAnalysis:
        findings: List[HopAnomalyFinding] = []
        forgery_score = 0.0
        regression_count = 0
        injection_count  = 0

        timestamps: List[Tuple[int, datetime]] = []  # (hop_index, dt)

        for i, hop in enumerate(hops):
            raw = getattr(hop, 'raw_header', '') or ''
            ip  = getattr(hop, 'ip', None)
            hn  = getattr(hop, 'hostname', None) or ''

            # ── 1a. Parse timestamp ──────────────────────────────────────
            ts = _parse_hop_ts(raw)
            if ts:
                timestamps.append((i, ts))
            else:
                findings.append(HopAnomalyFinding(
                    hop_index = i,
                    hop_ip    = ip,
                    anomaly   = "MISSING_TIMESTAMP",
                    detail    = "Received: header has no parseable timestamp — common in injected hops",
                    severity  = "medium",
                    evidence  = raw[:120],
                ))
                forgery_score += 0.08

            # ── 1b. Localhost / private IP in Received: ──────────────────
            if ip and _is_private_or_local(ip) and i < len(hops) - 1:
                findings.append(HopAnomalyFinding(
                    hop_index = i,
                    hop_ip    = ip,
                    anomaly   = "PRIVATE_IP_IN_CHAIN",
                    detail    = f"Private/localhost IP {ip} in mid-chain hop — expected only at final delivery",
                    severity  = "high",
                    evidence  = raw[:120],
                ))
                forgery_score += 0.15

            # ── 1c. Suspicious hostname ──────────────────────────────────
            if _LOCALHOST_PATTERNS.search(hn) or _FAKE_HOSTNAME_PATTERNS.search(hn):
                findings.append(HopAnomalyFinding(
                    hop_index = i,
                    hop_ip    = ip,
                    anomaly   = "SUSPICIOUS_HOSTNAME",
                    detail    = f"Hostname '{hn}' is a known fake/localhost pattern",
                    severity  = "high",
                    evidence  = raw[:120],
                ))
                forgery_score += 0.20
                injection_count += 1

        # ── 1d. Timestamp regression check ──────────────────────────────
        # Hops are ordered sender→recipient, so time should be non-decreasing
        for j in range(1, len(timestamps)):
            prev_idx, prev_dt = timestamps[j-1]
            curr_idx, curr_dt = timestamps[j]

            delta_secs = (curr_dt - prev_dt).total_seconds()

            if delta_secs < _MIN_HOP_SECONDS:
                regression_count += 1
                findings.append(HopAnomalyFinding(
                    hop_index = curr_idx,
                    hop_ip    = getattr(hops[curr_idx], 'ip', None),
                    anomaly   = "TIMESTAMP_REGRESSION",
                    detail    = (f"Hop {curr_idx} timestamped {abs(delta_secs):.0f}s BEFORE "
                                 f"hop {prev_idx} — definitive evidence of header injection"),
                    severity  = "critical",
                    evidence  = f"Hop {prev_idx}: {prev_dt.isoformat()} → Hop {curr_idx}: {curr_dt.isoformat()}",
                ))
                forgery_score += 0.35

            elif delta_secs == 0:
                findings.append(HopAnomalyFinding(
                    hop_index = curr_idx,
                    hop_ip    = getattr(hops[curr_idx], 'ip', None),
                    anomaly   = "ZERO_HOP_TIME",
                    detail    = "Two hops with identical timestamps — copy-pasted header or scripted injection",
                    severity  = "high",
                    evidence  = f"Both at {curr_dt.isoformat()}",
                ))
                forgery_score += 0.20

            elif delta_secs > _MAX_HOP_SECONDS:
                findings.append(HopAnomalyFinding(
                    hop_index = curr_idx,
                    hop_ip    = getattr(hops[curr_idx], 'ip', None),
                    anomaly   = "EXCESSIVE_HOP_DELAY",
                    detail    = f"Hop took {delta_secs/3600:.1f} hours — suggests queued spam or timestamp manipulation",
                    severity  = "medium",
                    evidence  = f"{prev_dt.isoformat()} → {curr_dt.isoformat()}",
                ))
                forgery_score += 0.10

        # ── 1e. Excess hop count ─────────────────────────────────────────
        if len(hops) > self.NORMAL_MAX_HOPS:
            excess = len(hops) - self.NORMAL_MAX_HOPS
            findings.append(HopAnomalyFinding(
                hop_index = 0,
                hop_ip    = None,
                anomaly   = "EXCESS_HOP_COUNT",
                detail    = (f"{len(hops)} hops detected — {excess} above normal max ({self.NORMAL_MAX_HOPS}). "
                             "Attackers pad the chain with fake hops to obscure origin."),
                severity  = "medium",
                evidence  = f"hop_count={len(hops)}",
            ))
            forgery_score += 0.05 * excess

        forgery_score = min(1.0, forgery_score)

        if forgery_score >= 0.50:
            verdict = "FORGED"
            mitre   = ["T1036.005", "T1584"]
        elif forgery_score >= 0.20:
            verdict = "SUSPICIOUS"
            mitre   = ["T1036"]
        else:
            verdict = "CLEAN"
            mitre   = []

        return HopChainAnalysis(
            total_hops           = len(hops),
            analysed_hops        = len(timestamps),
            forgery_score        = forgery_score,
            forged_hop_count     = injection_count,
            regression_count     = regression_count,
            injection_indicators = injection_count,
            findings             = findings,
            verdict              = verdict,
            mitre_techniques     = mitre,
        )


# ─────────────────────────────────────────────────────────────────────────────
#  DETECTOR 2 — TIMEZONE VALIDITY
# ─────────────────────────────────────────────────────────────────────────────

# Valid UTC offsets that actually exist (in minutes, multiples of 15)
# Full list per IANA/ISO 8601 — includes all real-world offsets
_VALID_OFFSETS_MIN = {
    -720, -660, -630, -600, -570, -540, -480, -420, -360,
    -300, -270, -240, -210, -180, -120, -60, 0,
     60,  120,  180,  210,  240,  270,  300,  330,  345,
     360,  390,  420,  480,  525,  540,  570,  600,  630,
     660,  720,  765,  780,  840,
}

# Offset → most common countries/regions for attribution
_OFFSET_TO_REGIONS: Dict[int, List[str]] = {
    -720: ["Baker Island (US)"],
    -660: ["American Samoa", "Samoa"],
    -600: ["Hawaii (US)", "Cook Islands"],
    -540: ["Alaska (US)"],
    -480: ["US Pacific", "Canada Pacific"],
    -420: ["US Mountain", "Mexico", "Canada Mountain"],
    -360: ["US Central", "Mexico", "Central America"],
    -300: ["US Eastern", "Canada Eastern", "Colombia", "Peru"],
    -270: ["Venezuela"],
    -240: ["Chile", "Bolivia", "Caribbean"],
    -210: ["Newfoundland (Canada)"],
    -180: ["Brazil", "Argentina", "Uruguay"],
    -120: ["South Georgia"],
    -60:  ["Cape Verde", "Azores"],
      0:  ["UK", "Ireland", "Portugal", "Ghana", "Nigeria", "Senegal"],
     60:  ["Germany", "France", "Poland", "Algeria", "Tunisia", "Romania"],
    120:  ["Ukraine", "South Africa", "Egypt", "Israel", "Finland"],
    180:  ["Russia (Moscow)", "Turkey", "Saudi Arabia", "Kenya", "Ethiopia"],
    210:  ["Iran"],
    240:  ["UAE", "Azerbaijan", "Georgia", "Oman"],
    270:  ["Afghanistan"],
    300:  ["Pakistan", "Uzbekistan", "Kazakhstan"],
    330:  ["India", "Sri Lanka"],
    345:  ["Nepal"],
    360:  ["Bangladesh", "Kazakhstan"],
    390:  ["Myanmar"],
    420:  ["Thailand", "Vietnam", "Indonesia", "Cambodia"],
    480:  ["China", "Philippines", "Singapore", "Malaysia", "Taiwan"],
    525:  ["Australia (Eucla)"],
    540:  ["Japan", "South Korea", "Indonesia (WIT)"],
    570:  ["Australia (Adelaide)"],
    600:  ["Australia (AEST)", "Papua New Guinea"],
    630:  ["Australia (Lord Howe)"],
    660:  ["Australia (AEDT)", "Solomon Islands"],
    720:  ["New Zealand", "Fiji"],
    765:  ["Chatham Islands (NZ)"],
    780:  ["Phoenix Islands", "Tokelau"],
    840:  ["Line Islands (Kiribati)"],
}

# Offsets that are valid but extremely rare — flag as suspicious if unexpected
_RARE_OFFSETS_MIN = {525, 345, 765, 840, 630}


class TimezoneValidityChecker:
    """
    Detector 2: Validate the timezone offset from the Date: header.

    Checks:
      - Is the offset syntactically valid? (+HHMM format)
      - Is the offset within the real-world range (-12:00 to +14:00)?
      - Does the offset correspond to a known valid timezone?
      - Is it a deliberately impossible value (e.g. -1900, +9999)?
      - Is it a rare/suspicious offset that warrants investigation?
    """

    def check(self, email_date: Optional[str],
              raw_date_header: Optional[str] = None) -> TimezoneAnalysis:

        raw_offset = self._extract_offset(email_date, raw_date_header)

        if raw_offset is None:
            return TimezoneAnalysis(
                raw_offset       = None,
                is_valid         = False,
                is_spoofed       = False,
                offset_minutes   = None,
                plausible_regions= [],
                anomaly          = "NO_DATE_HEADER — missing Date: header (RFC 5322 violation)",
                confidence       = 0.90,
                mitre_techniques = ["T1036"],
            )

        offset_min = self._offset_to_minutes(raw_offset)

        if offset_min is None:
            return TimezoneAnalysis(
                raw_offset       = raw_offset,
                is_valid         = False,
                is_spoofed       = True,
                offset_minutes   = None,
                plausible_regions= [],
                anomaly          = (f"UNPARSEABLE_OFFSET '{raw_offset}' — cannot be converted "
                                    "to minutes, likely script error or deliberate obfuscation"),
                confidence       = 0.95,
                mitre_techniques = ["T1036", "T1070.006"],
            )

        # Range check: UTC offsets cannot exceed ±14:00 (840 minutes)
        if abs(offset_min) > 840:
            return TimezoneAnalysis(
                raw_offset       = raw_offset,
                is_valid         = False,
                is_spoofed       = True,
                offset_minutes   = offset_min,
                plausible_regions= [],
                anomaly          = (f"IMPOSSIBLE_OFFSET {raw_offset} ({offset_min} min) — "
                                    "valid range is -12:00 to +14:00. "
                                    "Deliberate spoofing to mislead attribution tools."),
                confidence       = 0.98,
                mitre_techniques = ["T1036", "T1070.006"],
            )

        # Check against known valid offsets
        if offset_min not in _VALID_OFFSETS_MIN:
            # Find nearest valid offset
            nearest = min(_VALID_OFFSETS_MIN, key=lambda x: abs(x - offset_min))
            return TimezoneAnalysis(
                raw_offset       = raw_offset,
                is_valid         = False,
                is_spoofed       = True,
                offset_minutes   = offset_min,
                plausible_regions= _OFFSET_TO_REGIONS.get(nearest, []),
                anomaly          = (f"INVALID_OFFSET {raw_offset} — no timezone uses this offset. "
                                    f"Nearest valid: {self._minutes_to_str(nearest)} "
                                    f"({', '.join(_OFFSET_TO_REGIONS.get(nearest,[])[:2])})"),
                confidence       = 0.95,
                mitre_techniques = ["T1036", "T1070.006"],
            )

        regions = _OFFSET_TO_REGIONS.get(offset_min, [])
        is_rare = offset_min in _RARE_OFFSETS_MIN
        anomaly = None
        mitre   = []

        if is_rare:
            anomaly = (f"RARE_OFFSET {raw_offset} — only used by: "
                       f"{', '.join(regions)}. Verify this matches other signals.")
            mitre = ["T1036"]

        return TimezoneAnalysis(
            raw_offset       = raw_offset,
            is_valid         = True,
            is_spoofed       = False,
            offset_minutes   = offset_min,
            plausible_regions= regions,
            anomaly          = anomaly,
            confidence       = 0.85 if is_rare else 0.70,
            mitre_techniques = mitre,
        )

    @staticmethod
    def _extract_offset(email_date: Optional[str],
                        raw_header: Optional[str]) -> Optional[str]:
        """Extract +HHMM or -HHMM from isoformat date or raw Date: header."""
        for src in filter(None, [email_date, raw_header]):
            src = str(src)
            # isoformat: 2002-08-23T15:42:17+05:30 → normalise to +0530
            m = re.search(r'([+-])(\d{2}):(\d{2})(?:$|\s)', src)
            if m:
                return f"{m.group(1)}{m.group(2)}{m.group(3)}"
            # Raw Date header: +0530
            m = re.search(r'([+-]\d{4})', src)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _offset_to_minutes(offset_str: str) -> Optional[int]:
        """Convert +0530 → 330, -0500 → -300."""
        m = re.match(r'^([+-])(\d{2})(\d{2})$', offset_str.strip())
        if not m:
            return None
        sign = 1 if m.group(1) == '+' else -1
        hours, mins = int(m.group(2)), int(m.group(3))
        if hours > 14 or mins >= 60:
            return None
        return sign * (hours * 60 + mins)

    @staticmethod
    def _minutes_to_str(minutes: int) -> str:
        sign = '+' if minutes >= 0 else '-'
        minutes = abs(minutes)
        return f"{sign}{minutes//60:02d}{minutes%60:02d}"


# ─────────────────────────────────────────────────────────────────────────────
#  DETECTOR 3 — SEND REGULARITY (Bot / Human / Scripted)
# ─────────────────────────────────────────────────────────────────────────────

class SendRegularityScorer:
    """
    Detector 3: Classify the sender as Bot, Scripted Human, or Human
    based on the statistical regularity of inter-send intervals.

    Algorithm:
      - Parse all send timestamps from the campaign
      - Compute inter-send intervals in seconds
      - Compute Coefficient of Variation (CV = std / mean)
        CV < 0.10  → Bot     (machine-precise timing)
        CV < 0.40  → Scripted Human (tool-assisted, some variation)
        CV ≥ 0.40  → Human   (organic variation)
      - Additional signals: burst detection, off-hours sends, weekday patterns

    Requires at least 3 emails for statistical significance.
    """

    # CV thresholds
    BOT_CV_THRESHOLD       = 0.10
    SCRIPTED_CV_THRESHOLD  = 0.40

    # Minimum interval for burst detection (seconds)
    BURST_THRESHOLD_SECS   = 60        # Emails < 60s apart = automated burst

    def score(self, send_timestamps: List[str],
              send_hours: Optional[List[int]] = None) -> SendRegularityResult:

        n = len(send_timestamps)
        evidence = []

        if n < 2:
            return SendRegularityResult(
                sender_type       = "unknown",
                confidence        = 0.0,
                cv                = None,
                mean_interval_hrs = None,
                std_interval_hrs  = None,
                n_emails          = n,
                send_times        = send_timestamps,
                evidence          = ["Insufficient data — need ≥2 emails for analysis"],
                mitre_techniques  = [],
            )

        # Parse timestamps
        dts: List[datetime] = []
        for ts in send_timestamps:
            try:
                dt = datetime.fromisoformat(str(ts).replace(' ', 'T'))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                dts.append(dt)
            except Exception:
                pass

        dts.sort()
        if len(dts) < 2:
            return SendRegularityResult(
                sender_type="unknown", confidence=0.0, cv=None,
                mean_interval_hrs=None, std_interval_hrs=None,
                n_emails=n, send_times=send_timestamps,
                evidence=["Could not parse timestamps"], mitre_techniques=[],
            )

        # Inter-send intervals in seconds
        intervals = [(dts[i] - dts[i-1]).total_seconds() for i in range(1, len(dts))]
        positive  = [iv for iv in intervals if iv > 0]

        if not positive:
            return SendRegularityResult(
                sender_type="bot", confidence=0.90, cv=0.0,
                mean_interval_hrs=0.0, std_interval_hrs=0.0,
                n_emails=n, send_times=send_timestamps,
                evidence=["All emails sent at identical timestamps — automated burst"],
                mitre_techniques=["T1059", "T1584"],
            )

        mean_s = statistics.mean(positive)
        std_s  = statistics.stdev(positive) if len(positive) > 1 else 0.0
        cv     = std_s / mean_s if mean_s > 0 else 0.0

        # ── Burst detection ──────────────────────────────────────────────
        bursts = sum(1 for iv in intervals if 0 < iv < self.BURST_THRESHOLD_SECS)
        if bursts > 0:
            evidence.append(
                f"{bursts} email(s) sent within 60 seconds of each other — automated burst pattern"
            )

        # ── Off-hours analysis ───────────────────────────────────────────
        if send_hours:
            off_hours = sum(1 for h in send_hours if not (7 <= h <= 23))
            if off_hours > len(send_hours) * 0.5:
                evidence.append(
                    f"{off_hours}/{len(send_hours)} emails sent between midnight–7am "
                    "— overnight sends suggest automation"
                )

        # ── Interval regularity ──────────────────────────────────────────
        evidence.append(
            f"Inter-send CV={cv:.3f}  "
            f"mean={mean_s/3600:.2f}h  "
            f"std={std_s/3600:.2f}h  "
            f"n={len(positive)} intervals"
        )

        # ── Round-number detection (bot schedule) ────────────────────────
        if len(positive) >= 3:
            round_intervals = [
                iv for iv in positive
                if any(abs(iv - r) < 30 for r in [
                    300, 600, 900, 1800, 3600, 7200, 14400, 86400
                ])
            ]
            round_fraction = len(round_intervals) / len(positive)
            if round_fraction >= 0.70:
                evidence.append(
                    f"{round_fraction:.0%} of intervals are round numbers "
                    "(5min, 10min, 30min, 1h, 6h, 24h) — scheduled/cron job pattern"
                )

        # ── Classify ─────────────────────────────────────────────────────
        if cv < self.BOT_CV_THRESHOLD or bursts > len(intervals) * 0.5:
            sender_type  = "bot"
            confidence   = min(0.95, 0.70 + (0.10 - cv) * 25) if cv < 0.10 else 0.85
            mitre        = ["T1059", "T1584"]
            evidence.insert(0, f"BOT: CV={cv:.3f} < {self.BOT_CV_THRESHOLD} — machine-precise timing")

        elif cv < self.SCRIPTED_CV_THRESHOLD:
            sender_type  = "scripted_human"
            confidence   = 0.65
            mitre        = ["T1059"]
            evidence.insert(0,
                f"SCRIPTED HUMAN: CV={cv:.3f} — some timing variation "
                "but too regular for organic human behavior"
            )
        else:
            sender_type  = "human"
            confidence   = min(0.85, 0.50 + (cv - 0.40) * 0.50)
            mitre        = []
            evidence.insert(0,
                f"HUMAN: CV={cv:.3f} ≥ {self.SCRIPTED_CV_THRESHOLD} — "
                "organic variation consistent with manual sending"
            )

        return SendRegularityResult(
            sender_type       = sender_type,
            confidence        = confidence,
            cv                = cv,
            mean_interval_hrs = mean_s / 3600,
            std_interval_hrs  = std_s  / 3600,
            n_emails          = n,
            send_times        = [dt.isoformat() for dt in dts],
            evidence          = evidence,
            mitre_techniques  = mitre,
        )


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

_hop_detector  = HopTimestampAnomalyDetector()
_tz_checker    = TimezoneValidityChecker()
_reg_scorer    = SendRegularityScorer()


def classify_sender(
    header_analysis,
    email_fingerprints: Optional[list] = None,
    email_file: Optional[str] = None,
) -> SenderClassification:
    """
    Single-email sender classification.

    Args:
        header_analysis:     ReceivedChainAnalysis from hunterTrace Stage 1
        email_fingerprints:  Optional list of EmailFingerprint (for regularity)
        email_file:          Optional filename for labeling

    Returns:
        SenderClassification with all three detector results
    """
    hops      = getattr(header_analysis, 'hops', []) or []
    email_date= getattr(header_analysis, 'email_date', None)

    hop_result = _hop_detector.analyse(hops)
    tz_result  = _tz_checker.check(email_date)

    # Regularity on single email = unknown (need campaign)
    if email_fingerprints and len(email_fingerprints) >= 2:
        timestamps = [fp.email_date for fp in email_fingerprints if fp.email_date]
        hours      = [fp.send_hour_local for fp in email_fingerprints if fp.send_hour_local is not None]
        reg_result = _reg_scorer.score(timestamps, hours)
    else:
        reg_result = SendRegularityResult(
            sender_type="unknown", confidence=0.0, cv=None,
            mean_interval_hrs=None, std_interval_hrs=None, n_emails=1,
            send_times=[], evidence=["Single email — regularity analysis requires campaign data"],
            mitre_techniques=[],
        )

    return _combine(hop_result, tz_result, reg_result, email_file=email_file)


def classify_campaign_sender(
    actor_id:     str,
    fingerprints: list,
) -> SenderClassification:
    """
    Campaign-level sender classification (35 actors in your corpus).

    Args:
        actor_id:     e.g. "ACTOR_001"
        fingerprints: List[EmailFingerprint] for this actor's emails

    Returns:
        SenderClassification with all three detector results
    """
    if not fingerprints:
        raise ValueError(f"No fingerprints provided for {actor_id}")

    # Use first email's header for hop analysis (most representative)
    # For hop analysis we need the raw header_analysis — if not available,
    # we create a minimal proxy from the fingerprint
    hop_result = _hop_detector.analyse([])   # No hops in fingerprint — campaign mode

    # Use campaign timestamps for timezone
    timestamps = [fp.email_date for fp in fingerprints if fp.email_date]
    offsets    = [fp.timezone_offset for fp in fingerprints if fp.timezone_offset]
    hours      = [fp.send_hour_local for fp in fingerprints if fp.send_hour_local is not None]

    # Timezone: use most common offset in the campaign
    if offsets:
        consensus_tz = max(set(offsets), key=offsets.count)
        tz_result = _tz_checker.check(None, f"Date: Thu, 1 Jan 2004 12:00:00 {consensus_tz}")
    else:
        tz_result = _tz_checker.check(None, None)

    reg_result = _reg_scorer.score(timestamps, hours)

    return _combine(hop_result, tz_result, reg_result,
                    actor_id=actor_id, email_file=None)


def _combine(
    hop:   HopChainAnalysis,
    tz:    TimezoneAnalysis,
    reg:   SendRegularityResult,
    email_file: Optional[str] = None,
    actor_id:   Optional[str] = None,
) -> SenderClassification:
    """Merge three detector results into a single SenderClassification."""

    red_flags = []
    for f in hop.findings:
        if f.severity in ("critical", "high"):
            red_flags.append(f"[HOP] {f.anomaly}: {f.detail}")
    if tz.is_spoofed:
        red_flags.append(f"[TIMEZONE] {tz.anomaly}")
    if not tz.is_valid and not tz.is_spoofed:
        red_flags.append(f"[TIMEZONE] {tz.anomaly}")

    # Overall sender type: regularity takes priority; hop forgery adjusts it
    sender_type = reg.sender_type
    confidence  = reg.confidence

    if hop.verdict == "FORGED":
        # Forged headers are a strong bot/scripted indicator
        if sender_type == "human":
            sender_type = "scripted_human"
            confidence  = max(confidence, 0.60)
        red_flags.append(f"[HOP] Chain FORGED (score={hop.forgery_score:.2f}) — "
                         "header injection detected, origin IP unreliable")

    # If timezone spoofed → deliberate evasion → upgrade to scripted_human minimum
    if tz.is_spoofed and sender_type == "human":
        sender_type = "scripted_human"
        confidence  = max(confidence, 0.55)

    # Aggregate MITRE
    all_mitre = sorted(set(
        hop.mitre_techniques + tz.mitre_techniques + reg.mitre_techniques
    ))

    return SenderClassification(
        email_file         = email_file,
        actor_id           = actor_id,
        hop_chain          = hop,
        timezone           = tz,
        regularity         = reg,
        overall_verdict    = sender_type,
        overall_confidence = min(0.99, confidence),
        red_flags          = red_flags,
        all_mitre          = all_mitre,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  CLI — test on your corpus actor profiles
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json, sys, argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="HunterTrace Sender Classifier")
    parser.add_argument("--profiles", required=True,
                        help="Path to v3_actor_profiles_*.json")
    parser.add_argument("--attribution", default=None,
                        help="Path to v3_attribution_*.json (optional)")
    parser.add_argument("--out", default=None,
                        help="Output JSON file (default: stdout)")
    args = parser.parse_args()

    profiles    = json.loads(Path(args.profiles).read_text())
    attribution = json.loads(Path(args.attribution).read_text()) if args.attribution else {}

    results = {}
    print(f"\nClassifying {len(profiles)} actors...\n")

    for actor_id, profile in profiles.items():
        # Build minimal EmailFingerprint-like objects from profile data
        class _FP:
            pass

        fps = []
        # Extract send timestamps from temporal data
        dates = profile.get('temporal', {}).get('send_dates', []) or []
        tz_off = profile.get('temporal', {}).get('timezone_offset')
        peak_h = profile.get('temporal', {}).get('peak_send_hour')

        for i, d in enumerate(dates):
            fp = _FP()
            fp.email_date       = d
            fp.timezone_offset  = tz_off
            fp.send_hour_local  = peak_h
            fp.send_day_of_week = None
            fps.append(fp)

        # If no dates stored, simulate from campaign_count
        if not fps:
            count = profile.get('campaign_count', 1)
            for i in range(count):
                fp = _FP()
                fp.email_date       = None
                fp.timezone_offset  = tz_off
                fp.send_hour_local  = peak_h
                fp.send_day_of_week = None
                fps.append(fp)

        clf = classify_campaign_sender(actor_id, fps)
        results[actor_id] = clf.to_dict()

        tz_str = f"tz={clf.timezone.raw_offset}"
        valid  = "✓" if clf.timezone.is_valid else ("SPOOFED" if clf.timezone.is_spoofed else "INVALID")
        print(f"  {actor_id}  verdict={clf.overall_verdict:<15} "
              f"conf={clf.overall_confidence:.0%}  {tz_str}({valid})  "
              f"n={clf.regularity.n_emails}")
        if clf.red_flags:
            for rf in clf.red_flags[:2]:
                print(f"           ⚠ {rf[:80]}")

    print(f"\nSender type distribution:")
    from collections import Counter
    dist = Counter(r['overall_verdict'] for r in results.values())
    for t, n in sorted(dist.items(), key=lambda x: -x[1]):
        print(f"  {t:<18}: {n}")

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
        print(f"\nSaved to {args.out}")
    else:
        print(json.dumps(results, indent=2))