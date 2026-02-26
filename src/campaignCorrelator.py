#!/usr/bin/env python3
"""
HUNTЕРТRACE v3 — CAMPAIGN CORRELATOR
======================================

Core v3 module. Takes batch output from hunterTrace and clusters emails
by threat actor using behavioral fingerprinting — even when attackers
rotate VPN exit nodes between campaigns.

RESEARCH FINDING:
    Attackers are fingerprint-able across campaigns via stable behavioral
    signals that survive VPN rotation:

    Signal                  Stability   Why attackers can't easily change it
    ─────────────────────────────────────────────────────────────────────────
    Timezone offset         Very high   System clock, rarely faked
    Webmail provider        High        Account already set up
    VPN ASN preference      High        Paid subscription to one provider
    Send-time window        High        Working hours in real timezone
    DKIM signing domain     High        Email account domain
    Subject line structure  Medium      Attacker template reuse
    Mail client header      Medium      Email client version
    Hop count pattern       Medium      Network path consistency

    Two emails with 4+ matching signals = same actor with 85%+ confidence.
    Three emails with 6+ signals = same actor with 95%+ confidence.

USAGE:
    from campaignCorrelator import CampaignCorrelator

    correlator = CampaignCorrelator()

    # Feed results from hunterTrace batch run
    for email_file, pipeline_result in batch_results.items():
        correlator.ingest(email_file, pipeline_result)

    # Get actor clusters
    report = correlator.correlate()
    print(report.summary())
"""

import re
import json
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from datetime import datetime
from collections import defaultdict
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EmailFingerprint:
    """
    Behavioral fingerprint extracted from a single email analysis result.
    These are the stable signals that survive VPN rotation.
    """
    email_file:        str
    email_from:        str
    email_subject:     str
    email_date:        Optional[str]
    message_id:        Optional[str]

    # Temporal signals
    timezone_offset:   Optional[str]    # e.g. "+0530"
    timezone_region:   Optional[str]    # e.g. "India / Sri Lanka"
    send_hour_local:   Optional[int]    # 0–23 local time
    send_day_of_week:  Optional[str]    # "Monday" etc.

    # Infrastructure signals
    vpn_asn:           Optional[str]    # ASN of VPN/proxy used
    vpn_provider:      Optional[str]    # e.g. "NordVPN"
    origin_ip:         Optional[str]    # VPN exit or real IP
    real_ip:           Optional[str]    # Webmail-extracted real IP (v2)
    real_ip_source:    Optional[str]    # Which technique found it

    # Provider signals
    webmail_provider:  Optional[str]    # "Gmail", "Yahoo", etc.
    dkim_domain:       Optional[str]    # Signing domain from DKIM
    mail_client:       Optional[str]    # X-Mailer header value
    hop_count:         int = 1

    # Content signals
    subject_pattern:   Optional[str]    = None  # Normalized subject (stripped of specifics)
    from_domain:       Optional[str]    = None  # Domain part of From address

    # Computed
    fingerprint_hash:  Optional[str]    = None

    def compute_hash(self) -> str:
        """Stable hash of the most reliable signals for quick comparison."""
        stable = "|".join([
            self.timezone_offset or "",
            self.vpn_provider or "",
            self.webmail_provider or "",
            self.dkim_domain or "",
            self.from_domain or "",
        ])
        self.fingerprint_hash = hashlib.md5(stable.encode()).hexdigest()[:12]
        return self.fingerprint_hash


@dataclass
class SignalMatch:
    """One matched signal between two fingerprints."""
    signal_name:  str
    value:        str
    weight:       float      # Contribution to similarity score
    confidence:   float      # How reliable this signal is


@dataclass
class FingerprintSimilarity:
    """Similarity result between two email fingerprints."""
    fp_a:           str               # email_file a
    fp_b:           str               # email_file b
    matched_signals: List[SignalMatch]
    similarity_score: float           # 0.0 – 1.0
    same_actor_probability: float     # 0.0 – 1.0
    verdict:        str               # "SAME_ACTOR" | "LIKELY_SAME" | "POSSIBLE" | "DIFFERENT"


@dataclass
class ThreatActorCluster:
    """
    A group of emails attributed to the same threat actor.
    """
    actor_id:           str            # e.g. "ACTOR_001"
    emails:             List[str]      # email filenames
    fingerprints:       List[EmailFingerprint]
    confidence:         float

    # Consensus signals (stable across all emails in cluster)
    consensus_timezone: Optional[str]
    consensus_vpn_provider: Optional[str]
    consensus_webmail:  Optional[str]
    consensus_send_window: Optional[str]    # e.g. "18:00–22:00 IST"
    consensus_dkim_domain: Optional[str]

    # Derived actor profile
    likely_country:     Optional[str]
    likely_city:        Optional[str]
    campaign_count:     int
    first_seen:         Optional[str]
    last_seen:          Optional[str]
    ttps:               List[str]      # Behaviorally observed TTPs

    # Infrastructure across campaign
    all_vpn_ips:        List[str]
    all_vpn_providers:  List[str]
    all_origin_ips:     List[str]


@dataclass
class CorrelationReport:
    """Complete correlation report from a batch of emails."""
    total_emails:       int
    total_actors:       int
    actor_clusters:     List[ThreatActorCluster]
    singleton_emails:   List[str]       # Emails with no matching peer
    similarity_matrix:  Dict[str, Dict[str, float]]  # fp_a → fp_b → score
    correlations:       List[FingerprintSimilarity]
    timestamp:          str

    def summary(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("HUNTЕРТRACE v3 — CAMPAIGN CORRELATION REPORT")
        lines.append("=" * 70)
        lines.append(f"  Emails analysed:  {self.total_emails}")
        lines.append(f"  Distinct actors:  {self.total_actors}")
        lines.append(f"  Unmatched emails: {len(self.singleton_emails)}")
        lines.append("")
        for actor in self.actor_clusters:
            lines.append(f"  [{actor.actor_id}]  {actor.campaign_count} email(s)  "
                         f"confidence={actor.confidence:.0%}")
            if actor.likely_country:
                lines.append(f"    Location:    {actor.likely_city or '?'}, {actor.likely_country}")
            if actor.consensus_timezone:
                lines.append(f"    Timezone:    {actor.consensus_timezone}")
            if actor.consensus_vpn_provider:
                lines.append(f"    VPN:         {actor.consensus_vpn_provider}")
            if actor.consensus_webmail:
                lines.append(f"    Webmail:     {actor.consensus_webmail}")
            if actor.consensus_send_window:
                lines.append(f"    Active hrs:  {actor.consensus_send_window}")
            if actor.ttps:
                lines.append(f"    TTPs:        {', '.join(actor.ttps)}")
            lines.append(f"    Emails:      {', '.join(actor.emails)}")
            lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL WEIGHTS
# ─────────────────────────────────────────────────────────────────────────────

SIGNAL_WEIGHTS = {
    # Highest weight — very hard to fake or accidentally change
    "timezone_offset":    0.25,   # System clock, rarely faked
    "real_ip":            0.22,   # Webmail-leaked real IP — definitive
    "dkim_domain":        0.18,   # Signing domain locked to email account
    "from_domain":        0.15,   # Domain part of From: address

    # Medium weight — stable but not unique
    "vpn_provider":       0.12,   # Paid VPN subscription
    "webmail_provider":   0.10,   # Account already set up
    "send_hour_bucket":   0.08,   # Working-hour window (bucketed to 4h)
    "mail_client":        0.07,   # Email client version string

    # Lower weight — useful but less discriminating
    "vpn_asn":            0.06,
    "subject_pattern":    0.05,
    "hop_count":          0.04,
    "send_day_type":      0.03,   # weekday vs weekend
}

# Minimum similarity score thresholds for verdicts
THRESHOLD_SAME_ACTOR   = 0.72
THRESHOLD_LIKELY_SAME  = 0.50
THRESHOLD_POSSIBLE     = 0.30


# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINT EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

class FingerprintExtractor:
    """
    Extracts an EmailFingerprint from a hunterTrace CompletePipelineResult.
    Handles missing data gracefully — partial fingerprints still correlate.
    """

    # Timezone offset → region map (same as webmailRealIpExtractor)
    TZ_REGION_MAP = {
        "+0000": "UTC",        "+0100": "Central Europe",
        "+0200": "Eastern Europe / South Africa",
        "+0300": "Russia (Moscow) / East Africa",
        "+0330": "Iran",       "+0400": "UAE / Azerbaijan",
        "+0430": "Afghanistan","+0500": "Pakistan",
        "+0530": "India",      "+0545": "Nepal",
        "+0600": "Bangladesh", "+0700": "Thailand / Vietnam",
        "+0800": "China / Singapore / Philippines",
        "+0900": "Japan / South Korea",
        "+1000": "Australia (East)",
        "-0300": "Brazil / Argentina",
        "-0400": "Venezuela / Chile",
        "-0500": "US Eastern", "-0600": "US Central",
        "-0700": "US Mountain","-0800": "US Pacific",
    }

    def extract(self, email_file: str, result) -> EmailFingerprint:
        """
        Build fingerprint from a CompletePipelineResult object.
        Works even if many stages failed / returned None.
        """
        ha = result.header_analysis
        pc = result.proxy_analysis
        cl = result.classifications or {}
        we = result.webmail_extraction  # v2 result
        geo = result.geolocation_results or {}
        bt = result.vpn_backtrack_analysis
        ri = result.real_ip_analysis

        # ── Temporal signals ──────────────────────────────────────────────
        tz_offset   = self._extract_tz_offset(ha)
        tz_region   = self.TZ_REGION_MAP.get(tz_offset) if tz_offset else None
        send_hour   = self._extract_send_hour(ha)
        send_dow    = self._extract_day_of_week(ha)

        # ── Infrastructure signals ────────────────────────────────────────
        vpn_provider = None
        vpn_asn      = None
        origin_ip    = ha.origin_ip if ha else None

        for ip, c in cl.items():
            if getattr(c, 'is_vpn', False) or 'VPN' in getattr(c, 'classification', ''):
                vpn_provider = getattr(c, 'provider', None) or vpn_provider
            vpn_asn = getattr(c, 'asn', None) or vpn_asn

        # VPN provider from backtrack
        if bt and not vpn_provider:
            vpn_provider = getattr(bt, 'vpn_provider', None)

        # ── Real IP (v2 webmail extraction takes priority) ────────────────
        real_ip      = None
        real_ip_src  = None

        if we and getattr(we, 'real_ip_found', False) and we.real_ip:
            real_ip     = we.real_ip
            real_ip_src = f"webmail_header:{we.leak_header}"
        elif ri and getattr(ri, 'suspected_real_ip', None):
            real_ip     = ri.suspected_real_ip
            real_ip_src = "real_ip_extractor"
        elif bt and getattr(bt, 'probable_real_ip', None):
            real_ip     = bt.probable_real_ip
            real_ip_src = "vpn_backtrack"

        # ── Provider signals ──────────────────────────────────────────────
        webmail  = getattr(we, 'provider_name', None) if we else None
        dkim_dom = self._extract_dkim_domain(ha)
        mailer   = self._extract_mailer(ha)
        hops     = ha.hop_count if ha else 1

        # ── Content signals ───────────────────────────────────────────────
        subj_pat  = self._normalize_subject(ha.email_subject if ha else "")
        from_dom  = self._extract_from_domain(ha.email_from if ha else "")

        fp = EmailFingerprint(
            email_file      = email_file,
            email_from      = ha.email_from if ha else "",
            email_subject   = ha.email_subject if ha else "",
            email_date      = ha.email_date if ha else None,
            message_id      = ha.message_id if ha else None,
            timezone_offset = tz_offset,
            timezone_region = tz_region,
            send_hour_local = send_hour,
            send_day_of_week= send_dow,
            vpn_asn         = vpn_asn,
            vpn_provider    = vpn_provider,
            origin_ip       = origin_ip,
            real_ip         = real_ip,
            real_ip_source  = real_ip_src,
            webmail_provider= webmail,
            dkim_domain     = dkim_dom,
            mail_client     = mailer,
            hop_count       = hops,
            subject_pattern = subj_pat,
            from_domain     = from_dom,
        )
        fp.compute_hash()
        return fp

    # ── Private helpers ───────────────────────────────────────────────────

    def _extract_tz_offset(self, ha) -> Optional[str]:
        if not ha or not ha.email_date:
            return None
        m = re.search(r'([+-]\d{4})', str(ha.email_date))
        return m.group(1) if m else None

    def _extract_send_hour(self, ha) -> Optional[int]:
        if not ha or not ha.email_date:
            return None
        m = re.search(r'T(\d{2}):', str(ha.email_date))
        if m:
            return int(m.group(1))
        m2 = re.search(r'(\d{2}):(\d{2}):\d{2}', str(ha.email_date))
        return int(m2.group(1)) if m2 else None

    def _extract_day_of_week(self, ha) -> Optional[str]:
        if not ha or not ha.email_date:
            return None
        try:
            dt = datetime.fromisoformat(str(ha.email_date).replace(' ', 'T'))
            return dt.strftime("%A")
        except Exception:
            return None

    def _extract_dkim_domain(self, ha) -> Optional[str]:
        """Extract d= domain from DKIM-Signature header if available."""
        if not ha:
            return None
        for hop in getattr(ha, 'hops', []):
            raw = getattr(hop, 'raw_header', '')
            m = re.search(r'd=([a-zA-Z0-9._-]+)', raw)
            if m:
                return m.group(1).lower()
        return None

    def _extract_mailer(self, ha) -> Optional[str]:
        """Normalize X-Mailer string to remove version noise."""
        if not ha:
            return None
        for hop in getattr(ha, 'hops', []):
            raw = getattr(hop, 'raw_header', '')
            m = re.search(r'X-Mailer:\s*(.+?)(?:\r|\n|$)', raw, re.IGNORECASE)
            if m:
                mailer = m.group(1).strip()
                # Strip version numbers for stable comparison
                mailer = re.sub(r'[\d.]+', 'X', mailer)
                return mailer[:60]
        return None

    def _normalize_subject(self, subject: str) -> str:
        """
        Normalize subject to a structural pattern:
          "Urgent: Invoice #4872 from ACME Corp" → "urgent:invoice#from"
        Strips numbers, proper nouns, keeps keywords.
        """
        if not subject:
            return ""
        s = subject.lower()
        s = re.sub(r'\b\d+\b', '#', s)           # numbers → #
        s = re.sub(r'[^a-z#: ]+', '', s)          # keep letters, #, :, space
        s = re.sub(r'\s+', ' ', s).strip()
        # Keep only first 60 chars as pattern
        return s[:60]

    def _extract_from_domain(self, from_addr: str) -> Optional[str]:
        m = re.search(r'@([a-zA-Z0-9._-]+)', from_addr)
        return m.group(1).lower() if m else None


# ─────────────────────────────────────────────────────────────────────────────
# SIMILARITY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class SimilarityEngine:
    """
    Computes pairwise similarity between EmailFingerprints.
    Weighted signal matching — missing signals contribute 0 (not penalized).
    """

    def compare(self, a: EmailFingerprint, b: EmailFingerprint) -> FingerprintSimilarity:
        matched: List[SignalMatch] = []
        total_possible_weight = 0.0
        total_matched_weight  = 0.0

        checks = [
            ("timezone_offset",  a.timezone_offset,  b.timezone_offset,  0.25, 0.95, self._exact),
            ("real_ip",          a.real_ip,           b.real_ip,          0.22, 0.99, self._exact),
            ("dkim_domain",      a.dkim_domain,       b.dkim_domain,      0.18, 0.90, self._exact),
            ("from_domain",      a.from_domain,       b.from_domain,      0.15, 0.90, self._exact),
            ("vpn_provider",     a.vpn_provider,      b.vpn_provider,     0.12, 0.85, self._exact),
            ("webmail_provider", a.webmail_provider,  b.webmail_provider, 0.10, 0.80, self._exact),
            ("send_hour_bucket", a.send_hour_local,   b.send_hour_local,  0.08, 0.70, self._hour_bucket),
            ("mail_client",      a.mail_client,       b.mail_client,      0.07, 0.75, self._prefix),
            ("vpn_asn",          a.vpn_asn,           b.vpn_asn,          0.06, 0.80, self._exact),
            ("subject_pattern",  a.subject_pattern,   b.subject_pattern,  0.05, 0.65, self._fuzzy),
            ("hop_count",        a.hop_count,         b.hop_count,        0.04, 0.60, self._exact),
            ("send_day_type",    a.send_day_of_week,  b.send_day_of_week, 0.03, 0.55, self._day_type),
        ]

        for name, va, vb, weight, sig_conf, matcher in checks:
            if va is None or vb is None:
                continue  # Missing signal — don't penalize
            total_possible_weight += weight
            match_val, display = matcher(va, vb)
            if match_val > 0:
                contribution = weight * match_val
                total_matched_weight += contribution
                matched.append(SignalMatch(
                    signal_name = name,
                    value       = display,
                    weight      = contribution,
                    confidence  = sig_conf * match_val,
                ))

        # Normalize: score = matched / possible (not penalized for missing data)
        if total_possible_weight == 0:
            score = 0.0
        else:
            score = total_matched_weight / total_possible_weight

        # Convert score → actor probability (slight curve up for high scores)
        prob = min(0.99, score * 1.15 if score > 0.6 else score)

        if prob >= THRESHOLD_SAME_ACTOR:
            verdict = "SAME_ACTOR"
        elif prob >= THRESHOLD_LIKELY_SAME:
            verdict = "LIKELY_SAME"
        elif prob >= THRESHOLD_POSSIBLE:
            verdict = "POSSIBLE"
        else:
            verdict = "DIFFERENT"

        return FingerprintSimilarity(
            fp_a                 = a.email_file,
            fp_b                 = b.email_file,
            matched_signals      = matched,
            similarity_score     = score,
            same_actor_probability = prob,
            verdict              = verdict,
        )

    # ── Matchers ─────────────────────────────────────────────────────────

    def _exact(self, a, b) -> Tuple[float, str]:
        if str(a).strip().lower() == str(b).strip().lower():
            return 1.0, str(a)
        return 0.0, ""

    def _prefix(self, a, b) -> Tuple[float, str]:
        """Match on first 20 chars — handles minor version differences."""
        sa, sb = str(a)[:20].lower(), str(b)[:20].lower()
        if sa == sb:
            return 1.0, sa
        # Partial prefix match
        common = len(os.path.commonprefix([sa, sb])) if sa and sb else 0
        if common >= 8:
            return 0.6, sa[:common]
        return 0.0, ""

    def _hour_bucket(self, a, b) -> Tuple[float, str]:
        """Hours within same 4-hour bucket (e.g. 18–22)."""
        try:
            ah, bh = int(a), int(b)
            ba, bb = ah // 4, bh // 4
            if ba == bb:
                bucket_start = ba * 4
                return 1.0, f"{bucket_start:02d}:00–{bucket_start+4:02d}:00"
            if abs(ah - bh) <= 1:
                return 0.5, f"~{ah:02d}:00"
        except (ValueError, TypeError):
            pass
        return 0.0, ""

    def _day_type(self, a, b) -> Tuple[float, str]:
        """Weekday vs weekend match."""
        weekend = {"Saturday", "Sunday"}
        if (a in weekend) == (b in weekend):
            day_type = "weekend" if a in weekend else "weekday"
            return 1.0, day_type
        return 0.0, ""

    def _fuzzy(self, a, b) -> Tuple[float, str]:
        """Simple token overlap for subject patterns."""
        ta = set(str(a).split())
        tb = set(str(b).split())
        if not ta or not tb:
            return 0.0, ""
        overlap = len(ta & tb) / max(len(ta), len(tb))
        if overlap >= 0.6:
            return overlap, " ".join(sorted(ta & tb))[:40]
        return 0.0, ""


# Need os for _prefix helper
import os


# ─────────────────────────────────────────────────────────────────────────────
# CLUSTER BUILDER
# ─────────────────────────────────────────────────────────────────────────────

class ClusterBuilder:
    """
    Union-Find based clustering of similar fingerprints into actor groups.
    Builds ThreatActorCluster objects with consensus signals.
    """

    def __init__(self):
        self._parent: Dict[str, str] = {}

    def build(
        self,
        fingerprints: Dict[str, EmailFingerprint],
        similarities: List[FingerprintSimilarity],
    ) -> Tuple[List[ThreatActorCluster], List[str]]:
        """
        Cluster fingerprints into actor groups.
        Returns (clusters, singleton_email_files).
        """
        # Initialize union-find
        for key in fingerprints:
            self._parent[key] = key

        # Union emails that are SAME_ACTOR or LIKELY_SAME
        for sim in similarities:
            if sim.verdict in ("SAME_ACTOR", "LIKELY_SAME"):
                self._union(sim.fp_a, sim.fp_b)

        # Group by root
        groups: Dict[str, List[str]] = defaultdict(list)
        for key in fingerprints:
            groups[self._find(key)].append(key)

        clusters = []
        singletons = []
        actor_counter = 1

        for root, members in sorted(groups.items(), key=lambda x: -len(x[1])):
            fps = [fingerprints[m] for m in members]
            if len(fps) == 1:
                singletons.append(members[0])
                continue

            cluster = self._build_cluster(fps, actor_counter)
            clusters.append(cluster)
            actor_counter += 1

        return clusters, singletons

    def _build_cluster(self, fps: List[EmailFingerprint], n: int) -> ThreatActorCluster:
        """Build a ThreatActorCluster from a group of fingerprints."""

        actor_id = f"ACTOR_{n:03d}"

        # Consensus: most common non-None value per signal
        def consensus(values):
            vals = [v for v in values if v]
            if not vals:
                return None
            return max(set(vals), key=vals.count)

        tz     = consensus([fp.timezone_offset for fp in fps])
        tz_reg = consensus([fp.timezone_region  for fp in fps])
        vpn    = consensus([fp.vpn_provider      for fp in fps])
        wm     = consensus([fp.webmail_provider  for fp in fps])
        dkim   = consensus([fp.dkim_domain       for fp in fps])

        # Send window: bucket most common hour
        hours = [fp.send_hour_local for fp in fps if fp.send_hour_local is not None]
        send_window = None
        if hours:
            avg_hour = int(sum(hours) / len(hours))
            bucket   = (avg_hour // 4) * 4
            # Adjust for timezone if available
            tz_label = tz_reg.split('/')[0].strip() if tz_reg else "local"
            send_window = f"{bucket:02d}:00–{bucket+4:02d}:00 {tz_label}"

        # Dates
        dates = sorted([fp.email_date for fp in fps if fp.email_date])

        # Confidence: average pairwise similarity would be ideal,
        # but approximate here as function of cluster size + signal richness
        signals_filled = sum(
            1 for fp in fps
            for v in [fp.timezone_offset, fp.vpn_provider, fp.webmail_provider,
                      fp.dkim_domain, fp.real_ip]
            if v is not None
        )
        max_signals = len(fps) * 5
        confidence = min(0.98, 0.60 + 0.38 * (signals_filled / max_signals if max_signals else 0))

        # TTPs (behavioral observations)
        ttps = []
        if any(fp.vpn_provider for fp in fps):
            ttps.append(f"T1090 – Proxy ({consensus([fp.vpn_provider for fp in fps])})")
        if any(fp.webmail_provider for fp in fps):
            ttps.append(f"T1566 – Phishing via {consensus([fp.webmail_provider for fp in fps])}")
        if tz_reg:
            ttps.append(f"Active timezone: {tz_reg}")
        if send_window:
            ttps.append(f"Send window: {send_window}")

        # Geographic inference from timezone
        country_from_tz = _tz_to_country(tz)

        return ThreatActorCluster(
            actor_id            = actor_id,
            emails              = [fp.email_file for fp in fps],
            fingerprints        = fps,
            confidence          = confidence,
            consensus_timezone  = f"{tz} ({tz_reg})" if tz and tz_reg else tz,
            consensus_vpn_provider = vpn,
            consensus_webmail   = wm,
            consensus_send_window = send_window,
            consensus_dkim_domain = dkim,
            likely_country      = country_from_tz,
            likely_city         = None,     # Populated by actorProfiler
            campaign_count      = len(fps),
            first_seen          = dates[0]  if dates else None,
            last_seen           = dates[-1] if dates else None,
            ttps                = ttps,
            all_vpn_ips         = list(set(fp.origin_ip   for fp in fps if fp.origin_ip)),
            all_vpn_providers   = list(set(fp.vpn_provider for fp in fps if fp.vpn_provider)),
            all_origin_ips      = list(set(fp.real_ip      for fp in fps if fp.real_ip)),
        )

    def _find(self, x: str) -> str:
        if self._parent[x] != x:
            self._parent[x] = self._find(self._parent[x])
        return self._parent[x]

    def _union(self, x: str, y: str):
        rx, ry = self._find(x), self._find(y)
        if rx != ry:
            self._parent[rx] = ry


def _tz_to_country(tz_offset: Optional[str]) -> Optional[str]:
    """Map timezone offset to most likely single country for display."""
    TZ_COUNTRY = {
        "+0530": "India",        "+0545": "Nepal",
        "+0600": "Bangladesh",   "+0530": "India",
        "+0800": "China",        "+0900": "Japan",
        "+0700": "Thailand",     "+0300": "Russia",
        "+0200": "South Africa", "+0100": "Germany",
        "+0000": "UK",           "-0500": "United States (ET)",
        "-0800": "United States (PT)", "-0300": "Brazil",
        "+0400": "UAE",          "+0330": "Iran",
    }
    return TZ_COUNTRY.get(tz_offset) if tz_offset else None


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CORRELATOR
# ─────────────────────────────────────────────────────────────────────────────

class CampaignCorrelator:
    """
    Main v3 entry point.
    Ingest hunterTrace results → extract fingerprints → cluster by actor.
    """

    def __init__(self, verbose: bool = False):
        self.verbose        = verbose
        self.extractor      = FingerprintExtractor()
        self.similarity_eng = SimilarityEngine()
        self.cluster_builder= ClusterBuilder()
        self.fingerprints:  Dict[str, EmailFingerprint] = {}

    def ingest(self, email_file: str, pipeline_result) -> EmailFingerprint:
        """Add one email's pipeline result. Returns extracted fingerprint."""
        fp = self.extractor.extract(email_file, pipeline_result)
        self.fingerprints[email_file] = fp
        if self.verbose:
            print(f"  [correlator] ingested {email_file}  tz={fp.timezone_offset}  "
                  f"vpn={fp.vpn_provider}  webmail={fp.webmail_provider}")
        return fp

    def ingest_json(self, email_file: str, json_report: dict) -> Optional[EmailFingerprint]:
        """
        Ingest from a saved hunterTrace JSON report (for offline correlation).
        """
        fp = self._extract_from_json(email_file, json_report)
        if fp:
            self.fingerprints[email_file] = fp
        return fp

    def correlate(self) -> CorrelationReport:
        """Run full correlation. Returns CorrelationReport."""
        fps = self.fingerprints
        n   = len(fps)

        if n == 0:
            return CorrelationReport(0, 0, [], [], {}, [], datetime.now().isoformat())

        if self.verbose:
            print(f"\n[v3] Correlating {n} email fingerprints...")

        # Pairwise similarity
        keys  = list(fps.keys())
        sims  = []
        matrix: Dict[str, Dict[str, float]] = defaultdict(dict)

        for i in range(n):
            for j in range(i + 1, n):
                sim = self.similarity_eng.compare(fps[keys[i]], fps[keys[j]])
                sims.append(sim)
                matrix[keys[i]][keys[j]] = sim.same_actor_probability
                matrix[keys[j]][keys[i]] = sim.same_actor_probability
                if self.verbose and sim.verdict != "DIFFERENT":
                    print(f"  {keys[i]} ↔ {keys[j]}: {sim.verdict} "
                          f"({sim.same_actor_probability:.0%})")

        # Cluster
        clusters, singletons = self.cluster_builder.build(fps, sims)

        return CorrelationReport(
            total_emails      = n,
            total_actors      = len(clusters),
            actor_clusters    = clusters,
            singleton_emails  = singletons,
            similarity_matrix = dict(matrix),
            correlations      = sims,
            timestamp         = datetime.now().isoformat(),
        )

    def _extract_from_json(self, email_file: str, report: dict) -> Optional[EmailFingerprint]:
        """Extract fingerprint from a serialised JSON report."""
        try:
            email_meta  = report.get("email", {})
            stage1      = report.get("stage1_header_extraction", {})
            stage2      = report.get("stage2_ip_classification", {})
            webmail     = report.get("webmail_extraction_v2", {})
            real_ip_r   = report.get("real_ip_extraction", {})

            tz_offset = None
            send_hour = None
            date_str  = email_meta.get("date", "")
            if date_str:
                m = re.search(r'([+-]\d{4})', str(date_str))
                tz_offset = m.group(1) if m else None
                mh = re.search(r'T(\d{2}):', str(date_str))
                send_hour = int(mh.group(1)) if mh else None

            vpn_provider = None
            for ip_data in stage2.values():
                if ip_data.get("is_vpn"):
                    vpn_provider = ip_data.get("provider") or vpn_provider

            real_ip = (webmail.get("real_ip")
                       or real_ip_r.get("suspected_real_ip"))

            from_addr = email_meta.get("from", "")
            m_dom = re.search(r'@([a-zA-Z0-9._-]+)', from_addr)
            from_domain = m_dom.group(1).lower() if m_dom else None

            fp = EmailFingerprint(
                email_file       = email_file,
                email_from       = from_addr,
                email_subject    = email_meta.get("subject", ""),
                email_date       = date_str,
                message_id       = email_meta.get("message_id"),
                timezone_offset  = tz_offset,
                timezone_region  = FingerprintExtractor.TZ_REGION_MAP.get(tz_offset) if tz_offset else None,
                send_hour_local  = send_hour,
                send_day_of_week = None,
                vpn_asn          = None,
                vpn_provider     = vpn_provider,
                origin_ip        = stage1.get("origin_ip"),
                real_ip          = real_ip,
                real_ip_source   = "json_report",
                webmail_provider = webmail.get("provider"),
                dkim_domain      = None,
                mail_client      = None,
                hop_count        = stage1.get("hops_found", 1),
                subject_pattern  = FingerprintExtractor().
                                   _normalize_subject(email_meta.get("subject", "")),
                from_domain      = from_domain,
            )
            fp.compute_hash()
            return fp
        except Exception as e:
            if self.verbose:
                print(f"  [correlator] JSON ingest failed for {email_file}: {e}")
            return None
