#!/usr/bin/env python3
"""
HUNTЕРТRACE v3 — ACTOR PROFILER
=================================

Synthesizes a threat actor's behavioral TTP profile from a
ThreatActorCluster produced by campaignCorrelator.

Outputs:
  - Structured ActorTTPProfile (MITRE-aligned)
  - Human-readable analyst brief
  - Law-enforcement-ready evidence summary
  - Confidence scoring per attribute

USAGE:
    from actorProfiler import ActorProfiler

    profiler = ActorProfiler()
    profile  = profiler.build(cluster, geolocation_map)
    print(profile.analyst_brief())
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from collections import Counter, defaultdict
from datetime import datetime
import re


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MITREMapping:
    """Single MITRE ATT&CK technique observation."""
    technique_id:   str     # e.g. "T1566.001"
    technique_name: str     # e.g. "Spearphishing Attachment"
    tactic:         str     # e.g. "Initial Access"
    confidence:     float
    evidence:       str     # Why this was attributed


@dataclass
class TemporalPattern:
    """When the actor operates."""
    timezone_offset:        Optional[str]
    timezone_region:        Optional[str]
    likely_country:         Optional[str]

    # Send-time distribution
    peak_send_hour:         Optional[int]    # 0–23 local
    send_hour_distribution: Dict[int, int]   # hour → count
    active_window:          Optional[str]    # "18:00–22:00 IST"
    active_window_type:     Optional[str]    # "evening", "business", "overnight"

    # Day distribution
    weekday_count:          int
    weekend_count:          int
    prefers_weekday:        bool

    # Campaign cadence
    campaign_count:         int
    date_range_days:        Optional[int]
    avg_days_between:       Optional[float]
    cadence_label:          str     # "sporadic", "weekly", "daily"

    timezone_confidence:    float


@dataclass
class InfrastructurePattern:
    """How the actor builds and uses infrastructure."""
    vpn_providers:          List[str]
    vpn_provider_diversity: str      # "single", "few", "many"
    rotates_vpn_ips:        bool     # Same provider, different IPs
    rotates_vpn_providers:  bool     # Different providers

    webmail_providers:      List[str]
    primary_webmail:        Optional[str]

    origin_ips:             List[str]   # Real IPs (webmail-leaked)
    vpn_exit_ips:           List[str]   # VPN endpoints observed

    opsec_score:            int     # 0–100
    opsec_label:            str     # "amateur", "intermediate", "advanced"
    opsec_notes:            List[str]


@dataclass
class ContentPattern:
    """Email content / social engineering patterns."""
    subject_themes:         List[str]   # Extracted themes
    lure_types:             List[str]   # "job", "invoice", "urgency", "gov"
    from_domains:           List[str]
    impersonated_brands:    List[str]
    language_indicators:    List[str]   # Language hints from content
    subject_templates:      List[str]   # Normalized patterns


@dataclass
class ActorTTPProfile:
    """
    Complete behavioral TTP profile for a threat actor cluster.
    This is the core v3 research output.
    """
    actor_id:           str
    generated_at:       str
    campaign_count:     int
    confidence:         float

    temporal:           TemporalPattern
    infrastructure:     InfrastructurePattern
    content:            ContentPattern
    mitre_mappings:     List[MITREMapping]

    # Summary attributes
    sophistication:     str     # "novice", "intermediate", "advanced", "nation-state"
    likely_motivation:  str     # "financial", "espionage", "disruption", "hacktivism"
    actor_label:        str     # Short descriptive label e.g. "India-based phisher, NordVPN"

    # Distinguishing fingerprint (what makes this actor unique)
    fingerprint_summary: str
    distinguishing_signals: List[str]

    def analyst_brief(self) -> str:
        """Generate human-readable analyst brief."""
        lines = []
        lines.append("=" * 70)
        lines.append(f"THREAT ACTOR PROFILE — {self.actor_id}")
        lines.append("=" * 70)
        lines.append(f"  Label:          {self.actor_label}")
        lines.append(f"  Campaigns:      {self.campaign_count}")
        lines.append(f"  Confidence:     {self.confidence:.0%}")
        lines.append(f"  Sophistication: {self.sophistication}")
        lines.append(f"  Motivation:     {self.likely_motivation}")
        lines.append("")

        lines.append("  [TEMPORAL PROFILE]")
        t = self.temporal
        if t.timezone_region:
            lines.append(f"    Timezone:     {t.timezone_offset} → {t.timezone_region}")
        if t.likely_country:
            lines.append(f"    Country:      {t.likely_country}")
        if t.active_window:
            lines.append(f"    Active hrs:   {t.active_window} ({t.active_window_type})")
        lines.append(f"    Day pref:     {'Weekday' if t.prefers_weekday else 'Any'}")
        lines.append(f"    Cadence:      {t.cadence_label}")
        lines.append("")

        lines.append("  [INFRASTRUCTURE PROFILE]")
        i = self.infrastructure
        if i.vpn_providers:
            lines.append(f"    VPN:          {', '.join(i.vpn_providers)}")
            lines.append(f"    VPN rotation: {'Yes' if i.rotates_vpn_ips else 'No'}")
        if i.primary_webmail:
            lines.append(f"    Webmail:      {i.primary_webmail}")
        if i.origin_ips:
            lines.append(f"    Real IPs:     {', '.join(i.origin_ips[:3])}"
                         + (" ..." if len(i.origin_ips) > 3 else ""))
        lines.append(f"    OpSec:        {i.opsec_label} ({i.opsec_score}/100)")
        for note in i.opsec_notes:
            lines.append(f"      • {note}")
        lines.append("")

        lines.append("  [MITRE ATT&CK MAPPINGS]")
        for m in self.mitre_mappings:
            lines.append(f"    {m.technique_id:<12} {m.technique_name:<35} "
                         f"({m.confidence:.0%})")
            lines.append(f"               ↳ {m.evidence}")
        lines.append("")

        lines.append("  [DISTINGUISHING SIGNALS]")
        for sig in self.distinguishing_signals:
            lines.append(f"    • {sig}")
        lines.append("")

        lines.append(f"  FINGERPRINT: {self.fingerprint_summary}")
        lines.append("=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dict."""
        return {
            "actor_id":         self.actor_id,
            "generated_at":     self.generated_at,
            "campaign_count":   self.campaign_count,
            "confidence":       self.confidence,
            "actor_label":      self.actor_label,
            "sophistication":   self.sophistication,
            "likely_motivation":self.likely_motivation,
            "fingerprint_summary": self.fingerprint_summary,
            "distinguishing_signals": self.distinguishing_signals,
            "temporal": {
                "timezone_offset":   self.temporal.timezone_offset,
                "timezone_region":   self.temporal.timezone_region,
                "likely_country":    self.temporal.likely_country,
                "peak_send_hour":    self.temporal.peak_send_hour,
                "active_window":     self.temporal.active_window,
                "active_window_type":self.temporal.active_window_type,
                "prefers_weekday":   self.temporal.prefers_weekday,
                "cadence_label":     self.temporal.cadence_label,
                "campaign_count":    self.temporal.campaign_count,
            },
            "infrastructure": {
                "vpn_providers":     self.infrastructure.vpn_providers,
                "primary_webmail":   self.infrastructure.primary_webmail,
                "origin_ips":        self.infrastructure.origin_ips,
                "vpn_exit_ips":      self.infrastructure.vpn_exit_ips,
                "opsec_score":       self.infrastructure.opsec_score,
                "opsec_label":       self.infrastructure.opsec_label,
                "opsec_notes":       self.infrastructure.opsec_notes,
            },
            "content": {
                "subject_themes":    self.content.subject_themes,
                "lure_types":        self.content.lure_types,
                "from_domains":      self.content.from_domains,
            },
            "mitre_mappings": [
                {
                    "id":         m.technique_id,
                    "name":       m.technique_name,
                    "tactic":     m.tactic,
                    "confidence": m.confidence,
                    "evidence":   m.evidence,
                }
                for m in self.mitre_mappings
            ],
        }


# ─────────────────────────────────────────────────────────────────────────────
# ACTOR PROFILER
# ─────────────────────────────────────────────────────────────────────────────

class ActorProfiler:
    """
    Builds a full ActorTTPProfile from a ThreatActorCluster.
    """

    def build(self, cluster, geo_map: Dict = None) -> ActorTTPProfile:
        """
        cluster:  ThreatActorCluster from campaignCorrelator
        geo_map:  Optional {ip: GeolocationData} for enriching origin IPs
        """
        fps = cluster.fingerprints

        temporal       = self._build_temporal(cluster, fps)
        infrastructure = self._build_infrastructure(cluster, fps, geo_map or {})
        content        = self._build_content(fps)
        mitre          = self._map_mitre(cluster, fps, temporal, infrastructure)
        sophistication = self._assess_sophistication(infrastructure, temporal, mitre)
        motivation     = self._infer_motivation(content, mitre)
        label          = self._build_label(cluster, temporal, infrastructure)
        signals        = self._build_distinguishing_signals(temporal, infrastructure, content)
        fp_summary     = self._fingerprint_summary(cluster, temporal, infrastructure)

        return ActorTTPProfile(
            actor_id             = cluster.actor_id,
            generated_at         = datetime.now().isoformat(),
            campaign_count       = cluster.campaign_count,
            confidence           = cluster.confidence,
            temporal             = temporal,
            infrastructure       = infrastructure,
            content              = content,
            mitre_mappings       = mitre,
            sophistication       = sophistication,
            likely_motivation    = motivation,
            actor_label          = label,
            fingerprint_summary  = fp_summary,
            distinguishing_signals = signals,
        )

    # ── Temporal ─────────────────────────────────────────────────────────

    def _build_temporal(self, cluster, fps) -> TemporalPattern:
        tz_off  = cluster.consensus_timezone
        # Strip region from combined string if stored as "offset (region)"
        if tz_off and '(' in tz_off:
            tz_off = tz_off.split('(')[0].strip()

        tz_reg  = None
        for fp in fps:
            if fp.timezone_region:
                tz_reg = fp.timezone_region
                break

        country = cluster.likely_country

        # Send hour distribution
        hours = [fp.send_hour_local for fp in fps if fp.send_hour_local is not None]
        hour_dist = dict(Counter(hours))
        peak_hour = max(hour_dist, key=hour_dist.get) if hour_dist else None

        # Active window
        active_window = cluster.consensus_send_window
        window_type   = None
        if peak_hour is not None:
            if 9 <= peak_hour <= 17:
                window_type = "business hours"
            elif 18 <= peak_hour <= 22:
                window_type = "evening"
            elif 22 <= peak_hour or peak_hour <= 5:
                window_type = "overnight / late night"
            else:
                window_type = "early morning"

        # Weekday/weekend
        weekend = {"Saturday", "Sunday"}
        dow_list = [fp.send_day_of_week for fp in fps if fp.send_day_of_week]
        wkday = sum(1 for d in dow_list if d not in weekend)
        wkend = sum(1 for d in dow_list if d in weekend)

        # Campaign cadence
        dates = sorted([fp.email_date for fp in fps if fp.email_date])
        date_range_days = None
        avg_gap         = None
        cadence         = "sporadic"
        if len(dates) >= 2:
            try:
                d0 = datetime.fromisoformat(str(dates[0]).replace(' ', 'T'))
                d1 = datetime.fromisoformat(str(dates[-1]).replace(' ', 'T'))
                date_range_days = (d1 - d0).days
                avg_gap = date_range_days / (len(dates) - 1)
                if avg_gap <= 1:
                    cadence = "daily / burst"
                elif avg_gap <= 7:
                    cadence = "weekly"
                elif avg_gap <= 30:
                    cadence = "monthly"
                else:
                    cadence = "sporadic"
            except Exception:
                pass

        # Timezone confidence: how consistent are the offsets?
        offsets = [fp.timezone_offset for fp in fps if fp.timezone_offset]
        tz_conf = (offsets.count(tz_off) / len(offsets)) if offsets and tz_off else 0.5

        return TemporalPattern(
            timezone_offset        = tz_off,
            timezone_region        = tz_reg,
            likely_country         = country,
            peak_send_hour         = peak_hour,
            send_hour_distribution = hour_dist,
            active_window          = active_window,
            active_window_type     = window_type,
            weekday_count          = wkday,
            weekend_count          = wkend,
            prefers_weekday        = wkday >= wkend,
            campaign_count         = len(fps),
            date_range_days        = date_range_days,
            avg_days_between       = avg_gap,
            cadence_label          = cadence,
            timezone_confidence    = tz_conf,
        )

    # ── Infrastructure ────────────────────────────────────────────────────

    def _build_infrastructure(self, cluster, fps, geo_map) -> InfrastructurePattern:
        vpn_providers = list(set(fp.vpn_provider for fp in fps if fp.vpn_provider))
        webmails      = list(set(fp.webmail_provider for fp in fps if fp.webmail_provider))
        origin_ips    = list(set(fp.real_ip    for fp in fps if fp.real_ip))
        vpn_ips       = list(set(fp.origin_ip  for fp in fps if fp.origin_ip))

        rotates_ips  = len(vpn_ips) > 1
        rotates_prov = len(vpn_providers) > 1

        vpn_diversity = ("many"   if len(vpn_providers) > 3
                         else "few"    if len(vpn_providers) > 1
                         else "single" if vpn_providers
                         else "none")

        primary_webmail = (max(set(fp.webmail_provider for fp in fps if fp.webmail_provider),
                               key=[fp.webmail_provider for fp in fps
                                    if fp.webmail_provider].count)
                           if any(fp.webmail_provider for fp in fps) else None)

        # OpSec scoring
        opsec = 0
        notes = []

        if vpn_providers:
            opsec += 25
            notes.append(f"Uses VPN ({', '.join(vpn_providers[:2])})")
        if rotates_ips:
            opsec += 20
            notes.append("Rotates VPN exit IPs across campaigns")
        if rotates_prov:
            opsec += 15
            notes.append("Rotates VPN providers")
        else:
            notes.append("Single VPN provider — attributable via subscription records")

        # Webmail leaks IP = opsec failure
        if any(fp.real_ip and fp.real_ip_source and 'webmail' in fp.real_ip_source
               for fp in fps):
            notes.append("OpSec failure: webmail provider leaked real IP in headers")
        else:
            opsec += 10

        # Timezone consistent = opsec failure (didn't fake clock)
        tz_vals = [fp.timezone_offset for fp in fps if fp.timezone_offset]
        if len(set(tz_vals)) == 1 and len(tz_vals) >= 2:
            notes.append("Consistent timezone across all emails — system clock not masked")
        else:
            opsec += 10

        if opsec >= 70:
            opsec_label = "advanced"
        elif opsec >= 45:
            opsec_label = "intermediate"
        else:
            opsec_label = "amateur"

        return InfrastructurePattern(
            vpn_providers          = vpn_providers,
            vpn_provider_diversity = vpn_diversity,
            rotates_vpn_ips        = rotates_ips,
            rotates_vpn_providers  = rotates_prov,
            webmail_providers      = webmails,
            primary_webmail        = primary_webmail,
            origin_ips             = origin_ips,
            vpn_exit_ips           = vpn_ips,
            opsec_score            = min(100, opsec),
            opsec_label            = opsec_label,
            opsec_notes            = notes,
        )

    # ── Content ───────────────────────────────────────────────────────────

    def _build_content(self, fps) -> ContentPattern:
        subjects  = [fp.email_subject for fp in fps if fp.email_subject]
        from_doms = list(set(fp.from_domain for fp in fps if fp.from_domain))
        templates = list(set(fp.subject_pattern for fp in fps if fp.subject_pattern))

        # Theme extraction
        themes  = []
        lures   = []
        brands  = []
        LURE_KEYWORDS = {
            "financial":   ["invoice", "payment", "wire", "bank", "salary", "payroll"],
            "urgency":     ["urgent", "action required", "verify", "confirm", "suspended"],
            "job":         ["offer", "hiring", "nqt", "interview", "application", "job"],
            "government":  ["irs", "gov", "tax", "penalty", "compliance", "authority"],
            "delivery":    ["package", "dhl", "fedex", "shipment", "tracking"],
            "tech":        ["password", "account", "login", "security", "2fa", "breach"],
        }
        BRAND_KEYWORDS = [
            "tcs", "infosys", "wipro", "google", "microsoft", "apple", "amazon",
            "paypal", "dhl", "fedex", "irs", "bank", "hdfc", "sbi", "icici",
        ]

        for subj in subjects:
            sl = subj.lower()
            for theme, kws in LURE_KEYWORDS.items():
                if any(kw in sl for kw in kws):
                    if theme not in lures:
                        lures.append(theme)
            for brand in BRAND_KEYWORDS:
                if brand in sl and brand not in brands:
                    brands.append(brand)
            # General theme words
            for word in re.findall(r'\b[a-z]{4,}\b', sl):
                if word not in ("this", "that", "with", "from", "your", "have"):
                    if word not in themes:
                        themes.append(word)

        return ContentPattern(
            subject_themes      = themes[:10],
            lure_types          = lures,
            from_domains        = from_doms,
            impersonated_brands = brands,
            language_indicators = [],   # Could add later with langdetect
            subject_templates   = templates[:5],
        )

    # ── MITRE mapping ─────────────────────────────────────────────────────

    def _map_mitre(self, cluster, fps, temporal, infra) -> List[MITREMapping]:
        mappings = []

        # T1566 — Phishing
        mappings.append(MITREMapping(
            technique_id   = "T1566.001",
            technique_name = "Spearphishing via Email",
            tactic         = "Initial Access",
            confidence     = 0.95,
            evidence       = f"{cluster.campaign_count} phishing email(s) analysed",
        ))

        # T1090 — Proxy (VPN)
        if infra.vpn_providers:
            vpn_str = ", ".join(infra.vpn_providers[:2])
            mappings.append(MITREMapping(
                technique_id   = "T1090.003",
                technique_name = "Multi-hop Proxy (VPN)",
                tactic         = "Command and Control",
                confidence     = 0.90,
                evidence       = f"VPN detected: {vpn_str}",
            ))

        # T1036 — Masquerading (if brand impersonation detected)
        brands = []
        for fp in fps:
            for b in ["tcs", "infosys", "google", "microsoft", "amazon", "paypal"]:
                if b in fp.email_subject.lower():
                    brands.append(b)
        if brands:
            mappings.append(MITREMapping(
                technique_id   = "T1036",
                technique_name = "Masquerading / Brand Impersonation",
                tactic         = "Defense Evasion",
                confidence     = 0.80,
                evidence       = f"Impersonated: {', '.join(set(brands))}",
            ))

        # T1078 — Valid Accounts (if webmail used with real account)
        if infra.primary_webmail:
            mappings.append(MITREMapping(
                technique_id   = "T1078",
                technique_name = "Valid Accounts (Webmail)",
                tactic         = "Persistence",
                confidence     = 0.70,
                evidence       = f"Sent via {infra.primary_webmail} account",
            ))

        # T1589 — Gather Victim Identity (job lures)
        content_lures = [fp.subject_pattern or "" for fp in fps]
        if any("job" in s or "nqt" in s or "hiring" in s for s in content_lures):
            mappings.append(MITREMapping(
                technique_id   = "T1589",
                technique_name = "Gather Victim Identity Information",
                tactic         = "Reconnaissance",
                confidence     = 0.65,
                evidence       = "Job-themed lure collects applicant PII",
            ))

        # T1204 — User Execution (if urgency lures present)
        if any("urgent" in (fp.email_subject or "").lower() for fp in fps):
            mappings.append(MITREMapping(
                technique_id   = "T1204",
                technique_name = "User Execution (Social Engineering)",
                tactic         = "Execution",
                confidence     = 0.75,
                evidence       = "Urgency language used to drive clicks",
            ))

        return mappings

    # ── Helpers ───────────────────────────────────────────────────────────

    def _assess_sophistication(self, infra, temporal, mitre) -> str:
        score = infra.opsec_score
        if score >= 70 or len(mitre) >= 5:
            return "advanced"
        elif score >= 45:
            return "intermediate"
        else:
            return "novice"

    def _infer_motivation(self, content, mitre) -> str:
        if "financial" in content.lure_types:
            return "financial"
        if "government" in content.lure_types:
            return "espionage"
        if "job" in content.lure_types:
            return "credential_harvest / PII collection"
        return "unknown"

    def _build_label(self, cluster, temporal, infra) -> str:
        parts = []
        if temporal.likely_country:
            parts.append(temporal.likely_country + "-based")
        if infra.primary_webmail:
            parts.append(infra.primary_webmail + " phisher")
        elif not parts:
            parts.append("unknown-origin phisher")
        if infra.vpn_providers:
            parts.append(f"via {infra.vpn_providers[0]}")
        return ", ".join(parts)

    def _build_distinguishing_signals(self, temporal, infra, content) -> List[str]:
        sigs = []
        if temporal.timezone_offset:
            sigs.append(f"Timezone {temporal.timezone_offset} "
                        f"({temporal.timezone_region or 'unknown region'})")
        if temporal.active_window:
            sigs.append(f"Consistently active {temporal.active_window}")
        if infra.vpn_providers:
            sigs.append(f"VPN provider: {', '.join(infra.vpn_providers)}")
        if infra.origin_ips:
            sigs.append(f"Real IP(s) leaked by webmail: {', '.join(infra.origin_ips[:3])}")
        if infra.primary_webmail:
            sigs.append(f"Sends via {infra.primary_webmail}")
        if content.lure_types:
            sigs.append(f"Lure types: {', '.join(content.lure_types)}")
        if content.impersonated_brands:
            sigs.append(f"Impersonates: {', '.join(content.impersonated_brands)}")
        return sigs

    def _fingerprint_summary(self, cluster, temporal, infra) -> str:
        parts = []
        if temporal.timezone_offset:
            parts.append(f"TZ:{temporal.timezone_offset}")
        if infra.vpn_providers:
            parts.append(f"VPN:{infra.vpn_providers[0]}")
        if infra.primary_webmail:
            parts.append(f"MAIL:{infra.primary_webmail}")
        if infra.origin_ips:
            parts.append(f"REALIP:{infra.origin_ips[0]}")
        return " | ".join(parts) if parts else "insufficient signals"
