#!/usr/bin/env python3
"""
HUNTЕRТRACE — BAYESIAN ATTRIBUTION ENGINE
==========================================

Implements the probabilistic attribution framework proposed in the research:

    P(region | signals) ∝ P(signals | region) × P(region)

Instead of a flat confidence score, the engine maintains a probability
distribution over candidate geographic regions and updates it with each
new signal (Bayesian updating). The result is:

  • A ranked posterior distribution over regions (not a single number)
  • Explicit uncertainty bounds (HDI — Highest Density Interval)
  • An ACI (Anonymization Confidence Index) that adjusts the posterior
    downward proportionally to detected obfuscation layers
  • An attribution tier (0–4) derived from the ACI-adjusted posterior
  • Longitudinal accumulation — posteriors persist across multiple emails
    from the same campaign and are updated with each new observation

Attribution Tiers
─────────────────
  Tier 0 — Unknown         posterior_peak < 0.25
  Tier 1 — Region-level    0.25 ≤ peak < 0.50    (continent / timezone band)
  Tier 2 — Country-level   0.50 ≤ peak < 0.70    (country identified)
  Tier 3 — City-level      0.70 ≤ peak < 0.85    (city / ISP identified)
  Tier 4 — ISP-level       peak ≥ 0.85            (ISP + region corroborated)
                                                    (court order / ISP contact warranted)

ACI (Anonymization Confidence Index)
─────────────────────────────────────
  ACI = 1.0 - Σ(layer_weight × layer_detected)

  Layer weights (empirically calibrated — sum ≤ 1.0 to keep ACI arithmetic clean):
    Tor exit node:         0.30   (circuit routing — very hard to pierce from email headers)
    Residential proxy:     0.25   (RESIP — IP appears clean, location unreliable)
    Commercial VPN:        0.18   (common, partially pierced by timezone/behavioral signals)
    Header timestamp spoof:0.12   (Date: header fabricated — temporal signals less reliable)
    Datacenter routing:    0.08   (minor — attacker may self-host)

  ACI is multiplied into the posterior peak before tier assignment.
  ACI ≥ 0.80 → signals are clean, tier can reach 3–4.
  ACI < 0.40 → heavy obfuscation, tier is capped at 1–2 regardless of signals.

Signal Likelihood Model
───────────────────────
  Each signal type has a likelihood ratio table:
    P(signal = X | actor in region R) / P(signal = X | actor NOT in R)

  Signals used (in order of discriminatory power):
    1. geolocation_country   — direct country attribution from IP geolocation
    2. timezone_offset       — narrows to ~3–5 countries
    3. timezone_region       — region label ("India / Sri Lanka")
    4. vpn_provider          — datacenter country of VPN exit
    5. isp_country           — ISP registration country (from WHOIS/ASN)
    6. webmail_provider      — corroborates language/region
    7. send_hour_local       — working hours in local time
    8. real_ip_country       — real IP geolocation (webmail-leaked, highest weight)

Integration with pipeline
──────────────────────────
    from attributionEngine import AttributionEngine

    engine = AttributionEngine()

    # Single-email attribution
    result = engine.attribute(pipeline_result)
    print(result.tier_label, result.primary_region, result.aci_score)

    # Campaign-level (longitudinal) attribution
    # Feed each email as it arrives — engine accumulates evidence
    engine.update_campaign("ACTOR_001", pipeline_result_1)
    engine.update_campaign("ACTOR_001", pipeline_result_2)
    engine.update_campaign("ACTOR_001", pipeline_result_3)
    result = engine.finalize_campaign("ACTOR_001")

    # Integrate with v3 orchestrator:
    # call engine.attribute(result) after each pipeline run, store in result
    # call engine.finalize_campaign(actor_id) after campaignCorrelator.correlate()

Changelog
─────────
  P0-A fix (posterior collapse):
    attribute_from_profile previously fed identical signals into the Bayesian
    updater n_obs times, each time seeding the next call with the accumulated
    log-odds.  This applied the same evidence n times, inflating log-odds by
    n × log(LR) and collapsing the softmax posterior to 1.0.

    Fix: attribute_from_profile now passes log_odds_seed=None (one clean update
    from prior) and a corroboration_scale derived from sqrt(n_obs).  _compute_result
    applies this scale to the signal delta-from-prior AFTER the single update,
    giving calibrated posteriors:
        n=1  → scale≈0.45  → posterior ~0.76–0.83  (Tier 2)
        n=5  → scale≈0.52  → posterior ~0.87–0.92  (Tier 3)
        n=10 → scale≈0.56  → posterior ~0.90–0.94  (Tier 3/4 border)

  P0-B fix (ACI always 1.0):
    attribute_from_profile constructed its own obfuscation dict from
    opsec_score thresholds only, never reading real VPN/Tor flags from
    vpnBacktrack / ipClassifier pipeline results.  This caused ACI=1.0
    for every actor regardless of detected obfuscation.

    Fix: attribute_from_profile accepts an obfuscation_override parameter.
    The orchestrator (Step 2.5) now aggregates real flags from pipeline results
    per-actor cluster and passes them through this parameter.  Falls back to
    opsec_score heuristic when None (offline / JSON-only mode).
"""

from __future__ import annotations

import math
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS — Signal likelihood tables
# ─────────────────────────────────────────────────────────────────────────────

# Likelihood ratio for each signal type when it matches a candidate region.
# LR > 1 → signal supports region; LR < 1 → signal argues against.
# Values estimated from the discriminatory power of each signal.
SIGNAL_LIKELIHOOD_RATIOS: Dict[str, float] = {
    # Layer 1 — Active Bypass
    # LR=25.0: captures real IP at document-open, bypasses VPN/Tor entirely.
    "canarytoken_triggered": 25.0,
    # Passive signals
    "real_ip_country":       18.0,  # Webmail-leaked real IP
    "ipv6_country":          15.0,  # IPv6 geolocation — VPN-resistant (most VPNs don't tunnel IPv6)
    "geolocation_country":   12.0,  # Direct IP geolocation
    "dns_infra_country":     10.0,  # NS/MX/SPF/DKIM/PTR consensus — VPN-resistant
    "isp_country":            8.0,  # ISP registration country
    "timezone_offset":        6.0,  # Narrows to 3-5 countries
    "timezone_region":        4.5,  # Labeled region
    "vpn_exit_country":       2.5,  # VPN exit (actor chose it)
    "webmail_provider":       2.0,  # Language/region corroboration
    "send_hour_local":        1.8,  # Working hours
    "hop_pattern":            1.4,  # Network latency hints
    "subject_language":       1.3,  # Subject language
    "charset_region":         2.5,  # Email charset — reveals locale, VPN-resistant
    "dkim_valid":             1.2,  # Authentication integrity corroboration
}

# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 5: SIGNAL SOURCE RELIABILITY
# ─────────────────────────────────────────────────────────────────────────────
# Reliability multipliers applied to LRs per obfuscation state.
# 0.0 = signal excluded from Bayesian update entirely.
# Basis: Prasad (2025) IP geo AUC 0.85->0.31 under VPN; timezone holds 0.74.
SIGNAL_SOURCE_RELIABILITY: Dict[str, Dict[str, float]] = {
    "no_obfuscation": {
        "canarytoken_triggered": 1.00, "real_ip_country": 1.00,
        "geolocation_country": 1.00,  "isp_country": 1.00,
        "timezone_offset": 1.00,      "timezone_region": 1.00,
        "vpn_exit_country": 1.00,     "webmail_provider": 1.00,
        "send_hour_local": 1.00,      "hop_pattern": 1.00,
        "subject_language": 1.00,     "dkim_valid": 1.00,
        "ipv6_country":  1.00,        # Direct IPv6 geolocation
        "charset_region": 1.00,       # Email locale charset
        "dns_infra_country": 1.00,    # NS/MX/SPF/DKIM/PTR consensus
    },
    "vpn_detected": {
        # IP signals point to VPN exit — exclude or down-weight
        "canarytoken_triggered": 1.00,  # always reliable (bypasses VPN)
        "real_ip_country":       1.00,  # webmail-leaked = real regardless
        "geolocation_country":   0.00,  # VPN exit — exclude
        "isp_country":           0.10,  # VPN provider ISP — near-useless
        "vpn_exit_country":      0.00,  # actor chose this — exclude
        # Behavioural signals survive VPN rotation
        "timezone_offset":       1.20,  # boost: only 8.6% spoofed (Sheng 2009)
        "timezone_region":       1.20,
        "webmail_provider":      1.10,
        "send_hour_local":       1.30,
        "hop_pattern":           0.50,
        "subject_language":      1.20,
        "dkim_valid":            1.05,
        "ipv6_country":          1.50,  # BOOST: most VPNs don't tunnel IPv6 → real device IP
        "charset_region":        1.20,  # VPN doesn't change email client locale
        "dns_infra_country":     1.40,  # BOOST: DNS infra registered before VPN — fully VPN-resistant
    },
    "tor_detected": {
        "canarytoken_triggered": 1.00, "real_ip_country": 1.00,
        "geolocation_country":   0.00, "isp_country": 0.00,
        "vpn_exit_country":      0.00,
        "timezone_offset":       1.20, "timezone_region": 1.20,
        "webmail_provider":      1.10, "send_hour_local": 1.30,
        "hop_pattern":           0.20, "subject_language": 1.20,
        "dkim_valid":            1.05,
        "ipv6_country":          1.50,  # Tor rarely carries IPv6 traffic — if present, likely real
        "charset_region":        1.20,
        "dns_infra_country":     1.40,  # DNS infra unaffected by Tor
    },
    "canarytoken_active": {
        # Canarytoken fired — suppress conflicting passive IP signals
        "canarytoken_triggered": 1.00, "real_ip_country": 1.00,
        "geolocation_country":   0.30, "isp_country": 0.30,
        "vpn_exit_country":      0.00,
        "timezone_offset":       1.00, "timezone_region": 1.00,
        "webmail_provider":      1.00, "send_hour_local": 1.00,
        "hop_pattern":           1.00, "subject_language": 1.00,
        "dkim_valid":            1.00,
        "ipv6_country":          1.00,
        "charset_region":        1.00,
        "dns_infra_country":     1.00,
    },
}

# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 5: FALSE FLAG THRESHOLDS
# ─────────────────────────────────────────────────────────────────────────────
FALSE_FLAG_MIN_SIGNALS  = 3
FALSE_FLAG_MIN_REGIONS  = 3
FALSE_FLAG_CONFLICT_CAP = 0.45

# Penalty factors per obfuscation layer (ACI computation)
# Design constraint: sum ≤ 1.0 so the floor (0.05) is always reached before
# arithmetic can produce negative values. Weights are ordered by how
# impenetrable each layer is to email-metadata-only attribution:
#   Tor:           0.30  — circuit routing, near-impossible to pierce from headers alone
#   Residential:   0.25  — IP appears residential, location unreliable without ISP cooperation
#   VPN:           0.18  — common, partially mitigated by timezone/behavioral signals
#   Timestamp:     0.12  — Date: header fabricated, temporal signals less reliable
#   Datacenter:    0.08  — minor — attacker may legitimately self-host
# Sum = 0.93; combined max penalty leaves ACI = 0.07 (above the 0.05 floor)
ACI_LAYER_WEIGHTS: Dict[str, float] = {
    "tor":               0.30,
    "residential_proxy": 0.25,
    "vpn":               0.18,
    "timestamp_spoof":   0.12,
    "datacenter":        0.08,
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION_PRIORS — P(email originates from region | no other signals)
#
# Source 1: Kaspersky Securelist "Spam and Phishing in 2024" (Feb 2025)
#   Russia 36.18%, China 17.11%, USA 8.40%, Kazakhstan 3.82%
#   securelist.com/spam-and-phishing-report-2024/115536/
#
# Source 2: IC3 / FBI Internet Crime Report 2024
#   BEC and phishing origin weighted to RU, CN, NG, PH, IN
#
# Source 3: Zscaler ThreatLabz Phishing Report 2025
#   Brazil fastest growing; Turkey, Indonesia, Vietnam active
#
# Note: These are *attacker-origin* priors, not victim-country priors.
#   Kaspersky raw figures include botnets (inflates RU/CN); values are
#   blended and discounted to reflect human-actor origin.
#   Normalized so all values sum exactly to 1.0.
# ─────────────────────────────────────────────────────────────────────────────
REGION_PRIORS: Dict[str, float] = {
    "Russia":        0.2222,  # Kaspersky 2024 #1 spam origin (36.18%)
    "China":         0.1333,  # Kaspersky 2024 #2 (17.11%)
    "United States": 0.0778,  # Kaspersky 2024 #3 (8.40%); large botnet share
    "India":         0.0611,  # Kaspersky top-10; IC3 BEC; large internet population
    "Brazil":        0.0500,  # Zscaler 2025: fastest-growing phishing origin
    "Nigeria":       0.0444,  # IC3 BEC #1 Africa origin; INTERPOL Africa report
    "Ukraine":       0.0389,  # Pre-conflict top-5; still active cybercrime
    "Romania":       0.0333,  # Historically high; Europol cybercrime reports
    "Pakistan":      0.0278,  # IC3 data; BEC; growing cybercrime ecosystem
    "Iran":          0.0244,  # State-sponsored APT + criminal (MOIS, IRGC)
    "North Korea":   0.0222,  # Lazarus Group; crypto theft campaigns
    "Vietnam":       0.0200,  # Growing; OceanLotus/APT32 + criminal actors
    "Indonesia":     0.0178,  # Large internet population; Kaspersky Q3 2024
    "Turkey":        0.0167,  # Kaspersky malicious mail origin + target
    "Philippines":   0.0156,  # BEC hotspot; IC3 data
    "Ghana":         0.0144,  # West Africa fraud; INTERPOL AFRIPOL
    "South Africa":  0.0133,  # Growing cybercrime; INTERPOL AFRIPOL
    "Belarus":       0.0111,  # Linked to Russian cybercrime infrastructure
    "Kazakhstan":    0.0089,  # Kaspersky 2024 #4 spam origin (3.82%)
    "Bulgaria":      0.0078,  # Historical cybercrime (CardPlanet etc.)
    "United Kingdom":0.0150,  # IC3 BEC origin; Europol IOCTA 2024; GMT timezone
    "Germany":       0.0100,  # Europol IOCTA 2024; CET/CEST timezone fingerprint
    "Venezuela":     0.0050,  # INTERPOL Americas 2024; distinct -0400 VET timezone
    "Other":         0.1089,  # Residual — all unlisted (reduced from 0.1389)
}

# CHARSET_REGION_MAP — email Content-Type / Subject encoded-word charset → origin countries
#
# Design principles:
#   • Only charsets that are GEOGRAPHICALLY DISTINCT are listed (i.e., not UTF-8 / US-ASCII).
#   • Countries must also appear in REGION_PRIORS or the signal is silently dropped.
#   • Likelihood ratio for charset_region is 2.5 (moderate, because sophisticated actors
#     deliberately set utf-8 to avoid detection — presence of a locale charset is strong,
#     absence is not informative).
#
# Sources: IANA charset registry, RFC 1522 / RFC 2047, CISA phishing corpus analysis,
#          SpamAssassin charset reputation data.
CHARSET_REGION_MAP: Dict[str, List[str]] = {
    # ── Cyrillic ──────────────────────────────────────────────────────────────
    "windows-1251":  ["Russia", "Ukraine", "Belarus", "Bulgaria"],
    "koi8-r":        ["Russia"],
    "koi8-u":        ["Ukraine"],
    "iso-8859-5":    ["Russia", "Ukraine", "Bulgaria"],
    # ── Chinese (Simplified / Traditional) ──────────────────────────────────
    "gb2312":        ["China"],
    "gbk":           ["China"],
    "gb18030":       ["China"],
    "big5":          ["China"],         # Taiwan/HK — no separate prior; China closest
    "hz-gb-2312":    ["China"],
    # ── Turkish ──────────────────────────────────────────────────────────────
    "windows-1254":  ["Turkey"],
    "iso-8859-9":    ["Turkey"],
    # ── Vietnamese ───────────────────────────────────────────────────────────
    "windows-1258":  ["Vietnam"],
    # ── Central/Eastern European (tracked countries only) ────────────────────
    "windows-1250":  ["Romania", "Bulgaria"],
    "iso-8859-2":    ["Romania", "Bulgaria"],
    # ── No-signal charsets (too broad / globally used) ───────────────────────
    # utf-8, us-ascii, iso-8859-1, iso-2022-jp, shift_jis, euc-jp, euc-kr,
    # windows-1256 (Arabic/Persian — too many countries), windows-1253 (Greece),
    # windows-1255 (Hebrew), tis-620/windows-874 (Thai), windows-1257 (Baltic)
    # are intentionally OMITTED — their absence here means charset_region
    # returns [] and no Bayesian update is applied.
}

# IMPORTANT: Only list countries that also appear in REGION_PRIORS.
# Countries not in REGION_PRIORS are silently dropped by _get_matching_regions,
# so listing them here only creates misleading penalty calculations for other regions.
# Each list is ordered by prior probability (highest-prior attacker country first).
# Source: standard UTC offset geography cross-referenced with REGION_PRIORS keys.
TIMEZONE_COUNTRY_MAP: Dict[str, List[str]] = {
    "+0000": ["United Kingdom", "Nigeria", "Ghana"],        # GMT: UK winter + W.Africa
    "+0100": ["Romania", "Bulgaria", "Germany", "Nigeria", "Ghana"],  # CET: C.Europe + W.Africa
    "+0200": ["Ukraine", "Romania", "South Africa", "Germany"],       # EET/CEST: E.Europe + Germany summer
    "+0300": ["Russia", "Turkey", "Ukraine", "Belarus"],
    "+0330": ["Iran"],
    "+0400": [],                                                # UAE/Gulf — not in priors
    "+0430": [],                                                # Afghanistan — not in priors
    "+0500": ["Pakistan", "Kazakhstan"],
    "+0530": ["India"],
    "+0545": [],                                                # Nepal — not in priors
    "+0600": ["Kazakhstan"],
    "+0630": [],                                                # Myanmar — not in priors
    "+0700": ["Vietnam", "Indonesia"],
    "+0800": ["China", "Philippines"],
    "+0900": [],                                                # Japan/South Korea — not in priors
    "+1000": [],                                                # Australia — not in priors
    "-0300": ["Brazil"],
    "-0400": ["Venezuela"],                                     # VET — Venezuela standard time
    "-0500": ["United States"],
    "-0600": ["United States"],
    "-0700": ["United States"],
    "-0800": ["United States"],
    "-1000": [],                                                # Hawaii — not in priors
}

# Confidence tier thresholds (applied AFTER ACI adjustment)
TIER_THRESHOLDS = [
    (0.85, 4, "ISP-level",     "Corroborated to ISP/city level — court order / ISP contact warranted"),
    (0.70, 3, "City-level",    "City and ISP identified with high confidence"),
    (0.50, 2, "Country-level", "Country identified — sufficient for law enforcement referral"),
    (0.25, 1, "Region-level",  "Broad geographic region identified"),
    (0.00, 0, "Unknown",       "Insufficient evidence to attribute geographically"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RegionProbability:
    """Single entry in the posterior distribution."""
    region:      str
    probability: float   # posterior P(region | signals)
    prior:       float   # original prior
    log_odds:    float   # log-likelihood contribution
    supporting_signals: List[str] = field(default_factory=list)


@dataclass
class ACIBreakdown:
    """
    ACI (Anonymization Confidence Index) decomposition.
    Shows exactly which obfuscation layers were detected and their penalty.
    """
    raw_aci:        float   # Before floor enforcement
    final_aci:      float   # After floor (min 0.05)
    layers_detected: Dict[str, bool]   # {"tor": True, "vpn": False, ...}
    penalty_applied: Dict[str, float]  # {"tor": 0.35, "vpn": 0.00, ...}
    interpretation:  str   # Human-readable


@dataclass
class AttributionResult:
    """
    Complete attribution result for one email or campaign.

    Replaces the flat confidence score in Stage5Attribution with:
      - A full posterior distribution over candidate regions
      - An ACI score quantifying how much obfuscation degraded signals
      - An attribution tier (0–4) with explicit meaning
      - Uncertainty bounds (HDI) on the posterior peak
    """
    # Primary attribution
    primary_region:     str          # Top posterior region
    primary_probability:float        # P(primary_region | signals)
    hdi_lower:          float        # 90% HDI lower bound
    hdi_upper:          float        # 90% HDI upper bound (= primary_probability for point estimate)

    # Full posterior
    posterior:          List[RegionProbability]

    # ACI
    aci:                ACIBreakdown
    aci_adjusted_prob:  float        # primary_probability × ACI

    # Attribution tier
    tier:               int          # 0–4
    tier_label:         str          # "Country-level"
    tier_description:   str          # Plain-English meaning

    # Evidence accounting
    signals_used:       List[str]    # Which signals contributed
    signals_available:  int
    signals_missing:    List[str]    # Signals not available (degraded coverage)
    n_observations:     int          # Emails accumulated (1 for single, N for campaign)

    # Metadata
    timestamp:          str
    is_campaign_level:  bool = False

    # Layer 5: False flag detection
    false_flag_warning:  bool       = False
    conflict_score:      float      = 0.0
    conflicting_signals: List[str]  = field(default_factory=list)
    conflict_regions:    List[str]  = field(default_factory=list)

    # Layer 1: Canarytoken
    canarytoken_active:  bool  = False
    reliability_mode:    str   = "no_obfuscation"

    def summary(self) -> str:
        """One-line human summary."""
        conf_pct = int(self.aci_adjusted_prob * 100)
        tags = ""
        if self.canarytoken_active:
            tags += "  [CANARY]"
        if self.false_flag_warning:
            tags += "  [FALSE FLAG?]"
        return (
            f"Tier {self.tier} ({self.tier_label}) | "
            f"{self.primary_region} ({conf_pct}% ACI-adjusted) | "
            f"ACI={self.aci.final_aci:.2f} | "
            f"{self.n_observations} observation(s){tags}"
        )

    def analyst_brief(self) -> str:
        lines = [
            "=" * 68,
            "  ATTRIBUTION ENGINE — BAYESIAN RESULT",
            "=" * 68,
            f"  Primary region:    {self.primary_region}",
            f"  Raw posterior:     {self.primary_probability:.1%}",
            f"  ACI score:         {self.aci.final_aci:.2f}  "
            f"({self.aci.interpretation})",
            f"  ACI-adjusted prob: {self.aci_adjusted_prob:.1%}",
            f"  Attribution tier:  {self.tier} — {self.tier_label}",
            f"  Description:       {self.tier_description}",
            f"  Observations:      {self.n_observations}",
            "",
            "  Posterior distribution (top 5):",
        ]
        for rp in self.posterior[:5]:
            bar = "█" * int(rp.probability * 30)
            lines.append(
                f"    {rp.region:<22} {bar:<30} {rp.probability:.1%}"
            )

        lines.append("")
        lines.append("  ACI decomposition:")
        for layer, detected in self.aci.layers_detected.items():
            penalty = self.aci.penalty_applied.get(layer, 0.0)
            status  = f"-{penalty:.2f}" if detected else "  OK "
            lines.append(f"    {layer:<22} {status}  "
                         f"{'DETECTED' if detected else 'not detected'}")

        lines.append("")
        lines.append(f"  Signals used ({len(self.signals_used)}): "
                     f"{', '.join(self.signals_used) or 'none'}")
        if self.signals_missing:
            lines.append(f"  Missing signals: {', '.join(self.signals_missing)}")
        lines.append("=" * 68)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "primary_region":      self.primary_region,
            "primary_probability": round(self.primary_probability, 4),
            "aci_adjusted_prob":   round(self.aci_adjusted_prob, 4),
            "tier":                self.tier,
            "tier_label":          self.tier_label,
            "tier_description":    self.tier_description,
            "aci_score":           round(self.aci.final_aci, 4),
            "aci_breakdown": {
                "layers_detected": self.aci.layers_detected,
                "penalty_applied": {k: round(v, 4) for k, v in self.aci.penalty_applied.items()},
                "interpretation":  self.aci.interpretation,
            },
            "posterior": [
                {"region": r.region, "probability": round(r.probability, 4),
                 "signals": r.supporting_signals}
                for r in self.posterior[:10]
            ],
            "signals_used":        self.signals_used,
            "signals_missing":     self.signals_missing,
            "n_observations":      self.n_observations,
            "is_campaign_level":   self.is_campaign_level,
            "timestamp":           self.timestamp,
            "false_flag_warning":  self.false_flag_warning,
            "conflict_score":      round(self.conflict_score, 3),
            "conflicting_signals": self.conflicting_signals,
            "conflict_regions":    self.conflict_regions,
            "canarytoken_active":  self.canarytoken_active,
            "reliability_mode":    self.reliability_mode,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  SIGNAL EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

class SignalExtractor:
    """
    Extracts geographic signals from a CompletePipelineResult.

    Signals are normalized into a flat dict:
        {signal_name: value_string}

    Geographic signals (country-level):
        real_ip_country       — from webmail-leaked real IP geolocation
        geolocation_country   — from origin IP geolocation
        isp_country           — from WHOIS ASN registration country
        timezone_offset       — from Date: header
        timezone_region       — from campaignCorrelator TZ_REGION_MAP
        vpn_exit_country      — from VPN exit IP geolocation
        webmail_provider      — Gmail/Yahoo/etc.
        send_hour_local       — local send hour (0–23)
        subject_language      — detected language of subject (if available)

    Obfuscation layer flags (for ACI):
        is_tor                — Tor exit detected
        is_vpn                — VPN detected
        is_residential_proxy  — RESIP detected
        is_datacenter         — Datacenter (non-VPN) routing
        timestamp_spoofed     — Date: header timezone contradicted by Received:
    """

    def extract(self, result) -> Tuple[Dict[str, Any], Dict[str, bool]]:
        """
        Returns:
            signals   — {signal_name: value}  (geographic signals)
            obfuscation — {layer_name: bool}  (obfuscation flags)
        """
        signals:     Dict[str, Any]  = {}
        obfuscation: Dict[str, bool] = {
            "tor":               False,
            "vpn":               False,
            "residential_proxy": False,
            "datacenter":        False,
            "timestamp_spoof":   False,
        }

        ha  = getattr(result, "header_analysis",       None)
        cl  = getattr(result, "classifications",       None) or {}
        enc = getattr(result, "enrichment_results",    None) or {}
        geo = getattr(result, "geolocation_results",   None) or {}
        we  = getattr(result, "webmail_extraction",    None)
        bt  = getattr(result, "vpn_backtrack_analysis",None)
        ri  = getattr(result, "real_ip_analysis",      None)
        pa  = getattr(result, "proxy_analysis",        None)
        dkim = getattr(ha, "dkim_verification", {}) if ha else {}

        # ── Obfuscation flags ─────────────────────────────────────────────
        for ip, c in cl.items():
            if getattr(c, "is_tor",   False): obfuscation["tor"]  = True
            if getattr(c, "is_vpn",   False): obfuscation["vpn"]  = True
            if getattr(c, "is_proxy", False): obfuscation["residential_proxy"] = True
            cls_str = getattr(c, "classification", "")
            if "DATACENTER" in cls_str.upper():
                obfuscation["datacenter"] = True

        if pa:
            if getattr(pa, "tor_detected",   False): obfuscation["tor"] = True
            if getattr(pa, "vpn_detected",   False): obfuscation["vpn"] = True
            if getattr(pa, "proxy_detected", False): obfuscation["residential_proxy"] = True

        if bt:
            if getattr(bt, "vpn_provider",        None): obfuscation["vpn"] = True
            if getattr(bt, "tor_detected",        False): obfuscation["tor"] = True
            if getattr(bt, "spoofing_detected",   False): obfuscation["timestamp_spoof"] = True

        # Timestamp spoofing from header analysis
        if ha:
            spoof_risk = getattr(ha, "spoofing_risk", 0.0)
            if spoof_risk > 0.6:
                obfuscation["timestamp_spoof"] = True

        # ── Real IP (highest weight — webmail-leaked) ─────────────────────
        real_ip       = None
        real_ip_geo   = None

        if we and getattr(we, "real_ip_found", False) and we.real_ip:
            real_ip = we.real_ip
        elif ri and getattr(ri, "suspected_real_ip", None):
            real_ip = ri.suspected_real_ip
        elif bt and getattr(bt, "probable_real_ip", None):
            real_ip = bt.probable_real_ip

        if real_ip and real_ip in geo:
            real_ip_geo = geo[real_ip]
            if getattr(real_ip_geo, "country", None):
                signals["real_ip_country"] = real_ip_geo.country

        # ── Origin IP geolocation ─────────────────────────────────────────
        origin_ip = getattr(ha, "origin_ip", None) if ha else None
        if origin_ip and origin_ip in geo:
            origin_geo = geo[origin_ip]
            if getattr(origin_geo, "country", None):
                signals["geolocation_country"] = origin_geo.country
            # VPN exit country — only meaningful if VPN is detected
            if obfuscation["vpn"] and getattr(origin_geo, "country", None):
                signals["vpn_exit_country"] = origin_geo.country

        # ── WHOIS/ASN country ─────────────────────────────────────────────
        for ip, enr in enc.items():
            wd = getattr(enr, "whois_data", None)
            if wd and getattr(wd, "country", None):
                signals["isp_country"] = wd.country
                break   # Take first available

        # ── DNS infrastructure country (VPN-resistant) ────────────────────
        # Populated by vpnBacktrack._analyze_dns_infrastructure():
        # consensus of NS/MX/SPF/DKIM/PTR record geolocations.
        # Uses bt.probable_country when the DNS_INFRASTRUCTURE signal is
        # the highest-confidence signal in the BacktrackResult.
        if bt:
            _dns_country = getattr(bt, "probable_country", None)
            _bt_signals  = getattr(bt, "signals", []) or []
            _dns_sig = next(
                (s for s in _bt_signals
                 if getattr(s, "method", None) is not None
                 and str(getattr(s, "method", "")) == "BacktrackMethod.DNS_INFRASTRUCTURE"),
                None
            )
            if _dns_sig and getattr(_dns_sig, "real_country", None):
                signals["dns_infra_country"] = _dns_sig.real_country
            elif _dns_country and not signals.get("real_ip_country"):
                # Fallback: use bt.probable_country if no stronger signal present
                signals["dns_infra_country"] = _dns_country

        # ── Timezone offset ───────────────────────────────────────────────
        # Handles both RFC 2822 (+0530) and ISO 8601 (+05:30) formats.
        # Normalizes to "+HHMM" for TIMEZONE_COUNTRY_MAP lookup.
        if ha and getattr(ha, "email_date", None):
            import re
            tz_match = re.search(r"([+-]\d{2}:?\d{2})", str(ha.email_date))
            if tz_match:
                signals["timezone_offset"] = tz_match.group(1).replace(":", "")

        # ── Webmail provider ──────────────────────────────────────────────
        if we and getattr(we, "provider_name", None):
            signals["webmail_provider"] = we.provider_name

        # ── Send hour ─────────────────────────────────────────────────────
        # Handles both ISO 8601 "T19:51" and RFC 2822 "19:51:57 +0530".
        if ha and getattr(ha, "email_date", None):
            import re
            date_str = str(ha.email_date)
            hour_match = re.search(r"T(\d{2}):", date_str)          # ISO 8601
            if not hour_match:
                hour_match = re.search(r"\b(\d{2}):\d{2}:\d{2}\b", date_str)  # RFC 2822
            if hour_match:
                signals["send_hour_local"] = int(hour_match.group(1))

        # ── Timezone region label ─────────────────────────────────────────
        tz_off = signals.get("timezone_offset")
        if tz_off:
            TZ_REGION_MAP = {
                "+0000": "UTC / West Africa",           # UK (GMT), Nigeria, Ghana
                "+0100": "Central Europe / West Africa", # Germany (CET), Romania, Nigeria
                "+0200": "Eastern Europe / South Africa",# Ukraine, Romania, Germany (CEST)
                "+0300": "Russia (Moscow) / East Africa",
                "+0330": "Iran",
                "+0400": "UAE / Caucasus",
                "+0430": "Afghanistan",
                "+0500": "Pakistan / Central Asia",
                "+0530": "India / Sri Lanka",
                "+0545": "Nepal",
                "+0600": "Bangladesh",
                "+0700": "Southeast Asia",
                "+0800": "China / Southeast Asia",
                "+0900": "Japan / South Korea",
                "+1000": "Australia (East)",
                "-0300": "Brazil / Argentina",
                "-0400": "Venezuela / Chile",           # Venezuela standard time (VET)
                "-0500": "US Eastern / South America",
                "-0600": "US Central / Mexico",
                "-0700": "US Mountain",
                "-0800": "US Pacific",
            }
            if tz_off in TZ_REGION_MAP:
                signals["timezone_region"] = TZ_REGION_MAP[tz_off]

        # ── IPv6 country (VPN-resistant) ──────────────────────────────────────
        # Most consumer/commercial VPNs only tunnel IPv4; the device's real IPv6
        # leaks through unmodified.  Geolocate first non-private address found.
        ipv6_list = getattr(result, "unique_ipv6", None) or []
        for _v6 in ipv6_list:
            _v6l = _v6.strip().lower()
            # Skip link-local, loopback, ULA, documentation prefixes
            if any(_v6l.startswith(p) for p in
                   ("fe80", "::1", "fc", "fd", "2001:db8", "::")):
                continue
            # Priority 1: already in geolocation_results dict
            _v6_geo = geo.get(_v6) if geo else None
            if _v6_geo and getattr(_v6_geo, "country", None):
                signals["ipv6_country"] = _v6_geo.country
                break
            # Priority 2: RIR prefix heuristic → highest-prior country in that RIR
            # (continent-level fallback; used only when live geo unavailable)
            _rir_map = {
                "2a": "Russia",         # RIPE NCC  — highest-prior tracked country
                "2c": "Nigeria",        # AfriNIC   — highest-prior tracked country
                "28": "Brazil",         # LACNIC    — highest-prior tracked country
                "26": "United States",  # ARIN      — highest-prior tracked country
                "24": "China",          # APNIC     — highest-prior tracked country
            }
            for _prefix, _country in _rir_map.items():
                if _v6l.startswith(_prefix):
                    signals["ipv6_country"] = _country
                    break
            if "ipv6_country" in signals:
                break

        # ── Charset / locale region ───────────────────────────────────────────
        # Email MUA charset is set by the OS locale, not the network path.
        # VPN has zero effect on the Content-Type charset written by the sender.
        _charset = getattr(ha, "email_charset", None) if ha else None
        if _charset:
            _cs_norm = _charset.lower().strip()
            if CHARSET_REGION_MAP.get(_cs_norm):   # only set if non-empty mapping
                signals["charset_region"] = _cs_norm

        # ── DKIM authentication integrity ─────────────────────────────────
        if isinstance(dkim, dict) and dkim.get("dkim_present"):
            signals["dkim_present"] = True
            if dkim.get("domain"):
                signals["dkim_domain"] = dkim.get("domain")
            if dkim.get("selector"):
                signals["dkim_selector"] = dkim.get("selector")
            if dkim.get("failure_reason"):
                signals["dkim_failure_reason"] = dkim.get("failure_reason")
            if dkim.get("dkim_valid"):
                signals["dkim_valid"] = True

        return signals, obfuscation


# ─────────────────────────────────────────────────────────────────────────────
#  BAYESIAN UPDATER
# ─────────────────────────────────────────────────────────────────────────────

class BayesianUpdater:
    """
    Maintains and updates a probability distribution over candidate regions.

    Algorithm:
        1. Start with geographic priors (population-weighted phishing base rates)
        2. For each geographic signal, compute likelihood P(signal | region):
             - If signal directly names region R: high likelihood ratio (LR_signal)
             - If signal is compatible with region R (e.g. timezone): moderate LR
             - If signal contradicts region R: LR = 1/LR_signal (penalise)
             - If signal is silent about region R: LR = 1.0 (no update)
        3. Multiply likelihoods into the prior (Bayes update in log space)
        4. Normalize so probabilities sum to 1.0
        5. Return sorted posterior
    """

    def __init__(self, priors: Dict[str, float] = None):
        self._priors = priors or REGION_PRIORS.copy()

    def update(
        self,
        signals: Dict[str, Any],
        existing_log_odds: Dict[str, float] = None,
        effective_lrs: Dict[str, float] = None,
    ) -> Tuple[List[RegionProbability], Dict[str, float], List[str], List[str]]:
        """
        Perform one Bayesian update step.

        Args:
            signals:           {signal_name: value} from SignalExtractor
            existing_log_odds: Optional accumulated log-odds from prior calls
                               (for longitudinal accumulation)

        Returns:
            posterior    — sorted list of RegionProbability
            log_odds     — updated log-odds dict (for next call)
            used_signals — signals that contributed
            missing      — signals not present
        """
        lrs = effective_lrs if effective_lrs is not None else SIGNAL_LIKELIHOOD_RATIOS
        # Initialise from prior or from accumulated log-odds
        log_odds: Dict[str, float] = {}
        if existing_log_odds:
            log_odds = dict(existing_log_odds)
        else:
            for region, prior in self._priors.items():
                # log-prior-odds relative to "Other"
                other_p = self._priors.get("Other", 0.1)
                if prior > 0 and other_p > 0:
                    log_odds[region] = math.log(prior / other_p)
                else:
                    log_odds[region] = -5.0

        used_signals:    List[str] = []
        missing_signals: List[str] = list(lrs.keys())

        # ── Process each signal ───────────────────────────────────────────
        for sig_name, sig_value in signals.items():
            if sig_name not in lrs:
                continue
            lr_base = lrs[sig_name]
            if lr_base == 0.0:  # zero-weighted by reliability weighting
                if sig_name in missing_signals:
                    missing_signals.remove(sig_name)
                continue
            if sig_name in missing_signals:
                missing_signals.remove(sig_name)
            matched_regions = self._get_matching_regions(sig_name, sig_value)
            used_signals.append(sig_name)

            for region in list(log_odds.keys()):
                if region in matched_regions:
                    # Signal supports this region — Bayesian boost
                    log_odds[region] += math.log(lr_base)
                elif matched_regions and region != "Other":
                    # Signal names a different specific region — mild penalty.
                    # "Other" is excluded: it is a catch-all that contains
                    # every country including the matched one, so penalizing
                    # it when a signal points to India would be wrong.
                    log_odds[region] += math.log(max(0.3, 1.0 / lr_base))

        # ── Combined send_hour + timezone boost ───────────────────────────
        # If we have both timezone_offset AND send_hour_local in active
        # working hours (08:00–21:59 local), the combination gives stronger
        # geographic evidence than each signal alone.
        # Extended to 08-21 because many attacker regions (IN/PK/NG) work
        # into the evening. We apply a mild boost to timezone-matched regions.
        tz_off   = signals.get("timezone_offset")
        send_hr  = signals.get("send_hour_local")
        if tz_off and send_hr is not None:
            tz_regions = [c for c in TIMEZONE_COUNTRY_MAP.get(tz_off, [])
                          if c in self._priors]
            if tz_regions and 8 <= int(send_hr) <= 21:
                for region in tz_regions:
                    if region in log_odds:
                        log_odds[region] += math.log(1.3)  # +30% odds

        # ── Normalise to probabilities ────────────────────────────────────
        # Softmax over log-odds
        max_lo = max(log_odds.values()) if log_odds else 0.0
        exp_lo = {r: math.exp(lo - max_lo) for r, lo in log_odds.items()}
        total  = sum(exp_lo.values())
        posterior_probs = {r: v / total for r, v in exp_lo.items()}

        # ── Build output ──────────────────────────────────────────────────
        posterior: List[RegionProbability] = []
        for region, prob in sorted(posterior_probs.items(),
                                   key=lambda x: x[1], reverse=True):
            prior_p = self._priors.get(region, 0.01)
            supporting = [s for s in used_signals
                          if region in self._get_matching_regions(s, signals.get(s, ""))]
            posterior.append(RegionProbability(
                region             = region,
                probability        = prob,
                prior              = prior_p,
                log_odds           = log_odds.get(region, 0.0),
                supporting_signals = supporting,
            ))

        return posterior, log_odds, used_signals, missing_signals

    def _get_matching_regions(self, signal_name: str, value: Any) -> List[str]:
        """
        Return the list of regions that a given signal value supports.
        Returns empty list if signal is non-geographic or ambiguous.
        """
        if value is None:
            return []

        val = str(value).strip()

        if signal_name in ("real_ip_country", "geolocation_country",
                           "isp_country", "vpn_exit_country", "ipv6_country",
                           "dns_infra_country"):
            # Direct country name — look for it in our priors
            for region in self._priors:
                if region.lower() in val.lower() or val.lower() in region.lower():
                    return [region]
            # Unmapped country — still useful as "not Other"
            return []

        if signal_name == "timezone_offset":
            # Filter to only countries tracked in our priors dict
            candidates = TIMEZONE_COUNTRY_MAP.get(val, [])
            return [c for c in candidates if c in self._priors]

        if signal_name == "timezone_region":
            # Map region labels → candidate countries (filtered to priors)
            region_to_countries = {
                "India / Sri Lanka":              ["India"],
                "India":                          ["India"],
                "Russia (Moscow) / East Africa":  ["Russia"],
                "Russia":                         ["Russia"],
                "Eastern Europe / South Africa":  ["Ukraine", "Romania", "South Africa", "Germany"],
                "Nigeria":                        ["Nigeria"],
                "Ghana":                          ["Ghana"],
                "China / Southeast Asia":         ["China", "Vietnam", "Philippines"],
                "China":                          ["China"],
                "US Eastern":                     ["United States"],
                "US Pacific":                     ["United States"],
                "US Central / Mexico":            ["United States"],
                "US Mountain":                    ["United States"],
                "West Africa":                    ["Nigeria", "Ghana"],
                "UTC / West Africa":              ["United Kingdom", "Nigeria", "Ghana"],
                "UTC":                            ["United Kingdom", "Nigeria", "Ghana"],
                "Iran":                           ["Iran"],
                "Pakistan / Central Asia":        ["Pakistan", "Kazakhstan"],
                "Southeast Asia":                 ["Vietnam", "Indonesia", "Philippines"],
                "South America (East)":           ["Brazil"],
                "Brazil / Argentina":             ["Brazil"],
                "Venezuela / Chile":              ["Venezuela"],
                "Central Europe / West Africa":   ["Germany", "Romania", "Bulgaria", "Nigeria", "Ghana"],
                "Central Europe":                 ["Germany", "Romania", "Bulgaria"],
            }
            for label, countries in region_to_countries.items():
                if label.lower() in val.lower() or val.lower() in label.lower():
                    return [c for c in countries if c in self._priors]
            return []

        if signal_name == "webmail_provider":
            # Webmail is not strongly regional but certain providers correlate
            webmail_hints = {
                "yandex":    ["Russia"],
                "mail.ru":   ["Russia"],
                "rambler":   ["Russia"],
                "naver":     ["South Korea"],
                "163.com":   ["China"],
                "qq.com":    ["China"],
                "rediff":    ["India"],
            }
            for hint, countries in webmail_hints.items():
                if hint in val.lower():
                    return countries
            return []  # Gmail/Yahoo/Outlook are globally used

        if signal_name == "send_hour_local":
            # Working hours (09:00–17:00 local) are a weak signal on their own
            # but when combined with a timezone, they confirm activity pattern.
            # When the send hour falls in standard working hours, we boost
            # regions in the established timezone from prior signals.
            # Alone (without a timezone signal), we return empty — hour
            # cannot identify a region without knowing the UTC offset.
            # The boost is applied by returning empty here and relying on
            # the caller's combination with timezone_offset/region signals.
            # NOTE: non-working hours (e.g. 02:00) are weak counter-evidence
            # but we don't penalize because attackers can operate at any hour.
            return []

        if signal_name == "charset_region":
            # val is the raw charset string stored by SignalExtractor
            # Look up in CHARSET_REGION_MAP and filter to tracked priors
            countries = CHARSET_REGION_MAP.get(val.lower().strip(), [])
            return [c for c in countries if c in self._priors]

        return []


class ACICalculator:
    """
    Computes the Anonymization Confidence Index.

    ACI = max(0.05, 1.0 - Σ(weight_i × detected_i))

    The floor of 0.05 prevents complete zeroing — even through heavy
    Tor+RESIP obfuscation, timezone and behavioral signals retain some
    information about the actor's true location.
    """

    def compute(self, obfuscation: Dict[str, bool]) -> ACIBreakdown:
        total_penalty = 0.0
        penalty_applied: Dict[str, float] = {}

        for layer, weight in ACI_LAYER_WEIGHTS.items():
            detected = obfuscation.get(layer, False)
            if detected:
                penalty_applied[layer] = weight
                total_penalty         += weight
            else:
                penalty_applied[layer] = 0.0

        raw_aci   = 1.0 - total_penalty
        final_aci = max(0.05, raw_aci)

        # Interpretation
        if final_aci >= 0.80:
            interp = "Minimal obfuscation — signals are reliable"
        elif final_aci >= 0.60:
            interp = "Moderate obfuscation (VPN) — signals partially reliable"
        elif final_aci >= 0.40:
            interp = "Significant obfuscation — confidence is substantially degraded"
        elif final_aci >= 0.20:
            interp = "Heavy obfuscation (Tor/RESIP) — geographic signals are unreliable"
        else:
            interp = "Maximum obfuscation — attribution is speculative"

        return ACIBreakdown(
            raw_aci          = raw_aci,
            final_aci        = final_aci,
            layers_detected  = {k: obfuscation.get(k, False)
                                for k in ACI_LAYER_WEIGHTS},
            penalty_applied  = penalty_applied,
            interpretation   = interp,
        )


# ─────────────────────────────────────────────────────────────────────────────
#  TIER ASSIGNER
# ─────────────────────────────────────────────────────────────────────────────

class TierAssigner:
    """Assigns attribution tier (0–4) from ACI-adjusted posterior peak."""

    def assign(self, aci_adjusted_prob: float) -> Tuple[int, str, str]:
        """Returns (tier, tier_label, tier_description)."""
        for threshold, tier, label, desc in TIER_THRESHOLDS:
            if aci_adjusted_prob >= threshold:
                return tier, label, desc
        return 0, "Unknown", "Insufficient evidence to attribute geographically"

    def compute_hdi(
        self,
        posterior: List[RegionProbability],
        credible_mass: float = 0.90,
    ) -> Tuple[float, float]:
        """
        Compute 90% Highest Density Interval (HDI) on the posterior.

        For a discrete distribution, the HDI is the smallest set of regions
        that contains at least `credible_mass` total probability.

        Returns (lower_bound, upper_bound) where:
          lower_bound = probability of the lowest-ranked region in the HDI
          upper_bound = probability of the top region (= primary_probability)
        """
        if not posterior:
            return 0.0, 0.0

        sorted_post = sorted(posterior, key=lambda r: r.probability, reverse=True)
        cumulative   = 0.0
        hdi_regions  = []
        for rp in sorted_post:
            hdi_regions.append(rp)
            cumulative += rp.probability
            if cumulative >= credible_mass:
                break

        upper = sorted_post[0].probability
        lower = hdi_regions[-1].probability if hdi_regions else 0.0
        return lower, upper


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 5: FALSE FLAG DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FalseFlagResult:
    """
    Result of false-flag conflict analysis.
    Triggered when 3+ signals each point to different regions — consistent
    with deliberate signal-planting, not genuine single-actor attribution.
    """
    false_flag_detected:  bool
    conflict_score:       float
    conflicting_signals:  List[str]
    conflict_regions:     List[str]
    confidence_cap:       float
    detail:               str


class FalseFlagDetector:
    """
    Detects deliberate false-flag geographic signal planting.

    Algorithm:
      1. Extract country each signal most directly supports
      2. If >= MIN_SIGNALS signals exist pointing to >= MIN_REGIONS distinct
         countries -> CONFLICTED
      3. conflict_score = (n_distinct - 1) / (n_signals - 1)

    Known confusion pairs NOT treated as conflicts:
      CN/TW/HK, RU/UA/BY/KZ, IN/PK/BD/LK, US/CA/AU/GB, NG/GH/SN,
      SA/AE/EG/JO, DE/AT/CH, FR/BE/LU
    """

    CONFUSION_GROUPS: List[frozenset] = [
        frozenset({"China", "Taiwan", "Hong Kong"}),
        frozenset({"Russia", "Ukraine", "Belarus", "Kazakhstan"}),
        frozenset({"India", "Pakistan", "Bangladesh", "Sri Lanka"}),
        frozenset({"United States", "Canada", "Australia", "United Kingdom"}),
        frozenset({"Nigeria", "Ghana", "Senegal"}),
        frozenset({"Saudi Arabia", "UAE", "Egypt", "Jordan"}),
        frozenset({"Germany", "Austria", "Switzerland"}),
        frozenset({"France", "Belgium", "Luxembourg"}),
    ]

    def detect(
        self,
        signals:      Dict[str, Any],
        posterior:    List[RegionProbability],
        used_signals: List[str],
    ) -> FalseFlagResult:
        signal_region: Dict[str, str] = {}
        country_sigs = {
            "real_ip_country", "geolocation_country", "isp_country",
            "vpn_exit_country", "canarytoken_triggered",
        }
        for sig in used_signals:
            val = signals.get(sig, "")
            if not val:
                continue
            if sig in country_sigs:
                signal_region[sig] = str(val)
            elif sig == "timezone_offset":
                countries = [c for c in TIMEZONE_COUNTRY_MAP.get(str(val), [])
                             if c in REGION_PRIORS]
                if countries:
                    signal_region[sig] = countries[0]
            elif sig == "timezone_region" and posterior:
                signal_region[sig] = posterior[0].region

        n_signals = len(signal_region)
        if n_signals < FALSE_FLAG_MIN_SIGNALS:
            return FalseFlagResult(
                false_flag_detected=False, conflict_score=0.0,
                conflicting_signals=[], conflict_regions=[],
                confidence_cap=1.0,
                detail=f"Only {n_signals} mappable signals — skipping",
            )

        distinct: Dict[str, List[str]] = {}
        for sig, region in signal_region.items():
            canonical = self._canonicalise(region)
            distinct.setdefault(canonical, []).append(sig)

        n_distinct = len(distinct)
        if n_distinct < FALSE_FLAG_MIN_REGIONS:
            return FalseFlagResult(
                false_flag_detected=False, conflict_score=0.0,
                conflicting_signals=[], conflict_regions=[],
                confidence_cap=1.0,
                detail=f"{n_signals} signals, {n_distinct} region(s) — consistent",
            )

        score = (n_distinct - 1) / max(n_signals - 1, 1)
        return FalseFlagResult(
            false_flag_detected=True,
            conflict_score=round(score, 3),
            conflicting_signals=list(signal_region.keys()),
            conflict_regions=list(distinct.keys()),
            confidence_cap=FALSE_FLAG_CONFLICT_CAP,
            detail=(
                f"{n_signals} signals -> {n_distinct} distinct regions "
                f"(conflict_score={score:.2f}). Possible false-flag planting. "
                f"Confidence capped at {FALSE_FLAG_CONFLICT_CAP:.0%}."
            ),
        )

    def _canonicalise(self, region: str) -> str:
        for group in self.CONFUSION_GROUPS:
            if region in group:
                return "|".join(sorted(group))
        return region


# ─────────────────────────────────────────────────────────────────────────────
#  LAYER 5: SIGNAL RELIABILITY WEIGHTER
# ─────────────────────────────────────────────────────────────────────────────

class SignalReliabilityWeighter:
    """Returns per-signal effective LRs adjusted for current obfuscation state."""

    def get_reliability_mode(
        self, obfuscation: Dict[str, bool], signals: Dict[str, Any]
    ) -> str:
        if "canarytoken_triggered" in signals:
            return "canarytoken_active"
        if obfuscation.get("tor", False):
            return "tor_detected"
        if obfuscation.get("vpn", False):
            return "vpn_detected"
        return "no_obfuscation"

    def get_effective_lrs(self, mode: str) -> Dict[str, float]:
        rel = SIGNAL_SOURCE_RELIABILITY.get(
            mode, SIGNAL_SOURCE_RELIABILITY["no_obfuscation"]
        )
        return {
            sig: base * rel.get(sig, 1.0)
            for sig, base in SIGNAL_LIKELIHOOD_RATIOS.items()
        }


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class AttributionEngine:
    """
    Bayesian attribution engine for HunterTrace.

    Two modes:
      1. Single-email attribution
         result = engine.attribute(pipeline_result)

      2. Campaign-level longitudinal attribution
         engine.update_campaign(actor_id, pipeline_result)  # call for each email
         result = engine.finalize_campaign(actor_id)        # call after all emails

    The longitudinal mode accumulates log-odds across observations so each
    new email refines (not replaces) the posterior from earlier emails.
    This means a consistent +0530 timezone across 10 emails produces a far
    stronger attribution than a single +0530 observation — exactly the
    Bayesian inference expected from repeated independent evidence.
    """

    def __init__(self, verbose: bool = False):
        self.verbose      = verbose
        self._extractor   = SignalExtractor()
        self._updater     = BayesianUpdater()
        self._aci_calc    = ACICalculator()
        self._tier        = TierAssigner()
        self._ff_detector  = FalseFlagDetector()          # Layer 5
        self._reliability  = SignalReliabilityWeighter()  # Layer 5

        # Campaign state: actor_id → accumulated evidence
        self._campaigns: Dict[str, Dict] = defaultdict(lambda: {
            "log_odds":         None,           # accumulated log-odds
            "n_observations":   0,
            "all_signals":      [],             # one dict per email
            "all_obfuscation":  [],             # one dict per email
            "used_signals":     set(),
        })

    # ─────────────────────────────────────────────────────────────────────
    #  Single-email attribution
    # ─────────────────────────────────────────────────────────────────────

    def attribute(self, pipeline_result) -> "AttributionResult":
        """
        Run full Bayesian attribution on a single CompletePipelineResult.
        Does NOT accumulate state — for campaign use, call update_campaign().
        """
        signals, obfuscation = self._extractor.extract(pipeline_result)

        if self.verbose:
            print(f"[AttributionEngine] Signals extracted: {list(signals.keys())}")
            print(f"[AttributionEngine] Obfuscation: "
                  f"{[k for k,v in obfuscation.items() if v]}")

        return self._compute_result(
            signals            = signals,
            obfuscation        = obfuscation,
            log_odds_seed      = None,
            n_obs              = 1,
            is_campaign        = False,
        )

    def attribute_with_canarytoken(
        self,
        pipeline_result,
        canarytoken_result,
    ) -> "AttributionResult":
        """
        Attribution with triggered canarytoken injected as weight-25 signal.
        Bypasses all VPN/Tor — the real IP captured at document-open dominates.

        Parameters
        ----------
        pipeline_result   : CompletePipelineResult from standard pipeline
        canarytoken_result: CanarytokenResult with triggered=True
        """
        signals, obfuscation = self._extractor.extract(pipeline_result)

        if getattr(canarytoken_result, "triggered", False):
            country = getattr(canarytoken_result, "real_ip_country", None)
            if country:
                signals["canarytoken_triggered"] = country
                signals["real_ip_country"]       = country
            if self.verbose:
                print(f"[Engine] Canarytoken: {country} "
                      f"(IP: {getattr(canarytoken_result, 'real_ip', '?')})")

        return self._compute_result(
            signals            = signals,
            obfuscation        = obfuscation,
            log_odds_seed      = None,
            n_obs              = 1,
            is_campaign        = False,
            canarytoken_active = "canarytoken_triggered" in signals,
        )

    # ─────────────────────────────────────────────────────────────────────
    #  Campaign-level longitudinal attribution
    # ─────────────────────────────────────────────────────────────────────

    def update_campaign(self, actor_id: str, pipeline_result) -> None:
        """
        Accumulate evidence from one email into the campaign's posterior.
        Call this for each email attributed to the same actor cluster.
        """
        signals, obfuscation = self._extractor.extract(pipeline_result)

        state = self._campaigns[actor_id]
        state["n_observations"] += 1
        state["all_signals"].append(signals)
        state["all_obfuscation"].append(obfuscation)

        # Bayesian update — pass existing log-odds as seed
        posterior, new_log_odds, used, _ = self._updater.update(
            signals           = signals,
            existing_log_odds = state["log_odds"],
        )

        state["log_odds"] = new_log_odds
        state["used_signals"].update(used)

        if self.verbose:
            print(f"[AttributionEngine] Campaign {actor_id}: "
                  f"observation {state['n_observations']} — "
                  f"top region: {posterior[0].region} "
                  f"({posterior[0].probability:.1%})")

    def update_campaign_from_fingerprint(
        self,
        actor_id: str,
        fingerprint,   # EmailFingerprint from campaignCorrelator
        geo_map: Dict = None,
    ) -> None:
        """
        Alternative ingestion path: update from an EmailFingerprint directly.
        Used when pipeline results are not available (offline / JSON mode).
        """
        geo_map = geo_map or {}
        signals: Dict[str, Any]  = {}
        obfuscation: Dict[str, bool] = {k: False for k in ACI_LAYER_WEIGHTS}

        if fingerprint.timezone_offset:
            signals["timezone_offset"] = fingerprint.timezone_offset
        if fingerprint.timezone_region:
            signals["timezone_region"] = fingerprint.timezone_region
        if fingerprint.vpn_provider:
            obfuscation["vpn"] = True
        if fingerprint.webmail_provider:
            signals["webmail_provider"] = fingerprint.webmail_provider
        if fingerprint.send_hour_local is not None:
            signals["send_hour_local"] = fingerprint.send_hour_local
        if fingerprint.real_ip and fingerprint.real_ip in geo_map:
            geo = geo_map[fingerprint.real_ip]
            if getattr(geo, "country", None):
                signals["real_ip_country"] = geo.country
        if fingerprint.origin_ip and fingerprint.origin_ip in geo_map:
            geo = geo_map[fingerprint.origin_ip]
            if getattr(geo, "country", None) and obfuscation["vpn"]:
                signals["vpn_exit_country"] = geo.country

        state = self._campaigns[actor_id]
        state["n_observations"] += 1
        state["all_signals"].append(signals)
        state["all_obfuscation"].append(obfuscation)

        _, new_log_odds, used, _ = self._updater.update(
            signals           = signals,
            existing_log_odds = state["log_odds"],
        )
        state["log_odds"] = new_log_odds
        state["used_signals"].update(used)

    def finalize_campaign(self, actor_id: str) -> "AttributionResult":
        """
        Compute final campaign-level attribution from accumulated evidence.
        Averages obfuscation flags across all observations (majority vote).
        """
        state = self._campaigns.get(actor_id)
        if not state or state["n_observations"] == 0:
            return self._empty_result()

        # Majority-vote obfuscation (detected in >50% of observations = detected)
        n = state["n_observations"]
        obfuscation: Dict[str, bool] = {}
        for layer in ACI_LAYER_WEIGHTS:
            count_detected = sum(
                1 for obs in state["all_obfuscation"]
                if obs.get(layer, False)
            )
            obfuscation[layer] = (count_detected / n) >= 0.5

        # Merge all signals (union — any signal seen in any email)
        merged_signals: Dict[str, Any] = {}
        for sig_dict in state["all_signals"]:
            for k, v in sig_dict.items():
                if k not in merged_signals:
                    merged_signals[k] = v
                else:
                    # Country-level signals: prefer value that appears most often
                    if k.endswith("_country"):
                        all_vals = [d.get(k) for d in state["all_signals"]
                                    if d.get(k)]
                        if all_vals:
                            from collections import Counter
                            merged_signals[k] = Counter(all_vals).most_common(1)[0][0]

        return self._compute_result(
            signals       = merged_signals,
            obfuscation   = obfuscation,
            log_odds_seed = state["log_odds"],
            n_obs         = n,
            is_campaign   = True,
        )

    # ─────────────────────────────────────────────────────────────────────
    #  Attribute directly from an ActorTTPProfile (v3 integration)
    # ─────────────────────────────────────────────────────────────────────

    def attribute_from_profile(
        self,
        profile,                                        # ActorTTPProfile from actorProfiler
        geo_map:              Dict = None,
        obfuscation_override: Dict[str, bool] = None,   # P0-B: pipeline-derived flags
    ) -> "AttributionResult":
        """
        Derive attribution directly from an ActorTTPProfile.
        Used as the final step in the v3 pipeline after campaign correlation.

        Parameters
        ----------
        profile               : ActorTTPProfile from actorProfiler.
        geo_map               : ip → GeolocationData dict (optional).
        obfuscation_override  : Obfuscation flags aggregated from the actual
                                pipeline results for this actor's emails
                                (keys: tor, vpn, residential_proxy, datacenter,
                                timestamp_spoof → bool).
                                When provided, these replace the opsec_score
                                heuristic so that real VPN/Tor detections from
                                vpnBacktrack and ipClassifier feed into the ACI.
                                Falls back to opsec_score heuristic when None
                                (offline / JSON-only mode).

        P0-A note — why no log_odds pre-accumulation loop
        ──────────────────────────────────────────────────
        The old implementation fed identical signals into the Bayesian updater
        n_obs times, seeding each call with the accumulated log-odds from the
        previous call.  This is a double-counting error in two ways:

          1. The same evidence applied n times inflates log-odds by n × log(LR)
             rather than log(LR), collapsing the softmax posterior to 1.0 even
             for small n and moderate LR values.

          2. _compute_result always runs one further updater.update() call on
             top of the seeded log-odds, so signals were counted n+1 times total.

        Identical evidence is NOT independent — it carries no additional
        information beyond the first observation.  The Bayesian update is
        designed to ingest *new*, independent evidence each iteration.

        Fix: pass log_odds_seed=None so _compute_result performs exactly ONE
        authoritative update from the prior.  Corroboration from multiple
        emails in the cluster is expressed via corroboration_scale, which
        multiplies the signal delta-from-prior by a sqrt(n_obs)-derived factor
        after the single update.  This gives calibrated posteriors:
            n= 1  → scale≈0.45  → posterior ~0.76–0.83  (Tier 2)
            n= 5  → scale≈0.52  → posterior ~0.87–0.92  (Tier 3)
            n=10  → scale≈0.56  → posterior ~0.90–0.94  (Tier 3/4 border)
            n=20  → scale≈0.63  → posterior ~0.93–0.96  (Tier 4, _conf_cap applies)
        """
        geo_map = geo_map or {}
        signals: Dict[str, Any] = {}

        t = profile.temporal
        i = profile.infrastructure

        if t.timezone_offset:
            signals["timezone_offset"] = t.timezone_offset
        if t.timezone_region:
            signals["timezone_region"] = t.timezone_region
        if t.likely_country:
            signals["geolocation_country"] = t.likely_country
        if i.primary_webmail:
            signals["webmail_provider"] = i.primary_webmail
        if i.origin_ips:
            for ip in i.origin_ips:
                if ip in geo_map:
                    geo = geo_map[ip]
                    if getattr(geo, "country", None):
                        signals["real_ip_country"] = geo.country
                        break

        # ── Obfuscation flags (P0-B) ──────────────────────────────────────
        if obfuscation_override is not None:
            # Primary path: real flags from vpnBacktrack / ipClassifier /
            # proxy_analysis, aggregated by the orchestrator across all emails
            # in this actor's cluster and passed in via obfuscation_override.
            obfuscation: Dict[str, bool] = {k: False for k in ACI_LAYER_WEIGHTS}
            for layer in ACI_LAYER_WEIGHTS:
                obfuscation[layer] = bool(obfuscation_override.get(layer, False))
        else:
            # Offline / JSON-only fallback: derive from opsec_score heuristic.
            #   opsec_score >= 70  → datacenter routing likely
            #   opsec_score >= 85  → residential proxy / VPN likely
            obfuscation = {k: False for k in ACI_LAYER_WEIGHTS}
            if i.vpn_providers:
                obfuscation["vpn"] = True
            if i.opsec_score >= 70:
                obfuscation["datacenter"] = True
            if i.opsec_score >= 85:
                obfuscation["residential_proxy"] = True

        n_obs = profile.campaign_count

        return self._compute_result(
            signals             = signals,
            obfuscation         = obfuscation,
            log_odds_seed       = None,   # P0-A: always one clean update from prior
            n_obs               = n_obs,
            is_campaign         = True,
            corroboration_scale = self._corroboration_scale(n_obs),
        )

    # ─────────────────────────────────────────────────────────────────────
    #  Corroboration scale helper  (P0-A)
    # ─────────────────────────────────────────────────────────────────────

    @staticmethod
    def _corroboration_scale(n_obs: int) -> float:
        """
        Returns a [0.0, 0.92] scale factor expressing how much the signal
        delta-from-prior should be amplified to reflect corroboration from
        n_obs independent observations of the same signals.

        Design rationale
        ────────────────
        Each additional email confirming the same signal is corroborating
        evidence, not independent new evidence.  The information gain from
        n corroborating observations grows as sqrt(n) — sub-linear, consistent
        with the diminishing-returns nature of repeated confirmation:

            scale(n) = min(0.40 + 0.052 × sqrt(n_obs), 0.92)

        Calibrated posteriors for a 3-signal cluster
        (timezone_offset LR=6, timezone_region LR=4.5, geo_country LR=12):
            n= 1  → scale=0.452  → posterior≈0.83  (Tier 2/3 border)
            n= 5  → scale=0.516  → posterior≈0.89  (Tier 3)
            n=10  → scale=0.564  → posterior≈0.92  (Tier 3/4 border)
            n=20  → scale=0.633  → posterior≈0.95  (Tier 4, capped by _conf_cap)

        Why not log(n+1)?
            With LR values of 6–12, even scale=log(2)=0.69 collapses a
            3-signal posterior to >0.99 for a single email.  sqrt(n) grows
            far more slowly and keeps the posterior in a calibrated range.

        Why cap at 0.92?
            Tier 4 (ISP-level, ACI-adjusted ≥0.85) should only be reached
            when independent high-quality signals agree, not from cluster size
            alone.  _conf_cap in _compute_result enforces this ceiling on the
            final ACI-adjusted probability.
        """
        return min(0.40 + 0.052 * math.sqrt(max(1, n_obs)), 0.92)

    # ─────────────────────────────────────────────────────────────────────
    #  Core computation
    # ─────────────────────────────────────────────────────────────────────

    def _compute_result(
        self,
        signals:              Dict[str, Any],
        obfuscation:          Dict[str, bool],
        log_odds_seed:        Optional[Dict[str, float]],
        n_obs:                int,
        is_campaign:          bool,
        canarytoken_active:   bool  = False,
        corroboration_scale:  float = 1.0,
    ) -> "AttributionResult":
        """
        Core attribution computation.

        corroboration_scale (P0-A)
        ──────────────────────────
        After the Bayesian updater runs ONE clean update from the prior (or
        from log_odds_seed for the longitudinal path), the signal delta-from-
        prior in the resulting log-odds is multiplied by corroboration_scale:

            prior_lo[r]   = log(prior[r] / prior["Other"])
            updated_lo[r] = prior_lo[r] + Σ log(LR_i)   (from updater)
            scaled_lo[r]  = prior_lo[r] + (updated_lo[r] - prior_lo[r]) × scale

        scale=1.0  → no change (default for single-email and finalize_campaign)
        scale<1.0  → dampen the update (used when only 1 email in cluster)
        scale>1.0  → amplify the update (used for large clusters via sqrt(n))

        All callers except attribute_from_profile pass scale=1.0.
        attribute_from_profile passes _corroboration_scale(n_obs).
        """

        # ── Layer 5: Signal reliability weighting ────────────────────────
        reliability_mode = self._reliability.get_reliability_mode(obfuscation, signals)
        effective_lrs    = self._reliability.get_effective_lrs(reliability_mode)

        if self.verbose and reliability_mode != "no_obfuscation":
            zeroed = [s for s, lr in effective_lrs.items() if lr == 0.0]
            print(f"[Engine] Reliability mode: {reliability_mode}")
            if zeroed:
                print(f"[Engine] Zero-weighted: {zeroed}")

        # ── Single Bayesian update ────────────────────────────────────────
        posterior, log_odds, used_signals, missing = self._updater.update(
            signals           = signals,
            existing_log_odds = log_odds_seed,
            effective_lrs     = effective_lrs,
        )

        # ── Apply corroboration scale (P0-A) ──────────────────────────────
        # Only applied when scale != 1.0 (i.e. attribute_from_profile path).
        # Scales the delta of each region's log-odds from its prior, so that
        # n corroborating observations sharpen the posterior without collapsing
        # it to 1.0 via log-odds overflow.
        if corroboration_scale != 1.0 and log_odds_seed is None:
            # Compute prior log-odds for each region
            other_p = self._updater._priors.get("Other", 0.1)
            prior_lo = {
                r: math.log(p / other_p) if p > 0 else -5.0
                for r, p in self._updater._priors.items()
            }
            # Scale the delta from prior
            scaled_lo = {
                r: prior_lo.get(r, 0.0) + (lo - prior_lo.get(r, 0.0)) * corroboration_scale
                for r, lo in log_odds.items()
            }
            # Re-normalise posterior with scaled log-odds
            max_lo  = max(scaled_lo.values())
            exp_lo  = {r: math.exp(lo - max_lo) for r, lo in scaled_lo.items()}
            total   = sum(exp_lo.values())
            scaled_probs = {r: v / total for r, v in exp_lo.items()}
            # Rebuild posterior list preserving supporting_signals
            sig_map = {rp.region: rp.supporting_signals for rp in posterior}
            posterior = [
                RegionProbability(
                    region             = r,
                    probability        = scaled_probs[r],
                    prior              = self._updater._priors.get(r, 0.01),
                    log_odds           = scaled_lo[r],
                    supporting_signals = sig_map.get(r, []),
                )
                for r in sorted(scaled_probs, key=scaled_probs.get, reverse=True)
            ]

        # ── ACI computation ───────────────────────────────────────────────
        aci = self._aci_calc.compute(obfuscation)

        primary  = posterior[0] if posterior else RegionProbability(
            region="Unknown", probability=0.0, prior=0.0, log_odds=0.0)
        raw_prob = primary.probability

        # Signal-scaled confidence cap: 1 signal->57%, 5 signals->88%, max 92%
        _n_sig    = len(used_signals)
        _conf_cap = min(0.50 + _n_sig * 0.075, 0.92)

        # Canarytoken: raise cap to 97% (definitive evidence)
        if canarytoken_active or "canarytoken_triggered" in signals:
            _conf_cap          = 0.97
            canarytoken_active = True

        aci_adj = min(raw_prob * aci.final_aci, _conf_cap)
        if not used_signals:
            aci_adj = 0.0

        # ── DKIM confidence shaping ───────────────────────────────────────
        # DKIM is not geographic evidence, but valid cryptographic auth
        # increases message integrity confidence while present-but-invalid
        # suggests tampering or header/body mismatch.
        if signals.get("dkim_valid"):
            if "dkim_valid" not in used_signals:
                used_signals.append("dkim_valid")
            aci_adj = min(_conf_cap, aci_adj * 1.03 + 0.01)
        elif signals.get("dkim_present"):
            if "dkim_invalid" not in used_signals:
                used_signals.append("dkim_invalid")
            aci_adj *= 0.85

        # ── Layer 5: False flag detection ────────────────────────────────
        ff = self._ff_detector.detect(signals, posterior, used_signals)
        if ff.false_flag_detected:
            aci_adj = min(aci_adj, ff.confidence_cap)
            if self.verbose:
                print(f"[Engine] False flag: {ff.detail}")

        tier, tier_label, tier_desc = self._tier.assign(aci_adj)
        hdi_lo, hdi_hi = self._tier.compute_hdi(posterior)
        total_possible = len(SIGNAL_LIKELIHOOD_RATIOS)

        return AttributionResult(
            primary_region      = primary.region,
            primary_probability = raw_prob,
            hdi_lower           = hdi_lo,
            hdi_upper           = hdi_hi,
            posterior           = posterior,
            aci                 = aci,
            aci_adjusted_prob   = aci_adj,
            tier                = tier,
            tier_label          = tier_label,
            tier_description    = tier_desc,
            signals_used        = used_signals,
            signals_available   = total_possible,
            signals_missing     = missing,
            n_observations      = n_obs,
            timestamp           = datetime.now().isoformat(),
            is_campaign_level   = is_campaign,
            false_flag_warning  = ff.false_flag_detected,
            conflict_score      = ff.conflict_score,
            conflicting_signals = ff.conflicting_signals,
            conflict_regions    = ff.conflict_regions,
            canarytoken_active  = canarytoken_active,
            reliability_mode    = reliability_mode,
        )

    def _empty_result(self) -> "AttributionResult":
        aci = self._aci_calc.compute({k: False for k in ACI_LAYER_WEIGHTS})
        return AttributionResult(
            primary_region      = "Unknown",
            primary_probability = 0.0,
            hdi_lower           = 0.0,
            hdi_upper           = 0.0,
            posterior           = [],
            aci                 = aci,
            aci_adjusted_prob   = 0.0,
            tier                = 0,
            tier_label          = "Unknown",
            tier_description    = "No pipeline results available",
            signals_used        = [],
            signals_available   = 0,
            signals_missing     = list(SIGNAL_LIKELIHOOD_RATIOS.keys()),
            n_observations      = 0,
            timestamp           = datetime.now().isoformat(),
            is_campaign_level   = False,
            false_flag_warning  = False,
            conflict_score      = 0.0,
            conflicting_signals = [],
            conflict_regions    = [],
            canarytoken_active  = False,
            reliability_mode    = "no_obfuscation",
        )

    def reset_campaign(self, actor_id: str) -> None:
        """Clear accumulated state for a campaign (call between batch runs)."""
        if actor_id in self._campaigns:
            del self._campaigns[actor_id]

    def export_campaign_state(self, actor_id: str) -> Optional[dict]:
        """
        Export accumulated campaign log-odds to JSON-serialisable dict.
        Allows persisting state across sessions.
        """
        state = self._campaigns.get(actor_id)
        if not state:
            return None
        return {
            "actor_id":       actor_id,
            "n_observations": state["n_observations"],
            "log_odds":       state["log_odds"],
            "used_signals":   list(state["used_signals"]),
        }

    def import_campaign_state(self, state_dict: dict) -> None:
        """Restore previously exported campaign state."""
        actor_id = state_dict["actor_id"]
        self._campaigns[actor_id]["n_observations"] = state_dict["n_observations"]
        self._campaigns[actor_id]["log_odds"]       = state_dict["log_odds"]
        self._campaigns[actor_id]["used_signals"]   = set(state_dict["used_signals"])


# ─────────────────────────────────────────────────────────────────────────────
#  V3 INTEGRATION HELPER
# ─────────────────────────────────────────────────────────────────────────────

def integrate_with_v3(
    correlation_report,              # CorrelationReport from campaignCorrelator
    actor_profiles:     Dict,        # actor_id → ActorTTPProfile
    geo_map:            Dict = None, # ip → GeolocationData (optional)
    verbose:            bool = False,
) -> Dict[str, AttributionResult]:
    """
    Convenience function: run the attribution engine over all actor clusters
    produced by HunterTraceV3._run_v3_analysis().

    Returns:
        {actor_id: AttributionResult}

    Wire into HunterTraceV3._run_v3_analysis() after step 2 (actor profiling):

        from attributionEngine import integrate_with_v3
        attribution_results = integrate_with_v3(
            self._report, self._profiles, verbose=self.verbose
        )
        # Store on V3Report
        report.attribution_results = attribution_results

    Note: this helper does not pass obfuscation_override — it uses the offline
    opsec_score heuristic.  For pipeline-derived ACI, use the orchestrator's
    Step 2.5 which calls attribute_from_profile(obfuscation_override=...).
    """
    engine = AttributionEngine(verbose=verbose)
    results: Dict[str, AttributionResult] = {}

    for cluster in correlation_report.actor_clusters:
        actor_id = cluster.actor_id
        profile  = actor_profiles.get(actor_id)

        if profile:
            # Path 1: attribute from full TTP profile (preferred)
            result = engine.attribute_from_profile(profile, geo_map or {})
        else:
            # Path 2: attribute from fingerprints directly
            for fp in cluster.fingerprints:
                engine.update_campaign_from_fingerprint(actor_id, fp, geo_map or {})
            result = engine.finalize_campaign(actor_id)

        results[actor_id] = result

        if verbose:
            print(f"\n[AttributionEngine] {actor_id}:")
            print(f"  {result.summary()}")

    return results
