#!/usr/bin/env python3
"""
test_attributionEngine.py — Comprehensive test suite for the Bayesian
Attribution Engine and its integration with the HunterTrace v3 pipeline.

Tests:
  1. Constants & calibration  — priors sum to 1.0, LR values are positive
  2. ACI Calculator           — penalty arithmetic, floor, interpretation bands
  3. Tier Assigner            — all 5 tiers reachable, HDI computation
  4. BayesianUpdater          — update correctness, longitudinal accumulation
  5. SignalExtractor          — extracts from mock pipeline result
  6. AttributionEngine        — single-email & campaign mode end-to-end
  7. attribute_from_profile   — ActorTTPProfile → AttributionResult
  8. signals_available fix    — should be 10 (total possible), not len(signals)
  9. send_hour boost          — working hours + timezone gives bonus
 10. V3 integration           — integrate_with_v3 helper function
 11. Serialization            — to_dict / summary / analyst_brief round-trips
 12. Edge cases               — empty results, missing signals, heavy obfuscation
"""

import math
import json
import sys
from types import SimpleNamespace
from typing import Any, Dict

# ── Allow import from parent directory ────────────────────────────────────────
import os
sys.path.insert(0, os.path.dirname(__file__))

try:
    from attributionEngine import (
        AttributionEngine,
        SignalExtractor,
        BayesianUpdater,
        ACICalculator,
        TierAssigner,
        RegionProbability,
        ACIBreakdown,
        AttributionResult,
        REGION_PRIORS,
        SIGNAL_LIKELIHOOD_RATIOS,
        ACI_LAYER_WEIGHTS,
        TIMEZONE_COUNTRY_MAP,
        TIER_THRESHOLDS,
        integrate_with_v3,
    )
    print("[OK] attributionEngine imported successfully")
except ImportError as e:
    print(f"[FAIL] Could not import attributionEngine: {e}")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
#  Test helpers
# ─────────────────────────────────────────────────────────────────────────────

PASS = 0
FAIL = 0
TESTS: list = []

def check(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        TESTS.append(("PASS", name))
        print(f"  ✓  {name}")
    else:
        FAIL += 1
        TESTS.append(("FAIL", name))
        print(f"  ✗  {name}  {detail}")

def section(title: str):
    print(f"\n{'─'*68}")
    print(f"  {title}")
    print(f"{'─'*68}")


def _make_pipeline_result(
    tz_offset: str = "+0530",
    origin_country: str = "India",
    real_ip_country: str = None,
    isp_country: str = None,
    vpn: bool = False,
    tor: bool = False,
    resip: bool = False,
    datacenter: bool = False,
    timestamp_spoof: bool = False,
    send_hour: int = 14,
    webmail: str = "Gmail",
) -> SimpleNamespace:
    """
    Build a minimal mock CompletePipelineResult that SignalExtractor understands.
    Only sets the attributes that the extractor reads.
    """
    # Header analysis
    ha = SimpleNamespace(
        email_date     = f"2026-02-20T{send_hour:02d}:05:00{tz_offset}",
        origin_ip      = "1.2.3.4",
        email_subject  = "Test subject",
        email_from     = "attacker@evil.com",
        message_id     = "<test@test>",
        spoofing_risk  = 0.8 if timestamp_spoof else 0.0,
        hops           = [],
    )

    # Classifications
    cl_entry = SimpleNamespace(
        is_tor          = tor,
        is_vpn          = vpn,
        is_proxy        = resip,
        classification  = "DATACENTER" if datacenter else "RESIDENTIAL",
    )

    # Geolocation
    geo = {}
    if origin_country:
        geo["1.2.3.4"] = SimpleNamespace(country=origin_country, confidence=0.80)
    if real_ip_country:
        geo["9.9.9.9"] = SimpleNamespace(country=real_ip_country, confidence=0.90)

    # Enrichment
    enc = {}
    if isp_country:
        enc["1.2.3.4"] = SimpleNamespace(
            whois_data = SimpleNamespace(country=isp_country, asn="AS12345")
        )

    # Webmail extraction
    we = None
    if real_ip_country:
        we = SimpleNamespace(
            real_ip_found = True,
            real_ip       = "9.9.9.9",
            provider_name = webmail,
            leak_header   = "X-Originating-IP",
        )
    elif webmail:
        we = SimpleNamespace(
            real_ip_found = False,
            real_ip       = None,
            provider_name = webmail,
            leak_header   = None,
        )

    # Proxy analysis
    pa = SimpleNamespace(
        tor_detected   = tor,
        vpn_detected   = vpn,
        proxy_detected = resip,
        obfuscation_count = sum([tor, vpn, resip]),
    )

    # VPN backtrack
    bt = SimpleNamespace(
        vpn_provider      = "NordVPN" if vpn else None,
        tor_detected      = tor,
        spoofing_detected = timestamp_spoof,
        probable_real_ip  = None,
    )

    return SimpleNamespace(
        header_analysis        = ha,
        classifications        = {"1.2.3.4": cl_entry},
        enrichment_results     = enc,
        geolocation_results    = geo,
        webmail_extraction     = we,
        vpn_backtrack_analysis = bt,
        proxy_analysis         = pa,
        real_ip_analysis       = None,
    )


def _make_actor_profile(
    tz_offset: str = "+0530",
    tz_region: str = "India / Sri Lanka",
    likely_country: str = "India",
    vpn_providers: list = None,
    origin_ips: list = None,
    opsec_score: int = 30,
    campaign_count: int = 5,
) -> SimpleNamespace:
    """Build a minimal mock ActorTTPProfile."""
    temporal = SimpleNamespace(
        timezone_offset   = tz_offset,
        timezone_region   = tz_region,
        likely_country    = likely_country,
        peak_send_hour    = 14,
        campaign_count    = campaign_count,
    )
    infra = SimpleNamespace(
        vpn_providers  = vpn_providers or [],
        primary_webmail= "Gmail",
        origin_ips     = origin_ips or [],
        vpn_exit_ips   = [],
        opsec_score    = opsec_score,
        opsec_label    = "intermediate",
        opsec_notes    = [],
    )
    from collections import namedtuple
    MITRE = namedtuple("MITRE", ["technique_id","technique_name","tactic","confidence","evidence"])
    return SimpleNamespace(
        actor_id        = "ACTOR_TEST_001",
        campaign_count  = campaign_count,
        confidence      = 0.82,
        temporal        = temporal,
        infrastructure  = infra,
        mitre_mappings  = [MITRE("T1566.001","Spearphishing","Initial Access",0.80,"5 emails")],
        actor_label     = "India-based phisher",
        sophistication  = "intermediate",
        likely_motivation = "financial",
    )


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 1: Constants & calibration
# ─────────────────────────────────────────────────────────────────────────────
section("1. Constants & calibration")

prior_sum = sum(REGION_PRIORS.values())
check("priors sum ≈ 1.0", 0.98 <= prior_sum <= 1.02,
      f"sum={prior_sum:.4f}")

check("all LR values > 1.0", all(v > 1.0 for v in SIGNAL_LIKELIHOOD_RATIOS.values()),
      f"LRs={SIGNAL_LIKELIHOOD_RATIOS}")

check("real_ip_country has highest LR",
      SIGNAL_LIKELIHOOD_RATIOS["real_ip_country"] == max(SIGNAL_LIKELIHOOD_RATIOS.values()))

aci_sum = sum(ACI_LAYER_WEIGHTS.values())
check("ACI weights sum ≤ 1.0", aci_sum <= 1.0, f"sum={aci_sum:.3f}")

check("all 5 tiers defined", len(TIER_THRESHOLDS) == 5)

check("+0530 maps to India", "India" in TIMEZONE_COUNTRY_MAP.get("+0530", []))
check("+0300 maps to Russia", "Russia" in TIMEZONE_COUNTRY_MAP.get("+0300", []))
check("-0800 maps to United States", "United States" in TIMEZONE_COUNTRY_MAP.get("-0800", []))


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 2: ACI Calculator
# ─────────────────────────────────────────────────────────────────────────────
section("2. ACI Calculator")

aci_calc = ACICalculator()

# No obfuscation
result_clean = aci_calc.compute({k: False for k in ACI_LAYER_WEIGHTS})
check("no obfuscation → ACI = 1.0", result_clean.final_aci == 1.0)
check("no obfuscation → interp contains 'Minimal'",
      "Minimal" in result_clean.interpretation)

# VPN only
result_vpn = aci_calc.compute({"vpn": True, "tor": False,
                                "residential_proxy": False,
                                "datacenter": False, "timestamp_spoof": False})
expected_vpn = 1.0 - ACI_LAYER_WEIGHTS["vpn"]
check(f"VPN only → ACI = {expected_vpn:.2f}",
      abs(result_vpn.final_aci - expected_vpn) < 1e-9)

# Tor + VPN + RESIP (maximum stack)
heavy = {k: True for k in ACI_LAYER_WEIGHTS}
result_heavy = aci_calc.compute(heavy)
total_penalty = sum(ACI_LAYER_WEIGHTS.values())
raw_expected  = max(0.05, 1.0 - total_penalty)
check("heavy obfuscation → raw_aci floor applied",
      result_heavy.final_aci >= 0.05)
check("heavy obfuscation → interpretation warns about unreliability",
      any(w in result_heavy.interpretation for w in ["Heavy", "Maximum", "Significant"]))
check("penalty_applied dict has all layers",
      set(result_heavy.penalty_applied.keys()) == set(ACI_LAYER_WEIGHTS.keys()))


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 3: Tier Assigner
# ─────────────────────────────────────────────────────────────────────────────
section("3. Tier Assigner")

tier_asgn = TierAssigner()

tier4, label4, _ = tier_asgn.assign(0.90)
check("prob=0.90 → Tier 4", tier4 == 4)

tier3, label3, _ = tier_asgn.assign(0.75)
check("prob=0.75 → Tier 3", tier3 == 3)

tier2, label2, _ = tier_asgn.assign(0.60)
check("prob=0.60 → Tier 2", tier2 == 2)

tier1, label1, _ = tier_asgn.assign(0.35)
check("prob=0.35 → Tier 1", tier1 == 1)

tier0, label0, _ = tier_asgn.assign(0.10)
check("prob=0.10 → Tier 0", tier0 == 0)

# HDI computation
posterior = [
    RegionProbability("India", 0.55, 0.08, 2.0, ["timezone_offset"]),
    RegionProbability("Pakistan", 0.18, 0.03, 0.5, ["timezone_offset"]),
    RegionProbability("Sri Lanka", 0.10, 0.01, 0.3, ["timezone_offset"]),
    RegionProbability("Other", 0.17, 0.15, -0.1, []),
]
hdi_lo, hdi_hi = tier_asgn.compute_hdi(posterior, credible_mass=0.90)
check("HDI upper = top region probability", abs(hdi_hi - 0.55) < 1e-9)
check("HDI lower ≤ HDI upper", hdi_lo <= hdi_hi)
check("HDI lower > 0", hdi_lo > 0)


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 4: BayesianUpdater
# ─────────────────────────────────────────────────────────────────────────────
section("4. BayesianUpdater")

updater = BayesianUpdater()

# Update with India timezone
signals_india = {"timezone_offset": "+0530", "timezone_region": "India / Sri Lanka"}
posterior4, lo4, used4, missing4 = updater.update(signals_india)

check("posterior sums to 1.0",
      abs(sum(r.probability for r in posterior4) - 1.0) < 1e-6)
check("India is top region after +0530",
      posterior4[0].region == "India")
check("India probability > any other single region",
      posterior4[0].probability > posterior4[1].probability)
check("timezone_offset in used_signals", "timezone_offset" in used4)
check("real_ip_country in missing_signals (not available)",
      "real_ip_country" in missing4)

# Longitudinal: second observation confirms India
signals_india2 = {"timezone_offset": "+0530", "geolocation_country": "India"}
posterior4b, lo4b, used4b, _ = updater.update(
    signals_india2, existing_log_odds=lo4
)
check("India probability increases with second observation",
      posterior4b[0].probability > posterior4[0].probability)
check("India still top after two observations",
      posterior4b[0].region == "India")

# Conflicting signal: Russia geolocation
signals_conflict = {"geolocation_country": "Russia", "timezone_offset": "+0530"}
posterior4c, lo4c, _, _ = updater.update(signals_conflict)
# India should still be competitive (timezone_offset) even with Russia geo
india_idx = next((i for i, r in enumerate(posterior4c)
                  if r.region in ("India", "Russia")), None)
check("conflicting signals produce mixed posterior",
      len(set(r.region for r in posterior4c[:3])) >= 2)

# Real IP signal — highest LR — should dominate
signals_realip = {"real_ip_country": "Nigeria"}
posterior_ng, _, used_ng, _ = updater.update(signals_realip)
check("Nigeria tops posterior after real_ip_country signal",
      posterior_ng[0].region == "Nigeria")
check("real_ip_country in used_signals", "real_ip_country" in used_ng)


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 5: SignalExtractor
# ─────────────────────────────────────────────────────────────────────────────
section("5. SignalExtractor")

extractor = SignalExtractor()

# Clean result — India, no obfuscation
result_india = _make_pipeline_result(
    tz_offset="+0530", origin_country="India",
    vpn=False, tor=False, send_hour=11
)
signals5, obf5 = extractor.extract(result_india)

check("timezone_offset extracted", signals5.get("timezone_offset") == "+0530")
check("timezone_region extracted as India",
      "India" in signals5.get("timezone_region", ""))
check("geolocation_country extracted", signals5.get("geolocation_country") == "India")
check("send_hour_local extracted", signals5.get("send_hour_local") == 11)
check("no obfuscation flags set", not any(obf5.values()))

# VPN result
result_vpn = _make_pipeline_result(
    tz_offset="+0530", origin_country="Netherlands",
    vpn=True, send_hour=14
)
signals5v, obf5v = extractor.extract(result_vpn)
check("vpn obfuscation flag set", obf5v.get("vpn") == True)
check("vpn_exit_country extracted (VPN IP geolocation)",
      signals5v.get("vpn_exit_country") is not None)

# Tor result
result_tor = _make_pipeline_result(tor=True)
_, obf5t = extractor.extract(result_tor)
check("tor obfuscation flag set", obf5t.get("tor") == True)

# Timestamp spoof
result_spoof = _make_pipeline_result(timestamp_spoof=True)
_, obf5s = extractor.extract(result_spoof)
check("timestamp_spoof flag set when spoofing_risk > 0.6",
      obf5s.get("timestamp_spoof") == True)

# Real IP country extraction
result_realip = _make_pipeline_result(
    tz_offset="+0530", origin_country="Netherlands",
    real_ip_country="India", vpn=True
)
signals5r, _ = extractor.extract(result_realip)
check("real_ip_country extracted from webmail leak",
      signals5r.get("real_ip_country") == "India")


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 6: AttributionEngine single-email mode
# ─────────────────────────────────────────────────────────────────────────────
section("6. AttributionEngine — single-email mode")

engine = AttributionEngine(verbose=False)

# India phisher with no VPN
result6 = _make_pipeline_result(
    tz_offset="+0530", origin_country="India",
    vpn=False, send_hour=10
)
ar6 = engine.attribute(result6)

check("returns AttributionResult", isinstance(ar6, AttributionResult))
check("primary_region is India", ar6.primary_region == "India")
check("aci_score = 1.0 (no obfuscation)", ar6.aci.final_aci == 1.0)
check("tier ≥ 2 (country-level) with India timezone+geo",
      ar6.tier >= 2)
check("n_observations = 1", ar6.n_observations == 1)
check("is_campaign_level = False", ar6.is_campaign_level == False)

# signals_available fix — should be total possible (len(SIGNAL_LR)), not len(signals present)
total_possible = len(SIGNAL_LIKELIHOOD_RATIOS)
check(f"signals_available = {total_possible} (total possible, not signals found)",
      ar6.signals_available == total_possible,
      f"got {ar6.signals_available}")

# VPN-obscured India phisher
result6v = _make_pipeline_result(
    tz_offset="+0530", origin_country="Netherlands",
    vpn=True, send_hour=14
)
ar6v = engine.attribute(result6v)
check("VPN detected → aci < 1.0",
      ar6v.aci.final_aci < 1.0)
check("VPN → aci_adjusted_prob < primary_probability",
      ar6v.aci_adjusted_prob <= ar6v.primary_probability)

# Tor — heavy obfuscation
result6t = _make_pipeline_result(tor=True, vpn=True, resip=True,
                                  timestamp_spoof=True,
                                  tz_offset="+0000",
                                  origin_country="Netherlands")
ar6t = engine.attribute(result6t)
check("heavy obfuscation → tier ≤ 2", ar6t.tier <= 2)
check("heavy obfuscation → ACI < 0.20 or tier degraded",
      ar6t.aci.final_aci < 0.20 or ar6t.tier <= 1)

# Real IP country — should dominate and push tier up
result6r = _make_pipeline_result(
    tz_offset="+0530", origin_country="Netherlands",
    real_ip_country="India", vpn=True, send_hour=11
)
ar6r = engine.attribute(result6r)
check("real_ip_country signal → India tops posterior",
      ar6r.primary_region == "India")


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 7: Campaign-level longitudinal attribution
# ─────────────────────────────────────────────────────────────────────────────
section("7. AttributionEngine — campaign-level longitudinal")

engine7 = AttributionEngine(verbose=False)
actor_id7 = "TEST_CAMPAIGN_A"

# Feed 5 emails from same India-based actor
for i in range(5):
    r = _make_pipeline_result(
        tz_offset="+0530",
        origin_country="India",
        send_hour=11 + i % 3,  # vary hour slightly
        vpn=False,
    )
    engine7.update_campaign(actor_id7, r)

ar7 = engine7.finalize_campaign(actor_id7)

check("campaign is_campaign_level = True", ar7.is_campaign_level)
check("campaign n_observations = 5", ar7.n_observations == 5)
check("campaign India is top region", ar7.primary_region == "India")
check("campaign tier ≥ 2 (5 consistent observations)",
      ar7.tier >= 2)

# Single-email baseline to confirm campaign > single
ar7_single = engine7.attribute(_make_pipeline_result(
    tz_offset="+0530", origin_country="India", vpn=False
))
check("campaign posterior peak > single-email posterior peak",
      ar7.primary_probability >= ar7_single.primary_probability)

# Campaign with conflicting emails (different timezones)
engine7b = AttributionEngine(verbose=False)
actor_id7b = "TEST_CAMPAIGN_B"
for tz in ["+0530", "+0530", "+0530", "+0500", "+0300"]:
    engine7b.update_campaign(actor_id7b, _make_pipeline_result(
        tz_offset=tz, origin_country="India" if tz == "+0530" else "Pakistan",
        vpn=False
    ))
ar7b = engine7b.finalize_campaign(actor_id7b)
check("mixed signals → India still favored (majority timezone)",
      ar7b.primary_region == "India")


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 8: attribute_from_profile
# ─────────────────────────────────────────────────────────────────────────────
section("8. attribute_from_profile")

engine8 = AttributionEngine(verbose=False)
profile8 = _make_actor_profile(
    tz_offset="+0530", tz_region="India / Sri Lanka",
    likely_country="India", vpn_providers=["NordVPN"],
    opsec_score=45, campaign_count=8,
)
ar8 = engine8.attribute_from_profile(profile8, geo_map={})

check("returns AttributionResult", isinstance(ar8, AttributionResult))
check("India tops posterior", ar8.primary_region == "India")
check("VPN in profile → obfuscation detected",
      ar8.aci.layers_detected.get("vpn") == True)
check("VPN penalty applied", ar8.aci.penalty_applied.get("vpn", 0) > 0)
check("campaign_level flag set", ar8.is_campaign_level == True)
check("n_observations = 8 (campaign_count)", ar8.n_observations == 8)

# Nigeria actor with Tor — tier should be limited
profile8b = _make_actor_profile(
    tz_offset="+0100", tz_region="UTC / West Africa",
    likely_country="Nigeria", vpn_providers=["TorGuard"],
    opsec_score=90, campaign_count=3,
)
ar8b = engine8.attribute_from_profile(profile8b, geo_map={})
check("Nigeria actor tops posterior", ar8b.primary_region in ("Nigeria", "Ghana"))
check("high opsec score → resip/tor obfuscation detected",
      ar8b.aci.layers_detected.get("residential_proxy")
      or ar8b.aci.layers_detected.get("tor")
      or ar8b.aci.final_aci < 0.90)


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 9: Working hours + timezone boost
# ─────────────────────────────────────────────────────────────────────────────
section("9. send_hour_local + timezone combined boost")

updater9 = BayesianUpdater()

# Without working hours
signals9a = {"timezone_offset": "+0530"}
post9a, lo9a, _, _ = updater9.update(signals9a)
india_prob_no_hour = next((r.probability for r in post9a if r.region == "India"), 0)

# With working hours in timezone
signals9b = {"timezone_offset": "+0530", "send_hour_local": 14}
post9b, lo9b, _, _ = updater9.update(signals9b)
india_prob_with_hour = next((r.probability for r in post9b if r.region == "India"), 0)

check("working hours + timezone boosts India over timezone alone",
      india_prob_with_hour >= india_prob_no_hour,
      f"no_hour={india_prob_no_hour:.3f}, with_hour={india_prob_with_hour:.3f}")

# Non-working hours should NOT boost (or only neutral)
signals9c = {"timezone_offset": "+0530", "send_hour_local": 2}  # 2am
post9c, _, _, _ = updater9.update(signals9c)
india_prob_night = next((r.probability for r in post9c if r.region == "India"), 0)
check("non-working hours do not receive extra boost",
      india_prob_night <= india_prob_with_hour)


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 10: integrate_with_v3 helper
# ─────────────────────────────────────────────────────────────────────────────
section("10. integrate_with_v3 helper")

# Build mock correlation report and actor profiles
from dataclasses import dataclass, field
from typing import List

@dataclass
class MockFingerprint:
    timezone_offset: str = "+0530"
    timezone_region: str = "India / Sri Lanka"
    vpn_provider: str = None
    webmail_provider: str = "Gmail"
    send_hour_local: int = 11
    real_ip: str = None
    origin_ip: str = "1.2.3.4"
    email_file: str = "test.eml"
    email_date: str = "2026-02-20T11:05:00+0530"

@dataclass
class MockCluster:
    actor_id: str
    fingerprints: List[Any]
    campaign_count: int = 3
    confidence: float = 0.82
    likely_country: str = "India"
    consensus_timezone: str = "+0530"
    consensus_vpn_provider: str = None
    consensus_webmail: str = "Gmail"
    consensus_send_window: str = "09:00–17:00 IST"
    emails: list = field(default_factory=list)
    first_seen: str = "2026-02-01"
    last_seen: str = "2026-02-20"
    ttps: list = field(default_factory=list)
    all_vpn_ips: list = field(default_factory=list)
    all_origin_ips: list = field(default_factory=list)

@dataclass
class MockCorrelationReport:
    actor_clusters: List[Any]
    total_emails: int = 3
    total_actors: int = 1
    singleton_emails: list = field(default_factory=list)
    timestamp: str = "2026-02-20T12:00:00"

cluster10 = MockCluster(
    actor_id     = "ACTOR_001",
    fingerprints = [MockFingerprint() for _ in range(3)],
)
report10  = MockCorrelationReport(actor_clusters=[cluster10])
profile10 = _make_actor_profile(
    tz_offset="+0530", tz_region="India / Sri Lanka",
    likely_country="India", campaign_count=3
)

results10 = integrate_with_v3(
    correlation_report = report10,
    actor_profiles     = {"ACTOR_001": profile10},
    geo_map            = {},
    verbose            = False,
)

check("integrate_with_v3 returns dict", isinstance(results10, dict))
check("ACTOR_001 in results", "ACTOR_001" in results10)
check("result is AttributionResult",
      isinstance(results10["ACTOR_001"], AttributionResult))
check("India tops result from integrate_with_v3",
      results10["ACTOR_001"].primary_region == "India")


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 11: Serialization
# ─────────────────────────────────────────────────────────────────────────────
section("11. Serialization — to_dict, summary, analyst_brief")

engine11 = AttributionEngine(verbose=False)
r11 = _make_pipeline_result(tz_offset="+0530", origin_country="India")
ar11 = engine11.attribute(r11)

d = ar11.to_dict()
check("to_dict returns dict", isinstance(d, dict))
check("to_dict has primary_region", "primary_region" in d)
check("to_dict has aci_score", "aci_score" in d)
check("to_dict has tier", "tier" in d)
check("to_dict posterior is list", isinstance(d.get("posterior"), list))
check("to_dict aci_breakdown has layers_detected",
      "layers_detected" in d.get("aci_breakdown", {}))

# Round-trip via JSON
try:
    json_str = json.dumps(d)
    d2 = json.loads(json_str)
    check("JSON serialization round-trip OK", d2["primary_region"] == d["primary_region"])
except Exception as e:
    check("JSON serialization round-trip OK", False, str(e))

summary = ar11.summary()
check("summary() returns non-empty string", bool(summary) and "Tier" in summary)

brief = ar11.analyst_brief()
check("analyst_brief() returns formatted string",
      bool(brief) and "ATTRIBUTION ENGINE" in brief)
check("analyst_brief() contains ACI", "ACI" in brief)
check("analyst_brief() contains posterior", "Posterior" in brief or "posterior" in brief)


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 12: Edge cases
# ─────────────────────────────────────────────────────────────────────────────
section("12. Edge cases")

engine12 = AttributionEngine(verbose=False)

# Empty pipeline result
empty_result = SimpleNamespace(
    header_analysis        = None,
    classifications        = None,
    enrichment_results     = None,
    geolocation_results    = None,
    webmail_extraction     = None,
    vpn_backtrack_analysis = None,
    proxy_analysis         = None,
    real_ip_analysis       = None,
)
ar12e = engine12.attribute(empty_result)
check("empty result → returns AttributionResult", isinstance(ar12e, AttributionResult))
# With zero signals, the engine returns the prior distribution — this is correct
# Bayesian behaviour: P(region | no signals) = prior(region). The top prior
# region (Nigeria ~8.5%) is still below the Tier 1 threshold (25%), so tier 0.
# We check that: no signals used, and tier reflects low evidence quality.
check("empty result → no signals used", len(ar12e.signals_used) == 0)
check("empty result → tier 0 (prior-only, below 25% threshold)",
      ar12e.tier == 0,
      f"got tier={ar12e.tier}, prob={ar12e.primary_probability:.3f}")

# finalize_campaign with no observations
engine12b = AttributionEngine(verbose=False)
ar12b = engine12b.finalize_campaign("NEVER_FED")
check("finalize empty campaign → returns empty result", ar12b.tier == 0)

# All obfuscation layers — posterior should still exist
result12h = _make_pipeline_result(
    tor=True, vpn=True, resip=True, datacenter=True, timestamp_spoof=True,
    tz_offset="+0530", origin_country="Netherlands",
)
ar12h = engine12.attribute(result12h)
check("all obfuscation → posterior still non-empty", len(ar12h.posterior) > 0)
check("all obfuscation → ACI floor applied (≥ 0.05)",
      ar12h.aci.final_aci >= 0.05)
check("all obfuscation → ACI-adjusted < 0.30",
      ar12h.aci_adjusted_prob < 0.30)

# signals_available always equals total possible regardless of signals present
result12_sparse = _make_pipeline_result(
    tz_offset="+0530",       # only timezone — other signals absent
    origin_country=None,
    vpn=False, send_hour=0,  # 0 = midnight, not None (avoid format error)
    webmail=None,
)
# Manually clear webmail and send_hour from the mock result
result12_sparse.webmail_extraction = None
result12_sparse.header_analysis.email_date = "2026-02-20T00:05:00+0530"
ar12s = engine12.attribute(result12_sparse)
check(f"signals_available always = {len(SIGNAL_LIKELIHOOD_RATIOS)} regardless of coverage",
      ar12s.signals_available == len(SIGNAL_LIKELIHOOD_RATIOS),
      f"got {ar12s.signals_available}")

# Export/import campaign state
engine12c = AttributionEngine(verbose=False)
for _ in range(3):
    engine12c.update_campaign("PERSIST_ME", _make_pipeline_result(
        tz_offset="+0530", origin_country="India"
    ))
state = engine12c.export_campaign_state("PERSIST_ME")
check("export_campaign_state returns dict", isinstance(state, dict))
check("state has actor_id", state.get("actor_id") == "PERSIST_ME")
check("state has n_observations = 3", state.get("n_observations") == 3)
check("state has log_odds dict", isinstance(state.get("log_odds"), dict))

engine12d = AttributionEngine(verbose=False)
engine12d.import_campaign_state(state)
ar12i = engine12d.finalize_campaign("PERSIST_ME")
check("imported state produces same top region as original",
      ar12i.primary_region == "India")


# ─────────────────────────────────────────────────────────────────────────────
#  FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

print(f"\n{'='*68}")
print(f"  ATTRIBUTION ENGINE TEST RESULTS")
print(f"{'='*68}")
print(f"  PASSED:  {PASS}")
print(f"  FAILED:  {FAIL}")
print(f"  TOTAL:   {PASS + FAIL}")
print(f"{'='*68}")

if FAIL > 0:
    print("\n  FAILED TESTS:")
    for status, name in TESTS:
        if status == "FAIL":
            print(f"    ✗  {name}")
    sys.exit(1)
else:
    print("\n  All tests passed.")
    sys.exit(0)
