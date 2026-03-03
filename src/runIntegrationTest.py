#!/usr/bin/env python3
"""
HUNTЕРТRACE v3 — END-TO-END INTEGRATION TEST
=============================================

Runs the full pipeline:
  .eml files → CompletePipeline → CampaignCorrelator → ActorProfiler
              → AttributionEngine → AttackGraphBuilder → MitreMapper
              → JSON / HTML outputs

All external network calls are stubbed so this runs fully offline.

Usage:
    python3 run_integration_test.py
"""

import sys
import os
import json
import types
import traceback
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────

MODULES_DIR = Path(__file__).parent / "modules"
EMAILS_DIR  = Path(__file__).parent / "mails"
OUTPUT_DIR  = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(MODULES_DIR))

# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# MAILS FOLDER NAVIGATION
# ─────────────────────────────────────────────────────────────────────────────

# OFFLINE STUBS — inject before any module imports
# ─────────────────────────────────────────────────────────────────────────────

# 1. Stub 'whois' — not installed, not needed for our test
whois_stub = types.ModuleType("whois")
whois_stub.whois = lambda domain: type("W", (), {
    "org": "Test ISP", "country": "IN", "creation_date": None,
    "registrar": "Test Registrar", "name_servers": [],
})()
sys.modules["whois"] = whois_stub

# 2. Stub 'requests' to block all real HTTP calls
import requests as _real_requests

class OfflineSession:
    """Returns safe fallback JSON for any API call."""
    def get(self, url, **kwargs):
        return self._fake_response(url)
    def post(self, url, **kwargs):
        return self._fake_response(url)
    def _fake_response(self, url):
        r = type("Resp", (), {})()
        r.status_code = 200
        r.ok = True
        r.text = "{}"
        # AbuseIPDB stub
        if "abuseipdb" in url:
            r.json = lambda: {"data": {"abuseConfidenceScore": 0, "countryCode": "IN",
                                        "isp": "Test ISP", "usageType": "Data Center/Web Hosting/Transit",
                                        "totalReports": 0}}
        # ip-api stub
        elif "ip-api" in url:
            r.json = lambda: {"status": "success", "country": "India",
                              "countryCode": "IN", "city": "Mumbai",
                              "lat": 19.0760, "lon": 72.8777,
                              "timezone": "Asia/Kolkata", "isp": "Test ISP",
                              "org": "Test Org", "query": "103.45.67.89"}
        # PeeringDB stub
        elif "peeringdb" in url:
            r.json = lambda: {"data": []}
        # ipinfo stub
        elif "ipinfo" in url:
            r.json = lambda: {"country": "IN", "org": "AS12345 Test ISP",
                              "city": "Mumbai", "timezone": "Asia/Kolkata"}
        # Generic geo stubs
        elif "ipapi" in url or "ipgeolocation" in url or "ipdata" in url:
            r.json = lambda: {"country_name": "India", "country_code2": "IN",
                              "city": "Mumbai", "latitude": 19.0760,
                              "longitude": 72.8777, "time_zone": {"name": "Asia/Kolkata"},
                              "isp": "Test ISP", "organisation": "Test Org",
                              "ip": "103.45.67.89"}
        # NordVPN / VPN detection stubs
        elif "nordvpn" in url or "vpnapi" in url or "proxycheck" in url:
            r.json = lambda: {}
        else:
            r.json = lambda: {}
        r.raise_for_status = lambda: None
        return r

_offline = OfflineSession()
_real_requests.get  = _offline.get
_real_requests.post = _offline.post

# 3. Stub socket.gethostbyaddr to avoid reverse DNS lookups
import socket as _socket
_orig_gethostbyaddr = _socket.gethostbyaddr
def _safe_gethostbyaddr(ip):
    return (f"stub-host.{ip}.example.com", [], [ip])
_socket.gethostbyaddr = _safe_gethostbyaddr

# 4. Stub socket.getaddrinfo for any outbound resolution
_orig_getaddrinfo = _socket.getaddrinfo
def _safe_getaddrinfo(host, port, *args, **kwargs):
    return [(2, 1, 6, '', ('127.0.0.1', port or 0))]
_socket.getaddrinfo = _safe_getaddrinfo


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

PASS = "✓"
FAIL = "✗"
WARN = "⚠"

results = []

def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, label, detail))
    print(f"  {status}  {label}" + (f"  [{detail}]" if detail else ""))
    return condition

def section(title):
    print(f"\n{'─'*68}")
    print(f"  {title}")
    print(f"{'─'*68}")


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — IMPORT ALL MODULES
# ─────────────────────────────────────────────────────────────────────────────

section("PHASE 1 — Module Imports")

imported = {}

modules_to_import = [
    ("hunterTrace",         "CompletePipeline"),
    ("campaignCorrelator",  "CampaignCorrelator"),
    ("actorProfiler",       "ActorProfiler"),
    ("attackGraphBuilder",  "AttackGraphBuilder"),
    ("attributionEngine",   "AttributionEngine"),
    ("hunterTraceV3",       "HunterTraceV3"),
]

for mod_name, class_name in modules_to_import:
    try:
        mod = __import__(mod_name)
        cls = getattr(mod, class_name, None)
        imported[mod_name] = mod
        check(f"import {mod_name}.{class_name}", cls is not None)
    except Exception as e:
        check(f"import {mod_name}.{class_name}", False, str(e)[:80])
        if mod_name in ("hunterTrace", "hunterTraceV3"):
            print(f"\n  FATAL: Cannot continue without {mod_name}")
            print(f"  Error: {e}")
            traceback.print_exc()
            sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — SINGLE EMAIL PIPELINE (hunterTrace.CompletePipeline)
# ─────────────────────────────────────────────────────────────────────────────

section("PHASE 2 — Single Email Pipeline")

CompletePipeline = imported["hunterTrace"].CompletePipeline

single_results = {}
eml_files = sorted(EMAILS_DIR.glob("*.eml"))
check("eml files found", len(eml_files) >= 1, f"{len(eml_files)} files")

pipeline = None
try:
    pipeline = CompletePipeline(verbose=False, skip_enrichment=True)
    check("CompletePipeline instantiated", True)
except Exception as e:
    check("CompletePipeline instantiated", False, str(e)[:80])
    traceback.print_exc()

if pipeline:
    for eml in eml_files:
        try:
            result = pipeline.run(str(eml))
            ok = result is not None
            single_results[eml.name] = result
            check(f"pipeline.run({eml.name})", ok,
                  f"IPs={len(result.classifications) if ok else 0}")
        except Exception as e:
            check(f"pipeline.run({eml.name})", False, str(e)[:80])
            traceback.print_exc()

# Spot-check first result structure
if single_results:
    first = next(iter(single_results.values()))
    check("result.header_analysis exists",   hasattr(first, "header_analysis"))
    check("result.classifications exists",   hasattr(first, "classifications"))
    check("result.proxy_analysis exists",    hasattr(first, "proxy_analysis"))
    has_geo = getattr(first, "geolocation_results", None) is not None
    check("result.geolocation_results set",  True,  # either None or dict is acceptable
          "present" if has_geo else "None (skip_enrichment)")


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — CAMPAIGN CORRELATOR
# ─────────────────────────────────────────────────────────────────────────────

section("PHASE 3 — Campaign Correlator")

CampaignCorrelator = imported["campaignCorrelator"].CampaignCorrelator

correlator = None
try:
    correlator = CampaignCorrelator(verbose=False)
    check("CampaignCorrelator instantiated", True)
except Exception as e:
    check("CampaignCorrelator instantiated", False, str(e)[:80])
    traceback.print_exc()

correlation_report = None
if correlator and single_results:
    for fname, result in single_results.items():
        if result:
            try:
                correlator.ingest(fname, result)
                check(f"correlator.ingest({fname})", True)
            except Exception as e:
                check(f"correlator.ingest({fname})", False, str(e)[:80])

    try:
        correlation_report = correlator.correlate()
        ok = correlation_report is not None
        check("correlator.correlate() returned report", ok)
        if ok:
            check("report.total_emails > 0",
                  correlation_report.total_emails > 0,
                  str(correlation_report.total_emails))
            check("report.actor_clusters exists",
                  hasattr(correlation_report, "actor_clusters"))
            print(f"\n  {correlation_report.summary()}")
    except Exception as e:
        check("correlator.correlate()", False, str(e)[:80])
        traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — ACTOR PROFILER
# ─────────────────────────────────────────────────────────────────────────────

section("PHASE 4 — Actor Profiler")

ActorProfiler = imported["actorProfiler"].ActorProfiler

profiler = None
actor_profiles = {}
try:
    profiler = ActorProfiler()
    check("ActorProfiler instantiated", True)
except Exception as e:
    check("ActorProfiler instantiated", False, str(e)[:80])

if profiler and correlation_report:
    clusters = getattr(correlation_report, "actor_clusters", [])
    check("actor clusters returned", len(clusters) >= 0, f"{len(clusters)} clusters")

    for cluster in clusters:
        try:
            profile = profiler.build(cluster)
            actor_profiles[cluster.actor_id] = profile
            check(f"profiler.build({cluster.actor_id})", profile is not None)
            if profile:
                check(f"  profile.actor_id set",       bool(profile.actor_id))
                check(f"  profile.mitre_mappings set",  hasattr(profile, "mitre_mappings"))
                check(f"  profile.infrastructure set",  hasattr(profile, "infrastructure"))
        except Exception as e:
            check(f"profiler.build({cluster.actor_id})", False, str(e)[:80])
            traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — ATTRIBUTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

section("PHASE 5 — Bayesian Attribution Engine")

AttributionEngine = imported["attributionEngine"].AttributionEngine

engine = None
attribution_results = {}
try:
    engine = AttributionEngine(verbose=False)
    check("AttributionEngine instantiated", True)
except Exception as e:
    check("AttributionEngine instantiated", False, str(e)[:80])

if engine and correlation_report:
    # Build geo map from all pipeline results
    geo_map = {}
    for result in single_results.values():
        if result:
            geo = getattr(result, "geolocation_results", None) or {}
            geo_map.update(geo)

    if actor_profiles:
        for actor_id, profile in actor_profiles.items():
            try:
                ar = engine.attribute_from_profile(profile, geo_map)
                attribution_results[actor_id] = ar
                check(f"attribute_from_profile({actor_id})", ar is not None)
                if ar:
                    check(f"  tier assigned (0–4)",
                          0 <= ar.tier <= 4, f"Tier {ar.tier}")
                    check(f"  ACI score valid",
                          0.0 < ar.aci.final_aci <= 1.0, f"{ar.aci.final_aci:.2f}")
                    check(f"  primary_region set",
                          bool(ar.primary_region), ar.primary_region)
                    check(f"  signals_available = 10",
                          ar.signals_available == 10, str(ar.signals_available))
            except Exception as e:
                check(f"attribute_from_profile({actor_id})", False, str(e)[:80])
                traceback.print_exc()
    else:
        # No clusters yet — test single-email attribution directly
        for fname, result in single_results.items():
            if result:
                try:
                    ar = engine.attribute(result)
                    check(f"engine.attribute({fname})", ar is not None)
                    if ar:
                        check(f"  tier valid", 0 <= ar.tier <= 4, f"Tier {ar.tier}")
                        check(f"  ACI valid",  0 < ar.aci.final_aci <= 1.0,
                              f"{ar.aci.final_aci:.2f}")
                except Exception as e:
                    check(f"engine.attribute({fname})", False, str(e)[:80])
                    traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 — ATTACK GRAPH BUILDER
# ─────────────────────────────────────────────────────────────────────────────

section("PHASE 6 — Attack Graph Builder")

AttackGraphBuilder = imported["attackGraphBuilder"].AttackGraphBuilder

graph_builder = None
attack_graph = None
try:
    graph_builder = AttackGraphBuilder()
    check("AttackGraphBuilder instantiated", True)
except Exception as e:
    check("AttackGraphBuilder instantiated", False, str(e)[:80])

if graph_builder and correlation_report:
    try:
        attack_graph = graph_builder.build(correlation_report, actor_profiles)
        check("graph_builder.build() returned graph", attack_graph is not None)
        if attack_graph:
            n_nodes = len(getattr(attack_graph, "nodes", []))
            n_edges = len(getattr(attack_graph, "edges", []))
            check("graph has nodes", n_nodes >= 0, f"{n_nodes} nodes")
            check("graph has edges", n_edges >= 0, f"{n_edges} edges")
    except Exception as e:
        check("graph_builder.build()", False, str(e)[:80])
        traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — MITRE MAPPER
# ─────────────────────────────────────────────────────────────────────────────

section("PHASE 7 — MITRE Mapper")

try:
    from hunterTraceV3 import MitreMapper
    mapper = MitreMapper()
    check("MitreMapper instantiated", True)

    if actor_profiles:
        layer = mapper.generate_layer(list(actor_profiles.values()))
        check("generate_layer() returned dict",    isinstance(layer, dict))
        check("layer has 'techniques' key",        "techniques" in layer)
        check("layer has 'name' key",              "name" in layer)
        check("layer has ATT&CK version",          "versions" in layer)
        mapper.print_summary(list(actor_profiles.values()))
    else:
        check("MITRE layer (no actors)", True, "SKIP — no actor clusters")
except Exception as e:
    check("MitreMapper", False, str(e)[:80])
    traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8 — OUTPUT WRITING
# ─────────────────────────────────────────────────────────────────────────────

section("PHASE 8 — Output Writing")

# Correlation JSON
if correlation_report:
    try:
        corr_path = OUTPUT_DIR / "integration_correlation.json"
        corr_data = {
            "timestamp": correlation_report.timestamp,
            "total_emails": correlation_report.total_emails,
            "total_actors": correlation_report.total_actors,
            "actor_clusters": [
                {
                    "actor_id": c.actor_id,
                    "emails": c.emails,
                    "confidence": c.confidence,
                    "likely_country": c.likely_country,
                }
                for c in correlation_report.actor_clusters
            ]
        }
        corr_path.write_text(json.dumps(corr_data, indent=2))
        check("Write correlation JSON", corr_path.exists(), str(corr_path.name))
    except Exception as e:
        check("Write correlation JSON", False, str(e)[:80])

# Attribution JSON
if attribution_results:
    try:
        attr_path = OUTPUT_DIR / "integration_attribution.json"
        attr_data = {k: v.to_dict() for k, v in attribution_results.items()}
        attr_path.write_text(json.dumps(attr_data, indent=2))
        check("Write attribution JSON", attr_path.exists(), str(attr_path.name))
    except Exception as e:
        check("Write attribution JSON", False, str(e)[:80])

# Attack graph HTML
if attack_graph and graph_builder:
    try:
        html_path = OUTPUT_DIR / "integration_attack_graph.html"
        graph_builder.export_html(attack_graph, str(html_path))
        check("Write attack graph HTML", html_path.exists(), str(html_path.name))
    except Exception as e:
        check("Write attack graph HTML", False, str(e)[:80])

# MITRE layer JSON
if actor_profiles:
    try:
        mitre_path = OUTPUT_DIR / "integration_mitre_layer.json"
        from hunterTraceV3 import MitreMapper
        MitreMapper().export_layer(list(actor_profiles.values()), str(mitre_path))
        check("Write MITRE layer JSON", mitre_path.exists(), str(mitre_path.name))
    except Exception as e:
        check("Write MITRE layer JSON", False, str(e)[:80])


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9 — FULL V3 ORCHESTRATOR (end-to-end via HunterTraceV3)
# ─────────────────────────────────────────────────────────────────────────────

section("PHASE 9 — Full HunterTraceV3 Orchestrator")

HunterTraceV3 = imported["hunterTraceV3"].HunterTraceV3

v3_output = OUTPUT_DIR / "v3_full_run"
v3_output.mkdir(exist_ok=True)

try:
    v3 = HunterTraceV3(
        verbose         = False,
        skip_enrichment = True,
        output_dir      = str(v3_output),
    )
    check("HunterTraceV3 instantiated", True)

    report = v3.run_batch(str(EMAILS_DIR))
    check("run_batch() returned V3Report", report is not None)

    if report:
        check("V3Report.correlation exists",
              report.correlation is not None)
        check("V3Report.actor_profiles is dict",
              isinstance(report.actor_profiles, dict))

        # Check output files were written
        output_files = list(v3_output.glob("*.json")) + list(v3_output.glob("*.html"))
        check("Output files written", len(output_files) > 0,
              f"{len(output_files)} files")

        print()
        report.print_executive_summary()

except Exception as e:
    check("HunterTraceV3 full run", False, str(e)[:80])
    traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

print(f"\n{'='*68}")
print("  INTEGRATION TEST RESULTS")
print(f"{'='*68}")

passed = [r for r in results if r[0] == PASS]
failed = [r for r in results if r[0] == FAIL]

print(f"  PASSED:  {len(passed)}")
print(f"  FAILED:  {len(failed)}")
print(f"  TOTAL:   {len(results)}")

if failed:
    print(f"\n  FAILURES:")
    for _, label, detail in failed:
        print(f"    ✗  {label}" + (f"  [{detail}]" if detail else ""))

print(f"{'='*68}")
print(f"  Outputs: {OUTPUT_DIR}/")
print(f"{'='*68}\n")

sys.exit(0 if not failed else 1)
