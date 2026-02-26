#!/usr/bin/env python3
"""
HUNTЕРТRACE v3 — MITRE MAPPER & V3 ORCHESTRATOR
=================================================

Two things in one file:

1. MitreMapper
   Auto-generates a structured MITRE ATT&CK Navigator layer JSON from
   all ActorTTPProfiles in a campaign run. Drop it into MITRE Navigator
   (https://mitre-attack.github.io/attack-navigator/) for a visual
   kill-chain map.

2. HunterTraceV3
   The v3 orchestrator. Wraps the existing CompletePipeline (v1/v2)
   and adds the full v3 campaign intelligence layer on top.

   In single-email mode:  runs pipeline → extracts fingerprint → stores
   In batch mode:         runs all emails → correlates → profiles → graphs
   In report mode:        loads saved JSON reports → offline correlation

USAGE:
    # Full v3 batch run
    from hunterTraceV3 import HunterTraceV3

    v3 = HunterTraceV3(verbose=True)
    v3.run_batch("/path/to/emails/")

    # Load existing JSON reports and correlate offline
    v3.correlate_from_json_dir("/path/to/reports/")
"""

import json
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK NAVIGATOR LAYER GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

# Full technique metadata for the techniques HunterTrace can observe
MITRE_TECHNIQUES = {
    "T1566":     {"name": "Phishing",                        "tactic": "initial-access"},
    "T1566.001": {"name": "Spearphishing Link",              "tactic": "initial-access"},
    "T1566.002": {"name": "Spearphishing Attachment",        "tactic": "initial-access"},
    "T1566.003": {"name": "Spearphishing via Service",       "tactic": "initial-access"},
    "T1090":     {"name": "Proxy",                           "tactic": "command-and-control"},
    "T1090.001": {"name": "Internal Proxy",                  "tactic": "command-and-control"},
    "T1090.002": {"name": "External Proxy",                  "tactic": "command-and-control"},
    "T1090.003": {"name": "Multi-hop Proxy",                 "tactic": "command-and-control"},
    "T1036":     {"name": "Masquerading",                    "tactic": "defense-evasion"},
    "T1036.005": {"name": "Match Legitimate Name or Location","tactic": "defense-evasion"},
    "T1078":     {"name": "Valid Accounts",                  "tactic": "persistence"},
    "T1078.004": {"name": "Cloud Accounts",                  "tactic": "persistence"},
    "T1589":     {"name": "Gather Victim Identity Info",     "tactic": "reconnaissance"},
    "T1589.001": {"name": "Credentials",                     "tactic": "reconnaissance"},
    "T1589.002": {"name": "Email Addresses",                 "tactic": "reconnaissance"},
    "T1204":     {"name": "User Execution",                  "tactic": "execution"},
    "T1204.001": {"name": "Malicious Link",                  "tactic": "execution"},
    "T1598":     {"name": "Phishing for Information",        "tactic": "reconnaissance"},
    "T1114":     {"name": "Email Collection",                "tactic": "collection"},
    "T1071":     {"name": "Application Layer Protocol",      "tactic": "command-and-control"},
    "T1071.003": {"name": "Mail Protocols",                  "tactic": "command-and-control"},
}

# Tactic display order (ATT&CK kill chain order)
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact"
]

# Confidence → Navigator score (0–100)
CONFIDENCE_TO_SCORE = {
    (0.9, 1.0): 100,
    (0.7, 0.9): 75,
    (0.5, 0.7): 50,
    (0.0, 0.5): 25,
}


class MitreMapper:
    """
    Generates MITRE ATT&CK Navigator layer JSON from actor profiles.

    Output can be loaded directly into:
      https://mitre-attack.github.io/attack-navigator/
    """

    def generate_layer(
        self,
        actor_profiles: List,       # List[ActorTTPProfile]
        layer_name: str = "HunterTrace v3 — Campaign Analysis",
        description: str = ""
    ) -> dict:
        """Generate a Navigator layer dict from all actor profiles."""

        techniques_seen: Dict[str, Dict] = {}   # tid → aggregated data

        for prof in actor_profiles:
            for mapping in prof.mitre_mappings:
                tid = mapping.technique_id
                if tid not in techniques_seen:
                    techniques_seen[tid] = {
                        "techniqueID": tid,
                        "score":       0,
                        "comment":     "",
                        "actors":      [],
                        "color":       "",
                        "enabled":     True,
                        "showSubtechniques": True,
                    }
                # Aggregate score (highest confidence wins)
                score = self._confidence_to_score(mapping.confidence)
                if score > techniques_seen[tid]["score"]:
                    techniques_seen[tid]["score"] = score
                # Append actor + evidence comment
                techniques_seen[tid]["actors"].append(prof.actor_id)
                comment_line = f"[{prof.actor_id}] {mapping.evidence}"
                if comment_line not in techniques_seen[tid]["comment"]:
                    techniques_seen[tid]["comment"] += comment_line + "\n"

        # Set colours by score
        for tid, data in techniques_seen.items():
            data["color"] = self._score_to_color(data["score"])

        # Build Navigator layer
        layer = {
            "name":        layer_name,
            "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain":      "enterprise-attack",
            "description": description or f"Generated by HunterTrace v3 on {datetime.now().strftime('%Y-%m-%d')}",
            "filters":     {"platforms": ["Linux", "Windows", "macOS", "Network", "PRE"]},
            "sorting":     0,
            "layout":      {"layout": "side", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques":  list(techniques_seen.values()),
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Observed (high conf)",   "color": "#E63946"},
                {"label": "Observed (medium conf)",  "color": "#F4A261"},
                {"label": "Observed (low conf)",     "color": "#E9C46A"},
            ],
            "metadata":    [],
            "links":       [],
            "showTacticRowBackground": True,
            "tacticRowBackground":     "#1d3557",
        }

        return layer

    def export_layer(self, actor_profiles: List, output_path: str,
                     layer_name: str = "HunterTrace v3") -> str:
        layer = self.generate_layer(actor_profiles, layer_name)
        Path(output_path).write_text(json.dumps(layer, indent=2))
        return output_path

    def print_summary(self, actor_profiles: List):
        """Print a text summary of all observed MITRE techniques."""
        all_mappings = []
        for prof in actor_profiles:
            for m in prof.mitre_mappings:
                all_mappings.append((m.technique_id, m.technique_name,
                                     m.tactic, m.confidence, prof.actor_id))

        # Deduplicate by tid
        seen = {}
        for tid, name, tactic, conf, actor in all_mappings:
            if tid not in seen or conf > seen[tid][2]:
                seen[tid] = (name, tactic, conf, actor)

        print("\n[v3] MITRE ATT&CK Coverage")
        print("=" * 70)
        print(f"  {'ID':<14} {'Tactic':<22} {'Technique':<35} Conf")
        print("  " + "-" * 68)

        # Sort by tactic order
        def tactic_key(item):
            t = item[1][1]
            return TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99

        for tid, (name, tactic, conf, actor) in sorted(seen.items(), key=tactic_key):
            print(f"  {tid:<14} {tactic:<22} {name:<35} {conf:.0%}")
        print("=" * 70)

    def _confidence_to_score(self, conf: float) -> int:
        for (lo, hi), score in CONFIDENCE_TO_SCORE.items():
            if lo <= conf <= hi:
                return score
        return 25

    def _score_to_color(self, score: int) -> str:
        if score >= 75:
            return "#E63946"
        elif score >= 50:
            return "#F4A261"
        else:
            return "#E9C46A"


# ─────────────────────────────────────────────────────────────────────────────
# V3 ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class HunterTraceV3:
    """
    v3 Orchestrator — wraps CompletePipeline + adds full campaign intelligence.

    Modes:
      run_batch(mail_dir)       — process .eml files + full v3 correlation
      correlate_from_json_dir() — offline correlation from saved JSON reports
      add_result(file, result)  — manual ingestion for custom pipelines
    """

    def __init__(self, verbose: bool = False, skip_enrichment: bool = False,
                 output_dir: str = "."):
        self.verbose        = verbose
        self.skip_enrichment= skip_enrichment
        self.output_dir     = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Import v3 modules
        try:
            from campaignCorrelator import CampaignCorrelator
            self.correlator = CampaignCorrelator(verbose=verbose)
        except ImportError as e:
            raise RuntimeError(f"campaignCorrelator.py not found: {e}")

        try:
            from actorProfiler import ActorProfiler
            self.profiler = ActorProfiler()
        except ImportError as e:
            raise RuntimeError(f"actorProfiler.py not found: {e}")

        try:
            from attackGraphBuilder import AttackGraphBuilder
            self.graph_builder = AttackGraphBuilder()
        except ImportError as e:
            raise RuntimeError(f"attackGraphBuilder.py not found: {e}")

        self.mitre_mapper = MitreMapper()

        # Import v1/v2 pipeline (optional — not needed for offline mode)
        self._pipeline_class = None
        try:
            # Try to import from same directory
            _orig_path = sys.path.copy()
            sys.path.insert(0, str(Path(__file__).parent))
            from hunterTrace import CompletePipeline
            self._pipeline_class = CompletePipeline
            sys.path = _orig_path
        except ImportError:
            if verbose:
                print("[v3] hunterTrace.py not found — offline-only mode")

        # State
        self._results:  Dict[str, Any] = {}   # file → CompletePipelineResult
        self._report:   Any = None
        self._profiles: Dict[str, Any] = {}   # actor_id → ActorTTPProfile
        self._graph:    Any = None

    # ─────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────

    def run_batch(self, mail_dir: str) -> "V3Report":
        """
        Full v3 batch run:
          1. Process each .eml via CompletePipeline (v1+v2)
          2. Ingest into correlator
          3. Correlate → actor clusters
          4. Profile each actor
          5. Build attack graph
          6. Generate MITRE layer
          7. Write all outputs
        """
        mail_path = Path(mail_dir)
        eml_files = sorted(mail_path.glob("*.eml"))

        if not eml_files:
            print(f"[v3] No .eml files found in {mail_dir}")
            return None

        if not self._pipeline_class:
            print("[v3] ERROR: hunterTrace.py required for batch run")
            return None

        print(f"\n{'='*70}")
        print(f"  HUNTЕРТRACE v3 — BATCH CAMPAIGN ANALYSIS")
        print(f"  Processing {len(eml_files)} email(s)")
        print(f"{'='*70}\n")

        pipeline = self._pipeline_class(
            verbose=self.verbose,
            skip_enrichment=self.skip_enrichment,
        )

        for i, eml_file in enumerate(eml_files, 1):
            print(f"\n[{i}/{len(eml_files)}] {eml_file.name}")
            print("-" * 50)
            try:
                result = pipeline.run(str(eml_file))
                if result:
                    self._results[eml_file.name] = result
                    self.correlator.ingest(eml_file.name, result)
                    print(f"  ✓ Ingested into v3 correlator")
                else:
                    print(f"  ✗ Pipeline returned no result")
            except Exception as e:
                print(f"  ✗ Failed: {e}")
                if self.verbose:
                    import traceback; traceback.print_exc()

        return self._run_v3_analysis()

    def correlate_from_json_dir(self, json_dir: str) -> "V3Report":
        """
        Offline correlation — ingest saved hunterTrace JSON reports.
        No .eml files or pipeline run needed.
        """
        json_path = Path(json_dir)
        json_files = sorted(json_path.glob("*.json"))

        if not json_files:
            print(f"[v3] No .json files found in {json_dir}")
            return None

        print(f"\n[v3] Offline correlation from {len(json_files)} JSON report(s)")

        for jf in json_files:
            try:
                with open(jf) as f:
                    report = json.load(f)
                fp = self.correlator.ingest_json(jf.stem, report)
                if fp:
                    print(f"  ✓ {jf.name}  tz={fp.timezone_offset}  "
                          f"vpn={fp.vpn_provider}")
            except Exception as e:
                print(f"  ✗ {jf.name}: {e}")

        return self._run_v3_analysis()

    def add_result(self, email_file: str, pipeline_result) -> None:
        """Manually add a single pipeline result (for custom pipeline wrappers)."""
        self._results[email_file] = pipeline_result
        self.correlator.ingest(email_file, pipeline_result)

    # ─────────────────────────────────────────────────────────────────────
    # INTERNAL
    # ─────────────────────────────────────────────────────────────────────

    def _run_v3_analysis(self) -> "V3Report":
        """Run correlation → profiling → graph → MITRE after ingestion."""

        # Step 1: Correlate
        print(f"\n{'='*70}")
        print("  [v3 STEP 1] Campaign Correlation")
        print(f"{'='*70}")
        self._report = self.correlator.correlate()
        print(self._report.summary())

        # Step 2: Profile each actor
        print(f"\n{'='*70}")
        print("  [v3 STEP 2] Actor Profiling")
        print(f"{'='*70}")
        for cluster in self._report.actor_clusters:
            profile = self.profiler.build(cluster)
            self._profiles[cluster.actor_id] = profile
            print(profile.analyst_brief())

        # Step 3: Build attack graph
        print(f"\n{'='*70}")
        print("  [v3 STEP 3] Attack Graph")
        print(f"{'='*70}")
        self._graph = self.graph_builder.build(self._report, self._profiles)
        self.graph_builder.print_stats(self._graph)

        # Step 4: MITRE mapping
        print(f"\n{'='*70}")
        print("  [v3 STEP 4] MITRE ATT&CK Mapping")
        print(f"{'='*70}")
        self.mitre_mapper.print_summary(list(self._profiles.values()))

        # Step 5: Write outputs
        self._write_outputs()

        report = V3Report(
            correlation   = self._report,
            actor_profiles= self._profiles,
            attack_graph  = self._graph,
            output_dir    = str(self.output_dir),
        )

        print(f"\n{'='*70}")
        print(f"  [v3] ALL OUTPUTS WRITTEN TO: {self.output_dir}/")
        print(f"{'='*70}\n")

        return report

    def _write_outputs(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # 1. Correlation JSON
        corr_path = self.output_dir / f"v3_correlation_{ts}.json"
        corr_data = {
            "timestamp":       self._report.timestamp,
            "total_emails":    self._report.total_emails,
            "total_actors":    self._report.total_actors,
            "singleton_emails":self._report.singleton_emails,
            "actor_clusters": [
                {
                    "actor_id":           c.actor_id,
                    "emails":             c.emails,
                    "confidence":         c.confidence,
                    "likely_country":     c.likely_country,
                    "consensus_timezone": c.consensus_timezone,
                    "consensus_vpn":      c.consensus_vpn_provider,
                    "consensus_webmail":  c.consensus_webmail,
                    "send_window":        c.consensus_send_window,
                    "first_seen":         c.first_seen,
                    "last_seen":          c.last_seen,
                    "ttps":               c.ttps,
                    "all_vpn_ips":        c.all_vpn_ips,
                    "all_origin_ips":     c.all_origin_ips,
                }
                for c in self._report.actor_clusters
            ],
        }
        corr_path.write_text(json.dumps(corr_data, indent=2))
        print(f"  → Correlation:  {corr_path.name}")

        # 2. Actor profiles JSON
        if self._profiles:
            prof_path = self.output_dir / f"v3_actor_profiles_{ts}.json"
            prof_data = {
                actor_id: prof.to_dict()
                for actor_id, prof in self._profiles.items()
            }
            prof_path.write_text(json.dumps(prof_data, indent=2))
            print(f"  → Profiles:     {prof_path.name}")

            # 3. MITRE Navigator layer
            mitre_path = self.output_dir / f"v3_mitre_layer_{ts}.json"
            self.mitre_mapper.export_layer(
                list(self._profiles.values()),
                str(mitre_path),
                f"HunterTrace v3 — {self._report.total_emails} email(s), "
                f"{self._report.total_actors} actor(s)"
            )
            print(f"  → MITRE layer:  {mitre_path.name}")

        # 4. Attack graph HTML
        if self._graph:
            graph_path = self.output_dir / f"v3_attack_graph_{ts}.html"
            self.graph_builder.export_html(self._graph, str(graph_path))
            print(f"  → Graph HTML:   {graph_path.name}  (open in browser)")

            # 5. Graph JSON
            graph_json_path = self.output_dir / f"v3_attack_graph_{ts}.json"
            self.graph_builder.export_json(self._graph, str(graph_json_path))
            print(f"  → Graph JSON:   {graph_json_path.name}")

            # 6. GraphML (Gephi/Maltego)
            if hasattr(self._graph, 'nx_graph') and self._graph.nx_graph:
                try:
                    gml_path = self.output_dir / f"v3_attack_graph_{ts}.graphml"
                    self.graph_builder.export_graphml(self._graph, str(gml_path))
                    print(f"  → GraphML:      {gml_path.name}  (Gephi/Maltego)")
                except Exception:
                    pass


# ─────────────────────────────────────────────────────────────────────────────
# V3 REPORT CONTAINER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class V3Report:
    """Container for all v3 outputs."""
    correlation:    Any     # CorrelationReport
    actor_profiles: Dict    # actor_id → ActorTTPProfile
    attack_graph:   Any     # AttackGraph
    output_dir:     str

    def print_executive_summary(self):
        c = self.correlation
        print("\n" + "=" * 70)
        print("  HUNTЕРТRACE v3 — EXECUTIVE SUMMARY")
        print("=" * 70)
        print(f"  Emails analysed:       {c.total_emails}")
        print(f"  Distinct threat actors:{c.total_actors}")
        print(f"  Unattributed emails:   {len(c.singleton_emails)}")
        print()
        for actor_id, prof in self.actor_profiles.items():
            print(f"  [{actor_id}] {prof.actor_label}")
            print(f"    Campaigns:  {prof.campaign_count}")
            print(f"    Confidence: {prof.confidence:.0%}")
            print(f"    Motivation: {prof.likely_motivation}")
            print(f"    OpSec:      {prof.infrastructure.opsec_label} "
                  f"({prof.infrastructure.opsec_score}/100)")
            if prof.temporal.likely_country:
                print(f"    Country:    {prof.temporal.likely_country}")
            print(f"    MITRE:      "
                  f"{', '.join(m.technique_id for m in prof.mitre_mappings)}")
            print()
        print(f"  Outputs saved to: {self.output_dir}/")
        print("=" * 70)


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="HunterTrace v3 — Campaign Correlation & Actor Profiling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MODES:
  Batch (process .eml files):
    python hunterTraceV3.py batch /path/to/emails/ --output ./v3_reports/

  Offline (correlate from saved JSON reports):
    python hunterTraceV3.py offline /path/to/json_reports/ --output ./v3_reports/

OUTPUTS (written to --output directory):
  v3_correlation_<ts>.json     — Actor clusters + signal matches
  v3_actor_profiles_<ts>.json  — Full TTP profiles per actor
  v3_mitre_layer_<ts>.json     — MITRE Navigator layer (drag into navigator)
  v3_attack_graph_<ts>.html    — Interactive D3.js graph (open in browser)
  v3_attack_graph_<ts>.graphml — Gephi / Maltego import
        """
    )
    parser.add_argument("mode", choices=["batch", "offline"],
                        help="Run mode")
    parser.add_argument("path", help="Email directory (batch) or JSON dir (offline)")
    parser.add_argument("--output", default="./v3_output",
                        help="Output directory (default: ./v3_output)")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--skip-enrichment", action="store_true",
                        help="Skip WHOIS enrichment (faster)")

    args = parser.parse_args()

    v3 = HunterTraceV3(
        verbose         = args.verbose,
        skip_enrichment = args.skip_enrichment,
        output_dir      = args.output,
    )

    if args.mode == "batch":
        report = v3.run_batch(args.path)
    else:
        report = v3.correlate_from_json_dir(args.path)

    if report:
        report.print_executive_summary()
