#!/usr/bin/env python3
"""
HunterTrace — Phase 1 Evaluation Harness
==========================================
Runs the real Bayesian attribution engine (engine.py) against the
synthetic dataset produced by dataset_generator.py.

No live network calls. No pipeline dependencies.
Signals are parsed directly from each sample's `planted_signals` labels
and injected into AttributionEngine._compute_result(), bypassing all
pipeline stages that require live IP lookups.

Outputs
-------
  console  — per-scenario accuracy table + top-level metrics
  eval_results.json — full per-sample results for offline analysis

Usage
-----
  python eval_harness.py                          # runs on dataset.json
  python eval_harness.py --dataset my_data.json
  python eval_harness.py --out results.json
  python eval_harness.py --limit 500              # quick smoke test
  python eval_harness.py --scenario vpn_masked    # one scenario only
  python eval_harness.py --verbose                # show engine debug output
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Engine import ─────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, "/mnt/project")


try:
    from huntertrace.attribution.engine import (
        AttributionEngine,
        ACI_LAYER_WEIGHTS,
        REGION_PRIORS,
        TIMEZONE_COUNTRY_MAP,
    )
except ImportError as e:
    print(f"[FATAL] Cannot import huntertrace.attribution.engine: {e}")
    print("  Make sure PYTHONPATH includes the project root and huntertrace is a package.")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
#  SIGNAL PARSER
#  Translates planted_signals strings → (signals dict, obfuscation dict)
#  that engine._compute_result() can consume directly.
# ─────────────────────────────────────────────────────────────────────────────

# Map obfuscation_type strings from the dataset to the ACI layer flags
# the engine uses in ACI_LAYER_WEIGHTS
OBFUSCATION_FLAGS: Dict[str, Dict[str, bool]] = {
    # ── Phase 1: Synthetic baseline scenarios ────────────────────────────
    "clean_smtp":     {"tor": False, "vpn": False, "residential_proxy": False,
                       "datacenter": False, "timestamp_spoof": False},
    "vpn_masked":     {"tor": False, "vpn": True,  "residential_proxy": False,
                       "datacenter": True,  "timestamp_spoof": False},
    "webmail":        {"tor": False, "vpn": False, "residential_proxy": False,
                       "datacenter": False, "timestamp_spoof": False},
    "proxy_chain":    {"tor": False, "vpn": False, "residential_proxy": False,
                       "datacenter": True,  "timestamp_spoof": False},
    "header_forgery": {"tor": False, "vpn": False, "residential_proxy": False,
                       "datacenter": False, "timestamp_spoof": True},
    "tz_spoofing":    {"tor": False, "vpn": False, "residential_proxy": False,
                       "datacenter": False, "timestamp_spoof": True},
    "tor_exit":       {"tor": True,  "vpn": False, "residential_proxy": False,
                       "datacenter": False, "timestamp_spoof": False},
    "residential_proxy": {"tor": False, "vpn": False, "residential_proxy": True,
                          "datacenter": False, "timestamp_spoof": False},
    # ── Phase 2: Adversarial scenarios ───────────────────────────────────
    "multihop_vpn":          {"tor": False, "vpn": True,  "residential_proxy": False,
                              "datacenter": True,  "timestamp_spoof": False},
    "compromised_relay":     {"tor": False, "vpn": False, "residential_proxy": False,
                              "datacenter": False, "timestamp_spoof": False},
    "false_flag_infra":      {"tor": False, "vpn": True,  "residential_proxy": False,
                              "datacenter": False, "timestamp_spoof": False},
    "charset_normalization": {"tor": False, "vpn": True,  "residential_proxy": False,
                              "datacenter": True,  "timestamp_spoof": False},
    "ipv6_leak":             {"tor": False, "vpn": True,  "residential_proxy": False,
                              "datacenter": True,  "timestamp_spoof": False},
    "dns_false_flag":        {"tor": False, "vpn": False, "residential_proxy": False,
                              "datacenter": False, "timestamp_spoof": False},
    "send_hour_manipulation":{"tor": False, "vpn": False, "residential_proxy": False,
                              "datacenter": False, "timestamp_spoof": False},
}

# Planted signal prefixes that map 1-to-1 to engine signal keys
DIRECT_SIGNAL_MAP = {
    "geolocation_country",
    "isp_country",
    "real_ip_country",
    "vpn_exit_country",
    "timezone_offset",
    "timezone_region",
    "webmail_provider",
    "send_hour_local",
    "charset_region",
    "ipv6_country",
    "dns_infra_country",
}

# Prefixes that provide metadata but are NOT engine signals (skip them)
METADATA_PREFIXES = {
    "vpn_provider",        # not a direct signal key (engine reads via obfuscation flag)
    "hop_pattern",         # used for hop count, not Bayesian signal
    "timestamp_regression",# label metadata
    "apparent_country",    # describes the spoofed timezone's implied country
    "tz_spoof",            # metadata describing the spoof direction
    # Adversarial metadata
    "vpn_chain",           # list metadata, not a signal
    "relay_host",          # metadata
    "decoy_countries",     # metadata
}


def parse_planted_signals(
    planted: List[str],
    obfuscation_type: str,
) -> Tuple[Dict[str, Any], Dict[str, bool]]:
    """
    Parse a sample's planted_signals list into:
      signals      — dict keyed by engine signal names
      obfuscation  — dict of ACI layer booleans

    The tz_spoofing scenario plants the SPOOFED timezone as timezone_offset
    (because that's what the Date: header says) but also plants
    geolocation_country from the real X-Originating-IP.  The engine handles
    this correctly because geolocation_country has LR=12 vs timezone_offset
    LR=6 — the real IP signal outweighs the spoofed timezone.
    """
    signals: Dict[str, Any] = {}
    obfuscation = dict(OBFUSCATION_FLAGS.get(
        obfuscation_type,
        {k: False for k in ACI_LAYER_WEIGHTS}
    ))

    for entry in planted:
        if ":" not in entry:
            continue
        key, _, raw_val = entry.partition(":")
        val = raw_val.strip()

        if key in METADATA_PREFIXES:
            continue  # not an engine signal

        if key in DIRECT_SIGNAL_MAP:
            # send_hour_local must be int
            if key == "send_hour_local":
                try:
                    signals[key] = int(val)
                except ValueError:
                    pass
            else:
                signals[key] = val

        # timezone_region — derive from timezone_offset if not explicitly planted
    tz_off = signals.get("timezone_offset")
    if tz_off and "timezone_region" not in signals:
        TZ_REGION_MAP = {
            "+0000": "UTC / West Africa",
            "+0100": "Central Europe / West Africa",
            "+0200": "Eastern Europe / South Africa",
            "+0300": "Russia (Moscow) / East Africa",
            "+0330": "Iran",
            "+0500": "Pakistan / Central Asia",
            "+0530": "India / Sri Lanka",
            "+0700": "Southeast Asia",
            "+0800": "China / Southeast Asia",
            "-0300": "Brazil / Argentina",
            "-0400": "Venezuela / Chile",
            "-0500": "US Eastern / South America",
            "-0600": "US Central / Mexico",
            "-0700": "US Mountain",
            "-0800": "US Pacific",
        }
        region = TZ_REGION_MAP.get(tz_off)
        if region:
            signals["timezone_region"] = region

    return signals, obfuscation


# ─────────────────────────────────────────────────────────────────────────────
#  RESULT STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SampleResult:
    email_id:              str
    scenario:              str
    true_country:          str
    predicted_country:     str
    correct_country:       bool
    aci_adjusted_prob:     float
    tier:                  int
    tier_label:            str
    expected_tier_floor:   int
    tier_met:              bool          # predicted tier >= expected_tier_floor
    signals_used:          List[str]
    obfuscation_type:      str
    false_flag_warning:    bool
    reliability_mode:      str
    aci_score:             float
    top3:                  List[Tuple[str, float]]   # top 3 (region, prob) pairs

    def to_dict(self) -> dict:
        return {
            "email_id":            self.email_id,
            "scenario":            self.scenario,
            "true_country":        self.true_country,
            "predicted_country":   self.predicted_country,
            "correct_country":     self.correct_country,
            "aci_adjusted_prob":   round(self.aci_adjusted_prob, 4),
            "tier":                self.tier,
            "tier_label":          self.tier_label,
            "expected_tier_floor": self.expected_tier_floor,
            "tier_met":            self.tier_met,
            "signals_used":        self.signals_used,
            "obfuscation_type":    self.obfuscation_type,
            "false_flag_warning":  self.false_flag_warning,
            "reliability_mode":    self.reliability_mode,
            "aci_score":           round(self.aci_score, 4),
            "top3":                [(r, round(p, 4)) for r, p in self.top3],
        }


@dataclass
class ScenarioMetrics:
    scenario:           str
    n:                  int = 0
    correct:            int = 0
    tier_met_count:     int = 0
    false_flags:        int = 0
    avg_prob:           float = 0.0
    avg_aci:            float = 0.0
    avg_signals:        float = 0.0
    country_confusion:  Dict[str, int] = field(default_factory=dict)  # predicted→count when wrong

    @property
    def accuracy(self) -> float:
        return self.correct / self.n if self.n else 0.0

    @property
    def tier_rate(self) -> float:
        return self.tier_met_count / self.n if self.n else 0.0


# ─────────────────────────────────────────────────────────────────────────────
#  HARNESS
# ─────────────────────────────────────────────────────────────────────────────

class EvalHarness:
    """
    Runs AttributionEngine._compute_result() on every dataset sample and
    aggregates accuracy metrics per scenario, per country, and overall.
    """

    def __init__(self, verbose: bool = False):
        self.engine  = AttributionEngine(verbose=verbose)
        self.verbose = verbose

    def run_sample(self, sample: dict) -> SampleResult:
        labels   = sample["labels"]
        email_id = sample["email_id"]
        obf_type = labels["obfuscation_type"]
        true_c   = labels["true_origin_country"]
        tier_fl  = labels.get("expected_tier_floor", 1)
        planted  = labels.get("planted_signals", [])

        signals, obfuscation = parse_planted_signals(planted, obf_type)

        result = self.engine._compute_result(
            signals        = signals,
            obfuscation    = obfuscation,
            log_odds_seed  = None,
            n_obs          = 1,
            is_campaign    = False,
        )

        top3 = [(rp.region, rp.probability)
                for rp in result.posterior[:3]]

        correct = (result.primary_region == true_c)
        tier_ok = (result.tier >= tier_fl)

        return SampleResult(
            email_id            = email_id,
            scenario            = obf_type,
            true_country        = true_c,
            predicted_country   = result.primary_region,
            correct_country     = correct,
            aci_adjusted_prob   = result.aci_adjusted_prob,
            tier                = result.tier,
            tier_label          = result.tier_label,
            expected_tier_floor = tier_fl,
            tier_met            = tier_ok,
            signals_used        = result.signals_used,
            obfuscation_type    = obf_type,
            false_flag_warning  = result.false_flag_warning,
            reliability_mode    = result.reliability_mode,
            aci_score           = result.aci.final_aci,
            top3                = top3,
        )

    def run(
        self,
        samples:          List[dict],
        scenario_filter:  Optional[str] = None,
        limit:            Optional[int] = None,
    ) -> Tuple[List[SampleResult], Dict[str, ScenarioMetrics]]:

        if scenario_filter:
            samples = [s for s in samples
                       if s["labels"]["obfuscation_type"] == scenario_filter]
        if limit:
            samples = samples[:limit]

        results: List[SampleResult]             = []
        metrics: Dict[str, ScenarioMetrics]     = {}
        per_country: Dict[str, Dict[str, int]]  = defaultdict(lambda: defaultdict(int))

        n_total = len(samples)
        t0      = time.time()

        for i, sample in enumerate(samples):
            if i > 0 and i % 1000 == 0:
                elapsed = time.time() - t0
                rate    = i / elapsed
                eta     = (n_total - i) / rate if rate > 0 else 0
                print(f"  [{i:>6}/{n_total}]  "
                      f"elapsed={elapsed:.1f}s  "
                      f"eta={eta:.0f}s  "
                      f"rate={rate:.0f}/s",
                      end="\r", flush=True)

            sr = self.run_sample(sample)
            results.append(sr)

            scen = sr.scenario
            if scen not in metrics:
                metrics[scen] = ScenarioMetrics(scenario=scen)
            m = metrics[scen]
            m.n          += 1
            m.correct    += int(sr.correct_country)
            m.tier_met_count += int(sr.tier_met)
            m.false_flags += int(sr.false_flag_warning)
            m.avg_prob   += sr.aci_adjusted_prob
            m.avg_aci    += sr.aci_score
            m.avg_signals += len(sr.signals_used)

            if not sr.correct_country:
                pred = sr.predicted_country
                m.country_confusion[pred] = m.country_confusion.get(pred, 0) + 1

            per_country[sr.true_country]["total"]   += 1
            per_country[sr.true_country]["correct"] += int(sr.correct_country)

        # Finalise averages
        for m in metrics.values():
            if m.n:
                m.avg_prob    /= m.n
                m.avg_aci     /= m.n
                m.avg_signals /= m.n

        elapsed = time.time() - t0
        if n_total >= 1000:
            print(f"  [{n_total:>6}/{n_total}]  "
                  f"elapsed={elapsed:.1f}s  "
                  f"rate={n_total/elapsed:.0f}/s   ")

        return results, metrics, per_country


# ─────────────────────────────────────────────────────────────────────────────
#  REPORT PRINTER
# ─────────────────────────────────────────────────────────────────────────────

TIER_LABELS = {0: "Unknown", 1: "Region", 2: "Country", 3: "City", 4: "ISP"}

def print_report(
    results:     List[SampleResult],
    metrics:     Dict[str, ScenarioMetrics],
    per_country: Dict[str, Dict[str, int]],
    dataset_path: str,
    elapsed:     float,
):
    W = 72
    print()
    print("=" * W)
    print("  HUNTЕРТRACE — PHASE 1 BASELINE ACCURACY REPORT")
    print("=" * W)
    print(f"  Dataset : {dataset_path}")
    print(f"  Samples : {len(results)}")
    print(f"  Runtime : {elapsed:.2f}s  ({len(results)/elapsed:.0f} samples/s)")
    print()

    # ── Overall ───────────────────────────────────────────────────────────────
    total   = len(results)
    correct = sum(1 for r in results if r.correct_country)
    tier_ok = sum(1 for r in results if r.tier_met)
    ff_warn = sum(1 for r in results if r.false_flag_warning)
    avg_prob = sum(r.aci_adjusted_prob for r in results) / total if total else 0
    avg_sigs = sum(len(r.signals_used) for r in results) / total if total else 0

    tier_dist = defaultdict(int)
    for r in results:
        tier_dist[r.tier] += 1

    print(f"  OVERALL ACCURACY")
    print(f"  {'─'*40}")
    print(f"  Country correct     : {correct:>6} / {total:<6}  "
          f"({correct/total*100:.1f}%)")
    print(f"  Tier floor met      : {tier_ok:>6} / {total:<6}  "
          f"({tier_ok/total*100:.1f}%)")
    print(f"  Avg ACI-adj prob    : {avg_prob:.4f}")
    print(f"  Avg signals used    : {avg_sigs:.2f}")
    print(f"  False-flag warnings : {ff_warn:>6} / {total:<6}  "
          f"({ff_warn/total*100:.1f}%)")
    print()
    print(f"  Tier distribution:")
    for t in sorted(tier_dist.keys()):
        n   = tier_dist[t]
        bar = "█" * int(n / total * 40)
        print(f"    Tier {t} ({TIER_LABELS[t]:<8}) : {n:>6}  "
              f"({n/total*100:5.1f}%)  {bar}")

    # ── Per-scenario table ────────────────────────────────────────────────────
    print()
    print(f"  {'─'*68}")
    print(f"  {'SCENARIO':<22}  {'N':>6}  {'ACC%':>6}  {'TIER%':>6}  "
          f"{'AvgProb':>8}  {'AvgACI':>7}  {'AvgSig':>7}  {'FF%':>5}")
    print(f"  {'─'*68}")

    scenario_order = [
        # Phase 1 — synthetic baseline
        "clean_smtp", "vpn_masked", "webmail", "proxy_chain",
        "header_forgery", "tz_spoofing", "tor_exit",
        # Phase 2 — adversarial
        "multihop_vpn", "residential_proxy", "compromised_relay",
        "false_flag_infra", "charset_normalization", "ipv6_leak",
        "dns_false_flag", "send_hour_manipulation",
    ]
    for scen in scenario_order:
        m = metrics.get(scen)
        if not m:
            continue
        acc     = m.accuracy * 100
        tier_r  = m.tier_rate * 100
        ff_r    = (m.false_flags / m.n * 100) if m.n else 0
        print(f"  {scen:<22}  {m.n:>6}  {acc:>6.1f}  {tier_r:>6.1f}  "
              f"{m.avg_prob:>8.4f}  {m.avg_aci:>7.4f}  "
              f"{m.avg_signals:>7.2f}  {ff_r:>5.1f}")

    print(f"  {'─'*68}")
    total_acc  = correct / total * 100 if total else 0
    total_tier = tier_ok / total * 100 if total else 0
    print(f"  {'ALL SCENARIOS':<22}  {total:>6}  {total_acc:>6.1f}  "
          f"{total_tier:>6.1f}  {avg_prob:>8.4f}  "
          f"{'─':>7}  {avg_sigs:>7.2f}  "
          f"{ff_warn/total*100:>5.1f}")

    # ── Per-country accuracy ──────────────────────────────────────────────────
    print()
    print(f"  {'─'*48}")
    print(f"  {'PER-COUNTRY ACCURACY':<24}  {'Total':>6}  {'Correct':>8}  {'Acc%':>6}")
    print(f"  {'─'*48}")

    sorted_countries = sorted(
        per_country.items(),
        key=lambda x: x[1].get("total", 0),
        reverse=True,
    )
    for country, cnts in sorted_countries:
        n_c   = cnts.get("total", 0)
        n_ok  = cnts.get("correct", 0)
        acc_c = (n_ok / n_c * 100) if n_c else 0
        flag  = "  ✓" if acc_c >= 90 else ("  ~" if acc_c >= 60 else "  ✗")
        print(f"  {country:<24}  {n_c:>6}  {n_ok:>8}  {acc_c:>6.1f}{flag}")

    # ── Failure analysis ──────────────────────────────────────────────────────
    print()
    print(f"  {'─'*60}")
    print(f"  FAILURE ANALYSIS  (where wrong, what was predicted?)")
    print(f"  {'─'*60}")

    for scen in scenario_order:
        m = metrics.get(scen)
        if not m or not m.country_confusion:
            continue
        top_errors = sorted(m.country_confusion.items(),
                            key=lambda x: -x[1])[:3]
        errors_str = "  ".join(f"{c}({n})" for c, n in top_errors)
        wrong_n    = m.n - m.correct
        print(f"  {scen:<22}  {wrong_n:>4} wrong  →  {errors_str}")

    # ── Signal coverage ───────────────────────────────────────────────────────
    print()
    print(f"  {'─'*52}")
    print(f"  SIGNAL COVERAGE  (how often each signal type fired)")
    print(f"  {'─'*52}")

    sig_counts: Dict[str, int] = defaultdict(int)
    for r in results:
        for sig in r.signals_used:
            sig_counts[sig] += 1

    for sig, cnt in sorted(sig_counts.items(), key=lambda x: -x[1]):
        bar = "█" * int(cnt / total * 30)
        print(f"  {sig:<28} {cnt:>6}  ({cnt/total*100:5.1f}%)  {bar}")

    # ── Accuracy by tier ─────────────────────────────────────────────────────
    print()
    print(f"  {'─'*48}")
    print(f"  ACCURACY WITHIN EACH TIER (confidence calibration check)")
    print(f"  {'─'*48}")

    tier_correct: Dict[int, list] = defaultdict(list)
    for r in results:
        tier_correct[r.tier].append(int(r.correct_country))

    for t in sorted(tier_correct.keys()):
        data = tier_correct[t]
        acc  = sum(data) / len(data) * 100 if data else 0
        print(f"  Tier {t} ({TIER_LABELS.get(t,'?'):<8})  "
              f"n={len(data):>5}  acc={acc:>6.1f}%  "
              f"{'✓ well-calibrated' if (t==0 and acc<50) or (t>=2 and acc>=70) else '~ review'}")

    print()
    print("=" * W)
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HunterTrace Phase 1 evaluation harness"
    )
    parser.add_argument("--dataset",  default="dataset.json",
                        help="Input dataset JSON (default: dataset.json)")
    parser.add_argument("--out",      default="eval_results.json",
                        help="Output results JSON (default: eval_results.json)")
    parser.add_argument("--scenario", default=None,
                        help="Run only this scenario type")
    parser.add_argument("--limit",    type=int, default=None,
                        help="Cap sample count (for quick smoke test)")
    parser.add_argument("--verbose",  action="store_true",
                        help="Show engine debug output per sample")
    parser.add_argument("--no-save",  action="store_true",
                        help="Skip writing eval_results.json")
    args = parser.parse_args()

    # ── Load dataset ──────────────────────────────────────────────────────────
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"[ERROR] Dataset not found: {dataset_path}")
        print("  Run: python dataset_generator.py --output dataset.json")
        sys.exit(1)

    with open(dataset_path) as f:
        samples = json.load(f)

    print(f"[harness] Loaded {len(samples)} samples from {dataset_path}")
    if args.scenario:
        before = len(samples)
        samples = [s for s in samples
                   if s["labels"]["obfuscation_type"] == args.scenario]
        print(f"[harness] Filtered to scenario '{args.scenario}': "
              f"{before} → {len(samples)}")
    if args.limit:
        samples = samples[:args.limit]
        print(f"[harness] Limited to {len(samples)} samples")

    # ── Run ───────────────────────────────────────────────────────────────────
    harness = EvalHarness(verbose=args.verbose)
    print(f"[harness] Running attribution engine on {len(samples)} samples...")

    t0 = time.time()
    results, metrics, per_country = harness.run(samples)
    elapsed = time.time() - t0

    # ── Print report ──────────────────────────────────────────────────────────
    print_report(results, metrics, per_country, str(dataset_path), elapsed)

    # ── Save results ──────────────────────────────────────────────────────────
    if not args.no_save:
        out_data = {
            "meta": {
                "dataset":    str(dataset_path),
                "n_samples":  len(results),
                "elapsed_s":  round(elapsed, 3),
                "rate_per_s": round(len(results) / elapsed, 1) if elapsed else 0,
                "scenario_filter": args.scenario,
            },
            "overall": {
                "country_accuracy":   round(
                    sum(1 for r in results if r.correct_country) / len(results), 4
                ) if results else 0,
                "tier_floor_rate":    round(
                    sum(1 for r in results if r.tier_met) / len(results), 4
                ) if results else 0,
            },
            "per_scenario": {
                scen: {
                    "n":           m.n,
                    "accuracy":    round(m.accuracy, 4),
                    "tier_rate":   round(m.tier_rate, 4),
                    "avg_prob":    round(m.avg_prob, 4),
                    "avg_aci":     round(m.avg_aci, 4),
                    "avg_signals": round(m.avg_signals, 3),
                    "false_flag_rate": round(m.false_flags / m.n, 4) if m.n else 0,
                    "top_errors":  sorted(m.country_confusion.items(),
                                          key=lambda x: -x[1])[:5],
                }
                for scen, m in metrics.items()
            },
            "per_country": {
                c: {
                    "n":        cnts.get("total", 0),
                    "correct":  cnts.get("correct", 0),
                    "accuracy": round(cnts["correct"] / cnts["total"], 4)
                    if cnts.get("total") else 0,
                }
                for c, cnts in per_country.items()
            },
            "samples": [r.to_dict() for r in results],
        }
        with open(args.out, "w") as f:
            json.dump(out_data, f, indent=2)
        print(f"[harness] Full results saved → {args.out}")


if __name__ == "__main__":
    main()
