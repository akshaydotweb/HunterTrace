#!/usr/bin/env python3
"""
HunterTrace — Evaluation Runner v3
=====================================
Run from src/:
    python runEval.py
    python runEval.py --auto-corpus --target 150
    python runEval.py --corpus ../mails/corpus.json --no-ablation
"""

import os, sys, argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 0 — Load .env BEFORE any hunterTrace import
#  Root cause of avg_confidence=0.0: IPClassifierLight reads
#  os.getenv("ABUSEIPDB_API_KEY") at __init__ time. If env isn't set
#  before CompletePipeline() is constructed, AbuseIPDB is never called.
# ─────────────────────────────────────────────────────────────────────────────

def _load_env() -> dict:
    here = Path(__file__).parent
    loaded = {}
    for directory in [here, here.parent, here.parent.parent]:
        env_file = directory / ".env"
        if not env_file.exists():
            continue
        print(f"[runEval] .env → {env_file.resolve()}")
        for raw in env_file.read_text(errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if val and key in ("ABUSEIPDB_API_KEY", "IPINFO_TOKEN",
                               "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY"):
                os.environ[key] = val
                loaded[key] = val[:8] + "…"
        break

    print("[runEval] API keys:")
    for k in ("ABUSEIPDB_API_KEY", "IPINFO_TOKEN", "VIRUSTOTAL_API_KEY"):
        v = os.environ.get(k)
        print(f"  {'✓' if v else '✗'}  {k}: {v[:8]+'…' if v else 'NOT SET'}")
    print()
    return loaded


_loaded_keys = _load_env()   # must run before imports below

from huntertrace.core.pipeline import CompletePipeline
from huntertrace.evaluation.dataset import DatasetLoader, BatchEvaluator
from huntertrace.evaluation.framework import EvaluationFramework


# ─────────────────────────────────────────────────────────────────────────────
#  PIPELINE — instantiated AFTER env is loaded
# ─────────────────────────────────────────────────────────────────────────────

pipeline = CompletePipeline(verbose=False)

def run_pipeline(eml_path: str):
    return pipeline.run(eml_path)


# ─────────────────────────────────────────────────────────────────────────────
#  COUNTRY EXTRACTOR  — fixed to always return ISO-3166 alpha-2
#
#  Bug fixed: geolocation sets .country = "United States" (full name)
#  but corpus ground truth uses .country = "US" (ISO code).
#  extract_country() now always returns country_code, never the full name.
#
#  Priority:
#    1. bayesian_attribution.primary_region  → ISO code via reverse lookup
#    2. attribution_analysis fields          → ISO code
#    3. geolocation_results[*].country_code  → ISO code directly ← KEY FIX
# ─────────────────────────────────────────────────────────────────────────────

# Full-name → ISO-2 lookup (covers common geolocation return values)
_NAME_TO_ISO = {
    "nigeria":"NG","india":"IN","russia":"RU","china":"CN","united states":"US",
    "romania":"RO","brazil":"BR","ukraine":"UA","south africa":"ZA","ghana":"GH",
    "pakistan":"PK","indonesia":"ID","vietnam":"VN","philippines":"PH","turkey":"TR",
    "iran":"IR","bulgaria":"BG","north korea":"KP","belarus":"BY","germany":"DE",
    "france":"FR","united kingdom":"GB","netherlands":"NL","poland":"PL","kenya":"KE",
    "egypt":"EG","morocco":"MA","thailand":"TH","malaysia":"MY","singapore":"SG",
    "bangladesh":"BD","australia":"AU","canada":"CA","mexico":"MX","argentina":"AR",
    "saudi arabia":"SA","united arab emirates":"AE","israel":"IL","japan":"JP",
    "south korea":"KR","spain":"ES","italy":"IT","sweden":"SE","norway":"NO",
    "finland":"FI","czech republic":"CZ","hungary":"HU","austria":"AT",
    "ethiopia":"ET","tanzania":"TZ","senegal":"SN","cameroon":"CM",
    "colombia":"CO","chile":"CL","peru":"PE","venezuela":"VE",
    "iraq":"IQ","afghanistan":"AF","myanmar":"MM","cambodia":"KH","laos":"LA",
    "taiwan":"TW","hong kong":"HK","new zealand":"NZ","portugal":"PT",
    "greece":"GR","serbia":"RS","croatia":"HR","slovakia":"SK","moldova":"MD",
}

def _to_iso(val: str) -> str:
    """Convert a country string to ISO-3166 alpha-2 if it isn't already."""
    if not val:
        return ""
    v = val.strip()
    if len(v) == 2 and v.upper().isalpha():
        return v.upper()
    return _NAME_TO_ISO.get(v.lower(), v.upper()[:2])


def extract_country(result) -> str | None:
    """
    Extract predicted country as ISO-3166 alpha-2 from a CompletePipelineResult.

    Architecture:
      Geolocation gives the most accurate COUNTRY prediction.
      Bayesian engine gives the most accurate CONFIDENCE score.
      These are separate concerns — do not mix them.

    Priority for country:
      1. Geolocation country_code  (ISO-2, most accurate for country-level)
      2. Geolocation country name  (convert via _to_iso)
      3. attribution_analysis      (Stage 5 fallback)
      4. bayesian primary_region   (last resort — region-level only)
    """
    # 1 & 2. Geolocation — most accurate country prediction
    geo = getattr(result, "geolocation_results", None) or {}
    for ip, g in geo.items():
        cc = getattr(g, "country_code", None)
        if cc and len(str(cc)) == 2:
            return str(cc).upper()
        country = getattr(g, "country", None)
        if country:
            iso = _to_iso(country)
            if iso:
                return iso

    # 3. Stage 5 attribution analysis
    aa = getattr(result, "attribution_analysis", None)
    if aa:
        for attr in ("attributed_country", "primary_country", "country_code", "country"):
            val = getattr(aa, attr, None)
            if val:
                iso = _to_iso(val)
                if iso:
                    return iso

    # 4. Bayesian primary_region — region-level fallback only
    ba = getattr(result, "bayesian_attribution", None)
    if ba:
        region = getattr(ba, "primary_region", None)
        if region and region not in ("Unknown", "Other", ""):
            iso = _to_iso(region)
            if iso:
                return iso

    return None


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIDENCE EXTRACTOR
#  NOW uses aci_adjusted_prob from the Bayesian engine directly.
#  This is a proper calibrated confidence — lower when signals are ambiguous,
#  higher when multiple signals agree. Fixes ECE from 0.33 → target < 0.20.
# ─────────────────────────────────────────────────────────────────────────────

def extract_confidence(result) -> float:
    # PRIMARY: Bayesian aci_adjusted_prob — properly calibrated
    ba = getattr(result, "bayesian_attribution", None)
    if ba:
        prob = getattr(ba, "aci_adjusted_prob", None)
        if prob is not None and float(prob) > 0.0:
            return float(prob)

    # FALLBACK: geolocation confidence proxy
    geo = getattr(result, "geolocation_results", None) or {}
    confs = [getattr(g, "confidence", 0.0) for g in geo.values()
             if getattr(g, "confidence", None) is not None]
    if confs:
        return sum(confs) / len(confs)

    return 0.0


# ─────────────────────────────────────────────────────────────────────────────
#  PATCHED BatchEvaluator that uses extract_confidence
# ─────────────────────────────────────────────────────────────────────────────

from huntertrace.evaluation.dataset import EmailEntry, Prediction as _Prediction

class PatchedBatchEvaluator(BatchEvaluator):
    """Override _run_one to also extract confidence via extract_confidence()."""

    def _run_one(self, entry: EmailEntry, eml_path: str) -> _Prediction:
        pred = super()._run_one(entry, eml_path)
        if pred.error is None and pred.raw_result is not None:
            pred.confidence_score = extract_confidence(pred.raw_result)
        return pred


# ─────────────────────────────────────────────────────────────────────────────
#  AUTO-CORPUS
# ─────────────────────────────────────────────────────────────────────────────

def ensure_corpus(corpus_path: Path, target: int) -> None:
    needs_build = True
    if corpus_path.exists():
        try:
            import json
            data = json.load(open(corpus_path))
            n = len(data.get("emails", []))
            if n >= target:
                print(f"[runEval] Corpus already has {n} entries. Skipping build.")
                needs_build = False
            else:
                print(f"[runEval] Corpus has {n}/{target} — building more...")
        except Exception:
            pass
    if needs_build:
        try:
            from autoCorpusBuilder import build_corpus
            build_corpus(target=target, out_path=str(corpus_path),
                         eml_out_dir=str(corpus_path.parent / "emails"))
        except ImportError:
            print("[!] autoCorpusBuilder.py not in src/. Copy it first.")
            sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HunterTrace Evaluation Runner")
    parser.add_argument("--corpus",       default="../mails/corpus.json")
    parser.add_argument("--test-ratio",   type=float, default=0.20)
    parser.add_argument("--seed",         type=int,   default=42)
    parser.add_argument("--report",       default="../results/evaluation_report.json")
    parser.add_argument("--auto-corpus",  action="store_true")
    parser.add_argument("--target",       type=int, default=150)
    parser.add_argument("--no-ablation",  action="store_true")
    parser.add_argument("--no-baselines", action="store_true")
    args = parser.parse_args()

    corpus_path = Path(args.corpus)

    if args.auto_corpus:
        ensure_corpus(corpus_path, args.target)

    if not corpus_path.exists():
        print(f"\n[!] No corpus at {corpus_path}")
        print("    Run:  python runEval.py --auto-corpus --target 150\n")
        sys.exit(1)

    # 1. Load
    print("[1/5] Loading corpus...")
    dataset = DatasetLoader(str(corpus_path))
    dataset.print_stats()

    total = dataset.stats()["total"]
    if total < 20:
        print(f"[!] Only {total} emails. Run: python runEval.py --auto-corpus --target 150")
        sys.exit(1)

    # 2. Split
    print("[2/5] Splitting...")
    train, test = dataset.split(test_ratio=args.test_ratio, seed=args.seed)
    print(f"      Train: {len(train)}  |  Test: {len(test)}\n")

    # 3. Run
    print(f"[3/5] Running pipeline on {len(test)} test emails...")
    evaluator = PatchedBatchEvaluator(
        pipeline_fn    = run_pipeline,
        geo_country_fn = extract_country,
        base_dir       = str(corpus_path.parent),
        verbose        = True,
    )
    predictions = evaluator.run(test)

    # Debug: print first 5 predictions vs ground truth
    print("\n[DEBUG] First 5 predictions vs ground truth:")
    print(f"  {'ID':<14} {'Predicted':>10}  {'GroundTruth':>12}  {'Conf':>6}  {'Match'}")
    print("  " + "─" * 55)
    for pred, entry in zip(predictions[:5], test[:5]):
        match = "✓" if pred.predicted_country == entry.ground_truth.country else "✗"
        print(f"  {entry.id:<14} {str(pred.predicted_country):>10}  "
              f"{entry.ground_truth.country:>12}  "
              f"{pred.confidence_score:>6.2f}  {match}")
    print()

    # 4. Metrics
    print("[4/5] Computing metrics...")
    framework = EvaluationFramework()
    metrics   = framework.evaluate(test, predictions)

    # ── Pre-compute webmail rate so it's available for metrics patch ──────
    _webmail_hits = 0
    _diag_done = False
    for _pred in predictions:
        if _pred.raw_result is None:
            continue
        _we  = getattr(_pred.raw_result, 'webmail_extraction', None)
        _ria = getattr(_pred.raw_result, 'real_ip_analysis', None)
        # One-time diagnostic on first prediction
        if not _diag_done:
            _diag_done = True
            print(f"  [DIAG] webmail_extraction field = {_we}")
            print(f"  [DIAG] real_ip_analysis field   = {type(_ria).__name__ if _ria else None}")
            print(f"  [DIAG] result fields: {[f for f in dir(_pred.raw_result) if not f.startswith('_')]}")
        if (_we and (getattr(_we, 'real_ip_found', False) or getattr(_we, 'real_ip', None))) or (_ria and getattr(_ria, 'real_ip', None)):
            _webmail_hits += 1
    _n_pred  = len([p for p in predictions if p.raw_result is not None])
    _wm_rate = _webmail_hits / _n_pred if _n_pred > 0 else 0.0
    # Patch into metrics dict immediately
    if isinstance(metrics, dict) and 'coverage' in metrics:
        metrics['coverage']['webmail_leak_rate'] = _wm_rate

    framework.print_report(metrics)

    # 5. Extras
    print("[5/5] Extras...\n")
    if not args.no_baselines:
        framework.compare_baselines(test, predictions)
    if not args.no_ablation:
        framework.run_ablation(test, predictions)
    print(f"\n[WEBMAIL] Emails with real IP leaked: {_webmail_hits}/{_n_pred} ({_wm_rate:.1%})")
    framework.webmail_extraction_rate(test, predictions)

    # ── Forensic scanner metrics ─────────────────────────────────────────
    _forensic_counts = {
        "hop_forgery_suspicious": 0,
        "hop_forgery_forged":     0,
        "bot_send":               0,
        "scripted_send":          0,
        "ai_content":             0,
        "tracking_pixel":         0,
        "html_smuggling":         0,
        "homoglyph":              0,
        "zero_font":              0,
        "forensic_scanned":       0,
    }
    for _pred in predictions:
        _fs = getattr(getattr(_pred, 'raw_result', None), 'forensic_scan', None)
        if _fs is None:
            continue
        _forensic_counts["forensic_scanned"] += 1
        v = getattr(getattr(_fs, 'hop_forgery', None), 'verdict', '')
        if v == "SUSPICIOUS": _forensic_counts["hop_forgery_suspicious"] += 1
        if v == "FORGED":     _forensic_counts["hop_forgery_forged"]     += 1
        sv = getattr(getattr(_fs, 'send_pattern', None), 'verdict', '')
        if sv == "bot":             _forensic_counts["bot_send"]      += 1
        if sv == "scripted_human":  _forensic_counts["scripted_send"] += 1
        if getattr(getattr(_fs, 'ai_content',     None), 'verdict', '') == "ai_likely": _forensic_counts["ai_content"] += 1
        if getattr(getattr(_fs, 'tracking_pixel', None), 'found', False): _forensic_counts["tracking_pixel"] += 1
        if getattr(getattr(_fs, 'html_smuggling', None), 'found', False): _forensic_counts["html_smuggling"] += 1
        if getattr(getattr(_fs, 'homoglyph',      None), 'found', False): _forensic_counts["homoglyph"]      += 1
        if getattr(getattr(_fs, 'zero_font',      None), 'found', False): _forensic_counts["zero_font"]      += 1
    _fn = _forensic_counts["forensic_scanned"]
    if _fn > 0:
        print(f"\n[FORENSICS] Scanned: {_fn} email(s)")
        print(f"  Hop forgery    suspicious={_forensic_counts['hop_forgery_suspicious']}  "
              f"forged={_forensic_counts['hop_forgery_forged']}  "
              f"({(_forensic_counts['hop_forgery_suspicious']+_forensic_counts['hop_forgery_forged'])/_fn:.1%})")
        print(f"  Bot send       {_forensic_counts['bot_send']/_fn:.1%} bot  "
              f"{_forensic_counts['scripted_send']/_fn:.1%} scripted")
        print(f"  AI content     {_forensic_counts['ai_content']}/{_fn} ({_forensic_counts['ai_content']/_fn:.1%})")
        print(f"  Tracking pixel {_forensic_counts['tracking_pixel']}/{_fn} ({_forensic_counts['tracking_pixel']/_fn:.1%})")
        print(f"  HTML smuggling {_forensic_counts['html_smuggling']}/{_fn} ({_forensic_counts['html_smuggling']/_fn:.1%})")
        print(f"  Homoglyph      {_forensic_counts['homoglyph']}/{_fn} ({_forensic_counts['homoglyph']/_fn:.1%})")
        print(f"  Zero-pt font   {_forensic_counts['zero_font']}/{_fn} ({_forensic_counts['zero_font']/_fn:.1%})")
        # Patch into saved report JSON
        _forensic_counts_norm = {k: (v/_fn if k != "forensic_scanned" else v)
                                 for k, v in _forensic_counts.items()}
        try:
            _rpt_f = _json.loads(Path(args.report).read_text())
            _rpt_f.setdefault('forensics', {}).update(_forensic_counts_norm)
            Path(args.report).write_text(_json.dumps(_rpt_f, indent=2))
        except Exception:
            pass

    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    framework.save_report(metrics, args.report)
    # Belt-and-suspenders: directly patch webmail_leak_rate in saved JSON
    import json as _json
    try:
        _rpt = _json.loads(Path(args.report).read_text())
        _rpt.setdefault('coverage', {})['webmail_leak_rate'] = _wm_rate
        Path(args.report).write_text(_json.dumps(_rpt, indent=2))
    except Exception:
        pass
    print(f"\nDone. Report → {args.report}")


if __name__ == "__main__":
    main()
