#!/usr/bin/env python3
"""
HunterTrace — Evaluation Runner
=================================
Run this from the src/ directory:
    python runEval.py
    python runEval.py --corpus ../mails/corpus.json --test-ratio 0.2
    python runEval.py --auto-corpus --target 150   <- build corpus first
"""

import os
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


# ─────────────────────────────────────────────────────────────────────────────
#  STEP 0 — Load .env BEFORE importing CompletePipeline
#
#  Root cause of avg_confidence=0.0:
#  hunterTrace._load_config() is only called inside main() (CLI mode).
#  When CompletePipeline is imported as a module, keys never reach
#  os.environ — so AbuseIPDB, IPInfo, VirusTotal all silently skip.
# ─────────────────────────────────────────────────────────────────────────────

def _load_env() -> dict:
    here       = Path(__file__).parent
    candidates = [here, here.parent, here.parent.parent]
    loaded     = {}

    for directory in candidates:
        env_file = directory / ".env"
        if not env_file.exists():
            continue
        print(f"[runEval] Found .env → {env_file.resolve()}")
        for raw in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
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

    print("[runEval] API key status:")
    for key in ("ABUSEIPDB_API_KEY", "IPINFO_TOKEN", "VIRUSTOTAL_API_KEY"):
        val = os.environ.get(key)
        status = f"✓  {val[:8]}…" if val else "✗  NOT SET (add to HunterTrace/.env)"
        print(f"  {key}: {status}")

    if not loaded:
        print("\n  WARNING: No .env file found. Create HunterTrace/.env:")
        print("    ABUSEIPDB_API_KEY=your_key_here")
        print("    IPINFO_TOKEN=your_token_here\n")
    else:
        print()

    return loaded


# Load keys NOW — before CompletePipeline is imported
_loaded_keys = _load_env()

from hunterTrace import CompletePipeline
from datasetCreator import DatasetLoader, BatchEvaluator
from evaluationFramework import EvaluationFramework


# ─────────────────────────────────────────────────────────────────────────────
#  PIPELINE WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

pipeline = CompletePipeline(verbose=False)

def run_pipeline(eml_path: str):
    return pipeline.run(eml_path)


# ─────────────────────────────────────────────────────────────────────────────
#  COUNTRY EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def extract_country(result):
    # 1. Bayesian attribution (v3)
    ba = getattr(result, "bayesian_attribution", None)
    if ba:
        region = getattr(ba, "primary_region", None)
        if region and region != "Unknown":
            return region

    # 2. Stage 5 attribution
    aa = getattr(result, "attribution_analysis", None)
    if aa:
        for attr in ("attributed_country", "primary_country", "country"):
            val = getattr(aa, attr, None)
            if val:
                return val

    # 3. Geolocation fallback
    geo = getattr(result, "geolocation_results", None) or {}
    for ip, g in geo.items():
        cc = getattr(g, "country_code", None) or getattr(g, "country", None)
        if cc:
            return cc

    return None


# ─────────────────────────────────────────────────────────────────────────────
#  CORPUS AUTO-BUILD
# ─────────────────────────────────────────────────────────────────────────────

def ensure_corpus(corpus_path: Path, target: int) -> None:
    needs_build = True
    if corpus_path.exists():
        try:
            import json
            with open(corpus_path) as f:
                data = json.load(f)
            current = len(data.get("emails", []))
            if current >= target:
                print(f"[runEval] Corpus already has {current} entries. Skipping build.")
                needs_build = False
            else:
                print(f"[runEval] Corpus has {current}/{target} — running autoCorpusBuilder...")
        except Exception:
            print("[runEval] corpus.json unreadable — rebuilding...")

    if needs_build:
        try:
            from autoCorpusBuilder import build_corpus
            build_corpus(
                target      = target,
                out_path    = str(corpus_path),
                eml_out_dir = str(corpus_path.parent / "emails"),
                verbose     = False,
            )
        except ImportError:
            print("[!] autoCorpusBuilder.py not in src/ — copy it first.")
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
    parser.add_argument("--auto-corpus",  action="store_true",
                        help="Auto-build corpus if missing or too small")
    parser.add_argument("--target",       type=int, default=150,
                        help="Corpus size target for --auto-corpus")
    parser.add_argument("--no-ablation",  action="store_true")
    parser.add_argument("--no-baselines", action="store_true")
    args = parser.parse_args()

    corpus_path = Path(args.corpus)

    # Optional auto-build
    if args.auto_corpus:
        ensure_corpus(corpus_path, args.target)

    if not corpus_path.exists():
        print(f"\n[!] Corpus not found: {corpus_path}")
        print("    Run:  python runEval.py --auto-corpus --target 150\n")
        sys.exit(1)

    # 1. Load
    print("[1/5] Loading corpus...")
    dataset = DatasetLoader(str(corpus_path))
    dataset.print_stats()

    if dataset.stats()["total"] < 20:
        print(f"[!] Corpus too small ({dataset.stats()['total']} emails).")
        print("    Run:  python runEval.py --auto-corpus --target 150")
        sys.exit(1)

    # 2. Split
    print("[2/5] Splitting...")
    train, test = dataset.split(test_ratio=args.test_ratio, seed=args.seed)
    print(f"      Train: {len(train)}  |  Test: {len(test)}\n")

    # 3. Run pipeline
    print(f"[3/5] Running pipeline on {len(test)} test emails...")
    evaluator = BatchEvaluator(
        pipeline_fn    = run_pipeline,
        geo_country_fn = extract_country,
        base_dir       = str(corpus_path.parent),
        verbose        = True,
    )
    predictions = evaluator.run(test)

    # 4. Metrics
    print("\n[4/5] Computing metrics...")
    framework = EvaluationFramework()
    metrics   = framework.evaluate(test, predictions)
    framework.print_report(metrics)

    # 5. Extras
    print("[5/5] Extras...\n")
    if not args.no_baselines:
        framework.compare_baselines(test, predictions)
    if not args.no_ablation:
        framework.run_ablation(test, predictions)
    framework.webmail_extraction_rate(test, predictions)

    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    framework.save_report(metrics, args.report)
    print(f"\nDone. Report → {args.report}")


if __name__ == "__main__":
    main()