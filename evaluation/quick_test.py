#!/usr/bin/env python3
"""Quick 10-email evaluation test for HunterTrace."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'evaluation'))

from pathlib import Path

# Load .env
env_file = Path(__file__).resolve().parent.parent / '.env'
if env_file.exists():
    for raw in env_file.read_text(errors='ignore').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, val = line.partition('=')
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if val and key in ('ABUSEIPDB_API_KEY', 'IPINFO_TOKEN', 'VIRUSTOTAL_API_KEY'):
            os.environ[key] = val

from huntertrace.core.pipeline import CompletePipeline
from datasetCreator import DatasetLoader

pipeline = CompletePipeline(verbose=False)
dataset = DatasetLoader('mails/corpus.json')
_, test = dataset.split(test_ratio=0.05, seed=42)

base_dir = 'mails'
correct = 0
total = 0

print(f"Running pipeline on 10 test emails...\n")
print(f"{'#':<4} {'ID':<14} {'GT':>4}  {'Pred':>6}  {'Conf':>7}  {'Match'}")
print("-" * 50)

for i, entry in enumerate(test[:10]):
    eml = os.path.join(base_dir, entry.file)
    gt = entry.ground_truth.country

    try:
        result = pipeline.run(eml)

        # Extract country from geolocation
        geo = getattr(result, 'geolocation_results', None) or {}
        pred = None
        for ip, g in geo.items():
            cc = getattr(g, 'country_code', None)
            if cc and len(str(cc)) == 2:
                pred = str(cc).upper()
                break
            c = getattr(g, 'country', None)
            if c:
                pred = c[:2].upper()
                break
        if not pred:
            ba = getattr(result, 'bayesian_attribution', None)
            if ba:
                pred = getattr(ba, 'primary_region', 'UNK')

        # Extract confidence
        conf = 0.0
        ba = getattr(result, 'bayesian_attribution', None)
        if ba:
            p = getattr(ba, 'aci_adjusted_prob', None)
            if p:
                conf = float(p)

        match = (pred == gt)
        if match:
            correct += 1
        total += 1
        sym = '✓' if match else '✗'
        print(f"{i+1:<4} {entry.id:<14} {gt:>4}  {str(pred):>6}  {conf:>6.1%}  {sym}")

    except Exception as e:
        total += 1
        print(f"{i+1:<4} {entry.id:<14} {gt:>4}  {'ERR':>6}  {'0.0%':>7}  ✗  {type(e).__name__}")

print("-" * 50)
print(f"\nAccuracy: {correct}/{total} ({correct/total*100:.0f}%)")
