#!/usr/bin/env python3
"""Validate synthetic email samples against ground truth labels."""

import json
import sys
from pathlib import Path

sys.path.insert(0, "/Users/lapac/Documents/projects/HunterTrace")


def validate_samples():
    """Compare actual results against ground truth."""

    # Load ground truth
    gt_path = Path("/Users/lapac/Documents/projects/HunterTrace/examples/GROUND_TRUTH.json")
    ground_truth = json.loads(gt_path.read_text())

    # Load actual results
    results_path = Path("/tmp/results.json")
    actual_results = json.loads(results_path.read_text())

    # Create lookup by filename
    actual_by_file = {Path(r["file"]).name: r for r in actual_results}

    print("=" * 80)
    print("GROUND TRUTH VALIDATION REPORT")
    print("=" * 80)
    print()

    # Per-sample validation
    gt_data = ground_truth["ground_truth_labels"]

    matches = 0
    mismatches = 0

    for sample in gt_data:
        sample_id = sample["sample_id"]
        filename = sample["filename"]
        gt_region = sample["ground_truth_region"]
        gt_verdict = sample["ground_truth_verdict"]
        expected_conf_range = sample["confidence_range"]
        category = sample["category"]

        actual = actual_by_file.get(filename)
        if not actual:
            print(f"❌ {sample_id}: NO RESULTS FOUND")
            mismatches += 1
            continue

        actual_region = actual.get("region")
        actual_verdict = actual.get("verdict")
        actual_conf = actual.get("confidence", 0.0)

        # Validate
        verdict_ok = actual_verdict == gt_verdict
        conf_ok = expected_conf_range[0] <= actual_conf <= expected_conf_range[1]
        region_ok = (gt_region is None and actual_region is None) or (gt_region == actual_region)

        status = "✓" if (verdict_ok and region_ok) else "✗"
        matches += 1 if (verdict_ok and region_ok) else 0
        mismatches += 1 if not (verdict_ok and region_ok) else 0

        print(f"{status} {sample_id} ({category})")
        print(f"   Ground Truth: region={gt_region}, verdict={gt_verdict}, conf={expected_conf_range}")
        print(f"   Actual:       region={actual_region}, verdict={actual_verdict}, conf={actual_conf:.2%}")

        if not verdict_ok:
            print(f"   ⚠️  VERDICT MISMATCH: expected {gt_verdict}, got {actual_verdict}")
        if not region_ok:
            print(f"   ⚠️  REGION MISMATCH: expected {gt_region}, got {actual_region}")
        if not conf_ok:
            print(f"   ⚠️  CONFIDENCE OUT OF RANGE: expected {expected_conf_range}, got {actual_conf:.2%}")

        print()

    print("=" * 80)
    print(f"SUMMARY: {matches} passed, {mismatches} failed out of {len(gt_data)} samples")
    print(f"Pass rate: {matches / len(gt_data) * 100:.1f}%")
    print("=" * 80)
    print()

    # Gap-by-gap analysis
    print("Gap Coverage Analysis:")
    print()

    gaps = ground_truth["summary"]["test_coverage"]
    for gap_name, description in gaps.items():
        print(f"  {gap_name}:")
        print(f"    {description}")
        print()

    return matches, mismatches


if __name__ == "__main__":
    matches, mismatches = validate_samples()
    sys.exit(0 if mismatches == 0 else 1)
