"""Analysis tool for scoring results JSON."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List


def analyze_results(results: List[Dict[str, Any]]) -> None:
    """Analyze and print detailed statistics from scoring results."""
    successful = [r for r in results if r.get("status") == "success"]
    errors = [r for r in results if r.get("status") == "error"]

    attributed = [r for r in successful if r.get("verdict") == "attributed"]
    inconclusive = [r for r in successful if r.get("verdict") == "inconclusive"]

    print("\n" + "=" * 70)
    print("DETAILED SCORING ANALYSIS")
    print("=" * 70)

    # Basic stats
    print("\nOVERALL:")
    print(f"  Total: {len(results)}")
    print(f"  Success: {len(successful)} ({100*len(successful)/max(1,len(results)):.1f}%)")
    print(f"  Errors: {len(errors)}")

    # Attribution breakdown
    print("\nATTRIBUTION:")
    print(f"  Attributed: {len(attributed)} ({100*len(attributed)/max(1,len(successful)):.1f}%)")
    print(f"  Inconclusive: {len(inconclusive)} ({100*len(inconclusive)/max(1,len(successful)):.1f}%)")

    # Regions if any
    if attributed:
        regions = Counter(r.get("region") for r in attributed)
        print("\nREGIONS:")
        for region, count in regions.most_common():
            print(f"  {region}: {count}")

    # Confidence distribution
    if attributed:
        confs = [r["confidence"] for r in attributed]
        print("\nCONFIDENCE DISTRIBUTION:")
        print(f"  Min: {min(confs):.1%}")
        print(f"  Max: {max(confs):.1%}")
        print(f"  Avg: {sum(confs)/len(confs):.1%}")
        print(f"  Median: {sorted(confs)[len(confs)//2]:.1%}")

        # Confidence buckets
        buckets = defaultdict(int)
        for conf in confs:
            bucket = int(conf * 10) * 10
            buckets[bucket] += 1
        print("\n  By confidence range:")
        for bucket in sorted(buckets.keys()):
            print(f"    {bucket}%-{bucket+10}%: {buckets[bucket]}")

    # Consistency scores
    consis = [r.get("consistency_score", 0) for r in successful]
    print("\nCONSISTENCY SCORES:")
    print(f"  Min: {min(consis):.1%}")
    print(f"  Max: {max(consis):.1%}")
    print(f"  Avg: {sum(consis)/len(consis):.1%}")

    # Signal counts
    signal_counts = [r.get("signals_count", 0) for r in successful]
    print("\nSIGNAL COUNTS:")
    print(f"  Min: {min(signal_counts)}")
    print(f"  Max: {max(signal_counts)}")
    print(f"  Avg: {sum(signal_counts)/len(signal_counts):.1f}")

    # Limitations
    all_limitations = []
    for r in successful:
        all_limitations.extend(r.get("limitations", []))
    if all_limitations:
        limitations = Counter(all_limitations)
        print("\nTOP LIMITATIONS:")
        for limit, count in limitations.most_common(5):
            print(f"  {limit}: {count}")

    # Error analysis
    if errors:
        error_msgs = Counter(r.get("error", "unknown")[:60] for r in errors)
        print("\nTOP ERRORS:")
        for err, count in error_msgs.most_common(5):
            print(f"  {err}: {count}")

    print("\n" + "=" * 70)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="huntertrace-analyze",
        description="Analyze scoring results JSON.",
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Input JSON file from huntertrace-score",
    )
    parser.add_argument(
        "--filter-region",
        help="Filter results by region",
    )
    parser.add_argument(
        "--filter-verdict",
        help="Filter results by verdict (attributed/inconclusive)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        help="Filter by minimum confidence threshold",
    )

    args = parser.parse_args()

    # Load results
    try:
        with open(args.input) as f:
            results = json.load(f)
    except Exception as e:
        print(f"Error reading {args.input}: {e}", file=sys.stderr)
        return 1

    # Apply filters
    if args.filter_region:
        results = [r for r in results if r.get("region") == args.filter_region]
    if args.filter_verdict:
        results = [r for r in results if r.get("verdict") == args.filter_verdict]
    if args.threshold is not None:
        results = [r for r in results if r.get("confidence", 0) >= args.threshold]

    if not results:
        print("No results match filter criteria")
        return 0

    # Analyze
    analyze_results(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
