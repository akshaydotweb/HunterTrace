"""CLI for HunterTrace Atlas scoring and attribution testing."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from huntertrace.analysis import (
    AtlasCorrelationEngine,
    AtlasScoringEngine,
    ScoringConfig,
)
from huntertrace.parsing import AtlasHeaderPipeline
from huntertrace.signals import SignalBuilder
from huntertrace.signals.enrichment import SignalEnricher


def _load_eml_file(path: Path) -> str:
    """Load raw email from .eml file."""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        raise ValueError(f"Failed to read {path}: {e}")


def _process_email(
    eml_path: Path,
    config: Optional[ScoringConfig] = None,
) -> Dict[str, Any]:
    """Process single email: parse → signals → correlate → score."""
    try:
        # Parse email
        raw_email = _load_eml_file(eml_path)
        hop_chain = AtlasHeaderPipeline.parse_header_string(raw_email)

        # Build signals
        signals, rejected = SignalBuilder.build(hop_chain)

        # ENRICHMENT: Add geographic and categorical information
        enriched_signals = SignalEnricher.enrich_signals(signals)

        # Correlate
        correlation = AtlasCorrelationEngine.correlate(enriched_signals)

        # Score
        result = AtlasScoringEngine.score(enriched_signals, correlation, config or ScoringConfig())

        return {
            "file": str(eml_path),
            "status": "success",
            "region": result.region,
            "confidence": round(result.confidence, 4),
            "verdict": result.verdict,
            "consistency_score": round(result.consistency_score, 4),
            "signals_count": len(enriched_signals),
            "rejected_signals_count": len(rejected),
            "anomalies_count": len(result.anomalies) if result.anomalies else 0,
            "limitations": result.limitations if result.limitations else [],
        }

    except Exception as e:
        return {
            "file": str(eml_path),
            "status": "error",
            "error": str(e),
        }


def _extract_region_hint(signal) -> Optional[str]:
    """Extract region hint from signal using hostname TLD heuristics."""
    value_str = str(signal.value).lower()

    # Extract TLD from hostnames
    if "." in value_str and not all(c.isdigit() or c == "." for c in value_str.split(".")[-1]):
        # It's likely a hostname, get TLD
        parts = value_str.split(".")
        tld = parts[-1]

        # TLD to region mapping (common TLDs)
        tld_map = {
            "uk": "UK",
            "gb": "UK",
            "de": "DE",
            "fr": "FR",
            "jp": "JP",
            "cn": "CN",
            "in": "IN",
            "ir": "IR",
            "ru": "RU",
            "br": "BR",
            "au": "AU",
            "ca": "CA",
            "com": "US",  # Common commercial
            "net": "US",
            "org": "US",
            "gov": "US",
            "edu": "US",
        }

        if tld in tld_map:
            return tld_map[tld]

    # Hostname-based heuristics
    if any(x in value_str for x in [".uk", ".gb", "london"]):
        return "UK"
    elif any(x in value_str for x in [".de", "berlin"]):
        return "DE"
    elif any(x in value_str for x in [".fr", "paris"]):
        return "FR"
    elif any(x in value_str for x in [".jp", "tokyo"]):
        return "JP"
    elif any(x in value_str for x in [".cn", "beijing"]):
        return "CN"

    return None


def _extract_group_hint(signal) -> Optional[str]:
    """Extract group hint from signal name."""
    name = signal.name
    if name.startswith("hop_timestamp") or name in ["hop_count", "chain_completeness_score"]:
        return "temporal"
    elif name.startswith("hop_from") or name.startswith("hop_by") or name == "hop_protocol":
        return "infrastructure"
    elif name in ["chain_anomaly_count", "anomaly_types"]:
        return "structure"
    else:
        return "quality"


def _collect_eml_files(path: Path) -> List[Path]:
    """Recursively collect .eml files from path."""
    if path.is_file():
        return [path] if path.suffix.lower() == ".eml" else []

    eml_files = []
    for p in path.rglob("*.eml"):
        eml_files.append(p)
    return sorted(eml_files)


def _format_result_summary(results: List[Dict[str, Any]]) -> str:
    """Format summary statistics."""
    successful = [r for r in results if r.get("status") == "success"]
    errors = [r for r in results if r.get("status") == "error"]

    attributed = [r for r in successful if r.get("verdict") == "attributed"]
    inconclusive = [r for r in successful if r.get("verdict") == "inconclusive"]

    # Collect regions and other stats
    regions = {}
    for r in attributed:
        region = r.get("region")
        if region:
            regions[region] = regions.get(region, 0) + 1

    lines = [
        "",
        "=" * 70,
        "SCORING RESULTS SUMMARY",
        "=" * 70,
        f"Total processed: {len(results)}",
        f"Successful: {len(successful)}",
        f"Errors: {len(errors)}",
        "",
        "ATTRIBUTION RESULTS:",
        f"  Attributed: {len(attributed)} ({100*len(attributed)/max(1,len(successful)):.1f}%)",
        f"  Inconclusive: {len(inconclusive)} ({100*len(inconclusive)/max(1,len(successful)):.1f}%)",
        "",
    ]

    if regions:
        lines.append("REGIONS ATTRIBUTED:")
        for region, count in sorted(regions.items(), key=lambda x: -x[1]):
            pct = 100 * count / len(attributed)
            lines.append(f"  {region}: {count} ({pct:.1f}%)")
        lines.append("")

    if attributed:
        avg_conf = sum(r["confidence"] for r in attributed) / len(attributed)
        min_conf = min(r["confidence"] for r in attributed)
        max_conf = max(r["confidence"] for r in attributed)
        lines.extend([
            "ATTRIBUTED STATISTICS:",
            f"  Avg confidence: {avg_conf:.1%}",
            f"  Min confidence: {min_conf:.1%}",
            f"  Max confidence: {max_conf:.1%}",
            "",
        ])

    if successful:
        avg_consistency = sum(r.get("consistency_score", 0) for r in successful) / len(successful)
        avg_signals = sum(r.get("signals_count", 0) for r in successful) / len(successful)
        lines.extend([
            "OVERALL STATISTICS:",
            f"  Avg consistency: {avg_consistency:.1%}",
            f"  Avg signals/email: {avg_signals:.1f}",
            "",
        ])

    if errors:
        lines.extend([
            "ERRORS:",
        ])
        unique_errors = {}
        for r in errors:
            err = r.get("error", "unknown")[:50]
            unique_errors[err] = unique_errors.get(err, 0) + 1
        for err, count in sorted(unique_errors.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"  {err}: {count}")

    lines.append("=" * 70)

    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="huntertrace-score",
        description="Process .eml files through full scoring pipeline.",
    )

    parser.add_argument(
        "path",
        type=Path,
        help="Path to .eml file or directory containing .eml files",
    )

    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file (JSON format)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output",
    )

    parser.add_argument(
        "-s", "--summary",
        action="store_true",
        help="Show summary statistics",
    )

    parser.add_argument(
        "-l", "--limit",
        type=int,
        help="Limit number of files to process",
    )

    parser.add_argument(
        "--confidence-threshold",
        type=float,
        default=0.30,
        help="Custom confidence threshold for scoring (default: 0.30)",
    )

    parser.add_argument(
        "--min-signals",
        type=int,
        default=2,
        help="Minimum supporting signals required (default: 2)",
    )

    parser.add_argument(
        "--min-groups",
        type=int,
        default=1,
        help="Minimum signal groups required (default: 1)",
    )

    parser.add_argument(
        "-e", "--enrichment-file",
        type=Path,
        help="JSON file with signal->region mappings for enrichment",
    )

    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Only show summary statistics, no details",
    )

    return parser


def main() -> int:
    """Main CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    # Validate path
    if not args.path.exists():
        print(f"Error: Path does not exist: {args.path}", file=sys.stderr)
        return 1

    # Collect .eml files
    eml_files = _collect_eml_files(args.path)
    if not eml_files:
        print(f"Error: No .eml files found in {args.path}", file=sys.stderr)
        return 1

    # Apply limit
    if args.limit:
        eml_files = eml_files[:args.limit]

    print(f"Found {len(eml_files)} .eml files to process")

    # Build custom config
    config = ScoringConfig(
        confidence_threshold=args.confidence_threshold,
        minimum_supporting_signals=args.min_signals,
        minimum_signal_groups=args.min_groups,
    )

    # Process files
    results = []
    for i, eml_path in enumerate(eml_files, 1):
        if i % 100 == 0:
            print(f"Processing {i}/{len(eml_files)}...", file=sys.stderr)

        result = _process_email(eml_path, config)
        results.append(result)

        if args.verbose:
            status = result.get("status", "unknown")
            if status == "success":
                print(
                    f"  {eml_path.name}: {result.get('verdict')} "
                    f"({result.get('confidence', 0):.0%} confidence)",
                )
            else:
                print(f"  {eml_path.name}: ERROR - {result.get('error', 'unknown')}")

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults written to {args.output}")

    # Show summary
    if args.summary or not args.output:
        print(_format_result_summary(results))

    return 0


if __name__ == "__main__":
    sys.exit(main())
