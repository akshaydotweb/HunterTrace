"""CLI for explainability engine."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from huntertrace.analysis.models import (
    AttributionResult,
    CorrelationResult,
    Signal,
)
from huntertrace.explainability import ExplainabilityEngine, FormatterFactory
from huntertrace.parsing.models import HopChain


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Explainability engine for HunterTrace Atlas attribution"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to input JSON file containing signals, correlation, and attribution results",
    )

    parser.add_argument(
        "--format",
        default="json",
        choices=["json", "text", "markdown"],
        help="Output format (default: json)",
    )

    parser.add_argument(
        "--output",
        help="Output file path (default: stdout)",
    )

    parser.add_argument(
        "--hops",
        help="Optional path to hop chain JSON file for full traceability",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show verbose output including processing steps",
    )

    return parser.parse_args()


def load_input_data(input_path: str) -> Dict[str, Any]:
    """Load input JSON containing signals, correlation, and attribution."""
    with open(input_path, "r") as f:
        return json.load(f)


def load_hop_chain(hops_path: str) -> HopChain | None:
    """Load optional hop chain for traceability."""
    if not hops_path:
        return None

    try:
        with open(hops_path, "r") as f:
            data = json.load(f)
            # Deserialize HopChain
            # This assumes HopChain has a from_dict method
            return HopChain.from_dict(data)
    except FileNotFoundError:
        print(f"Warning: Hop chain file not found: {hops_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Warning: Failed to load hop chain: {e}", file=sys.stderr)
        return None


def deserialize_signals(data: Dict) -> list[Signal]:
    """Deserialize signals from JSON."""
    signals_data = data.get("signals", [])
    signals = []

    for sig_data in signals_data:
        signal = Signal(
            signal_id=sig_data.get("signal_id", ""),
            name=sig_data.get("name", ""),
            value=sig_data.get("value"),
            source=sig_data.get("source", ""),
            validation_flags=tuple(sig_data.get("validation_flags", [])),
            confidence=float(sig_data.get("confidence", 0.5)),
            evidence=sig_data.get("evidence", ""),
            candidate_region=sig_data.get("candidate_region"),
            group=sig_data.get("group"),
        )
        signals.append(signal)

    return signals


def deserialize_correlation(data: Dict) -> CorrelationResult:
    """Deserialize correlation result from JSON."""
    from huntertrace.analysis.models import (
        AnonymizationResult,
        Contradiction,
        Relationship,
    )

    # Deserialize contradictions
    contradictions = []
    for contra_data in data.get("correlation", {}).get("contradictions", []):
        contradiction = Contradiction(
            type=contra_data.get("type", ""),
            signals=contra_data.get("signals", []),
            reason=contra_data.get("reason", ""),
            severity=contra_data.get("severity", "medium"),
        )
        contradictions.append(contradiction)

    # Deserialize relationships
    relationships = []
    for rel_data in data.get("correlation", {}).get("relationships", []):
        relationship = Relationship(
            type=rel_data.get("type", ""),
            source_signal=rel_data.get("source_signal", ""),
            target_signal=rel_data.get("target_signal", ""),
            rationale=rel_data.get("rationale", ""),
        )
        relationships.append(relationship)

    # Deserialize anonymization
    anon_data = data.get("correlation", {}).get("anonymization", {})
    anonymization = AnonymizationResult(
        detected=anon_data.get("detected", False),
        confidence=float(anon_data.get("confidence", 0.0)),
        indicators=anon_data.get("indicators", []),
        strength=anon_data.get("strength", "low"),
    )

    correlation = CorrelationResult(
        consistency_score=float(data.get("correlation", {}).get("consistency_score", 0.5)),
        contradictions=contradictions,
        relationships=relationships,
        anonymization=anonymization,
        group_scores=data.get("correlation", {}).get("group_scores", {}),
        limitations=data.get("correlation", {}).get("limitations", []),
    )

    return correlation


def deserialize_attribution(data: Dict) -> AttributionResult:
    """Deserialize attribution result from JSON."""
    from huntertrace.analysis.models import RejectedSignalDetail, SignalContribution

    # Deserialize signal contributions
    signals_used = []
    for sig_data in data.get("attribution", {}).get("signals_used", []):
        contrib = SignalContribution(
            signal_id=sig_data.get("signal_id", ""),
            name=sig_data.get("name", ""),
            value=sig_data.get("value", ""),
            role=sig_data.get("role", "neutral"),
            group=sig_data.get("group"),
            contribution=float(sig_data.get("contribution", 0.0)),
            penalty=float(sig_data.get("penalty", 0.0)),
        )
        signals_used.append(contrib)

    # Deserialize rejected signals
    signals_rejected = []
    for sig_data in data.get("attribution", {}).get("signals_rejected", []):
        rejected = RejectedSignalDetail(
            signal_id=sig_data.get("signal_id", ""),
            name=sig_data.get("name", ""),
            reason=sig_data.get("reason", ""),
        )
        signals_rejected.append(rejected)

    attribution = AttributionResult(
        region=data.get("attribution", {}).get("region"),
        confidence=float(data.get("attribution", {}).get("confidence", 0.0)),
        verdict=data.get("attribution", {}).get("verdict", "inconclusive"),
        consistency_score=float(data.get("attribution", {}).get("consistency_score", 0.5)),
        signals_used=signals_used,
        signals_rejected=signals_rejected,
        anomalies=data.get("attribution", {}).get("anomalies", []),
        limitations=data.get("attribution", {}).get("limitations", []),
        reasoning=data.get("attribution", {}).get("reasoning", ""),
    )

    return attribution


def main():
    """Main CLI entry point."""
    args = parse_args()

    if args.verbose:
        print("Loading input data...", file=sys.stderr)

    # Load and deserialize data
    input_data = load_input_data(args.input)
    signals = deserialize_signals(input_data)
    correlation = deserialize_correlation(input_data)
    attribution = deserialize_attribution(input_data)

    if args.verbose:
        print(f"Loaded {len(signals)} signals", file=sys.stderr)
        print(f"Consistency score: {correlation.consistency_score:.1%}", file=sys.stderr)
        print(f"Attribution verdict: {attribution.verdict}", file=sys.stderr)

    # Load optional hop chain
    hop_chain = load_hop_chain(args.hops)

    if args.verbose and hop_chain:
        print(f"Loaded hop chain with {len(hop_chain.hops)} hops", file=sys.stderr)

    # Create explainability engine and explain
    if args.verbose:
        print("Generating explainability...", file=sys.stderr)

    engine = ExplainabilityEngine(hop_chain=hop_chain)
    result = engine.explain(signals, correlation, attribution)

    # Format output
    output = FormatterFactory.format(result, args.format)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        if args.verbose:
            print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
