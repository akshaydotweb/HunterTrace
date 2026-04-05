"""CLI entry point for HunterTrace testing framework.

Usage:
    python -m huntertrace.testing --generate-synthetic 100 --layers full
    python -m huntertrace.testing --dataset datasets/real/ceas --limit 1000 --layers parsing,signals
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from huntertrace.testing.generator import SyntheticGenerator
from huntertrace.testing.datasets import DatasetLoader
from huntertrace.testing.runner import TestRunner
from huntertrace.testing.reporting import ReportGenerator
from huntertrace.testing.metrics import compute_pipeline_metrics, check_determinism


def _build_parser() -> argparse.ArgumentParser:
    """Build argument parser."""
    parser = argparse.ArgumentParser(
        prog="huntertrace.testing",
        description="HunterTrace comprehensive testing framework",
    )

    dataset_group = parser.add_argument_group("Dataset")
    dataset_group.add_argument(
        "--generate-synthetic",
        type=int,
        metavar="COUNT",
        help="Generate N synthetic test samples",
    )
    dataset_group.add_argument(
        "--dataset",
        type=str,
        default=None,
        metavar="PATH",
        help="Dataset directory or name (ceas, corpus, actor, emails, eml_raw)",
    )
    dataset_group.add_argument(
        "--include-real",
        action="store_true",
        help="Include real datasets alongside synthetic",
    )
    dataset_group.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Limit samples per dataset",
    )
    dataset_group.add_argument(
        "--seed",
        type=int,
        default=42,
        metavar="SEED",
        help="Random seed for deterministic generation",
    )

    layers_group = parser.add_argument_group("Layers")
    layers_group.add_argument(
        "--layers",
        type=str,
        default="full",
        metavar="LAYERS",
        help="Comma-separated layer names: parsing,signals,correlation,scoring,explainability,full (default: full)",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--output",
        type=str,
        default="reports",
        metavar="DIR",
        help="Output directory for reports (default: reports/)",
    )
    output_group.add_argument(
        "--save-intermediate",
        action="store_true",
        help="Save per-layer outputs",
    )
    output_group.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose logging",
    )

    testing_group = parser.add_argument_group("Testing")
    testing_group.add_argument(
        "--determinism-runs",
        type=int,
        default=3,
        metavar="N",
        help="Number of runs for determinism check (default: 3)",
    )
    testing_group.add_argument(
        "--enable-explainability",
        action="store_true",
        help="Enable explainability layer testing",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Prepare output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Collect samples
    samples = []

    if args.generate_synthetic:
        if args.verbose:
            print(f"[*] Generating {args.generate_synthetic} synthetic samples...")

        scenarios = [
            "clean_enterprise",
            "multi_hop_relay",
            "forwarded_chain",
            "spoofed_headers",
            "broken_chain",
            "timestamp_spoof",
            "anonymized_like",
            "malformed_headers",
            "geo_hop",
            "vpn_tor_like",
        ]

        per_scenario = args.generate_synthetic // len(scenarios)
        remainder = args.generate_synthetic % len(scenarios)

        for i, scenario in enumerate(scenarios):
            count = per_scenario + (1 if i < remainder else 0)
            if count > 0:
                batch = SyntheticGenerator.generate_batch(
                    scenario, count, seed=args.seed + i * 1000
                )
                samples.extend(batch)
                if args.verbose:
                    print(f"  - {scenario}: {count} samples")

    if args.include_real or args.dataset:
        if args.verbose:
            print(f"[*] Loading real datasets...")

        if args.dataset:
            # Load specific dataset
            dataset_name = args.dataset
            if dataset_name == "ceas":
                dataset_samples = DatasetLoader.load_ceas(args.limit)
            elif dataset_name == "corpus":
                dataset_samples = DatasetLoader.load_corpus(args.limit)
            elif dataset_name == "actor":
                dataset_samples = DatasetLoader.load_actor_based(args.limit)
            elif dataset_name == "fraud":
                dataset_samples = DatasetLoader.load_fraud_csv(sample_limit=args.limit)
            elif Path(dataset_name).exists():
                dataset_samples = DatasetLoader.load_email_collection(dataset_name, args.limit)
            else:
                dataset_samples = DatasetLoader.load_email_collection(dataset_name, args.limit)

            if args.verbose:
                print(f"  - {dataset_name}: {len(dataset_samples)} samples")
            samples.extend(dataset_samples)

        elif args.include_real:
            # Load all datasets
            all_samples = DatasetLoader.load_all(args.limit)
            if args.verbose:
                print(f"  - Total: {len(all_samples)} samples")
            samples.extend(all_samples)

    if not samples:
        print("ERROR: No samples to test. Use --generate-synthetic or --dataset.", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"[*] Total samples: {len(samples)}")

    # Parse layers
    layers = [l.strip() for l in args.layers.split(",")]
    if args.verbose:
        print(f"[*] Testing layers: {', '.join(layers)}")

    # Run tests
    layer_results = {}
    pipeline_results = []

    config = {
        "seed": args.seed,
        "layers": layers,
        "synthetic_count": args.generate_synthetic,
        "total_samples": len(samples),
        "enable_explainability": args.enable_explainability,
    }

    try:
        if "full" in layers or len(layers) == 1 and layers[0] == "full":
            if args.verbose:
                print(f"[*] Running full pipeline...")
            pipeline_results = TestRunner.run_full_pipeline(
                samples, enable_explainability=args.enable_explainability
            )
        else:
            # Run individual layers
            for layer in layers:
                if args.verbose:
                    print(f"[*] Running {layer} layer...")

                if layer == "parsing":
                    layer_results[layer] = TestRunner.run_parsing(samples)
                elif layer == "signals" and "parsing" not in layer_results:
                    # Can't run signals without parsing
                    parse_results = TestRunner.run_parsing(samples)
                    hop_chains = [r.output.get("hop_chain") if r.passed else None for r in parse_results]
                    signal_results, _ = TestRunner.run_signals(
                        [h for h in hop_chains if h is not None]
                    )
                    layer_results[layer] = signal_results
                elif layer == "signals":
                    hop_chains = [r.output.get("hop_chain") if r.passed else None for r in layer_results["parsing"]]
                    signal_results, _ = TestRunner.run_signals(
                        [h for h in hop_chains if h is not None]
                    )
                    layer_results[layer] = signal_results

        # Compute determinism
        determinism_rate = 0.0
        if args.determinism_runs > 1:
            if args.verbose:
                print(f"[*] Checking determinism ({args.determinism_runs} runs)...")

            all_runs = [TestRunner.run_full_pipeline(samples[:10]) for _ in range(args.determinism_runs)]
            determinism_rate = check_determinism(all_runs, args.determinism_runs)
            if args.verbose:
                print(f"  - Determinism rate: {determinism_rate * 100:.1f}%")

        # Generate report
        if args.verbose:
            print(f"[*] Generating report...")

        dataset_category = (
            args.dataset or ("synthetic" if args.generate_synthetic else "mixed")
        )
        report = ReportGenerator.generate_report(
            dataset_category=dataset_category,
            dataset_sample_count=len(samples),
            layer_results=layer_results,
            pipeline_results=pipeline_results,
            config=config,
            determinism_rate=determinism_rate,
        )

        report_path = ReportGenerator.save_report(report, output_dir)
        if args.verbose:
            print(f"[*] Report saved to {report_path}")

        # Print summary
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total samples:        {len(samples)}")
        print(f"Success rate:         {report.pipeline_metrics.end_to_end_success_rate * 100:.1f}%")
        print(f"Determinism rate:     {determinism_rate * 100:.1f}%")
        print(f"Abstention rate:      {report.pipeline_metrics.abstention_rate * 100:.1f}%")
        print(f"Anomaly detection:    {report.pipeline_metrics.anomaly_detection_rate * 100:.1f}%")
        print(f"Avg pipeline time:    {report.pipeline_metrics.avg_pipeline_duration_ms:.1f} ms")
        print("=" * 60)

        return 0 if report.pipeline_metrics.end_to_end_success_rate >= 0.8 else 1

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
