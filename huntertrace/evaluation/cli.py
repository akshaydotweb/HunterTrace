"""CLI for evaluation module."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from huntertrace.analysis.models import ScoringConfig
from huntertrace.evaluation.cost import CostConfig
from huntertrace.evaluation.datasets import load_dataset
from huntertrace.evaluation.evaluator import AtlasEvaluator
from huntertrace.evaluation.reporting import generate_report


def load_config(config_path: Optional[str]) -> ScoringConfig:
    """Load ScoringConfig from YAML or JSON."""
    if not config_path:
        return ScoringConfig()

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    # Try JSON first
    if config_path.endswith(".json"):
        with open(config_path) as f:
            data = json.load(f)
        return ScoringConfig(**data)

    # Try YAML
    try:
        import yaml

        with open(config_path) as f:
            data = yaml.safe_load(f)
        return ScoringConfig(**data)
    except ImportError:
        raise RuntimeError("YAML support requires 'pyyaml' package")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m huntertrace.evaluation",
        description="Evaluate HunterTrace Atlas scoring pipeline"
    )

    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to dataset (JSONL file or directory with labels.json)"
    )
    parser.add_argument(
        "--config",
        help="Path to ScoringConfig (JSON or YAML)"
    )
    parser.add_argument(
        "--format",
        choices=["auto", "jsonl", "directory"],
        default="auto",
        help="Dataset format"
    )
    parser.add_argument(
        "--out",
        default="evaluation_report.json",
        help="Output report path (JSON)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Max samples to evaluate (for testing)"
    )
    parser.add_argument(
        "--error-sample-size",
        type=int,
        default=10,
        help="Max error cases to collect"
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Random seed for deterministic sampling"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--bootstrap-iterations",
        type=int,
        default=1000,
        help="Number of bootstrap iterations for confidence intervals"
    )
    parser.add_argument(
        "--cost-config",
        help="Path to CostConfig (JSON)"
    )
    parser.add_argument(
        "--enable-adversarial",
        action="store_true",
        help="Enable adversarial robustness testing"
    )
    parser.add_argument(
        "--adversarial-samples-per-input",
        type=int,
        default=1,
        help="Number of adversarial samples per input"
    )

    args = parser.parse_args()

    try:
        # Load dataset
        if args.verbose:
            print(f"Loading dataset from {args.dataset}...")
        samples = load_dataset(args.dataset, format=args.format)

        if args.verbose:
            print(f"Loaded {len(samples)} samples")

        # Limit if requested
        if args.limit:
            samples = samples[:args.limit]
            if args.verbose:
                print(f"Limited to {len(samples)} samples")

        # Load config
        if args.verbose and args.config:
            print(f"Loading config from {args.config}...")
        config = load_config(args.config)

        # Load cost config (NEW)
        cost_config = CostConfig()
        if args.cost_config:
            if args.verbose:
                print(f"Loading cost config from {args.cost_config}...")
            with open(args.cost_config) as f:
                cost_data = json.load(f)
            cost_config = CostConfig(**cost_data)

        # Run evaluation
        if args.verbose:
            print("Starting evaluation...")
        evaluator = AtlasEvaluator(
            scoring_config=config,
            bootstrap_iterations=args.bootstrap_iterations,
            cost_config=cost_config,
            enable_adversarial=args.enable_adversarial,
            adversarial_samples_per_input=args.adversarial_samples_per_input,
        )
        context = evaluator.evaluate(samples, error_sample_limit=args.error_sample_size)

        # Generate report
        if args.verbose:
            print("Generating report...")
        report = generate_report(context, error_sample_limit=args.error_sample_size)

        # Save report
        report.save(args.out)
        if args.verbose:
            print(f"Report saved to {args.out}")

        # Print summary
        print("\n=== Evaluation Summary ===")
        print(f"Samples: {report.sample_count}")
        print(f"Accuracy: {report.summary_metrics['accuracy']:.4f}")
        print(f"False Attribution Rate: {report.summary_metrics['false_attribution_rate']:.4f}")
        print(f"Abstention Rate: {report.summary_metrics['abstention_rate']:.4f}")
        print(f"Coverage Rate: {report.summary_metrics['coverage_rate']:.4f}")

        print(f"\nECE: {report.calibration_metrics['ece']:.4f}")
        print(f"MCE: {report.calibration_metrics['mce']:.4f}")
        print(f"Brier Score: {report.calibration_metrics['brier_score']:.4f}")

        # NEW: Print confidence intervals if available
        if report.metric_confidence_intervals:
            print(f"\n=== Confidence Intervals (95%) ===")
            for metric_name, ci in report.metric_confidence_intervals.items():
                print(f"{metric_name}: [{ci['ci_lower']:.4f}, {ci['ci_upper']:.4f}]")

        # NEW: Print cost metrics if available
        if report.cost_metrics:
            print(f"\n=== Cost Analysis ===")
            print(f"Expected Cost: {report.cost_metrics['expected_cost']:.4f}")
            breakdown = report.cost_metrics["cost_breakdown"]
            print(f"  False Attribution: {breakdown['false_attribution']:.4f}")
            print(f"  Missed Attribution: {breakdown['missed_attribution']:.4f}")
            print(f"  Abstention: {breakdown['abstention']:.4f}")

        # NEW: Print adversarial metrics if available
        if report.adversarial_metrics:
            print(f"\n=== Adversarial Robustness ===")
            print(f"Performance Drop: {report.adversarial_metrics['performance_drop']:.4f}")
            print(f"FAR Increase: {report.adversarial_metrics['false_attribution_increase']:.4f}")
            print(f"Attack Success Rate: {report.adversarial_metrics['attack_success_rate']:.4f}")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
