"""CLI interface for adversarial testing."""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from huntertrace.adversarial.evaluator import AdversarialEvaluator, AdversarialRunConfig
from huntertrace.adversarial.models import AttackSeverity, AttackType
from huntertrace.adversarial.scenarios import ScenarioLibrary


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 7: Adversarial Testing & Robustness Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test all attacks at medium severity
  python3 -m huntertrace.adversarial --dataset samples/ --out report.json

  # Test specific scenario
  python3 -m huntertrace.adversarial --dataset samples/ --scenarios vpn_like_chain --out report.json

  # High severity, limited samples
  python3 -m huntertrace.adversarial --dataset samples/ --severity high --limit 10 --out report.json

  # List available scenarios
  python3 -m huntertrace.adversarial --list-scenarios

  # List available attacks
  python3 -m huntertrace.adversarial --list-attacks
        """,
    )

    parser.add_argument(
        "--dataset",
        type=str,
        help="Path to dataset directory or JSONL file with email samples",
    )

    parser.add_argument(
        "--attacks",
        type=str,
        nargs="+",
        help="Attack types to test (default: all). Options: " + ", ".join(t.value for t in AttackType),
    )

    parser.add_argument(
        "--severity",
        type=str,
        choices=["low", "medium", "high"],
        default="medium",
        help="Attack severity level (default: medium)",
    )

    parser.add_argument(
        "--scenarios",
        type=str,
        nargs="+",
        help="Predefined scenarios to test. Options: " + ", ".join(ScenarioLibrary.list_scenarios()),
    )

    parser.add_argument(
        "--limit",
        type=int,
        help="Max samples to test (default: all)",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for determinism (default: 42)",
    )

    parser.add_argument(
        "--out",
        type=str,
        help="Output file for report (JSON)",
    )

    parser.add_argument(
        "--include-explanations",
        action="store_true",
        help="Include explainability analysis for failures",
    )

    parser.add_argument(
        "--list-attacks",
        action="store_true",
        help="List available attack types",
    )

    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List available scenarios",
    )

    parser.add_argument(
        "--describe-attack",
        type=str,
        help="Describe specific attack (e.g., --describe-attack header_injection)",
    )

    parser.add_argument(
        "--describe-scenario",
        type=str,
        help="Describe specific scenario",
    )

    return parser.parse_args(args)


def list_attacks() -> None:
    """List available attacks."""
    print("\n=== Available Attacks ===\n")
    for attack_type in AttackType:
        print(f"  {attack_type.value}")
        from huntertrace.adversarial.attacks import AttackLibrary
        desc = AttackLibrary.get_attack_description(attack_type.value)
        print(f"    {desc}\n")


def list_scenarios() -> None:
    """List available scenarios."""
    print("\n=== Available Scenarios ===\n")
    for name in ScenarioLibrary.list_scenarios():
        scenario = ScenarioLibrary.get_scenario(name)
        print(f"  {name}")
        print(f"    Description: {scenario.description}")
        print(f"    Severity: {scenario.severity_level}")
        print(f"    Attacks: {', '.join(scenario.attack_sequence)}\n")


def describe_attack(attack_type: str) -> None:
    """Describe specific attack."""
    from huntertrace.adversarial.attacks import AttackLibrary

    desc = AttackLibrary.get_attack_description(attack_type)
    impact = AttackLibrary.get_attack_impact(attack_type)

    print(f"\n=== {attack_type} ===\n")
    print(f"Description: {desc}\n")
    if impact:
        print("Expected Impact:")
        for metric, value in impact.items():
            print(f"  {metric}: {value:.1f}")
    print()


def describe_scenario(scenario_name: str) -> None:
    """Describe specific scenario."""
    scenario = ScenarioLibrary.get_scenario(scenario_name)
    if not scenario:
        print(f"Unknown scenario: {scenario_name}")
        return

    print(f"\n=== {scenario.name} ===\n")
    print(f"Description: {scenario.description}\n")
    print(f"Severity: {scenario.severity_level}")
    print(f"Attack Sequence:")
    for i, attack in enumerate(scenario.attack_sequence, 1):
        print(f"  {i}. {attack}")
    if scenario.target_properties:
        print(f"\nTarget Properties: {scenario.target_properties}")
    print()


def collect_samples(dataset_path: str) -> List[str]:
    """Collect email samples from dataset."""
    path = Path(dataset_path)

    if path.is_file() and path.suffix == ".jsonl":
        # Read JSONL file
        samples = []
        with open(path, "r") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if "path" in obj:
                        samples.append(obj["path"])
                except json.JSONDecodeError:
                    continue
        return samples

    elif path.is_dir():
        # Collect .eml files from directory
        samples = list(path.glob("*.eml"))
        return [str(s) for s in samples]

    else:
        raise ValueError(f"Dataset not found: {dataset_path}")


def create_pipeline_executor() -> Tuple:
    """Create a pipeline executor for the evaluation."""
    # This is a placeholder - in real use, integrate with actual pipeline
    def executor(email_content: str) -> Tuple[Optional[str], float, Optional[List[str]]]:
        """Mock executor - returns dummy predictions."""
        # In production, this would call the full pipeline
        if "test" in email_content.lower():
            return ("region1", 0.8, [])
        return (None, 0.0, ["unknown"])

    return executor


def main(args: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    try:
        parsed = parse_args(args)

        # Handle info commands
        if parsed.list_attacks:
            list_attacks()
            return 0

        if parsed.list_scenarios:
            list_scenarios()
            return 0

        if parsed.describe_attack:
            describe_attack(parsed.describe_attack)
            return 0

        if parsed.describe_scenario:
            describe_scenario(parsed.describe_scenario)
            return 0

        # Validate required arguments for evaluation
        if not parsed.dataset:
            print("Error: --dataset is required for evaluation", file=sys.stderr)
            return 1

        if not parsed.out:
            print("Error: --out is required for evaluation", file=sys.stderr)
            return 1

        # Collect samples
        print(f"[*] Loading samples from {parsed.dataset}...")
        samples = collect_samples(parsed.dataset)
        print(f"[*] Found {len(samples)} samples")

        # Create config
        config = AdversarialRunConfig(
            seed=parsed.seed,
            attack_types=parsed.attacks,
            severity=parsed.severity,
            scenarios=parsed.scenarios,
            limit=parsed.limit,
            include_explanations=parsed.include_explanations,
        )

        # Create pipeline executor (placeholder)
        executor = create_pipeline_executor()

        # Run evaluation
        print("[*] Initializing adversarial evaluator...")
        evaluator = AdversarialEvaluator(pipeline_executor=executor)

        print(f"[*] Running adversarial evaluation (seed={config.seed})...")
        report = evaluator.evaluate_samples(samples, config)

        # Save report
        with open(parsed.out, "w") as f:
            json.dump(report.to_dict(), f, indent=2)

        print(f"[+] Report saved to {parsed.out}")

        # Print summary
        print("\n=== Adversarial Robustness Report ===\n")
        print(f"Baseline Accuracy: {report.baseline_metrics['accuracy']:.4f}")
        print(f"Baseline FAR: {report.baseline_metrics['far']:.4f}")
        print(f"Adversarial Accuracy: {report.adversarial_metrics['accuracy']:.4f}")
        print(f"Adversarial FAR: {report.adversarial_metrics['far']:.4f}")
        print(f"\nAccuracy Drop: {report.robustness_metrics.accuracy_drop:.4f}")
        print(f"FAR Increase: {report.robustness_metrics.false_attribution_increase:.4f}")
        print(f"Attack Success Rate: {report.robustness_metrics.attack_success_rate:.4f}")
        print(f"Confidence Instability: {report.robustness_metrics.confidence_instability:.4f}")

        if report.robustness_metrics.failure_cases:
            print(f"\nTop Failures: {len(report.robustness_metrics.failure_cases)}")
            for failure in report.robustness_metrics.failure_cases[:3]:
                print(
                    f"  - {failure.attack_type}/{failure.failure_type}: "
                    f"confidence_delta={failure.confidence_delta:.4f}"
                )

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
