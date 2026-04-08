#!/usr/bin/env python3
"""Production CLI for deterministic forensic attribution workflows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from huntertrace.__version__ import __version__
from huntertrace.attribution.adversarial_testing import AdversarialTester
from huntertrace.attribution.config_loader import load_runtime_config
from huntertrace.attribution.evaluation import (
    AttributionEvaluator,
    build_default_dataset,
)
from huntertrace.attribution.report import evaluate_inputs
from huntertrace.attribution.scoring import InferenceEngine


def _emit_log(enabled: bool, event: str, **fields: Any) -> None:
    if not enabled:
        return
    payload = {"event": event}
    for key, value in fields.items():
        payload[key] = value
    print(json.dumps(payload, sort_keys=True, default=str), file=sys.stderr)


def _load_dataset(path: Optional[str]) -> Sequence[Mapping[str, Any]]:
    if not path:
        return build_default_dataset()
    raw = json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("cases"), list):
        return raw["cases"]
    raise ValueError("Dataset must be a list or object with 'cases'.")


def _pretty_result(result: Mapping[str, Any], trace: Optional[Mapping[str, Any]] = None) -> str:
    lines = [
        f"verdict: {result['verdict']}",
        f"region: {result['region']}",
        f"confidence: {float(result['confidence']):.6f}",
        f"signals_used: {len(result['signals_used'])}",
        f"signals_rejected: {len(result['signals_rejected'])}",
    ]
    correlation = {}
    if isinstance(trace, Mapping):
        correlation_raw = trace.get("correlation", {})
        if isinstance(correlation_raw, Mapping):
            correlation = dict(correlation_raw)
    if correlation:
        lines.append(
            "correlation: "
            f"enabled={bool(correlation.get('enabled', False))}, "
            f"anonymization_detected={bool(correlation.get('anonymization_detected', False))}, "
            f"confidence_impact={float(correlation.get('confidence_impact', 0.0)):.6f}"
        )
        indicators = list(correlation.get("key_indicators", []) or [])
        if indicators:
            lines.append(f"correlation_indicators: {', '.join(str(item) for item in indicators[:5])}")
    if result.get("limitations"):
        lines.append("key_reasoning:")
        for limitation in result["limitations"][:5]:
            lines.append(f"  - {limitation}")
        if len(result["limitations"]) > 5:
            lines.append(f"  - ... {len(result['limitations']) - 5} more")
    lines.append(f"explanation: {result['explanation']}")
    return "\n".join(lines)


def _handle_analyze(args: argparse.Namespace) -> int:
    runtime = load_runtime_config(args.config, overrides=args.set)
    logging_enabled = bool(runtime.logging.get("enabled", True))
    _emit_log(logging_enabled, "analysis_start", input=args.input_file)

    report = evaluate_inputs(
        args.input_file,
        runtime,
        use_correlation=(not args.disable_correlation),
    )
    items = report["reports"]

    for row in items:
        _emit_log(
            logging_enabled,
            "scoring_decision",
            evidence_id=row["evidence_id"],
            signals_processed=len(row["result"]["signals_used"]) + len(row["result"]["signals_rejected"]),
            verdict=row["result"]["verdict"],
            confidence=row["result"]["confidence"],
            region=row["result"]["region"],
        )

    if len(items) == 1:
        result = items[0]["result"]
        if args.format == "pretty":
            print(_pretty_result(result, trace=items[0].get("trace")))
        else:
            single_output = dict(result)
            single_output["trace"] = items[0].get("trace", {})
            print(json.dumps(single_output, indent=2, sort_keys=True))
    else:
        if args.format == "pretty":
            print(json.dumps(report["summary"], indent=2, sort_keys=True))
            for row in items:
                print("")
                print(f"source: {row['source']}")
                print(_pretty_result(row["result"], trace=row.get("trace")))
        else:
            print(json.dumps(report, indent=2, sort_keys=True))

    _emit_log(logging_enabled, "analysis_complete", input_count=len(items), summary=report["summary"])
    return 0


def _handle_report(args: argparse.Namespace) -> int:
    runtime = load_runtime_config(args.config, overrides=args.set)
    logging_enabled = bool(runtime.logging.get("enabled", True))
    _emit_log(logging_enabled, "report_start", input=args.input)

    try:
        report = evaluate_inputs(
            args.input,
            runtime,
            use_correlation=(not args.disable_correlation),
        )
    except Exception as exc:
        report = {
            "summary": {"total_inputs": 1, "attributed": 0, "inconclusive": 1},
            "reports": [
                {
                    "evidence_id": "report-error",
                    "source": args.input,
                    "result": {
                        "region": None,
                        "confidence": 0.0,
                        "verdict": "inconclusive",
                        "signals_used": [],
                        "signals_rejected": [],
                        "anomalies": [],
                        "limitations": [f"Report generation error: {type(exc).__name__}: {exc}"],
                        "explanation": "Inconclusive attribution due to report generation error.",
                    },
                    "trace": {"source": args.input, "error": f"{type(exc).__name__}: {exc}"},
                }
            ],
        }
        _emit_log(logging_enabled, "error", error=f"{type(exc).__name__}: {exc}")

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    _emit_log(
        logging_enabled,
        "report_complete",
        output=str(output_path),
        total_inputs=report["summary"]["total_inputs"],
        attributed=report["summary"]["attributed"],
        inconclusive=report["summary"]["inconclusive"],
    )
    print(str(output_path))
    return 0


def _handle_test(args: argparse.Namespace) -> int:
    runtime = load_runtime_config(args.config, overrides=args.set)
    logging_enabled = bool(runtime.logging.get("enabled", True))
    dataset = _load_dataset(args.dataset)

    engine = InferenceEngine(config=runtime.scoring)
    evaluator = AttributionEvaluator(
        engine=engine,
        confidence_threshold=float(runtime.inference.get("confidence_threshold", 0.35)),
        tie_epsilon=float(runtime.inference.get("tie_epsilon", 1e-9)),
        min_supporting_signals=int(runtime.inference.get("min_supporting_signals", 2)),
        min_contributing_groups=int(runtime.inference.get("min_contributing_groups", 2)),
        min_winning_groups=int(runtime.inference.get("min_distinct_supporting_groups", 2)),
    )

    _emit_log(logging_enabled, "test_start", dataset_size=len(dataset))
    eval_report = evaluator.evaluate(dataset).to_dict()
    adversarial_report = AdversarialTester(evaluator=evaluator).run(dataset=dataset).to_dict()

    output = {
        "metrics_summary": {
            "accuracy": eval_report["accuracy"],
            "false_attribution_rate": eval_report["false_attribution_rate"],
            "abstention_rate": eval_report["abstention_rate"],
            "robustness_score": adversarial_report["robustness_score"],
            "attack_success_rate": adversarial_report["attack_success_rate"],
            "confidence_shift": adversarial_report["confidence_shift"],
        },
        "failures": {
            "evaluation_failure_cases": eval_report["failure_cases"],
            "adversarial_failures": adversarial_report["failures"],
        },
        "adversarial_robustness": adversarial_report,
    }

    _emit_log(
        logging_enabled,
        "test_complete",
        false_attribution_rate=eval_report["false_attribution_rate"],
        robustness_score=adversarial_report["robustness_score"],
    )
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="huntertrace",
        description=f"HunterTrace v{__version__} attribution CLI",
    )
    parser.add_argument("--version", action="version", version=f"huntertrace {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="Analyze .eml or JSON signals")
    analyze.add_argument("input_file", help="Path to .eml, JSON signals file, or directory")
    analyze.add_argument("--format", choices=("json", "pretty"), default="json")
    analyze.add_argument("--config", default="config/scoring.yaml")
    analyze.add_argument("--set", action="append", default=[], help="Config override (key.path=value)")
    analyze.add_argument(
        "--disable-correlation",
        action="store_true",
        help="Skip correlation preprocessing and run baseline scoring input.",
    )

    report = subparsers.add_parser("report", help="Generate full JSON report")
    report.add_argument("input", help="Path to .eml/.json or directory")
    report.add_argument("--output", required=True, help="Output report path")
    report.add_argument("--config", default="config/scoring.yaml")
    report.add_argument("--set", action="append", default=[], help="Config override (key.path=value)")
    report.add_argument(
        "--disable-correlation",
        action="store_true",
        help="Skip correlation preprocessing and run baseline scoring input.",
    )

    test = subparsers.add_parser("test", help="Run evaluation + adversarial robustness tests")
    test.add_argument("--dataset", help="Evaluation dataset JSON path")
    test.add_argument("--config", default="config/scoring.yaml")
    test.add_argument("--set", action="append", default=[], help="Config override (key.path=value)")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    try:
        if args.command == "analyze":
            return _handle_analyze(args)
        if args.command == "report":
            return _handle_report(args)
        if args.command == "test":
            return _handle_test(args)
        parser.error(f"Unknown command: {args.command}")
    except Exception as exc:
        _emit_log(True, "error", error=f"{type(exc).__name__}: {exc}")
        fallback = {
            "region": None,
            "confidence": 0.0,
            "verdict": "inconclusive",
            "signals_used": [],
            "signals_rejected": [],
            "anomalies": [],
            "limitations": [f"Processing error: {type(exc).__name__}: {exc}"],
            "explanation": "Inconclusive attribution due to processing error.",
        }
        print(json.dumps(fallback, indent=2, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
