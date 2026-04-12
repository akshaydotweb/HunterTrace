#!/usr/bin/env python3
"""Enterprise demo runner for baseline, robustness, and security strength."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from huntertrace.atlas.provenance import derive_provenance
from huntertrace.attribution.adversarial_testing import ALL_ATTACK_TYPES, generate_adversarial_case
from huntertrace.attribution.comparative_evaluation import ComparativeEvaluator, _as_case


def _bucket(confidence: float) -> str:
    if confidence >= 0.60:
        return "high"
    if confidence >= 0.35:
        return "medium"
    return "low"


def _load_cases(path: Path) -> List[Mapping[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Dataset must be a JSON list of cases")
    return payload


def _scenario_kind(case_id: str) -> str:
    mapping = {
        "clean_enterprise": "clean",
        "forwarded_email": "forwarded",
        "mailing_list_modified": "mailing_list",
        "spoofed_email": "spoofed",
    }
    return mapping.get(case_id, "other")


def _explainability_rows(case_obj: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for signal in case_obj.signals:
        source_hint = str(getattr(signal, "source", "") or "")
        header, provenance, trust = derive_provenance(
            signal_name=str(getattr(signal, "name", "")),
            source_hint=source_hint,
        )
        rows.append(
            {
                "signal": signal.name,
                "source_hint": source_hint,
                "source_header": header,
                "provenance_class": provenance.value,
                "trust_weight": round(float(trust), 4),
            }
        )
    return rows


def run_demo(dataset_path: Path, output_path: Path, config_path: str, overrides: Optional[List[str]]) -> Dict[str, Any]:
    cases = _load_cases(dataset_path)
    evaluator = ComparativeEvaluator(config_path=config_path, overrides=overrides or [])

    scenario_rows: List[Dict[str, Any]] = []
    confidences: Dict[str, List[float]] = {"clean": [], "forwarded": [], "mailing_list": [], "spoofed": []}

    false_positive_avoidance = {
        "forwarded_not_spoof": True,
        "mailing_not_spoof": True,
        "notes": [],
    }

    for raw_case in cases:
        case_obj = _as_case(raw_case)
        baseline = evaluator._evaluate_case(case_obj, use_correlation=False)
        correlation = evaluator._evaluate_case(case_obj, use_correlation=True)
        repeated = evaluator._evaluate_case(case_obj, use_correlation=True)

        deterministic = (
            correlation.verdict == repeated.verdict
            and correlation.predicted_region == repeated.predicted_region
            and abs(correlation.confidence - repeated.confidence) < 1e-12
        )

        kind = _scenario_kind(case_obj.case_id)
        if kind in confidences:
            confidences[kind].append(correlation.confidence)

        if kind == "forwarded" and correlation.verdict != "inconclusive":
            false_positive_avoidance["forwarded_not_spoof"] = False
            false_positive_avoidance["notes"].append("Forwarded case moved out of inconclusive")
        if kind == "mailing_list" and correlation.verdict != "inconclusive":
            false_positive_avoidance["mailing_not_spoof"] = False
            false_positive_avoidance["notes"].append("Mailing-list case moved out of inconclusive")

        scenario_rows.append(
            {
                "case_id": case_obj.case_id,
                "scenario": kind,
                "baseline": {
                    "verdict": baseline.verdict,
                    "predicted_region": baseline.predicted_region,
                    "confidence": baseline.confidence,
                    "confidence_bucket": _bucket(baseline.confidence),
                },
                "correlation": {
                    "verdict": correlation.verdict,
                    "predicted_region": correlation.predicted_region,
                    "confidence": correlation.confidence,
                    "confidence_bucket": _bucket(correlation.confidence),
                    "limitations": list(correlation.limitations),
                },
                "deterministic": deterministic,
                "explainability": _explainability_rows(case_obj),
            }
        )

    # Adversarial sweep on clean baseline only: same email, five attack variants.
    clean_case = next(_as_case(item) for item in cases if str(item.get("case_id")) == "clean_enterprise")
    clean_baseline = evaluator._evaluate_case(clean_case, use_correlation=True)

    adversarial_rows: List[Dict[str, Any]] = []
    for attack in ALL_ATTACK_TYPES:
        attacked_case = generate_adversarial_case(clean_case, attack)
        attacked_outcome = evaluator._evaluate_case(attacked_case, use_correlation=True)
        adversarial_rows.append(
            {
                "attack_type": attack,
                "baseline_verdict": clean_baseline.verdict,
                "baseline_confidence": clean_baseline.confidence,
                "attacked_verdict": attacked_outcome.verdict,
                "attacked_confidence": attacked_outcome.confidence,
                "confidence_drop": round(clean_baseline.confidence - attacked_outcome.confidence, 12),
                "attack_detected": attacked_outcome.verdict == "inconclusive" or attacked_outcome.confidence < clean_baseline.confidence,
                "limitations": list(attacked_outcome.limitations),
            }
        )

    report = {
        "dataset": str(dataset_path),
        "metrics": {
            "confidence_distribution": {
                key: {
                    "count": len(values),
                    "mean": round(sum(values) / len(values), 12) if values else 0.0,
                    "bucket": _bucket((sum(values) / len(values)) if values else 0.0),
                }
                for key, values in confidences.items()
            },
            "false_positive_avoidance": false_positive_avoidance,
            "determinism": {
                "all_deterministic": all(row["deterministic"] for row in scenario_rows),
                "non_deterministic_cases": [row["case_id"] for row in scenario_rows if not row["deterministic"]],
            },
            "adversarial": {
                "attacks_run": len(adversarial_rows),
                "attacks_detected": sum(1 for row in adversarial_rows if row["attack_detected"]),
                "mean_confidence_drop": round(
                    sum(row["confidence_drop"] for row in adversarial_rows) / max(len(adversarial_rows), 1),
                    12,
                ),
            },
        },
        "scenarios": scenario_rows,
        "adversarial_cases": adversarial_rows,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run enterprise demo scenarios and export summarized metrics")
    parser.add_argument(
        "--dataset",
        default="demo/enterprise_demo_cases.json",
        help="Path to enterprise demo dataset JSON",
    )
    parser.add_argument(
        "--output",
        default="demo/enterprise_demo_report.json",
        help="Path for generated JSON summary",
    )
    parser.add_argument(
        "--config",
        default="config/scoring.yaml",
        help="Runtime scoring config path",
    )
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        help="Config override in key.path=value format",
    )
    args = parser.parse_args()

    report = run_demo(
        dataset_path=Path(args.dataset),
        output_path=Path(args.output),
        config_path=args.config,
        overrides=args.set,
    )

    print("Enterprise demo report generated")
    print(f"Output: {args.output}")
    print("Scenario outcomes:")
    for row in report["scenarios"]:
        corr = row["correlation"]
        print(
            f"- {row['case_id']}: verdict={corr['verdict']} "
            f"confidence={corr['confidence']:.4f} bucket={corr['confidence_bucket']}"
        )


if __name__ == "__main__":
    main()
