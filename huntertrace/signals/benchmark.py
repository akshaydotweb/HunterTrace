"""Benchmark runner for Atlas signal pipeline against local .eml datasets."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Tuple

from huntertrace.signals.output import AtlasSignalPipeline


def _iter_eml_files(dataset: Path) -> Iterable[Path]:
    yield from sorted(dataset.rglob("*.eml"))


def run_benchmark(dataset: Path, limit: int = 0, determinism_repeats: int = 3) -> Dict[str, Any]:
    started = time.perf_counter()
    files = list(_iter_eml_files(dataset))
    if limit > 0:
        files = files[:limit]

    parsed = 0
    failed = 0
    errors: List[Tuple[str, str]] = []
    hop_counts: List[int] = []
    observability_scores: List[float] = []
    confidence_scores: List[float] = []
    anomaly_counts: List[int] = []

    for path in files:
        try:
            result = AtlasSignalPipeline.from_eml(str(path))
            parsed += 1
            hop_count = len([s for s in result.signals_used if s.name == "hop_count"])
            hop_counts.append(
                next((s.value for s in result.signals_used if s.name == "hop_count"), 0)
                if hop_count
                else 0
            )
            observability_scores.append(result.observability_score)
            confidence_scores.append(result.confidence)
            anomaly_counts.append(len([s for s in result.signals_used if s.name == "anomaly_types"]))
        except Exception as exc:
            failed += 1
            errors.append((str(path), str(exc)))

    determinism_ok = True
    determinism_sample = files[: min(5, len(files))]
    for sample in determinism_sample:
        baseline = AtlasSignalPipeline.from_eml(str(sample)).to_dict()
        for _ in range(max(1, determinism_repeats - 1)):
            current = AtlasSignalPipeline.from_eml(str(sample)).to_dict()
            if current != baseline:
                determinism_ok = False
                break
        if not determinism_ok:
            break

    elapsed = time.perf_counter() - started

    def _safe_mean(values: List[float]) -> float:
        return round(mean(values), 4) if values else 0.0

    return {
        "dataset": str(dataset),
        "files_total": len(files),
        "parsed_ok": parsed,
        "failed": failed,
        "duration_seconds": round(elapsed, 4),
        "throughput_files_per_sec": round((len(files) / elapsed), 4) if elapsed > 0 else 0.0,
        "avg_hops": _safe_mean([float(v) for v in hop_counts]),
        "avg_observability_score": _safe_mean(observability_scores),
        "avg_confidence": _safe_mean(confidence_scores),
        "avg_anomaly_signal_count": _safe_mean([float(v) for v in anomaly_counts]),
        "determinism_ok": determinism_ok,
        "errors": [{"file": file_path, "error": message} for file_path, message in errors[:20]],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="huntertrace-benchmark",
        description="Benchmark Atlas signal pipeline on local .eml datasets.",
    )
    parser.add_argument("--dataset", required=True, help="Dataset root path containing .eml files")
    parser.add_argument("--limit", type=int, default=0, help="Max number of .eml files (0 = all)")
    parser.add_argument(
        "--determinism-repeats",
        type=int,
        default=3,
        help="How many repeated parses to compare for determinism checks",
    )
    parser.add_argument("--out", help="Optional output JSON file path")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    dataset = Path(args.dataset)
    if not dataset.exists():
        print(json.dumps({"error": f"dataset not found: {dataset}"}))
        return 2

    result = run_benchmark(dataset=dataset, limit=args.limit, determinism_repeats=args.determinism_repeats)

    if args.out:
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    if args.compact:
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

