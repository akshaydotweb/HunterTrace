from __future__ import annotations

import argparse
import sys

from .cli import main as cli_main
from .validation import ValidationRunner


def main() -> int:
    if "--validate-dataset" not in sys.argv:
        return cli_main()

    parser = argparse.ArgumentParser(prog="huntertrace")
    parser.add_argument("--validate-dataset", required=True)
    parser.add_argument("--bootstrap-iterations", type=int, default=0)
    parser.add_argument("--enable-adversarial", action="store_true")
    parser.add_argument("--export-report")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    runner = ValidationRunner()
    report = runner.run_dataset(
        args.validate_dataset,
        limit=args.limit,
        enable_adversarial=args.enable_adversarial,
        bootstrap_iterations=args.bootstrap_iterations,
    )
    if args.export_report:
        runner.export_report(report, args.export_report)
    print(runner.summarize(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
