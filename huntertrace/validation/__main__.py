from .runner import ValidationRunner
from .reporting import build_summary_text


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m huntertrace.validation")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--enable-adversarial", action="store_true")
    parser.add_argument("--export-report")
    args = parser.parse_args()

    runner = ValidationRunner()
    report = runner.run_dataset(args.dataset, limit=args.limit, enable_adversarial=args.enable_adversarial)
    if args.export_report:
        runner.export_report(report, args.export_report)
    print(build_summary_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
