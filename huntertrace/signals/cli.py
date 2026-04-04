"""CLI for HunterTrace Atlas signal-layer audit output."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from huntertrace.signals.output import AtlasSignalPipeline


def _read_stdin() -> str:
    text = sys.stdin.read()
    if not text.strip():
        raise ValueError("No input received on stdin.")
    return text


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="huntertrace-atlas",
        description="Build audit-ready signal output from email headers (.eml or raw headers).",
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--eml", help="Path to .eml file")
    source.add_argument("--headers-file", help="Path to raw email/header text file")
    source.add_argument("--stdin", action="store_true", help="Read raw email/header text from stdin")

    parser.add_argument("--compact", action="store_true", help="Emit compact JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.eml:
            result = AtlasSignalPipeline.from_eml(args.eml)
        elif args.headers_file:
            text = Path(args.headers_file).read_text(encoding="utf-8", errors="replace")
            result = AtlasSignalPipeline.from_header_text(text)
        else:
            result = AtlasSignalPipeline.from_header_text(_read_stdin())
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: atlas signal pipeline failed: {exc}", file=sys.stderr)
        return 1

    if args.compact:
        print(json.dumps(result.to_dict(), separators=(",", ":"), sort_keys=True))
    else:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

