"""CLI for HunterTrace Atlas header parsing and hop-chain reconstruction."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from huntertrace.parsing import AtlasHeaderPipeline


def _chain_to_dict(chain, include_raw: bool = True) -> Dict[str, Any]:
    hops = []
    for hop in chain.hops:
        item = {
            "index": hop.index,
            "from_host": hop.from_host,
            "from_ip": hop.from_ip,
            "by_host": hop.by_host,
            "protocol": hop.protocol,
            "timestamp": hop.timestamp.isoformat() if hop.timestamp else None,
            "parse_confidence": hop.parse_confidence,
            "validation_flags": [flag.value for flag in hop.validation_flags],
        }
        if include_raw:
            item["raw_header"] = hop.raw_header
        hops.append(item)

    return {
        "hops": hops,
        "anomalies": list(chain.anomalies),
        "completeness_score": chain.completeness_score,
    }


def _read_stdin() -> str:
    content = sys.stdin.read()
    if not content.strip():
        raise ValueError("No input received on stdin.")
    return content


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="huntertrace-parse",
        description="Parse email headers and reconstruct validated Received hop chains.",
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--eml", help="Path to .eml file")
    source.add_argument("--headers-file", help="Path to file containing raw email/header text")
    source.add_argument(
        "--stdin",
        action="store_true",
        help="Read raw email/header text from stdin",
    )

    parser.add_argument(
        "--no-raw",
        action="store_true",
        help="Omit raw_header from hop output",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON output",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.eml:
            chain = AtlasHeaderPipeline.parse_eml_file(args.eml)
        elif args.headers_file:
            text = Path(args.headers_file).read_text(encoding="utf-8", errors="replace")
            chain = AtlasHeaderPipeline.parse_header_string(text)
        else:
            text = _read_stdin()
            chain = AtlasHeaderPipeline.parse_header_string(text)
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: parsing failed: {exc}", file=sys.stderr)
        return 1

    payload = _chain_to_dict(chain, include_raw=not args.no_raw)
    if args.compact:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

