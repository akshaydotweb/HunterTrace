#!/usr/bin/env python3
"""
Example: Analyze a single phishing email with HunterTrace.

Usage:
    python examples/analyze_email.py path/to/phishing.eml
    python examples/analyze_email.py path/to/phishing.eml --verbose
    python examples/analyze_email.py path/to/phishing.eml -o ./report
"""

import sys
import json
from pathlib import Path

# ── pip install huntertrace ──
from huntertrace import HunterTrace


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_email.py <email.eml> [--verbose] [-o OUTPUT_DIR]")
        sys.exit(1)

    email_path = sys.argv[1]
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    output_dir = None
    if "-o" in sys.argv:
        idx = sys.argv.index("-o")
        if idx + 1 < len(sys.argv):
            output_dir = sys.argv[idx + 1]

    if not Path(email_path).exists():
        print(f"Error: file not found — {email_path}")
        sys.exit(1)

    # ── Run the 7-stage pipeline ──
    pipeline = HunterTrace(verbose=verbose)
    result = pipeline.run(email_path)

    # ── Generate text report ──
    report = result.generate_report()
    text_report = report.generate_text_report()
    print(text_report)

    # ── Optionally save JSON ──
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        json_path = out / (Path(email_path).stem + ".json")
        json_path.write_text(json.dumps(report.to_json(), indent=2, default=str))
        print(f"\nJSON report saved to {json_path}")

    # ── Quick summary ──
    bayes = getattr(result, "bayesian_attribution", None)
    if bayes:
        print(f"\n{'='*60}")
        print(f"  ATTRIBUTION RESULT")
        print(f"  Region     : {bayes.primary_region}")
        print(f"  Confidence : {bayes.aci_adjusted_prob:.1%}")
        print(f"  Tier       : {bayes.tier} — {bayes.tier_label}")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()
