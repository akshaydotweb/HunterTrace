#!/usr/bin/env python3
"""Command-line interface for HUNTЕRТRACE."""

import sys
import argparse
from pathlib import Path
from .__version__ import __version__

_LOGO_FILE = Path(__file__).resolve().parent / 'assets' / 'img' / 'hunterTrace_ascii_logo.txt'


def _load_banner():
    """Load ASCII logo and append version tag."""
    try:
        art = _LOGO_FILE.read_text(encoding='utf-8').rstrip('\n')
        return f"\n{art}\n  HUNTERTRACE v{__version__}\n"
    except Exception:
        return f"\n  HUNTERTRACE v{__version__}\n"


def main():
    """Main CLI entry point."""
    banner = _load_banner()

    parser = argparse.ArgumentParser(
        prog='huntertrace',
        description=(
            f'{banner}\n'
            'Advanced Phishing Actor Attribution Engine\n'
            '\n'
            'A 7-stage forensic pipeline that extracts real IP addresses from\n'
            'email headers, classifies VPN/proxy/webmail layers, enriches IPs\n'
            'with geolocation and WHOIS data, and performs Bayesian multi-signal\n'
            'attribution to identify the likely geographic origin of a phishing\n'
            'actor. Includes MITRE ATT&CK mapping, campaign correlation, and\n'
            'infrastructure reuse detection via graph centrality analysis.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'examples:\n'
            '  huntertrace analyze phish.eml                 Analyze a single email\n'
            '  huntertrace analyze phish.eml -o ./report     Save output to a directory\n'
            '  huntertrace analyze phish.eml -v              Verbose stage-by-stage output\n'
            '  huntertrace batch ./mailbox -o ./results      Batch analyze a folder of .eml files\n'
            '  huntertrace campaign ./mailbox -o ./report    Run campaign correlation across emails\n'
            '\n'
            'pipeline stages:\n'
            '  1. Header Extraction    Parse Received: hops, SPF, DKIM, DMARC\n'
            '  2. Real-IP Extraction   Strip VPN/proxy/webmail layers (11 techniques)\n'
            '  3. IP Classification    Categorise each IP (residential, hosting, VPN, Tor)\n'
            '  4. Enrichment           Geolocation, WHOIS, ASN, hosting provider lookup\n'
            '  5. Attribution          Bayesian inference with ACI confidence scoring\n'
            '  6. Graph Analysis       Infrastructure reuse & centrality boost\n'
            '  7. Forensic Scan        Hop forgery, AI content, tracking pixels, homoglyphs\n'
            '\n'
            'documentation: https://github.com/akshaydotweb/HunterTrace'
        ),
    )
    
    parser.add_argument('--version', action='version', 
                       version=f'huntertrace {__version__}')
    
    subparsers = parser.add_subparsers(dest='command', title='commands',
                                       description='Run huntertrace <command> -h for command-specific help.')
    
    # Analyze command
    analyze = subparsers.add_parser(
        'analyze',
        help='Analyze a single .eml file',
        description=(
            'Run the full 7-stage attribution pipeline on a single email.\n'
            'Outputs a JSON report with IP extraction, geolocation, Bayesian\n'
            'attribution scores, MITRE ATT&CK mappings, and forensic findings.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    analyze.add_argument('email', help='Path to the .eml file to analyze')
    analyze.add_argument('-o', '--output', help='Directory to save the JSON report (default: stdout)')
    analyze.add_argument('-v', '--verbose', action='store_true',
                         help='Print detailed stage-by-stage progress to stderr')
    
    # Batch command
    batch = subparsers.add_parser(
        'batch',
        help='Batch analyze every .eml in a directory',
        description=(
            'Scan a directory for .eml files and run the full pipeline on each.\n'
            'Results are written as individual JSON files in the output folder.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    batch.add_argument('directory', help='Directory containing .eml files')
    batch.add_argument('-o', '--output', help='Directory to save JSON reports (default: ./ht_output)')
    
    # Campaign command
    campaign = subparsers.add_parser(
        'campaign',
        help='Run campaign correlation across multiple emails',
        description=(
            'Analyze a set of emails for shared infrastructure, behavioural\n'
            'fingerprints, and timing patterns to identify coordinated phishing\n'
            'campaigns. Uses graph centrality and clustering to group emails by\n'
            'threat actor.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    campaign.add_argument('directory', help='Directory containing .eml files for correlation')
    campaign.add_argument('-o', '--output', help='Directory to save the campaign report (default: ./ht_output)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    print(banner)

    # Import here to avoid slow startup
    if args.command == 'analyze':
        from .core.pipeline import CompletePipeline
        pipeline = CompletePipeline(verbose=args.verbose)
        result = pipeline.run(args.email)
        print(f"Analysis complete")
        return 0
    
    elif args.command == 'batch':
        from .core.pipeline import CompletePipeline, BatchProcessor
        processor = BatchProcessor(args.directory, verbose=True)
        processor.process_all_emails()
        return 0
    
    elif args.command == 'campaign':
        from .core.orchestrator import HunterTraceV3
        v3 = HunterTraceV3(output_dir=args.output or './output')
        report = v3.run_batch(args.directory)
        return 0
    
    return 1

if __name__ == '__main__':
    sys.exit(main())
