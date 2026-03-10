#!/usr/bin/env python3
"""Command-line interface for HUNTЕRТRACE."""

import sys
import argparse
from pathlib import Path
from .__version__ import __version__

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='huntertrace',
        description='HUNTЕRТRACE - Advanced Phishing Actor Attribution'
    )
    
    parser.add_argument('--version', action='version', 
                       version=f'huntertrace {__version__}')
    
    subparsers = parser.add_subparsers(dest='command')
    
    # Analyze command
    analyze = subparsers.add_parser('analyze', help='Analyze single email')
    analyze.add_argument('email', help='Path to .eml file')
    analyze.add_argument('-o', '--output', help='Output directory')
    analyze.add_argument('-v', '--verbose', action='store_true')
    
    # Batch command
    batch = subparsers.add_parser('batch', help='Batch analyze emails')
    batch.add_argument('directory', help='Directory with .eml files')
    batch.add_argument('-o', '--output', help='Output directory')
    
    # Campaign command
    campaign = subparsers.add_parser('campaign', help='Campaign analysis')
    campaign.add_argument('directory', help='Directory with .eml files')
    campaign.add_argument('-o', '--output', help='Output directory')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
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
