"""CLI entry point for HunterTrace API service."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import uvicorn

from huntertrace.service.api import HunterTraceAPI
from huntertrace.service.config import ServiceConfig


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="huntertrace-service",
        description="Run HunterTrace Atlas API service",
    )

    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Server host (default: 0.0.0.0)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Server port (default: 8000)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of worker processes (default: 4)",
    )

    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload on code changes",
    )

    parser.add_argument(
        "--config",
        type=Path,
        help="Path to YAML configuration file",
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    parser.add_argument(
        "--enable-explainability",
        action="store_true",
        help="Enable explainability layer",
    )

    parser.add_argument(
        "--enable-evaluation",
        action="store_true",
        help="Enable evaluation metrics",
    )

    parser.add_argument(
        "--enable-adversarial",
        action="store_true",
        help="Enable adversarial testing",
    )

    args = parser.parse_args()

    # Load configuration
    if args.config:
        config = ServiceConfig.from_file(str(args.config))
    else:
        config = ServiceConfig()

    # Override with CLI arguments
    config.host = args.host
    config.port = args.port
    config.workers = args.workers
    config.reload = args.reload
    config.log_level = args.log_level

    if args.enable_explainability:
        config.enable_explainability = True
    if args.enable_evaluation:
        config.enable_evaluation = True
    if args.enable_adversarial:
        config.enable_adversarial = True

    # Create API
    api = HunterTraceAPI(config)
    app = api.get_app()

    # Start server
    print(f"Starting HunterTrace API on {config.host}:{config.port}")
    print(f"Documentation: http://{config.host}:{config.port}/docs")

    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        workers=config.workers,
        reload=config.reload,
        log_level=config.log_level.lower(),
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
