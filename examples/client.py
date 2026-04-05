"""Example client for HunterTrace API service."""

import json
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("Please install requests: pip install requests")
    sys.exit(1)


class HunterTraceClient:
    """Client for HunterTrace Atlas API."""

    def __init__(self, base_url: str = "http://localhost:8000", api_key: str | None = None):
        """Initialize client.

        Args:
            base_url: API base URL (default: http://localhost:8000)
            api_key: Optional API key for authentication
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()

        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})

    def analyze(
        self,
        content: str,
        input_type: str = "eml",
        include_explainability: bool = True,
        include_evaluation: bool = False,
    ) -> dict:
        """Analyze single email.

        Args:
            content: Email content
            input_type: "eml" or "raw"
            include_explainability: Include explainability layer
            include_evaluation: Include evaluation metrics

        Returns:
            Analysis result dictionary
        """
        response = self.session.post(
            f"{self.base_url}/analyze",
            json={
                "input_type": input_type,
                "content": content,
                "options": {
                    "include_explainability": include_explainability,
                    "include_evaluation": include_evaluation,
                },
            },
        )
        response.raise_for_status()
        return response.json()

    def batch_analyze(
        self,
        emails: list[str],
        input_type: str = "eml",
        include_explainability: bool = True,
    ) -> dict:
        """Analyze batch of emails.

        Args:
            emails: List of email contents
            input_type: "eml" or "raw"
            include_explainability: Include explainability layer

        Returns:
            Batch results dictionary
        """
        response = self.session.post(
            f"{self.base_url}/batch",
            json={
                "inputs": [
                    {
                        "input_type": input_type,
                        "content": email,
                        "options": {"include_explainability": include_explainability},
                    }
                    for email in emails
                ]
            },
        )
        response.raise_for_status()
        return response.json()

    def health(self) -> dict:
        """Check service health."""
        response = self.session.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()

    def version(self) -> dict:
        """Get version information."""
        response = self.session.get(f"{self.base_url}/version")
        response.raise_for_status()
        return response.json()

    def config(self) -> dict:
        """Get service configuration."""
        response = self.session.get(f"{self.base_url}/config")
        response.raise_for_status()
        return response.json()


def main():
    """Demo of client usage."""
    import argparse

    parser = argparse.ArgumentParser(description="HunterTrace API client example")
    parser.add_argument("--url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--api-key", help="Optional API key")
    parser.add_argument("--file", type=Path, help="EML file to analyze")
    parser.add_argument("--health", action="store_true", help="Check health")
    parser.add_argument("--version", action="store_true", help="Get version")
    parser.add_argument("--config", action="store_true", help="Get config")

    args = parser.parse_args()

    # Create client
    client = HunterTraceClient(base_url=args.url, api_key=args.api_key)

    try:
        # Health check
        if args.health:
            print("=== Health Check ===")
            result = client.health()
            print(json.dumps(result, indent=2))
            return

        # Version info
        if args.version:
            print("=== Version Info ===")
            result = client.version()
            print(json.dumps(result, indent=2))
            return

        # Config
        if args.config:
            print("=== Service Config ===")
            result = client.config()
            print(json.dumps(result, indent=2))
            return

        # Analyze file
        if args.file:
            if not args.file.exists():
                print(f"File not found: {args.file}")
                return

            print(f"Analyzing {args.file}...")
            with open(args.file) as f:
                content = f.read()

            result = client.analyze(content, include_explainability=True)
            print("\n=== Analysis Result ===")
            print(json.dumps(result, indent=2, default=str))
            return

        # Default: show usage
        parser.print_help()

    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to {args.url}")
        print("Make sure the service is running: python3 -m huntertrace.service")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
