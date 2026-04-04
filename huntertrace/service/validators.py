"""Input validators for API requests."""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from huntertrace.service.schemas import AnalyzeRequest


class InputValidator:
    """Validates and sanitizes API inputs."""

    # Maximum email size (10 MB)
    MAX_EMAIL_SIZE = 10 * 1024 * 1024

    # Maximum batch size
    MAX_BATCH_SIZE = 1000

    # Email format patterns for quick validation
    EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    @staticmethod
    def validate_request_size(content: str) -> None:
        """Validate email content size."""
        content_bytes = len(content.encode("utf-8"))
        if content_bytes > InputValidator.MAX_EMAIL_SIZE:
            raise ValueError(
                f"Email exceeds maximum size ({content_bytes} > {InputValidator.MAX_EMAIL_SIZE} bytes)"
            )

    @staticmethod
    def validate_eml_structure(content: str) -> None:
        """Basic validation of EML structure."""
        # Should have headers and body
        lines = content.strip().split("\n", 100)
        if len(lines) < 2:
            raise ValueError("Invalid EML format: too short")

        # Should contain common email headers or MIME structure markers
        content_lower = content.lower()
        has_header_or_mime = any(
            marker in content_lower
            for marker in [
                "from:",
                "to:",
                "subject:",
                "received:",
                "date:",
                "mime-version:",
                "content-type:",
            ]
        )
        if not has_header_or_mime:
            raise ValueError("Invalid EML format: missing standard email headers or MIME markers")

    @staticmethod
    def validate_raw_format(content: str) -> None:
        """Basic validation of raw headers."""
        # Raw should have at least some structure
        if not content.strip():
            raise ValueError("Raw content is empty")

        lines = content.strip().split("\n")
        if len(lines) < 1:
            raise ValueError("Raw content too short")

        # Should have header-like lines (contain colons or at least some structure)
        has_structure = any(":" in line for line in lines[:20])
        if not has_structure and len(lines) < 5:
            raise ValueError("Raw content does not appear to contain structured headers")

    @staticmethod
    def validate_request(request: AnalyzeRequest) -> None:
        """Validate full request."""
        # Size check
        InputValidator.validate_request_size(request.content)

        # Format-specific validation
        if request.input_type == "eml":
            InputValidator.validate_eml_structure(request.content)
        elif request.input_type == "raw":
            InputValidator.validate_raw_format(request.content)
        else:
            raise ValueError(f"Unknown input_type: {request.input_type}")

        # Options validation
        if request.options:
            if request.options.confidence_threshold is not None:
                if not (0.0 <= request.options.confidence_threshold <= 1.0):
                    raise ValueError("confidence_threshold must be between 0.0 and 1.0")

            if request.options.adversarial_samples_per_input < 1:
                raise ValueError("adversarial_samples_per_input must be >= 1")

    @staticmethod
    def compute_deterministic_hash(content: str, config_str: str = "") -> str:
        """Compute deterministic hash of input for reproducibility."""
        combined = f"{content}{config_str}".encode("utf-8")
        return hashlib.sha256(combined).hexdigest()[:16]

    @staticmethod
    def sanitize_mask_headers(content: str) -> str:
        """Create a sanitized version for logging (mask sensitive parts)."""
        lines = []
        for line in content.split("\n"):
            # Mask email addresses in logging
            if "@" in line and ("from" in line.lower() or "to" in line.lower()):
                # Keep structure but mask email details
                parts = line.split(":")
                if len(parts) >= 2:
                    line = f"{parts[0]}: [MASKED_EMAIL]"

            # Keep header names but mask values for sensitive headers
            if any(header in line.lower() for header in ["password", "authorization", "token", "cookie"]):
                parts = line.split(":")
                if len(parts) >= 2:
                    line = f"{parts[0]}: [MASKED_VALUE]"

            lines.append(line)

        return "\n".join(lines[:50]) + ("\n... (truncated)" if len(lines) > 50 else "")
