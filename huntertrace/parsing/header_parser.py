"""Header parsing utilities for extracting Received headers from raw email input."""

from __future__ import annotations

from pathlib import Path
from typing import List

class HeaderParser:
    """Extract and normalize RFC-style headers with folded-line support."""

    @staticmethod
    def parse_from_file(path: str) -> List[str]:
        """Parse a `.eml` file and return raw Received header values in original order."""

        raw = Path(path).read_text(encoding="utf-8", errors="replace")
        return HeaderParser.parse_from_string(raw)

    @staticmethod
    def parse_from_string(raw_email_or_headers: str) -> List[str]:
        """
        Parse raw email text or header-only text and extract Received values.

        Returned values preserve the original Received header content (including
        folded-line structure) so downstream processing keeps auditable raw input.
        """

        header_block = HeaderParser._extract_header_block(raw_email_or_headers)
        folded_headers = HeaderParser._split_headers_preserving_folds(header_block)

        received_values: List[str] = []
        for item in folded_headers:
            if not item.lower().startswith("received:"):
                continue
            raw_value = item.split(":", 1)[1].lstrip(" \t")
            received_values.append(raw_value)

        return received_values

    @staticmethod
    def _extract_header_block(raw_email_or_headers: str) -> str:
        """Return only the header section from a full message or header string."""

        text = raw_email_or_headers.replace("\r\n", "\n").replace("\r", "\n")
        if "\n\n" in text:
            return text.split("\n\n", 1)[0]
        return text

    @staticmethod
    def _split_headers_preserving_folds(header_block: str) -> List[str]:
        """Split header block into unfolded logical headers preserving raw semantics."""

        lines = header_block.split("\n")
        merged: List[str] = []
        current = ""

        for line in lines:
            if not line:
                continue
            if line.startswith((" ", "\t")):
                if current:
                    current += "\n" + line
                else:
                    current = line
                continue

            if current:
                merged.append(current)
            current = line

        if current:
            merged.append(current)

        return merged
