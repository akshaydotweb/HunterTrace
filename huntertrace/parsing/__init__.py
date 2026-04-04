"""HunterTrace Atlas parsing package."""

from huntertrace.parsing.header_parser import HeaderParser
from huntertrace.parsing.hop_builder import HopChainBuilder
from huntertrace.parsing.models import Hop, HopChain, ValidationFlag


class AtlasHeaderPipeline:
    """High-level deterministic parser pipeline for Received hop reconstruction."""

    @staticmethod
    def parse_eml_file(path: str) -> HopChain:
        """Parse an EML file into a validated hop chain."""

        received = HeaderParser.parse_from_file(path)
        return HopChainBuilder.build(received)

    @staticmethod
    def parse_header_string(raw_email_or_headers: str) -> HopChain:
        """Parse raw headers/email text into a validated hop chain."""

        received = HeaderParser.parse_from_string(raw_email_or_headers)
        return HopChainBuilder.build(received)


__all__ = [
    "Hop",
    "HopChain",
    "ValidationFlag",
    "HeaderParser",
    "HopChainBuilder",
    "AtlasHeaderPipeline",
]

