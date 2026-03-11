"""
extraction — Real IP extraction: basic, advanced, webmail, VPN backtracking.
"""
from huntertrace.extraction.basic import RealIPExtractor, extract_real_ip_summary
from huntertrace.extraction.advanced import (
    AdvancedRealIPExtractor,
    RealIPAnalysis,
    ExtractionTechnique,
)
from huntertrace.extraction.webmail import (
    run_webmail_extraction,
    WebmailExtractionResult,
)
from huntertrace.extraction.vpnBacktrack import (
    RealIPBacktracker,
    BacktrackResult,
    RealIPSignal,
)

__all__ = [
    "RealIPExtractor", "extract_real_ip_summary",
    "AdvancedRealIPExtractor", "RealIPAnalysis", "ExtractionTechnique",
    "run_webmail_extraction", "WebmailExtractionResult",
    "RealIPBacktracker", "BacktrackResult", "RealIPSignal",
]