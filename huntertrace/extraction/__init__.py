"""
extraction — Real-IP identification through VPN/proxy/webmail layers.

Three complementary extractors (use together for best coverage):
  basic        → RealIPExtractor       fast, header-based
  advanced     → AdvancedRealIPExtractor  11-technique research implementation
  webmail      → WebmailRealIPExtractor   12 provider-specific header patterns
  vpn_backtrack → RealIPBacktracker      12 VPN backtracking techniques
"""
from huntertrace.extraction.basic import RealIPExtractor, extract_real_ip_summary
from huntertrace.extraction.advanced import (
    AdvancedRealIPExtractor,
    extract_real_ip_summary as extract_advanced_summary,
)
from huntertrace.extraction.webmail import (
    run_webmail_extraction,
    WebmailExtractionResult,
)
from huntertrace.extraction.vpnBacktrack import RealIPBacktracker

__all__ = [
    "RealIPExtractor", "extract_real_ip_summary",
    "AdvancedRealIPExtractor", "extract_advanced_summary",
    "run_webmail_extraction", "WebmailExtractionResult",
    "RealIPBacktracker",
]
