# Changelog

All notable changes to HUNTЕRТRACE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-01-15

### Added
- Initial release
- 7-stage attribution pipeline
- 12 VPN bypass techniques
- Webmail provider IP leak detection (Gmail, Yahoo, Outlook)
- Timezone-based attribution
- Bayesian multi-signal fusion
- Infrastructure graph centrality analysis
- Campaign correlation
- Actor profiling
- Command-line interface
- Python API
- Batch processing
- Campaign intelligence mode

### Technical Details
- 14,990 lines of Python code
- 91 classes, 36 functions
- Support for Python 3.8+
- Core components:
  - Email header extraction (RFC 2822)
  - IP classification (Tor/VPN/Proxy)
  - WHOIS enrichment
  - Geolocation (city-level)
  - Threat intelligence integration
  - Attribution confidence tiers (0-4)

### Performance
- 73% accuracy (Bayesian attribution)
- 82% accuracy (with graph features)
- 67% webmail IP extraction rate
- 2.3× better than IP geolocation alone

[1.0.0]: https://github.com/akshaydotweb/huntertrace/releases/tag/v1.0.0
