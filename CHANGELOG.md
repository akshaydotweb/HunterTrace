# Changelog

All notable changes to HUNTЕRТRACE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.2] - 2026-04-09

### Added
- Cryptographic ARC chain validation (AMS/AS verification) with upstream auth extraction
- Forwarding classification using ARC results to reduce false spoofing
- ARC signals for explainability and scoring integration

## [1.2.1] - 2026-04-08

### Added
- Actual DKIM cryptographic verification (DNS key fetch, header/body validation, signed header checks)
- SPF/DKIM/DMARC alignment validation with ARC-aware handling for forwarding

## [1.0.3] - 2026-03-11

### Fixed
- IPv6 regex now rejects timestamp false positives (strict segment validation)
- `_is_valid_ipv6()` validates via `ipaddress.IPv6Address` instead of regex alone
- Pipeline stage ordering: Real IP Extraction runs before Stage 3B to populate `unique_ips`
- 0-hop emails (no Received headers): body/URL fallback IP extraction
- Bayesian attribution now runs after result construction, receiving full context
- Sender classification integrated into pipeline with result assignment
- Campaign correlator: `_extract_tz_offset()` handles ISO 8601 `+05:30` format
- Campaign correlator: `_tz_to_country()` expanded from 14→21 entries, fixed duplicate key
- Geolocation/Stage 5 guard refined to avoid misleading "skipped" messages
- `NameError: enc` in attribution engine (added `enrichment_map` parameter)
- `NameError: n_obs` in attribution engine (derived from `profile.campaign_count`)

### Added
- Webmail IP injection into `unique_ips` before Real IP Extraction
- `_country_from_ips()` geolocation fallback in campaign correlator
- Bayesian attribution section in text report (region, ACI, tier, top candidates)
- Sender classification field in `CompletePipelineResult` dataclass
- Example script (`examples/analyze_email.py`)

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

[1.2.2]: https://github.com/akshaydotweb/huntertrace/releases/tag/v1.2.2
[1.2.1]: https://github.com/akshaydotweb/huntertrace/releases/tag/v1.2.1
[1.0.3]: https://github.com/akshaydotweb/huntertrace/releases/tag/v1.0.3
[1.0.0]: https://github.com/akshaydotweb/huntertrace/releases/tag/v1.0.0
