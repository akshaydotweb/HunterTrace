# HUNTERTRACE

> Advanced phishing actor attribution using multi-signal Bayesian inference and infrastructure graph analysis

[![PyPI version](https://badge.fury.io/py/huntertrace.svg)](https://badge.fury.io/py/huntertrace)
[![Python Versions](https://img.shields.io/pypi/pyversions/huntertrace.svg)](https://pypi.org/project/huntertrace/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

HUNTERTRACE is an open-source phishing attribution engine that identifies the **geographic origin of phishing actors** with **73% accuracy** — even when they operate behind VPNs, proxies, or Tor. With infrastructure graph analysis enabled, accuracy reaches **82%**.

Traditional email forensics relies on IP geolocation alone (~31% accuracy). HUNTERTRACE fuses **8+ orthogonal signals** through Bayesian inference:

| Signal | Source | VPN-Resistant |
|--------|--------|:---:|
| Webmail IP leaks | X-Originating-IP, X-Sender-IP headers | Yes |
| Timezone offset | Date header / Received chain | Yes |
| Language fingerprint | Content-Type charset, Subject encoding | Yes |
| Infrastructure reuse | Graph centrality across campaigns | Yes |
| Hop chain forgery | Received header consistency | Partial |
| VPN exit node mapping | ASN + hosting provider classification | N/A |
| SPF/DKIM/DMARC | Authentication results | Partial |
| Webmail provider | Header fingerprinting (Gmail/Yahoo/Outlook) | Yes |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HUNTERTRACE PIPELINE                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Stage 1: Header Extraction (RFC 2822 parsing)              │
│      ↓                                                      │
│  Webmail IP Leak Detection (X-Originating-IP extraction)    │
│      ↓                                                      │
│  Stage 2: IP Classification (VPN/Tor/Proxy/Residential)     │
│      ↓                                                      │
│  Stage 3A: Enrichment (WHOIS, ASN, hosting provider)        │
│      ↓                                                      │
│  VPN Backtrack Analysis (12 bypass techniques)              │
│      ↓                                                      │
│  Real IP Extraction (strips proxy layers)                   │
│      ↓                                                      │
│  Stage 3B: Threat Intelligence                              │
│  Stage 3C: Correlation Analysis                             │
│      ↓                                                      │
│  Stage 4: Geolocation (city-level, IPv4 + IPv6)             │
│      ↓                                                      │
│  Stage 5: Attribution Analysis (evidence packaging)         │
│      ↓                                                      │
│  Bayesian Multi-Signal Fusion (ACI confidence scoring)      │
│      ↓                                                      │
│  Sender Classification (hop forgery + timezone analysis)    │
│      ↓                                                      │
│  Output: JSON report + text summary + attack graph HTML     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
pip install huntertrace
```

### Python API

```python
from huntertrace import HunterTrace

# Run the full 7-stage pipeline
pipeline = HunterTrace(verbose=True)
result = pipeline.run("phishing.eml")

# Generate text report
report = result.generate_report()
print(report.generate_text_report())

# Access Bayesian attribution
bayes = result.bayesian_attribution
if bayes:
    print(f"Region: {bayes.primary_region}")
    print(f"Confidence: {bayes.aci_adjusted_prob:.1%}")
    print(f"Tier: {bayes.tier} — {bayes.tier_label}")
```

### Command Line

```bash
# Single email analysis
huntertrace analyze phishing.eml --verbose

# Batch processing
huntertrace batch emails/ -o results/

# Campaign correlation (cross-email actor linking)
huntertrace campaign emails/ -o campaign_report/
```

## Performance

Evaluated on a corpus of phishing emails with known ground-truth origins:

| Method | Region Accuracy | Notes |
|--------|:-:|---|
| IP Geolocation Only | 31% | Baseline |
| Timezone Only | 52% | VPN-resistant but coarse |
| **HUNTERTRACE (Bayesian)** | **73%** | Multi-signal fusion |
| **HUNTERTRACE (+ Graph)** | **82%** | With infrastructure reuse detection |

## Key Techniques

### Webmail Provider IP Leak Detection
Gmail, Yahoo, and Outlook inject the sender's real IP into headers like `X-Originating-IP` and `X-Sender-IP`. HUNTERTRACE detects these leaks with a **67% extraction rate** across webmail-originated phishing emails.

### Timezone-Based VPN Bypass
The `Date:` header timezone offset reveals the sender's local time regardless of VPN usage. Combined with `Received:` chain timing analysis, this provides a VPN-resistant geographic signal.

### Infrastructure Graph Centrality
When analyzing multiple emails (batch/campaign mode), HUNTERTRACE builds an infrastructure reuse graph and applies centrality metrics to identify shared attacker infrastructure — providing a **+9% accuracy boost**.

### Bayesian Multi-Signal Fusion
All signals are combined using likelihood ratios and Bayesian updating. The Adversarial Confidence Index (ACI) adjusts for evasion attempts, producing calibrated confidence tiers (0–4).

### VPN Backtrack Analysis
12 techniques to identify the real origin behind VPN/proxy layers, including ASN classification, exit node fingerprinting, and webmail header correlation.

## Project Structure

```
huntertrace/
├── core/           # Main pipeline + orchestrator
├── extraction/     # IP extraction (basic, advanced, VPN backtrack, webmail)
├── enrichment/     # Geolocation, WHOIS, hosting provider, IP classification
├── attribution/    # Bayesian engine + evidence analysis
├── analysis/       # Campaign correlator, sender classifier, actor profiler
├── graph/          # Attack graph builder, centrality engine
├── forensics/      # Header forensic scanner
├── cli.py          # Command-line interface
└── assets/         # HTML templates, logos
```

## Requirements

- Python 3.8+
- networkx >= 2.6
- numpy >= 1.20
- requests >= 2.25

### Optional Dependencies

```bash
# Graph community detection (for campaign analysis)
pip install huntertrace[graph]

# WHOIS enrichment
pip install huntertrace[whois]

# Everything
pip install huntertrace[all]
```

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [Changelog](CHANGELOG.md)

## Citation

If you use HUNTERTRACE in your research:

```bibtex
@software{huntertrace2026,
  author = {Akshay V},
  title = {HUNTERTRACE: Advanced Phishing Actor Attribution Using Multi-Signal Bayesian Inference},
  year = {2026},
  url = {https://github.com/akshaydotweb/huntertrace}
}
```

## License

MIT License — see [LICENSE](LICENSE)

## Disclaimer

This tool is intended for **legitimate security research, incident response, and law enforcement** use only. Always obtain proper authorization before analyzing emails. The authors are not responsible for misuse.

## Contact

- GitHub: [@akshaydotweb](https://github.com/akshaydotweb)
- Email: akshayvmudaliar@gmail.com
