# HUNTERTRACE

<p align="center">
  <img src="assets/hunterTraceLogo.png" alt="HunterTrace Logo" width="400">
</p>

> Advanced phishing actor attribution using multi-signal Bayesian inference and infrastructure graph analysis

[![PyPI version](https://badge.fury.io/py/huntertrace.svg)](https://badge.fury.io/py/huntertrace)
[![Python Versions](https://img.shields.io/pypi/pyversions/huntertrace.svg)](https://pypi.org/project/huntertrace/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Current release: 1.2.3

## Overview

HUNTERTRACE is an open-source phishing attribution engine that identifies the
**geographic origin of phishing actors** through multi-signal Bayesian inference,
combining 8+ orthogonal signals to bypass VPN and proxy obfuscation. Evaluated
on 53 labeled emails, it achieves **52.8% country-level** and **56.6%
region-level** accuracy — outperforming single-signal methods — with larger-scale
validation ongoing.

Traditional email forensics relies on IP geolocation alone (~31% accuracy). HUNTERTRACE fuses **8+ orthogonal signals** through Bayesian inference:

| Signal | Source | VPN-Resistant |
|--------|--------|:---:|
| Webmail IP leaks | X-Originating-IP, X-Sender-IP headers | Yes |
| Timezone offset | Date header / Received chain | Yes |
| Language fingerprint | Content-Type charset, Subject encoding | Yes |
| Infrastructure reuse | Graph centrality across campaigns | Yes |
| Hop chain forgery | Received header consistency | Partial |
| VPN exit node mapping | ASN + hosting provider classification | N/A |
| SPF/DKIM/DMARC/ARC | Authentication results (incl. ARC chain validation) | Partial |
| Webmail provider | Header fingerprinting (Gmail/Yahoo/Outlook) | Yes |

## Architecture

The HunterTrace pipeline is modeled in two complementary views:

- **Single Email Pipeline**: end-to-end analysis for one `.eml` sample
- **Campaign Intelligence Pipeline**: cross-email correlation and actor-level attribution

### Single Email Pipeline

<p align="center">
  <img src="assets/design/huntertrace-single-email-container.svg" alt="HunterTrace Single Email Architecture" width="680" style="max-width: 100%; height: auto;">
</p>

Source: [assets/design/huntertrace-single-email-container.svg](assets/design/huntertrace-single-email-container.svg)

<!-- ### Campaign Intelligence Pipeline

![HunterTrace Campaign Architecture](assets/design/huntertrace-campaign-container.svg)

Source: [assets/design/huntertrace-campaign-container.svg](assets/design/huntertrace-campaign-container.svg) -->



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

Evaluated on a labeled corpus of 53 phishing emails with known ground-truth origins:

| Method | Top-1 Country Accuracy | Notes |
|--------|------------------------|-------|
| IP Geolocation Only | ~31% | Industry baseline |
| Timezone Only | ~52% | VPN-resistant, coarse |
| **HUNTERTRACE (Bayesian)** | **52.8%** | Multi-signal fusion |
| **HUNTERTRACE (+ Graph)** | **56.6%** | Region-level accuracy |

**95% Confidence Interval**: 39.7% – 65.6% (n=53)  
**Webmail IP Leak Rate**: 37.7% of analyzed emails  
**Coverage**: 100% (no failed predictions)

> ⚠️ **Note**: Performance numbers are based on an initial corpus of 53 labeled
> emails. Larger-scale validation is in progress. Region-level accuracy (56.6%)
> is more reliable than country-level given current corpus size.

## ✨ Key Features

- 🎯 Multi-Signal Attribution (8+ signals)
- 🔓 VPN Bypass (webmail leaks, timezone)
- 🕸️ Graph Analysis (infrastructure reuse)
- 📊 Bayesian Fusion (probabilistic)

## 🚀 Quick Start

```bash
git clone https://github.com/akshaydotweb/HunterTrace.git
cd HunterTrace
pip install -r requirements.txt

# Analyze email
python hunterTrace.py analyze phishing.eml
```

## 📖 Documentation

- [Technical Summary](docs/HUNTERTRACE_Technical_Summary.md)
- [Installation Guide](docs/INSTALLATION.md)
- [API Documentation](docs/API.md)

## 🔬 Evaluation

**Dataset**: 53 labeled phishing emails  
**Methodology**: Manual OSINT labeling with ground truth
- Top-1 Country Accuracy: 52.8%
- Top-1 Region Accuracy: 56.6%
- 95% Confidence Interval: 39.7% – 65.6%
- Webmail Leak Rate: 37.7%
- Macro F1: 0.37

See [evaluation/](evaluation/) for full results.

## 🎓 Citation

```bibtex
@software{huntertrace2026,
  author = {[Your Name]},
  title = {HUNTERTRACE: Multi-Signal Phishing Attribution},
  year = {2026},
  url = {https://github.com/akshaydotweb/HunterTrace}
}
```

## 📄 License

MIT License - See [LICENSE](LICENSE)

---

**Black Hat Arsenal 2026 Submission**
