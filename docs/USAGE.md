# Usage Guide

## Single email analysis

```bash
huntertrace suspicious.eml
huntertrace suspicious.eml --output ./reports/ --format json --verbose
huntertrace suspicious.eml --skip-enrichment   # faster, no WHOIS/rDNS
```

## Batch mode

```bash
huntertrace batch ./inbox/ --output ./reports/
```

## Campaign intelligence (v3)

Full actor clustering, TTP profiling, and MITRE ATT&CK mapping:

```bash
huntertrace v3 ./inbox/ --output ./reports/ --verbose
```

Produces:
- `v3_attribution_*.json` — per-actor country attribution
- `v3_actor_profiles_*.json` — TTP profiles and infrastructure fingerprints
- `v3_correlation_*.json` — cross-email clustering results
- `v3_attack_graph_*.html` — interactive 4-tab visualisation

## Offline mode

Correlate from previously-saved pipeline JSON (no network):

```bash
huntertrace offline ./saved_reports/
```

## Python API

```python
from huntertrace import HunterTrace, CampaignAnalyzer

# Single email
ht = HunterTrace()
result = ht.analyze("suspicious.eml")
print(result.primary_region, result.aci_adjusted_prob)

# Campaign mode
ca = CampaignAnalyzer(verbose=True)
ca.run_batch("./inbox/", output_dir="./reports/")

# Direct attribution engine
from huntertrace.attribution import AttributionEngine
engine = AttributionEngine()
result = engine.attribute_from_signals({
    "geolocation_country": "Germany",
    "timezone_offset": "+0100",
    "timezone_region": "Central Europe / West Africa",
}, n_observations=5)

# Forensic scan only
from huntertrace.forensics import ForensicScanSummary
summary = ForensicScanSummary.from_raw(open("email.eml").read())
print(summary.hop_forgery.detected)
```

## Evaluation tools

```bash
# Full evaluation suite
huntertrace eval

# VPN false-positive audit (cross-validates all VPN flags via ipinfo.io)
huntertrace audit --auto

# 3-API geolocation cross-validation (requires network)
huntertrace geovalidate --auto
```

## Reading results

See the [Reading Results wiki page](https://github.com/YOUR_ORG/huntertrace/wiki/Reading-Results) for:
- How to interpret ACI scores and confidence tiers
- Attack graph navigation (4 tabs)
- When NOT to trust an attribution (low n_observations, high ACI penalty)
