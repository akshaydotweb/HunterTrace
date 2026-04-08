# HunterTrace Processing Flow Visualization

## Overview

The Processing Flow visualization is a **forensic pipeline explorer** that shows how emails are parsed, analyzed, and attributed through the HunterTrace multi-layer graph system.

**4 Key Features:**
- **Multi-layer graph**: Emails → Hops → Signals → Correlation → Attribution → Verdict
- **Bulk handling**: Deduplication, clustering, infrastructure sharing visualization
- **Interactive traceability**: Click any node/edge to explore forensic reasoning
- **Real-time ready**: Animation-capable for live pipeline runs

---

## Architecture

### Layers (Left → Right Flow)

| Layer | Description | Node Type | Color |
|-------|-------------|-----------|-------|
| **Input** | Email messages | Rectangle | `#fecaca` (red) |
| **Hop Chain** | SMTP servers / IPs | Circle | `#d1d5db` (gray) |
| **Signals** | Extracted features (IP, ASN, timing) | Circle (small) | Blue/Green/Yellow |
| **Correlation** | Feature consistency analysis | Diamond | Green (consistent) / Red (contradictions) |
| **Attribution** | Confidence scoring | Circle | Blue (high) / Orange (low) |
| **Verdict** | Final classification | Highlighted rect | Red (malicious) / Green (benign) / Gray (unknown) |

### Edge Meanings

- **Email → Hop**: SMTP routing path (hop index)
- **Hop → Signal**: Feature extraction from headers
- **Signal → Correlation**: Evidence integration
- **Correlation → Attribution**: Scoring
- **Attribution → Verdict**: Final decision

### Visualization Modes

**1. All Emails** - Every email as separate path
- Shows all 1-N parallel flows
- Useful for pattern recognition
- Scalability: ~50 emails comfortable

**2. Clustered** - Deduplicated infrastructure
- Same hop/signal nodes reused
- Counts: "2 emails" badge
- Shows attacker infrastructure graph
- Scalability: ~1000 emails

**3. Single Email** - Focused drill-down
- Full forensic chain for one email
- Click-to-explore raw headers
- Educational/validation tool

---

## Data Schema

### Input Format: `FLOW_DATA`

```javascript
[
  {
    // Email metadata
    id: "email_123",
    from: "attacker@domain.com",
    to: "victim@company.com",
    subject: "Urgent: Action Required",
    received_at: "2024-01-15T10:32:00Z",

    // Hop chain (SMTP routing)
    hop_chain: [
      {
        index: 0,
        server: "smtp.attacker.com",
        ip: "192.0.2.1",
        asn: "AS12345",
        country: "RU",
        timestamp: "2024-01-15T10:31:00Z",

        // Signals extracted from this hop
        signals: [
          {
            type: "ip",              // ip | asn | timing | tls_cert | reverse_dns
            value: "192.0.2.1",
            confidence: 0.95,
            source: "received-from-header"
          },
          {
            type: "asn",
            value: "AS12345",
            confidence: 0.88,
            source: "ip-geolocation"
          }
        ]
      },
      {
        index: 1,
        server: "mail.company.com",
        ip: "203.0.113.5",
        asn: "AS64496",
        country: "US",
        timestamp: "2024-01-15T10:32:00Z",
        signals: [
          {
            type: "reverse_dns",
            value: "mail.company.com",
            confidence: 1.0,
            source: "dns-record"
          }
        ]
      }
    ],

    // Correlation analysis
    correlation: {
      strength: "high",          // high | medium | low
      consistent_signals: 3,
      contradictions: 0,
      geography_consistent: true,
      timing_consistent: true
    },

    // Attribution result
    attribution: {
      confidence: 0.87,          // 0.0 - 1.0
      top_region: "Eastern Europe",
      regions: [
        {name: "Eastern Europe", probability: 0.45},
        {name: "Russia", probability: 0.35},
        {name: "Unknown", probability: 0.20}
      ]
    },

    // Final verdict
    verdict: {
      status: "malicious",       // malicious | benign | suspicious | unknown
      confidence: 0.91,
      primary_reason: "infrastructure-overlap",
      risks: ["spoofing", "open-relay", "compromised-account"]
    }
  }
  // ... more emails
]
```

### Node Structure (Internal)

```javascript
{
  id: "unique-key",               // "email_123", "hop_192.0.2.1", etc
  type: "email|hop|signal|correlation|attribution|verdict",
  label: "Display Text",
  color: "#hexcolor",
  layer: 0-5,                     // Layer index
  x: number,                      // Computed by layer
  y: number,                      // Computed by density
  size: 12,                       // Node radius
  meta: {                         // Click-explore data
    from: "attacker@domain.com",
    to: "victim@company.com",
    ip: "192.0.2.1",
    signal_type: "ip",
    value: "192.0.2.1",
    confidence: 0.95
  }
}
```

### Edge Structure (Internal)

```javascript
{
  x1, y1: number,                 // Source coords
  x2, y2: number,                 // Target coords
  type: "route|signal|correlation|attribution|verdict",
  label: "hop 0",                 // Display label
  shared: boolean,                // Multi-email shared node
  highlight: boolean              // Animation state
}
```

---

## Integration: Connect to HunterTrace API

### From Batch Endpoint

Use the **`/batch`** endpoint output to populate `FLOW_DATA`:

```bash
curl -X POST http://localhost:8000/batch \
  -H "Content-Type: application/json" \
  -d '{
    "inputs": [
      {"input_type": "email", "content": "From: ..."},
      {"input_type": "email", "content": "From: ..."}
    ]
  }' > batch_results.json
```

**Transform `batch_results.json` → `FLOW_DATA`:**

```python
#!/usr/bin/env python3
"""Transform HunterTrace batch API output to flow visualization format."""

import json
from huntertrace.evaluation.evaluator import Evaluator
from huntertrace.service.schemas import BatchResponse

def batch_to_flow_data(batch_results: BatchResponse) -> list:
    """Convert batch API results to visualization format."""
    flow_data = []

    for i, result in enumerate(batch_results.results):
        email_entry = {
            "id": f"email_{i}",
            "from": result.metadata.get("from", "unknown"),
            "to": result.metadata.get("to", "unknown"),
            "subject": result.metadata.get("subject", "No subject"),
            "received_at": result.metadata.get("received_at"),

            # Build hop chain from parsing stage
            "hop_chain": build_hop_chain(result),

            # Correlation from scoring
            "correlation": {
                "strength": infer_strength(result.confidence),
                "consistent_signals": count_signals(result),
                "contradictions": 0,  # From evaluation if available
                "geography_consistent": True,
                "timing_consistent": True
            },

            # Attribution from scoring result
            "attribution": {
                "confidence": result.confidence,
                "top_region": result.region or "Unknown",
                "regions": build_region_list(result)
            },

            # Verdict from result
            "verdict": {
                "status": "malicious" if result.verdict == "malicious" else "benign",
                "confidence": result.confidence,
                "primary_reason": "sig-correlation",
                "risks": extract_risks(result)
            }
        }
        flow_data.append(email_entry)

    return flow_data


def build_hop_chain(result):
    """Extract hop chain from parsing."""
    hops = []
    if hasattr(result, 'hop_chain'):
        for i, hop in enumerate(result.hop_chain):
            hop_entry = {
                "index": i,
                "server": hop.hostname or "unknown",
                "ip": hop.ip or "unknown",
                "asn": hop.asn or "unknown",
                "country": hop.country or "unknown",
                "timestamp": hop.timestamp,
                "signals": []
            }

            # Add signals from this hop's metadata
            if hop.ip:
                hop_entry["signals"].append({
                    "type": "ip",
                    "value": hop.ip,
                    "confidence": 0.95,
                    "source": "received-header"
                })
            if hop.asn:
                hop_entry["signals"].append({
                    "type": "asn",
                    "value": hop.asn,
                    "confidence": 0.88,
                    "source": "ip-geolocation"
                })

            hops.append(hop_entry)

    return hops


def count_signals(result) -> int:
    """Count signals from results."""
    count = 0
    if hasattr(result, 'hop_chain'):
        for hop in result.hop_chain:
            if hop.ip: count += 1
            if hop.asn: count += 1
    return count


def infer_strength(confidence: float) -> str:
    """Map confidence to correlation strength."""
    if confidence > 0.8:
        return "high"
    elif confidence > 0.5:
        return "medium"
    return "low"


def build_region_list(result):
    """Build region probability distribution."""
    regions = [
        {"name": result.region or "Unknown", "probability": result.confidence}
    ]
    remaining = 1.0 - result.confidence
    if remaining > 0:
        regions.append({"name": "Other", "probability": remaining})
    return regions


def extract_risks(result):
    """Extract risk indicators."""
    risks = []
    # Infer from confidence and verdict
    if result.confidence < 0.6:
        risks.append("low-confidence")
    return risks


if __name__ == "__main__":
    # Load batch results
    with open("batch_results.json") as f:
        batch_json = json.load(f)

    # Transform
    flow_data = batch_to_flow_data(batch_json)

    # Output
    with open("flow_data.json", "w") as f:
        json.dump(flow_data, f, indent=2)

    print(f"Converted {len(flow_data)} emails to flow format")
```

**Insert into HTML:**

```html
<script>
  const __FLOW_DATA_JSON__ = {FLOW_DATA};
</script>
```

---

## Interaction Guide

### Click Actions

| Target | Action | Result |
|--------|--------|--------|
| Email node | Click | Show: from, to, subject |
| Hop node | Click | Show: IP, ASN, country, raw header |
| Signal node | Click | Show: type, value, confidence |
| Correlation node | Click | Show: consistency, contradictions |
| Attribution node | Click | Show: confidence, regions |
| Verdict node | Click | Show: status, reasoning, risks |
| Edge | Click | Show: connection type, data flow |

### Hover Actions

| Target | Action | Result |
|--------|--------|--------|
| Email → Verdict path | Hover | Highlight full forensic chain in color |
| Shared hop (e.g., "2 emails") | Hover | Highlight all emails using this hop |
| Signal → Correlation edge | Hover | Show evidence linkage |

### Controls

- **Mode selector**: Switch between "All", "Clustered", "Single"
- **Email selector**: (Single mode) Pick specific email
- **Reset View**: Zoom back to default (D3 zoom still available)
- **Toggle Labels**: Hide/show node text for less clutter

---

## Color Semantics

### Node Colors

**Input Layer:**
- `#fecaca` - Email (neutral)

**Hop Layer:**
- `#d1d5db` - Server/IP (gray, neutral)

**Signal Layer:**
- `#93c5fd` (blue) - IP-based signal
- `#86efac` (green) - ASN signal
- `#fbbf24` (yellow) - Timing signal
- More signal types: TLS cert, reverse DNS (variations)

**Correlation Layer:**
- `#66bb6a` (green) - Consistent signals
- `#ef5350` (red) - Contradictions detected

**Attribution Layer:**
- `#2563eb` (blue) - High confidence (>0.7)
- `#f59e0b` (orange) - Low confidence (<0.7)

**Verdict Layer:**
- `#E63946` (red) - Malicious
- `#10b981` (green) - Benign
- `#9ca3af` (gray) - Unknown/Suspicious

---

## Scalability Notes

### Single Email (Mode: Single)
- Typical: 5-20 hops, 10-40 signals
- Rendering: Instant
- Use case: Training, validation, audit trail

### All Emails (Mode: All)
- Comfortable: 10-50 emails
- Performance: 200-800ms render
- Tip: Filter to sample if >100 emails

### Clustered (Mode: Clustered)
- Comfortable: 100-1000 emails
- Deduplication: Collapses shared infrastructure
- Cluster badge: "15 emails" on shared hop
- Performance: 500-2000ms render
- Use case: Campaign analysis, infrastructure mapping

### Large Datasets (>1000 emails)
*Implement:*
1. Virtual scrolling / pagination
2. Layer-by-layer expand (collapse intermediate signals)
3. Heatmap overlay for density
4. Sampling strategy (stratified)

### Optimization Tips

1. **Deduplicate early**: Remove exact duplicates before visualization
2. **Collapse low-confidence paths**: Hide <0.3 confidence edges
3. **Progressive loading**: Render layered-by-layer, left-to-right
4. **WebGL backend (future)**: Swap D3 SVG for Babylon.js for 10K+ nodes

---

## Example: Full Flow

```
1. User uploads batch of 100 phishing emails
   ↓
2. HunterTrace /batch endpoint processes all
   ↓
3. Results transformed to FLOW_DATA
   ↓
4. Visualization loads in "Clustered" mode
   ↓
5. User sees:
   - 4 unique attacker IPs (hop nodes)
   - 6 unique ASNs (signal nodes)
   - 3 contradicted timezone claims (red nodes)
   - 85 emails merged into clusters
   - Top candidate region: "Russia" (0.73 confidence)
   ↓
6. User clicks one shared hop ("85 emails using 192.0.2.1")
   ↓
7. Sidebar shows raw header, ASN, geolocation
   ↓
8. User clicks "Single mode" to drill one specific email
   ↓
9. Full forensic chain shown with reasoning
```

---

## Testing

### Manual Test Data

```javascript
// Minimal valid example
const FLOW_DATA = [
  {
    id: "email_1",
    from: "sender@attacker.ru",
    to: "target@company.com",
    subject: "Invoice Approval",
    hop_chain: [
      {
        index: 0,
        server: "mail.attacker.ru",
        ip: "192.0.2.5",
        asn: "AS12345",
        signals: [{type: "ip", value: "192.0.2.5", confidence: 0.95}]
      }
    ],
    correlation: {
      strength: "high",
      consistent_signals: 1,
      contradictions: 0
    },
    attribution: {
      confidence: 0.85,
      top_region: "Russia"
    },
    verdict: {
      status: "malicious",
      confidence: 0.88
    }
  }
];
```

### Automated Testing

```bash
# Validate flow data schema
pytest tests/test_flow_visualization.py -v

# Generate sample flow data
python scripts/generate_flow_data.py \
  --emails 50 \
  --output flow_data.json

# Render locally
open processing_flow_visualization.html
```

---

## Future Extensions

1. **Real-time animation**: Animate node appearance as pipeline processes
2. **Timeline scrubber**: Replay analysis stages in sequence
3. **Explainability chain**: Click signal → see contributing features
4. **Comparison view**: Side-by-side email analysis
5. **Export**: PDF report with highlighted chains
6. **3D layout**: Layer depth for very large datasets
