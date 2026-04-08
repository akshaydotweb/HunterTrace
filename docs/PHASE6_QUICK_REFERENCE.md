# Phase 6: Explainability Engine - Quick Reference

## 5-Minute Overview

HunterTrace Atlas Phase 6 provides **explainable, auditable reasoning** for every attribution decision. It transforms raw pipeline outputs into structured explanations suitable for DFIR analysts and enterprise auditors.

## Key Outputs

### 1. Decision Trace (Ordered Steps)
```
Parsed 5 hops from header chain
Extracted 8 signals from headers
Consistency score: 82.5%
Detected 2 contradictions
Signal classification: 6 supporting, 1 conflicting
Final confidence: 72.5%, verdict: attributed
Attribution decision: us-west-2
```

### 2. Signal Contributions (Impact Breakdown)
```
hop_from_ip                    +0.2325  [infrastructure]  supporting
hop_from_host                  +0.1800  [infrastructure]  supporting
temporal_consistency           +0.1575  [temporal]        supporting
anonymity_detected             -0.1200  [quality]         conflicting
```

### 3. Evidence Traceability
```
Signal: hop_from_ip (sig_1)
  Hop 0: 192.0.2.1
    from_ip: 192.0.2.1
    from_host: mail.example.com
    timestamp: 2024-01-01T10:00:00
    parse_confidence: 0.95
```

### 4. Detected Anomalies
```
[HIGH] CONTRADICTION: Timestamps inconsistent between hops
[MED]  ANONYMIZATION: Generic hostnames, excessive relay hops
[LOW]  TEMPORAL: Temporal anomaly flag in hop validation
```

### 5. Analysis Limitations
```
⚠ [evidence] Limited signal diversity constrains attribution confidence
→ [correlation] Low consistency score reflects internal contradictions
• [observability] Anonymization reduces infrastructure observability
```

### 6. Human Explanation
```
The email routing analysis identified 7 signal contributions. These signals 6/7 supported
attribution to us-west-2, resulting in a consistency score of 82.5%. Two contradictions
reduced confidence. Final decision: attributed to us-west-2 with 72.5% confidence.
```

## CLI Usage

```bash
# Generate text report
python3 -m huntertrace.explainability \
  --input analysis.json \
  --format text \
  --output report.txt

# Generate JSON for programmatic consumption
python3 -m huntertrace.explainability \
  --input analysis.json \
  --format json \
  --hops hops.json \
  --output explain.json

# Generate Markdown for documentation
python3 -m huntertrace.explainability \
  --input analysis.json \
  --format markdown \
  --output report.md
```

## Python API

```python
from huntertrace.explainability import ExplainabilityEngine, FormatterFactory

# Create engine with optional hop chain for full traceability
engine = ExplainabilityEngine(hop_chain=hop_chain)

# Generate explainability
result = engine.explain(signals, correlation, attribution)

# Access key components
print(result.decision_trace)      # List of reasoning steps
print(result.contributions)        # Signal impact breakdown
print(result.evidence_links)       # Signal→hop→header traceability
print(result.anomalies)            # Detected anomalies
print(result.limitations)          # Analysis constraints
print(result.explanation)          # Human-readable summary

# Format for output
json_str = FormatterFactory.format(result, "json")
text_str = FormatterFactory.format(result, "text")
markdown_str = FormatterFactory.format(result, "markdown")
```

## Input Format

The explainability engine consumes outputs from the full HunterTrace pipeline:

```json
{
  "signals": [
    {
      "signal_id": "sig_1",
      "name": "hop_from_ip",
      "value": "192.0.2.1",
      "source": "hop_0",
      "confidence": 0.95,
      "evidence": "192.0.2.1 found in hop 0",
      "candidate_region": "us-west-2",
      "group": "infrastructure"
    }
  ],
  "correlation": {
    "consistency_score": 0.825,
    "contradictions": [
      {
        "type": "temporal",
        "signals": ["sig_2", "sig_3"],
        "reason": "Timestamps inconsistent",
        "severity": "high"
      }
    ],
    "anonymization": {
      "detected": true,
      "confidence": 0.85,
      "indicators": ["generic_hostnames", "excessive_hops"],
      "strength": "medium"
    },
    "group_scores": {
      "temporal": 0.8,
      "infrastructure": 0.9,
      "structure": 0.85,
      "quality": 0.75
    },
    "limitations": ["Incomplete header chain"]
  },
  "attribution": {
    "region": "us-west-2",
    "confidence": 0.725,
    "verdict": "attributed",
    "consistency_score": 0.825,
    "signals_used": [
      {
        "signal_id": "sig_1",
        "name": "hop_from_ip",
        "value": "192.0.2.1",
        "role": "supporting",
        "group": "infrastructure",
        "contribution": 0.2325,
        "penalty": 0.0
      }
    ],
    "signals_rejected": [],
    "limitations": []
  }
}
```

## Output Formats

### JSON (Default)

Machine-readable JSON structure with all explainability components.
Best for: Programmatic consumption, log aggregation, SIEM/SOAR integration.

### Text

Human-readable plain text with sections and formatting.
Best for: Analyst review, command-line inspection, simple reporting.

### Markdown

Structured markdown suitable for documentation and reports.
Best for: Long-form reports, wiki integration, audit documentation.

## Key Design Principles

| Principle | Implementation |
|-----------|-----------------|
| **Deterministic** | All outputs sorted; no randomness; seeded algorithms (none used) |
| **Auditable** | Every decision traced to source; full evidence chain |
| **Non-invasive** | No modification to pipeline logic; evaluation layer only |
| **Explainable** | No speculative reasoning; only actual outputs; limitations documented |
| **DFIR-aligned** | Analyst-friendly output; timeline reconstruction enabled |

## Integration Example

```python
from huntertrace.parsing import parse_email_headers
from huntertrace.signals import SignalBuilder
from huntertrace.analysis import AtlasCorrelationEngine, AtlasScoringEngine
from huntertrace.explainability import ExplainabilityEngine, FormatterFactory

# Full pipeline
hop_chain = parse_email_headers(email_headers)
signals = SignalBuilder.build(hop_chain)
correlation = AtlasCorrelationEngine.correlate(signals)
attribution = AtlasScoringEngine.score(signals, correlation)

# Add explainability
engine = ExplainabilityEngine(hop_chain=hop_chain)
explain = engine.explain(signals, correlation, attribution)

# Output
print(FormatterFactory.format(explain, "text"))
```

## Data Structures

### `ExplainabilityResult`
The complete explainability output:
- `verdict`: "attributed" | "inconclusive"
- `region`: Attributed region or None
- `confidence`: 0.0-1.0 confidence score
- `decision_trace`: List[str] - ordered reasoning steps
- `contributions`: List[Contribution] - signal impact breakdown
- `evidence_links`: List[EvidenceLink] - signal→hop→header links
- `anomalies`: List[Anomaly] - detected anomalies
- `limitations`: List[Limitation] - analysis constraints
- `explanation`: str - human-readable summary

### `Contribution`
Signal impact on final score:
- `signal_id/name`: Which signal
- `role`: supporting | conflicting | neutral
- `group`: temporal | infrastructure | structure | quality
- `contribution_score`: Positive impact
- `penalty_score`: Negative penalty
- `net_effect`: contribution - penalty

### `EvidenceLink`
Traceable evidence chain:
- `signal_id/name`: Which signal
- `hop_index`: Which hop in chain
- `hop_from_ip/host`: Extracted address info
- `raw_header_snippet`: Minimal header excerpt (max 200 chars)
- `extracted_fields`: Parsed fields (IP, host, protocol, timestamp, etc.)

### `Anomaly`
Detected anomaly:
- `type`: contradiction | anonymization | temporal | structural | quality
- `severity`: high | medium | low
- `description`: Human-readable explanation
- `source`: correlation | signal | chain

### `Limitation`
Analysis constraint:
- `category`: evidence | observability | correlation | inference
- `description`: What is limited
- `impact`: high | medium | low

## Test Coverage

14 comprehensive tests covering:
- Decision trace generation
- Contribution arithmetic and sorting
- Anomaly extraction
- Limitation categorization
- Output formatting (JSON/text/markdown)
- Determinism verification
- Edge cases (no signals, high confidence)

Run tests:
```bash
python3 -m pytest tests/test_explainability.py -v
```

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `huntertrace/explainability/models.py` | Data structures | 120 |
| `huntertrace/explainability/tracer.py` | Evidence traceability | 110 |
| `huntertrace/explainability/engine.py` | Main orchestrator | 380 |
| `huntertrace/explainability/formatter.py` | Output formatters | 240 |
| `huntertrace/explainability/cli.py` | CLI interface | 210 |
| `tests/test_explainability.py` | Test suite | 350+ |

## Constraints & Guarantees

✅ **Non-invasive**: No changes to pipeline logic
✅ **Deterministic**: Identical input → identical output
✅ **Auditable**: Every decision traced to evidence
✅ **Explainable**: No speculation; limitations documented
✅ **Backward compatible**: Works with existing outputs
✅ **Production-ready**: Type hints, error handling, comprehensive tests

## Common Questions

**Q: Does explainability modify the attribution decision?**
A: No. It only consumes and explains outputs; the scoring engine is unchanged.

**Q: Is the output deterministic?**
A: Yes. Same input always produces identical output. All sorting is deterministic.

**Q: Can I trace a decision to raw header evidence?**
A: Yes, via `evidence_links`. Optional hop chain integration enables full traceability.

**Q: What if I don't have hop chain data?**
A: Explainability works without it, but evidence_links will be empty or inferred.

**Q: How do I integrate this into my pipeline?**
A: Use `ExplainabilityEngine.explain()` after scoring, before output.

## See Also

- `docs/PHASE6_EXPLAINABILITY.md` - Complete technical documentation
- `tests/test_explainability.py` - Test cases and examples
- `huntertrace/explainability/` - Source code
