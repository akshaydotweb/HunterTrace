# Phase 6: HunterTrace Atlas Explainability Engine

## Overview

The Phase 6 Explainability Engine provides deterministic, auditable, human-readable explanations for every attribution decision made by HunterTrace Atlas. This layer converts raw pipeline outputs (signals, correlations, scores) into structured explainability artifacts that satisfy DFIR and enterprise audit requirements.

## Design Principles

✅ **Deterministic** - Same input always produces identical output
✅ **Auditable** - Every decision traceable to source evidence
✅ **Non-invasive** - No modification of pipeline logic
✅ **Explainable** - Clear reasoning without speculation
✅ **DFIR-aligned** - Designed for analyst and enterprise use

## Architecture

### Module Structure

```
huntertrace/explainability/
├── models.py          # Data structures for explainability output
├── tracer.py          # Evidence traceability (signal → hop → header)
├── engine.py          # Main explainability orchestrator
├── formatter.py       # Output formatters (JSON/text/markdown)
├── cli.py             # Command-line interface
├── __main__.py        # Module entry point
└── __init__.py        # Module exports
```

### Data Flow

```
Attribution Result ──┐
Correlation Result ──┤──→ ExplainabilityEngine ──→ ExplainabilityResult
Signals ─────────────┼                              ├─ decision_trace
Hop Chain (opt) ─────┘                              ├─ contributions
                                                    ├─ evidence_links
                                          FormatterFactory ├─ anomalies
                                                    ├─ limitations
                                                    └─ explanation
                                                         │
                                                 ┌───────┼───────┐
                                                 ▼       ▼       ▼
                                               JSON    Text  Markdown
```

## Core Components

### 1. Models (`models.py`)

Data structures for explainability output:

#### `Contribution`
Represents quantified impact of a signal on the attribution decision.

```python
@dataclass(frozen=True)
class Contribution:
    signal_id: str                    # Reference to original signal
    signal_name: str                  # Signal type (e.g., "hop_from_ip")
    role: str                         # "supporting" | "conflicting" | "neutral"
    group: Optional[str]              # Signal group (temporal, infrastructure, structure, quality)
    contribution_score: float         # Positive contribution to final score
    penalty_score: float              # Negative penalty applied
    net_effect: float                 # contribution_score - penalty_score
```

#### `EvidenceLink`
Traceable link from decision through signal to raw evidence.

```python
@dataclass(frozen=True)
class EvidenceLink:
    signal_id: str                    # Which signal produced this evidence
    signal_name: str                  # Signal type
    hop_index: int                    # Which hop in the chain
    hop_from_ip: Optional[str]        # Extracted IP address
    hop_from_host: Optional[str]      # Extracted hostname
    raw_header_snippet: str           # Minimal excerpt (max 200 chars)
    extracted_fields: Dict[str, Any]  # Parsed fields: from_ip, from_host, timestamp, etc.
```

#### `Anomaly`
Detected anomaly extracted from correlation analysis.

```python
@dataclass(frozen=True)
class Anomaly:
    type: str                         # "contradiction" | "anonymization" | "temporal" etc.
    severity: str                     # "high" | "medium" | "low"
    description: str                  # Human-readable explanation
    source: str                       # "correlation" | "signal" | "chain"
```

#### `Limitation`
Documented analysis limitation.

```python
@dataclass(frozen=True)
class Limitation:
    category: str                     # "evidence" | "observability" | "correlation" | "inference"
    description: str                  # What is limited
    impact: str                       # "high" | "medium" | "low"
```

#### `ExplainabilityResult`
Complete explainability output for a decision.

```python
@dataclass
class ExplainabilityResult:
    verdict: str                      # "attributed" | "inconclusive"
    region: Optional[str]             # Attributed region (if any)
    confidence: float                 # 0.0 to 1.0

    # Phase 1: Ordered reasoning steps
    decision_trace: List[str]

    # Phase 2: Signal impacts sorted by magnitude
    contributions: List[Contribution]

    # Phase 3: Evidence traceability (decision → signal → hop → header)
    evidence_links: List[EvidenceLink]

    # Phase 4: Detected anomalies
    anomalies: List[Anomaly]

    # Phase 5: Analysis scope and constraints
    limitations: List[Limitation]

    # Phase 5: Human-readable summary
    explanation: str
```

### 2. Evidence Tracer (`tracer.py`)

Builds traceable links from decisions through signals to raw headers.

#### `EvidenceTracer.trace_evidence()`

**Input:**
- `signals`: List of Signal objects
- `hop_indices`: Optional mapping of signal_id → hop indices

**Output:**
- `List[EvidenceLink]`: Sorted deterministically by (signal_id, hop_index)

**Algorithm:**
1. For each signal in signals:
   - Skip if no evidence available
   - Find corresponding hop indices (explicit or inferred)
   - For each hop index:
     - Extract hop object
     - Create EvidenceLink with:
       - Signal reference
       - Raw header snippet (max 200 chars)
       - Extracted fields (IP, hostname, protocol, timestamp, etc.)
2. Sort by (signal_id, hop_index) for determinism

**Inference Strategy:**
If hop_indices not provided, infer from signal evidence:
- Match by IP address (case-insensitive)
- Match by hostname (case-insensitive)
- Return deduplicated indices

### 3. Explainability Engine (`engine.py`)

Orchestrates all explainability phases.

#### `ExplainabilityEngine.explain()`

**Input:**
- `signals`: List[Signal] from signal layer
- `correlation`: CorrelationResult from correlation engine
- `attribution`: AttributionResult from scoring engine

**Output:**
- `ExplainabilityResult` with complete explainability

#### Phase 1: Decision Trace

Build ordered reasoning steps reflecting actual pipeline execution:

```python
def _build_decision_trace():
```

Example trace:
```
1. Parsed 5 hops from header chain
2. Extracted 8 signals from headers
3. Consistency score: 82.5%
4. Detected 2 contradictions (1 high, 1 low severity)
5. Anonymization patterns detected (medium strength)
6. Signal classification: 6 supporting, 1 conflicting
7. 1 signal rejected
8. Final confidence: 72.5%, verdict: attributed
9. Attribution decision: us-west-2
```

Rules:
- Strictly ordered (parsing → signal processing → correlation → scoring → decision)
- Only reflect actual pipeline outputs (no invented reasoning)
- Include contradictions/anomalies counts with severity breakdown
- Show final verdict with confidence

#### Phase 2: Contribution Breakdown

Build contribution list from signal contributions in attribution result.

```python
def _build_contributions():
```

For each signal_contribution in attribution.signals_used:
- Extract original signal for group info
- Calculate net_effect = contribution - penalty
- Create Contribution object

Sort by |net_effect| descending (absolute impact).

Example:
```
Signal                     Role        Group           Net Effect
hop_from_ip               supporting   infrastructure  +0.2325
hop_from_host             supporting   infrastructure  +0.1800
temporal_consistency      supporting   temporal        +0.1575
chain_completeness_score  supporting   quality         +0.0800
anonymity_detected        conflicting  quality         -0.1200
```

#### Phase 3: Evidence Traceability

Link decision → signal → hop → raw header using EvidenceTracer.

```python
def _trace_evidence():
```

Creates deterministic list of EvidenceLink objects showing:
- Which signal identified the evidence
- Which hop it came from
- What address information was extracted
- Snippet of raw header

#### Phase 4: Anomalies Extraction

Extract anomalies from correlation and signals.

```python
def _extract_anomalies():
```

Sources:
1. **Contradictions** from correlation.contradictions
   - Type, severity, reason
2. **Anonymization** patterns from correlation.anonymization
   - Type: "anonymization"
   - Severity matches correlation.anonymization.strength
   - Description includes top indicators
3. **Validation flags** from signals
   - Extract unique flags (TEMPORAL_ANOMALY, BROKEN_CHAIN, etc.)
   - Type: lowercase flag name
   - Severity: medium

Sort deterministically by (type, severity).

#### Phase 5: Limitations Extraction

Extract analysis constraints.

```python
def _extract_limitations():
```

Sources:
1. **Attribution limitations**: From attribution.limitations
2. **Correlation limitations**: From correlation.limitations
3. **Observability limitations**: If anonymization detected
4. **Evidence quality**: If few signals or low consistency

Deduplicate and categorize by impact.

#### Phase 5b: Human Explanation

Generate readable paragraph summarizing the decision.

```python
def _generate_explanation():
```

Template:
```
"The email routing analysis [findings].
These signals [agreement/conflict],
resulting in consistency score of [X].
[Anomalies] reduced confidence.
Final decision: [verdict] with [confidence] confidence."
```

Example:
```
The email routing analysis identified 7 signal contributions.
These signals 6/7 supported attribution,
resulting in a consistency score of 82.5%.
2 contradictions reduced confidence.
Final decision: attributed to us-west-2 with 72.5% confidence.
```

### 4. Formatters (`formatter.py`)

Convert ExplainabilityResult to different output formats.

#### JSON Formatter

Direct serialization of ExplainabilityResult.to_dict().

```json
{
  "verdict": "attributed",
  "region": "us-west-2",
  "confidence": 0.725,
  "decision_trace": ["Parsed 5 hops...", ...],
  "contributions": [
    {
      "signal_id": "sig_1",
      "signal_name": "hop_from_ip",
      "role": "supporting",
      "group": "infrastructure",
      "contribution_score": 0.2325,
      "penalty_score": 0.0,
      "net_effect": 0.2325
    }
  ],
  "evidence_links": [...],
  "anomalies": [...],
  "limitations": [...],
  "explanation": "The email routing analysis..."
}
```

#### Text Formatter

Human-readable plain text with sections and formatting.

```
================================================================================
ATTRIBUTION EXPLAINABILITY REPORT
================================================================================

DECISION SUMMARY
----------------
Verdict:     attributed
Region:      us-west-2
Confidence:  72.5%

EXPLANATION
----------------
The email routing analysis identified 7 signal contributions...

DECISION TRACE
----------------
1. Parsed 5 hops from header chain
2. Extracted 8 signals from headers
...

SIGNAL CONTRIBUTIONS
----------------
+ hop_from_ip                     +0.2325 [infrastructure]
+ hop_from_host                   +0.1800 [infrastructure]
...

DETECTED ANOMALIES
----------------
[HIGH] CONTRADICTION: Timestamps inconsistent between hops
[MED]  TEMPORAL: Temporal anomaly in hop 2

ANALYSIS LIMITATIONS
----------------
⚠ [evidence] Limited signal diversity constrains confidence
→ [correlation] Low consistency score reflects contradictions

================================================================================
```

#### Markdown Formatter

Markdown-formatted output for reports and documentation.

```markdown
# Attribution Explainability Report

## Decision Summary

- **Verdict:** attributed
- **Region:** us-west-2
- **Confidence:** 72.5%

## Explanation

The email routing analysis identified 7 signal contributions...

## Signal Contributions

| Signal | Role | Group | Net Effect |
|--------|------|-------|------------|
| hop_from_ip | supporting | infrastructure | +0.2325 |
...

## Detected Anomalies

### Contradiction (high)

Timestamps inconsistent between hops...

## Analysis Limitations

### Evidence (high)

Limited signal diversity constrains confidence...
```

### 5. CLI Interface (`cli.py`)

Command-line access to explainability engine.

#### Usage

```bash
python3 -m huntertrace.explainability \
  --input analysis_output.json \
  --format text \
  --output report.txt \
  --hops hop_chain.json \
  --verbose
```

#### Arguments

- `--input`: Path to input JSON (required) - must contain signals, correlation, attribution
- `--format`: Output format (json|text|markdown, default: json)
- `--output`: Output file path (default: stdout)
- `--hops`: Optional path to hop chain JSON for full traceability
- `--verbose`: Show processing steps to stderr

#### Input Format

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
    "contradictions": [...],
    "anonymization": {...},
    "group_scores": {...},
    "limitations": [...]
  },
  "attribution": {
    "region": "us-west-2",
    "confidence": 0.725,
    "verdict": "attributed",
    "consistency_score": 0.825,
    "signals_used": [...],
    "signals_rejected": [...],
    "limitations": [...]
  }
}
```

## Test Coverage

### Test Suites

**tests/test_explainability.py** - 14 comprehensive tests:

1. **Decision Trace Tests** (3 tests)
   - Hop count included
   - Contradiction counts included
   - Deterministic ordering

2. **Contribution Tests** (2 tests)
   - Arithmetic correctness (contribution - penalty = net_effect)
   - Sorted by impact descending

3. **Anomaly Tests** (2 tests)
   - Extracts contradictions
   - Extracts anonymization patterns

4. **Limitation Tests** (1 test)
   - Extracts from attribution

5. **Formatter Tests** (3 tests)
   - JSON produces valid JSON
   - Text is readable
   - Markdown is valid

6. **Determinism Tests** (1 test)
   - Identical input → identical output

7. **Edge Case Tests** (2 tests)
   - No signals
   - High confidence attribution

### Test Results

```
tests/test_explainability.py::TestDecisionTrace::test_trace_includes_hop_count PASSED
tests/test_explainability.py::TestDecisionTrace::test_trace_includes_contradictions_count PASSED
tests/test_explainability.py::TestDecisionTrace::test_trace_deterministic_ordering PASSED
tests/test_explainability.py::TestContributions::test_contributions_sum_to_net_effect PASSED
tests/test_explainability.py::TestContributions::test_contributions_sorted_by_impact PASSED
tests/test_explainability.py::TestAnomalies::test_extracts_contradictions PASSED
tests/test_explainability.py::TestAnomalies::test_extracts_anonymization PASSED
tests/test_explainability.py::TestLimitations::test_extracts_from_attribution PASSED
tests/test_explainability.py::TestFormatters::test_json_formatter_valid_json PASSED
tests/test_explainability.py::TestFormatters::test_text_formatter_readable PASSED
tests/test_explainability.py::TestFormatters::test_markdown_formatter_valid_markdown PASSED
tests/test_explainability.py::TestDeterminism::test_same_input_identical_output PASSED
tests/test_explainability.py::TestEdgeCases::test_no_signals PASSED
tests/test_explainability.py::TestEdgeCases::test_high_confidence_attributed PASSED

========================= 14 passed in 0.04s ==========================
```

## Usage Examples

### Python API

```python
from huntertrace.explainability import ExplainabilityEngine, FormatterFactory
from huntertrace.analysis.models import Signal, CorrelationResult, AttributionResult

# Create engine (optional: pass hop_chain for full traceability)
engine = ExplainabilityEngine(hop_chain=hop_chain)

# Generate explainability
result = engine.explain(
    signals=signals,
    correlation=correlation_result,
    attribution=attribution_result
)

# Access explainability components
print("Decision trace:")
for step in result.decision_trace:
    print(f"  - {step}")

print("Contributions:")
for contrib in result.contributions:
    print(f"  {contrib.signal_name}: {contrib.net_effect:+.4f}")

# Format for output
json_output = FormatterFactory.format(result, "json")
text_output = FormatterFactory.format(result, "text")
markdown_output = FormatterFactory.format(result, "markdown")
```

### CLI Usage

```bash
# Generate explainability in text format
python3 -m huntertrace.explainability \
  --input analysis.json \
  --format text \
  --output report.txt

# Generate JSON with full traceability
python3 -m huntertrace.explainability \
  --input analysis.json \
  --format json \
  --hops hops.json \
  --output explain.json \
  --verbose
```

### Integration with Existing Pipeline

```python
from huntertrace.parsing import parse_email_headers
from huntertrace.signals import SignalBuilder
from huntertrace.analysis import AtlasCorrelationEngine, AtlasScoringEngine
from huntertrace.explainability import ExplainabilityEngine, FormatterFactory

# Pipeline execution
hop_chain = parse_email_headers(email_headers)
signals = SignalBuilder.build(hop_chain)
correlation = AtlasCorrelationEngine.correlate(signals)
attribution = AtlasScoringEngine.score(signals, correlation)

# Add explainability
engine = ExplainabilityEngine(hop_chain=hop_chain)
explainability = engine.explain(signals, correlation, attribution)

# Output results
results = {
    "hop_chain": hop_chain,
    "signals": signals,
    "correlation": correlation,
    "attribution": attribution,
    "explainability": explainability,
}

print(FormatterFactory.format(explainability, "text"))
```

## Constraints Satisfied

✅ **DO NOT modify scoring logic**
   - No changes to AtlasScoringEngine
   - Only consumes outputs

✅ **DO NOT modify parser/signals**
   - Evaluation layer only
   - Non-invasive integration

✅ **MUST remain deterministic**
   - Sorted outputs throughout
   - Seeded randomness (none used)
   - No external dependencies

✅ **MUST be reproducible**
   - Same input → identical output
   - Test verified

✅ **MUST be explainable**
   - Per-signal breakdown
   - Clear anomaly categorization
   - Limitation documentation

✅ **MUST NOT use external APIs**
   - Pure Python
   - Only stdlib + existing deps

## Success Criteria Met

✅ Explanation matches system behavior exactly
   - Traces actual pipeline decisions
   - Reports actual signals and their roles
   - Reflects actual correlation results

✅ Every decision is traceable to raw evidence
   - Signal → hop → raw header
   - Deterministic EvidenceLink creation
   - Optional hop chain integration

✅ Contributions are numerically consistent
   - contribution - penalty = net_effect
   - Sorted by impact
   - Auditable totals

✅ No hallucinated reasoning
   - Only reflects actual outputs
   - No speculation beyond evidence
   - Limitations documented

✅ Deterministic output
   - Sorted by signal_id
   - Sorted by hop_index
   - Identical to previous run

✅ Usable by DFIR analysts
   - Text format for humans
   - JSON for parsing
   - Markdown for reports

## Files Modified/Created

**New Files (1,200+ lines):**
- `huntertrace/explainability/models.py` (120 lines)
- `huntertrace/explainability/tracer.py` (110 lines)
- `huntertrace/explainability/engine.py` (380 lines)
- `huntertrace/explainability/formatter.py` (240 lines)
- `huntertrace/explainability/cli.py` (210 lines)
- `huntertrace/explainability/__init__.py` (20 lines)
- `huntertrace/explainability/__main__.py` (5 lines)

**Test Files (350+ lines):**
- `tests/test_explainability.py` (350+ lines)

**Documentation (this file):**
- `docs/PHASE6_EXPLAINABILITY.md` (~500 lines)

## Next Steps

The Phase 6 Explainability Engine is complete and production-ready. Possible future enhancements:

- Interactive HTML visualization of decision trace
- Time-series analysis for header chain evolution
- DFIR report template integration
- Confidence bootstrapping visualization
- Comparative explainability (alternative hypotheses ranking)
- Audit log export (for SIEM/SOAR integration)
