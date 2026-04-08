# Phase 5 Quick Reference Guide

## Installation & Setup

```bash
# No additional dependencies required (uses existing HunterTrace modules)
# All code is in: huntertrace/evaluation/
```

## CLI Quick Start

### Basic Evaluation

```bash
# Evaluate JSONL dataset
python3 -m huntertrace.evaluation \
  --dataset evaluation_dataset.jsonl \
  --out evaluation_report.json

# Evaluate directory
python3 -m huntertrace.evaluation \
  --dataset /path/to/emails \
  --format directory \
  --out report.json
```

### Advanced Options

```bash
# With custom config and sampling
python3 -m huntertrace.evaluation \
  --dataset dataset.jsonl \
  --config scoring_config.json \
  --limit 100 \
  --error-sample-size 20 \
  --out report.json \
  --verbose
```

### See All Options

```bash
python3 -m huntertrace.evaluation --help
```

## Python API Quick Start

### Minimal Example

```python
from huntertrace.evaluation import (
    load_dataset,
    AtlasEvaluator,
    generate_report,
)

# Load dataset
samples = load_dataset("dataset.jsonl")

# Create evaluator with signal extractor
def get_signals(path):
    # Your implementation here
    analyzer = Analyzer()
    result = analyzer.analyze(path)
    return result.signals, result.correlation

evaluator = AtlasEvaluator(signal_extractor=get_signals)

# Run evaluation
context = evaluator.evaluate(samples)

# Generate and save report
report = generate_report(context)
report.save("report.json")

# Access metrics
print(f"Accuracy: {context.overall_metrics.accuracy:.4f}")
print(f"False Attribution Rate: {context.overall_metrics.false_attribution_rate:.4f}")
```

### Access Different Results

```python
# Overall metrics
metrics = context.overall_metrics
print(f"Accuracy: {metrics.accuracy:.4f}")
print(f"FAR: {metrics.false_attribution_rate:.4f}")
print(f"Abstention: {metrics.abstention_rate:.4f}")

# Calibration analysis
cal = context.calibration_metrics
print(f"ECE: {cal.ece:.4f}")
print(f"Brier: {cal.brier_score:.4f}")

# Stratified analysis
for strata in context.stratified_metrics:
    print(f"{strata.stratum_name}: {strata.metrics.accuracy:.4f}")

# Threshold analysis
for threshold in context.threshold_analysis:
    print(f"Threshold {threshold.threshold:.1f}: FAR={threshold.false_attribution_rate:.4f}")

# Error cases
for error in context.error_cases:
    print(f"{error.error_type}: {error.predicted_region} vs {error.ground_truth_region}")
```

## Dataset Formats

### JSONL Format

File: `dataset.jsonl`

```jsonl
{"input_path": "/path/to/email1.eml", "ground_truth_region": "US", "metadata": {...}}
{"input_path": "/path/to/email2.eml", "ground_truth_region": "UK", "metadata": {...}}
```

**Load with**:
```bash
python3 -m huntertrace.evaluation --dataset dataset.jsonl
```

### Directory Format

Structure:
```
emails/
  email1.eml
  email2.eml
  labels.json
```

`labels.json`:
```json
{
  "email1.eml": "US",
  "email2.eml": "UK"
}
```

**Load with**:
```bash
python3 -m huntertrace.evaluation --dataset emails --format directory
```

## Key Metrics

### Understand the Numbers

| Metric | What It Means | Target Value |
|--------|-----------|---------|
| **Accuracy** | Correct predictions / total | High (>0.85) |
| **False Attribution Rate** | Wrong attributions / total attributions | **Very Low (<0.05)** ⚠️ |
| **Precision** | Correct attributions / total attributions | High (>0.9) |
| **Recall** | Correct attributions / total ground truth | Balance needed |
| **Abstention Rate** | Inconclusive decisions / total | Acceptable if FAR is low |
| **Coverage Rate** | Attributed / total | High (>0.8) goal |
| **ECE** | Confidence calibration error | Low (<0.1) |

### Critical Decision: False Attribution Rate

**High FAR** (>10%) → Model is attributing to wrong regions too often → Lower confidence threshold

**Low FAR** (<5%) → Model is reliable when it attributes → Can use higher threshold

## Interpreting Results

### Scenario 1: Good Overall Performance

```
Accuracy:              0.92
False Attribution:     0.02  ✓ Very Good
Abstention:            0.05
Coverage:              0.95  ✓ High
ECE:                   0.08  ✓ Good Calibration
```

**Verdict**: Deploy as-is ✅

### Scenario 2: High Abstention

```
Accuracy:              0.88
False Attribution:     0.01  ✓ Excellent
Abstention:            0.25  ⚠️ High
Coverage:              0.75
```

**Verdict**: Consider lowering confidence threshold to increase coverage
→ Run threshold analysis to find optimal point

### Scenario 3: Poor Calibration

```
Accuracy:              0.80
False Attribution:     0.08  ⚠️
ECE:                   0.22  ⚠️ Poor Calibration
```

**Verdict**: Model is overconfident. Review confidence cap settings
→ Consider lowering max_confidence_cap in ScoringConfig

## Stratified Analysis Meaning

### Clean Signals (consistency_score > 0.7)

Expected: High accuracy, low FAR

```
The email has consistent signals pointing to same region
→ Should perform best
→ If FAR is high here: Fix scoring logic
```

### Conflicting Signals (anomalies present)

Expected: Lower accuracy, possible abstention

```
The email has contradictory signals
→ May trigger abstention (acceptable)
→ If FAR is high here: Too confident on contradictions
```

### Low Observability (signal_count < 5)

Expected: More conservative attribution

```
Limited signals in email
→ May abstain more (acceptable)
→ If FAR is high here: Not enough evidence check
```

## Threshold Analysis Workflow

Finding optimal confidence threshold:

```
1. Run evaluation to get context.threshold_analysis
2. Look at each threshold (0.0 to 0.8)
3. Find sweet spot where:
   - FAR < 5%
   - Coverage > 80%
   - Accuracy > 85%
4. That's your optimal threshold for deployment
```

**Example**:

```python
# Find optimal threshold
for t in context.threshold_analysis:
    if t.false_attribution_rate < 0.05 and t.coverage_rate > 0.80:
        print(f"Optimal threshold: {t.threshold:.1f}")
        print(f"  Accuracy: {t.accuracy:.4f}")
        print(f"  FAR: {t.false_attribution_rate:.4f}")
        break
```

## Error Analysis Workflow

Understanding failures:

```
1. Look at error_samples in report
2. Categorize:
   - false_attribution: Predicted wrong region
   - overconfident_incorrect: High conf but wrong
   - unnecessary_abstention: Abstained when it could decide
3. For each category, ask:
   - Common pattern? (e.g., always confuses US/CA)
   - Fixable? (e.g., config/threshold change or logic issue)
   - Accept as limitation?
```

**Example from context**:

```python
for error in context.error_cases:
    print(f"\n{error.error_type.upper()}")
    print(f"  Sample: {error.sample_id}")
    print(f"  Predicted: {error.predicted_region} @ {error.predicted_confidence:.3f}")
    print(f"  Ground Truth: {error.ground_truth_region}")
    print(f"  Reason: {error.reasoning}")
```

## Saving Results

### JSON Report

```python
report.save("evaluation_report.json")
```

**Contains**:
- All metrics
- Calibration analysis
- Stratified results
- Threshold sweep results
- Top error cases
- Full timestamps and metadata

### Reading Report Later

```python
import json

with open("evaluation_report.json") as f:
    report_data = json.load(f)

print(f"Samples: {report_data['sample_count']}")
print(f"Accuracy: {report_data['summary_metrics']['accuracy']:.4f}")
print(f"FAR: {report_data['summary_metrics']['false_attribution_rate']:.4f}")
```

## Common Tasks

### Task: Compare Two Models

```python
# Model A
config_a = ScoringConfig(max_confidence_cap=0.80)
eval_a = AtlasEvaluator(scoring_config=config_a, ...)
context_a = eval_a.evaluate(samples)
report_a = generate_report(context_a)

# Model B
config_b = ScoringConfig(max_confidence_cap=0.75)
eval_b = AtlasEvaluator(scoring_config=config_b, ...)
context_b = eval_b.evaluate(samples)
report_b = generate_report(context_b)

# Compare
print(f"Model A - FAR: {report_a.summary_metrics['false_attribution_rate']:.4f}")
print(f"Model B - FAR: {report_b.summary_metrics['false_attribution_rate']:.4f}")
```

### Task: Track Performance Over Time

```python
# Save report with date
import datetime
date_str = datetime.datetime.now().strftime("%Y-%m-%d")
report_path = f"reports/evaluation_{date_str}.json"
report.save(report_path)

# Later: Compare across dates
# Load multiple reports and plot trends
```

### Task: Find Problematic Email Scenarios

```python
# Analyze errors by scenario from metadata
error_by_scenario = {}
for error in context.error_cases:
    scenario = error.sample_id
    if scenario not in error_by_scenario:
        error_by_scenario[scenario] = []
    error_by_scenario[scenario].append(error)

# Which scenarios have most errors?
for scenario, errors in sorted(error_by_scenario.items(),
                               key=lambda x: -len(x[1])):
    print(f"{scenario}: {len(errors)} errors")
```

## Troubleshooting

### Problem: All Predictions are "Inconclusive"

**Causes**:
- Signals have no `candidate_region`
- Signals failing minimum evidence requirements

**Fix**:
```python
# Check sample signal
analyzer = Analyzer()
result = analyzer.analyze(sample_path)
for signal in result.signals:
    print(f"{signal.name}: candidate_region={signal.candidate_region}")
```

### Problem: Very High False Attribution Rate

**Causes**:
- Confidence threshold too low
- Scoring config weights misconfigured

**Solutions**:
1. Run threshold analysis to find better threshold
2. Review ScoringConfig settings
3. Check stratified metrics - is FAR localized to specific conditions?

### Problem: Poor Calibration (High ECE)

**Causes**:
- Model is overconfident
- Confidence cap too high

**Solutions**:
1. Lower max_confidence_cap in ScoringConfig
2. Review error cases for patterns

## Performance Optimization

For large datasets (1000+ samples):

```python
# Limit sampling for quick analysis
context = evaluator.evaluate(
    samples[:100],  # Evaluate first 100 only
    error_sample_limit=5
)

# Or use --limit flag in CLI
python3 -m huntertrace.evaluation --dataset big_dataset.jsonl --limit 100
```

## Getting Help

### Run CLI Help

```bash
python3 -m huntertrace.evaluation --help
```

### Read Full Documentation

```bash
cat docs/EVALUATION_FRAMEWORK.md
```

### Run Tests to Verify Installation

```bash
python3 -m pytest tests/test_evaluation.py -v
```

## Key Takeaways

1. **Always check False Attribution Rate** - It's the critical metric
2. **Examine stratified results** - Performance varies by signal quality
3. **Run threshold analysis** - Find optimal operating point
4. **Review error cases** - Understand failure modes
5. **Check calibration** - Ensure confidence is trustworthy
6. **Save reports** - Track performance over time

---

**Questions? Check the full documentation**: `docs/EVALUATION_FRAMEWORK.md`
