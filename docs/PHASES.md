# HunterTrace Atlas — Complete Implementation Guide

## Overview

HunterTrace Atlas is a deterministic, auditable email origin attribution system for forensic analysis and security research. The complete implementation spans **8 phases**, from parsing to production-grade API service.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Phase Overview](#phase-overview)
3. [API Service Usage](#api-service-usage)
4. [CLI Usage](#cli-usage)
5. [Architecture](#architecture)
6. [Testing](#testing)
7. [Deployment](#deployment)

---

## Quick Start

### For API Users (Phase 8)

```bash
# 1. Install dependencies
pip install -r requirements-service.txt

# 2. Start the service
python3 -m huntertrace.service --port 8000

# 3. Access API docs
# Open: http://localhost:8000/docs

# 4. Test with sample email
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "input_type": "eml",
    "content": "From: sender@example.com\nReceived: from...",
    "options": {"include_explainability": true}
  }'
```

### For CLI Users (Phases 1-4)

```bash
# Parse email
python3 -m huntertrace.parsing --eml "path/to/sample.eml"

# Extract signals
python3 -m huntertrace.signals --eml "path/to/sample.eml"

# Analyze and attribute
python3 -m huntertrace.analysis --eml "path/to/sample.eml" --out result.json
```

### For Researchers (Phase 5 - Evaluation)

```bash
# Evaluate system performance
python3 -m huntertrace.evaluation \
  --dataset "path/to/dataset.jsonl" \
  --out "report.json" \
  --bootstrap-iterations 1000
```

---

## Phase Overview

### Phase 1: Parsing
**Status**: ✅ COMPLETE
**Purpose**: Extract and validate Received hop chain from email headers
**CLI**: `python3 -m huntertrace.parsing --eml file.eml`
**Output**: HopChain with validation flags

### Phase 2: Signals
**Status**: ✅ COMPLETE
**Purpose**: Build normalized, auditable signals from hop chain
**CLI**: `python3 -m huntertrace.signals --eml file.eml`
**Output**: List[Signal] with evidence and confidence

### Phase 3: Correlation
**Status**: ✅ COMPLETE
**Purpose**: Check signal consistency and detect anomalies
**CLI**: Part of analysis pipeline
**Output**: CorrelationResult with consistency score

### Phase 4: Scoring
**Status**: ✅ COMPLETE
**Purpose**: Deterministic 16-phase algorithm for attribution
**CLI**: `python3 -m huntertrace.analysis --eml file.eml`
**Output**: AttributionResult (region, confidence, verdict)

### Phase 5: Evaluation
**Status**: ✅ COMPLETE
**Purpose**: Statistical evaluation, cost analysis, adversarial robustness
**CLI**: `python3 -m huntertrace.evaluation --dataset file.jsonl`
**Output**: EvaluationReport with CIs, costs, robustness metrics

### Phase 6: Explainability
**Status**: ✅ COMPLETE
**Purpose**: Auditable explanation layer for attribution decisions
**CLI**: `python3 -m huntertrace.explainability --input analysis.json`
**Output**: ExplainabilityResult with decision trace and evidence links

### Phase 7: Adversarial Testing
**Status**: ✅ COMPLETE
**Purpose**: Test robustness against 5 attack types
**CLI**: Part of evaluation
**Output**: RobustnessMetrics with attack-specific vulnerability breakdown

### Phase 8: API Service Layer (NEW)
**Status**: ✅ COMPLETE
**Purpose**: Production-grade REST API exposing full pipeline
**CLI**: `python3 -m huntertrace.service --port 8000`
**Output**: FastAPI service with 5 endpoints

---

## API Service Usage (Phase 8)

### Installation

```bash
pip install -r requirements-service.txt
```

### Running the Service

```bash
# Default (localhost:8000)
python3 -m huntertrace.service

# Custom configuration
python3 -m huntertrace.service \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --enable-explainability \
  --log-level INFO

# From YAML config
python3 -m huntertrace.service --config config.service.yaml
```

### API Endpoints

#### POST /analyze
Analyze single email for attribution

```python
import requests

response = requests.post(
    "http://localhost:8000/analyze",
    json={
        "input_type": "eml",  # or "raw"
        "content": "From: sender@...\nReceived: ...",
        "options": {
            "include_explainability": True,
            "include_evaluation": False,
            "include_adversarial": False
        }
    }
)
result = response.json()
# {
#   "region": "US",
#   "confidence": 0.85,
#   "verdict": "attributed",
#   "consistency_score": 0.92,
#   ...
# }
```

#### POST /batch
Analyze up to 1000 emails in batch

```python
response = requests.post(
    "http://localhost:8000/batch",
    json={
        "inputs": [
            {"input_type": "eml", "content": "..."},
            {"input_type": "eml", "content": "..."}
        ]
    }
)
batch_results = response.json()
# {"results": [...], "batch_processing_time_ms": 150.5, "batch_size": 2}
```

#### GET /health
Health check

```python
requests.get("http://localhost:8000/health")
# {"status": "ok", "version": "1.0.0", "uptime_seconds": 3600}
```

#### GET /version
Version info

```python
requests.get("http://localhost:8000/version")
# {"version": "1.0.0", "pipeline_version": "1.0.0", ...}
```

#### GET /config
Configuration

```python
requests.get("http://localhost:8000/config")
# {"version": "1.0.0", "max_batch_size": 1000, "features": {...}}
```

### Python Client

```python
from examples.client import HunterTraceClient

client = HunterTraceClient("http://localhost:8000")

# Single analysis
result = client.analyze(email_content)

# Batch analysis
results = client.batch_analyze([email1, email2])

# Health check
health = client.health()
```

---

## CLI Usage

### Phase 1: Parsing

```bash
# Parse EML file
python3 -m huntertrace.parsing --eml "path/to/email.eml"

# Parse raw headers file
python3 -m huntertrace.parsing --headers-file "path/to/headers.txt"

# Parse from stdin
cat email.eml | python3 -m huntertrace.parsing --stdin

# Compact output
python3 -m huntertrace.parsing --eml "email.eml" --compact

# No raw headers in output
python3 -m huntertrace.parsing --eml "email.eml" --no-raw
```

### Phase 2: Signals

```bash
# Build signals from EML
python3 -m huntertrace.signals --eml "path/to/email.eml"

# Build signals from headers
python3 -m huntertrace.signals --headers-file "path/to/headers.txt"

# Run benchmark on dataset
python3 -m huntertrace.signals.benchmark \
  --dataset "mails/ceas08_eml" \
  --limit 500 \
  --out "reports/benchmark.json"
```

### Phase 3-4: Analysis (combined)

```bash
# Analyze email (parse → signals → correlate → score)
python3 -m huntertrace.analysis --eml "path/to/email.eml" --out result.json

# Analyze all EML files in directory
python3 -m huntertrace.analysis --directory "path/to/mails" --out results.json

# Process JSONL dataset
python3 -m huntertrace.analysis --jsonl "dataset.jsonl" --out results.json
```

### Phase 5: Evaluation

```bash
# Evaluate on labeled dataset
python3 -m huntertrace.evaluation \
  --dataset "dataset.jsonl" \
  --out "report.json" \
  --bootstrap-iterations 1000 \
  --enable-adversarial

# With cost-sensitive evaluation
python3 -m huntertrace.evaluation \
  --dataset "dataset.jsonl" \
  --cost-config cost_config.json \
  --out "report.json"
```

### Phase 6: Explainability

```bash
# Generate explanations for analysis results
python3 -m huntertrace.explainability \
  --input analysis_results.json \
  --format text \
  --out explanations.txt

# JSON output
python3 -m huntertrace.explainability \
  --input analysis_results.json \
  --format json
```

### Phase 7: Adversarial Testing

```bash
# Run adversarial evaluation
python3 -m huntertrace.adversarial \
  --input analysis_results.json \
  --samples-per-input 5 \
  --out adversarial_report.json
```

---

## Architecture

### Data Flow

```
Input Email (EML or raw headers)
    ↓
[Phase 1] Parsing
    ↓ HopChain
[Phase 2] Signals
    ↓ List[Signal]
[Phase 3] Correlation
    ↓ CorrelationResult
[Phase 4] Scoring
    ↓ AttributionResult
    │
    ├→ [Phase 6] Explainability (optional) → ExplainabilityResult
    ├→ [Phase 5] Evaluation (optional) → EvaluationReport
    └→ [Phase 7] Adversarial (optional) → RobustnessMetrics

Output Response
```

### Service Architecture (Phase 8)

```
HTTP Client
    ↓
FastAPI Service (NEW)
    ├─ RequestIDMiddleware
    ├─ LoggingMiddleware
    └─ ErrorHandlingMiddleware
    ↓
PipelineOrchestrator (NEW)
    ↓
Core Pipeline (Phases 1-4, existing)
    ↓
Optional Layers (Phases 5-7, existing)
    ↓
AnalyzeResponse
    ↓
HTTP Response
```

---

## Testing

### Unit Tests

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test file
python3 -m pytest tests/test_parsing.py -v

# Run with coverage
python3 -m pytest tests/ --cov=huntertrace
```

### Phase-Specific Tests

```bash
# Phase 1: Parsing
pytest tests/test_parsing_module.py -v

# Phase 2: Signals
pytest tests/test_signal_layer.py -v

# Phase 3: Correlation
pytest tests/test_correlation.py -v

# Phase 4: Scoring
pytest tests/test_scoring.py -v

# Phase 5: Evaluation
pytest tests/test_evaluation_hardening.py -v

# Phase 6: Explainability
pytest tests/test_explainability.py -v

# Phase 7: Adversarial
pytest tests/test_adversarial.py -v

# Phase 8: Service
pytest tests/test_service.py -v
```

---

## Deployment

### Development

```bash
# Install all dependencies
pip install -r requirements.txt requirements-service.txt

# Run service with auto-reload
python3 -m huntertrace.service --reload
```

### Production (Docker)

```bash
# Build image
docker build -f Dockerfile.service -t huntertrace-api:latest .

# Run with Docker
docker run -p 8000:8000 huntertrace-api:latest

# Or with Docker Compose
docker-compose -f docker-compose.service.yml up -d
```

### Production (Multi-container)

```bash
# Start full stack with nginx + prometheus
docker-compose -f docker-compose.service.yml up -d

# Access:
# - API: http://localhost:8000
# - API Docs: http://localhost:8000/docs
# - Prometheus: http://localhost:9090
```

---

## Configuration

### Environment Variables

```bash
HUNTERTRACE_HOST=0.0.0.0
HUNTERTRACE_PORT=8000
HUNTERTRACE_WORKERS=4
HUNTERTRACE_LOG_LEVEL=INFO
HUNTERTRACE_ENABLE_EXPLAINABILITY=true
HUNTERTRACE_ENABLE_EVALUATION=false
HUNTERTRACE_ENABLE_ADVERSARIAL=false
HUNTERTRACE_MAX_REQUEST_MB=10
HUNTERTRACE_API_KEY_REQUIRED=false
```

### YAML Configuration

```yaml
host: 0.0.0.0
port: 8000
workers: 4
enable_explainability: true
enable_evaluation: false
enable_adversarial: false
log_level: INFO
```

---

## Performance Characteristics

### Latency
- **Per email**: 50-150ms (average)
- **Parsing**: 5-20ms
- **Signals**: 3-10ms
- **Correlation**: 10-30ms
- **Scoring**: 15-40ms
- **Explainability** (optional): 20-50ms

### Throughput
- **Single worker**: 6-10 emails/sec
- **4 workers**: 24-40 emails/sec
- **Batch of 100**: 30-50 emails/sec

### Resource Usage
- **Baseline**: ~100 MB RAM
- **Per request**: ~5-10 MB
- **Batch of 100**: ~500-1000 MB

---

## Support & Documentation

### Documentation Files
- `docs/SERVICE_LAYER.md` - Complete API service documentation
- `docs/PHASE8_SUMMARY.md` - Phase 8 implementation summary
- Each phase has dedicated documentation in `docs/` directory

### Example Files
- `examples/client.py` - Python client library and CLI

### Configuration Files
- `config.service.yaml` - Example service configuration
- `Dockerfile.service` - Docker build
- `docker-compose.service.yml` - Docker Compose orchestration
- `nginx.conf` - Reverse proxy configuration

---

## License

Same as HunterTrace Atlas main project.
