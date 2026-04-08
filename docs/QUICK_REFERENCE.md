# HunterTrace Phase 8 - Quick Reference

## Start the Service

```bash
# Install dependencies
pip install -r requirements-service.txt

# Run service
python3 -m huntertrace.service --port 8000

# Access docs: http://localhost:8000/docs
```

---

## API Endpoints (5 Total)

| Endpoint | Method | Purpose | Response |
|----------|--------|---------|----------|
| `/analyze` | POST | Single email analysis | AnalyzeResponse |
| `/batch` | POST | Batch analysis (up to 1000) | BatchResponse |
| `/health` | GET | Health check | HealthResponse |
| `/version` | GET | Version info | VersionResponse |
| `/config` | GET | Service config | ConfigResponse |

---

## Request Examples

### Analyze Single Email

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "input_type": "eml",
    "content": "From: sender@example.com\nReceived: from...",
    "options": {
      "include_explainability": true,
      "include_evaluation": false,
      "include_adversarial": false
    }
  }'
```

### Batch Analysis

```bash
curl -X POST http://localhost:8000/batch \
  -H "Content-Type: application/json" \
  -d '{
    "inputs": [
      {"input_type": "eml", "content": "..."},
      {"input_type": "raw", "content": "..."}
    ]
  }'
```

### Health Check

```bash
curl http://localhost:8000/health
```

---

## Response Structure

### AnalyzeResponse

```json
{
  "region": "US",
  "confidence": 0.85,
  "verdict": "attributed",
  "consistency_score": 0.92,
  "signals_used": [...],
  "signals_rejected": [...],
  "anomalies": [],
  "limitations": [],
  "reasoning": "Attribution to US with 85% confidence...",
  "explainability": null,
  "evaluation": null,
  "adversarial": null,
  "metadata": {
    "processing_time_ms": 45.2,
    "pipeline_version": "1.0.0",
    "deterministic_hash": "a1b2c3d4e5f6g7h8",
    "input_size_bytes": 1024
  }
}
```

---

## Python Client

```python
from examples.client import HunterTraceClient

client = HunterTraceClient("http://localhost:8000")

# Single analysis
result = client.analyze(email_content)

# Batch analysis
results = client.batch_analyze([email1, email2, email3])

# Health check
health = client.health()

# Version
version = client.version()

# Config
config = client.config()
```

---

## Configuration

### Via CLI

```bash
python3 -m huntertrace.service \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --log-level INFO \
  --enable-explainability
```

### Via Environment Variables

```bash
export HUNTERTRACE_HOST=0.0.0.0
export HUNTERTRACE_PORT=8000
export HUNTERTRACE_WORKERS=4
export HUNTERTRACE_LOG_LEVEL=INFO
export HUNTERTRACE_ENABLE_EXPLAINABILITY=true
python3 -m huntertrace.service
```

### Via YAML Config File

```bash
python3 -m huntertrace.service --config config.service.yaml
```

---

## Docker Deployment

### Build

```bash
docker build -f Dockerfile.service -t huntertrace-api .
```

### Run

```bash
docker run -p 8000:8000 huntertrace-api
```

### Docker Compose (with nginx)

```bash
docker-compose -f docker-compose.service.yml up
```

---

## Key Features

✅ **Deterministic** - Same input → same output (verified with hash)
✅ **Secure** - Input validation, injection prevention, optional API keys
✅ **Auditable** - Request IDs, structured logging, signal breakdown
✅ **Scalable** - Multi-worker support, batch processing (up to 1000)
✅ **Production-Ready** - Type hints, error handling, CORS, health checks

---

## Configurable Options

| Setting | Default | Range |
|---------|---------|-------|
| `host` | 0.0.0.0 | any |
| `port` | 8000 | 1-65535 |
| `workers` | 4 | 1-∞ |
| `max_batch_size` | 1000 | 1-∞ |
| `max_request_size_mb` | 10 | 1-∞ |
| `request_timeout_seconds` | 30 | 1-∞ |
| `enable_explainability` | true | true/false |
| `enable_evaluation` | false | true/false |
| `enable_adversarial` | false | true/false |

---

## Performance

| Metric | Value |
|--------|-------|
| **Single email** | 50-150ms |
| **Throughput** | 6-10 emails/sec (1 worker), 24-40 emails/sec (4 workers) |
| **Memory baseline** | ~100 MB |
| **Per request** | ~5-10 MB |

---

## Error Responses

| Status | Code | Meaning |
|--------|------|---------|
| 400 | `validation_error` | Input validation failed |
| 401 | `unauthorized` | Missing API key |
| 403 | `forbidden` | Invalid API key |
| 500 | `internal_error` | Server error |

---

## Files

### Service Code (1,500 LOC)
- `huntertrace/service/schemas.py` - Request/response models
- `huntertrace/service/orchestrator.py` - Pipeline orchestration
- `huntertrace/service/api.py` - FastAPI endpoints
- `huntertrace/service/validators.py` - Input validation
- `huntertrace/service/middleware.py` - Logging/error handling
- `huntertrace/service/config.py` - Configuration
- `huntertrace/service/__init__.py` - Package exports
- `huntertrace/service/__main__.py` - CLI entry point

### Testing (800 LOC)
- `tests/test_service.py` - 40+ comprehensive tests

### Documentation
- `docs/SERVICE_LAYER.md` - Complete API documentation
- `docs/PHASE8_SUMMARY.md` - Phase 8 summary
- `PHASES.md` - Complete phases guide
- `examples/client.py` - Python client + CLI

### Configuration
- `config.service.yaml` - Example YAML config
- `Dockerfile.service` - Docker image
- `docker-compose.service.yml` - Docker Compose
- `nginx.conf` - Reverse proxy
- `requirements-service.txt` - Dependencies

---

## Common Commands

```bash
# Start service
python3 -m huntertrace.service

# Run tests
pytest tests/test_service.py -v

# Analyze single email
python3 examples/client.py --file sample.eml

# Check health
curl http://localhost:8000/health

# Docker deployment
docker-compose -f docker-compose.service.yml up

# Get help
python3 -m huntertrace.service --help
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Port already in use | Use `--port 9000` |
| Module not found | Run `pip install -r requirements-service.txt` |
| Connection refused | Ensure service is running on correct host:port |
| Validation error | Check email format (must have Received headers or MIME) |
| High latency | Increase workers `--workers 8` or check logs |

---

## Next Steps

1. **Edit Configuration**: Modify `config.service.yaml` for your environment
2. **Set API Key**: Export `HUNTERTRACE_API_KEY_REQUIRED=true` to enable auth
3. **Deploy**: Use `docker-compose.service.yml` for production
4. **Monitor**: Add Prometheus metrics (see `docker-compose.service.yml`)
5. **Scale**: Increase workers or add load balancer (nginx provided)

---

**For complete documentation, see `docs/SERVICE_LAYER.md`**
