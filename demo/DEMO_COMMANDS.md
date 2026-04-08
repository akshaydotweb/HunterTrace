# HunterTrace Board Demo Commands (Locked)

Use these exact commands from project root:

```bash
python3 -m huntertrace.cli analyze demo/clean_case.json --format pretty --set logging.enabled=false
python3 -m huntertrace.cli analyze demo/vpn_case.json --format pretty --disable-correlation --set logging.enabled=false
python3 -m huntertrace.cli analyze demo/vpn_case.json --format pretty --set logging.enabled=false
python3 -m huntertrace.cli analyze demo/conflict_case.json --format pretty --set logging.enabled=false
```

Expected behavior:
- `clean_case.json` → `verdict=attributed` with stable confidence.
- `vpn_case.json` baseline (`--disable-correlation`) → higher confidence than correlation-enabled run.
- `vpn_case.json` correlation-enabled → `anonymization_detected=true`, confidence drop, `verdict=inconclusive`.
- `conflict_case.json` → conflicting reasoning, `verdict=inconclusive`.

Demo display policy:
- Hide comparative/adversarial non-blockers in live demo.
- Ignore `false_attribution_reduction=0.0` and adversarial confidence-rise warnings when verdict remains `inconclusive`.
