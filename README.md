# HunterTrace Atlas Parsing Module

Deterministic email-header parsing focused on:
- `Received` header extraction
- hop-chain reconstruction (bottom-up)
- structural and temporal validation
- signal construction with audit-ready evidence output

## Dedicated CLI Usage

Run from project root:

```bash
python3 -m huntertrace.parsing --eml "mails/samples/phish_0018.eml"
```

Equivalent explicit CLI entrypoint:

```bash
python3 -m huntertrace.parsing.cli --eml "mails/samples/phish_0004.eml"
```

Parse raw headers from a file:

```bash
python3 -m huntertrace.parsing --headers-file /path/to/headers.txt
```

Parse from stdin:

```bash
cat /path/to/email_or_headers.txt | python3 -m huntertrace.parsing --stdin
```

### CLI Flags

- `--no-raw`: omit `raw_header` from each hop in JSON output
- `--compact`: emit compact JSON (single-line)

Example:

```bash
python3 -m huntertrace.parsing --eml "mails/samples/phish_0018.eml" --no-raw --compact
```

## Atlas Signal Layer CLI

Build an audit-ready output directly from `.eml`:

```bash
python3 -m huntertrace.signals --eml "mails/yahoo.eml"
```

From raw headers file:

```bash
python3 -m huntertrace.signals.cli --headers-file /path/to/headers.txt --compact
```

From stdin:

```bash
cat /path/to/email_or_headers.txt | python3 -m huntertrace.signals --stdin
```

## Benchmark Against Real-World Datasets

Run benchmark on local DFIR corpus:

```bash
python3 -m huntertrace.signals.benchmark --dataset "mails/ceas08_eml" --limit 200 --determinism-repeats 3
```

Write benchmark report JSON:

```bash
python3 -m huntertrace.signals.benchmark --dataset "mails/ceas08_eml" --limit 500 --out "reports/atlas/benchmark_ceas08.json"
```

## Run Tests

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```
