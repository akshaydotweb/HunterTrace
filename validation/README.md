# HunterTrace Validation Workspace

This directory is the new home for all HunterTrace validation work.

## Structure

- `datasets/fixtures/`: Small hand-picked `.eml` samples for smoke tests
- `datasets/corpora/`: Curated labeled evaluation datasets
- `datasets/external/`: Imported third-party datasets before curation
- `datasets/ground-truth/`: Labels, metadata, and adjudicated truth files
- `tests/smoke/`: Fast sanity checks for CLI and pipeline basics
- `tests/regression/`: Reproductions for known bugs and fixed issues
- `tests/integration/`: End-to-end validation across multiple stages
- `tests/performance/`: Throughput, scale, and stability checks
- `scripts/`: Validation runners and dataset preparation helpers
- `reports/`: Fresh validation outputs only
- `tmp/`: Scratch space for local runs

## Rules

1. Do not place legacy assets directly in this tree.
2. Every dataset added here should have a clear source and ground truth.
3. Every report in `reports/` should be generated from the current codebase.
4. Prefer small categorized fixtures first, then larger corpora.

## Legacy Archive

Previous validation assets were archived intact under:

- `archive/legacy-validation-2026-04-22/`

Use the archive only as a reference while rebuilding the new validation suite.
