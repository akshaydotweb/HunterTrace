#!/usr/bin/env bash
# build_release.sh — build and validate a PyPI release
# Usage: ./scripts/build_release.sh [--upload]
set -euo pipefail

UPLOAD=0
for arg in "$@"; do
  [[ "$arg" == "--upload" ]] && UPLOAD=1
done

echo "=== HunterTrace Release Builder ==="
echo ""

# 1. Clean
echo "Cleaning dist/..."
rm -rf dist/ build/ src/*.egg-info *.egg-info

# 2. Lint
echo "Linting..."
python -m ruff check huntertrace/ || { echo "Lint failed"; exit 1; }

# 3. Tests
echo "Running tests..."
python -m pytest tests/ -q --tb=short || { echo "Tests failed"; exit 1; }

# 4. Build
echo "Building distributions..."
python -m build

echo ""
echo "Built:"
ls -lh dist/

# 5. Validate
echo ""
echo "Validating with twine..."
python -m twine check dist/*

# 6. Upload (optional)
if [[ $UPLOAD -eq 1 ]]; then
  echo ""
  echo "Uploading to PyPI..."
  python -m twine upload dist/*
  echo "Done. https://pypi.org/project/huntertrace/"
else
  echo ""
  echo "Dry run complete. Run with --upload to publish to PyPI."
  echo "Or: python -m twine upload dist/*"
fi
