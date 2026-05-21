#!/usr/bin/env bash
set -e
source .venv/bin/activate

echo "=== Phase 1 Tests ==="
cd phase1-model
pytest tests/ -v --cov=src --cov-report=term-missing
cd ..

echo "=== Phase 2 Tests ==="
cd phase2-backend
pytest tests/ -v
cd ..

echo "All tests passed."
