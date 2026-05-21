#!/usr/bin/env bash
# Sets up the Python virtual environment for the project.
set -e

echo "Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "Installing Phase 1 dependencies..."
pip install --upgrade pip
pip install -r phase1-model/requirements.txt

echo "Installing Phase 2 dependencies..."
pip install -r phase2-backend/requirements.txt

echo "Environment ready. Activate with: source .venv/bin/activate"
