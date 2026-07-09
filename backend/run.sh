#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Copy .env if it doesn't exist
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example"
fi

# Install dependencies if needed
if [ ! -d "../scanapk/venv" ]; then
    python3 -m venv ../scanapk/venv
    ../scanapk/venv/bin/pip install -r requirements.txt -r ../scanapk/requirements.txt
fi

export PYTHONPATH="${PYTHONPATH:-}:$(realpath ../scanapk)"
../scanapk/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload
