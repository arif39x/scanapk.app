#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example"
fi

VENV_DIR="../../.venv"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install -r requirements.txt -r ../scanapk-backend/requirements.txt
fi

export PYTHONPATH="${PYTHONPATH:-}:$(realpath ../scanapk-backend)"
"$VENV_DIR/bin/uvicorn" api_server.main:app --host 0.0.0.0 --port 8000 --reload
