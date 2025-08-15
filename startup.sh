#!/usr/bin/env bash
set -euo pipefail
# Azure sets $PORT on Linux; default to 8000 locally
PORT="${PORT:-8000}"
exec gunicorn --workers=2 --threads=8 --timeout=120 --bind=0.0.0.0:${PORT} app:app
