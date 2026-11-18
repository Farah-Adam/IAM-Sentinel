#!/usr/bin/env bash
# IAM Sentinel - one-command start.
#   ./run.sh                 -> install deps (first run), run tests, start dashboard on http://127.0.0.1:8000
#   ./run.sh scan [args]     -> CLI passthrough, e.g. ./run.sh scan iam-small.json --fail-on HIGH
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! "$PY" -c "import fastapi, uvicorn, networkx, multipart" >/dev/null 2>&1; then
  echo "[setup] installing requirements..."
  "$PY" -m pip install -q -r requirements.txt
fi
if [ "$#" -gt 0 ]; then
  exec "$PY" cli.py "$@"
fi
"$PY" cli.py scan iam-small.json || true
exec "$PY" main.py
