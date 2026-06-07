#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

export ATLAS_HOST="${ATLAS_HOST:-127.0.0.1}"
export ATLAS_PORT="${ATLAS_PORT:-8511}"

if command -v python3 >/dev/null 2>&1; then
  exec python3 -u atlas_lab/app.py
fi

if command -v python >/dev/null 2>&1; then
  exec python -u atlas_lab/app.py
fi

echo "python3 or python was not found." >&2
exit 1
