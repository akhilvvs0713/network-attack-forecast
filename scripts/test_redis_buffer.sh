#!/bin/bash
set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASE_DIR="$(dirname "$DIR")"
VENV_PYTHON="$BASE_DIR/.venv/bin/python"

if [ ! -x "$VENV_PYTHON" ]; then
    echo "[!] Virtual environment not found. Please setup the project."
    exit 1
fi

echo "============================================"
echo " Redis Buffer Integration Test"
echo "============================================"
"$VENV_PYTHON" "$DIR/test_redis_buffer.py"
