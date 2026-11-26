#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

PYTHON="$(resolve_python)"

if [ "$#" -gt 0 ]; then
  exec "$PYTHON" "$ROOT_DIR/scripts/verify.py" --check-report "$1"
fi

exec "$PYTHON" "$ROOT_DIR/scripts/verify.py" --check-report
