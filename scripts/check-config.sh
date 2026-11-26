#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

PYTHON="$(resolve_python)"
exec "$PYTHON" "$ROOT_DIR/scripts/verify.py" --check-config
