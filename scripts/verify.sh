#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$ROOT_DIR"

PYTHON="$(resolve_python)"
require_nmap

for script in "$ROOT_DIR/build.sh" "$ROOT_DIR/probe.sh" "$ROOT_DIR"/scripts/*.sh; do
  bash -n "$script"
done

bash "$ROOT_DIR/scripts/check-config.sh"
"$PYTHON" -m compileall -q "$ROOT_DIR/src"
"$PYTHON" -m pytest -q "$ROOT_DIR/test_probe.py"
"$PYTHON" "$ROOT_DIR/src/main.py" --target localhost --timeout 60
bash "$ROOT_DIR/scripts/check-outputs.sh"

echo "Build check: OK"
