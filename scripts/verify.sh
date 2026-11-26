#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$ROOT_DIR"

PYTHON="$(resolve_python)"
require_nmap

for script in "$ROOT_DIR/build.sh" "$ROOT_DIR/probe.sh" "$ROOT_DIR"/scripts/*.sh; do
  bash -n "$script"
done

exec "$PYTHON" "$ROOT_DIR/scripts/verify.py"
