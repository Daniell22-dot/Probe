#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

PYTHON="$(resolve_python)"

"$PYTHON" - <<'PY'
import ipaddress
from pathlib import Path

import yaml

config = yaml.safe_load(Path("config/targets.yaml").read_text(encoding="utf-8")) or {}
targets = [target for target in config.get("targets", []) if target.get("authorized") is True]

if not targets:
    raise SystemExit("No authorized targets configured")

if not any(target.get("name") == "localhost" for target in targets):
    raise SystemExit("localhost must remain authorized for the build scan")

for target in targets:
    host = str(target.get("host", ""))
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if loopback:
        continue
    notes = str(target.get("notes", "")).lower()
    if "authorization" not in notes or "signatory" not in notes:
        raise SystemExit(
            f"Non-loopback target {target.get('name')!r} needs authorization and signatory in notes"
        )

print("Config check: OK")
PY
