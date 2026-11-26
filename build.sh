#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [ -x "env/Scripts/python.exe" ]; then
  PYTHON="env/Scripts/python.exe"
elif [ -x "env/bin/python" ]; then
  PYTHON="env/bin/python"
else
  echo "Python environment not found at env/Scripts/python.exe or env/bin/python" >&2
  exit 1
fi

if command -v nmap >/dev/null 2>&1 || command -v nmap.exe >/dev/null 2>&1; then
  :
else
  echo "Nmap not found in PATH" >&2
  exit 1
fi

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

"$PYTHON" -m compileall -q src
"$PYTHON" -m pytest -q
"$PYTHON" src/main.py --target localhost --timeout 60

shopt -s nullglob
scans=(output/scans/*.json)
reports=(output/reports/*.md)

if [ "${#scans[@]}" -eq 0 ] || [ "${#reports[@]}" -eq 0 ]; then
  echo "Build check failed: no scan JSON or report Markdown found in output/" >&2
  exit 1
fi

latest_scan="${scans[${#scans[@]}-1]}"
latest_report="${reports[${#reports[@]}-1]}"

grep -q '"tcp"' "$latest_scan"
grep -q "Exposure Summary" "$latest_report"
grep -q "Data Protection Act Compliance" "$latest_report"
grep -q "Recommended Actions" "$latest_report"

echo "Build check: OK"
echo "Latest scan: $latest_scan"
echo "Latest report: $latest_report"
