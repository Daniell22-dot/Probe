#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

shopt -s nullglob
scans=(output/scans/*.json)
reports=(output/reports/*.md)

if [ "${#scans[@]}" -eq 0 ] || [ "${#reports[@]}" -eq 0 ]; then
  fail "No scan JSON or report Markdown found in output/"
fi

latest_scan="${scans[${#scans[@]}-1]}"
latest_report="${reports[${#reports[@]}-1]}"

grep -Fq '"tcp"' "$latest_scan" || fail "Scan JSON has no TCP data: $latest_scan"
bash "$ROOT_DIR/scripts/check-report.sh" "$latest_report"

echo "Output check: OK"
echo "Latest scan: $latest_scan"
echo "Latest report: $latest_report"
