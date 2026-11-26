#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

report="${1:-}"

if [ -z "$report" ]; then
  shopt -s nullglob
  reports=(output/reports/*.md)
  if [ "${#reports[@]}" -eq 0 ]; then
    fail "No report Markdown found in output/reports"
  fi
  report="${reports[${#reports[@]}-1]}"
fi

[ -f "$report" ] || fail "Report not found: $report"

grep -Fq "# Basic Exposure & Compliance Risk Report" "$report" || fail "Report title is missing"
grep -Fq "**Target:**" "$report" || fail "Report target is missing"
grep -Fq "## Exposure Summary" "$report" || fail "Exposure summary is missing"
grep -Fq "## Data Protection Act Compliance" "$report" || fail "Compliance section is missing"
grep -Fq "## Recommended Actions" "$report" || fail "Recommended actions are missing"
grep -Fq "no login or exploitation was attempted" "$report" || fail "Scope statement is missing"

lines="$(wc -l < "$report")"
words="$(wc -w < "$report")"
if [ "$lines" -gt 60 ]; then
  fail "Report is too long: $lines lines"
fi
if [ "$words" -gt 500 ]; then
  fail "Report is too long: $words words"
fi

echo "Report check: OK ($lines lines, $words words)"
