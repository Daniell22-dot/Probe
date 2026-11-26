#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/scripts/common.sh"
cd "$ROOT_DIR"

PYTHON="$(resolve_python)"

usage() {
  echo "Usage: ./probe.sh <command> [options]"
  echo ""
  echo "Commands:"
  echo "  verify                 Run full build verification"
  echo "  scan [options]         Scan an authorized target (defaults to localhost)"
  echo "  odpc [options]         Scan with ODPC registration lookup"
  echo "  check-config           Validate targets.yaml authorization rules"
  echo "  check-report [file]    Validate latest or given report"
  echo "  check-outputs          Validate latest scan and report"
}

has_flag() {
  local wanted="$1"
  shift
  for arg in "$@"; do
    case "$arg" in
      "$wanted"|"$wanted="*) return 0 ;;
    esac
  done
  return 1
}

command="${1:-}"

case "$command" in
  verify)
    shift
    exec bash "$ROOT_DIR/scripts/verify.sh" "$@"
    ;;
  check-config)
    exec bash "$ROOT_DIR/scripts/check-config.sh"
    ;;
  check-report)
    shift
    exec bash "$ROOT_DIR/scripts/check-report.sh" "$@"
    ;;
  check-outputs)
    exec bash "$ROOT_DIR/scripts/check-outputs.sh"
    ;;
  scan)
    shift
    require_nmap
    bash "$ROOT_DIR/scripts/check-config.sh"
    if ! has_flag "--target" "$@"; then
      set -- --target localhost "$@"
    fi
    if ! has_flag "--timeout" "$@"; then
      set -- "$@" --timeout 60
    fi
    exec "$PYTHON" "$ROOT_DIR/src/main.py" "$@"
    ;;
  odpc)
    shift
    require_nmap
    bash "$ROOT_DIR/scripts/check-config.sh"
    if ! has_flag "--register-file" "$@"; then
      fail "odpc requires --register-file"
    fi
    if ! has_flag "--target" "$@"; then
      set -- --target localhost "$@"
    fi
    if ! has_flag "--timeout" "$@"; then
      set -- "$@" --timeout 60
    fi
    exec "$PYTHON" "$ROOT_DIR/src/main.py" "$@"
    ;;
  ""|-h|--help)
    usage
    ;;
  *)
    fail "Unknown command: $command"
    ;;
esac
