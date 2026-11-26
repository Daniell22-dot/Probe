ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

resolve_python() {
  if [ -x "$ROOT_DIR/env/Scripts/python.exe" ]; then
    echo "$ROOT_DIR/env/Scripts/python.exe"
  elif [ -x "$ROOT_DIR/env/bin/python" ]; then
    echo "$ROOT_DIR/env/bin/python"
  else
    fail "Python environment not found at env/Scripts/python.exe or env/bin/python"
  fi
}

require_nmap() {
  if command -v nmap >/dev/null 2>&1 || command -v nmap.exe >/dev/null 2>&1; then
    return 0
  fi
  fail "Nmap not found in PATH"
}

run_python() {
  local python
  python="$(resolve_python)"
  "$python" "$@"
}
