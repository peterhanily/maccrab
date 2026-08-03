#!/bin/bash
# Run a release Python program under Apple's fixed interpreter, isolated from
# cwd, PYTHONPATH, user-site packages, inherited credentials, and bytecode I/O.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPS="${1:-}"
PROGRAM="${2:-}"
[[ -n "$DEPS" && -n "$PROGRAM" && -f "$PROGRAM" ]] || {
    echo "usage: $0 <verified-dependency-root> <python-program> [args...]" >&2
    exit 2
}
shift 2

"$SCRIPT_DIR/check-release-pyyaml.sh" "$DEPS" >/dev/null

/usr/bin/env -i \
    PATH=/usr/bin:/bin \
    HOME="${HOME:?}" \
    TMPDIR="${TMPDIR:-/tmp}" \
    LC_ALL=C \
    LANG=C \
    PYTHONDONTWRITEBYTECODE=1 \
    /usr/bin/python3 -I -B -c '
import runpy, sys
deps, program, *arguments = sys.argv[1:]
sys.path.insert(0, deps)
sys.argv = [program, *arguments]
runpy.run_path(program, run_name="__main__")
' "$DEPS" "$PROGRAM" "$@"
