#!/usr/bin/env bash
# Bounded loopback smoke test. The helper verifies only its own exact span;
# --receiver-only emits an identity for the root recorder and proves acceptance
# only. It never prints unrelated trace rows or stored attribute contents.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec /usr/bin/python3 -B "$SCRIPT_DIR/otlp-smoke.py" "$@"
