#!/usr/bin/env bash
# test-otlp-claude-code.sh
#
# v1.9 PR-3b — manual integration smoke test for the Agent Traces feature.
# Spins up a development daemon with the trace receiver active, prints
# the env exports the operator should set in their Claude Code shell,
# waits N seconds for traces to land, then queries `traces.db` to confirm
# spans were ingested.
#
# Not run in CI — needs a real Claude Code install with telemetry enabled.
# See docs/AGENT_TRACES.md for the full operator workflow.
#
# Usage:
#   sudo scripts/test-otlp-claude-code.sh              # default 60s wait
#   sudo scripts/test-otlp-claude-code.sh --wait 180   # custom wait window
#
# Requirements (operator runs in their shell, NOT this script):
#   export CLAUDE_CODE_ENABLE_TELEMETRY=1
#   export OTEL_TRACES_EXPORTER=otlp
#   export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
#   export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
# Then: launch claude code, ask it to do something simple ("ls /tmp"),
# return to this terminal.

set -euo pipefail

WAIT_SECONDS=60
while [[ $# -gt 0 ]]; do
    case "$1" in
        --wait) WAIT_SECONDS="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "$EUID" -ne 0 ]]; then
    echo "error: run as root (sudo)" >&2
    exit 1
fi

# Build a fresh daemon binary so we know we're testing this branch.
echo "→ Building maccrabd…"
swift build -c release --product maccrabd

DAEMON_BIN="$REPO_ROOT/.build/release/maccrabd"
if [[ ! -x "$DAEMON_BIN" ]]; then
    echo "error: build did not produce $DAEMON_BIN" >&2
    exit 1
fi

# Resolve traces.db location. Daemon uses /Library/Application Support
# when run as root (which we are).
SUPPORT_DIR="/Library/Application Support/MacCrab"
TRACES_DB="$SUPPORT_DIR/traces.db"

# Snapshot the current span count so we can compare delta.
INITIAL=0
if [[ -f "$TRACES_DB" ]]; then
    INITIAL=$(sqlite3 "$TRACES_DB" "SELECT COUNT(*) FROM spans" 2>/dev/null || echo 0)
fi
echo "→ Initial span count: $INITIAL"

# Print operator instructions.
cat <<INSTRUCTIONS

═══════════════════════════════════════════════════════════════════
  In another shell, run:

    export CLAUDE_CODE_ENABLE_TELEMETRY=1
    export OTEL_TRACES_EXPORTER=otlp
    export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
    export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
    claude  # ask it: "ls /tmp"

  This script will start the daemon, wait $WAIT_SECONDS seconds,
  then query traces.db.
═══════════════════════════════════════════════════════════════════

INSTRUCTIONS

# Start daemon with the agent-traces feature flag and a self-managed
# OTLP receiver hint env var that PR-4 will use to auto-toggle the
# receiver on. PR-3b ships the receiver class but does not yet wire
# auto-start at boot — operator-controlled. For this script we leave
# the receiver toggle to be wired manually.
echo "→ Starting daemon for ${WAIT_SECONDS}s window…"
MACCRAB_AGENT_TRACES=1 \
MACCRAB_OTLP_RECEIVER=1 \
"$DAEMON_BIN" &
DAEMON_PID=$!

cleanup() {
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Wait for the receiver to bind. NWListener bind is fast; 2s is generous.
sleep 2

if ! curl -fsS -X POST -H 'Content-Type: application/x-protobuf' \
        --data-binary "" http://127.0.0.1:4318/v1/traces -o /dev/null 2>/dev/null; then
    echo "warn: localhost:4318 didn't accept a probe POST — receiver may not be enabled"
    echo "     (PR-4 wires the dashboard toggle; for now you may need to enable manually)"
fi

echo "→ Waiting ${WAIT_SECONDS}s for traces to arrive…"
sleep "$WAIT_SECONDS"

# Final count.
FINAL=0
if [[ -f "$TRACES_DB" ]]; then
    FINAL=$(sqlite3 "$TRACES_DB" "SELECT COUNT(*) FROM spans" 2>/dev/null || echo 0)
fi
DELTA=$((FINAL - INITIAL))

echo
echo "→ Final span count: $FINAL  (delta: $DELTA)"

if [[ "$DELTA" -gt 0 ]]; then
    echo
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  Recent spans (top 5 by start_ns desc):"
    echo "═══════════════════════════════════════════════════════════════════"
    sqlite3 "$TRACES_DB" \
        "SELECT trace_id, span_name, agent_tool, service_name FROM spans ORDER BY start_ns DESC LIMIT 5"
    echo
    echo "✓ End-to-end ingest verified — $DELTA new span(s) ingested."
else
    echo
    echo "✗ No new spans were ingested in the ${WAIT_SECONDS}s window."
    echo "  Check: receiver actually started? operator env exported correctly?"
    echo "         CLAUDE_CODE_ENABLE_TELEMETRY=1 set in the shell that ran claude?"
    exit 1
fi
