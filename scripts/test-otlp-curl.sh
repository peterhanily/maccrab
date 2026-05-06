#!/usr/bin/env bash
# test-otlp-curl.sh
#
# v1.9 Agent Traces — fast local smoke test that does NOT require
# Claude Code or any AI tool to be configured.
#
# Builds a hand-encoded ExportTraceServiceRequest protobuf body
# containing one Claude-Code-shaped span, POSTs it via curl to
# 127.0.0.1:4318/v1/traces, and verifies the span landed in
# traces.db. Useful for verifying the OTLPReceiver pathway end-to-end
# in 5 seconds.
#
# Requirements:
#   - daemon running with MACCRAB_AGENT_TRACES=1 + MACCRAB_OTLP_RECEIVER=1
#   - python3 (for protobuf wire-format encoding)
#   - sqlite3 (for verification)
#
# Usage:
#   scripts/test-otlp-curl.sh
#   scripts/test-otlp-curl.sh --port 4318    # custom port
#   scripts/test-otlp-curl.sh --secret-test  # encode an api_key in attrs to verify sanitiser

set -euo pipefail

PORT=4318
SECRET_TEST=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --secret-test) SECRET_TEST=1; shift ;;
        -h|--help)
            echo "Usage: $0 [--port 4318] [--secret-test]"
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Resolve traces.db location. Daemon writes to system support dir
# when running as root; user support dir otherwise. Probe both.
SYSTEM_DB="/Library/Application Support/MacCrab/traces.db"
USER_DB="$HOME/Library/Application Support/MacCrab/traces.db"
TRACES_DB=""
if [[ -f "$SYSTEM_DB" ]]; then
    TRACES_DB="$SYSTEM_DB"
elif [[ -f "$USER_DB" ]]; then
    TRACES_DB="$USER_DB"
fi

# Probe receiver health. We send an empty-body POST and accept ANY HTTP
# response code as proof of life — the receiver correctly returns 411
# "Length Required" when content-length is missing, but that's still a
# response, not a connection refusal. `--connect-timeout 2` so a dead
# socket fails fast.
#
# Bug fix: the previous version did `curl ... || echo "000"` inside a
# command-substitution. On connect-refused curl writes "000" to stdout
# AND exits non-zero, so the `||` ran the echo too and we captured
# "000" + "000" = "000000" — which then passed the != "000" guard.
# Capture stdout + exit code separately to avoid the concatenation.
set +e
PROBE_OUT=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 \
    -X POST -H 'Content-Type: application/x-protobuf' \
    --data-binary "" "http://127.0.0.1:$PORT/v1/traces" 2>/dev/null)
PROBE_RC=$?
set -e
PROBE_CODE="${PROBE_OUT:-000}"
if [[ "$PROBE_RC" -ne 0 || "$PROBE_CODE" == "000" || "$PROBE_CODE" == "" ]]; then
    echo "✗ Receiver not responding at 127.0.0.1:$PORT (curl exit $PROBE_RC, http $PROBE_CODE)"
    echo
    echo "  Make sure the daemon is running with the feature flags:"
    echo "    MACCRAB_AGENT_TRACES=1 MACCRAB_OTLP_RECEIVER=1 .build/debug/maccrabd"
    echo "  …or toggle 'Receive agent traces' on in Intelligence → Agent Traces."
    exit 1
fi
echo "✓ Receiver is up at 127.0.0.1:$PORT (probe HTTP $PROBE_CODE)"

# Snapshot pre-test span count.
INITIAL=0
if [[ -n "$TRACES_DB" ]]; then
    INITIAL=$(sqlite3 "$TRACES_DB" "SELECT COUNT(*) FROM spans" 2>/dev/null || echo 0)
fi
echo "→ Initial span count: $INITIAL"

# Build the protobuf body in python. We hand-encode a minimal
# ExportTraceServiceRequest so the script is dep-free (no protoc
# install needed). Wire-format reference:
#   https://protobuf.dev/programming-guides/encoding/
#
# Schema:
#   ExportTraceServiceRequest { repeated ResourceSpans resource_spans = 1; }
#   ResourceSpans { Resource resource = 1; repeated ScopeSpans scope_spans = 2; }
#   ScopeSpans { repeated Span spans = 2; }
#   Span { bytes trace_id=1; bytes span_id=2; bytes parent_span_id=4;
#          string name=5; fixed64 start_time_unix_nano=7;
#          fixed64 end_time_unix_nano=8; repeated KeyValue attributes=9; }

if [[ "$SECRET_TEST" == "1" ]]; then
    SECRET_NOTE="api_key=sk-ant-EVIL-AAAAAAAAAAAAAAAAAAAAAAAAA"
else
    SECRET_NOTE=""
fi

PAYLOAD_HEX=$(SECRET_NOTE="$SECRET_NOTE" python3 - <<'PY'
import os, struct, sys, time

def varint(v):
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v & 0x7F)
    return bytes(out)

def tag(field, wt):
    return varint((field << 3) | wt)

def lendelim(field, payload):
    return tag(field, 2) + varint(len(payload)) + payload

def varintf(field, value):
    return tag(field, 0) + varint(value)

def fixed64(field, value):
    return tag(field, 1) + struct.pack('<Q', value)

def s(field, st):
    return lendelim(field, st.encode('utf-8'))

def any_value_string(v):
    return s(1, v)

def kv(k, v):
    return s(1, k) + lendelim(2, any_value_string(v))

# Stable trace_id (so a recurring smoke-test run aggregates under one
# trace in the dashboard) but a randomised span_id so each invocation
# is a fresh INSERT — INSERT OR REPLACE on (trace_id, span_id) would
# otherwise overwrite the prior run's row and produce a misleading
# "no row landed" signal in the test.
now_ns = int(time.time() * 1_000_000_000)
trace_id  = bytes.fromhex('4bf92f3577b34da6a3ce929d0e0e4736')
span_id   = os.urandom(8)
parent_id = bytes.fromhex('fedcba9876543210')

attrs = [
    kv('tool_name', 'Bash'),
    kv('full_command', 'echo curl-smoke-test'),
    kv('duration_ms', '42'),
    kv('gen_ai.system', 'anthropic'),
    kv('gen_ai.request.model', 'claude-3.5-sonnet'),
]
note = os.environ.get('SECRET_NOTE', '')
if note:
    # Triggers redact-by-key (api_key) AND redact-by-value (sk-ant-...)
    attrs.append(kv('api_key', 'sk-ant-AAAAAAAAAAAAAAAAAAAAAAAAA'))
    attrs.append(kv('user_note', f'leaked {note} into a comment'))

span_body = (
    lendelim(1, trace_id) +
    lendelim(2, span_id) +
    lendelim(4, parent_id) +
    s(5, 'claude_code.tool.execution') +
    fixed64(7, now_ns - 1_000_000_000) +
    fixed64(8, now_ns) +
    b''.join(lendelim(9, a) for a in attrs)
)

# ScopeSpans: scope (field 1) + repeated spans (field 2)
scope_body = lendelim(1, s(1, 'claude_code.otel')) + lendelim(2, span_body)

# Resource: KeyValue list at field 1 holds service.name
resource_body = lendelim(1, kv('service.name', 'claude-code'))

# ResourceSpans: resource (1) + scope_spans (2)
resource_spans_body = lendelim(1, resource_body) + lendelim(2, scope_body)

# ExportTraceServiceRequest: resource_spans (1)
export_request = lendelim(1, resource_spans_body)

sys.stdout.write(export_request.hex())
PY
)

# POST it.
echo "→ POSTing $((${#PAYLOAD_HEX} / 2)) bytes to /v1/traces…"
RESP_CODE=$(echo -n "$PAYLOAD_HEX" | xxd -r -p | curl -sS -o /dev/null \
    -w '%{http_code}' -X POST \
    -H 'Content-Type: application/x-protobuf' \
    --data-binary @- "http://127.0.0.1:$PORT/v1/traces")
if [[ "$RESP_CODE" != "200" ]]; then
    echo "✗ Receiver returned HTTP $RESP_CODE"
    exit 1
fi
echo "✓ Receiver returned HTTP 200"

# Give the actor a moment to flush.
sleep 1

# Re-resolve traces.db in case the daemon just created it.
if [[ -z "$TRACES_DB" ]]; then
    if [[ -f "$SYSTEM_DB" ]]; then
        TRACES_DB="$SYSTEM_DB"
    elif [[ -f "$USER_DB" ]]; then
        TRACES_DB="$USER_DB"
    fi
fi

if [[ -z "$TRACES_DB" ]]; then
    echo "⚠ traces.db not found at either /Library/... or ~/Library/..."
    echo "  Receiver accepted the POST but no DB exists yet —"
    echo "  the daemon may not have wired the TraceStore (PR-3b/4 wiring)."
    exit 1
fi

FINAL=$(sqlite3 "$TRACES_DB" "SELECT COUNT(*) FROM spans" 2>/dev/null || echo 0)
DELTA=$((FINAL - INITIAL))

echo "→ Final span count: $FINAL  (delta: $DELTA)"
echo "→ traces.db: $TRACES_DB"
echo

if [[ "$DELTA" -lt 1 ]]; then
    echo "✗ POST accepted but no rows landed — check daemon logs"
    exit 1
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "  Latest span:"
echo "═══════════════════════════════════════════════════════════════════"
sqlite3 -line "$TRACES_DB" "
    SELECT trace_id, span_id, span_name, agent_tool, service_name,
           legacy_gen_ai_system, attributes_json
    FROM spans ORDER BY start_ns DESC LIMIT 1
"

if [[ "$SECRET_TEST" == "1" ]]; then
    echo
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  Sanitiser check (--secret-test):"
    echo "═══════════════════════════════════════════════════════════════════"
    LATEST_ATTRS=$(sqlite3 "$TRACES_DB" \
        "SELECT attributes_json FROM spans ORDER BY start_ns DESC LIMIT 1")
    if [[ "$LATEST_ATTRS" == *"sk-ant-EVIL"* ]]; then
        echo "✗ LEAK: raw api_key value present in attributes_json"
        exit 1
    fi
    if [[ "$LATEST_ATTRS" != *"REDACTED"* ]]; then
        echo "⚠ no [REDACTED] marker in attributes_json — sanitiser may not have fired"
    else
        echo "✓ Sanitiser redacted secret-shaped attribute (no raw key in DB)"
    fi
fi

echo
echo "✓ End-to-end OTLP ingest verified."
