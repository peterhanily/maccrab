#!/bin/bash
# MacCrab Burst Load Benchmark (v1.21.5)
# Storms the engine with rapid short-lived process spawns + /tmp file
# create/delete pairs, then reads the daemon's OWN drop gauges to turn the
# "serial pipeline throughput ceiling" question into numbers.
#
# Gauge sources (no sudo needed — both are world-readable):
#   heartbeat_rich.json (support dir, ~30s tick) — per-stream split:
#     merged_priority_dropped_total   priority stream (exec/network/tcc/auth)
#     merged_file_dropped_total       file-write stream (low-value shed lane)
#     detection_input_dropped_total   priority + file aggregate
#     es_kernel_dropped_total         ES kernel-side drops
#     es_copy_backpressure_dropped_total / es_stream_yield_dropped_total
#     events_storage_write_dropped_total  batched writer (storage, not detection)
#     es_msg_e2e_latency_p99_us       drain-lag leading indicator (gauge)
#   /var/tmp/maccrab.metrics.json (Prometheus textfile) — aggregate fallback.
#
# PASS (exit 0): merged_priority_dropped_total did not increase — the burst
#                shed at most file-stream noise, never a high-value event.
# FAIL (exit 1): priority-stream drops increased (or the engine died).
# exit 2:        environment problem (no engine, stale/missing gauges).
#
# Safe by construction: artifacts only under /tmp/maccrab_burst_$$, bounded
# count AND wall-clock cap, full cleanup on exit via trap.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

SPAWNS=1500        # short-lived process spawns
FILES=1500         # /tmp file create+delete pairs
MAX_SECONDS=30     # hard wall-clock cap on the burst loop
FLUSH_TIMEOUT=90   # max wait for a post-burst heartbeat flush (~30s tick)

usage() {
    cat <<EOF
Usage: $(basename "$0") [--spawns N] [--files N] [--max-seconds S]

Burst load benchmark: generates a process-spawn + file-write storm, then
diffs the daemon's drop gauges. Fails (exit 1) if the PRIORITY event
stream (exec/network/tcc) dropped anything; file-stream drops are
reported but tolerated — that lane exists to absorb floods.

  --spawns N       short-lived process spawns to generate (default $SPAWNS)
  --files N        /tmp file create+delete pairs to generate (default $FILES)
  --max-seconds S  hard time cap on the burst loop (default $MAX_SECONDS)
  -h, --help       show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --spawns)      SPAWNS=$2; shift 2 ;;
        --files)       FILES=$2; shift 2 ;;
        --max-seconds) MAX_SECONDS=$2; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "Unknown option: $1"; usage; exit 2 ;;
    esac
done

command -v python3 > /dev/null || { echo "✘ python3 required"; exit 2; }

METRICS_FILE="/var/tmp/maccrab.metrics.json"
HB_ROOT="/Library/Application Support/MacCrab/heartbeat_rich.json"
HB_USER="$HOME/Library/Application Support/MacCrab/heartbeat_rich.json"

# Pick whichever heartbeat_rich.json is freshest (root sysext vs non-root dev
# daemon support dir) — the live engine's file always wins on written_at_unix.
pick_heartbeat() {
    python3 - "$HB_ROOT" "$HB_USER" <<'PY'
import json, sys
best, best_ts = "", -1.0
for p in sys.argv[1:]:
    try:
        with open(p) as f:
            ts = float(json.load(f).get("written_at_unix", -1))
    except Exception:
        continue
    if ts > best_ts:
        best, best_ts = p, ts
print(best)
PY
}

heartbeat_written_at() {
    python3 -c 'import json,sys; print(int(float(json.load(open(sys.argv[1])).get("written_at_unix", 0))))' "$1" 2>/dev/null || echo 0
}

# Emit "<prefix><var>=<int>" lines for eval. Primary source is the heartbeat;
# keys the Prometheus textfile also carries fall back to it. -1 = unavailable.
read_gauges() {
    python3 - "$(pick_heartbeat)" "$METRICS_FILE" "$1" <<'PY'
import json, sys
hb_path, m_path, prefix = sys.argv[1], sys.argv[2], sys.argv[3]
def load(p):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return {}
hb, m = load(hb_path), load(m_path)
KEYS = [
    ("events_processed",             "events_processed",                   "events_total"),
    ("priority_dropped",             "merged_priority_dropped_total",      None),
    ("file_dropped",                 "merged_file_dropped_total",          None),
    ("detection_input_dropped",      "detection_input_dropped_total",      None),
    ("es_kernel_dropped",            "es_kernel_dropped_total",            "es_kernel_dropped_total"),
    ("es_copy_backpressure_dropped", "es_copy_backpressure_dropped_total", "es_copy_backpressure_dropped_total"),
    ("es_stream_yield_dropped",      "es_stream_yield_dropped_total",      "es_stream_yield_dropped_total"),
    ("storage_write_dropped",        "events_storage_write_dropped_total", None),
    ("events_dropped",               "events_dropped",                     "events_dropped_total"),
    ("latency_p99_us",               "es_msg_e2e_latency_p99_us",          "es_msg_e2e_latency_p99_us"),
]
for var, hk, mk in KEYS:
    v = hb.get(hk)
    if v is None and mk is not None:
        v = m.get(mk)
    print(f"{prefix}{var}={int(v) if v is not None else -1}")
PY
}

# Block until the freshest heartbeat is strictly newer than $1 (unix ts).
wait_for_flush() {
    local target=$1 waited=0 hb
    while [ $waited -lt $FLUSH_TIMEOUT ]; do
        hb="$(pick_heartbeat)"
        if [ -n "$hb" ] && [ "$(heartbeat_written_at "$hb")" -gt "$target" ]; then
            return 0
        fi
        sleep 5
        waited=$(( waited + 5 ))
    done
    return 1
}

echo "╔══════════════════════════════════════════╗"
echo "║        MacCrab Burst Benchmark           ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Engine: reuse the live sysext or dev daemon; start dev maccrabd otherwise
BURST_DIR="/tmp/maccrab_burst_$$"
STARTED_DAEMON=0
ENGINE_PID=""

cleanup() {
    rm -rf "$BURST_DIR" 2>/dev/null || true
    if [ "$STARTED_DAEMON" = "1" ] && [ -n "$ENGINE_PID" ]; then
        kill "$ENGINE_PID" 2>/dev/null || true
        wait "$ENGINE_PID" 2>/dev/null || true
        echo "Dev daemon stopped."
    fi
}
trap cleanup EXIT

if pgrep -x com.maccrab.agent > /dev/null; then
    ENGINE_PID=$(pgrep -x com.maccrab.agent | head -1)
    ENGINE_KIND="system extension (com.maccrab.agent)"
elif pgrep -x maccrabd > /dev/null; then
    ENGINE_PID=$(pgrep -x maccrabd | head -1)
    ENGINE_KIND="dev daemon (maccrabd)"
else
    if [ ! -x .build/debug/maccrabd ]; then
        echo "✘ No engine running and .build/debug/maccrabd not built (run 'make build')."
        exit 2
    fi
    echo "Starting dev daemon..."
    .build/debug/maccrabd >> /tmp/maccrab_burst.log 2>&1 &
    ENGINE_PID=$!
    STARTED_DAEMON=1
    ENGINE_KIND="dev daemon (started by this script)"
    sleep 3
fi
echo "Engine: $ENGINE_KIND, PID $ENGINE_PID"
echo "Burst:  $SPAWNS spawns + $FILES file pairs, cap ${MAX_SECONDS}s"
echo ""

# ── Baseline: need a heartbeat fresh enough to anchor the delta (≤60s old;
# also covers a just-started dev daemon whose first tick is ~30s out).
echo "Waiting for a fresh gauge snapshot..."
if ! wait_for_flush $(( $(date +%s) - 60 )); then
    echo "✘ No heartbeat_rich.json flushed within ${FLUSH_TIMEOUT}s — engine gauges unavailable."
    exit 2
fi
eval "$(read_gauges PRE_)"
START_RSS=$(ps -o rss= -p "$ENGINE_PID" 2>/dev/null | tr -d ' ' || echo "")

# ── Burst: interleaved spawn + file-write storm, artifacts in /tmp only
mkdir -p "$BURST_DIR"
echo "Generating burst..."
BURST_START=$(date +%s)
i=0
TOTAL=$(( SPAWNS > FILES ? SPAWNS : FILES ))
while [ $i -lt $TOTAL ]; do
    if [ $i -lt $SPAWNS ]; then
        /usr/bin/true
    fi
    if [ $i -lt $FILES ]; then
        : > "$BURST_DIR/f_$i"
        rm -f "$BURST_DIR/f_$i"
    fi
    if [ $(( i % 100 )) -eq 0 ] && [ $(( $(date +%s) - BURST_START )) -ge $MAX_SECONDS ]; then
        echo "  time cap ${MAX_SECONDS}s hit at iteration $i/$TOTAL"
        break
    fi
    i=$(( i + 1 ))
done
BURST_END=$(date +%s)
echo "  burst done: $(( BURST_END - BURST_START ))s"
echo ""

# ── Post: wait for the first heartbeat flushed AFTER the burst ended
echo "Waiting for post-burst gauge flush (heartbeat tick ~30s)..."
if ! wait_for_flush "$BURST_END"; then
    echo "✘ Heartbeat did not flush within ${FLUSH_TIMEOUT}s after the burst."
    exit 2
fi
eval "$(read_gauges POST_)"
END_RSS=$(ps -o rss= -p "$ENGINE_PID" 2>/dev/null | tr -d ' ' || echo "")

if [ -z "$END_RSS" ]; then
    echo "✘ FAIL: engine (PID $ENGINE_PID) died during the burst."
    exit 1
fi

# ── Delta table
fmt() { if [ "$1" -lt 0 ]; then echo "n/a"; else echo "$1"; fi; }
row() {
    local d="n/a"
    if [ "$2" -ge 0 ] && [ "$3" -ge 0 ]; then d=$(( $3 - $2 )); fi
    printf "%-38s %14s %14s %10s\n" "$1" "$(fmt "$2")" "$(fmt "$3")" "$d"
}
echo "────────────────────────────────────────────────────────────────────────────"
printf "%-38s %14s %14s %10s\n" "Gauge" "Before" "After" "Δ"
echo "────────────────────────────────────────────────────────────────────────────"
row "events_processed"                    "$PRE_events_processed"             "$POST_events_processed"
row "merged_priority_dropped_total"       "$PRE_priority_dropped"             "$POST_priority_dropped"
row "merged_file_dropped_total"           "$PRE_file_dropped"                 "$POST_file_dropped"
row "detection_input_dropped_total"       "$PRE_detection_input_dropped"      "$POST_detection_input_dropped"
row "es_kernel_dropped_total"             "$PRE_es_kernel_dropped"            "$POST_es_kernel_dropped"
row "es_copy_backpressure_dropped_total"  "$PRE_es_copy_backpressure_dropped" "$POST_es_copy_backpressure_dropped"
row "es_stream_yield_dropped_total"       "$PRE_es_stream_yield_dropped"      "$POST_es_stream_yield_dropped"
row "events_storage_write_dropped_total"  "$PRE_storage_write_dropped"        "$POST_storage_write_dropped"
row "events_dropped (total fold)"         "$PRE_events_dropped"               "$POST_events_dropped"
row "es_msg_e2e_latency_p99_us (gauge)"   "$PRE_latency_p99_us"               "$POST_latency_p99_us"
row "engine RSS (KB)"                     "${START_RSS:--1}"                  "$END_RSS"
echo "────────────────────────────────────────────────────────────────────────────"
echo ""

# ── Assertion: any priority-stream drop is the real failure signal —
# that stream carries the high-value exec/network/tcc events.
if [ "$PRE_priority_dropped" -lt 0 ] || [ "$POST_priority_dropped" -lt 0 ]; then
    echo "✘ merged_priority_dropped_total unavailable — cannot assert (is heartbeat_rich.json readable?)"
    exit 2
fi
PRIO_DELTA=$(( POST_priority_dropped - PRE_priority_dropped ))
if [ "$PRIO_DELTA" -gt 0 ]; then
    echo "✘ FAIL: priority stream dropped $PRIO_DELTA event(s) under burst — high-value exec/network/tcc events were shed."
    exit 1
fi
echo "✔ PASS: no priority drops under burst"
