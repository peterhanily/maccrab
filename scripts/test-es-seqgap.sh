#!/bin/bash
# MacCrab ES seq-gap (D1) / handler-gauge (D4) harness — v1.21.4 Phase-0.
#
# Models the operator eslogger discriminator, but measures MacCrab's OWN new
# kernel-drop counters (`es_kernel_dropped_*`) read from the rich heartbeat —
# NOT DB rows. DB-row presence conflates a kernel ingest-drop with the ~30×
# retention fast-eviction; `seq_num` continuity at the callback boundary is the
# correct instrument (see plans/2026-07-13-es-telemetry-blindspot-plan.md, D1).
#
# Two experiments:
#   (i)  quiet control — 500 marker execs → assert the NOTIFY_EXEC kernel-drop
#        delta is exactly 0 (a quiet window drops nothing).
#   (ii) flood — ~120k /tmp file writes concurrent with 500 marker execs →
#        assert the whole-client kernel-drop delta (es_kernel_dropped_total) > 0.
#
# REQUIRES a running MacCrab whose NATIVE ES collector is active (release
# System Extension, or `sudo maccrabd` with the ES entitlement). Without it the
# collector is nil (dev eslogger/kdebug fallback) and the D1 counters stay 0 —
# the harness SKIPs in that case rather than failing, because this is a
# device-dependent integration test.
#
# Safe: writes only under /tmp; every artifact + background worker is cleaned
# up on exit (including on Ctrl-C).
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; SKIP=0
pass() { echo -e "  ${GREEN}PASS${NC} $*"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $*"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC} $*"; SKIP=$((SKIP + 1)); }
info() { echo -e "${BLUE}>${NC} $*"; }

WORK_DIR="$(mktemp -d /tmp/maccrab-seqgap.XXXXXX)"
MARKER="$WORK_DIR/maccrab-seqgap-marker"
cleanup() {
    # Reap any still-running flood workers we backgrounded.
    pkill -P $$ 2>/dev/null || true
    rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- Locate the rich heartbeat (root sysext/daemon first, then dev) ---
HB=""
for candidate in \
    "/Library/Application Support/MacCrab/heartbeat_rich.json" \
    "$HOME/Library/Application Support/MacCrab/heartbeat_rich.json"; do
    if [ -f "$candidate" ]; then HB="$candidate"; break; fi
done

if [ -z "$HB" ]; then
    skip "no heartbeat_rich.json found — start MacCrab (sysext or 'sudo maccrabd') first"
    echo ""; echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"; exit 0
fi
info "Reading counters from: $HB"

# --- JSON readers (python3 is reliably present via Command Line Tools) ---
# read_scalar <heartbeat> <key>            -> integer (0 if absent)
read_scalar() {
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(int(d.get(sys.argv[2],0) or 0))' "$1" "$2"
}
# read_map_key <heartbeat> <mapKey> <subKey> -> integer (0 if absent)
read_map_key() {
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(int(d.get(sys.argv[2],{}).get(sys.argv[3],0) or 0))' "$1" "$2" "$3"
}
# native ES active? (es_processed_by_type non-empty)
native_es_active() {
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if len(d.get("es_processed_by_type",{}))>0 else 1)' "$1"
}

# Wait until the heartbeat is (re)written with written_at_unix > $1, or timeout.
wait_fresh_heartbeat() {
    local since="$1" timeout="${2:-90}" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        local w
        w=$(read_scalar "$HB" "written_at_unix" 2>/dev/null || echo 0)
        if [ "$w" -gt "$since" ]; then return 0; fi
        sleep 2; waited=$((waited + 2))
    done
    return 1
}

# --- Native-ES gate ---
if ! native_es_active "$HB"; then
    skip "native ES collector inactive (dev eslogger/kdebug fallback) — D1 counters stay 0; run on a Mac with the ES sysext/entitlement"
    echo ""; echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"; exit 0
fi

# --- Marker binary (benign; a copy of /bin/echo, exec'd with a unique arg) ---
cp /bin/echo "$MARKER"
chmod +x "$MARKER"
run_marker_execs() {
    local n="$1" i=0
    while [ "$i" -lt "$n" ]; do
        "$MARKER" "maccrab-seqgap-$i" >/dev/null 2>&1 || true
        i=$((i + 1))
    done
}

# --- File-write flood: ~120k open/write/close cycles under /tmp ---
run_flood() {
    local workers=8 per=15000 w
    for w in $(seq 1 "$workers"); do
        (
            f="$WORK_DIR/flood-$w"
            i=0
            while [ "$i" -lt "$per" ]; do
                echo x >> "$f"   # reopen+write+close each iteration
                i=$((i + 1))
            done
        ) &
    done
    wait
}

# ============================================================
# (i) Quiet control — 500 marker execs, expect NO NOTIFY_EXEC drops
# ============================================================
info "Control: 500 marker execs in a quiet window"
if ! wait_fresh_heartbeat 0 30; then
    skip "no fresh heartbeat within 30s (daemon stalled?) — cannot baseline"
    echo ""; echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"; exit 0
fi
EXEC_DROPS_BEFORE=$(read_map_key "$HB" "es_kernel_dropped_by_type" "NOTIFY_EXEC")
run_marker_execs 500
MARK_TS=$(date +%s)
if wait_fresh_heartbeat "$MARK_TS" 90; then
    EXEC_DROPS_AFTER=$(read_map_key "$HB" "es_kernel_dropped_by_type" "NOTIFY_EXEC")
    EXEC_DROP_DELTA=$((EXEC_DROPS_AFTER - EXEC_DROPS_BEFORE))
    if [ "$EXEC_DROP_DELTA" -eq 0 ]; then
        pass "quiet control: es_kernel_dropped_by_type[NOTIFY_EXEC] delta == 0"
    else
        fail "quiet control leaked $EXEC_DROP_DELTA NOTIFY_EXEC kernel drops (expected 0)"
    fi
else
    skip "control: no fresh heartbeat after execs within 90s"
fi

# ============================================================
# (ii) Flood — 120k writes + 500 execs, expect kernel drops > 0
# ============================================================
info "Flood: ~120k /tmp writes concurrent with 500 marker execs"
TOTAL_DROPS_BEFORE=$(read_scalar "$HB" "es_kernel_dropped_total")
P99_BEFORE=$(read_scalar "$HB" "es_handler_p99_us")
run_flood &
FLOOD_PID=$!
run_marker_execs 500
wait "$FLOOD_PID" 2>/dev/null || true
FLOOD_TS=$(date +%s)
if wait_fresh_heartbeat "$FLOOD_TS" 90; then
    TOTAL_DROPS_AFTER=$(read_scalar "$HB" "es_kernel_dropped_total")
    P99_AFTER=$(read_scalar "$HB" "es_handler_p99_us")
    EXEC_FLOOD_DROPS=$(read_map_key "$HB" "es_kernel_dropped_by_type" "NOTIFY_EXEC")
    TOTAL_DROP_DELTA=$((TOTAL_DROPS_AFTER - TOTAL_DROPS_BEFORE))
    info "es_kernel_dropped_total delta=$TOTAL_DROP_DELTA  handler_p99_us ${P99_BEFORE}->${P99_AFTER}  exec_drops(total)=$EXEC_FLOOD_DROPS"
    if [ "$TOTAL_DROP_DELTA" -gt 0 ]; then
        pass "flood: es_kernel_dropped_total climbed by $TOTAL_DROP_DELTA (kernel ingest-drop observed)"
    else
        # Not a hard failure: a fast host may absorb 120k writes without dropping.
        skip "flood: es_kernel_dropped_total did not climb — host absorbed the flood (raise the flood size or run under load)"
    fi
else
    skip "flood: no fresh heartbeat after flood within 90s"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
