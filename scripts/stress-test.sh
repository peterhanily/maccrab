#!/bin/bash
# MacCrab Stress / Sustained Operation Test
# Monitors daemon health over time while generating activity.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

DURATION=${1:-60}  # seconds, default 60
INTERVAL=5         # check interval

echo "╔══════════════════════════════════════════╗"
echo "║     MacCrab Stress Test ($DURATION seconds)       ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Engine: prefer the live System Extension, then a running dev daemon; only
# start .build/debug/maccrabd when neither is present.
#
# Probing ONLY `maccrabd` meant that on a release install — where
# `com.maccrab.agent` is the engine and `maccrabd` never runs — this script
# launched a SECOND, non-root engine alongside the production sysext and then
# reported RSS / CPU / event numbers for that throwaway process instead of the
# one actually protecting the host. Same probe as burst-bench.sh.
if pgrep -x com.maccrab.agent > /dev/null; then
    DAEMON_PID=$(pgrep -x com.maccrab.agent | head -1)
    ENGINE_KIND="system extension (com.maccrab.agent)"
    STARTED_DAEMON=0
elif pgrep -x maccrabd > /dev/null; then
    DAEMON_PID=$(pgrep -x maccrabd | head -1)
    ENGINE_KIND="dev daemon (maccrabd)"
    STARTED_DAEMON=0
else
    if [ ! -x .build/debug/maccrabd ]; then
        echo "✘ No engine running and .build/debug/maccrabd not built (run 'make build')."
        exit 2
    fi
    echo "Starting dev daemon..."
    .build/debug/maccrabd >> /tmp/maccrab_stress.log 2>&1 &
    DAEMON_PID=$!
    STARTED_DAEMON=1
    ENGINE_KIND="dev daemon (started by this script)"
    sleep 3
fi

echo "Engine: $ENGINE_KIND, PID $DAEMON_PID"
echo ""

# Baseline measurements
START_RSS=$(ps -o rss= -p $DAEMON_PID 2>/dev/null | tr -d ' ')
START_EVENTS=$(.build/debug/maccrabctl events stats 2>/dev/null | grep "Total events" | grep -o "[0-9]*" || echo "0")
START_TIME=$(date +%s)

echo "Baseline: RSS=${START_RSS}KB, Events=$START_EVENTS"
echo ""
echo "Generating activity and monitoring..."
echo "──────────────────────────────────────────"
printf "%-8s %-10s %-10s %-8s %-6s\n" "Time" "RSS (KB)" "Events" "Alerts" "CPU%"
echo "──────────────────────────────────────────"

ELAPSED=0
while [ $ELAPSED -lt $DURATION ]; do
    # Generate some activity
    # Network connections
    curl -s --connect-timeout 1 https://httpbin.org/get > /dev/null 2>&1 &
    curl -s --connect-timeout 1 https://example.com > /dev/null 2>&1 &

    # File operations (benign)
    touch /tmp/maccrab_test_$$_$(date +%s) 2>/dev/null
    ls /tmp > /dev/null 2>/dev/null

    # Process spawns
    /usr/bin/true 2>/dev/null
    echo "" | /usr/bin/wc -l > /dev/null 2>/dev/null

    sleep $INTERVAL

    # Measure
    ELAPSED=$(( $(date +%s) - START_TIME ))
    RSS=$(ps -o rss= -p $DAEMON_PID 2>/dev/null | tr -d ' ' || echo "DEAD")

    if [ "$RSS" = "DEAD" ]; then
        echo "DAEMON CRASHED at ${ELAPSED}s!"
        break
    fi

    EVENTS=$(.build/debug/maccrabctl events stats 2>/dev/null | grep "Total events" | grep -o "[0-9]*" || echo "?")
    # The CLI prints "[SEVERITY] …" (Severity.coloredLabel), never a leading
    # emoji, so the old pattern matched nothing and the Alerts column read 0/?
    # for the whole run — hiding exactly the alert storm this monitor exists to
    # catch. (grep -c exits 1 on zero matches, hence `|| true`.)
    ALERTS=$(.build/debug/maccrabctl alerts 1000 2>/dev/null | grep -cE "^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]" || true)
    CPU=$(ps -o %cpu= -p $DAEMON_PID 2>/dev/null | tr -d ' ' || echo "?")

    printf "%-8s %-10s %-10s %-8s %-6s\n" "${ELAPSED}s" "$RSS" "$EVENTS" "$ALERTS" "$CPU"
done

echo "──────────────────────────────────────────"
echo ""

# Final measurements
END_RSS=$(ps -o rss= -p $DAEMON_PID 2>/dev/null | tr -d ' ' || echo "DEAD")
END_EVENTS=$(.build/debug/maccrabctl events stats 2>/dev/null | grep "Total events" | grep -o "[0-9]*" || echo "0")

if [ "$END_RSS" != "DEAD" ]; then
    RSS_DELTA=$(( ${END_RSS:-0} - ${START_RSS:-0} ))
    EVENT_DELTA=$(( ${END_EVENTS:-0} - ${START_EVENTS:-0} ))

    echo "Results:"
    echo "  Duration:     ${ELAPSED}s"
    echo "  Memory:       ${START_RSS}KB → ${END_RSS}KB (Δ ${RSS_DELTA}KB)"
    echo "  Events:       ${START_EVENTS} → ${END_EVENTS} (Δ ${EVENT_DELTA})"
    echo "  Status:       ✔ Daemon alive"

    # Check for memory leak (> 50MB growth is suspicious)
    if [ $RSS_DELTA -gt 51200 ]; then
        echo "  ⚠ Memory grew >50MB — possible leak"
    else
        echo "  ✔ Memory stable"
    fi
else
    echo "  ✘ Daemon died during test!"
fi

# Cleanup
rm -f /tmp/maccrab_test_$$_* 2>/dev/null
if [ "$STARTED_DAEMON" = "1" ]; then
    kill $DAEMON_PID 2>/dev/null
    wait $DAEMON_PID 2>/dev/null || true
    echo "  Daemon stopped."
fi
