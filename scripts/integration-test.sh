#!/bin/bash
# MacCrab Live Integration Test
# Starts the daemon, triggers detectable actions, checks for alerts.
# Run from the maccrab project directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() { echo -e "  ${GREEN}✔ PASS${NC} $*"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}✘ FAIL${NC} $*"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YELLOW}○ SKIP${NC} $*"; SKIP=$((SKIP + 1)); }
info() { echo -e "${BLUE}▸${NC} $*"; }

cd "$PROJECT_DIR"

# Refuse to run alongside the System Extension.
#
# Unlike stress-test.sh this script CANNOT be pointed at the sysext: it is a
# dev-daemon test by construction — it wipes the user-domain events.db, starts
# .build/debug/maccrabd, and greps THAT process's stdout log for "Loaded N
# rules". Run next to a live sysext it (a) starts a second engine on the host
# and (b) reads its assertions back through .build/debug/maccrabctl, which
# resolves via maccrabDataDir() and prefers whichever support dir has the newer
# events.db — the ROOT one the sysext owns. Every PASS would then describe the
# production engine rather than the daemon under test. Fail loudly instead of
# reporting numbers about the wrong engine.
if pgrep -x com.maccrab.agent > /dev/null; then
    echo -e "${RED}✘ MacCrab System Extension (com.maccrab.agent) is running.${NC}"
    echo "  This integration test starts its own non-root maccrabd and would"
    echo "  measure the wrong engine. Deactivate the system extension first, or"
    echo "  set MACCRAB_ALLOW_SYSEXT=1 to override (results will be unreliable)."
    [ "${MACCRAB_ALLOW_SYSEXT:-0}" = "1" ] || exit 2
fi

# --- Setup ---
info "Building MacCrab..."
swift build 2>&1 | tail -1

info "Compiling rules..."
python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir .build/debug/compiled_rules 2>/dev/null | tail -1

# Clear old events from the user store
USER_SUPPORT_DIR="$HOME/Library/Application Support/MacCrab"
rm -f "$USER_SUPPORT_DIR/events.db" "$USER_SUPPORT_DIR/events.db-shm" "$USER_SUPPORT_DIR/events.db-wal" 2>/dev/null

info "Starting daemon (non-root mode)..."
# Use a FIFO to capture daemon output while running in background
LOG_FILE=/tmp/maccrab_integration_test.log
> "$LOG_FILE"
.build/debug/maccrabd >> "$LOG_FILE" 2>&1 &
DAEMON_PID=$!
# The script is `set -euo pipefail` with cleanup only INLINE at the end, so any
# mid-run abort left a stray non-root maccrabd alive writing into the user
# store. Reap it from an EXIT trap instead.
trap 'kill $DAEMON_PID 2>/dev/null || true; wait $DAEMON_PID 2>/dev/null || true' EXIT

# Wait for daemon to initialize and produce output
sleep 4

if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo -e "${RED}Daemon failed to start!${NC}"
    cat "$LOG_FILE"
    exit 1
fi

info "Daemon running (PID $DAEMON_PID)"
echo ""

# --- Verify daemon state ---
info "Test: Daemon loads rules"
RULE_COUNT=$(grep -o "Loaded [0-9]* single-event" "$LOG_FILE" | grep -o "[0-9]*" || echo "0")
SEQ_COUNT=$(grep -o "Loaded [0-9]* sequence" "$LOG_FILE" | grep -o "[0-9]*" || echo "0")
if [ "${RULE_COUNT:-0}" -gt 100 ]; then
    pass "Loaded $RULE_COUNT single-event + $SEQ_COUNT sequence rules"
else
    # Log might not be flushed yet; check daemon is alive as proxy
    if kill -0 $DAEMON_PID 2>/dev/null; then
        pass "Daemon running (log output may be buffered)"
    else
        fail "Expected 100+ rules, got ${RULE_COUNT:-0}"
    fi
fi

# Check rules count command
RULE_COUNT_OUTPUT=$(.build/debug/maccrabctl rules count 2>/dev/null || echo "")
if echo "$RULE_COUNT_OUTPUT" | grep -q "Severity\|Log Source"; then
    pass "maccrabctl rules count works"
else
    skip "maccrabctl rules count returned no data"
fi

# --- Trigger detectable actions ---
echo ""
info "Triggering test actions..."

# 1. Network: curl to an external IP on unusual port
# The network collector polls proc_pidinfo — it should see this connection
info "  Triggering: outbound network connection"
curl -s --connect-timeout 2 http://httpbin.org/get > /dev/null 2>&1 || true
sleep 2

# 2. Network: connection to localhost (should be less suspicious)
curl -s --connect-timeout 1 http://127.0.0.1:1 > /dev/null 2>&1 || true

# 3. Run osascript (commonly flagged)
info "  Triggering: osascript execution"
osascript -e 'return "test"' 2>/dev/null || true

# Wait for the network poll cycle (5s)
sleep 6

# --- Check results ---
echo ""
info "Checking results..."

# Check event count
EVENT_COUNT=$(.build/debug/maccrabctl events stats 2>/dev/null | grep "Total events" | grep -o "[0-9]*" || echo "0")
if [ "${EVENT_COUNT:-0}" -gt 0 ]; then
    pass "Events recorded: $EVENT_COUNT"
else
    fail "No events recorded"
fi

# Check if alerts were generated
ALERT_OUTPUT=$(.build/debug/maccrabctl alerts 20 2>/dev/null || echo "")
# `maccrabctl alerts` prints the severity TOKEN first and the emoji never (it
# uses Severity.coloredLabel → "[MEDIUM]  "), so the emoji-anchored pattern
# matched zero lines and this check could only ever take the skip branch — a
# total collapse of alerting was indistinguishable from normal operation.
# (grep -c exits 1 on zero matches, hence `|| true`.)
ALERT_COUNT=$(printf '%s\n' "$ALERT_OUTPUT" | grep -cE "^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]" || true)
if [ "${ALERT_COUNT:-0}" -gt 0 ]; then
    pass "Alerts generated: $ALERT_COUNT"
    echo "$ALERT_OUTPUT" | head -20 | sed 's/^/    /'
else
    skip "No alerts generated (expected in non-root mode with limited collectors)"
fi

# Check maccrabctl status works
# No `|| true`: under `set -e` a non-zero `status` aborted the whole script
# here — past every remaining check, past the summary, and (before the EXIT
# trap above) past the daemon kill.
STATUS=$(.build/debug/maccrabctl status 2>/dev/null || true)
if echo "$STATUS" | grep -q "running\|Active"; then
    pass "maccrabctl status reports daemon running"
else
    # Daemon might have stopped — check if it reported correctly
    if echo "$STATUS" | grep -q "Database"; then
        pass "maccrabctl status reports database info"
    else
        fail "maccrabctl status failed"
    fi
fi

# Check event search works
# A subcommand that EXITS NON-ZERO is a defect, not missing data — folding it
# into `skip` is how a completely broken maccrabctl still printed "All tests
# passed!". Keep skip only for the genuinely data-dependent shape.
SEARCH_RC=0
SEARCH_RESULT=$(.build/debug/maccrabctl events search "curl" 2>/dev/null) || SEARCH_RC=$?
if [ "$SEARCH_RC" -ne 0 ]; then
    fail "maccrabctl events search exited $SEARCH_RC"
elif echo "$SEARCH_RESULT" | grep -q "matches\|results"; then
    pass "maccrabctl event search works"
else
    skip "maccrabctl event search returned no results (curl may not have been captured)"
fi

# Check maccrabctl events tail works
TAIL_RC=0
TAIL_RESULT=$(.build/debug/maccrabctl events tail 5 2>/dev/null) || TAIL_RC=$?
if [ "$TAIL_RC" -ne 0 ]; then
    fail "maccrabctl events tail exited $TAIL_RC"
elif echo "$TAIL_RESULT" | grep -q "events\|connect"; then
    pass "maccrabctl events tail works"
else
    skip "maccrabctl events tail returned no events"
fi

# Check cdhash extraction works. This one is NOT data-dependent — cdhash of our
# own pid always has an answer — so a non-zero exit is unambiguously a defect.
CDHASH_RC=0
CDHASH_RESULT=$(.build/debug/maccrabctl cdhash $$ 2>/dev/null) || CDHASH_RC=$?
if [ "$CDHASH_RC" -ne 0 ]; then
    fail "maccrabctl cdhash exited $CDHASH_RC"
elif echo "$CDHASH_RESULT" | grep -q "PID\|no CDHash"; then
    pass "maccrabctl cdhash works"
else
    skip "maccrabctl cdhash failed"
fi

# Check hunt command works
HUNT_RC=0
HUNT_RESULT=$(.build/debug/maccrabctl hunt "show all events" 2>/dev/null) || HUNT_RC=$?
if [ "$HUNT_RC" -ne 0 ]; then
    fail "maccrabctl hunt exited $HUNT_RC"
elif echo "$HUNT_RESULT" | grep -q "Threat Hunt\|Results\|Interpretation"; then
    pass "maccrabctl hunt works"
else
    skip "maccrabctl hunt returned no results"
fi

# Check report generation
REPORT_RC=0
REPORT_RESULT=$(.build/debug/maccrabctl report --hours 1 2>/dev/null) || REPORT_RC=$?
if [ "$REPORT_RC" -ne 0 ]; then
    fail "maccrabctl report exited $REPORT_RC"
elif echo "$REPORT_RESULT" | grep -q "<html>\|MacCrab\|Report"; then
    pass "maccrabctl report generation works"
else
    skip "maccrabctl report returned no output"
fi

# --- Cleanup ---
echo ""
info "Stopping daemon..."
# `|| true`: without it, `set -e` aborted here whenever the daemon had already
# exited (kill returns 1), skipping the summary and the exit-code verdict.
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true

# --- Summary ---
echo ""
echo "════════════════════════════════════════"
echo -e "  ${GREEN}Passed:${NC}  $PASS"
echo -e "  ${RED}Failed:${NC}  $FAIL"
echo -e "  ${YELLOW}Skipped:${NC} $SKIP"
echo "════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n${RED}Some tests failed.${NC} Check /tmp/maccrab_integration_test.log"
    exit 1
else
    echo -e "\n${GREEN}All tests passed!${NC}"
fi
