#!/bin/bash
#
# false-positive-test.sh — Verify that known Apple system processes do NOT
# trigger MacCrab alerts.
#
# Starts the daemon, waits for it to stabilize, then checks the alert database
# for any alerts attributed to processes that should be allowlisted.
#
# Usage: ./scripts/false-positive-test.sh
#
# This test is designed to catch regressions like the universalaccessd false
# positive (flagged as keylogger despite being an Apple accessibility daemon).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
TOTAL=0

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo -e "  ${GREEN}✔ PASS${NC} $*"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo -e "  ${RED}✘ FAIL${NC} $*"; }
warn() { TOTAL=$((TOTAL+1)); WARN=$((WARN+1)); echo -e "  ${YELLOW}⚠ WARN${NC} $*"; }
header() { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}"; }
info() { echo -e "  ${BLUE}▸${NC} $*"; }

# ─── Known Apple system processes that MUST NOT trigger alerts ─────────
# Format: "process_name|path_substring" — either field matching means FP
APPLE_SYSTEM_PROCESSES=(
    # Accessibility / Input
    "universalaccessd|/usr/libexec/universalaccessd"
    "AXVisualSupportAgent|AXVisualSupportAgent"
    "VoiceOver|VoiceOver"
    "TextInputMenuAgent|TextInputMenuAgent"
    "TextInputSwitcher|TextInputSwitcher"
    "PressAndHold|PressAndHold"
    "imklaunchagent|imklaunchagent"

    # Window management / UI
    "WindowServer|WindowServer"
    "Dock|/System/Library/CoreServices/Dock"
    "SystemUIServer|SystemUIServer"
    "loginwindow|loginwindow"
    "ControlCenter|ControlCenter"
    "NotificationCenter|NotificationCenter"
    "Spotlight|Spotlight"
    "Finder|/System/Library/CoreServices/Finder"

    # Security / Auth
    "SecurityAgent|SecurityAgent"
    "authd|/usr/libexec/authd"
    "securityd|/usr/libexec/securityd"
    "trustd|/usr/libexec/trustd"
    "accountsd|/usr/libexec/accountsd"
    "tccd|/usr/libexec/tccd"
    "opendirectoryd|/usr/libexec/opendirectoryd"

    # System services
    "launchd|/sbin/launchd"
    "mDNSResponder|/usr/sbin/mDNSResponder"
    "configd|/usr/libexec/configd"
    "nsurlsessiond|/usr/libexec/nsurlsessiond"
    "apsd|/usr/libexec/apsd"
    "sharingd|/usr/libexec/sharingd"

    # Indexing
    "mds|/System/Library/Frameworks/CoreServices"
    "mdworker|mdworker"
    "mds_stores|mds_stores"

    # Update / install
    "softwareupdated|softwareupdated"
    "installer|/usr/sbin/installer"
    "mdmclient|/usr/libexec/mdmclient"

    # Networking
    "networkd|/usr/libexec/networkd"
    "symptomsd|/usr/libexec/symptomsd"
    "WiFiAgent|WiFiAgent"

    # Logging / diagnostics
    "syslogd|/usr/sbin/syslogd"
    "logd|/usr/libexec/logd"
    "ReportCrash|ReportCrash"
    "diagnosticd|/usr/libexec/diagnosticd"
    "spindump|/usr/sbin/spindump"

    # Screen sharing / remote
    "screensharingd|screensharingd"
    "ARDAgent|ARDAgent"
    "ScreenSharingAgent|ScreenSharingAgent"
    "screencaptureui|screencaptureui"
)

# ─── Apple path prefixes that should never appear in alerts ───────────
APPLE_PATH_PREFIXES=(
    "/System/Library/"
    "/usr/libexec/"
    "/usr/sbin/"
)

cleanup() {
    info "Cleaning up..."
    pkill -x maccrabd 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# ═══════════════════════════════════════════════════
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     MacCrab False Positive Test Suite            ║"
echo "║     Validates system processes are NOT flagged   ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Setup ────────────────────────────────────────────────────────────

info "Building MacCrab..."
swift build 2>&1 | tail -1

info "Compiling rules..."
python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir .build/debug/compiled_rules 2>&1 | tail -1
mkdir -p "$HOME/Library/Application Support/MacCrab/compiled_rules/sequences"
cp -f .build/debug/compiled_rules/*.json "$HOME/Library/Application Support/MacCrab/compiled_rules/" 2>/dev/null || true
cp -f .build/debug/compiled_rules/sequences/*.json "$HOME/Library/Application Support/MacCrab/compiled_rules/sequences/" 2>/dev/null || true

info "Clearing old alert data..."
USER_DB="$HOME/Library/Application Support/MacCrab/events.db"
# Only clear alerts, keep events for context
sqlite3 "$USER_DB" "DELETE FROM alerts;" 2>/dev/null || true

info "Starting daemon (non-root mode)..."
.build/debug/maccrabd > /tmp/maccrab_fp_test.log 2>&1 &
DAEMON_PID=$!
sleep 5

if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo -e "${RED}Daemon failed to start!${NC}"
    cat /tmp/maccrab_fp_test.log
    exit 1
fi
info "Daemon running (PID $DAEMON_PID)"

# ═══════════════════════════════════════════════════
header "1. INITIAL STABILIZATION"
# ═══════════════════════════════════════════════════

info "Waiting 30 seconds for daemon to complete initial scans..."
info "(Event taps, TCC, network, system policy polls all fire on startup)"
sleep 30

# ═══════════════════════════════════════════════════
header "2. CHECK ALERTS FOR SYSTEM PROCESS FALSE POSITIVES"
# ═══════════════════════════════════════════════════

# Get all alerts from the database
ALL_ALERTS=$(sqlite3 "$USER_DB" \
    "SELECT rule_id, rule_title, process_name, process_path, severity FROM alerts;" 2>/dev/null || echo "")

ALERT_COUNT=$(echo "$ALL_ALERTS" | grep -c '|' 2>/dev/null || echo "0")
info "Total alerts generated: $ALERT_COUNT"

if [ "$ALERT_COUNT" -eq 0 ]; then
    info "No alerts generated during stabilization (good — or daemon has limited sources)"
fi

# Check each known system process against alerts
FP_FOUND=0
header "2a. Named Process Check"

for entry in "${APPLE_SYSTEM_PROCESSES[@]}"; do
    proc_name="${entry%%|*}"
    path_substr="${entry##*|}"

    # Check if this process appears in any alert
    name_match=$(echo "$ALL_ALERTS" | grep -i "|${proc_name}|" 2>/dev/null || true)
    path_match=$(echo "$ALL_ALERTS" | grep -i "${path_substr}" 2>/dev/null || true)

    if [ -n "$name_match" ] || [ -n "$path_match" ]; then
        fail "FALSE POSITIVE: $proc_name triggered an alert"
        echo "$name_match$path_match" | head -3 | while IFS='|' read -r rid rtitle pname ppath sev; do
            echo -e "    ${RED}Rule: $rtitle | Process: $pname ($ppath) | Severity: $sev${NC}"
        done
        FP_FOUND=$((FP_FOUND + 1))
    fi
done

if [ "$FP_FOUND" -eq 0 ]; then
    pass "No named system process false positives found ($((${#APPLE_SYSTEM_PROCESSES[@]})) processes checked)"
fi

# ═══════════════════════════════════════════════════
header "2b. Path Prefix Check"
# ═══════════════════════════════════════════════════

# Check if any alerts have process paths from Apple system directories
PREFIX_FP=0
for prefix in "${APPLE_PATH_PREFIXES[@]}"; do
    matches=$(echo "$ALL_ALERTS" | grep "${prefix}" 2>/dev/null || true)
    if [ -n "$matches" ]; then
        match_count=$(echo "$matches" | wc -l | tr -d ' ')
        # These might be legitimate alerts if the process spawns something suspicious,
        # but they deserve review
        warn "$match_count alert(s) involve processes under $prefix"
        echo "$matches" | head -3 | while IFS='|' read -r rid rtitle pname ppath sev; do
            echo -e "    ${YELLOW}Rule: $rtitle | Process: $pname ($ppath)${NC}"
        done
        PREFIX_FP=$((PREFIX_FP + match_count))
    fi
done

if [ "$PREFIX_FP" -eq 0 ]; then
    pass "No alerts from Apple system path prefixes"
fi

# ═══════════════════════════════════════════════════
header "3. EVENT TAP MONITOR VALIDATION"
# ═══════════════════════════════════════════════════

# Specifically check for event tap keylogger alerts on system processes
ET_ALERTS=$(echo "$ALL_ALERTS" | grep -i "event.tap\|keylogger\|event-tap" 2>/dev/null || true)
if [ -n "$ET_ALERTS" ]; then
    ET_COUNT=$(echo "$ET_ALERTS" | wc -l | tr -d ' ')
    info "Event tap alerts found: $ET_COUNT"

    # Check if any are from system processes
    ET_FP=0
    while IFS='|' read -r rid rtitle pname ppath sev; do
        [ -z "$pname" ] && continue
        # Check if process is in system paths
        is_system=false
        for prefix in "${APPLE_PATH_PREFIXES[@]}"; do
            if [[ "$ppath" == ${prefix}* ]]; then
                is_system=true
                break
            fi
        done
        # Check named allowlist
        for entry in "${APPLE_SYSTEM_PROCESSES[@]}"; do
            allow_name="${entry%%|*}"
            if [ "$pname" = "$allow_name" ]; then
                is_system=true
                break
            fi
        done

        if [ "$is_system" = true ]; then
            fail "Event tap FP: $pname ($ppath) flagged as keylogger"
            ET_FP=$((ET_FP + 1))
        else
            pass "Event tap alert is legitimate: $pname ($ppath)"
        fi
    done <<< "$ET_ALERTS"

    if [ "$ET_FP" -eq 0 ]; then
        pass "All event tap alerts are for non-system processes"
    fi
else
    pass "No event tap keylogger false positives"
fi

# ═══════════════════════════════════════════════════
header "4. SELF-DEFENSE FALSE POSITIVE CHECK"
# ═══════════════════════════════════════════════════

SD_ALERTS=$(echo "$ALL_ALERTS" | grep -i "self-defense\|tamper" 2>/dev/null || true)
if [ -n "$SD_ALERTS" ]; then
    SD_COUNT=$(echo "$SD_ALERTS" | wc -l | tr -d ' ')
    warn "$SD_COUNT self-defense alert(s) during normal operation (should be 0)"
    echo "$SD_ALERTS" | head -3 | while IFS='|' read -r rid rtitle pname ppath sev; do
        echo -e "    ${YELLOW}$rtitle | $pname ($ppath)${NC}"
    done
else
    pass "No spurious self-defense alerts during normal operation"
fi

# ═══════════════════════════════════════════════════
header "5. ALERT SEVERITY DISTRIBUTION"
# ═══════════════════════════════════════════════════

if [ "$ALERT_COUNT" -gt 0 ]; then
    CRIT=$(echo "$ALL_ALERTS" | grep -ci "critical" 2>/dev/null || echo "0")
    HIGH=$(echo "$ALL_ALERTS" | grep -ci "high" 2>/dev/null || echo "0")
    MED=$(echo "$ALL_ALERTS" | grep -ci "medium" 2>/dev/null || echo "0")
    LOW=$(echo "$ALL_ALERTS" | grep -ci "low" 2>/dev/null || echo "0")
    INFO_SEV=$(echo "$ALL_ALERTS" | grep -ci "informational" 2>/dev/null || echo "0")

    echo -e "  Critical: $CRIT  |  High: $HIGH  |  Medium: $MED  |  Low: $LOW  |  Info: $INFO_SEV"

    # Critical alerts at idle are suspicious
    if [ "$CRIT" -gt 0 ]; then
        warn "$CRIT critical alerts at idle — review for false positives"
        echo "$ALL_ALERTS" | grep -i "critical" | head -5 | while IFS='|' read -r rid rtitle pname ppath sev; do
            echo -e "    ${RED}$rtitle | $pname ($ppath)${NC}"
        done
    else
        pass "No critical alerts at idle"
    fi
else
    pass "Clean idle — no alerts generated"
fi

# ═══════════════════════════════════════════════════
header "6. DAEMON LOG CHECK"
# ═══════════════════════════════════════════════════

# Check daemon log for error patterns
LOG_FILE="/tmp/maccrab_fp_test.log"
if [ -f "$LOG_FILE" ]; then
    ERROR_LINES=$(grep -ci "error\|fatal\|crash\|panic" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$ERROR_LINES" -gt 0 ]; then
        warn "$ERROR_LINES error-level log entries"
        grep -i "error\|fatal\|crash\|panic" "$LOG_FILE" | head -5 | sed 's/^/    /'
    else
        pass "No errors in daemon log"
    fi

    # Check for any CRIT lines in stdout (the old-style alerts)
    CRIT_LINES=$(grep -c "^\[CRIT\]" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$CRIT_LINES" -gt 0 ]; then
        warn "$CRIT_LINES [CRIT] lines in daemon output"
        grep "^\[CRIT\]" "$LOG_FILE" | head -5 | sed 's/^/    /'
    else
        pass "No [CRIT] alerts in daemon output"
    fi
fi

# ═══════════════════════════════════════════════════
header "RESULTS"
# ═══════════════════════════════════════════════════

echo ""
echo "════════════════════════════════════════════════════"
echo -e "  ${GREEN}Passed:${NC}   $PASS"
echo -e "  ${RED}Failed:${NC}   $FAIL"
echo -e "  ${YELLOW}Warnings:${NC} $WARN"
echo -e "  Total:    $TOTAL"
echo "════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n${RED}FALSE POSITIVES DETECTED!${NC}"
    echo "Review the failures above and update allowlists in:"
    echo "  - Sources/MacCrabCore/Collectors/EventTapMonitor.swift"
    echo "  - Detection rules in Rules/"
    echo "  - suppressions.json via: maccrabctl suppress <rule-id> <process-path>"
    exit 1
elif [ "$WARN" -gt 0 ]; then
    echo -e "\n${YELLOW}Passed with warnings — review items above.${NC}"
    exit 0
else
    echo -e "\n${GREEN}All clear — no false positives detected!${NC}"
    exit 0
fi
