#!/bin/bash
#
# dev.sh — Build, codesign, and (re)start the MacCrab daemon for development.
#
# Usage:
#   ./scripts/dev.sh           Build + sign + restart daemon (sudo required for ES)
#   ./scripts/dev.sh --no-es   Build + restart without root (no Endpoint Security)
#   ./scripts/dev.sh --build   Build + sign only, don't start daemon
#   ./scripts/dev.sh --restart Restart daemon only (no rebuild)
#   ./scripts/dev.sh --stop    Stop daemon and app
#   ./scripts/dev.sh --status  Show daemon status
#
# The script:
#   1. Builds the debug binary via swift build
#   2. Compiles detection rules (YAML -> JSON)
#   3. Codesigns maccrabd with the ES entitlement
#   4. Stops any running daemon/app
#   5. Starts the daemon (with sudo for ES, or without for limited sources)
#   6. Optionally opens the GUI app

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/.build/debug"
ENTITLEMENTS="$PROJECT_DIR/entitlements.plist"
DAEMON="$BUILD_DIR/maccrabd"
CTL="$BUILD_DIR/maccrabctl"
APP_BUNDLE="$BUILD_DIR/MacCrab.app"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}==>${NC} ${BOLD}$1${NC}"; }
ok()    { echo -e "${GREEN}  ✓${NC} $1"; }
warn()  { echo -e "${YELLOW}  ⚠${NC} $1"; }
fail()  { echo -e "${RED}  ✗${NC} $1"; exit 1; }

# ─── Stop daemon and app ──────────────────────────────────────────────

stop_daemon() {
    if pgrep -x maccrabd > /dev/null 2>&1; then
        info "Stopping running daemon..."
        # Cache sudo credentials up front (single password prompt)
        sudo -v
        sudo kill $(pgrep -x maccrabd) 2>/dev/null || true
        sleep 1
        # Force kill if still running
        if pgrep -x maccrabd > /dev/null 2>&1; then
            sudo kill -9 $(pgrep -x maccrabd) 2>/dev/null || true
            sleep 1
        fi
        ok "Daemon stopped"
    fi
    pkill -x MacCrabApp 2>/dev/null || true
    pkill -x MacCrab 2>/dev/null || true
}

# ──�� Build ─────────────────────────────────────────────────────────────

do_build() {
    info "Building MacCrab..."
    cd "$PROJECT_DIR"
    if swift build 2>&1 | tail -1 | grep -q "Build complete"; then
        ok "Build succeeded"
    else
        swift build 2>&1 | tail -5
        fail "Build failed"
    fi
}

# ─── Compile rules ────────────────────────────────────────────────────

compile_rules() {
    info "Compiling detection rules..."
    local rules_out="$BUILD_DIR/compiled_rules"
    mkdir -p "$rules_out/sequences"

    local output
    output=$(python3 "$PROJECT_DIR/Compiler/compile_rules.py" \
        --input-dir "$PROJECT_DIR/Rules/" \
        --output-dir "$rules_out" 2>&1 | tail -1)
    ok "$output"

    # Copy to user Application Support for non-root runs
    local user_rules="$HOME/Library/Application Support/MacCrab/compiled_rules"
    mkdir -p "$user_rules/sequences"
    cp -f "$rules_out"/*.json "$user_rules/" 2>/dev/null || true
    cp -f "$rules_out"/sequences/*.json "$user_rules/sequences/" 2>/dev/null || true

    # Copy to system Application Support for root daemon (if writable)
    local sys_rules="/Library/Application Support/MacCrab/compiled_rules"
    if [ -w "$sys_rules" ] 2>/dev/null || sudo -n true 2>/dev/null; then
        sudo mkdir -p "$sys_rules/sequences" 2>/dev/null
        sudo cp -f "$rules_out"/*.json "$sys_rules/" 2>/dev/null
        sudo cp -f "$rules_out"/sequences/*.json "$sys_rules/sequences/" 2>/dev/null
        ok "Rules deployed to system directory"
    fi
}

# ─── Codesign with ES entitlement ─────────────────────────────────────

codesign_binary() {
    info "Codesigning with ES entitlement..."
    if [ ! -f "$ENTITLEMENTS" ]; then
        fail "Entitlements file not found: $ENTITLEMENTS"
    fi

    codesign --sign - \
        --entitlements "$ENTITLEMENTS" \
        --force \
        "$DAEMON" 2>/dev/null

    ok "maccrabd signed with com.apple.developer.endpoint-security.client"

    # Also sign maccrabctl and app
    codesign --sign - --force "$CTL" 2>/dev/null
    ok "maccrabctl signed"

    if [ -d "$APP_BUNDLE" ]; then
        codesign --sign - --force "$APP_BUNDLE" 2>/dev/null
        ok "MacCrab.app signed"
    fi
}

# ─── Bundle app ───────────────────────────────────────────────────────

bundle_app() {
    if [ -x "$PROJECT_DIR/scripts/bundle-app.sh" ]; then
        info "Bundling MacCrab.app..."
        "$PROJECT_DIR/scripts/bundle-app.sh" 2>/dev/null
        ok "App bundle created"
    fi
}

# ─── Log rotation ─────────────────────────────────────────────────────

rotate_log() {
    local log="/tmp/maccrabd.log"
    if [ -f "$log" ]; then
        local size
        size=$(stat -f%z "$log" 2>/dev/null || echo 0)
        if [ "$size" -gt 10485760 ]; then  # 10MB
            mv "$log" "$log.$(date +%s)"
            # Keep only last 3 rotated logs
            ls -t /tmp/maccrabd.log.* 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null
        fi
    fi
}

# ─── Start daemon ─────────────────────────────────────────────────────

start_daemon() {
    local use_sudo="$1"
    rotate_log

    if [ "$use_sudo" = "true" ]; then
        info "Starting daemon with Endpoint Security (sudo)..."
        # Cache sudo credentials before backgrounding to avoid TTY issues
        sudo -v
        sudo nohup "$DAEMON" > /tmp/maccrabd.log 2>&1 &
        sleep 3

        if pgrep -x maccrabd > /dev/null 2>&1; then
            local pid
            pid=$(pgrep -x maccrabd)
            ok "Daemon running (PID $pid) with ES support"
            head -20 /tmp/maccrabd.log 2>/dev/null || true
        else
            # ES-entitled binary was likely killed by macOS (needs approval)
            warn "ES-entitled daemon was killed by macOS"
            echo ""
            echo -e "  ${YELLOW}macOS blocks ES-entitled binaries after rebuild (new hash).${NC}"
            echo -e "  ${YELLOW}Two options:${NC}"
            echo ""
            echo -e "  ${BOLD}Option 1:${NC} Approve in System Settings > Privacy & Security > Allow Anyway"
            echo -e "           Then re-run: ${CYAN}./scripts/dev.sh${NC}"
            echo ""
            echo -e "  ${BOLD}Option 2:${NC} Run without ES (other sources still work):"
            echo ""

            # Re-sign WITHOUT ES entitlement and start without sudo
            info "Falling back to non-ES mode..."
            codesign --sign - --force "$DAEMON" 2>/dev/null
            nohup "$DAEMON" > /tmp/maccrabd.log 2>&1 &
            sleep 3

            if pgrep -x maccrabd > /dev/null 2>&1; then
                local pid
                pid=$(pgrep -x maccrabd)
                ok "Daemon running (PID $pid) — no ES (Unified Log, TCC, Network active)"
                head -20 /tmp/maccrabd.log 2>/dev/null || true
            else
                warn "Daemon failed to start — log output:"
                cat /tmp/maccrabd.log 2>/dev/null || true
            fi
        fi
    else
        info "Starting daemon without root (limited sources)..."
        nohup "$DAEMON" > /tmp/maccrabd.log 2>&1 &
        sleep 3
        if pgrep -x maccrabd > /dev/null 2>&1; then
            local pid
            pid=$(pgrep -x maccrabd)
            ok "Daemon running (PID $pid) — no ES (run with sudo for full coverage)"
            head -20 /tmp/maccrabd.log 2>/dev/null || true
        else
            warn "Daemon failed to start — log output:"
            cat /tmp/maccrabd.log 2>/dev/null || true
        fi
    fi
}

# ─── Show status ──────────────────────────────────────────────────────

show_status() {
    echo ""
    if pgrep -x maccrabd > /dev/null 2>&1; then
        local pid
        pid=$(pgrep -x maccrabd)
        ok "Daemon is running (PID $pid)"
        # Show recent log output
        if [ -f /tmp/maccrabd.log ]; then
            echo ""
            info "Recent daemon output:"
            tail -10 /tmp/maccrabd.log 2>/dev/null || true
        fi
    else
        warn "Daemon is not running"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────

main() {
    local mode="${1:-full}"

    echo ""
    echo -e "${BOLD}MacCrab Development Script${NC}"
    echo ""

    case "$mode" in
        --stop)
            stop_daemon
            ok "All MacCrab processes stopped"
            ;;
        --status)
            show_status
            ;;
        --build)
            do_build
            compile_rules
            codesign_binary
            bundle_app
            ok "Build complete — ready to run"
            ;;
        --restart)
            stop_daemon
            start_daemon true
            show_status
            ;;
        --no-es)
            do_build
            compile_rules
            bundle_app
            stop_daemon
            start_daemon false
            show_status
            ;;
        full|"")
            do_build
            compile_rules
            codesign_binary
            bundle_app
            stop_daemon
            start_daemon true
            show_status
            ;;
        --help|-h)
            echo "Usage: ./scripts/dev.sh [option]"
            echo ""
            echo "Options:"
            echo "  (none)      Full cycle: build + sign + restart with ES (sudo)"
            echo "  --no-es     Build + restart without root (no Endpoint Security)"
            echo "  --build     Build + sign only, don't start daemon"
            echo "  --restart   Restart daemon only (no rebuild)"
            echo "  --stop      Stop daemon and app"
            echo "  --status    Show daemon status"
            echo "  --help      Show this help"
            ;;
        *)
            fail "Unknown option: $mode (try --help)"
            ;;
    esac

    echo ""
}

main "$@"
