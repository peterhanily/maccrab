#!/bin/bash
# HawkEye Install Script
# Builds, compiles rules, and installs the daemon + CLI tools.
# Must be run with sudo for system-wide installation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

PREFIX="${PREFIX:-/usr/local}"
SUPPORT_DIR="/Library/Application Support/HawkEye"
PLIST_NAME="com.hawkeye.daemon"
PLIST_DIR="/Library/LaunchDaemons"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

# Check root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo."
fi

cd "$PROJECT_DIR"

# Build
info "Building HawkEye (release mode)..."
swift build -c release 2>&1 | tail -3

# Create directories
info "Creating directories..."
mkdir -p "$SUPPORT_DIR"/{compiled_rules/sequences,logs}
chmod 755 "$SUPPORT_DIR"
mkdir -p "$PREFIX/bin"

# Install binaries
info "Installing binaries to $PREFIX/bin..."
cp -f .build/release/hawkeyed "$PREFIX/bin/hawkeyed"
cp -f .build/release/hawkctl "$PREFIX/bin/hawkctl"
chmod 755 "$PREFIX/bin/hawkeyed" "$PREFIX/bin/hawkctl"

# Install entitlements (for reference; codesigning must be done separately)
cp -f entitlements.plist "$SUPPORT_DIR/entitlements.plist"

# Compile and install rules
info "Compiling detection rules..."
python3 Compiler/compile_rules.py \
    --input-dir Rules/ \
    --output-dir "$SUPPORT_DIR/compiled_rules" 2>&1 | tail -5

# Install launchd plist
info "Installing launchd daemon plist..."
if launchctl list "$PLIST_NAME" &>/dev/null; then
    warn "Stopping existing daemon..."
    launchctl unload "$PLIST_DIR/$PLIST_NAME.plist" 2>/dev/null || true
fi
cp -f "$PLIST_NAME.plist" "$PLIST_DIR/$PLIST_NAME.plist"
chown root:wheel "$PLIST_DIR/$PLIST_NAME.plist"
chmod 644 "$PLIST_DIR/$PLIST_NAME.plist"

# Start daemon
info "Starting HawkEye daemon..."
launchctl load "$PLIST_DIR/$PLIST_NAME.plist"

# Verify
sleep 2
if pgrep -x hawkeyed >/dev/null; then
    info "HawkEye daemon is running (PID $(pgrep -x hawkeyed))."
else
    warn "Daemon may not have started. Check: sudo launchctl list $PLIST_NAME"
    warn "Logs: $SUPPORT_DIR/hawkeyed.log"
fi

echo ""
info "Installation complete!"
echo "  Daemon:   $PREFIX/bin/hawkeyed"
echo "  CLI:      $PREFIX/bin/hawkctl"
echo "  Rules:    $SUPPORT_DIR/compiled_rules/"
echo "  Logs:     $SUPPORT_DIR/hawkeyed.log"
echo ""
echo "  Usage:    hawkctl status"
echo "            hawkctl events tail 20"
echo "            hawkctl alerts 10"
echo ""
warn "Note: Full Endpoint Security support requires granting"
warn "Full Disk Access to hawkeyed in System Settings > Privacy."
