#!/bin/bash
# MacCrab Uninstall Script
# Must be run with sudo.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
SUPPORT_DIR="/Library/Application Support/MacCrab"
PLIST_NAME="com.maccrab.daemon"
PLIST_DIR="/Library/LaunchDaemons"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo."
fi

# Stop daemon
if launchctl list "$PLIST_NAME" &>/dev/null; then
    info "Stopping daemon..."
    launchctl unload "$PLIST_DIR/$PLIST_NAME.plist" 2>/dev/null || true
fi

# Kill any remaining process
pkill -x maccrabd 2>/dev/null || true

# Remove files
info "Removing binaries..."
rm -f "$PREFIX/bin/maccrabd" "$PREFIX/bin/maccrabctl"

info "Removing launchd plist..."
rm -f "$PLIST_DIR/$PLIST_NAME.plist"

# Ask about data
echo ""
read -p "Remove MacCrab data (events.db, rules, logs)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    info "Removing data directory..."
    rm -rf "$SUPPORT_DIR"
else
    warn "Data preserved at: $SUPPORT_DIR"
fi

echo ""
info "MacCrab uninstalled."
