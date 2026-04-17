#!/bin/bash
# MacCrab Install Script
# Builds, compiles rules, and installs the daemon + CLI tools.
# Must be run with sudo for system-wide installation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

PREFIX="${PREFIX:-/usr/local}"
SUPPORT_DIR="/Library/Application Support/MacCrab"
PLIST_NAME="com.maccrab.agent"
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

# Language selection
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         🦀 MacCrab Installation                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Select your language / Seleccione su idioma:"
echo ""
echo "  1) English"
echo "  2) Español (Spanish)"
echo "  3) Français (French)"
echo "  4) Deutsch (German)"
echo "  5) 日本語 (Japanese)"
echo "  6) 简体中文 (Simplified Chinese)"
echo "  7) 한국어 (Korean)"
echo "  8) Português (Brazilian Portuguese)"
echo "  9) Italiano (Italian)"
echo " 10) Nederlands (Dutch)"
echo " 11) 繁體中文 (Traditional Chinese)"
echo " 12) Русский (Russian)"
echo " 13) Svenska (Swedish)"
echo " 14) Polski (Polish)"
echo ""
read -p "Language [1]: " LANG_CHOICE
LANG_CHOICE="${LANG_CHOICE:-1}"

LANG_CODE="en"
LANG_NAME="English"
case "$LANG_CHOICE" in
    1)  LANG_CODE="en";      LANG_NAME="English" ;;
    2)  LANG_CODE="es";      LANG_NAME="Español" ;;
    3)  LANG_CODE="fr";      LANG_NAME="Français" ;;
    4)  LANG_CODE="de";      LANG_NAME="Deutsch" ;;
    5)  LANG_CODE="ja";      LANG_NAME="日本語" ;;
    6)  LANG_CODE="zh-Hans"; LANG_NAME="简体中文" ;;
    7)  LANG_CODE="ko";      LANG_NAME="한국어" ;;
    8)  LANG_CODE="pt-BR";   LANG_NAME="Português" ;;
    9)  LANG_CODE="it";      LANG_NAME="Italiano" ;;
    10) LANG_CODE="nl";      LANG_NAME="Nederlands" ;;
    11) LANG_CODE="zh-Hant"; LANG_NAME="繁體中文" ;;
    12) LANG_CODE="ru";      LANG_NAME="Русский" ;;
    13) LANG_CODE="sv";      LANG_NAME="Svenska" ;;
    14) LANG_CODE="pl";      LANG_NAME="Polski" ;;
esac

info "Language: $LANG_NAME ($LANG_CODE)"

# Set preferred language for MacCrab app
defaults write com.maccrab.app AppleLanguages -array "$LANG_CODE"
info "Set MacCrab dashboard language to $LANG_NAME"

echo ""

# Locate pre-built binaries or build from source
# Priority: 1) DMG mount (bin/), 2) .build/release/, 3) build from source.
# The daemon binary (maccrabd) lives inside MacCrab.app/Contents/Library/
# LaunchDaemons in 1.2.5+ — we only need maccrabctl here; the .app is
# installed further down.
BIN_SOURCE=""
if [ -x "$PROJECT_DIR/bin/maccrabctl" ]; then
    BIN_SOURCE="$PROJECT_DIR/bin"
    info "Using pre-built binaries from DMG."
elif [ -x "$PROJECT_DIR/.build/release/maccrabctl" ]; then
    BIN_SOURCE="$PROJECT_DIR/.build/release"
    info "Using pre-built binaries from .build/release."
else
    info "No pre-built binaries found. Building from source (requires Xcode CLT)..."
    if ! command -v swift &>/dev/null; then
        error "Swift toolchain not found. Install Xcode Command Line Tools: xcode-select --install"
    fi
    swift build -c release 2>&1 | tail -3
    BIN_SOURCE="$PROJECT_DIR/.build/release"
fi

# Create directories
info "Creating directories..."
mkdir -p "$SUPPORT_DIR"/{compiled_rules/sequences,logs}
chmod 755 "$SUPPORT_DIR"
mkdir -p "$PREFIX/bin"

# Clean up any stale standalone maccrabd binary from pre-1.2.5 installs
# (1.2.4 shipped maccrabd at $PREFIX/bin/maccrabd but AMFI couldn't
# discover the provisioning profile there; 1.2.5 moved it inside the .app).
for stale in "$PREFIX/bin/maccrabd" "/usr/local/bin/maccrabd" "/opt/homebrew/bin/maccrabd"; do
    if [ -L "$stale" ] || [ -f "$stale" ]; then
        rm -f "$stale"
    fi
done

# Install CLI binaries. The daemon binary lives inside MacCrab.app
# (see "Install app" below) — AMFI only honours the ES entitlement
# when the binary is inside an app bundle.
info "Installing CLI binaries to $PREFIX/bin..."
cp -f "$BIN_SOURCE/maccrabctl" "$PREFIX/bin/maccrabctl"
chmod 755 "$PREFIX/bin/maccrabctl"
if [ -f "$BIN_SOURCE/maccrab-mcp" ]; then
    cp -f "$BIN_SOURCE/maccrab-mcp" "$PREFIX/bin/maccrab-mcp"
    chmod 755 "$PREFIX/bin/maccrab-mcp"
fi

# Install entitlements (for reference; codesigning must be done separately)
cp -f entitlements.plist "$SUPPORT_DIR/entitlements.plist" 2>/dev/null || true

# Compile and install rules — use pre-compiled if available, otherwise compile
if [ -d "$PROJECT_DIR/compiled_rules" ] && [ "$(find "$PROJECT_DIR/compiled_rules" -name '*.json' 2>/dev/null | head -1)" ]; then
    info "Installing pre-compiled detection rules..."
    cp -f "$PROJECT_DIR/compiled_rules/"*.json "$SUPPORT_DIR/compiled_rules/" 2>/dev/null || true
    cp -f "$PROJECT_DIR/compiled_rules/sequences/"*.json "$SUPPORT_DIR/compiled_rules/sequences/" 2>/dev/null || true
elif [ -d "$PROJECT_DIR/Rules" ] && command -v python3 &>/dev/null; then
    info "Compiling detection rules..."
    python3 Compiler/compile_rules.py \
        --input-dir Rules/ \
        --output-dir "$SUPPORT_DIR/compiled_rules" 2>&1 | tail -5
else
    warn "No rules found to install. Rules can be added later with: make compile-rules"
fi

# Ensure compiled rules have correct permissions
chmod -R 644 "$SUPPORT_DIR/compiled_rules/"*.json 2>/dev/null || true
chmod -R 644 "$SUPPORT_DIR/compiled_rules/sequences/"*.json 2>/dev/null || true
find "$SUPPORT_DIR/compiled_rules" -type d -exec chmod 755 {} \;

RULE_COUNT=$(find "$SUPPORT_DIR/compiled_rules" -name '*.json' | wc -l | tr -d ' ')
info "Installed $RULE_COUNT compiled rules."

# Upgrade path from the pre-1.2.4 identifier. The daemon was previously
# labelled com.maccrab.daemon; Apple bound the Endpoint Security
# entitlement to com.maccrab.agent, so we moved the LaunchDaemon label
# and plist filename to match. Unload and remove any lingering old plist
# before installing the new one so the user doesn't end up with two
# competing daemons trying to claim the same binary.
OLD_PLIST="$PLIST_DIR/com.maccrab.daemon.plist"
if [ -f "$OLD_PLIST" ]; then
    warn "Detected pre-1.2.4 com.maccrab.daemon.plist — migrating to com.maccrab.agent.plist..."
    launchctl unload "$OLD_PLIST" 2>/dev/null || true
    rm -f "$OLD_PLIST"
fi

# Install provisioning profile system-wide (needed for Endpoint Security
# entitlement to be honoured on this machine). Profile ships next to
# install.sh inside the DMG; name is whatever Apple issued it under.
PROFILE_SRC=""
if [ -f "$PROJECT_DIR/MacCrab.provisionprofile" ]; then
    PROFILE_SRC="$PROJECT_DIR/MacCrab.provisionprofile"
elif [ -f "$PROJECT_DIR/embedded.provisionprofile" ]; then
    PROFILE_SRC="$PROJECT_DIR/embedded.provisionprofile"
fi
if [ -n "$PROFILE_SRC" ]; then
    info "Installing provisioning profile (Endpoint Security entitlement)..."
    PROFILE_DIR="/Library/MobileDevice/Provisioning Profiles"
    mkdir -p "$PROFILE_DIR"
    # Extract the UUID via a temp plist file. Piping `security cms` into
    # `PlistBuddy /dev/stdin` is unreliable — PlistBuddy sometimes emits
    # "Error Reading File: /dev/stdin" to stdout, which would otherwise
    # contaminate the target filename.
    PROFILE_TMP=$(mktemp)
    security cms -D -i "$PROFILE_SRC" -o "$PROFILE_TMP" 2>/dev/null
    PROFILE_UUID=$(/usr/libexec/PlistBuddy -c "Print :UUID" "$PROFILE_TMP" 2>/dev/null || echo "")
    rm -f "$PROFILE_TMP"
    # Validate: real UUIDs are 8-4-4-4-12 hex. Reject anything else so
    # we never run cp with a garbage filename.
    if [[ "$PROFILE_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        cp -f "$PROFILE_SRC" "$PROFILE_DIR/$PROFILE_UUID.provisionprofile"
        chown root:wheel "$PROFILE_DIR/$PROFILE_UUID.provisionprofile"
        chmod 644 "$PROFILE_DIR/$PROFILE_UUID.provisionprofile"
        info "Profile installed: $PROFILE_UUID"
    else
        warn "Could not extract UUID from provisioning profile — ES may not work"
    fi
else
    warn "No provisioning profile found next to install.sh. Endpoint Security will"
    warn "fall back to eslogger/kdebug/FSEvents. Detection still works, just slower."
fi

# Install launchd plist. The plist's ProgramArguments already points to
# /Applications/MacCrab.app/Contents/Library/LaunchDaemons/maccrabd so no
# path rewriting is needed.
info "Installing launchd daemon plist..."
if launchctl list "$PLIST_NAME" &>/dev/null; then
    warn "Stopping existing daemon..."
    launchctl unload "$PLIST_DIR/$PLIST_NAME.plist" 2>/dev/null || true
fi

cp "$PLIST_NAME.plist" "$PLIST_DIR/$PLIST_NAME.plist"
chown root:wheel "$PLIST_DIR/$PLIST_NAME.plist"
chmod 644 "$PLIST_DIR/$PLIST_NAME.plist"

# Start daemon
info "Starting MacCrab daemon..."
launchctl load "$PLIST_DIR/$PLIST_NAME.plist"

# Post-install verification
info "Verifying installation..."
VERIFY_OK=true

sleep 2
if pgrep -x maccrabd >/dev/null; then
    info "Daemon is running (PID $(pgrep -x maccrabd))."
else
    warn "Daemon may not have started. Check: sudo launchctl list $PLIST_NAME"
    warn "Logs: $SUPPORT_DIR/maccrabd.log"
    VERIFY_OK=false
fi

DAEMON_PATH="/Applications/MacCrab.app/Contents/Library/LaunchDaemons/maccrabd"
if [ ! -x "$DAEMON_PATH" ]; then
    warn "Daemon not found or not executable: $DAEMON_PATH"
    VERIFY_OK=false
fi

if [ ! -x "$PREFIX/bin/maccrabctl" ]; then
    warn "CLI tool not found or not executable: $PREFIX/bin/maccrabctl"
    VERIFY_OK=false
fi

if [ "$RULE_COUNT" -lt 1 ]; then
    warn "No compiled rules found in $SUPPORT_DIR/compiled_rules/"
    VERIFY_OK=false
fi

if [ "$VERIFY_OK" = true ]; then
    info "All checks passed."
else
    warn "Some checks failed — review warnings above."
fi

echo ""
info "Installation complete!"
echo "  Daemon:   $DAEMON_PATH"
echo "  CLI:      $PREFIX/bin/maccrabctl"
echo "  Rules:    $SUPPORT_DIR/compiled_rules/"
echo "  Logs:     $SUPPORT_DIR/maccrabd.log"
echo ""
echo "  Usage:    maccrabctl status"
echo "            maccrabctl events tail 20"
echo "            maccrabctl alerts 10"
echo ""
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  IMPORTANT: Grant Full Disk Access               ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║                                                  ║"
echo "║  MacCrab needs Full Disk Access for complete      ║"
echo "║  threat detection coverage.                       ║"
echo "║                                                  ║"
echo "║  1. Open System Settings                          ║"
echo "║  2. Privacy & Security > Full Disk Access         ║"
echo "║  3. Click + and add MacCrab.app (drag it in,      ║"
echo "║     or click + and browse to /Applications/       ║"
echo "║     MacCrab.app)                                  ║"
echo "║  4. Restart the daemon: sudo launchctl unload     ║"
echo "║     $PLIST_DIR/$PLIST_NAME.plist"
echo "║     && sudo launchctl load                        ║"
echo "║     $PLIST_DIR/$PLIST_NAME.plist"
echo "║                                                  ║"
echo "║  Without FDA, detection runs at ~70% coverage.    ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
# Offer to open System Settings directly
read -p "Open Full Disk Access settings now? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || \
    open "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles" 2>/dev/null || \
    warn "Could not open System Settings automatically. Please open manually."
fi
