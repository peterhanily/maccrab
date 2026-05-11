#!/bin/bash
# MacCrab Install Script
#
# v1.3.0 onwards: maccrabd is no longer a standalone binary. The ES
# detection engine lives inside MacCrab.app as a system extension that
# gets activated when you first launch the app and approve it in
# System Settings > General > Login Items & Extensions. This script:
#
#   1. Cleans up legacy LaunchDaemons and provisioning profiles left
#      over from 1.2.x installs on the same machine
#   2. Installs compiled rules under /Library/Application Support/MacCrab
#   3. Installs maccrabctl + maccrab-mcp CLI tools
#   4. Copies MacCrab.app to /Applications
#   5. Reminds the user to launch the app and approve the extension
#
# Must be run with sudo. Homebrew cask users never invoke this
# directly — the cask's postflight block mirrors the same steps.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

PREFIX="${PREFIX:-/usr/local}"
SUPPORT_DIR="/Library/Application Support/MacCrab"
PLIST_DIR="/Library/LaunchDaemons"
PROFILE_DIR="/Library/MobileDevice/Provisioning Profiles"

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

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         🦀 MacCrab Installation (v1.3.0+)        ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ─── Step 1: Clean up legacy 1.2.x artefacts ─────────────────────────
# 1.2.x shipped maccrabd as a LaunchDaemon with a stapled provisioning
# profile installed system-wide. 1.3.0 moved to a proper SystemExtension
# activated on first launch of MacCrab.app. Strip the old plumbing so
# the two models don't fight.

info "Cleaning up pre-1.3.0 LaunchDaemons and symlinks..."
for label in com.maccrab.daemon com.maccrab.agent; do
    if launchctl list "$label" &>/dev/null; then
        launchctl unload "$PLIST_DIR/$label.plist" 2>/dev/null || true
    fi
    rm -f "$PLIST_DIR/$label.plist"
done

for stale in "$PREFIX/bin/maccrabd" "/usr/local/bin/maccrabd" "/opt/homebrew/bin/maccrabd"; do
    if [ -L "$stale" ] || [ -f "$stale" ]; then
        rm -f "$stale"
    fi
done

# Legacy system-wide provisioning profile from 1.2.4/1.2.5. Not needed
# once the app's embedded profile takes over.
if [ -d "$PROFILE_DIR" ]; then
    for profile in "$PROFILE_DIR"/*.provisionprofile; do
        [ -f "$profile" ] || continue
        app_id=$(security cms -D -i "$profile" 2>/dev/null \
            | /usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" /dev/stdin 2>/dev/null \
            || echo "")
        if [[ "$app_id" == *"com.maccrab."* ]]; then
            rm -f "$profile"
            info "Removed legacy profile: $(basename "$profile")"
        fi
    done
fi

# ─── Step 2: Support dir + rules ─────────────────────────────────────
info "Creating $SUPPORT_DIR..."
mkdir -p "$SUPPORT_DIR"/{compiled_rules/sequences,logs,inbox}
chmod 755 "$SUPPORT_DIR"
# v1.10.0 audit fix: inbox/ is the cross-UID IPC drop point for the
# dashboard's "Reduce events.db now" button. Sticky bit (1777) lets
# the user-context dashboard write a marker file the root-context
# sysext picks up + processes, without granting blanket write access
# to the rest of the support dir.
chmod 1777 "$SUPPORT_DIR/inbox"

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
    warn "No rules found to install."
fi

chmod -R 644 "$SUPPORT_DIR/compiled_rules/"*.json 2>/dev/null || true
chmod -R 644 "$SUPPORT_DIR/compiled_rules/sequences/"*.json 2>/dev/null || true
find "$SUPPORT_DIR/compiled_rules" -type d -exec chmod 755 {} \;

RULE_COUNT=$(find "$SUPPORT_DIR/compiled_rules" -name '*.json' | wc -l | tr -d ' ')
info "Installed $RULE_COUNT compiled rules."

# ─── Step 3: Install MacCrab.app (moved before CLI step) ─────────────
# Order matters: we want to symlink CLIs into the .app's bundled
# Resources/bin so Sparkle in-place updates keep the terminal CLI
# current. Pre-fix the script copied loose CLIs to $PREFIX/bin —
# those copies stayed frozen at install time and went stale after
# every Sparkle update.
if [ -d "$PROJECT_DIR/MacCrab.app" ]; then
    info "Installing MacCrab.app to /Applications..."
    rm -rf "/Applications/MacCrab.app"
    cp -R "$PROJECT_DIR/MacCrab.app" "/Applications/MacCrab.app"
    chown -R root:admin "/Applications/MacCrab.app"
    chmod -R go-w "/Applications/MacCrab.app"
fi

# ─── Step 4: CLI symlinks ────────────────────────────────────────────
# Prefer symlinks pointing at the in-app CLIs over loose copies,
# so the user's terminal `maccrabctl` always tracks the running
# MacCrab.app version (including Sparkle in-place upgrades).
APP_BIN="/Applications/MacCrab.app/Contents/Resources/bin"
mkdir -p "$PREFIX/bin"

if [ -x "$APP_BIN/maccrabctl" ]; then
    info "Linking CLI binaries from $APP_BIN to $PREFIX/bin..."
    for cli in maccrabctl maccrab-mcp; do
        if [ -x "$APP_BIN/$cli" ]; then
            rm -f "$PREFIX/bin/$cli"
            ln -s "$APP_BIN/$cli" "$PREFIX/bin/$cli"
        fi
    done
else
    # Fallback: bundled .app didn't include the CLIs (older build,
    # or the .app wasn't installed). Copy from PROJECT_DIR/bin or
    # .build/release. These are static copies and won't auto-update.
    BIN_SOURCE=""
    if [ -x "$PROJECT_DIR/bin/maccrabctl" ]; then
        BIN_SOURCE="$PROJECT_DIR/bin"
    elif [ -x "$PROJECT_DIR/.build/release/maccrabctl" ]; then
        BIN_SOURCE="$PROJECT_DIR/.build/release"
    fi
    if [ -n "$BIN_SOURCE" ]; then
        warn "MacCrab.app does not contain bundled CLIs — falling back to static copies. These won't auto-update with Sparkle; reinstall after upgrade."
        cp -f "$BIN_SOURCE/maccrabctl" "$PREFIX/bin/maccrabctl"
        chmod 755 "$PREFIX/bin/maccrabctl"
        if [ -f "$BIN_SOURCE/maccrab-mcp" ]; then
            cp -f "$BIN_SOURCE/maccrab-mcp" "$PREFIX/bin/maccrab-mcp"
            chmod 755 "$PREFIX/bin/maccrab-mcp"
        fi
    else
        warn "CLI binaries not found (checked $APP_BIN, bin/, and .build/release/)."
    fi
fi

# Detect Apple Silicon: $PREFIX defaults to /usr/local but Apple
# Silicon's $PATH usually has /opt/homebrew/bin first. If a stale
# brew-cask CLI lives there from an older install, replace it with
# a symlink to the current in-app CLI so `which maccrabctl` returns
# a current binary regardless of which $PREFIX we wrote to.
if [ "$(uname -m)" = "arm64" ] && [ -d "/opt/homebrew/bin" ] && [ -x "$APP_BIN/maccrabctl" ]; then
    for cli in maccrabctl maccrab-mcp; do
        if [ -x "$APP_BIN/$cli" ] && [ "/opt/homebrew/bin" != "$PREFIX/bin" ]; then
            link="/opt/homebrew/bin/$cli"
            target=$(readlink "$link" 2>/dev/null || echo "")
            # Replace if missing OR if it's a stale brew-cask path
            if [ ! -e "$link" ] || [[ "$target" == *"/Caskroom/maccrab/"* ]] || \
               { [ -f "$link" ] && ! [ -L "$link" ]; }; then
                rm -f "$link"
                ln -s "$APP_BIN/$cli" "$link"
                info "Refreshed stale /opt/homebrew/bin/$cli → in-app CLI"
            fi
        fi
    done
fi

echo ""
info "Installation complete."
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  NEXT STEPS                                      ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║                                                  ║"
echo "║  1. Launch /Applications/MacCrab.app             ║"
echo "║  2. Click \"Enable Protection\" on the Overview tab║"
echo "║  3. macOS will prompt you to approve the         ║"
echo "║     Endpoint Security extension in System        ║"
echo "║     Settings > General > Login Items &           ║"
echo "║     Extensions > Endpoint Security Extensions.   ║"
echo "║  4. (Optional) Grant Full Disk Access to         ║"
echo "║     MacCrab.app for full coverage.               ║"
echo "║                                                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Optionally open System Settings to the right pane
read -p "Open MacCrab.app now? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    open "/Applications/MacCrab.app" 2>/dev/null || \
        warn "Could not launch MacCrab.app automatically. Open it from /Applications."
fi
