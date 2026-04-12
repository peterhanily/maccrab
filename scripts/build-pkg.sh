#!/bin/bash
# build-pkg.sh — Create a macOS .pkg installer for MacCrab
#
# Produces a standard macOS installer package that:
#   - Installs maccrabd and maccrabctl to /usr/local/bin
#   - Installs MacCrab.app to /Applications
#   - Installs compiled rules to /Library/Application Support/MacCrab
#   - Installs LaunchDaemon plist for auto-start
#   - Runs postinstall script to set permissions and start daemon
#
# Usage:
#   ./scripts/build-pkg.sh                  # Uses pre-built binaries
#   VERSION=1.0.0 ./scripts/build-pkg.sh    # Explicit version
#
# For signed packages:
#   INSTALLER_CERT="Developer ID Installer: Name (ID)" ./scripts/build-pkg.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="${VERSION:-1.0.0}"
IDENTIFIER="com.maccrab"
PKG_ROOT="/tmp/maccrab-pkg-root-$$"
PKG_SCRIPTS="/tmp/maccrab-pkg-scripts-$$"
PKG_PATH="$PROJECT_DIR/.build/MacCrab-v$VERSION.pkg"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

cd "$PROJECT_DIR"

# Locate binaries
BIN_SOURCE=""
if [ -x ".build/release/maccrabd" ]; then
    BIN_SOURCE=".build/release"
elif [ -x "bin/maccrabd" ]; then
    BIN_SOURCE="bin"
else
    info "Building release binaries..."
    swift build -c release --arch arm64 2>&1 | tail -1
    BIN_SOURCE=".build/release"
fi

info "Creating package root..."

# Clean up any previous run
rm -rf "$PKG_ROOT" "$PKG_SCRIPTS"

# Create package root structure
mkdir -p "$PKG_ROOT/usr/local/bin"
mkdir -p "$PKG_ROOT/Applications"
mkdir -p "$PKG_ROOT/Library/Application Support/MacCrab/compiled_rules/sequences"
mkdir -p "$PKG_ROOT/Library/LaunchDaemons"

# Install binaries
cp "$BIN_SOURCE/maccrabd" "$PKG_ROOT/usr/local/bin/maccrabd"
cp "$BIN_SOURCE/maccrabctl" "$PKG_ROOT/usr/local/bin/maccrabctl"
chmod 755 "$PKG_ROOT/usr/local/bin/maccrabd" "$PKG_ROOT/usr/local/bin/maccrabctl"
info "Binaries staged."

# Install app bundle (if available)
if [ -d ".build/MacCrab.app" ]; then
    cp -r ".build/MacCrab.app" "$PKG_ROOT/Applications/"
elif [ -d "/tmp/maccrab-release-*/MacCrab.app" ] 2>/dev/null; then
    cp -r /tmp/maccrab-release-*/MacCrab.app "$PKG_ROOT/Applications/"
fi

# Install compiled rules
if [ -d ".build/compiled_rules" ] && [ "$(find .build/compiled_rules -name '*.json' | head -1)" ]; then
    cp .build/compiled_rules/*.json "$PKG_ROOT/Library/Application Support/MacCrab/compiled_rules/" 2>/dev/null || true
    cp .build/compiled_rules/sequences/*.json "$PKG_ROOT/Library/Application Support/MacCrab/compiled_rules/sequences/" 2>/dev/null || true
elif [ -d "Rules" ] && command -v python3 &>/dev/null; then
    info "Compiling rules..."
    python3 Compiler/compile_rules.py \
        --input-dir Rules/ \
        --output-dir "$PKG_ROOT/Library/Application Support/MacCrab/compiled_rules" 2>&1 | tail -1
fi

RULE_COUNT=$(find "$PKG_ROOT/Library/Application Support/MacCrab/compiled_rules" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
info "$RULE_COUNT rules staged."

# Install LaunchDaemon plist
cp com.maccrab.daemon.plist "$PKG_ROOT/Library/LaunchDaemons/com.maccrab.daemon.plist"

# Create postinstall script
mkdir -p "$PKG_SCRIPTS"
cat > "$PKG_SCRIPTS/postinstall" << 'POSTINSTALL'
#!/bin/bash
# MacCrab postinstall — set permissions and start daemon

SUPPORT_DIR="/Library/Application Support/MacCrab"

# Ensure correct permissions
chmod 755 /usr/local/bin/maccrabd /usr/local/bin/maccrabctl
chmod -R 644 "$SUPPORT_DIR/compiled_rules/"*.json 2>/dev/null || true
find "$SUPPORT_DIR/compiled_rules" -type d -exec chmod 755 {} \;
chown root:wheel /Library/LaunchDaemons/com.maccrab.daemon.plist
chmod 644 /Library/LaunchDaemons/com.maccrab.daemon.plist

# Create log directory
mkdir -p "$SUPPORT_DIR/logs"

# Stop existing daemon if running
launchctl unload /Library/LaunchDaemons/com.maccrab.daemon.plist 2>/dev/null || true

# Start daemon
launchctl load /Library/LaunchDaemons/com.maccrab.daemon.plist

# Remove quarantine from app
xattr -cr /Applications/MacCrab.app 2>/dev/null || true

exit 0
POSTINSTALL
chmod +x "$PKG_SCRIPTS/postinstall"

# Create preinstall script (stop existing daemon before upgrade)
cat > "$PKG_SCRIPTS/preinstall" << 'PREINSTALL'
#!/bin/bash
# Stop existing MacCrab daemon before install/upgrade
launchctl unload /Library/LaunchDaemons/com.maccrab.daemon.plist 2>/dev/null || true
killall maccrabd 2>/dev/null || true
exit 0
PREINSTALL
chmod +x "$PKG_SCRIPTS/preinstall"

# Build component package
info "Building component package..."
mkdir -p "$(dirname "$PKG_PATH")"

COMPONENT_PKG="/tmp/maccrab-component-$$.pkg"

pkgbuild \
    --root "$PKG_ROOT" \
    --scripts "$PKG_SCRIPTS" \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --install-location "/" \
    --ownership recommended \
    "$COMPONENT_PKG"

# Create distribution XML for a proper installer experience
DIST_XML="/tmp/maccrab-dist-$$.xml"
cat > "$DIST_XML" << DIST
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>MacCrab v$VERSION</title>
    <welcome file="welcome.html"/>
    <license file="license.txt"/>
    <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="13.0"/>
        </allowed-os-versions>
    </volume-check>
    <choices-outline>
        <line choice="default">
            <line choice="com.maccrab"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.maccrab" visible="false">
        <pkg-ref id="com.maccrab"/>
    </choice>
    <pkg-ref id="com.maccrab" version="$VERSION" onConclusion="none">#maccrab.pkg</pkg-ref>
</installer-gui-script>
DIST

# Create resources directory with welcome and license
PKG_RESOURCES="/tmp/maccrab-pkg-resources-$$"
mkdir -p "$PKG_RESOURCES"

cat > "$PKG_RESOURCES/welcome.html" << 'WELCOME'
<html>
<body style="font-family: -apple-system, Helvetica, sans-serif; padding: 20px;">
<h1>MacCrab</h1>
<p><strong>Real-time threat detection for macOS</strong></p>
<p>This installer will set up:</p>
<ul>
    <li><strong>maccrabd</strong> — Detection daemon (auto-starts on boot)</li>
    <li><strong>maccrabctl</strong> — Command-line interface</li>
    <li><strong>MacCrab.app</strong> — Dashboard (menu bar app)</li>
    <li><strong>Detection rules</strong> — 376 Sigma-compatible rules</li>
</ul>
<p style="margin-top: 20px; padding: 10px; background: #fff3cd; border-radius: 5px;">
    <strong>After installation:</strong> Grant Full Disk Access to <code>/usr/local/bin/maccrabd</code> in
    System Settings &gt; Privacy &amp; Security for complete detection coverage.
</p>
</body>
</html>
WELCOME

cp "$PROJECT_DIR/LICENSE" "$PKG_RESOURCES/license.txt"

# Build product archive
info "Building installer package..."
productbuild \
    --distribution "$DIST_XML" \
    --resources "$PKG_RESOURCES" \
    --package-path "$(dirname "$COMPONENT_PKG")" \
    "$PKG_PATH"

# Sign if certificate available
if [ -n "${INSTALLER_CERT:-}" ]; then
    info "Signing package with: $INSTALLER_CERT"
    SIGNED_PKG="${PKG_PATH%.pkg}-signed.pkg"
    productsign --sign "$INSTALLER_CERT" "$PKG_PATH" "$SIGNED_PKG"
    mv "$SIGNED_PKG" "$PKG_PATH"
    info "Package signed."
fi

# Cleanup
rm -rf "$PKG_ROOT" "$PKG_SCRIPTS" "$COMPONENT_PKG" "$DIST_XML" "$PKG_RESOURCES"

echo ""
echo "═══════════════════════════════════════"
echo "  MacCrab v$VERSION Installer Package"
echo "═══════════════════════════════════════"
echo ""
echo "  PKG: $PKG_PATH"
echo "  Size: $(du -h "$PKG_PATH" | cut -f1)"
echo "  Rules: $RULE_COUNT"
echo ""
echo "  Install: double-click the .pkg file"
echo "  Or CLI:  sudo installer -pkg '$PKG_PATH' -target /"
echo ""
