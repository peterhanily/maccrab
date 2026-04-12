#!/bin/bash
# build-release.sh — Build universal release binaries and create DMG
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="${VERSION:-1.0.0}"
BUILD_DIR="$PROJECT_DIR/.build/release"
STAGING_DIR="/tmp/maccrab-release-$$"

cd "$PROJECT_DIR"

echo "Building MacCrab v$VERSION..."

# Build for arm64
echo "  Building arm64..."
swift build -c release --arch arm64 2>&1 | tail -1

# Build for x86_64 (Rosetta compatible)
echo "  Building x86_64..."
swift build -c release --arch x86_64 2>&1 | tail -1

# Create universal binaries with lipo
echo "  Creating universal binaries..."
mkdir -p "$STAGING_DIR/bin"
for binary in maccrabd maccrabctl MacCrabApp; do
    ARM_BIN="$PROJECT_DIR/.build/arm64-apple-macosx/release/$binary"
    X86_BIN="$PROJECT_DIR/.build/x86_64-apple-macosx/release/$binary"
    if [ -f "$ARM_BIN" ] && [ -f "$X86_BIN" ]; then
        lipo -create "$ARM_BIN" "$X86_BIN" -output "$STAGING_DIR/bin/$binary"
        echo "    ✓ $binary (universal)"
    elif [ -f "$ARM_BIN" ]; then
        cp "$ARM_BIN" "$STAGING_DIR/bin/$binary"
        echo "    ✓ $binary (arm64 only)"
    fi
done

# Compile rules
echo "  Compiling detection rules..."
python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir "$STAGING_DIR/compiled_rules" 2>&1 | tail -1
cp -r Rules/ "$STAGING_DIR/rules_source/"

# Create app bundle
echo "  Creating MacCrab.app bundle..."
APP="$STAGING_DIR/MacCrab.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$STAGING_DIR/bin/MacCrabApp" "$APP/Contents/MacOS/MacCrab"
cat > "$APP/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>MacCrab</string>
    <key>CFBundleDisplayName</key><string>MacCrab</string>
    <key>CFBundleIdentifier</key><string>com.maccrab.app</string>
    <key>CFBundleVersion</key><string>1.0.0</string>
    <key>CFBundleShortVersionString</key><string>1.0.0</string>
    <key>CFBundleExecutable</key><string>MacCrab</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSMicrophoneUsageDescription</key><string>MacCrab monitors for ultrasonic voice injection attacks</string>
</dict>
</plist>
PLIST
codesign --force --deep --sign - "$APP" 2>/dev/null || true
xattr -cr "$APP" 2>/dev/null || true

# Copy supporting files
cp "$PROJECT_DIR/entitlements.plist" "$STAGING_DIR/"
cp "$PROJECT_DIR/com.maccrab.daemon.plist" "$STAGING_DIR/"
cp "$PROJECT_DIR/LICENSE" "$STAGING_DIR/"
cp "$PROJECT_DIR/README.md" "$STAGING_DIR/"

# Create install script
cat > "$STAGING_DIR/install.sh" << 'INSTALL'
#!/bin/bash
# MacCrab Installer
set -euo pipefail

PREFIX="${1:-/usr/local}"
echo "Installing MacCrab to $PREFIX..."

sudo mkdir -p "$PREFIX/bin"
sudo cp bin/maccrabd "$PREFIX/bin/"
sudo cp bin/maccrabctl "$PREFIX/bin/"
sudo chmod 755 "$PREFIX/bin/maccrabd" "$PREFIX/bin/maccrabctl"

# Install rules
sudo mkdir -p "/Library/Application Support/MacCrab/compiled_rules/sequences"
sudo cp compiled_rules/*.json "/Library/Application Support/MacCrab/compiled_rules/" 2>/dev/null || true
sudo cp compiled_rules/sequences/*.json "/Library/Application Support/MacCrab/compiled_rules/sequences/" 2>/dev/null || true

# Install app
if [ -d "MacCrab.app" ]; then
    cp -r MacCrab.app /Applications/ 2>/dev/null || sudo cp -r MacCrab.app /Applications/
    echo "  ✓ MacCrab.app installed to /Applications"
fi

# Install LaunchDaemon (optional — enables auto-start)
read -p "Enable auto-start on boot? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo cp com.maccrab.daemon.plist /Library/LaunchDaemons/
    sudo sed -i '' "s|/usr/local/bin/maccrabd|$PREFIX/bin/maccrabd|g" /Library/LaunchDaemons/com.maccrab.daemon.plist
    sudo launchctl load /Library/LaunchDaemons/com.maccrab.daemon.plist
    echo "  ✓ Daemon installed and started"
fi

echo ""
echo "MacCrab installed successfully!"
echo ""
echo "Quick start:"
echo "  sudo maccrabd                    # Start daemon"
echo "  open /Applications/MacCrab.app   # Open dashboard"
echo "  maccrabctl status                # Check status"
INSTALL
chmod +x "$STAGING_DIR/install.sh"

# Create DMG
echo "  Creating DMG..."
DMG_NAME="MacCrab-v$VERSION.dmg"
DMG_PATH="$PROJECT_DIR/.build/$DMG_NAME"

# Create a temporary DMG with the staging dir contents
hdiutil create -volname "MacCrab v$VERSION" \
    -srcfolder "$STAGING_DIR" \
    -ov -format UDZO \
    "$DMG_PATH" 2>/dev/null

# Sign and notarize if credentials are available
if [ -n "${DEVELOPER_ID:-}" ] || [ -n "${APPLE_ID:-}" ]; then
    echo "  Signing and notarizing DMG..."
    "$SCRIPT_DIR/notarize.sh" "$DMG_PATH"
else
    echo "  Skipping code signing (set DEVELOPER_ID for Developer ID signing)"
fi

echo ""
echo "═══════════════════════════════════════"
echo "  MacCrab v$VERSION Release Built"
echo "═══════════════════════════════════════"
echo ""
echo "  DMG: $DMG_PATH"
echo "  Size: $(du -h "$DMG_PATH" | cut -f1)"
echo "  Binaries: universal (arm64 + x86_64)"
echo "  Rules: $(find "$STAGING_DIR/compiled_rules" -name "*.json" | wc -l | tr -d ' ')"
echo ""

# Cleanup
rm -rf "$STAGING_DIR"

echo "To create a GitHub release:"
echo "  gh release create v$VERSION '$DMG_PATH' --title 'MacCrab v$VERSION' --notes-file RELEASE_NOTES.md"
