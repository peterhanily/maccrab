#!/bin/bash
# Create a proper macOS .app bundle from the MacCrabApp executable.
# SPM builds a bare binary; macOS needs an app bundle for menu bar icons.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/.build/debug"
APP_BUNDLE="$BUILD_DIR/MacCrab.app"

# Clean old bundle
rm -rf "$APP_BUNDLE"

# Create bundle structure
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy executable
cp "$BUILD_DIR/MacCrabApp" "$APP_BUNDLE/Contents/MacOS/MacCrab"

# Copy app icon
if [ -f "$PROJECT_DIR/Sources/MacCrabApp/Resources/AppIcon.icns" ]; then
    cp "$PROJECT_DIR/Sources/MacCrabApp/Resources/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
fi

# Create Info.plist
cat > "$APP_BUNDLE/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>MacCrab</string>
    <key>CFBundleDisplayName</key>
    <string>MacCrab</string>
    <key>CFBundleIdentifier</key>
    <string>com.maccrab.app</string>
    <key>CFBundleVersion</key>
    <string>0.5.0</string>
    <key>CFBundleShortVersionString</key>
    <string>0.5.0</string>
    <key>CFBundleExecutable</key>
    <string>MacCrab</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <false/>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

# Ad-hoc sign (deep to cover embedded frameworks) so macOS doesn't block it
codesign --force --deep --sign - "$APP_BUNDLE" 2>/dev/null || true

# Remove quarantine xattr so macOS doesn't block the app
xattr -cr "$APP_BUNDLE" 2>/dev/null || true

echo "$APP_BUNDLE"
