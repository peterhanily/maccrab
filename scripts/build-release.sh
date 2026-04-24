#!/bin/bash
# build-release.sh — Build MacCrab.app with embedded ES system extension.
#
# v1.3.0 architectural shift: the daemon that previously ran as a
# standalone LaunchDaemon is now a proper .systemextension bundle
# embedded inside MacCrab.app. Apple's AMFI rejects ES entitlements
# on LaunchDaemon Mach-Os regardless of signing correctness — only
# binaries loaded via OSSystemExtensionRequest can use ES.
#
# Resulting DMG contains:
#   MacCrab.app/
#     Contents/
#       Info.plist                          (app metadata + NSSystemExtensionUsageDescription)
#       embedded.provisionprofile           (Developer ID profile, team + ES grant)
#       MacOS/MacCrab                       (dashboard + activator, signed with system-extension.install)
#       Resources/AppIcon.icns
#       Library/SystemExtensions/
#         com.maccrab.agent.systemextension/
#           Contents/
#             Info.plist                    (SYEX package, NSSystemExtensionPointIdentifier=endpoint_security)
#             embedded.provisionprofile     (same profile)
#             MacOS/com.maccrab.agent       (ES daemon, signed with ES entitlement)
#             _CodeSignature/CodeResources
#   bin/maccrabctl                          (CLI tool, no entitlement)
#   bin/maccrab-mcp                         (MCP server, no entitlement)
#   install.sh                              (thin wrapper; cask + manual installers call this)
#   compiled_rules/*.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="${VERSION:-1.0.0}"
BUILD_DIR="$PROJECT_DIR/.build/release"
STAGING_DIR="/tmp/maccrab-release-$$"

cd "$PROJECT_DIR"

# Source credentials from env file if it exists
ENV_FILE="$HOME/.maccrab-release-env"
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
fi

echo "Building MacCrab v$VERSION..."

# ─── Compile for both architectures ──────────────────────────────────
echo "  Building arm64..."
swift build -c release --arch arm64 2>&1 | tail -1

echo "  Building x86_64..."
swift build -c release --arch x86_64 2>&1 | tail -1

# Create universal binaries for every product. maccrabd still builds
# (it's the legacy SPM target used during `swift run` development) but
# isn't shipped — the system extension replaces it in the installed .app.
mkdir -p "$STAGING_DIR/bin"
for binary in maccrabctl maccrab-mcp MacCrabApp MacCrabAgent; do
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

# ─── Rules ───────────────────────────────────────────────────────────
echo "  Compiling detection rules..."
python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir "$STAGING_DIR/compiled_rules" 2>&1 | tail -1
cp -r Rules/ "$STAGING_DIR/rules_source/"
# v1.4.2: also stamp a bundle version marker so RuleBundle on app
# launch can compare against the installed rules and copy when newer.
echo "$VERSION" > "$STAGING_DIR/compiled_rules/.bundle_version"

# v1.4.3: tamper-detection manifest. For every compiled_rules file
# we stamp a SHA-256 into manifest.json. RuleBundleInstaller verifies
# the installed tree against this manifest before trusting it; a
# mismatch (attacker modified the installed rules tree post-sync)
# surfaces a dashboard banner and refuses to sync further. Generated
# at build time so the manifest is signed inside the .app bundle
# and can't be swapped independently of the app.
echo "  Generating rule-manifest hashes..."
(
    cd "$STAGING_DIR/compiled_rules"
    # Build a JSON object keyed by relative path with SHA-256 hex values.
    # Excludes the manifest itself and the .bundle_version marker.
    {
        echo '{'
        echo '  "schema_version": 1,'
        echo "  \"bundle_version\": \"$VERSION\","
        echo '  "hashes": {'
        find . -type f ! -name "manifest.json" ! -name ".bundle_version" \
            | sort \
            | while IFS= read -r f; do
                rel="${f#./}"
                sum=$(shasum -a 256 "$f" | awk '{print $1}')
                echo "    \"$rel\": \"$sum\","
            done \
            | sed '$ s/,$//'     # trim trailing comma on final entry
        echo '  }'
        echo '}'
    } > manifest.json
)
echo "  Manifest: $(wc -l < "$STAGING_DIR/compiled_rules/manifest.json") lines"

# ─── App bundle skeleton ─────────────────────────────────────────────
echo "  Creating MacCrab.app bundle..."
APP="$STAGING_DIR/MacCrab.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$STAGING_DIR/bin/MacCrabApp" "$APP/Contents/MacOS/MacCrab"

# v1.4.2: ship compiled rules INSIDE the .app bundle so Sparkle
# auto-updates (which replace only the .app, not the cask-postflight
# state under /Library/Application Support) still refresh rule JSON.
# The app's RuleBundleInstaller compares the bundled
# `.bundle_version` against `/Library/Application Support/MacCrab/
# compiled_rules/.bundle_version` on launch and syncs when the
# bundled copy is newer. Without this, every Sparkle update left
# users on whatever rule set their original brew install shipped —
# v1.3.11's compiler fix and every rule severity change since then
# never reached Sparkle-updated installs.
cp -r "$STAGING_DIR/compiled_rules" "$APP/Contents/Resources/compiled_rules"

ICON_SRC="$PROJECT_DIR/Sources/MacCrabApp/Resources/AppIcon.icns"
if [ -f "$ICON_SRC" ]; then
    cp "$ICON_SRC" "$APP/Contents/Resources/AppIcon.icns"
fi

cat > "$APP/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>MacCrab</string>
    <key>CFBundleDisplayName</key><string>MacCrab</string>
    <key>CFBundleIdentifier</key><string>com.maccrab.app</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleExecutable</key><string>MacCrab</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIconName</key><string>AppIcon</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSSystemExtensionUsageDescription</key><string>MacCrab uses an Endpoint Security system extension to detect threats in real time. Approve once in System Settings &gt; General &gt; Login Items &amp; Extensions.</string>
    <key>NSMicrophoneUsageDescription</key><string>MacCrab monitors for ultrasonic voice injection attacks.</string>
    <!-- Sparkle 2 auto-update config. SUPublicEDKey is the ed25519
         verification key; losing the matching private key bricks
         updates for every existing install. -->
    <key>SUFeedURL</key><string>https://maccrab.com/appcast.xml</string>
    <key>SUPublicEDKey</key><string>de+dzPjBve7LP5qxoE7nR6shThsjubkVasi+i8ehT4E=</string>
    <key>SUEnableAutomaticChecks</key><true/>
    <key>SUScheduledCheckInterval</key><integer>86400</integer>
    <key>SUAutomaticallyUpdate</key><false/>
</dict>
</plist>
PLIST

# ─── System extension bundle ─────────────────────────────────────────
AGENT_ID="com.maccrab.agent"
SYSEXT_BUNDLE="$APP/Contents/Library/SystemExtensions/${AGENT_ID}.systemextension"
mkdir -p "$SYSEXT_BUNDLE/Contents/MacOS"

# Mach-O executable name inside the sysext bundle. Convention: match
# the bundle identifier so Apple's extension registration tooling
# (systemextensionsctl, sysextd) locates it consistently.
cp "$STAGING_DIR/bin/MacCrabAgent" "$SYSEXT_BUNDLE/Contents/MacOS/${AGENT_ID}"

cat > "$SYSEXT_BUNDLE/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>MacCrabAgent</string>
    <key>CFBundleDisplayName</key><string>MacCrab Endpoint Security Extension</string>
    <key>CFBundleIdentifier</key><string>${AGENT_ID}</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleExecutable</key><string>${AGENT_ID}</string>
    <key>CFBundlePackageType</key><string>SYSX</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>NSSystemExtensionUsageDescription</key><string>MacCrab's endpoint security extension watches kernel events (process, file, network) to detect threats.</string>
    <!--
    Extension category. Without this key, systemextensionsctl rejects
    activation with "does not appear to belong to any extension
    categories". The Endpoint Security category specifically tells
    macOS to load this via sysextd with es_new_client eligibility.
    -->
    <key>NSSystemExtensionPointIdentifier</key><string>com.apple.system_extension.endpoint_security</string>
    <key>NSEndpointSecurityEarlyBoot</key><false/>
</dict>
</plist>
PLIST
echo "    ✓ System extension bundle layout created"

# Strip any quarantine xattrs the filesystem picked up during staging.
xattr -cr "$APP" 2>/dev/null || true

# ─── Code signing ────────────────────────────────────────────────────
# Provisioning profile + two entitlements files (one per target).
# Both live under the version-controlled paths so the signing flow is
# reproducible.
DEVELOPER_ID="${DEVELOPER_ID:-}"
APP_ENT="$PROJECT_DIR/Xcode/Resources/MacCrabApp.entitlements"
AGENT_ENT="$PROJECT_DIR/Xcode/Resources/MacCrabAgent.entitlements"

if [ -n "$DEVELOPER_ID" ]; then
    echo "  Signing with Developer ID..."
    if ! security find-identity -v -p codesigning | grep -q "$DEVELOPER_ID"; then
        echo "  ERROR: Certificate not found in keychain: $DEVELOPER_ID"
        exit 1
    fi

    PROVISION_PROFILE="${PROVISION_PROFILE:-$HOME/.maccrab-signing/MacCrab.provisionprofile}"
    if [ ! -f "$PROVISION_PROFILE" ]; then
        echo "  ERROR: Provisioning profile not found at $PROVISION_PROFILE"
        echo "  The ES system extension cannot be signed without it — v1.3.0 has no fallback path."
        exit 1
    fi
    echo "  Provisioning profile: $PROVISION_PROFILE"

    # Embed the profile at BOTH bundle levels. AMFI walks up from any
    # Mach-O to the nearest enclosing Contents/embedded.provisionprofile;
    # shipping it at both the sysext bundle and the app bundle covers
    # every discovery path Apple uses.
    cp "$PROVISION_PROFILE" "$APP/Contents/embedded.provisionprofile"
    cp "$PROVISION_PROFILE" "$SYSEXT_BUNDLE/Contents/embedded.provisionprofile"

    # Remove raw MacCrabApp / MacCrabAgent from bin/ — the real copies
    # live inside the .app now. Leaving extra unsigned Mach-Os in the
    # DMG would cause notarization to reject the whole package.
    rm -f "$STAGING_DIR/bin/MacCrabApp"
    rm -f "$STAGING_DIR/bin/MacCrabAgent"

    # 1. CLI tools. No entitlements, just hardened runtime.
    for binary in "$STAGING_DIR"/bin/*; do
        if [ -f "$binary" ] && file "$binary" | grep -q "Mach-O"; then
            codesign --sign "$DEVELOPER_ID" \
                --options runtime \
                --timestamp \
                --force \
                "$binary"
            echo "    ✓ $(basename "$binary") (hardened runtime)"
        fi
    done

    # 2. System extension Mach-O — signed with ES entitlement +
    # provisioning-profile-bound identifier. AMFI matches the identifier
    # against application-identifier in the embedded profile.
    codesign --sign "$DEVELOPER_ID" \
        --identifier "$AGENT_ID" \
        --options runtime \
        --entitlements "$AGENT_ENT" \
        --timestamp \
        --force \
        "$SYSEXT_BUNDLE/Contents/MacOS/${AGENT_ID}"

    # 3. System extension bundle — the bundle-level sign creates
    # _CodeSignature/CodeResources and seals the Info.plist + embedded
    # profile + Mach-O together.
    codesign --sign "$DEVELOPER_ID" \
        --identifier "$AGENT_ID" \
        --options runtime \
        --entitlements "$AGENT_ENT" \
        --timestamp \
        --force \
        "$SYSEXT_BUNDLE"
    echo "    ✓ Signed sysext bundle ($AGENT_ID, ES entitlement)"

    # 4a. Embed Sparkle.framework. SPM links MacCrabApp against Sparkle
    # (added in v1.3.5 Wave 1) but does NOT copy the framework into
    # the output bundle — that's an Xcode build-phase feature SPM
    # lacks. Without this step the dyld loader fails at launch with
    # "Library not loaded: @rpath/Sparkle.framework/Versions/B/Sparkle"
    # and the process aborts before SwiftUI gets a chance to render.
    SPARKLE_SRC="$PROJECT_DIR/.build/artifacts/sparkle/Sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework"
    if [ ! -d "$SPARKLE_SRC" ]; then
        # SPM extracts the xcframework on first build. If it's not
        # present it means swift build hasn't run yet; run a quick
        # release build to get it.
        echo "  Resolving Sparkle framework via swift build..."
        swift build -c release --product MacCrabApp 2>&1 | tail -3
    fi
    if [ ! -d "$SPARKLE_SRC" ]; then
        echo "  ERROR: Sparkle.framework not found at $SPARKLE_SRC"
        echo "  Ensure Package.swift declares the Sparkle SPM dep and swift build runs clean."
        exit 1
    fi

    FRAMEWORKS_DIR="$APP/Contents/Frameworks"
    mkdir -p "$FRAMEWORKS_DIR"
    # -R preserves the framework's internal symlinks (Versions/B ↔ Current).
    # Without -R, macOS treats the copy as malformed and codesign rejects it.
    cp -R "$SPARKLE_SRC" "$FRAMEWORKS_DIR/"
    echo "    ✓ Embedded Sparkle.framework"

    # Re-sign Sparkle's bundled helpers + the framework itself with
    # our Developer ID. The framework arrives from the SPM artifact
    # already signed (by the Sparkle project's team); re-signing with
    # our identity keeps the whole app bundle's code-signing chain
    # consistent for notarization.
    for bundle in "$FRAMEWORKS_DIR/Sparkle.framework/Versions/B/XPCServices"/*.xpc \
                  "$FRAMEWORKS_DIR/Sparkle.framework/Versions/B/Autoupdate" \
                  "$FRAMEWORKS_DIR/Sparkle.framework/Versions/B/Updater.app"; do
        if [ -e "$bundle" ]; then
            codesign --sign "$DEVELOPER_ID" \
                --options runtime \
                --timestamp \
                --force \
                "$bundle" 2>/dev/null && echo "    ✓ Signed $(basename "$bundle")"
        fi
    done
    codesign --sign "$DEVELOPER_ID" \
        --options runtime \
        --timestamp \
        --force \
        "$FRAMEWORKS_DIR/Sparkle.framework"
    echo "    ✓ Signed Sparkle.framework"

    # SPM builds executables without `@executable_path/../Frameworks/`
    # in their rpath — that's Xcode's default for .app targets, which
    # SwiftPM doesn't know we're assembling. Without this, dyld
    # searches only `@executable_path/` (Contents/MacOS/) for
    # Sparkle.framework, misses our Contents/Frameworks/ copy, and
    # aborts at launch with "Library not loaded: @rpath/Sparkle.framework".
    # Add the rpath BEFORE signing so the code signature seals the
    # patched load commands.
    if ! otool -l "$APP/Contents/MacOS/MacCrab" | grep -q "@executable_path/../Frameworks"; then
        install_name_tool -add_rpath "@executable_path/../Frameworks" "$APP/Contents/MacOS/MacCrab"
        echo "    ✓ Added @executable_path/../Frameworks rpath"
    fi

    # 4b. App's inner executable. The app needs the
    # system-extension.install entitlement so OSSystemExtensionRequest
    # can talk to sysextd.
    codesign --sign "$DEVELOPER_ID" \
        --identifier "com.maccrab.app" \
        --options runtime \
        --entitlements "$APP_ENT" \
        --timestamp \
        --force \
        "$APP/Contents/MacOS/MacCrab"

    # 5. App bundle — signs the outer container last so the bundle
    # signature seals the sysext + the profile + the inner executable.
    codesign --sign "$DEVELOPER_ID" \
        --identifier "com.maccrab.app" \
        --options runtime \
        --entitlements "$APP_ENT" \
        --timestamp \
        --force \
        "$APP"
    echo "    ✓ Signed MacCrab.app (system-extension.install entitlement)"

    # Verify before handing off to notarization — catches staging
    # layout mistakes fast. --deep emits many lines now that
    # Sparkle.framework is embedded (each helper + XPC service is
    # validated); head -5 closes the pipe early and triggers SIGPIPE
    # under `set -o pipefail`. Pipe through a shell function that
    # swallows SIGPIPE explicitly instead.
    codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | { head -5; cat >/dev/null; } || true
else
    echo "  Ad-hoc signing (set DEVELOPER_ID for distribution signing)"
    codesign --force --sign - "$APP" 2>/dev/null || true
fi

# ─── Supporting files + install.sh ───────────────────────────────────
cp "$PROJECT_DIR/LICENSE" "$STAGING_DIR/"
cp "$PROJECT_DIR/README.md" "$STAGING_DIR/"

cp "$SCRIPT_DIR/install.sh" "$STAGING_DIR/install.sh"
chmod +x "$STAGING_DIR/install.sh"

# ─── DMG ─────────────────────────────────────────────────────────────
echo "  Creating DMG..."
DMG_NAME="MacCrab-v$VERSION.dmg"
DMG_PATH="$PROJECT_DIR/.build/$DMG_NAME"

ln -s /Applications "$STAGING_DIR/Applications"

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

rm -rf "$STAGING_DIR"

echo "To create a GitHub release:"
echo "  gh release create v$VERSION '$DMG_PATH' --title 'MacCrab v$VERSION' --notes-file RELEASE_NOTES.md"
