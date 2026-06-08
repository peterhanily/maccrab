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
# Default to the latest annotated git tag (strip leading 'v') so
# we never accidentally ship MacCrab-v1.0.0.dmg when the operator
# forgets to pass VERSION=. Falls back to 1.0.0 only if there are
# no tags at all (fresh clone, dev sandbox).
DEFAULT_VERSION="$(cd "$PROJECT_DIR" && git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')"
VERSION="${VERSION:-${DEFAULT_VERSION:-1.0.0}}"

# v1.10.0 audit fix: derive a unique CFBundleVersion (build number)
# per build so sysextd can tell two builds of the same VERSION apart
# and actually replaces the cached binary. macOS sysextd compares
# (team-id, bundle-id, CFBundleShortVersionString, CFBundleVersion)
# tuples — if all four match, an activation request short-circuits
# even when the on-disk bundle bytes have changed. Field-observed:
# rebuilding 1.10.0 with code changes left the OLD binary running
# because both tuples said `1.10.0/1.10.0`. The build number is
# `<VERSION>.<unix-time>` so every rebuild is distinct; the
# user-visible marketing version (CFBundleShortVersionString) stays
# clean. Caller can override with `BUILD_NUMBER=<custom>`: release.sh
# (v1.18+) exports a DETERMINISTIC `<VERSION>.<commit-count>` so an
# identical rebuild reuses the same tuple and doesn't orphan a new
# reboot-pending sysext zombie. The per-second epoch below is the DEV-loop
# fallback (make dev / standalone build-release.sh): there you rebuild the
# same VERSION with changed code, so a distinct tuple each time is REQUIRED
# to force sysextd to swap the active extension.
if [ -z "${BUILD_NUMBER:-}" ]; then
    export BUILD_NUMBER="${VERSION}.$(date +%s)"
fi
echo "  CFBundleShortVersionString: $VERSION"
echo "  CFBundleVersion           : $BUILD_NUMBER"
BUILD_DIR="$PROJECT_DIR/.build/release"
STAGING_DIR="/tmp/maccrab-release-$$"

# Clean up the staging dir on any exit path. Without this trap, every
# failed release run (Sparkle resolve failure, codesign failure,
# hdiutil failure, notarize timeout) leaks a multi-MB staged dir to
# /tmp; ten failed runs filled the dev disk before the audit caught
# this. The trap fires after the rm at line 446 too, so successful
# runs still pass through cleanly (the dir is already gone).
trap 'rm -rf "$STAGING_DIR"' EXIT

cd "$PROJECT_DIR"

# ─── Sparkle config: single source of truth ──────────────────────────
# The shipped app's Info.plist (heredoc below) used to HARDCODE SUPublicEDKey
# + SUFeedURL — a third independent copy that prerelease-check.sh never
# validated (it only compares project.yml vs MacCrabApp-Info.plist). A future
# key rotation that updated those two but forgot this script would pass the
# pre-release gate GREEN while shipping a DMG with a stale key, bricking
# auto-update for every installed user (a yank-class failure). Derive both
# from Xcode/project.yml (canonical) at build time and fail hard if absent, so
# there is exactly ONE source and no drift surface.
SU_EDKEY=$(grep -E '^[[:space:]]*SUPublicEDKey:' Xcode/project.yml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
SU_FEEDURL=$(grep -E '^[[:space:]]*SUFeedURL:' Xcode/project.yml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$SU_EDKEY" ] || [ -z "$SU_FEEDURL" ]; then
    echo "  ERROR: could not read SUPublicEDKey / SUFeedURL from Xcode/project.yml — refusing to build a DMG with missing Sparkle config" >&2
    exit 1
fi

# Source credentials from env file if it exists
ENV_FILE="$HOME/.maccrab-release-env"
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
fi

echo "Building MacCrab v$VERSION..."
echo "  Sparkle: feed=$SU_FEEDURL key=${SU_EDKEY:0:8}… (from project.yml)"

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
# v1.12.0: graph rules (Rules/graph/*.json) are already JSON — no
# compilation step. Stage them next to the compiled single-event
# rules so GraphRuleEvaluator can load them at daemon start. Pre-fix
# the release DMG shipped without these and `maccrab_worm_self_propagation`
# (the flagship Wave-1 detection) silently never fired in production.
mkdir -p "$STAGING_DIR/compiled_rules/graph"
cp Rules/graph/*.json "$STAGING_DIR/compiled_rules/graph/" 2>/dev/null || true
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

# v1.12.0 RC16 (in-dashboard Sigma editor): bundle compile_rules.py
# plus a vendored copy of PyYAML's pure-Python module so the dashboard
# can compile user-edited YAML to the daemon-readable JSON format on
# save. macOS ships Python 3 at /usr/bin/python3 but NOT PyYAML, so we
# vendor PyYAML's source files (~624 KB, no C extension required —
# the pure-Python fallback works fine for our throughput).
mkdir -p "$APP/Contents/Resources/Compiler/yaml"
cp Compiler/compile_rules.py "$APP/Contents/Resources/Compiler/compile_rules.py"
PYYAML_SRC=$(/usr/bin/python3 -c "import yaml, os; print(os.path.dirname(yaml.__file__))" 2>/dev/null)
if [ -n "$PYYAML_SRC" ] && [ -d "$PYYAML_SRC" ]; then
    cp "$PYYAML_SRC"/*.py "$APP/Contents/Resources/Compiler/yaml/"
    echo "    ✓ Bundled Compiler + PyYAML ($(ls "$APP/Contents/Resources/Compiler/yaml/" | wc -l | tr -d ' ') yaml/ files) → Resources/Compiler/"
else
    # v1.12.0 RC25 (release-eng): hard failure when PyYAML is missing.
    # Pre-fix this was a warning, so a CI machine without PyYAML
    # silently shipped a DMG whose in-dashboard Sigma editor couldn't
    # compile rules. Fail loud so the release pipeline never produces
    # a half-working artifact.
    echo "    ✗ ERROR: PyYAML not found at build time. The in-dashboard Sigma editor"
    echo "      requires it. Aborting release build."
    echo "      Install with: /usr/bin/python3 -m pip install --user pyyaml"
    exit 1
fi

# v1.12.0 fix (Edit-YAML): ship the rule YAML sources inside the .app
# at Resources/rules/, named by the rule's Sigma `id:` UUID. The
# dashboard's V2DetectionWorkspace passes `rule.id` (the YAML's `id:`
# UUID like `d1a2b3c4-1003-4000-a000-000000001003`) to
# `Bundle.main.path(forResource:ofType:"yml", inDirectory:"rules")`,
# not the filename slug — so we need files named by UUID, not by slug.
# We also copy the slug name for human browsing / debugging. Bundle
# size cost: ~1 MB total for 463 rules; negligible vs the 80 MB DMG.
mkdir -p "$APP/Contents/Resources/rules"
# Pass 1: slug-named copies (filename-based browsing / debugging).
find Rules -name '*.yml' -not -path 'Rules/graph/*' -exec cp {} "$APP/Contents/Resources/rules/" \;
# Pass 2: UUID-named copies (Bundle.main.path lookup target).
uuid_copied=0
while IFS= read -r f; do
    uuid=$(grep -m1 '^id:' "$f" | awk '{print $2}' | tr -d "'\"" | tr -d '[:space:]')
    if [ -n "$uuid" ]; then
        cp "$f" "$APP/Contents/Resources/rules/$uuid.yml"
        uuid_copied=$((uuid_copied + 1))
    fi
done < <(find Rules -name '*.yml' -not -path 'Rules/graph/*')
echo "    ✓ Bundled $(ls "$APP/Contents/Resources/rules/" | wc -l | tr -d ' ') YAML files → Resources/rules/ ($uuid_copied UUID-named)"

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

# v1.12.0 RC2 fix (B9): copy SPM-generated MacCrab_MacCrabCore.bundle
# into the .app's Resources directory. Without this, Bundle.module
# returns nil at runtime in the shipped .app, and TyposquatDatabase
# falls back to its in-source ~30-entry starter corpus instead of the
# bundled top-200 npm + top-200 PyPI JSON files that
# Sources/MacCrabCore/Resources/typosquat-top-*.json carry. SPM emits
# the bundle into .build/<arch>/release/. We probe both Apple-silicon
# (arm64) and Intel (x86_64) trees so universal builds get coverage.
for arch in arm64-apple-macosx x86_64-apple-macosx; do
    SPM_BUNDLE="$PROJECT_DIR/.build/$arch/release/MacCrab_MacCrabCore.bundle"
    if [ -d "$SPM_BUNDLE" ]; then
        cp -R "$SPM_BUNDLE" "$APP/Contents/Resources/MacCrab_MacCrabCore.bundle"
        echo "    ✓ Bundled MacCrab_MacCrabCore resource bundle ($arch) → Resources/"
        break
    fi
done
# rc.4 — also copy the MacCrabApp resource bundle so bundled
# rave kits + catalog signing key reach Bundle.main.resourceURL.
for arch in arm64-apple-macosx x86_64-apple-macosx; do
    SPM_APP_BUNDLE="$PROJECT_DIR/.build/$arch/release/MacCrab_MacCrabApp.bundle"
    if [ -d "$SPM_APP_BUNDLE" ]; then
        cp -R "$SPM_APP_BUNDLE" "$APP/Contents/Resources/MacCrab_MacCrabApp.bundle"
        echo "    ✓ Bundled MacCrab_MacCrabApp resource bundle ($arch) → Resources/"
        break
    fi
done
if [ ! -d "$APP/Contents/Resources/MacCrab_MacCrabCore.bundle" ]; then
    echo "    ✗ WARNING: MacCrab_MacCrabCore.bundle not found in .build/*/release/"
    echo "      TyposquatDatabase will fall back to in-source starter corpus."
fi

# v1.12.4 fix (macOS 26 Tahoe crash): SwiftPM emits a stripped Info.plist
# in the resource bundle that contains only CFBundleDevelopmentRegion.
# macOS ≤ 25 accepts the minimal plist; macOS 26 rejects it — `Bundle(url:)`
# returns nil — and SwiftPM's auto-generated `Bundle.module` accessor
# then fatalError("unable to find bundle MacCrab_MacCrabCore"). Crash
# fires on first Intelligence-tab click because PackageScanner lazily
# instantiates TyposquatDatabase the first time .packages() is read.
#
# TyposquatDatabase itself no longer touches Bundle.module (it builds
# resource URLs directly), but other future SPM-resource consumers
# might — so write a complete CFBundle Info.plist over the SPM stub
# so the bundle validates on every macOS version. Keys mirror what
# Xcode emits for a typical resource bundle target.
BUNDLE_PLIST="$APP/Contents/Resources/MacCrab_MacCrabCore.bundle/Info.plist"
if [ -d "$APP/Contents/Resources/MacCrab_MacCrabCore.bundle" ]; then
    cat > "$BUNDLE_PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleIdentifier</key>
    <string>com.maccrab.MacCrabCore.resources</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>MacCrabCore Resources</string>
    <key>CFBundlePackageType</key>
    <string>BNDL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
</dict>
</plist>
PLIST
    echo "    ✓ Patched MacCrab_MacCrabCore.bundle/Info.plist (macOS 26 Bundle(url:) compatibility)"
fi

# v1.10.0: bundle maccrabctl + maccrab-mcp inside the .app at
# Contents/Resources/bin/. Pre-fix the dashboard's runMaccrabctl
# probed Bundle.main first, but the binary was only ever shipped to
# /usr/local/bin via install.sh. Brew users with v1.5.1's CLI at
# /opt/homebrew/bin/maccrabctl saw the dashboard call the OLD CLI
# (no `intel refresh`, no `unsuppress --id`, etc.) — every dashboard
# action that shells out failed silently with "Unknown command".
# Now the .app carries the matching CLI and the path probe finds it
# first.
mkdir -p "$APP/Contents/Resources/bin"
if [ -x "$STAGING_DIR/bin/maccrabctl" ]; then
    cp "$STAGING_DIR/bin/maccrabctl" "$APP/Contents/Resources/bin/maccrabctl"
    chmod 755 "$APP/Contents/Resources/bin/maccrabctl"
    echo "    ✓ Bundled maccrabctl into MacCrab.app/Contents/Resources/bin/"
fi
if [ -x "$STAGING_DIR/bin/maccrab-mcp" ]; then
    cp "$STAGING_DIR/bin/maccrab-mcp" "$APP/Contents/Resources/bin/maccrab-mcp"
    chmod 755 "$APP/Contents/Resources/bin/maccrab-mcp"
    echo "    ✓ Bundled maccrab-mcp into MacCrab.app/Contents/Resources/bin/"
fi

cat > "$APP/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>MacCrab</string>
    <key>CFBundleDisplayName</key><string>MacCrab</string>
    <key>CFBundleIdentifier</key><string>com.maccrab.app</string>
    <key>CFBundleVersion</key><string>${BUILD_NUMBER:-$VERSION}</string>
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
    <key>NSFullDiskAccessUsageDescription</key><string>MacCrab needs Full Disk Access so the detection engine can read TCC state, observe access to protected paths, and detect tamper attempts against its own configuration.</string>
    <key>NSLocalNetworkUsageDescription</key><string>MacCrab inspects local network connections made by running processes to surface suspicious outbound patterns. Metadata stays on-device.</string>
    <key>NSHumanReadableCopyright</key><string>© 2026 CaddyLabs. MacCrab is distributed under the Apache 2.0 License.</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <!-- Sparkle 2 auto-update config. SUPublicEDKey is the ed25519
         verification key; losing the matching private key bricks
         updates for every existing install. Both values are interpolated
         from Xcode/project.yml (the single source of truth) — never edit
         them here; rotate the key in project.yml only. -->
    <key>SUFeedURL</key><string>${SU_FEEDURL}</string>
    <key>SUPublicEDKey</key><string>${SU_EDKEY}</string>
    <key>SUEnableAutomaticChecks</key><true/>
    <key>SUScheduledCheckInterval</key><integer>86400</integer>
    <key>SUAutomaticallyUpdate</key><false/>
    <!-- maccrab:// deep-link scheme (APPCORE-01). Routes `open maccrab://...`
         and in-app bookmarks to MacCrab.app via the scene .onOpenURL →
         V2DashboardState.goto(url:) pipeline. -->
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLName</key><string>com.maccrab.app.deeplink</string>
            <key>CFBundleURLSchemes</key>
            <array><string>maccrab</string></array>
        </dict>
    </array>
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
    <key>CFBundleVersion</key><string>${BUILD_NUMBER:-$VERSION}</string>
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

    # 4a-bin. Sign the bundled CLI binaries that ride inside the app
    # at Contents/Resources/bin/. They have no entitlement (just
    # hardened runtime + Developer ID + timestamp). Without explicit
    # signing here, --deep on the app-level sign treats them as
    # ordinary resources and notarization rejects unsigned Mach-Os.
    for bin in "$APP/Contents/Resources/bin/maccrabctl" \
               "$APP/Contents/Resources/bin/maccrab-mcp"; do
        if [ -x "$bin" ]; then
            codesign --sign "$DEVELOPER_ID" \
                --identifier "com.maccrab.$(basename "$bin")" \
                --options runtime \
                --timestamp \
                --force \
                "$bin"
        fi
    done

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
    #
    # Resources/* sealing (compiled_rules, rules, Compiler) is provided
    # by codesign's bundle-mode `_CodeSignature/CodeResources` hash
    # list — built automatically when signing the bundle, NO --deep
    # required. The original v1.12.0 RC28 audit fix added --deep on
    # the assumption that --deep was needed for Resources sealing;
    # that assumption was wrong — --deep is for recursing into nested
    # SIGNED code (frameworks, XPC services), not for sealing data
    # resources. CodeResources covers data resources unconditionally.
    #
    # v1.12.2 fix (Sparkle install FP): drop --deep. With --deep on,
    # codesign re-signed every nested Mach-O (Sparkle.framework's
    # Autoupdate, Updater.app, Downloader.xpc, Installer.xpc) and
    # propagated our main-app entitlements
    # (`com.apple.developer.system-extension.install` +
    # keychain-access-groups) onto each. macOS refuses to launch a
    # Sparkle XPC helper carrying the system-extension.install
    # entitlement, which surfaced as the generic "An error occurred
    # while running the updater" on every Sparkle upgrade. Tried
    # --preserve-metadata=entitlements first (v1.12.1) — turns out
    # codesign doesn't "preserve" the *absence* of entitlements, so
    # the propagation still happened. Dropping --deep is the actual
    # fix: Sparkle's helpers keep their step-4a signatures (no
    # entitlements), and the outer .app sign just seals the bundle
    # via its own primary executable (which already carries APP_ENT
    # from step 4b) plus the CodeResources hash list.
    codesign --sign "$DEVELOPER_ID" \
        --identifier "com.maccrab.app" \
        --options runtime \
        --entitlements "$APP_ENT" \
        --timestamp \
        --force \
        "$APP"
    echo "    ✓ Signed MacCrab.app (CodeResources seals Resources/, nested code kept own signatures)"

    # Verify before handing off to notarization — catches staging
    # layout mistakes fast. --deep emits many lines now that
    # Sparkle.framework is embedded (each helper + XPC service is
    # validated); head -5 closes the pipe early and triggers SIGPIPE
    # under `set -o pipefail`. Pipe through a shell function that
    # swallows SIGPIPE explicitly instead.
    codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | { head -5; cat >/dev/null; } || true

    # ── Nested-entitlement guard (v1.13 audit improvement; see the v1.12.0
    # Sparkle brick above). No nested helper may carry a privileged APP
    # entitlement: the v1.12.0 regression propagated system-extension.install
    # onto Sparkle's Installer.xpc and macOS refused to launch the updater.
    # Read-only; fails loud. Does NOT trip on a correct build (Sparkle XPCs
    # carry none; the sysext carries only endpoint-security.client).
    echo "  Verifying nested-binary entitlements (no privileged leak)..."
    ent_leak=0
    while IFS= read -r _xpc; do
        _exe=$(/usr/bin/find "$_xpc/Contents/MacOS" -maxdepth 1 -type f -print -quit 2>/dev/null)
        [ -n "$_exe" ] || continue
        if codesign -d --entitlements - "$_exe" 2>/dev/null | grep -qiE 'system-extension\.install|endpoint-security'; then
            echo "    ✗ ENTITLEMENT LEAK: $(basename "$_xpc") carries a privileged app entitlement (v1.12.0-class regression)"
            ent_leak=1
        fi
    done < <(/usr/bin/find "$APP/Contents/Frameworks" -name '*.xpc' -type d 2>/dev/null)
    _sysexe="$APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
    if [ -f "$_sysexe" ] && codesign -d --entitlements - "$_sysexe" 2>/dev/null | grep -qi 'system-extension\.install'; then
        echo "    ✗ ENTITLEMENT LEAK: system extension carries system-extension.install (app-only entitlement)"
        ent_leak=1
    fi
    if [ "$ent_leak" != "0" ]; then
        echo "  ERROR: nested-entitlement guard failed — refusing to ship (see the v1.12.0 Sparkle brick)."
        exit 1
    fi
    echo "    ✓ no privileged entitlement leaked to Sparkle XPC / sysext"

    # ── Notarize + staple the .app itself so `stapler validate MacCrab.app`
    # passes after install (offline Gatekeeper). The DMG is notarized below;
    # this is the bundle. BEST-EFFORT: any failure here only warns — the DMG
    # is still notarized + stapled, so the build never bricks on this. Stapling
    # stores a ticket alongside the bundle; it does NOT modify the signature or
    # entitlements, so it carries no v1.12.0-class risk.
    NZ_AUTH=()
    if [ -n "${NOTARIZE_KEYCHAIN_PROFILE:-}" ]; then
        NZ_AUTH=(--keychain-profile "$NOTARIZE_KEYCHAIN_PROFILE")
    elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${NOTARIZE_PASSWORD:-}" ]; then
        NZ_AUTH=(--apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$NOTARIZE_PASSWORD")
    fi
    if [ "${#NZ_AUTH[@]}" -gt 0 ]; then
        echo "  Notarizing the app bundle (so it can be stapled)..."
        _appzip="${APP%.app}-notarize.zip"
        rm -f "$_appzip"
        if /usr/bin/ditto -c -k --keepParent "$APP" "$_appzip" \
           && xcrun notarytool submit "$_appzip" "${NZ_AUTH[@]}" --wait 2>&1 | grep -q "status: Accepted"; then
            if xcrun stapler staple "$APP"; then
                echo "    ✓ app bundle stapled"
            else
                echo "    ⚠ app staple failed (non-fatal — DMG staple still applies)"
            fi
        else
            echo "    ⚠ app notarization not accepted (non-fatal — DMG staple still applies)"
        fi
        rm -f "$_appzip"
    fi
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

# v1.18: build the DMG via attach + ditto + convert rather than
# `hdiutil create -srcfolder`. The latter's internal copy fails with
# "could not access .../MacCrab.app - Operation not permitted" once MacCrab is
# INSTALLED on the build host (macOS App-Management protects the registered
# com.maccrab.app from the diskimages-helper copy) — which is the normal
# developer situation, and silently bricked the build the moment the dev dog-
# fooded a prior RC. `ditto` into an explicitly-attached RW image is unaffected
# and preserves the bundle + the /Applications symlink. The mountpoint is under
# /tmp (not /Volumes) so a crash can't leave a stale /Volumes/MacCrab… volume.
STAGE_KB=$(du -sk "$STAGING_DIR" | cut -f1)
RW_DMG="${DMG_PATH%.dmg}.rw.dmg"
DMG_MNT="/tmp/maccrab-dmg-mnt-$$"
rm -f "$RW_DMG"
hdiutil create -size "$(( STAGE_KB / 1024 + 150 ))m" -volname "MacCrab v$VERSION" \
    -fs HFS+ -ov "$RW_DMG" >/dev/null
mkdir -p "$DMG_MNT"
hdiutil attach "$RW_DMG" -nobrowse -mountpoint "$DMG_MNT" >/dev/null
ditto "$STAGING_DIR/" "$DMG_MNT/"
hdiutil detach "$DMG_MNT" -force >/dev/null
rmdir "$DMG_MNT" 2>/dev/null || true
hdiutil convert "$RW_DMG" -format UDZO -ov -o "$DMG_PATH" >/dev/null
rm -f "$RW_DMG"

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
# v1.11.0 RC2 (audit ship MEDIUM): exclude `manifest.json` from the
# rule count so release.json doesn't ship "428 rules" when the actual
# count is 427. manifest.json is build-time metadata, not a rule.
RULE_COUNT=$(find "$STAGING_DIR/compiled_rules" -name "*.json" ! -name "manifest.json" | wc -l | tr -d ' ')
echo "  Rules: $RULE_COUNT"
echo ""

# v1.8.1: write release.json with version + rule + test counts so the
# website can fetch authoritative metadata instead of being hand-edited.
# Eliminates the version-drift class of bug that the v1.8.0 external
# review caught (website still showed 1.7.12 / 929 tests).
RELEASE_JSON="$PROJECT_DIR/release.json"
DMG_SHA=$(shasum -a 256 "$DMG_PATH" | awk '{print $1}')
DMG_SIZE_BYTES=$(stat -f%z "$DMG_PATH" 2>/dev/null || stat -c%s "$DMG_PATH")
# `set -e` + grep returning 1 on no match would abort the script; route
# through `|| true` so a missing test pattern doesn't kill the build.
TEST_COUNT=$(find Tests -name '*.swift' -exec grep -h '^@Test\|^    @Test' {} + 2>/dev/null | wc -l | tr -d ' ' || true)
SUITE_COUNT=$(find Tests -name '*.swift' -exec grep -h '^@Suite' {} + 2>/dev/null | wc -l | tr -d ' ' || true)
TEST_COUNT="${TEST_COUNT:-0}"
SUITE_COUNT="${SUITE_COUNT:-0}"
RELEASE_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cat > "$RELEASE_JSON" <<RELEASE_EOF
{
  "version": "$VERSION",
  "release_date": "$RELEASE_DATE",
  "rules": $RULE_COUNT,
  "tests": $TEST_COUNT,
  "test_suites": $SUITE_COUNT,
  "dmg": {
    "filename": "MacCrab-v${VERSION}.dmg",
    "url": "https://github.com/peterhanily/maccrab/releases/download/v${VERSION}/MacCrab-v${VERSION}.dmg",
    "sha256": "$DMG_SHA",
    "size_bytes": $DMG_SIZE_BYTES
  },
  "notes_url": "https://github.com/peterhanily/maccrab/releases/tag/v${VERSION}",
  "appcast_url": "https://maccrab.com/appcast.xml",
  "min_macos": "13.0"
}
RELEASE_EOF
echo "  release.json written → $RELEASE_JSON"
echo ""

rm -rf "$STAGING_DIR"

echo "To create a GitHub release:"
echo "  gh release create v$VERSION '$DMG_PATH' --title 'MacCrab v$VERSION' --notes-file RELEASE_NOTES.md"
