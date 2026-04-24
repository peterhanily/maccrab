#!/bin/bash
# release.sh — One-command local release: build, sign, notarize, publish
#
# Usage:
#   ./scripts/release.sh 1.1.0
#
# Requires: DEVELOPER_ID, APPLE_ID, APPLE_TEAM_ID, NOTARIZE_PASSWORD
# Set these in ~/.maccrab-release-env (sourced automatically) or export them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="${1:-}"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.1.0"
    exit 1
fi

cd "$PROJECT_DIR"

# Source credentials from env file if it exists
ENV_FILE="$HOME/.maccrab-release-env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading credentials from $ENV_FILE"
    source "$ENV_FILE"
fi

# Verify credentials
if [ -z "${DEVELOPER_ID:-}" ]; then
    echo "ERROR: DEVELOPER_ID not set."
    echo ""
    echo "Either export it or create ~/.maccrab-release-env with:"
    echo '  export DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"'
    echo '  export APPLE_ID="your@email.com"'
    echo '  export APPLE_TEAM_ID="TEAMID"'
    echo '  export NOTARIZE_PASSWORD="xxxx-xxxx-xxxx-xxxx"'
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  MacCrab v$VERSION Release                       "
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Step 0: Pre-release check — enforce RELEASE_CHECKLIST.md items so the
# pipeline refuses to ship out-of-sync versions, stale notes, or broken
# localizations. Warnings still proceed; hard errors abort.
echo "Step 0/6: Pre-release check..."
"$SCRIPT_DIR/prerelease-check.sh" "$VERSION" || {
    echo "Pre-release check failed — fix the errors above or run with --skip-prerelease-check to override (not recommended)"
    exit 1
}

# Step 1: Tests
echo "Step 1/6: Running tests..."
swift test 2>&1 | grep "Test run with" || { echo "Tests failed!"; exit 1; }

# Step 2: Rule compilation
echo "Step 2/6: Compiling rules..."
python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir .build/compiled_rules 2>&1 | tail -1

# Step 3: Build DMG
echo "Step 3/5: Building DMG..."
VERSION="$VERSION" ./scripts/build-release.sh

# (v1.6.11) PKG build removed — productbuild's distribution-XML
# pkg-ref name didn't match the component pkg filename, producing
# a 1.9KB stub archive that opened in Installer.app but contained
# no payload. DMG + Homebrew are the supported install paths.

# Step 4: Update Homebrew formula
DMG_PATH=".build/MacCrab-v$VERSION.dmg"
if [ -f "$DMG_PATH" ]; then
    echo "Step 4/5: Updating Homebrew formula..."
    SHA=$(shasum -a 256 "$DMG_PATH" | awk '{print $1}')
    sed -i '' "s/version \".*\"/version \"$VERSION\"/" homebrew/maccrab.rb
    sed -i '' "s/sha256 .*/sha256 \"$SHA\"/" homebrew/maccrab.rb
    echo "  Updated homebrew/maccrab.rb (sha256: ${SHA:0:16}...)"
fi

# Step 5: Create GitHub release
echo "Step 5/5: Creating GitHub release..."
git add homebrew/maccrab.rb
git diff --cached --quiet || git commit -m "chore: update Homebrew formula to v$VERSION"
git tag "v$VERSION"
git push origin main --tags

# Upload release artifacts (DMG only — PKG dropped in v1.6.11)
ARTIFACTS=""
[ -f ".build/MacCrab-v$VERSION.dmg" ] && ARTIFACTS=".build/MacCrab-v$VERSION.dmg"

if command -v gh &>/dev/null && [ -n "$ARTIFACTS" ]; then
    gh release create "v$VERSION" $ARTIFACTS \
        --title "MacCrab v$VERSION" \
        --generate-notes
    echo ""
    echo "  ✓ GitHub release created: https://github.com/peterhanily/maccrab/releases/tag/v$VERSION"
else
    echo ""
    echo "  Create release manually at: https://github.com/peterhanily/maccrab/releases/new?tag=v$VERSION"
    echo "  Upload: $ARTIFACTS"
fi

echo ""
echo "═══════════════════════════════════════"
echo "  MacCrab v$VERSION Released!"
echo "═══════════════════════════════════════"
echo ""
echo "  DMG: .build/MacCrab-v$VERSION.dmg"
echo ""
echo "  Users can install with:"
echo "    brew install --cask https://raw.githubusercontent.com/peterhanily/maccrab/main/homebrew/maccrab.rb"
echo ""
