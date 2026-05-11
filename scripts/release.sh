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

# Step 0a: appcast publishing precondition. v1.10.0-rc audit fix:
# step 6 below auto-publishes the appcast entry to the site repo
# when SITE_REPO_TOKEN is set, otherwise soft-fails with a warning.
# A soft-fail at minute ~12 of the release after the operator has
# already burnt notarization + DMG time is too late to recover —
# field-observed multiple times: "everything looked green but
# existing v1.x users never received the update." Now: refuse to
# start if the token is missing AND the operator hasn't explicitly
# opted out via SKIP_APPCAST=1. Catches the gap before any work
# is wasted.
if [ -z "${SITE_REPO_TOKEN:-}" ] && [ "${SKIP_APPCAST:-0}" != "1" ]; then
    echo "ERROR: SITE_REPO_TOKEN env var not set and SKIP_APPCAST != 1." >&2
    echo "" >&2
    echo "Without one of these, step 6 (Sparkle appcast publish) will not" >&2
    echo "run, and existing v1.x users WILL NOT receive v$VERSION via" >&2
    echo "auto-update — only the brew-upgrade path will deliver the new" >&2
    echo "version to them." >&2
    echo "" >&2
    echo "Either:" >&2
    echo "  - Add SITE_REPO_TOKEN to ~/.maccrab-release-env (recommended)" >&2
    echo "  - Or set SKIP_APPCAST=1 to confirm an intentional skip" >&2
    echo "    (e.g. internal-only / dry-run releases)" >&2
    exit 1
fi

# Step 0b: Pre-release check — enforce RELEASE_CHECKLIST.md items so the
# pipeline refuses to ship out-of-sync versions, stale notes, or broken
# localizations. Warnings still proceed; hard errors abort.
echo "Step 0/6: Pre-release check..."
"$SCRIPT_DIR/prerelease-check.sh" "$VERSION" || {
    echo "Pre-release check failed — fix the errors above or run with --skip-prerelease-check to override (not recommended)"
    exit 1
}

# Step 0b: Architectural-invariants audit (v1.6.19). Catches the
# wire-the-orphans bug class and AlertSink-bypass regressions BEFORE
# they ship. Sister script to prerelease-check.sh: that one verifies
# manifest sync, this one verifies code structure.
echo "Step 0b/6: Architectural audit..."
"$SCRIPT_DIR/pre-release-audit.sh" || {
    echo "Architectural audit failed — fix the structural issues above before shipping"
    exit 1
}

# Step 1: Tests
#
# Pre-fix: `swift test 2>&1 | grep "Test run with"` matched both
# pass AND fail summary lines (Swift Testing prints the same prefix
# in either case), so the OR-chain only fired when grep matched
# nothing — i.e., the test runner crashed. Any test-suite failure
# was silently treated as success and the release shipped broken.
# Now: capture the swift test exit code FIRST, then report.
echo "Step 1/6: Running tests..."
if ! swift test; then
    echo "Tests failed — fix and re-run release.sh"
    exit 1
fi

# Step 2: Rule compilation
echo "Step 2/6: Compiling rules..."
python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir .build/compiled_rules 2>&1 | tail -1

# Step 2b: Regenerate README rule-count table + docs/COVERAGE.md so
# they match the YAML tree being released. v1.10 shipped with stale
# numbers in the README's hand-written coverage paragraph; auto-gen
# closes that drift window.
echo "Step 2b/6: Regenerating coverage docs..."
python3 scripts/coverage_matrix.py --update-readme README.md Rules/
python3 scripts/generate-coverage-doc.py > docs/COVERAGE.md
if ! git diff --quiet -- README.md docs/COVERAGE.md; then
    echo "  README.md / docs/COVERAGE.md changed — staging diff for the release commit"
    git add README.md docs/COVERAGE.md
fi

# Step 3: Build DMG
echo "Step 3/5: Building DMG..."
VERSION="$VERSION" ./scripts/build-release.sh

# (v1.6.11) PKG build removed — productbuild's distribution-XML
# pkg-ref name didn't match the component pkg filename, producing
# a 1.9KB stub archive that opened in Installer.app but contained
# no payload. DMG + Homebrew are the supported install paths.

# Step 4: Update Homebrew formulae
#
# The repo historically has TWO cask files — homebrew/maccrab.rb (legacy,
# in-tree docs) and Casks/maccrab.rb (what the Homebrew tap actually
# reads when this repo is tapped via `brew tap peterhanily/maccrab`).
# Pre-v1.6.14 the script only updated homebrew/maccrab.rb, so every
# release since v1.6.5 landed with a stale Casks/maccrab.rb — brew
# users saw old versions for nine releases before anyone noticed.
# Both files are now updated in lockstep.
DMG_PATH=".build/MacCrab-v$VERSION.dmg"
if [ -f "$DMG_PATH" ]; then
    echo "Step 4/5: Updating Homebrew formulae..."
    SHA=$(shasum -a 256 "$DMG_PATH" | awk '{print $1}')
    for formula in homebrew/maccrab.rb Casks/maccrab.rb; do
        if [ -f "$formula" ]; then
            sed -i '' "s/version \".*\"/version \"$VERSION\"/" "$formula"
            sed -i '' "s/sha256 .*/sha256 \"$SHA\"/" "$formula"
            echo "  Updated $formula (sha256: ${SHA:0:16}...)"
        fi
    done
fi

# Step 5: Create GitHub release
echo "Step 5/5: Creating GitHub release..."
git add homebrew/maccrab.rb Casks/maccrab.rb 2>/dev/null || true
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

# Step 6: Publish appcast entry. Pre-fix this script stopped after
# `gh release create` and the operator had to remember to run
# generate-appcast-entry.sh + publish-appcast-entry.sh manually. The
# procedural gap meant several point releases shipped to GitHub but
# never reached existing users' Sparkle clients. Now: always try.
# Soft-fail if SITE_REPO_TOKEN is missing (log + skip; release stays
# successful) or SKIP_APPCAST=1 was passed (CI / manual override).
if [ "${SKIP_APPCAST:-0}" = "1" ]; then
    echo ""
    echo "  Step 6/6: Skipping appcast publish (SKIP_APPCAST=1)"
elif [ -n "${SITE_REPO_TOKEN:-}" ] && [ -f "$DMG_PATH" ]; then
    echo ""
    echo "Step 6/6: Publishing appcast entry..."
    SITE_REPO="${SITE_REPO:-peterhanily/maccrab-site}"
    APPCAST_ITEM=$(mktemp -t maccrab-appcast-item.XXXXXX.xml)
    if "$SCRIPT_DIR/generate-appcast-entry.sh" \
            --dmg "$DMG_PATH" --version "$VERSION" \
            > "$APPCAST_ITEM"; then
        if SITE_REPO_TOKEN="$SITE_REPO_TOKEN" \
                "$SCRIPT_DIR/publish-appcast-entry.sh" \
                --item "$APPCAST_ITEM" \
                --site-repo "$SITE_REPO" \
                --version "$VERSION"; then
            echo "  ✓ Appcast entry published; existing v1.x users will see the update within ~30s"
        else
            echo "  ! Appcast publish failed — run 'scripts/publish-appcast-entry.sh --item $APPCAST_ITEM' manually" >&2
        fi
    else
        echo "  ! Appcast generate failed — fix Sparkle sign_update + private key and retry" >&2
    fi
    rm -f "$APPCAST_ITEM"
else
    echo ""
    echo "  Step 6/6: Skipping appcast publish."
    if [ -z "${SITE_REPO_TOKEN:-}" ]; then
        echo "  → SITE_REPO_TOKEN env var not set. Existing users will NOT receive the update."
        echo "    To publish: SITE_REPO_TOKEN=<pat> scripts/publish-appcast-entry.sh \\"
        echo "                  --item <(scripts/generate-appcast-entry.sh --dmg $DMG_PATH --version $VERSION)"
    fi
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
