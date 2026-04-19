#!/bin/bash
# bump-cask.sh — Update the Homebrew cask to a new version + sha256.
#
# Usage:
#   scripts/bump-cask.sh --dmg /path/to/MacCrab-1.3.5.dmg --version 1.3.5
#
# Edits BOTH `Casks/maccrab.rb` and `homebrew/maccrab.rb` in place. The
# caller is expected to commit + push the result. Does NOT push to the
# third-party tap if you maintain one in another repo — that's a
# separate release step.

set -euo pipefail

DMG=""
VERSION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dmg)     DMG="$2";     shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$DMG" && -f "$DMG" ]] || { echo "ERROR: --dmg must point to a readable DMG" >&2; exit 2; }
[[ -n "$VERSION" ]]           || { echo "ERROR: --version required"                 >&2; exit 2; }

SHA=$(shasum -a 256 "$DMG" | awk '{print $1}')
[[ -n "$SHA" ]] || { echo "ERROR: sha256 computation failed" >&2; exit 1; }

echo "Version:  ${VERSION}"
echo "SHA-256:  ${SHA}"

for FILE in "Casks/maccrab.rb" "homebrew/maccrab.rb"; do
    [[ -f "$FILE" ]] || { echo "skipping missing: $FILE"; continue; }
    # Use sed -i "" for BSD sed (macOS). The `version` and `sha256` lines are
    # the only ones that change; everything else stays put.
    sed -i "" -E "s|^  version \"[^\"]*\"|  version \"${VERSION}\"|" "$FILE"
    sed -i "" -E "s|^  sha256 \"[^\"]*\"|  sha256 \"${SHA}\"|"       "$FILE"
    echo "✓ Updated: $FILE"
done

echo ""
echo "Verify the diff before committing:"
echo "  git diff Casks/maccrab.rb homebrew/maccrab.rb"
