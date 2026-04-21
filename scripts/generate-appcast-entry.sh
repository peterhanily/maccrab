#!/bin/bash
# generate-appcast-entry.sh — Produce a Sparkle <item> snippet for a signed DMG.
#
# Reads a signed, notarized MacCrab DMG, pulls the EdDSA signature from the
# signing Mac's login Keychain via Sparkle's `sign_update` helper, and
# writes an appcast XML fragment to stdout.
#
# Usage:
#   scripts/generate-appcast-entry.sh \
#       --dmg /path/to/MacCrab-1.3.5.dmg \
#       --version 1.3.5 \
#       [--sparkle-bin ~/Tools/Sparkle-2.6.4/bin] \
#       [--release-notes-md path/to/notes.md] \
#     > /tmp/item.xml
#
# Prereqs:
#   - DMG is already signed with Developer ID + notarized + stapled
#   - Sparkle's sign_update is on disk (default: ~/Tools/Sparkle-2.6.4/bin/)
#   - The matching private key lives in the login Keychain
#     (put there by `generate_keys` — see TROUBLESHOOTING.md)
#
# Output goes to stdout. Pipe or redirect to a file you can paste into
# maccrab-site's appcast.xml. `publish-appcast-entry.sh` can do the push
# for you once you've eyeballed the result.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DMG=""
VERSION=""
SPARKLE_BIN="${HOME}/Tools/Sparkle-2.6.4/bin"
RELEASE_NOTES_MD=""
FEED_URL="https://maccrab.com/appcast.xml"
DOWNLOAD_BASE="https://github.com/peterhanily/maccrab/releases/download"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dmg) DMG="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --sparkle-bin) SPARKLE_BIN="$2"; shift 2 ;;
        --release-notes-md) RELEASE_NOTES_MD="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$DMG"     ]] || { echo "ERROR: --dmg required" >&2; exit 2; }
[[ -n "$VERSION" ]] || { echo "ERROR: --version required" >&2; exit 2; }
[[ -f "$DMG"     ]] || { echo "ERROR: DMG not found: $DMG" >&2; exit 1; }
[[ -x "$SPARKLE_BIN/sign_update" ]] || {
    echo "ERROR: sign_update not found at $SPARKLE_BIN/sign_update" >&2
    echo "       Download Sparkle from https://github.com/sparkle-project/Sparkle/releases" >&2
    exit 1
}

# Pull ed25519 signature + byte length from the private key in login Keychain.
# sign_update prints:  sparkle:edSignature="..." length="NNN"
SIG_LINE=$("$SPARKLE_BIN/sign_update" "$DMG")
ED_SIG=$(echo "$SIG_LINE" | sed -E 's/.*edSignature="([^"]+)".*/\1/')
LEN=$(echo    "$SIG_LINE" | sed -E 's/.*length="([^"]+)".*/\1/')

[[ -n "$ED_SIG" ]] || { echo "ERROR: could not parse edSignature from: $SIG_LINE" >&2; exit 1; }
[[ -n "$LEN"    ]] || { echo "ERROR: could not parse length from: $SIG_LINE"     >&2; exit 1; }

PUB_DATE=$(LC_TIME=en_US.UTF-8 date -u '+%a, %d %b %Y %H:%M:%S +0000')
DMG_NAME=$(basename "$DMG")
DOWNLOAD_URL="${DOWNLOAD_BASE}/v${VERSION}/${DMG_NAME}"

# Release notes: prefer explicit --release-notes-md; otherwise the
# convention is a polished `RELEASE_NOTES/v{VERSION}.md`; as a last
# resort, cut the matching section out of CHANGELOG.md. The CHANGELOG
# fallback is information-dense (good for history, noisy in a Sparkle
# update sheet) so always prefer the RELEASE_NOTES file when it exists.
if [[ -z "$RELEASE_NOTES_MD" && -f "RELEASE_NOTES/v${VERSION}.md" ]]; then
    RELEASE_NOTES_MD="RELEASE_NOTES/v${VERSION}.md"
fi

if [[ -z "$RELEASE_NOTES_MD" ]]; then
    if [[ -f "CHANGELOG.md" ]]; then
        NOTES=$(awk -v v="$VERSION" '
            $0 ~ "^## \\["v"\\]" { found=1; next }
            found && /^## \[/ { exit }
            found { print }
        ' CHANGELOG.md)
    fi
    # Strip leading/trailing whitespace. If still empty (no CHANGELOG,
    # or no matching section), fall back to a placeholder so the Sparkle
    # UI doesn't render an empty update sheet.
    NOTES="$(echo "$NOTES" | sed -e '/./,$!d' -e ':a' -e '/^\s*$/{$d;N;ba' -e '}')"
    if [[ -z "$NOTES" ]]; then
        NOTES="No release notes provided for this version. See https://github.com/peterhanily/maccrab/releases/tag/v${VERSION} for details."
    fi
else
    NOTES=$(cat "$RELEASE_NOTES_MD")
fi

# Sparkle renders <description> as HTML, not Markdown. Shipping raw
# Markdown produced the v1.4.0 update sheet showing **bold** as
# literal text and every line collapsed onto one paragraph. Convert
# Markdown → HTML via scripts/_md_to_html.py so RELEASE_NOTES/vX.Y.Z.md
# stays as the single authoritative source (GitHub release still
# renders it as Markdown; Sparkle now sees HTML).
NOTES_TMP=$(mktemp -t maccrab-appcast-notes.XXXXXX.md)
trap 'rm -f "$NOTES_TMP"' EXIT
printf '%s' "$NOTES" > "$NOTES_TMP"
NOTES_HTML=$(python3 "$SCRIPT_DIR/_md_to_html.py" "$NOTES_TMP" 2>/dev/null || true)
rm -f "$NOTES_TMP"
if [[ -z "$NOTES_HTML" ]]; then
    # Converter failed — fall back to the raw Markdown so the sheet
    # at least shows content. Better than nothing; still fixable by
    # a follow-up appcast republish.
    NOTES_HTML="$NOTES"
fi

# Emit a single Sparkle <item>. HTML notes are embedded as CDATA so
# tags pass through unescaped.
cat <<XML
<item>
  <title>MacCrab ${VERSION}</title>
  <link>https://github.com/peterhanily/maccrab/releases/tag/v${VERSION}</link>
  <sparkle:version>${VERSION}</sparkle:version>
  <sparkle:shortVersionString>${VERSION}</sparkle:shortVersionString>
  <sparkle:minimumSystemVersion>13.0</sparkle:minimumSystemVersion>
  <pubDate>${PUB_DATE}</pubDate>
  <description><![CDATA[
${NOTES_HTML}
]]></description>
  <enclosure
    url="${DOWNLOAD_URL}"
    length="${LEN}"
    type="application/octet-stream"
    sparkle:edSignature="${ED_SIG}" />
</item>
XML
