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
#       [--sparkle-bin <dir-with-sign_update>] \
#       [--release-notes-md path/to/notes.md] \
#     > /tmp/item.xml
#
# Prereqs:
#   - DMG is already signed with Developer ID + notarized + stapled
#   - Sparkle's sign_update is on disk; auto-detected across
#     ~/Tools/bin, ~/Tools/Sparkle/bin, ~/Tools/Sparkle-2.6.4/bin,
#     ~/Tools/Sparkle-2*/bin, /usr/local/bin, /opt/homebrew/bin.
#     Override with --sparkle-bin or the SPARKLE_BIN env var.
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
SPARKLE_BIN="${SPARKLE_BIN:-}"   # env var override wins over auto-detect
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

# Auto-detect sign_update across a handful of well-known install
# layouts. Pre-fix the script hardcoded `~/Tools/Sparkle-2.6.4/bin`,
# which matched only the version-numbered tarball extract. After
# rolling Sparkle bumps, operators inevitably keep the tool at a
# version-agnostic path like `~/Tools/bin/` — the hardcoded default
# then silently failed at the very end of `release.sh` step 6.
# Try the env var / flag first, then any layout where `sign_update`
# is executable. Stops at the first hit. v1.10.0 audit fix.
if [[ -z "$SPARKLE_BIN" ]]; then
    for candidate in \
        "${HOME}/Tools/bin" \
        "${HOME}/Tools/Sparkle/bin" \
        "${HOME}/Tools/Sparkle-2.6.4/bin" \
        "${HOME}/Tools/Sparkle-2"*"/bin" \
        "/usr/local/bin" \
        "/opt/homebrew/bin"
    do
        # Glob expansion above can leave a literal Sparkle-2*/bin if
        # there are no matches — guard against that with `-x`.
        if [[ -x "$candidate/sign_update" ]]; then
            SPARKLE_BIN="$candidate"
            break
        fi
    done
fi

[[ -n "$DMG"     ]] || { echo "ERROR: --dmg required" >&2; exit 2; }
[[ -n "$VERSION" ]] || { echo "ERROR: --version required" >&2; exit 2; }
[[ -f "$DMG"     ]] || { echo "ERROR: DMG not found: $DMG" >&2; exit 1; }
[[ -n "$SPARKLE_BIN" && -x "$SPARKLE_BIN/sign_update" ]] || {
    echo "ERROR: sign_update not found." >&2
    echo "       Searched: ~/Tools/bin, ~/Tools/Sparkle/bin,"  >&2
    echo "                 ~/Tools/Sparkle-2.6.4/bin, ~/Tools/Sparkle-2*/bin," >&2
    echo "                 /usr/local/bin, /opt/homebrew/bin." >&2
    echo "       Override with --sparkle-bin <dir> or export SPARKLE_BIN." >&2
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

# Verify the signing key pairs with the SHIPPED public key BEFORE emitting the
# appcast item. The signature comes from whatever EdDSA private key the login
# Keychain holds; if that key does NOT pair with the SUPublicEDKey baked into
# the app (project.yml — canonical), every installed user's Sparkle verification
# fails silently and the update is dead on arrival. This catches a regenerated /
# wrong-account / restored-backup key BEFORE publish, not after a yank.
EXPECTED_PUB=$(grep -E '^[[:space:]]*SUPublicEDKey:' "$SCRIPT_DIR/../Xcode/project.yml" 2>/dev/null | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
if [[ -z "$EXPECTED_PUB" ]]; then
    echo "ERROR: could not read SUPublicEDKey from Xcode/project.yml to verify the appcast signature" >&2
    exit 1
fi
# 1. Pairing: generate_keys -p prints the PUBLIC key for the Keychain private
#    key. It must equal the public key shipped in the app.
GENKEYS="$SPARKLE_BIN/generate_keys"
if [[ -x "$GENKEYS" ]]; then
    ACTUAL_PUB=$("$GENKEYS" -p 2>/dev/null | tr -d '[:space:]')
    if [[ -n "$ACTUAL_PUB" && "$ACTUAL_PUB" != "$EXPECTED_PUB" ]]; then
        echo "ERROR: the Keychain Sparkle private key does NOT pair with the shipped SUPublicEDKey." >&2
        echo "       shipped (project.yml): ${EXPECTED_PUB:0:12}…   keychain: ${ACTUAL_PUB:0:12}…" >&2
        echo "       Publishing would brick auto-update for every installed user. Aborting." >&2
        exit 1
    fi
fi
# 2. Signature validity: confirm the just-produced edSignature actually verifies
#    for the DMG with the Keychain key (catches a corrupt/partial signature).
if ! "$SPARKLE_BIN/sign_update" --verify "$DMG" "$ED_SIG" >/dev/null 2>&1; then
    echo "ERROR: the produced appcast edSignature failed sign_update --verify against the DMG. Aborting." >&2
    exit 1
fi
# Status message → stderr ONLY. stdout is the appcast <item> XML that
# release.sh captures verbatim into the published appcast file; printing
# this confirmation to stdout would prepend a stray non-XML "signature
# verified" line into every published entry.
echo "  Appcast signature verified; signing key pairs with shipped SUPublicEDKey ${EXPECTED_PUB:0:8}…" >&2

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
