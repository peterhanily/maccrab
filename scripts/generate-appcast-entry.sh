#!/bin/bash
# Generate one schema-checked Sparkle <item> from a signed DMG.
#
# Release signing tools are never searched on PATH, in ~/Tools, or under
# Homebrew. Only the exact SwiftPM artifact pinned by Package.resolved and
# scripts/release-dependencies.lock may touch the Sparkle private key.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DMG=""
VERSION=""
BUILD_ID=""
RELEASE_NOTES_MD=""
IMMEDIATE="${MACCRAB_APPCAST_IMMEDIATE:-0}"
PHASED_INTERVAL="${MACCRAB_PHASED_ROLLOUT_INTERVAL:-86400}"

usage() {
    echo "usage: $0 --dmg MacCrab-vX.dmg --version X [--build-number X.N]" >&2
    echo "          [--release-notes-md FILE] [--phased-rollout-interval N|--immediate]" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dmg) [[ $# -ge 2 ]] || { usage; exit 2; }; DMG="$2"; shift 2 ;;
        --version) [[ $# -ge 2 ]] || { usage; exit 2; }; VERSION="$2"; shift 2 ;;
        --build-number) [[ $# -ge 2 ]] || { usage; exit 2; }; BUILD_ID="$2"; shift 2 ;;
        --release-notes-md) [[ $# -ge 2 ]] || { usage; exit 2; }; RELEASE_NOTES_MD="$2"; shift 2 ;;
        --phased-rollout-interval) [[ $# -ge 2 ]] || { usage; exit 2; }; PHASED_INTERVAL="$2"; shift 2 ;;
        --immediate|--critical) IMMEDIATE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        # There is intentionally no --sparkle-bin override. An override turns
        # the private-key verifier into attacker-selected executable code.
        *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$DMG" && -n "$VERSION" ]] || { usage; exit 2; }
[[ -f "$DMG" && ! -L "$DMG" ]] || { echo "ERROR: DMG must be a regular no-link file: $DMG" >&2; exit 1; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || {
    echo "ERROR: unsafe version shape: $VERSION" >&2; exit 2;
}
BUILD_ID="${BUILD_ID:-${BUILD_NUMBER:-$VERSION}}"
[[ "$BUILD_ID" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?(\.[0-9]+)?$ ]] || {
    echo "ERROR: unsafe build-number shape: $BUILD_ID" >&2; exit 2;
}
[[ "$(/usr/bin/basename "$DMG")" == "MacCrab-v${VERSION}.dmg" ]] || {
    echo "ERROR: DMG basename must be MacCrab-v${VERSION}.dmg" >&2; exit 2;
}
if [[ "$IMMEDIATE" != "0" && "$IMMEDIATE" != "1" ]]; then
    echo "ERROR: immediate rollout flag must be 0 or 1" >&2; exit 2
fi
if [[ "$IMMEDIATE" == "0" ]] && ! [[ "$PHASED_INTERVAL" =~ ^[1-9][0-9]{0,9}$ ]]; then
    echo "ERROR: phased rollout interval must be a positive decimal" >&2; exit 2
fi

# This validates Package.swift, Package.resolved, the resolved Sparkle package's
# binary-artifact checksum, and both exact tool hashes before either executes.
"$SCRIPT_DIR/check-release-dependencies.sh" >/dev/null
SPARKLE_BIN="$PROJECT_DIR/.build/artifacts/sparkle/Sparkle/bin"

run_sparkle_tool() {
    # GitHub PATs, notary credentials, Python paths, DYLD injection variables,
    # and every other ambient release secret are deliberately absent.
    /usr/bin/env -i \
        PATH=/usr/bin:/bin \
        HOME="${HOME:?}" \
        TMPDIR=/private/tmp \
        LC_ALL=C \
        LANG=C \
        "$@"
}

# sign_update prints: sparkle:edSignature="..." length="NNN".
SIG_LINE=$(run_sparkle_tool "$SPARKLE_BIN/sign_update" "$DMG")
ED_SIG=$(printf '%s\n' "$SIG_LINE" | /usr/bin/sed -nE 's/.*sparkle:edSignature="([A-Za-z0-9+\/=]+)".*/\1/p')
LEN=$(printf '%s\n' "$SIG_LINE" | /usr/bin/sed -nE 's/.*length="([0-9]+)".*/\1/p')
[[ "$ED_SIG" =~ ^[A-Za-z0-9+/]{86}==$ ]] || { echo "ERROR: sign_update returned an invalid Ed25519 signature shape" >&2; exit 1; }
[[ "$LEN" =~ ^[1-9][0-9]{0,15}$ ]] || { echo "ERROR: sign_update returned an invalid length" >&2; exit 1; }
ACTUAL_LEN=$(/usr/bin/stat -f%z "$DMG")
[[ "$LEN" == "$ACTUAL_LEN" ]] || {
    echo "ERROR: sign_update length $LEN != DMG size $ACTUAL_LEN" >&2; exit 1;
}

# Pair the Keychain key to the public key shipped in MacCrab, then verify the
# produced signature. These checks are meaningful because their binaries were
# independently authenticated above; a same-directory substituted pair cannot
# self-attest anymore.
EXPECTED_PUB=$(/usr/bin/grep -E '^[[:space:]]*SUPublicEDKey:' "$PROJECT_DIR/Xcode/project.yml" \
    | /usr/bin/head -1 | /usr/bin/sed -E 's/.*"([^"]+)".*/\1/')
[[ "$EXPECTED_PUB" =~ ^[A-Za-z0-9+/]{43}=$ ]] || {
    echo "ERROR: shipped SUPublicEDKey is absent or malformed" >&2; exit 1;
}
ACTUAL_PUB=$(run_sparkle_tool "$SPARKLE_BIN/generate_keys" -p | /usr/bin/tr -d '[:space:]')
[[ "$ACTUAL_PUB" == "$EXPECTED_PUB" ]] || {
    echo "ERROR: Keychain Sparkle key does not pair with the shipped SUPublicEDKey" >&2; exit 1;
}
if ! run_sparkle_tool "$SPARKLE_BIN/sign_update" --verify "$DMG" "$ED_SIG" >/dev/null 2>&1; then
    echo "ERROR: produced appcast signature failed independent tool verification" >&2
    exit 1
fi
echo "  Appcast signature verified with locked Sparkle tools; key pairs with ${EXPECTED_PUB:0:8}…" >&2

# Resolve notes without executing user-site Python. Bound the source before it
# reaches the converter or shell memory.
if [[ -z "$RELEASE_NOTES_MD" && -f "$PROJECT_DIR/RELEASE_NOTES/v${VERSION}.md" ]]; then
    RELEASE_NOTES_MD="$PROJECT_DIR/RELEASE_NOTES/v${VERSION}.md"
fi
WORK_DIR=$(/usr/bin/mktemp -d /private/tmp/maccrab-appcast.XXXXXX)
trap '/bin/rm -rf "$WORK_DIR"' EXIT HUP INT TERM
NOTES_MD="$WORK_DIR/notes.md"
NOTES_HTML="$WORK_DIR/notes.html"

if [[ -n "$RELEASE_NOTES_MD" ]]; then
    [[ -f "$RELEASE_NOTES_MD" && ! -L "$RELEASE_NOTES_MD" ]] || {
        echo "ERROR: release notes must be a regular no-link file" >&2; exit 1;
    }
    notes_size=$(/usr/bin/stat -f%z "$RELEASE_NOTES_MD")
    [[ "$notes_size" -le 1048576 ]] || { echo "ERROR: release notes exceed 1 MiB" >&2; exit 1; }
    /bin/cp "$RELEASE_NOTES_MD" "$NOTES_MD"
else
    printf '%s\n' "No release notes provided for this version. See https://github.com/peterhanily/maccrab/releases/tag/v${VERSION} for details." > "$NOTES_MD"
fi

if ! /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C LANG=C \
        /usr/bin/python3 -I "$SCRIPT_DIR/_md_to_html.py" "$NOTES_MD" > "$NOTES_HTML"; then
    echo "ERROR: release-note Markdown conversion failed" >&2
    exit 1
fi
[[ -s "$NOTES_HTML" ]] || { echo "ERROR: release-note HTML is empty" >&2; exit 1; }

PUB_DATE=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_TIME=en_US.UTF-8 /bin/date -u '+%a, %d %b %Y %H:%M:%S +0000')
GEN_ARGS=(
    generate
    --version "$VERSION"
    --build-number "$BUILD_ID"
    --pub-date "$PUB_DATE"
    --signature "$ED_SIG"
    --length "$LEN"
    --dmg-name "MacCrab-v${VERSION}.dmg"
    --notes-file "$NOTES_HTML"
)
if [[ "$IMMEDIATE" == "1" ]]; then
    echo "  Appcast rollout: IMMEDIATE (100% now)" >&2
else
    GEN_ARGS+=(--phased-interval "$PHASED_INTERVAL")
    echo "  Appcast rollout: PHASED — ${PHASED_INTERVAL}s per group" >&2
fi

# Generation includes CDATA splitting and a namespace-wrapped XML parse. Only a
# schema-valid fragment reaches stdout / the publisher.
/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C LANG=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_appcast_xml.py" "${GEN_ARGS[@]}"
