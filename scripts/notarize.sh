#!/bin/bash
# Disable tracing before any credential or private build-input expansion.
set +x
#
# notarize.sh — Sign a DMG and submit for Apple notarization.
#
# IMPORTANT: All binaries and app bundles inside the DMG must already be
# signed with Developer ID + hardened runtime BEFORE the DMG is created.
# Signing on a mounted DMG causes "internal error in Code Signing subsystem"
# due to APFS CoW. build-release.sh handles this.
#
# This script:
#   1. Signs the DMG itself
#   2. Submits for notarization (if credentials provided)
#   3. Staples the ticket on success
#   4. Verifies the result
#
# Usage:
#   ./scripts/notarize.sh <dmg-path>
#
# Environment variables:
#   DEVELOPER_ID        Developer ID Application certificate name
#                       (e.g., "Developer ID Application: Your Name (TEAMID)")
#                       If unset, falls back to ad-hoc signing.
#
#   NOTARIZE_KEYCHAIN_PROFILE  Name of a saved notarytool credential profile.
#                       Create it interactively with:
#                       xcrun notarytool store-credentials maccrab-notary
#                       Enter credentials at prompts, never in command arguments.
#
# Examples:
#   # Ad-hoc only (no credentials)
#   ./scripts/notarize.sh .build/MacCrab-v1.0.0.dmg
#
#   # Developer ID signing only
#   DEVELOPER_ID="Developer ID Application: Jane Doe (A1B2C3D4E5)" \
#     ./scripts/notarize.sh .build/MacCrab-v1.0.0.dmg
#
#   # Full signing + notarization
#   DEVELOPER_ID="Developer ID Application: Jane Doe (A1B2C3D4E5)" \
#   NOTARIZE_KEYCHAIN_PROFILE=maccrab-notary \
#     ./scripts/notarize.sh .build/MacCrab-v1.0.0.dmg

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}==>${NC} ${BOLD}$1${NC}"; }
ok()    { echo -e "${GREEN}  ✓${NC} $1"; }
warn()  { echo -e "${YELLOW}  ⚠${NC} $1"; }
fail()  { echo -e "${RED}  ✗${NC} $1"; exit 1; }

# Refuse the removed password-argument route before any external command,
# signing, sidecar deletion or submission. Existing profile-based configs may
# still contain unused legacy values; do not pass those to child processes.
NOTARIZE_KEYCHAIN_PROFILE="${NOTARIZE_KEYCHAIN_PROFILE:-}"
if [ -n "$NOTARIZE_KEYCHAIN_PROFILE" ]; then
    [[ "$NOTARIZE_KEYCHAIN_PROFILE" =~ ^[A-Za-z0-9._-]{1,128}$ ]] \
        || fail "NOTARIZE_KEYCHAIN_PROFILE has an unsafe shape"
elif [ -n "${APPLE_ID:-}${APPLE_TEAM_ID:-}${NOTARIZE_PASSWORD:-}" ]; then
    fail "Password-based notarization is disabled. Run xcrun notarytool store-credentials maccrab-notary interactively, enter credentials at prompts, then set NOTARIZE_KEYCHAIN_PROFILE=maccrab-notary."
fi
unset APPLE_ID APPLE_TEAM_ID NOTARIZE_PASSWORD

# ─── Validate arguments ──────────────────────────────────────────────

DMG_PATH="${1:-}"
if [ -z "$DMG_PATH" ]; then
    echo "Usage: $0 <dmg-path>"
    echo ""
    echo "Environment variables:"
    echo "  DEVELOPER_ID       Developer ID certificate (optional, ad-hoc if unset)"
    echo "  NOTARIZE_KEYCHAIN_PROFILE  Saved notarytool credential profile (optional)"
    exit 1
fi

if [ ! -f "$DMG_PATH" ]; then
    fail "DMG not found: $DMG_PATH"
fi

# Resolve to absolute path
DMG_PATH="$(cd "$(dirname "$DMG_PATH")" && pwd)/$(basename "$DMG_PATH")"
NOTARY_ID_PATH="$DMG_PATH.notary-submission-id"
# Never let a prior submission identity describe newly created/re-signed bytes.
# The accepted path below writes a fresh sidecar atomically.
/bin/rm -f "$NOTARY_ID_PATH"

echo ""
echo -e "${BOLD}MacCrab Code Signing & Notarization${NC}"
echo ""

# ─── Sign the DMG ─────────────────────────────────────────────────────

DEVELOPER_ID="${DEVELOPER_ID:-}"

if [ -n "$DEVELOPER_ID" ]; then
    info "Signing DMG with Developer ID..."

    # Verify the certificate exists in the keychain
    if ! security find-identity -v -p codesigning | grep -q "$DEVELOPER_ID"; then
        fail "Certificate not found in keychain: $DEVELOPER_ID"
    fi

    codesign --sign "$DEVELOPER_ID" \
        --timestamp \
        --force \
        "$DMG_PATH"
    ok "Signed DMG: $(basename "$DMG_PATH")"

else
    warn "DEVELOPER_ID not set — using ad-hoc signature"
    codesign --sign - --force "$DMG_PATH" 2>/dev/null || true
    ok "Ad-hoc signed DMG: $(basename "$DMG_PATH")"
fi

# ─── Notarize ─────────────────────────────────────────────────────────

# Credentials are read by notarytool from the selected Keychain profile.
# Interactive setup: xcrun notarytool store-credentials maccrab-notary
# Then set NOTARIZE_KEYCHAIN_PROFILE=maccrab-notary.
NOTARIZE_AUTH=()
NOTARIZE_AUTH_OK=0
NOTARIZE_DISPLAY=""
NOTARIZED="No"
if [ -n "$NOTARIZE_KEYCHAIN_PROFILE" ]; then
    NOTARIZE_AUTH=(--keychain-profile "$NOTARIZE_KEYCHAIN_PROFILE")
    NOTARIZE_AUTH_OK=1
    NOTARIZE_DISPLAY="keychain profile: $NOTARIZE_KEYCHAIN_PROFILE"
fi

if [ "$NOTARIZE_AUTH_OK" = "1" ]; then
    if [ -z "$DEVELOPER_ID" ]; then
        warn "Notarization requires Developer ID signing — skipping notarization"
        warn "Set DEVELOPER_ID to enable notarization"
    else
        info "Submitting for notarization..."
        echo "  $NOTARIZE_DISPLAY"

        # Submit and wait for result (|| true prevents set -e from
        # killing the script before we can inspect the output)
        NOTARIZE_OUTPUT=$(xcrun notarytool submit "$DMG_PATH" \
            "${NOTARIZE_AUTH[@]}" \
            --wait 2>&1) || true

        echo "$NOTARIZE_OUTPUT"

        # A final "status: Accepted" wins over a transient auth blip. The
        # `--wait` poll stream can carry a one-off "Unable to authenticate" /
        # 401 that notarytool recovered from before reaching Accepted, so
        # check acceptance FIRST and only treat auth failure as fatal when the
        # submission did NOT get accepted — otherwise a successful notarization
        # is aborted and the ticket is never stapled (offline installs break).
        if echo "$NOTARIZE_OUTPUT" | grep -q "status: Accepted"; then
            SUBMISSION_ID=$(echo "$NOTARIZE_OUTPUT" | grep -oE 'id: [a-fA-F0-9-]{36}' | head -1 | awk '{print $2}')
            if ! [[ "$SUBMISSION_ID" =~ ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5][a-fA-F0-9]{3}-[89aAbB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$ ]]; then
                fail "Notarization was accepted but its submission UUID was not recorded"
            fi
            ok "Notarization accepted"

            # Staple the ticket
            info "Stapling notarization ticket..."
            if xcrun stapler staple "$DMG_PATH" 2>&1; then
                ok "Notarization ticket stapled"
                NOTARY_ID_TMP="$NOTARY_ID_PATH.tmp.$$"
                /usr/bin/printf 'notary_submission_id=%s\n' \
                    "$(printf '%s' "$SUBMISSION_ID" | /usr/bin/tr '[:upper:]' '[:lower:]')" \
                    > "$NOTARY_ID_TMP"
                /bin/chmod 0600 "$NOTARY_ID_TMP"
                /bin/mv -f "$NOTARY_ID_TMP" "$NOTARY_ID_PATH"
                ok "Notarization identity recorded: $NOTARY_ID_PATH"
                NOTARIZED="Yes"
            else
                fail "Stapling failed — exact-candidate qualification requires an offline-verifiable ticket"
            fi
        elif echo "$NOTARIZE_OUTPUT" | grep -qi "unable to authenticate\|401"; then
            fail "Authentication failed — check NOTARIZE_KEYCHAIN_PROFILE"
        elif echo "$NOTARIZE_OUTPUT" | grep -q "status: Invalid"; then
            # Extract the submission ID for log retrieval
            SUBMISSION_ID=$(echo "$NOTARIZE_OUTPUT" | grep -o 'id: [a-f0-9-]*' | head -1 | awk '{print $2}')
            if [ -n "$SUBMISSION_ID" ]; then
                warn "Notarization rejected. Fetching log..."
                xcrun notarytool log "$SUBMISSION_ID" \
                    "${NOTARIZE_AUTH[@]}" 2>&1 || true
            fi
            fail "Notarization was rejected — see log above"
        else
            fail "Notarization did not succeed — see output above"
        fi
    fi
else
    warn "Notarization skipped — set NOTARIZE_KEYCHAIN_PROFILE after interactive notarytool store-credentials setup"
fi

# ─── Verify ───────────────────────────────────────────────────────────

info "Verifying signature..."
echo ""

if codesign --verify --verbose "$DMG_PATH" 2>&1; then
    ok "Signature verification passed"
else
    warn "Signature verification returned warnings (may be expected for ad-hoc)"
fi

# Check for notarization staple
if xcrun stapler validate "$DMG_PATH" 2>/dev/null; then
    ok "Notarization ticket validated"
fi

# Check Gatekeeper assessment (Developer ID only)
if [ -n "$DEVELOPER_ID" ]; then
    echo ""
    info "Gatekeeper assessment..."
    if spctl --assess --type open --context context:primary-signature --verbose "$DMG_PATH" 2>&1; then
        ok "Gatekeeper: accepted"
    else
        warn "Gatekeeper: not accepted (expected if notarization was skipped)"
    fi
fi

# ─── Summary ──────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo -e "${BOLD}  Signing Summary${NC}"
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo ""
echo "  DMG:          $(basename "$DMG_PATH")"
echo "  Size:         $(du -h "$DMG_PATH" | cut -f1)"
if [ -n "$DEVELOPER_ID" ]; then
    echo "  Signing:      Developer ID"
    echo "  Certificate:  $DEVELOPER_ID"
else
    echo "  Signing:      Ad-hoc (local development only)"
fi
echo "  Notarized:    $NOTARIZED"
echo ""
