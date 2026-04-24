#!/bin/bash
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
#   APPLE_ID            Apple ID email for notarization
#   APPLE_TEAM_ID       Apple Developer Team ID
#   NOTARIZE_PASSWORD    App-specific password (or @keychain:notarize)
#                       All three required to notarize; otherwise skipped.
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
#   APPLE_ID="jane@example.com" \
#   APPLE_TEAM_ID="A1B2C3D4E5" \
#   NOTARIZE_PASSWORD="@keychain:notarize" \
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

# ─── Validate arguments ──────────────────────────────────────────────

DMG_PATH="${1:-}"
if [ -z "$DMG_PATH" ]; then
    echo "Usage: $0 <dmg-path>"
    echo ""
    echo "Environment variables:"
    echo "  DEVELOPER_ID       Developer ID certificate (optional, ad-hoc if unset)"
    echo "  APPLE_ID           Apple ID for notarization (optional)"
    echo "  APPLE_TEAM_ID      Developer Team ID (optional)"
    echo "  NOTARIZE_PASSWORD  App-specific password (optional)"
    exit 1
fi

if [ ! -f "$DMG_PATH" ]; then
    fail "DMG not found: $DMG_PATH"
fi

# Resolve to absolute path
DMG_PATH="$(cd "$(dirname "$DMG_PATH")" && pwd)/$(basename "$DMG_PATH")"

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

APPLE_ID="${APPLE_ID:-}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
NOTARIZE_PASSWORD="${NOTARIZE_PASSWORD:-}"

if [ -n "$APPLE_ID" ] && [ -n "$APPLE_TEAM_ID" ] && [ -n "$NOTARIZE_PASSWORD" ]; then
    if [ -z "$DEVELOPER_ID" ]; then
        warn "Notarization requires Developer ID signing — skipping notarization"
        warn "Set DEVELOPER_ID to enable notarization"
    else
        info "Submitting for notarization..."
        echo "  Apple ID:  $APPLE_ID"
        echo "  Team ID:   $APPLE_TEAM_ID"

        # Submit and wait for result (|| true prevents set -e from
        # killing the script before we can inspect the output)
        NOTARIZE_OUTPUT=$(xcrun notarytool submit "$DMG_PATH" \
            --apple-id "$APPLE_ID" \
            --team-id "$APPLE_TEAM_ID" \
            --password "$NOTARIZE_PASSWORD" \
            --wait 2>&1) || true

        echo "$NOTARIZE_OUTPUT"

        # Check for auth failure
        if echo "$NOTARIZE_OUTPUT" | grep -qi "unable to authenticate\|401"; then
            fail "Authentication failed — check APPLE_ID, APPLE_TEAM_ID, and NOTARIZE_PASSWORD"
        fi

        if echo "$NOTARIZE_OUTPUT" | grep -q "status: Accepted"; then
            ok "Notarization accepted"

            # Staple the ticket
            info "Stapling notarization ticket..."
            if xcrun stapler staple "$DMG_PATH" 2>&1; then
                ok "Notarization ticket stapled"
            else
                warn "Stapling failed — users can still download (ticket is in Apple's servers)"
            fi
        elif echo "$NOTARIZE_OUTPUT" | grep -q "status: Invalid"; then
            # Extract the submission ID for log retrieval
            SUBMISSION_ID=$(echo "$NOTARIZE_OUTPUT" | grep -o 'id: [a-f0-9-]*' | head -1 | awk '{print $2}')
            if [ -n "$SUBMISSION_ID" ]; then
                warn "Notarization rejected. Fetching log..."
                xcrun notarytool log "$SUBMISSION_ID" \
                    --apple-id "$APPLE_ID" \
                    --team-id "$APPLE_TEAM_ID" \
                    --password "$NOTARIZE_PASSWORD" 2>&1 || true
            fi
            fail "Notarization was rejected — see log above"
        else
            fail "Notarization did not succeed — see output above"
        fi
    fi
else
    if [ -n "$APPLE_ID" ] || [ -n "$APPLE_TEAM_ID" ] || [ -n "$NOTARIZE_PASSWORD" ]; then
        warn "Incomplete notarization credentials — all three required:"
        [ -z "$APPLE_ID" ]          && warn "  Missing: APPLE_ID (Apple ID email)"
        [ -z "$APPLE_TEAM_ID" ]     && warn "  Missing: APPLE_TEAM_ID (Developer Team ID)"
        [ -z "$NOTARIZE_PASSWORD" ] && warn "  Missing: NOTARIZE_PASSWORD (app-specific password)"
    else
        warn "Notarization skipped — APPLE_ID, APPLE_TEAM_ID, and NOTARIZE_PASSWORD not set"
    fi
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
if [ -n "$APPLE_ID" ] && [ -n "$APPLE_TEAM_ID" ] && [ -n "$NOTARIZE_PASSWORD" ] && [ -n "$DEVELOPER_ID" ]; then
    echo "  Notarized:    Yes"
else
    echo "  Notarized:    No"
fi
echo ""
