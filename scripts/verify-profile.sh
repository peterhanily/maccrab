#!/bin/bash
# verify-profile.sh — Inspect a .provisionprofile file and print the fields
# that decide how we embed it in the release build.
#
# Usage:
#   scripts/verify-profile.sh ~/Downloads/MacCrab_Endpoint_Security.provisionprofile
#
# Output covers:
#   - Name, UUID, expiry
#   - Team identifier
#   - App ID (must match com.maccrab.agent or com.maccrab.app)
#   - Profile type: Development | Developer ID | Distribution
#   - Entitlements list (confirms Endpoint Security is present)
#   - Provisioned devices (development profiles only)
#
# No network, no side effects. Just reads the file and prints a report.

set -euo pipefail

PROFILE="${1:-}"
if [ -z "$PROFILE" ] || [ ! -f "$PROFILE" ]; then
    echo "Usage: $0 <path-to-.provisionprofile>"
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Provisioning profiles are CMS-signed plists. Extract the plist payload.
security cms -D -i "$PROFILE" -o "$TMPDIR/profile.plist" 2>/dev/null

pl() { /usr/libexec/PlistBuddy -c "Print $1" "$TMPDIR/profile.plist" 2>/dev/null || echo "(not set)"; }

NAME=$(pl ":Name")
UUID=$(pl ":UUID")
EXPIRES=$(pl ":ExpirationDate")
TEAM_NAME=$(pl ":TeamName")
TEAM_ID=$(pl ":TeamIdentifier:0")
APP_ID_NAME=$(pl ":AppIDName")
APP_ID=$(pl ":Entitlements:application-identifier")
PROV_ALL=$(pl ":ProvisionsAllDevices")

PLATFORM=$(pl ":Platform:0")

# Profile classification — Apple exposes different flag sets per type.
# - Development: has ProvisionedDevices list
# - Developer ID (distribution outside App Store): no DevicesFile, has appex entitlement set
# - App Store Distribution: has :ProvisionsAllDevices or specific DER fields
has_devices() {
    /usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" "$TMPDIR/profile.plist" 2>/dev/null | head -1 | grep -q "^Array\|^{"
}

TYPE="Unknown"
if has_devices; then
    TYPE="Development (provisioned devices only)"
elif [ "$PROV_ALL" = "true" ]; then
    TYPE="Distribution (provisions all devices)"
else
    # Heuristic: Developer ID signing cert name appears in DeveloperCertificates
    FIRST_CERT=$(/usr/libexec/PlistBuddy -c "Print :DeveloperCertificates:0" "$TMPDIR/profile.plist" 2>/dev/null \
        | xxd -r -p 2>/dev/null | openssl x509 -inform DER -noout -subject 2>/dev/null)
    if echo "$FIRST_CERT" | grep -qi "Developer ID"; then
        TYPE="Developer ID Distribution"
    elif echo "$FIRST_CERT" | grep -qi "Mac Developer\|Apple Development"; then
        TYPE="Development"
    fi
fi

cat <<REPORT
────────────────────────────────────────────────────────────────
  Provisioning profile:
    File: $PROFILE
    Name: $NAME
    UUID: $UUID
    Expires: $EXPIRES
    Platform: $PLATFORM

  Identity:
    Team: $TEAM_NAME ($TEAM_ID)
    App ID Name: $APP_ID_NAME
    App ID: $APP_ID

  Type: $TYPE

  Entitlements (from profile):
REPORT

/usr/libexec/PlistBuddy -c "Print :Entitlements" "$TMPDIR/profile.plist" 2>/dev/null \
    | sed 's/^/    /'

cat <<EOF

  Endpoint Security specifically:
EOF
for key in \
    "com.apple.developer.endpoint-security.client" \
    "com.apple.developer.system-extension.install" \
    "com.apple.developer.endpoint-security.event-monitor"; do
    val=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:$key" "$TMPDIR/profile.plist" 2>/dev/null || echo "")
    if [ -n "$val" ]; then
        echo "    ✓ $key = $val"
    fi
done

if has_devices; then
    echo ""
    echo "  Provisioned devices (development profile only):"
    /usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" "$TMPDIR/profile.plist" 2>/dev/null | sed 's/^/    /' | head -40
fi

echo "────────────────────────────────────────────────────────────────"
