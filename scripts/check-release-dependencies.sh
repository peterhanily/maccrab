#!/bin/bash
# Fail-closed provenance check for code executed during a release.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOCK="$SCRIPT_DIR/release-dependencies.lock"

fail() { echo "ERROR: release dependency provenance: $*" >&2; exit 1; }

[[ -f "$LOCK" && ! -L "$LOCK" ]] || fail "missing or linked lock: $LOCK"

bad_lock=$(/usr/bin/grep -Ev '^(#.*|[[:space:]]*|[a-z0-9_]+=[A-Za-z0-9._:/+-]+)$' "$LOCK" || true)
[[ -z "$bad_lock" ]] || fail "lock contains malformed data"

required_keys=(
    format_version
    sparkle_version
    sparkle_revision
    sparkle_binary_artifact_sha256
    sparkle_sign_update_sha256
    sparkle_generate_keys_sha256
    pyyaml_version
    pyyaml_file_count
)

while IFS='=' read -r key _; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    allowed=0
    for required in "${required_keys[@]}"; do
        [[ "$key" == "$required" ]] && allowed=1
    done
    [[ "$allowed" == "1" ]] || fail "unknown lock key: $key"
done < "$LOCK"

lock_value() {
    local key="$1" count
    count=$(/usr/bin/grep -c "^${key}=" "$LOCK" || true)
    [[ "$count" == "1" ]] || fail "lock key $key occurs $count times"
    /usr/bin/sed -n "s/^${key}=//p" "$LOCK"
}

for required in "${required_keys[@]}"; do
    lock_value "$required" >/dev/null
done

[[ "$(lock_value format_version)" == "1" ]] || fail "unsupported lock format"

SPARKLE_VERSION="$(lock_value sparkle_version)"
SPARKLE_REVISION="$(lock_value sparkle_revision)"
SPARKLE_ARTIFACT_SHA="$(lock_value sparkle_binary_artifact_sha256)"
SIGN_UPDATE_SHA="$(lock_value sparkle_sign_update_sha256)"
GENERATE_KEYS_SHA="$(lock_value sparkle_generate_keys_sha256)"

[[ "$SPARKLE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "bad Sparkle version shape"
[[ "$SPARKLE_REVISION" =~ ^[a-f0-9]{40}$ ]] || fail "bad Sparkle revision shape"
for digest in "$SPARKLE_ARTIFACT_SHA" "$SIGN_UPDATE_SHA" "$GENERATE_KEYS_SHA"; do
    [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || fail "bad SHA-256 shape"
done

manifest_version=$(/usr/bin/sed -nE '/url:[[:space:]]*"https:\/\/github\.com\/sparkle-project\/Sparkle"/{N;s/.*exact:[[:space:]]*"([0-9.]+)".*/\1/p;}' "$PROJECT_DIR/Package.swift" | /usr/bin/head -1)
[[ "$manifest_version" == "$SPARKLE_VERSION" ]] || fail "Package.swift Sparkle pin ($manifest_version) != lock ($SPARKLE_VERSION)"

resolved=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -c '
import json, sys
with open(sys.argv[1], "rb") as fh:
    data = json.load(fh)
pins = [p for p in data.get("pins", []) if p.get("identity") == "sparkle"]
if len(pins) != 1:
    raise SystemExit("expected exactly one Sparkle pin")
pin = pins[0]
if pin.get("location") != "https://github.com/sparkle-project/Sparkle":
    raise SystemExit("unexpected Sparkle origin")
state = pin.get("state", {})
print(state.get("version", "") + " " + state.get("revision", ""))
' "$PROJECT_DIR/Package.resolved") || fail "could not validate Package.resolved"
[[ "$resolved" == "$SPARKLE_VERSION $SPARKLE_REVISION" ]] || fail "Package.resolved Sparkle pin ($resolved) != lock"

CHECKOUT_MANIFEST="$PROJECT_DIR/.build/checkouts/Sparkle/Package.swift"
[[ -f "$CHECKOUT_MANIFEST" && ! -L "$CHECKOUT_MANIFEST" ]] || fail "clean-resolved Sparkle checkout is absent"
checkout_version=$(/usr/bin/sed -nE 's/^let version = "([0-9.]+)"$/\1/p' "$CHECKOUT_MANIFEST" | /usr/bin/head -1)
checkout_checksum=$(/usr/bin/sed -nE 's/^let checksum = "([a-f0-9]{64})"$/\1/p' "$CHECKOUT_MANIFEST" | /usr/bin/head -1)
[[ "$checkout_version" == "$SPARKLE_VERSION" ]] || fail "resolved checkout version ($checkout_version) != lock"
[[ "$checkout_checksum" == "$SPARKLE_ARTIFACT_SHA" ]] || fail "resolved binary-artifact checksum ($checkout_checksum) != lock"

SPARKLE_BIN="$PROJECT_DIR/.build/artifacts/sparkle/Sparkle/bin"
for tool in sign_update generate_keys; do
    path="$SPARKLE_BIN/$tool"
    [[ -f "$path" && ! -L "$path" && -x "$path" ]] || fail "$tool is missing, linked, or non-executable at the fixed SwiftPM artifact path"
done

actual_sign=$(/usr/bin/shasum -a 256 "$SPARKLE_BIN/sign_update" | /usr/bin/awk '{print $1}')
actual_keys=$(/usr/bin/shasum -a 256 "$SPARKLE_BIN/generate_keys" | /usr/bin/awk '{print $1}')
[[ "$actual_sign" == "$SIGN_UPDATE_SHA" ]] || fail "sign_update hash mismatch (got $actual_sign)"
[[ "$actual_keys" == "$GENERATE_KEYS_SHA" ]] || fail "generate_keys hash mismatch (got $actual_keys)"

echo "Sparkle $SPARKLE_VERSION release tools match Package.resolved + checked hashes"
