#!/bin/bash
# Verify an already-staged, pure-Python PyYAML tree against the checked lock.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${1:-}"
MANIFEST="$SCRIPT_DIR/release-pyyaml.sha256"
LOCK="$SCRIPT_DIR/release-dependencies.lock"

fail() { echo "ERROR: PyYAML provenance: $*" >&2; exit 1; }
[[ -n "$ROOT" && -d "$ROOT" && ! -L "$ROOT" ]] || fail "expected a real dependency root"
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || fail "missing checked hash manifest"

expected_count=$(/usr/bin/sed -n 's/^pyyaml_file_count=//p' "$LOCK")
[[ "$expected_count" =~ ^[0-9]+$ ]] || fail "bad locked file count"

manifest_count=$(/usr/bin/grep -Ec '^[a-f0-9]{64}  yaml/[A-Za-z0-9_]+\.py$' "$MANIFEST" || true)
[[ "$manifest_count" == "$expected_count" ]] || fail "manifest count $manifest_count != lock $expected_count"
bad_manifest=$(/usr/bin/grep -Ev '^(#.*|[[:space:]]*|[a-f0-9]{64}  yaml/[A-Za-z0-9_]+\.py)$' "$MANIFEST" || true)
[[ -z "$bad_manifest" ]] || fail "malformed manifest line"

actual_count=$(/usr/bin/find "$ROOT/yaml" -maxdepth 1 -type f -name '*.py' -print 2>/dev/null | /usr/bin/wc -l | /usr/bin/tr -d ' ')
[[ "$actual_count" == "$expected_count" ]] || fail "staged file count $actual_count != lock $expected_count"
[[ -z "$(/usr/bin/find "$ROOT/yaml" -mindepth 1 -maxdepth 1 ! -type f -print 2>/dev/null)" ]] || fail "staged tree contains a link, directory, or special file"

while read -r digest relative; do
    [[ -z "$digest" || "$digest" == \#* ]] && continue
    file="$ROOT/$relative"
    [[ -f "$file" && ! -L "$file" ]] || fail "missing or linked file: $relative"
    actual=$(/usr/bin/shasum -a 256 "$file" | /usr/bin/awk '{print $1}')
    [[ "$actual" == "$digest" ]] || fail "hash mismatch: $relative"
done < "$MANIFEST"

echo "PyYAML staged tree matches $expected_count checked source hashes"
