#!/bin/bash
# Adversarial fixture for the deterministic disabled-channel release guard.
# It uses only synthetic files under a temporary directory and never reads or
# names a private-key location.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECK="$SCRIPT_DIR/check-rules-trust-anchor.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/maccrab-rules-disabled.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

expect_fail() {
    local label="$1"
    shift
    if "$@" >"$WORK/output.log" 2>&1; then
        echo "FAIL: $label unexpectedly passed" >&2
        exit 1
    fi
    echo "PASS: $label refused"
}

"$CHECK" >/dev/null
echo "PASS: production disabled state accepted"

mkdir -p "$WORK/dormant-source"
printf 'func loadPushedRules(from directory: URL) throws -> Int { 0 }\n' > "$WORK/dormant-source/RuleEngine.swift"
printf 'public enum RuleChannelPolicy {\n    public static let productionEnabled = false\n}\n' > "$WORK/policy-false.swift"
"$CHECK" \
    --source-key "$WORK/absent-source.pub" \
    --artifact-key "$WORK/absent-artifact.pub" \
    --policy-source "$WORK/policy-false.swift" \
    --source-tree "$WORK/dormant-source" >/dev/null
echo "PASS: synthetic disabled fixture accepted"

printf 'unexpected anchor\n' > "$WORK/source.pub"
expect_fail "source public anchor" "$CHECK" \
    --source-key "$WORK/source.pub" \
    --policy-source "$WORK/policy-false.swift" \
    --source-tree "$WORK/dormant-source"

printf 'unexpected anchor\n' > "$WORK/artifact.pub"
expect_fail "final-artifact public anchor" "$CHECK" \
    --source-key "$WORK/absent-source.pub" \
    --artifact-key "$WORK/artifact.pub" \
    --policy-source "$WORK/policy-false.swift" \
    --source-tree "$WORK/dormant-source"

printf 'public enum RuleChannelPolicy {\n    public static let productionEnabled = true\n}\n' > "$WORK/policy-true.swift"
expect_fail "enabled production policy" "$CHECK" \
    --source-key "$WORK/absent-source.pub" \
    --policy-source "$WORK/policy-true.swift" \
    --source-tree "$WORK/dormant-source"

cp -R "$WORK/dormant-source" "$WORK/source-with-loader"
printf 'func drift() async throws { try await engine.loadPushedRules(from: url) }\n' > "$WORK/source-with-loader/Drift.swift"
expect_fail "production pushed-corpus loader drift" "$CHECK" \
    --source-key "$WORK/absent-source.pub" \
    --policy-source "$WORK/policy-false.swift" \
    --source-tree "$WORK/source-with-loader"

echo "rules disabled-state fixture: ALL GREEN"
