#!/bin/bash
# Hermetic adversarial fixtures for release-tool, appcast, Python and env trust
# boundaries. This script performs no network, signing, Keychain or publish I/O.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TMP_ROOT=$(/usr/bin/mktemp -d /private/tmp/maccrab-release-supply.XXXXXX)
trap '/bin/rm -rf "$TMP_ROOT"' EXIT

pass_count=0
pass() { pass_count=$((pass_count + 1)); echo "  ✓ $*"; }
expect_failure() {
    local label="$1"
    shift
    if "$@" >"$TMP_ROOT/failure.out" 2>&1; then
        echo "  ✗ $label unexpectedly succeeded" >&2
        exit 1
    fi
    pass "$label"
}

echo "Release environment parser"
VERSION_VALIDATOR="$TMP_ROOT/version-validation.sh"
# Exercise only the ordinary data validator, never any build/sign stage.
/usr/bin/sed -n '/^validate_build_number() {$/,/^}$/p' \
    "$SCRIPT_DIR/build-release.sh" > "$VERSION_VALIDATOR"
[[ -s "$VERSION_VALIDATOR" ]] || { echo "missing build identity validator" >&2; exit 1; }
printf '\nvalidate_build_number\n' >> "$VERSION_VALIDATOR"
VERSION=1.22.0-rc.2 BUILD_NUMBER=1.22.0.1121 /bin/bash "$VERSION_VALIDATOR"
VERSION=1.22.0 BUILD_NUMBER=1.22.0.1122 /bin/bash "$VERSION_VALIDATOR"
expect_failure "RC marketing suffix is forbidden in the numeric build identity" \
    /usr/bin/env VERSION=1.22.0-rc.2 BUILD_NUMBER=1.22.0-rc.2.1121 /bin/bash "$VERSION_VALIDATOR"
expect_failure "numeric build must match the marketing version's base" \
    /usr/bin/env VERSION=1.22.0-rc.2 BUILD_NUMBER=1.21.5.1121 /bin/bash "$VERSION_VALIDATOR"
expect_failure "numeric build revision must be positive" \
    /usr/bin/env VERSION=1.22.0-rc.2 BUILD_NUMBER=1.22.0.0 /bin/bash "$VERSION_VALIDATOR"
pass "RC and GA share the validated numeric build sequence"

STAGE_VERSION_ENV="$TMP_ROOT/version-stage.env"
printf 'VERSION=1.22.0-rc.2\nBUILD_NUMBER=1.22.0.1121\n' > "$STAGE_VERSION_ENV"
/bin/chmod 0600 "$STAGE_VERSION_ENV"
/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_release_env.py" --profile stage "$STAGE_VERSION_ENV" >/dev/null
printf 'VERSION=1.22.0-rc.2\nBUILD_NUMBER=1.22.0-rc.2.1121\n' > "$STAGE_VERSION_ENV"
expect_failure "persisted stage identity rejects an RC suffix in CFBundleVersion" \
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_release_env.py" --profile stage "$STAGE_VERSION_ENV"

GOOD_ENV="$TMP_ROOT/release.env"
printf '%s\n' \
    'export DEVELOPER_ID="Developer ID Application: Test (ABCDEFGHIJ)"' \
    'APPLE_ID=test@example.com' \
    'APPLE_TEAM_ID=ABCDEFGHIJ' \
    'NOTARIZE_PASSWORD=abcd-efgh-ijkl' \
    'NOTARIZE_KEYCHAIN_PROFILE=fixture-profile' \
    'SITE_REPO_TOKEN=github_pat_site_fixture' \
    'TAP_REPO_TOKEN=github_pat_tap_fixture' \
    'GH_TOKEN=github_pat_release_fixture' > "$GOOD_ENV"
/bin/chmod 0600 "$GOOD_ENV"
/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_release_env.py" --profile release "$GOOD_ENV" >/dev/null
pass "mode-0600 allowlisted KEY=VALUE data accepted"

/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_release_env.py" --profile signing "$GOOD_ENV" \
    > "$TMP_ROOT/signing.env0"
/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_release_env.py" --profile publisher "$GOOD_ENV" \
    > "$TMP_ROOT/publisher.env0"
/usr/bin/tr '\0' '\n' < "$TMP_ROOT/signing.env0" > "$TMP_ROOT/signing.lines"
/usr/bin/tr '\0' '\n' < "$TMP_ROOT/publisher.env0" > "$TMP_ROOT/publisher.lines"
/usr/bin/grep -qx 'DEVELOPER_ID' "$TMP_ROOT/signing.lines"
/usr/bin/grep -qx 'NOTARIZE_PASSWORD' "$TMP_ROOT/signing.lines"
if /usr/bin/grep -qE '^(GH_TOKEN|SITE_REPO_TOKEN|TAP_REPO_TOKEN)$' "$TMP_ROOT/signing.lines"; then
    echo "  ✗ signing projection imported publisher credentials" >&2
    exit 1
fi
/usr/bin/grep -qx 'GH_TOKEN' "$TMP_ROOT/publisher.lines"
/usr/bin/grep -qx 'SITE_REPO_TOKEN' "$TMP_ROOT/publisher.lines"
/usr/bin/grep -qx 'TAP_REPO_TOKEN' "$TMP_ROOT/publisher.lines"
if /usr/bin/grep -qE '^(DEVELOPER_ID|APPLE_ID|APPLE_TEAM_ID|NOTARIZE_PASSWORD|NOTARIZE_KEYCHAIN_PROFILE)$' \
        "$TMP_ROOT/publisher.lines"; then
    echo "  ✗ publisher projection imported signing credentials" >&2
    exit 1
fi
pass "signing and publisher profiles expose disjoint least-privilege projections"

/bin/chmod 0644 "$GOOD_ENV"
expect_failure "group/other-readable credential file rejected" \
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_release_env.py" --profile release "$GOOD_ENV"
/bin/chmod 0600 "$GOOD_ENV"
/bin/ln -s "$GOOD_ENV" "$TMP_ROOT/release-link.env"
expect_failure "credential-file symlink rejected" \
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_release_env.py" --profile release "$TMP_ROOT/release-link.env"

PWN_MARKER="$TMP_ROOT/should-not-exist"
printf 'DEVELOPER_ID=$(touch %s)\n' "$PWN_MARKER" > "$GOOD_ENV"
/bin/chmod 0600 "$GOOD_ENV"
expect_failure "shell command substitution rejected as data" \
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_release_env.py" --profile release "$GOOD_ENV"
[[ ! -e "$PWN_MARKER" ]] || { echo "  ✗ env parser executed shell text" >&2; exit 1; }
printf 'PATH=/attacker/bin\n' > "$GOOD_ENV"
expect_failure "non-allowlisted environment key rejected" \
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$SCRIPT_DIR/_release_env.py" --profile release "$GOOD_ENV"

echo "Hash-locked PyYAML staging"
PY_ROOT="$TMP_ROOT/pydeps"
"$SCRIPT_DIR/prepare-release-pyyaml.sh" "$PY_ROOT" >/dev/null
"$SCRIPT_DIR/check-release-pyyaml.sh" "$PY_ROOT" >/dev/null
pass "user-site source copied without import and re-hashed in private staging"
printf '\n# tamper\n' >> "$PY_ROOT/yaml/loader.py"
expect_failure "staged PyYAML mutation rejected" "$SCRIPT_DIR/check-release-pyyaml.sh" "$PY_ROOT"

echo "Exact tracked-only source export"
EXPORT_REPO="$TMP_ROOT/export-repo"
EXPORT_DEST="$TMP_ROOT/export-destination"
/bin/mkdir -p "$EXPORT_REPO/nested/private-input" "$EXPORT_REPO/.swiftpm/configuration" "$EXPORT_DEST"
/bin/chmod 0700 "$EXPORT_DEST"
printf '.swiftpm/\nnested/private-input/\n' > "$EXPORT_REPO/.gitignore"
printf 'committed bytes\n' > "$EXPORT_REPO/tracked.txt"
printf '#!/bin/bash\nexit 0\n' > "$EXPORT_REPO/run.sh"
/bin/chmod 0755 "$EXPORT_REPO/run.sh"
printf 'ignored registry poison\n' > "$EXPORT_REPO/.swiftpm/configuration/registries.json"
printf 'ignored nested poison\n' > "$EXPORT_REPO/nested/private-input/poison.yml"
(
    cd "$EXPORT_REPO"
    /usr/bin/git init -q
    /usr/bin/git config user.name 'MacCrab export fixture'
    /usr/bin/git config user.email 'export@invalid.example'
    /usr/bin/git config core.hooksPath .no-hooks
    /usr/bin/git add .gitignore tracked.txt run.sh
    /usr/bin/git commit -q -m root
)
EXPORT_COMMIT=$(/usr/bin/git -C "$EXPORT_REPO" rev-parse HEAD)
REPLACEMENT_BLOB=$(printf 'replacement-ref bytes\n' \
    | /usr/bin/git -C "$EXPORT_REPO" hash-object -w --stdin)
REPLACEMENT_INDEX="$TMP_ROOT/replacement.index"
GIT_INDEX_FILE="$REPLACEMENT_INDEX" /usr/bin/git -C "$EXPORT_REPO" read-tree "$EXPORT_COMMIT"
GIT_INDEX_FILE="$REPLACEMENT_INDEX" /usr/bin/git -C "$EXPORT_REPO" update-index \
    --cacheinfo "100644,$REPLACEMENT_BLOB,tracked.txt"
REPLACEMENT_TREE=$(GIT_INDEX_FILE="$REPLACEMENT_INDEX" \
    /usr/bin/git -C "$EXPORT_REPO" write-tree)
REPLACEMENT_COMMIT=$(printf 'replacement commit\n' \
    | /usr/bin/git -C "$EXPORT_REPO" commit-tree "$REPLACEMENT_TREE")
/usr/bin/git -C "$EXPORT_REPO" replace "$EXPORT_COMMIT" "$REPLACEMENT_COMMIT"
printf 'live worktree mutation\n' > "$EXPORT_REPO/tracked.txt"
GIT_DIR=/attacker/repository GIT_OBJECT_DIRECTORY=/attacker/objects \
    /usr/bin/python3 -I "$SCRIPT_DIR/export-release-source.py" \
    --repo "$EXPORT_REPO" --commit "$EXPORT_COMMIT" --destination "$EXPORT_DEST" >/dev/null
[ "$(cat "$EXPORT_DEST/tracked.txt")" = "committed bytes" ] \
    || { echo "  ✗ export used live worktree bytes" >&2; exit 1; }
[ -x "$EXPORT_DEST/run.sh" ] \
    || { echo "  ✗ export did not preserve committed executable mode" >&2; exit 1; }
[ ! -e "$EXPORT_DEST/.git" ] && [ ! -e "$EXPORT_DEST/.swiftpm" ] \
    && [ ! -e "$EXPORT_DEST/nested/private-input/poison.yml" ] \
    || { echo "  ✗ export admitted Git, SwiftPM, or ignored nested input" >&2; exit 1; }
pass "Git-object export ignored replacement/ambient Git state, live bytes, and ignored inputs"

echo "Locked Sparkle tools + appcast XML"
FIXTURE="$TMP_ROOT/fixture-repo"
/bin/mkdir -p "$FIXTURE/scripts" "$FIXTURE/Xcode" \
    "$FIXTURE/.build/checkouts/Sparkle" \
    "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin"
/bin/cp "$SCRIPT_DIR/generate-appcast-entry.sh" \
    "$SCRIPT_DIR/check-release-dependencies.sh" \
    "$SCRIPT_DIR/_appcast_xml.py" \
    "$SCRIPT_DIR/_md_to_html.py" \
    "$FIXTURE/scripts/"

cat > "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin/sign_update" <<'TOOL'
#!/bin/bash
set -euo pipefail
if [[ -n "${SITE_REPO_TOKEN+x}${GH_TOKEN+x}${NOTARIZE_PASSWORD+x}${PYTHONPATH+x}${DYLD_INSERT_LIBRARIES+x}" ]]; then
    echo "release secret leaked to sign_update" >&2
    exit 90
fi
marker="$(dirname "$0")/sign-update-ran"
: > "$marker"
if [[ "${1:-}" == "--verify" ]]; then exit 0; fi
length=$(/usr/bin/stat -f%z "$1")
signature=$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -c 'import base64; print(base64.b64encode(bytes(64)).decode())')
printf 'sparkle:edSignature="%s" length="%s"\n' "$signature" "$length"
TOOL
cat > "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin/generate_keys" <<'TOOL'
#!/bin/bash
set -euo pipefail
if [[ -n "${SITE_REPO_TOKEN+x}${GH_TOKEN+x}${NOTARIZE_PASSWORD+x}${PYTHONPATH+x}${DYLD_INSERT_LIBRARIES+x}" ]]; then
    echo "release secret leaked to generate_keys" >&2
    exit 90
fi
printf '%s\n' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
TOOL
/bin/chmod 0755 "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin/sign_update" \
    "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin/generate_keys"
sign_hash=$(/usr/bin/shasum -a 256 "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin/sign_update" | /usr/bin/awk '{print $1}')
keys_hash=$(/usr/bin/shasum -a 256 "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin/generate_keys" | /usr/bin/awk '{print $1}')
cat > "$FIXTURE/scripts/release-dependencies.lock" <<LOCK
format_version=1
sparkle_version=2.9.6
sparkle_revision=ac2def288cbff5cfc7df3ffef6abdf45b72bcb0a
sparkle_binary_artifact_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sparkle_sign_update_sha256=$sign_hash
sparkle_generate_keys_sha256=$keys_hash
pyyaml_version=6.0.3
pyyaml_file_count=17
LOCK
cat > "$FIXTURE/Package.swift" <<'SWIFT'
let packages = [
    .package(
        url: "https://github.com/sparkle-project/Sparkle",
        exact: "2.9.6"
    )
]
SWIFT
cat > "$FIXTURE/Package.resolved" <<'JSON'
{"pins":[{"identity":"sparkle","kind":"remoteSourceControl","location":"https://github.com/sparkle-project/Sparkle","state":{"revision":"ac2def288cbff5cfc7df3ffef6abdf45b72bcb0a","version":"2.9.6"}}],"version":2}
JSON
cat > "$FIXTURE/.build/checkouts/Sparkle/Package.swift" <<'SWIFT'
let version = "2.9.6"
let checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SWIFT
cat > "$FIXTURE/Xcode/project.yml" <<'YML'
settings:
  SUPublicEDKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
YML

DMG="$FIXTURE/MacCrab-v1.2.3.dmg"
NOTES="$FIXTURE/notes.md"
printf 'fixture-dmg-bytes' > "$DMG"
printf '# Notes\n\nBefore ]]> after.\n' > "$NOTES"
SITE_REPO_TOKEN=must_not_leak NOTARIZE_PASSWORD=must_not_leak PYTHONPATH=/attacker \
    "$FIXTURE/scripts/generate-appcast-entry.sh" \
    --dmg "$DMG" --version 1.2.3 --build-number 1.2.3.42 \
    --release-notes-md "$NOTES" --phased-rollout-interval 60 \
    > "$FIXTURE/item.xml"
/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$FIXTURE/scripts/_appcast_xml.py" validate-item \
    --item "$FIXTURE/item.xml" --expected-version 1.2.3 --expected-build 1.2.3.42 >/dev/null
pass "checked fixture tools ran with release secrets stripped and emitted valid XML"

/bin/rm -f "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin/sign-update-ran"
printf '\n# substituted\n' >> "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin/sign_update"
expect_failure "substituted Sparkle tool rejected before execution" \
    "$FIXTURE/scripts/generate-appcast-entry.sh" \
    --dmg "$DMG" --version 1.2.3 --build-number 1.2.3.43 \
    --release-notes-md "$NOTES" --immediate
[[ ! -e "$FIXTURE/.build/artifacts/sparkle/Sparkle/bin/sign-update-ran" ]] || {
    echo "  ✗ tampered tool executed before provenance check" >&2; exit 1;
}

SIG=$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -c 'import base64; print(base64.b64encode(bytes(64)).decode())')
printf '%s' '<p>before ]]><evil/> after</p>' > "$FIXTURE/raw-notes.html"
/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$FIXTURE/scripts/_appcast_xml.py" generate \
    --version 1.2.3 --build-number 1.2.3.44 \
    --pub-date 'Sun, 02 Aug 2026 12:00:00 +0000' \
    --signature "$SIG" --length 17 --dmg-name MacCrab-v1.2.3.dmg \
    --notes-file "$FIXTURE/raw-notes.html" > "$FIXTURE/cdata-item.xml"
/usr/bin/grep -qF ']]]]><![CDATA[>' "$FIXTURE/cdata-item.xml" || {
    echo "  ✗ CDATA terminator was not split" >&2; exit 1;
}
pass "malicious CDATA terminator split and namespace-wrapped item parsed"

/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I - "$FIXTURE/scripts/_appcast_xml.py" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location('appcast_version_fixture', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
key = module.build_sort_key
# Pinned Sparkle ignores the dash suffix and balances numeric trailing zeros.
assert key('1.22.0-rc.1.1120') == key('1.22.0')
assert key('1.22.0.0') == key('1.22.0')
assert key('1.22.0-rc.1.1120') < key('1.22.0.1119')
assert key('1.22.0.1119') < key('1.22.0.1121') < key('1.22.0.1122')
assert key('1.22.0.9999') < key('1.22.1.1')
assert not module.BUILD_RE.fullmatch('1.22.0-rc.2.1121')
assert module.BUILD_RE.fullmatch('1.22.0.1121')
PY
pass "appcast ordering matches Sparkle for numeric and historical RC identities"

/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$FIXTURE/scripts/_appcast_xml.py" generate \
    --version 1.22.0-rc.2 --build-number 1.22.0.1121 \
    --pub-date 'Sun, 02 Aug 2026 12:00:00 +0000' \
    --signature "$SIG" --length 17 --dmg-name MacCrab-v1.22.0-rc.2.dmg \
    --notes-file "$FIXTURE/raw-notes.html" > "$FIXTURE/rc-item.xml"
/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$FIXTURE/scripts/_appcast_xml.py" validate-item \
    --item "$FIXTURE/rc-item.xml" --expected-version 1.22.0-rc.2 --expected-build 1.22.0.1121 >/dev/null
expect_failure "appcast producer rejects a nonnumeric RC build" \
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$FIXTURE/scripts/_appcast_xml.py" generate \
    --version 1.22.0-rc.2 --build-number 1.22.0-rc.2.1121 \
    --pub-date 'Sun, 02 Aug 2026 12:00:00 +0000' \
    --signature "$SIG" --length 17 --dmg-name MacCrab-v1.22.0-rc.2.dmg \
    --notes-file "$FIXTURE/raw-notes.html"
pass "appcast keeps RC marketing version separate from numeric build"

cat > "$FIXTURE/feed.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel><title>MacCrab</title><description>Updates</description><language>en</language></channel>
</rss>
XML
/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$FIXTURE/scripts/_appcast_xml.py" inject \
    --item "$FIXTURE/cdata-item.xml" --current "$FIXTURE/feed.xml" \
    --output "$FIXTURE/new-feed.xml" --expected-version 1.2.3 --expected-build 1.2.3.44
expect_failure "duplicate Sparkle build identity rejected" \
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$FIXTURE/scripts/_appcast_xml.py" inject \
    --item "$FIXTURE/cdata-item.xml" --current "$FIXTURE/new-feed.xml" \
    --output "$FIXTURE/duplicate.xml" --expected-version 1.2.3 --expected-build 1.2.3.44

printf '%s' '<!DOCTYPE item [<!ENTITY x SYSTEM "file:///etc/passwd">]><item>&x;</item>' > "$FIXTURE/xxe.xml"
expect_failure "DOCTYPE/entity item rejected before publisher network boundary" \
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C \
    /usr/bin/python3 -I "$FIXTURE/scripts/_appcast_xml.py" validate-item --item "$FIXTURE/xxe.xml"
expect_failure "publisher rejects malformed item before any curl" \
    /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp LC_ALL=C SITE_REPO_TOKEN=fixturetoken \
    "$SCRIPT_DIR/publish-appcast-entry.sh" --item "$FIXTURE/xxe.xml" \
    --site-repo owner/repo --version 1.2.3

echo "Static drift guards"
for file in "$PROJECT_DIR/scripts/build-release.sh" "$PROJECT_DIR/scripts/release.sh"; do
    if /usr/bin/grep -qE 'source[[:space:]]+"?\$(ENV_FILE|STAGE_ENV)' "$file"; then
        echo "  ✗ external env file is shell-sourced in $file" >&2
        exit 1
    fi
done
if /usr/bin/grep -qE '\$\{HOME\}/Tools|"/opt/homebrew/bin"|"/usr/local/bin"|^[[:space:]]*--sparkle-bin\)|ALLOW_UNPAIRED_SPARKLE' \
        "$PROJECT_DIR/scripts/generate-appcast-entry.sh"; then
    echo "  ✗ unsafe Sparkle tool discovery/override returned" >&2
    exit 1
fi
if /usr/bin/grep -nE '(^|[^/A-Za-z0-9_-])python3([[:space:]]|$)' \
        "$PROJECT_DIR/scripts/build-release.sh" "$PROJECT_DIR/scripts/release.sh"; then
    echo "  ✗ bare Python returned to build/release scripts" >&2
    exit 1
fi
/usr/bin/grep -q 'check-release-dependencies.sh' "$PROJECT_DIR/scripts/generate-appcast-entry.sh"
/usr/bin/grep -q 'run-release-python.sh' "$PROJECT_DIR/scripts/build-release.sh"
/usr/bin/grep -q 'load_maccrab_env_file stage' "$PROJECT_DIR/scripts/build-release.sh"
if /usr/bin/grep -q 'load_maccrab_env_file release' \
        "$PROJECT_DIR/scripts/build-release.sh" "$PROJECT_DIR/scripts/release.sh"; then
    echo "  ✗ build/release flow imported the combined credential profile" >&2
    exit 1
fi
/usr/bin/grep -q 'load_maccrab_env_file signing' "$PROJECT_DIR/scripts/build-release.sh"
/usr/bin/grep -q 'load_maccrab_env_file publisher' "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'decode-github-response' "$PROJECT_DIR/scripts/publish-appcast-entry.sh"
/usr/bin/grep -q 'run_xml_helper inject' "$PROJECT_DIR/scripts/publish-appcast-entry.sh"

if /usr/bin/grep -qE -- '-X[[:space:]]+DELETE|--method[=[:space:]]+DELETE|release[[:space:]]+delete|delete_owned_draft' \
        "$PROJECT_DIR/scripts/release.sh"; then
    echo "  ✗ automatic GitHub release deletion returned" >&2
    exit 1
fi
if ! /usr/bin/grep -q 'MANUAL RECOVERY REQUIRED: retained GitHub release ID' \
        "$PROJECT_DIR/scripts/release.sh"; then
    echo "  ✗ failed/ambiguous drafts lack an immutable-ID manual recovery path" >&2
    exit 1
fi
if /usr/bin/grep -qE 'gh[[:space:]]+release[[:space:]]+create' \
        "$PROJECT_DIR/scripts/build-release.sh"; then
    echo "  ✗ build-only helper recommends bypassing the qualified release flow" >&2
    exit 1
fi
/usr/bin/grep -q 'do not tag, push, or publish this artifact directly' \
    "$PROJECT_DIR/scripts/build-release.sh" \
    || { echo "  ✗ build-only helper lacks explicit no-publication guidance" >&2; exit 1; }
/usr/bin/grep -q "scripts/release.sh's two-phase qualification flow" \
    "$PROJECT_DIR/scripts/build-release.sh" \
    || { echo "  ✗ build-only helper does not route operators to qualification" >&2; exit 1; }

for fixed_assignment in \
        'GIT_BIN=/usr/bin/git' \
        'SHASUM_BIN=/usr/bin/shasum' \
        'GH_BIN=/opt/homebrew/bin/gh' \
        'CODESIGN_BIN=/usr/bin/codesign' \
        'SWIFT_BIN=/usr/bin/swift'; do
    /usr/bin/grep -q "$fixed_assignment" \
        "$PROJECT_DIR/scripts/release.sh" "$PROJECT_DIR/scripts/build-release.sh" \
        "$PROJECT_DIR/scripts/ci-local.sh" "$PROJECT_DIR/.githooks/pre-push" \
        || { echo "  ✗ fixed critical tool assignment missing: $fixed_assignment" >&2; exit 1; }
done
/usr/bin/grep -q 'CANONICAL_GH_REPO=peterhanily/maccrab' "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'CANONICAL_GH_HOST=github.com' "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'unset GH_REPO GH_HOST' "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'GIT_INDEX_FILE GIT_OBJECT_DIRECTORY' \
    "$PROJECT_DIR/scripts/release.sh"
if /usr/bin/grep -q '{owner}/{repo}' "$PROJECT_DIR/scripts/release.sh"; then
    echo "  ✗ mutable GitHub owner/repo placeholder returned" >&2
    exit 1
fi

/usr/bin/grep -q 'if ! \$CODESIGN_BIN --verify --deep --strict' "$PROJECT_DIR/scripts/build-release.sh" \
    || { echo "  ✗ codesign verification is not a blocking conditional" >&2; exit 1; }
if /usr/bin/grep -qE 'codesign[^#]*--verify[^#]*\|\|[[:space:]]*true|CODESIGN_BIN[^#]*--verify[^#]*\|\|[[:space:]]*true' \
        "$PROJECT_DIR/scripts/build-release.sh"; then
    echo "  ✗ codesign verification failure is swallowed" >&2
    exit 1
fi
if /usr/bin/grep -qE 'MacCrabTools\.entitlements|TOOLS_ENT=' \
        "$PROJECT_DIR/scripts/build-release.sh" "$PROJECT_DIR/scripts/release.sh"; then
    echo "  ✗ provisioning-profile-bound entitlement input returned for bare tools" >&2
    exit 1
fi
if ! /usr/bin/grep -Fq 'strip -S -x "$STAGING_DIR/bin/$binary"' \
        "$PROJECT_DIR/scripts/build-release.sh"; then
    echo "  ✗ release binaries do not remove local symbols before signing" >&2
    exit 1
fi
if /usr/bin/grep -E 'strip -S -x .*\|\|[[:space:]]*true' \
        "$PROJECT_DIR/scripts/build-release.sh" >/dev/null; then
    echo "  ✗ release symbol-strip failure is swallowed" >&2
    exit 1
fi
for footprint_marker in \
        'APP_FOOTPRINT_BUDGET_KIB=184320' \
        'APP_FOOTPRINT_KIB=$(/usr/bin/du -sk "$APP" | /usr/bin/cut -f1)' \
        'APP_FOOTPRINT_KIB" -gt "$APP_FOOTPRINT_BUDGET_KIB'; do
    /usr/bin/grep -Fq "$footprint_marker" "$PROJECT_DIR/scripts/build-release.sh" \
        || { echo "  ✗ installed-app footprint release gate is incomplete" >&2; exit 1; }
done
[ "$(/usr/bin/grep -cF 'verify_bare_tool_runtime "$APP" "post-sign"' \
        "$PROJECT_DIR/scripts/build-release.sh")" = 1 ] \
    || { echo "  ✗ signed-app bare-tool execution probe is missing or duplicated" >&2; exit 1; }
[ "$(/usr/bin/grep -cF 'verify_bare_tool_runtime "$DMG_MNT/MacCrab.app" "mounted-DMG"' \
        "$PROJECT_DIR/scripts/build-release.sh")" = 1 ] \
    || { echo "  ✗ mounted-DMG bare-tool execution probe is missing or duplicated" >&2; exit 1; }
if /usr/bin/grep -E 'verify_bare_tool_runtime .*\|\|[[:space:]]*true' \
        "$PROJECT_DIR/scripts/build-release.sh" >/dev/null; then
    echo "  ✗ bare-tool execution probe failure is swallowed" >&2
    exit 1
fi

for binding_marker in \
        'SOURCE_COMMIT=' \
        'SOURCE_TREE=' \
        'METADATA_TREE=' \
        'GIT_INDEX_FILE=' \
        'commit-tree' \
        'update-ref' \
        'MACCRAB_RELEASE_SOURCE_COMMIT' \
        'MACCRAB_RELEASE_METADATA_TREE'; do
    /usr/bin/grep -q "$binding_marker" "$PROJECT_DIR/scripts/release.sh" \
        "$PROJECT_DIR/scripts/ci-local.sh" "$PROJECT_DIR/.githooks/pre-push" \
        || { echo "  ✗ source/tree binding marker missing: $binding_marker" >&2; exit 1; }
done
if /usr/bin/grep -qE '^[[:space:]]*(git|\$GIT_BIN)[[:space:]]+commit[[:space:]]' \
        "$PROJECT_DIR/scripts/release.sh"; then
    echo "  ✗ extensible porcelain commit returned to release.sh" >&2
    exit 1
fi
if /usr/bin/grep -qE 'GIT_INDEX_FILE=.*\$GIT_BIN[[:space:]]+add' \
        "$PROJECT_DIR/scripts/release.sh"; then
    echo "  ✗ metadata tree construction returned to filter-aware git add" >&2
    exit 1
fi
/usr/bin/grep -q 'hash-object -w --no-filters' "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q -- '-c core.hooksPath=/dev/null update-ref' \
    "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'export-release-source.py' "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'tracked-git-object-export' "$PROJECT_DIR/scripts/build-release.sh"
/usr/bin/grep -q 'reclaim_clean_ci_architecture_products' "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'minimum_release_free_kib' "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'Last 200 build-log lines' "$PROJECT_DIR/scripts/build-release.sh"
/usr/bin/grep -q 'repository-local SwiftPM configuration must not be a release input' \
    "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'Tools/AssessmentHarness/.build' "$PROJECT_DIR/scripts/ci-local.sh"
/usr/bin/grep -q '^SWT_EXPERIMENTAL_MAXIMUM_PARALLELIZATION_WIDTH=1$' \
    "$PROJECT_DIR/scripts/ci-local.sh" \
    || { echo "  ✗ local CI no longer bounds Swift Testing concurrency" >&2; exit 1; }
/usr/bin/grep -q 'check "Swift test suite" swift test --no-parallel' \
    "$PROJECT_DIR/scripts/ci-local.sh" \
    || { echo "  ✗ local CI no longer explicitly serializes Swift Testing" >&2; exit 1; }

for evidence_marker in \
        provisioning_profile_sha256 \
        xcode_toolchain \
        swift_toolchain \
        pyyaml_manifest_sha256 \
        core_npm_bundled_sha256 \
        release_input_attestation_sha256; do
    /usr/bin/grep -q "$evidence_marker" "$PROJECT_DIR/scripts/build-release.sh" \
        || { echo "  ✗ release input evidence missing: $evidence_marker" >&2; exit 1; }
done
/usr/bin/grep -q 'Required tracked resource bundle was not produced' \
    "$PROJECT_DIR/scripts/build-release.sh"
/usr/bin/grep -q -- '--dmg "\$UPLOAD_SNAPSHOT"' "$PROJECT_DIR/scripts/release.sh"
/usr/bin/grep -q 'BUILD_WORKSPACE/scripts/generate-appcast-entry.sh' \
    "$PROJECT_DIR/scripts/release.sh"

extract_executor_list() {
    /usr/bin/awk '
        /BEGIN RELEASE_CRITICAL_EXECUTORS/ { inside=1; next }
        /END RELEASE_CRITICAL_EXECUTORS/ { inside=0 }
        inside && $1 ~ /^(\.|scripts\/|Compiler\/)/ { print $1 }
    ' "$1"
}
EXECUTOR_BASELINE="$TMP_ROOT/executors.release"
extract_executor_list "$PROJECT_DIR/scripts/release.sh" > "$EXECUTOR_BASELINE"
for executor_surface in \
        "$PROJECT_DIR/scripts/ci-local.sh" \
        "$PROJECT_DIR/.githooks/pre-push" \
        "$PROJECT_DIR/scripts/test-release-artifact-preservation.sh"; do
    extract_executor_list "$executor_surface" > "$TMP_ROOT/executors.compare"
    /usr/bin/cmp -s "$EXECUTOR_BASELINE" "$TMP_ROOT/executors.compare" \
        || { echo "  ✗ critical executor list drifted: $executor_surface" >&2; exit 1; }
done
[ "$(/usr/bin/wc -l < "$EXECUTOR_BASELINE" | /usr/bin/tr -d ' ')" -ge 18 ] \
    || { echo "  ✗ critical executor list is unexpectedly incomplete" >&2; exit 1; }
pass "release source retains all provenance/isolation/parse boundaries"

echo "PASS: $pass_count release supply-chain adversarial checks"
