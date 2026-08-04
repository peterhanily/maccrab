#!/bin/bash
# Hermetic installer/DMG-layout regression fixtures.  No sudo, Keychain,
# mounted image, /Applications, or support-directory access.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TMP_ROOT=$(/usr/bin/mktemp -d /private/tmp/maccrab-install-payload.XXXXXX)
trap '/bin/rm -rf "$TMP_ROOT"' EXIT

fail() { echo "  ✗ $*" >&2; exit 1; }
pass() { echo "  ✓ $*"; }

write_fixture_manifest() {
    local root="$1"
    local version="$2"
    printf '%s\n' "$version" > "$root/.bundle_version"
    (
        cd "$root"
        {
            printf '{\n'
            printf '  "schema_version": 1,\n'
            printf '  "bundle_version": "%s",\n' "$version"
            printf '  "hashes": {\n'
            /usr/bin/find . -type f ! -name manifest.json ! -name .bundle_version \
                | /usr/bin/sort \
                | while IFS= read -r file; do
                    relative=${file#./}
                    digest=$(/usr/bin/shasum -a 256 "$file" | /usr/bin/awk '{print $1}')
                    printf '    "%s": "%s",\n' "$relative" "$digest"
                done \
                | /usr/bin/sed '$ s/,$//'
            printf '  }\n'
            printf '}\n'
        } > manifest.json
    )
}

# Sourcing exposes only the pure layout/mode helpers; the destructive installer
# body is guarded by BASH_SOURCE[0] == $0.
# shellcheck source=scripts/install.sh
source "$SCRIPT_DIR/install.sh"

REPO_FIXTURE="$TMP_ROOT/repo"
DMG_FIXTURE="$TMP_ROOT/MacCrab v9.9.9"
/bin/mkdir -p "$REPO_FIXTURE/scripts" \
    "$DMG_FIXTURE/MacCrab.app/Contents/Resources/compiled_rules"
printf '// fixture\n' > "$REPO_FIXTURE/Package.swift"
printf 'fixture plist\n' > "$DMG_FIXTURE/MacCrab.app/Contents/Info.plist"
printf 'fixture\n' > "$DMG_FIXTURE/MacCrab.app/Contents/Resources/compiled_rules/rule.json"
write_fixture_manifest \
    "$DMG_FIXTURE/MacCrab.app/Contents/Resources/compiled_rules" "9.9.9"

[ "$(maccrab_resolve_payload_root "$REPO_FIXTURE/scripts")" = "$REPO_FIXTURE" ] \
    || fail "repo/scripts layout did not resolve to the repository root"
[ "$(maccrab_resolve_payload_root "$DMG_FIXTURE")" = "$DMG_FIXTURE" ] \
    || fail "DMG-root install.sh layout did not resolve to the mount root"
pass "repo and DMG roots resolve deterministically"

MODE_APP="$TMP_ROOT/mode/MacCrab.app"
/bin/mkdir -p "$MODE_APP/Contents/MacOS" \
    "$MODE_APP/Contents/Resources/bin" \
    "$MODE_APP/Contents/Resources/data" \
    "$MODE_APP/Contents/Library/SystemExtensions/test.systemextension/Contents/MacOS"
printf 'main\n' > "$MODE_APP/Contents/MacOS/MacCrab"
printf 'cli\n' > "$MODE_APP/Contents/Resources/bin/maccrabctl"
printf 'resource\n' > "$MODE_APP/Contents/Resources/data/rules.json"
printf 'agent\n' > "$MODE_APP/Contents/Library/SystemExtensions/test.systemextension/Contents/MacOS/agent"
/bin/chmod 0700 "$MODE_APP/Contents/MacOS/MacCrab" \
    "$MODE_APP/Contents/Resources/bin/maccrabctl" \
    "$MODE_APP/Contents/Library/SystemExtensions/test.systemextension/Contents/MacOS/agent"
/bin/chmod 0600 "$MODE_APP/Contents/Resources/data/rules.json"
/bin/chmod +a 'everyone allow read' "$MODE_APP/Contents/Resources/data/rules.json"
/usr/bin/chflags uchg "$MODE_APP/Contents/Resources/data/rules.json"
maccrab_normalize_app_modes "$MODE_APP"

[ "$(/usr/bin/stat -f '%Lp' "$MODE_APP/Contents/MacOS/MacCrab")" = 755 ] \
    || fail "main app executable was not normalized to 0755"
[ "$(/usr/bin/stat -f '%Lp' "$MODE_APP/Contents/Resources/bin/maccrabctl")" = 755 ] \
    || fail "bundled CLI was not normalized to 0755"
[ "$(/usr/bin/stat -f '%Lp' "$MODE_APP/Contents/Library/SystemExtensions/test.systemextension/Contents/MacOS/agent")" = 755 ] \
    || fail "system-extension executable was not made traversable/executable"
[ "$(/usr/bin/stat -f '%Lp' "$MODE_APP/Contents/Resources/data/rules.json")" = 644 ] \
    || fail "ordinary app resource was not normalized to 0644"
if /bin/ls -lde "$MODE_APP/Contents/Resources/data/rules.json" \
        | /usr/bin/grep -E '^[[:space:]][[:digit:]]+: ' >/dev/null; then
    fail "manual installer mode helper retained a resource ACL"
fi
if /usr/bin/find "$MODE_APP/Contents/Resources/data/rules.json" -flags +uchg \
        -print | /usr/bin/grep . >/dev/null; then
    fail "manual installer mode helper retained an immutable resource flag"
fi
pass "sudo-installed app remains readable and executable by non-root users"

for linked_entry in main cli sysext; do
    LINK_APP="$TMP_ROOT/link-$linked_entry/MacCrab.app"
    LINK_TARGET="$TMP_ROOT/link-$linked_entry/attacker-target"
    /bin/mkdir -p "$LINK_APP/Contents/MacOS" \
        "$LINK_APP/Contents/Resources/bin" \
        "$LINK_APP/Contents/Library/SystemExtensions/test.systemextension/Contents/MacOS"
    printf 'main\n' > "$LINK_APP/Contents/MacOS/MacCrab"
    printf 'cli\n' > "$LINK_APP/Contents/Resources/bin/maccrabctl"
    printf 'agent\n' \
        > "$LINK_APP/Contents/Library/SystemExtensions/test.systemextension/Contents/MacOS/agent"
    printf 'outside payload\n' > "$LINK_TARGET"
    /bin/chmod 0600 "$LINK_TARGET"
    case "$linked_entry" in
        main)
            /bin/rm "$LINK_APP/Contents/MacOS/MacCrab"
            /bin/ln -s "$LINK_TARGET" "$LINK_APP/Contents/MacOS/MacCrab"
            ;;
        cli)
            /bin/rm "$LINK_APP/Contents/Resources/bin/maccrabctl"
            /bin/ln -s "$LINK_TARGET" "$LINK_APP/Contents/Resources/bin/maccrabctl"
            ;;
        sysext)
            /bin/rm "$LINK_APP/Contents/Library/SystemExtensions/test.systemextension/Contents/MacOS/agent"
            /bin/ln -s "$LINK_TARGET" \
                "$LINK_APP/Contents/Library/SystemExtensions/test.systemextension/Contents/MacOS/agent"
            ;;
    esac
    if maccrab_normalize_app_modes "$LINK_APP"; then
        fail "installer mode helper accepted a linked $linked_entry executable"
    fi
    [ "$(/usr/bin/stat -f '%Lp' "$LINK_TARGET")" = 600 ] \
        || fail "installer chmod followed a linked $linked_entry executable"
done
pass "privileged mode normalization rejects linked app/CLI/sysext executables"

RECOVERY_UID=$(/usr/bin/id -u)
for recovery_point in before-first-rename after-first-rename after-second-rename; do
    RECOVERY_ROOT="$TMP_ROOT/recovery-$recovery_point"
    RECOVERY_TARGET="$RECOVERY_ROOT/MacCrab.app"
    RECOVERY_WORK="$RECOVERY_ROOT/.MacCrab-install"
    /bin/mkdir -p "$RECOVERY_ROOT" "$RECOVERY_WORK"
    /bin/chmod 0700 "$RECOVERY_WORK"
    case "$recovery_point" in
        before-first-rename)
            /bin/mkdir "$RECOVERY_TARGET" "$RECOVERY_WORK/New-MacCrab.app"
            printf 'old\n' > "$RECOVERY_TARGET/generation"
            printf 'new\n' > "$RECOVERY_WORK/New-MacCrab.app/generation"
            ;;
        after-first-rename)
            /bin/mkdir "$RECOVERY_WORK/Previous-MacCrab.app" \
                "$RECOVERY_WORK/New-MacCrab.app"
            printf 'old\n' > "$RECOVERY_WORK/Previous-MacCrab.app/generation"
            printf 'new\n' > "$RECOVERY_WORK/New-MacCrab.app/generation"
            ;;
        after-second-rename)
            /bin/mkdir "$RECOVERY_TARGET" "$RECOVERY_WORK/Previous-MacCrab.app"
            printf 'new\n' > "$RECOVERY_TARGET/generation"
            printf 'old\n' > "$RECOVERY_WORK/Previous-MacCrab.app/generation"
            ;;
    esac
    maccrab_recover_interrupted_app_install "$RECOVERY_TARGET" "$RECOVERY_UID" \
        || fail "installer recovery failed at $recovery_point"
    [ "$(/bin/cat "$RECOVERY_TARGET/generation")" = old ] \
        || fail "installer recovery did not retain the predecessor at $recovery_point"
    [ ! -e "$RECOVERY_WORK" ] \
        || fail "installer recovery left its transaction workspace at $recovery_point"
done
pass "interrupted two-rename publication deterministically restores the predecessor at every crash point"

# Fault-inject both halves of rollback. A failed restore must never feed an
# existing target directory to mv (which would nest Previous inside it), and no
# cleanup may destroy the only predecessor/recovery copy.
for failure_mode in displace restore restore-and-fallback; do
    FAILURE_ROOT="$TMP_ROOT/recovery-failure-$failure_mode"
    FAILURE_TARGET="$FAILURE_ROOT/MacCrab.app"
    FAILURE_WORK="$FAILURE_ROOT/.MacCrab-install"
    FAILURE_PREVIOUS="$FAILURE_WORK/Previous-MacCrab.app"
    FAILURE_INTERRUPTED="$FAILURE_WORK/Interrupted-MacCrab.app"
    /bin/mkdir -p "$FAILURE_TARGET" "$FAILURE_PREVIOUS"
    printf 'new\n' > "$FAILURE_TARGET/generation"
    printf 'old\n' > "$FAILURE_PREVIOUS/generation"

    if (
        maccrab_move_path() {
            if [ "$failure_mode" = displace ] \
                    && [ "$1" = "$FAILURE_TARGET" ] \
                    && [ "$2" = "$FAILURE_INTERRUPTED" ]; then
                return 1
            fi
            if { [ "$failure_mode" = restore ] \
                    || [ "$failure_mode" = restore-and-fallback ]; } \
                    && [ "$1" = "$FAILURE_PREVIOUS" ] \
                    && [ "$2" = "$FAILURE_TARGET" ]; then
                return 1
            fi
            if [ "$failure_mode" = restore-and-fallback ] \
                    && [ "$1" = "$FAILURE_INTERRUPTED" ] \
                    && [ "$2" = "$FAILURE_TARGET" ]; then
                return 1
            fi
            /bin/mv "$1" "$2"
        }
        maccrab_rollback_app_install "$FAILURE_TARGET" "$FAILURE_WORK"
    ); then
        fail "fault-injected $failure_mode rollback unexpectedly succeeded"
    fi

    [ -d "$FAILURE_WORK" ] \
        || fail "$failure_mode rollback deleted its recovery workspace"
    [ -d "$FAILURE_PREVIOUS" ] \
        || fail "$failure_mode rollback deleted the only predecessor"
    [ "$(/bin/cat "$FAILURE_PREVIOUS/generation")" = old ] \
        || fail "$failure_mode rollback altered the retained predecessor"
    [ ! -e "$FAILURE_TARGET/Previous-MacCrab.app" ] \
        || fail "$failure_mode rollback nested Previous inside the target"
    if [ "$failure_mode" = restore-and-fallback ]; then
        [ ! -e "$FAILURE_TARGET" ] && [ -d "$FAILURE_INTERRUPTED" ] \
            || fail "double-failed rollback did not retain its displaced recovery copy"
        [ "$(/bin/cat "$FAILURE_INTERRUPTED/generation")" = new ] \
            || fail "double-failed rollback altered its displaced recovery copy"
    else
        [ -d "$FAILURE_TARGET" ] \
            || fail "$failure_mode rollback lost the pre-rollback target"
        [ "$(/bin/cat "$FAILURE_TARGET/generation")" = new ] \
            || fail "$failure_mode rollback changed the pre-rollback target"
    fi
done
pass "failed rollback retains predecessor/recovery copies without directory nesting"

PUBLISH_FIXTURE="$TMP_ROOT/publish"
PUBLISH_APP="$PUBLISH_FIXTURE/MacCrab.app"
/bin/mkdir -p "$PUBLISH_APP/Contents/MacOS" \
    "$PUBLISH_APP/Contents/Resources/bin" \
    "$PUBLISH_APP/Contents/Resources/compiled_rules" \
    "$PUBLISH_APP/Contents/Resources/compiled_rules/graph" \
    "$PUBLISH_APP/Contents/Resources/rules" \
    "$PUBLISH_APP/Contents/Resources/Compiler/yaml" \
    "$PUBLISH_APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/MacOS" \
    "$PUBLISH_APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/Resources/compiled_rules" \
    "$PUBLISH_FIXTURE/bin" "$PUBLISH_FIXTURE/compiled_rules" \
    "$PUBLISH_FIXTURE/rules_source/graph" \
    "$PUBLISH_FIXTURE/release-python/yaml"
printf '<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>com.maccrab.app</string></dict></plist>\n' \
    > "$PUBLISH_APP/Contents/Info.plist"
printf 'main\n' > "$PUBLISH_APP/Contents/MacOS/MacCrab"
printf 'agent\n' \
    > "$PUBLISH_APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
printf 'main\n' > "$PUBLISH_FIXTURE/bin/MacCrabApp"
printf 'agent\n' > "$PUBLISH_FIXTURE/bin/MacCrabAgent"
for cli in maccrabctl maccrab-mcp; do
    printf '%s\n' "$cli" > "$PUBLISH_APP/Contents/Resources/bin/$cli"
    /bin/cp "$PUBLISH_APP/Contents/Resources/bin/$cli" "$PUBLISH_FIXTURE/bin/$cli"
done
printf 'rule\n' > "$PUBLISH_APP/Contents/Resources/compiled_rules/rule.json"
printf 'yaml rule\n' > "$PUBLISH_APP/Contents/Resources/rules/sample.yml"
printf 'graph rule\n' > "$PUBLISH_APP/Contents/Resources/compiled_rules/graph/sample.json"
printf 'yaml module\n' > "$PUBLISH_APP/Contents/Resources/Compiler/yaml/__init__.py"
write_fixture_manifest "$PUBLISH_APP/Contents/Resources/compiled_rules" "9.9.9"
/bin/cp -R "$PUBLISH_APP/Contents/Resources/compiled_rules/." "$PUBLISH_FIXTURE/compiled_rules/"
/bin/cp -R "$PUBLISH_APP/Contents/Resources/compiled_rules/." \
    "$PUBLISH_APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/Resources/compiled_rules/"
/bin/cp "$PUBLISH_APP/Contents/Resources/rules/sample.yml" "$PUBLISH_FIXTURE/rules_source/sample.yml"
/bin/cp "$PUBLISH_APP/Contents/Resources/compiled_rules/graph/sample.json" \
    "$PUBLISH_FIXTURE/rules_source/graph/sample.json"
printf 'source documentation\n' > "$PUBLISH_FIXTURE/rules_source/README.md"
/bin/cp "$PUBLISH_APP/Contents/Resources/Compiler/yaml/__init__.py" \
    "$PUBLISH_FIXTURE/release-python/yaml/__init__.py"
printf '#!/bin/bash\n' > "$PUBLISH_FIXTURE/install.sh"
/bin/chmod 0700 "$PUBLISH_APP/Contents/MacOS/MacCrab" \
    "$PUBLISH_APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent" \
    "$PUBLISH_APP/Contents/Resources/bin/"* "$PUBLISH_FIXTURE/bin/"* \
    "$PUBLISH_FIXTURE/install.sh"

# A valid manifest must describe the complete tree, not merely exist. Exercise
# every release-critical invariant against disposable copies before accepting
# the pristine payload.
TAMPER_BASE="$TMP_ROOT/publish-tamper-base"
/bin/cp -R "$PUBLISH_FIXTURE" "$TAMPER_BASE"
for tamper in schema marker hash sysext-hash extra-file extra-directory \
        missing symlink hardlink special aggregate-limit rules-source-special; do
    TAMPER_FIXTURE="$TMP_ROOT/tamper-$tamper"
    /bin/cp -R "$TAMPER_BASE" "$TAMPER_FIXTURE"
    TAMPER_APP_RULES="$TAMPER_FIXTURE/MacCrab.app/Contents/Resources/compiled_rules"
    TAMPER_SYSEXT_RULES="$TAMPER_FIXTURE/MacCrab.app/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/Resources/compiled_rules"
    case "$tamper" in
        schema)
            /usr/bin/sed -i '' 's/"schema_version": 1/"schema_version": 2/' \
                "$TAMPER_APP_RULES/manifest.json"
            ;;
        marker)
            printf '9.9.8\n' > "$TAMPER_APP_RULES/.bundle_version"
            ;;
        hash)
            printf 'tampered\n' >> "$TAMPER_APP_RULES/rule.json"
            ;;
        sysext-hash)
            printf 'tampered\n' >> "$TAMPER_SYSEXT_RULES/rule.json"
            ;;
        extra-file)
            printf 'unmanifested\n' > "$TAMPER_APP_RULES/extra.json"
            ;;
        extra-directory)
            /bin/mkdir "$TAMPER_APP_RULES/empty"
            ;;
        missing)
            /bin/rm "$TAMPER_APP_RULES/rule.json"
            ;;
        symlink)
            /bin/ln -s rule.json "$TAMPER_APP_RULES/linked.json"
            ;;
        hardlink)
            /bin/ln "$TAMPER_APP_RULES/rule.json" "$TAMPER_APP_RULES/hardlink.json"
            ;;
        special)
            /usr/bin/mkfifo "$TAMPER_APP_RULES/special.json"
            ;;
        aggregate-limit)
            for index in {1..17}; do
                /usr/sbin/mkfile -n 4m "$TAMPER_APP_RULES/aggregate-$index.json"
            done
            ;;
        rules-source-special)
            /usr/bin/mkfifo "$TAMPER_FIXTURE/rules_source/injected.pipe"
            ;;
    esac
    if "$SCRIPT_DIR/prepare-dmg-payload.sh" "$TAMPER_FIXTURE" \
            >/dev/null 2>&1; then
        fail "payload validator accepted $tamper corpus tampering"
    fi
done
pass "release corpus validator rejects schema/version/hash/set/link/special tampering in app and sysext"

METADATA_FIXTURE="$TMP_ROOT/metadata-normalization"
/bin/cp -R "$TAMPER_BASE" "$METADATA_FIXTURE"
METADATA_APP_RULES="$METADATA_FIXTURE/MacCrab.app/Contents/Resources/compiled_rules"
METADATA_SYSEXT_RULES="$METADATA_FIXTURE/MacCrab.app/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/Resources/compiled_rules"
/bin/chmod +a 'everyone allow read' "$METADATA_APP_RULES/rule.json"
/usr/bin/chflags uchg "$METADATA_SYSEXT_RULES/rule.json"
"$SCRIPT_DIR/prepare-dmg-payload.sh" "$METADATA_FIXTURE" >/dev/null
if /usr/bin/find "$METADATA_FIXTURE" \
        \( -flags +uchg -o -flags +uappnd -o -flags +schg -o -flags +sappnd \) \
        -print | /usr/bin/grep . >/dev/null; then
    fail "payload normalization retained an unsafe BSD flag"
fi
if /usr/bin/find "$METADATA_FIXTURE" \( -type d -o -type f \) \
        -exec /bin/ls -lde {} + \
        | /usr/bin/grep -E '^[[:space:]][[:digit:]]+: ' >/dev/null; then
    fail "payload normalization retained an extended ACL"
fi
pass "payload normalization strips ACLs and immutable/append-only flags before signature re-verification"

# The release validator uses numeric Darwin flag values in its isolated Python
# helper while the runtime uses imported Darwin constants. Pin both sides so a
# future runtime hardening cannot silently leave packaging with a weaker mask.
runtime_flag_block=$(/usr/bin/awk '
    /private static let unsafeBSDFlags/ { capture = 1 }
    capture { print }
    capture && /^    \)/ { exit }
' "$PROJECT_DIR/Sources/MacCrabAgentKit/BundledRuleSynchronizer.swift")
runtime_flags=$(printf '%s\n' "$runtime_flag_block" \
    | /usr/bin/grep -oE '(UF|SF)_[A-Z_]+' \
    | /usr/bin/sort -u)
expected_runtime_flags=$(printf '%s\n' \
    SF_APPEND SF_DATALESS SF_IMMUTABLE SF_NOUNLINK \
    UF_APPEND UF_DATAVAULT UF_IMMUTABLE \
    | /usr/bin/sort)
[ "$runtime_flags" = "$expected_runtime_flags" ] \
    || fail "runtime unsafe-BSD-flag set drifted from the packaging contract"
for encoded_flag in 0x00000002 0x00000004 0x00000080 0x00020000 \
        0x00040000 0x00100000 0x40000000; do
    /usr/bin/grep -qF "$encoded_flag" "$SCRIPT_DIR/prepare-dmg-payload.sh" \
        || fail "release payload validator omits unsafe BSD flag $encoded_flag"
done
pass "runtime and release payload validators pin the same unsafe BSD flag set"
for pinned_limit in \
        'maximumSignedCorpusEntries = 4_096' \
        'maximumSignedCorpusFileBytes: off_t = 16 * 1_024 * 1_024' \
        'maximumSignedCorpusAggregateBytes: off_t = 64 * 1_024 * 1_024' \
        'maximumSignedCorpusDepth = 32'; do
    /usr/bin/grep -qF "$pinned_limit" \
        "$PROJECT_DIR/Sources/MacCrabAgentKit/BundledRuleSynchronizer.swift" \
        || fail "runtime signed-corpus resource contract drifted: $pinned_limit"
done
for pinned_limit in \
        'maximum_entries = 4096' \
        'maximum_file_bytes = 16 * 1024 * 1024' \
        'maximum_aggregate_bytes = 64 * 1024 * 1024' \
        'maximum_depth = 32'; do
    /usr/bin/grep -qF "$pinned_limit" "$SCRIPT_DIR/prepare-dmg-payload.sh" \
        || fail "release signed-corpus resource contract drifted: $pinned_limit"
done
pass "runtime and release packaging pin the same signed-corpus resource ceilings"

"$SCRIPT_DIR/prepare-dmg-payload.sh" "$PUBLISH_FIXTURE" >/dev/null
[ ! -e "$PUBLISH_FIXTURE/bin" ] || fail "published payload retained redundant root bin/"
[ ! -e "$PUBLISH_FIXTURE/compiled_rules" ] \
    || fail "published payload retained redundant root compiled_rules/"
[ ! -e "$PUBLISH_FIXTURE/rules_source" ] \
    || fail "published payload retained internal rules_source/"
[ ! -e "$PUBLISH_FIXTURE/release-python" ] \
    || fail "published payload retained internal release-python/"
[ "$(/usr/bin/stat -f '%Lp' "$PUBLISH_FIXTURE/install.sh")" = 755 ] \
    || fail "published installer was not executable by non-owner users"
[ "$(/usr/bin/stat -f '%Lp' "$PUBLISH_APP/Contents/Info.plist")" = 644 ] \
    || fail "published app metadata was not readable by non-owner users"
pass "published fixture prunes all four verified handoff trees and normalizes modes"

/usr/bin/diff -qr \
    "$PUBLISH_APP/Contents/Resources/compiled_rules" \
    "$PUBLISH_APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/Resources/compiled_rules" >/dev/null \
    || fail "published app/System Extension compiled-rule corpora drifted"
pass "published app and signed System Extension carry the same rule corpus"

/usr/bin/cmp -s "$PROJECT_DIR/Casks/maccrab.rb" "$PROJECT_DIR/homebrew/maccrab.rb" \
    || fail "the two Homebrew cask copies drifted"
for cask in "$PROJECT_DIR/Casks/maccrab.rb" "$PROJECT_DIR/homebrew/maccrab.rb"; do
    /usr/bin/grep -qF 'binary "#{appdir}/MacCrab.app/Contents/Resources/bin/maccrabctl"' "$cask" \
        || fail "cask does not consume the signed in-app maccrabctl"
    /usr/bin/grep -qF 'binary "#{appdir}/MacCrab.app/Contents/Resources/bin/maccrab-mcp"' "$cask" \
        || fail "cask does not consume the signed in-app maccrab-mcp"
    if /usr/bin/grep -qE 'staged_path}/(bin|compiled_rules)|binary "bin/' "$cask"; then
        fail "cask still consumes a redundant DMG-root payload"
    fi
    if /usr/bin/grep -qE 'rules_source|Dir\.glob\(.*compiled_rules|system_command "/bin/cp"' "$cask"; then
        fail "cask still mutates the installed rule corpus file-by-file"
    fi
done
pass "both casks consume in-app binaries and leave installed rules to the atomic sysext transaction"

# Exercise the exact release signature contract against both sides of the AMFI
# regression. A hardened, stable-ID bare executable with zero entitlements must
# pass; adding the restricted shared-Keychain group must fail even though
# codesign itself accepts the signature.
BARE_TOOL_GUARDS="$TMP_ROOT/bare-tool-release-guards.sh"
/usr/bin/sed -n \
    '/^# BEGIN BARE_TOOL_RELEASE_GUARDS$/,/^# END BARE_TOOL_RELEASE_GUARDS$/p' \
    "$SCRIPT_DIR/build-release.sh" > "$BARE_TOOL_GUARDS"
# shellcheck source=/dev/null
source "$BARE_TOOL_GUARDS"
CODESIGN_BIN=/usr/bin/codesign
BARE_TOOL_FIXTURE="$TMP_ROOT/bare-tool-signatures"
/bin/mkdir -p "$BARE_TOOL_FIXTURE/clean" "$BARE_TOOL_FIXTURE/restricted"
/bin/cp /bin/echo "$BARE_TOOL_FIXTURE/clean/maccrabctl"
"$CODESIGN_BIN" --force --sign - \
    --identifier com.maccrab.maccrabctl --options runtime \
    "$BARE_TOOL_FIXTURE/clean/maccrabctl" >/dev/null
verify_bare_tool_signature_contract "$BARE_TOOL_FIXTURE/clean/maccrabctl" \
    || fail "zero-entitlement hardened bare tool was rejected"

RESTRICTED_ENTITLEMENTS="$BARE_TOOL_FIXTURE/restricted.plist"
/usr/bin/plutil -create xml1 "$RESTRICTED_ENTITLEMENTS"
/usr/bin/plutil -insert keychain-access-groups \
    -json '["79S425CW99.com.maccrab.shared"]' "$RESTRICTED_ENTITLEMENTS"
/bin/cp /bin/echo "$BARE_TOOL_FIXTURE/restricted/maccrab-mcp"
"$CODESIGN_BIN" --force --sign - \
    --identifier com.maccrab.maccrab-mcp --options runtime \
    --entitlements "$RESTRICTED_ENTITLEMENTS" \
    "$BARE_TOOL_FIXTURE/restricted/maccrab-mcp" >/dev/null
if verify_bare_tool_signature_contract \
        "$BARE_TOOL_FIXTURE/restricted/maccrab-mcp" \
        >"$BARE_TOOL_FIXTURE/restricted/output.log" 2>&1; then
    fail "release guard accepted a restricted entitlement on a bare tool"
fi
/usr/bin/grep -q 'carries forbidden bare-tool entitlements' \
    "$BARE_TOOL_FIXTURE/restricted/output.log" \
    || fail "release guard did not diagnose the restricted bare-tool entitlement"
pass "release signature contract rejects restricted entitlements on bare tools"

/usr/bin/grep -qF 'prepare-dmg-payload.sh" "$STAGING_DIR"' "$SCRIPT_DIR/build-release.sh" \
    || fail "release publish stage does not prepare/prune the final payload"
stage_prepare_line=$(/usr/bin/grep -nF '"$SCRIPT_DIR/prepare-dmg-payload.sh" "$STAGING_DIR"' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
stage_verify_line=$(/usr/bin/grep -nF '$CODESIGN_BIN --verify --deep --strict "$APP"' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/tail -1 | /usr/bin/cut -d: -f1)
mount_prepare_line=$(/usr/bin/grep -nF '"$SCRIPT_DIR/prepare-dmg-payload.sh" "$DMG_MNT"' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
mount_verify_line=$(/usr/bin/grep -nF '$CODESIGN_BIN --verify --deep --strict "$DMG_MNT/MacCrab.app"' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
post_sign_verify_line=$(/usr/bin/grep -nF '$CODESIGN_BIN --verify --deep --strict --verbose=2 "$APP"' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
post_sign_runtime_line=$(/usr/bin/grep -nF 'verify_bare_tool_runtime "$APP" "post-sign"' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
mount_runtime_line=$(/usr/bin/grep -nF 'verify_bare_tool_runtime "$DMG_MNT/MacCrab.app" "mounted-DMG"' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
mount_detach_line=$(/usr/bin/grep -nF '/usr/bin/hdiutil detach "$DMG_MNT" -force' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
[ -n "$stage_prepare_line" ] && [ -n "$stage_verify_line" ] \
    && [ "$stage_prepare_line" -lt "$stage_verify_line" ] \
    && [ -n "$mount_prepare_line" ] && [ -n "$mount_verify_line" ] \
    && [ "$mount_prepare_line" -lt "$mount_verify_line" ] \
    && [ -n "$post_sign_verify_line" ] && [ -n "$post_sign_runtime_line" ] \
    && [ "$post_sign_verify_line" -lt "$post_sign_runtime_line" ] \
    && [ -n "$mount_runtime_line" ] && [ -n "$mount_detach_line" ] \
    && [ "$mount_verify_line" -lt "$mount_runtime_line" ] \
    && [ "$mount_runtime_line" -lt "$mount_detach_line" ] \
    || fail "release does not verify and execute both final app copies in order"

# Exercise the EXIT helper in isolation with adversarial neighbour paths.  The
# cleanup must remove only the exact per-run mount directory and RW work image;
# the completed DMG and same-prefix decoys are release evidence/artifacts and
# must survive.  ATTACH_ATTEMPTED=0 keeps this hermetic (no real disk attach).
CLEANUP_HELPER="$TMP_ROOT/build-release-cleanup.sh"
/usr/bin/sed -n \
    '/^# BEGIN RELEASE_DMG_EXIT_CLEANUP$/,/^# END RELEASE_DMG_EXIT_CLEANUP$/p' \
    "$SCRIPT_DIR/build-release.sh" > "$CLEANUP_HELPER"
# shellcheck source=/dev/null
source "$CLEANUP_HELPER"
CLEANUP_CASE="$TMP_ROOT/dmg-cleanup-case"
OWNED_MOUNT="$CLEANUP_CASE/owned-mount"
OWNED_RW="$CLEANUP_CASE/MacCrab-v9.9.9.rw.dmg"
FINAL_DMG="$CLEANUP_CASE/MacCrab-v9.9.9.dmg"
DECOY_MOUNT="$CLEANUP_CASE/owned-mount-neighbour"
DECOY_RW="$CLEANUP_CASE/MacCrab-v9.9.9.rw.dmg.neighbour"
/bin/mkdir -p "$OWNED_MOUNT" "$DECOY_MOUNT"
printf 'partial\n' > "$OWNED_RW"
printf 'final\n' > "$FINAL_DMG"
printf 'decoy\n' > "$DECOY_RW"
RELEASE_DMG_MOUNT_PATH="$OWNED_MOUNT"
RELEASE_RW_DMG_PATH="$OWNED_RW"
RELEASE_DMG_ATTACH_ATTEMPTED=0
cleanup_release_dmg_working_state
[ ! -e "$OWNED_MOUNT" ] && [ ! -e "$OWNED_RW" ] \
    || fail "release EXIT helper retained owned DMG working state"
[ -d "$DECOY_MOUNT" ] && [ -f "$DECOY_RW" ] && [ -f "$FINAL_DMG" ] \
    || fail "release EXIT helper removed a neighbour or successful DMG"
/usr/bin/grep -qF 'trap cleanup_release_build EXIT' "$SCRIPT_DIR/build-release.sh" \
    || fail "release builder does not install the unified EXIT cleanup"
/usr/bin/grep -qF '/usr/bin/hdiutil detach "$RELEASE_DMG_MOUNT_PATH" -force' \
    "$SCRIPT_DIR/build-release.sh" \
    || fail "release EXIT cleanup does not detach the exact owned mount"
rw_arm_line=$(/usr/bin/grep -nF 'RELEASE_RW_DMG_PATH="$RW_DMG"' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
rw_create_line=$(/usr/bin/grep -nF '/usr/bin/hdiutil create ' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
mount_arm_line=$(/usr/bin/grep -nF 'RELEASE_DMG_MOUNT_PATH="$DMG_MNT"' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
attach_arm_line=$(/usr/bin/grep -nF 'RELEASE_DMG_ATTACH_ATTEMPTED=1' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
attach_line=$(/usr/bin/grep -nF '/usr/bin/hdiutil attach ' \
    "$SCRIPT_DIR/build-release.sh" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
[ -n "$rw_arm_line" ] && [ -n "$rw_create_line" ] \
    && [ "$rw_arm_line" -lt "$rw_create_line" ] \
    && [ -n "$mount_arm_line" ] && [ -n "$attach_arm_line" ] \
    && [ -n "$attach_line" ] \
    && [ "$mount_arm_line" -lt "$attach_arm_line" ] \
    && [ "$attach_arm_line" -lt "$attach_line" ] \
    || fail "release builder does not arm exact-path cleanup before DMG operations"
/usr/bin/grep -qF 'DMG_MNT=$(/usr/bin/mktemp -d /private/tmp/maccrab-dmg-mnt.XXXXXX)' \
    "$SCRIPT_DIR/build-release.sh" \
    || fail "release builder does not create a private, invocation-owned mount directory"
if /usr/bin/sed -n \
        '/^# BEGIN RELEASE_DMG_EXIT_CLEANUP$/,/^# END RELEASE_DMG_EXIT_CLEANUP$/p' \
        "$SCRIPT_DIR/build-release.sh" | /usr/bin/grep -qF '$DMG_PATH'; then
    fail "release EXIT cleanup can address the successful DMG artifact"
fi
pass "release EXIT cleanup is exact-path bounded and retains the successful DMG"

if /usr/bin/grep -qF 'rm -rf "/Applications/MacCrab.app"' "$SCRIPT_DIR/install.sh"; then
    fail "manual installer still deletes the working app before staging its replacement"
fi
/usr/bin/grep -qF '/usr/bin/ditto "$source_app" "$staged_app"' "$SCRIPT_DIR/install.sh" \
    || fail "manual installer does not stage the app with ditto"
/usr/bin/grep -qF 'app_requirement=' "$SCRIPT_DIR/install.sh" \
    || fail "manual installer does not bind payload provenance to a designated requirement"
/usr/bin/grep -qF 'identifier "com.maccrab.app" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "79S425CW99"' \
    "$SCRIPT_DIR/install.sh" \
    || fail "manual installer requirement lacks the canonical Developer ID Application chain/app/team anchors"
/usr/bin/grep -qF 'certificate 1[field.1.2.840.113635.100.6.2.6] exists' \
    "$PROJECT_DIR/Sources/MacCrabAgentKit/BundledRuleSynchronizer.swift" \
    || fail "runtime System Extension requirement lacks the Developer ID intermediate marker"
/usr/bin/grep -qF 'certificate leaf[field.1.2.840.113635.100.6.1.13] exists' \
    "$PROJECT_DIR/Sources/MacCrabAgentKit/BundledRuleSynchronizer.swift" \
    || fail "runtime System Extension requirement lacks the Developer ID Application leaf marker"
/usr/bin/grep -qF '/usr/bin/codesign --verify --deep --strict "$staged_app"' "$SCRIPT_DIR/install.sh" \
    || fail "manual installer does not verify the normalized staged app"
/usr/bin/grep -qF -- '-R="$app_requirement" "$staged_app"' "$SCRIPT_DIR/install.sh" \
    || fail "manual installer does not enforce provenance on the staged app"
/usr/bin/grep -qF 'maccrab_recover_interrupted_app_install "$target_app"' "$SCRIPT_DIR/install.sh" \
    || fail "manual installer lacks deterministic interrupted-publication recovery"
/usr/bin/grep -qF 'maccrab_move_path "$staged_app" "$target_app"' "$SCRIPT_DIR/install.sh" \
    || fail "manual installer does not publish the verified staged app by same-volume rename"
if /usr/bin/grep -qE 'RULES_SOURCE=|cp -R .*compiled_rules|compile_rules\.py' \
        "$SCRIPT_DIR/install.sh"; then
    fail "manual installer still mutates the installed rule corpus outside the sysext transaction"
fi
pass "release and manual install gates verify final app copies; upgrades retain the prior app/rules until publish"
sync_line=$(/usr/bin/grep -nF 'BundledRuleSynchronizer.synchronizeAtBoot(' \
    "$PROJECT_DIR/Sources/MacCrabAgentKit/DaemonSetup.swift" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
reader_line=$(/usr/bin/grep -nF '// Initialize components' \
    "$PROJECT_DIR/Sources/MacCrabAgentKit/DaemonSetup.swift" | /usr/bin/head -1 | /usr/bin/cut -d: -f1)
[ -n "$sync_line" ] && [ -n "$reader_line" ] && [ "$sync_line" -lt "$reader_line" ] \
    || fail "daemon boot does not self-sync rules before constructing readers"
[ ! -e "$PROJECT_DIR/Sources/MacCrabApp/RuleBundleInstaller.swift" ] \
    || fail "obsolete GUI privileged rule installer is still present"
if /usr/bin/grep -R -qF 'with administrator privileges' \
        "$PROJECT_DIR/Sources/MacCrabApp"; then
    fail "MacCrab app still contains a launch-capable administrator-password rule sync"
fi
pass "release builder guards payload; app launch has no privileged rule sync"

echo "PASS: installer and DMG payload fixtures"
